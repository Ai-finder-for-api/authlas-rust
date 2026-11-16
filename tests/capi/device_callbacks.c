/* Device grant through host callbacks (RFC 8628). The host keeps records and attempt counters in tables and serialises
   each operation, as docs/CALLBACKS.md requires. */
#include <stdio.h>
#include <string.h>
#include "authlas.h"

#define MAX 8
#define MAXLEN 1024
typedef struct { char json[MAXLEN]; int used; } Slot;
typedef struct { char key[64]; unsigned count; int used; } Attempt;
typedef struct { Slot s[MAX]; Attempt a[MAX]; int saves; } Host;

static int failures = 0;
#define CHECK(c, m) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, m); failures++; } } while (0)

/* Pulls a string field out of the record JSON (values in these records never contain quotes). */
static int field(const char *json, const char *key, char *out, size_t n) {
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\":\"", key);
    const char *p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    const char *e = strchr(p, '"');
    if (!e) return 0;
    size_t len = (size_t)(e - p) < n - 1 ? (size_t)(e - p) : n - 1;
    memcpy(out, p, len); out[len] = 0;
    return 1;
}

static int host_insert(void *user, const char *rec) {
    Host *h = (Host *)user;
    for (int i = 0; i < MAX; i++) if (!h->s[i].used) {
        snprintf(h->s[i].json, MAXLEN, "%s", rec);
        h->s[i].used = 1;
        return 0;
    }
    return 2;
}

static int find(Host *h, const char *key_field, const char *key, AuthlasBuf *out) {
    for (int i = 0; i < MAX; i++) {
        if (!h->s[i].used) continue;
        char v[256];
        if (field(h->s[i].json, key_field, v, sizeof v) && strcmp(v, key) == 0)
            return authlas_buf_write(out, (const unsigned char *)h->s[i].json, strlen(h->s[i].json));
    }
    return authlas_buf_write(out, NULL, 0);
}

static int find_by_user_code(void *user, const char *code, AuthlasBuf *out) { return find((Host *)user, "user_code", code, out); }
static int find_by_device_hash(void *user, const char *hash, AuthlasBuf *out) { return find((Host *)user, "device_hash", hash, out); }

static int host_save(void *user, const char *rec) {
    Host *h = (Host *)user;
    char id[256];
    if (!field(rec, "device_hash", id, sizeof id)) return 1;
    for (int i = 0; i < MAX; i++) {
        char v[256];
        if (h->s[i].used && field(h->s[i].json, "device_hash", v, sizeof v) && strcmp(v, id) == 0) {
            snprintf(h->s[i].json, MAXLEN, "%s", rec);
            h->saves++;
            return 0;
        }
    }
    return 1;
}

static int find_attempts(void *user, const char *key, AuthlasBuf *out) {
    Host *h = (Host *)user;
    for (int i = 0; i < MAX; i++) if (h->a[i].used && strcmp(h->a[i].key, key) == 0) {
        char num[16]; snprintf(num, sizeof num, "%u", h->a[i].count);
        return authlas_buf_write(out, (const unsigned char *)num, strlen(num));
    }
    return authlas_buf_write(out, NULL, 0);
}

static int save_attempts(void *user, const char *key, unsigned count) {
    Host *h = (Host *)user;
    for (int i = 0; i < MAX; i++) if (h->a[i].used && strcmp(h->a[i].key, key) == 0) { h->a[i].count = count; return 0; }
    for (int i = 0; i < MAX; i++) if (!h->a[i].used) {
        snprintf(h->a[i].key, sizeof h->a[i].key, "%s", key);
        h->a[i].count = count; h->a[i].used = 1;
        return 0;
    }
    return 2;
}

static char *text_of(AuthlasBuf *b) {
    static char buf[4096];
    snprintf(buf, sizeof buf, "%.*s", (int)b->len, (const char *)b->data);
    return buf;
}

int main(void) {
    Host host; memset(&host, 0, sizeof host);
    AuthlasDeviceStore store = { &host, host_insert, find_by_user_code, find_by_device_hash, host_save, find_attempts, save_attempts };
    const char *uri = "https://as.example/device";

    /* 1. start: the device gets a device_code and a user_code. */
    AuthlasBuf s = { NULL, 0 };
    int st = authlas_device_start(store, "tv", "read", uri, 1000, &s);
    CHECK(st == AUTHLAS_STATUS_OK, "start succeeds");
    char device_code[256] = {0}, user_code[64] = {0};
    field(text_of(&s), "device_code", device_code, sizeof device_code);
    field(text_of(&s), "user_code", user_code, sizeof user_code);
    CHECK(device_code[0] != 0, "device_code returned");
    CHECK(user_code[0] != 0, "user_code returned");
    CHECK(strstr(host.s[0].json, device_code) == NULL, "raw device_code is not stored, only its hash");
    authlas_buf_free(&s);

    /* 2. poll before approval does not issue. */
    AuthlasBuf p = { NULL, 0 };
    CHECK(authlas_device_poll(store, "tv", device_code, 1010, &p) != AUTHLAS_STATUS_OK, "poll before approval does not issue");
    authlas_buf_free(&p);

    /* 3. the user types the code and approves. */
    AuthlasBuf d = { NULL, 0 };
    st = authlas_device_decide(store, "session-a", user_code, "alice", 5, 1020, &d);
    CHECK(st == AUTHLAS_STATUS_OK && strcmp(text_of(&d), "approved") == 0, "approval is recorded");
    authlas_buf_free(&d);

    /* 4. poll after approval issues the grant for alice. */
    AuthlasBuf g = { NULL, 0 };
    st = authlas_device_poll(store, "tv", device_code, 1100, &g);
    CHECK(st == AUTHLAS_STATUS_OK && strstr(text_of(&g), "\"subject\":\"alice\"") != NULL, "approved poll issues the grant for alice");
    authlas_buf_free(&g);

    /* 5. the grant is spent: a second poll cannot issue again. */
    AuthlasBuf again = { NULL, 0 };
    CHECK(authlas_device_poll(store, "tv", device_code, 1200, &again) != AUTHLAS_STATUS_OK, "second poll is refused (single use)");
    authlas_buf_free(&again);

    /* 6. another client cannot poll someone else's device code. */
    AuthlasBuf s2 = { NULL, 0 };
    authlas_device_start(store, "tv", "read", uri, 2000, &s2);
    char dc2[256] = {0};
    field(text_of(&s2), "device_code", dc2, sizeof dc2);
    authlas_buf_free(&s2);
    AuthlasBuf wrong = { NULL, 0 };
    CHECK(authlas_device_poll(store, "attacker", dc2, 2010, &wrong) != AUTHLAS_STATUS_OK, "a different client cannot poll the device code");
    authlas_buf_free(&wrong);

    /* 7. guesses that match nothing are counted per caller; after max_attempts the caller is refused, even for a real code. */
    AuthlasBuf s3 = { NULL, 0 };
    authlas_device_start(store, "tv", "read", uri, 3000, &s3);
    char uc3[64] = {0};
    field(text_of(&s3), "user_code", uc3, sizeof uc3);
    authlas_buf_free(&s3);
    for (int i = 0; i < 3; i++) {
        AuthlasBuf w = { NULL, 0 };
        CHECK(authlas_device_decide(store, "attacker-ip", "BBBB-BBBB", "mallory", 3, 3001 + i, &w) != AUTHLAS_STATUS_OK, "a wrong guess is refused");
        authlas_buf_free(&w);
    }
    AuthlasBuf locked = { NULL, 0 };
    CHECK(authlas_device_decide(store, "attacker-ip", uc3, "mallory", 3, 3010, &locked) != AUTHLAS_STATUS_OK, "an exhausted caller is refused even for a real code");
    authlas_buf_free(&locked);
    AuthlasBuf other = { NULL, 0 };
    CHECK(authlas_device_decide(store, "honest-session", uc3, "alice", 3, 3011, &other) == AUTHLAS_STATUS_OK, "another caller is not blocked by the attacker's count");
    authlas_buf_free(&other);

    printf(failures ? "%d FAILURES\n" : "device callback checks passed\n", failures);
    return failures ? 1 : 0;
}
