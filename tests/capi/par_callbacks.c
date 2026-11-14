/* PAR through host callbacks (docs/CALLBACKS.md). The "host" is a tiny in-memory table in this file. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "authlas.h"

#define MAX 8
typedef struct { char uri[160]; char json[1024]; int used; } Slot;
typedef struct { Slot slots[MAX]; int saves; } Host;

static int failures = 0;
#define CHECK(c, m) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, m); failures++; } } while (0)

static char *find_field(const char *json, const char *key, char *out, size_t n) {
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\":\"", key);
    const char *p = strstr(json, pat);
    if (!p) return NULL;
    p += strlen(pat);
    const char *e = strchr(p, '"');
    if (!e) return NULL;
    size_t len = (size_t)(e - p) < n - 1 ? (size_t)(e - p) : n - 1;
    memcpy(out, p, len); out[len] = 0;
    return out;
}

static int host_save(void *user, const char *record_json) {
    Host *h = (Host *)user;
    for (int i = 0; i < MAX; i++) {
        if (!h->slots[i].used) {
            char uri[160];
            if (!find_field(record_json, "request_uri", uri, sizeof uri)) return 1;
            snprintf(h->slots[i].uri, sizeof h->slots[i].uri, "%s", uri);
            snprintf(h->slots[i].json, sizeof h->slots[i].json, "%s", record_json);
            h->slots[i].used = 1;
            h->saves++;
            return 0;
        }
    }
    return 2; /* full */
}

static int host_take(void *user, const char *request_uri, AuthlasBuf *out) {
    Host *h = (Host *)user;
    for (int i = 0; i < MAX; i++) {
        if (h->slots[i].used && strcmp(h->slots[i].uri, request_uri) == 0) {
            h->slots[i].used = 0; /* removed in the same step */
            return authlas_buf_write(out, (const uint8_t *)h->slots[i].json, strlen(h->slots[i].json));
        }
    }
    return authlas_buf_write(out, NULL, 0);
}

int main(void) {
    Host host; memset(&host, 0, sizeof host);
    AuthlasPushStore store = { &host, host_save, host_take };

    const char *body = "client_id=app&response_type=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&client_secret=hunter2&state=xyz";
    AuthlasBuf pushed = { NULL, 0 };
    int st = authlas_par_push(store, "app", body, 1000, &pushed);
    CHECK(st == AUTHLAS_STATUS_OK, "push succeeds");
    CHECK(host.saves == 1, "host stored one record");
    CHECK(pushed.data && strstr((char *)pushed.data, "urn:ietf:params:oauth:request_uri:"), "request_uri returned");
    CHECK(strstr(host.slots[0].json, "hunter2") == NULL, "client secret not stored by host");

    char uri[160] = {0};
    find_field((char *)pushed.data, "request_uri", uri, sizeof uri);
    authlas_buf_free(&pushed);

    AuthlasBuf q = { NULL, 0 };
    st = authlas_par_redeem(store, "app", uri, 1010, &q);
    CHECK(st == AUTHLAS_STATUS_OK && q.data && strstr((char *)q.data, "state=xyz"), "redeem returns the stored query");
    authlas_buf_free(&q);

    AuthlasBuf again = { NULL, 0 };
    CHECK(authlas_par_redeem(store, "app", uri, 1011, &again) != AUTHLAS_STATUS_OK, "second redeem is refused");
    authlas_buf_free(&again);

    AuthlasBuf p2 = { NULL, 0 };
    CHECK(authlas_par_push(store, "app", "client_id=app&request_uri=urn%3Aevil", 1000, &p2) != AUTHLAS_STATUS_OK, "request_uri inside a push is refused");
    authlas_buf_free(&p2);

    printf(failures ? "%d FAILURES\n" : "par callback checks passed\n", failures);
    return failures ? 1 : 0;
}
