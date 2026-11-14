/* Client registration through host callbacks (RFC 7591 / 7592). The "host" keeps records in a small table. */
#include <stdio.h>
#include <string.h>
#include "authlas.h"

#define MAX 8
typedef struct { char client_id[64]; char json[4096]; int used; } Slot;
typedef struct { Slot s[MAX]; int inserts; int replaces; int removes; } Host;

static int failures = 0;
#define CHECK(c, m) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, m); failures++; } } while (0)

static int find_id(const char *json, char *out, size_t n) {
    const char *p = strstr(json, "\"client_id\":\"");
    if (!p) return 0;
    p += strlen("\"client_id\":\"");
    const char *e = strchr(p, '"');
    if (!e) return 0;
    size_t len = (size_t)(e - p) < n - 1 ? (size_t)(e - p) : n - 1;
    memcpy(out, p, len); out[len] = 0;
    return 1;
}

static Slot *slot_for(Host *h, const char *id) {
    for (int i = 0; i < MAX; i++) if (h->s[i].used && strcmp(h->s[i].client_id, id) == 0) return &h->s[i];
    return NULL;
}

static int host_get(void *user, const char *client_id, AuthlasBuf *out) {
    Host *h = (Host *)user;
    Slot *s = slot_for(h, client_id);
    if (!s) return authlas_buf_write(out, NULL, 0);
    return authlas_buf_write(out, (const unsigned char *)s->json, strlen(s->json));
}

static int host_insert(void *user, const char *rec) {
    Host *h = (Host *)user;
    char id[64];
    if (!find_id(rec, id, sizeof id) || slot_for(h, id)) return 1;
    for (int i = 0; i < MAX; i++) {
        if (!h->s[i].used) {
            snprintf(h->s[i].client_id, sizeof h->s[i].client_id, "%s", id);
            snprintf(h->s[i].json, sizeof h->s[i].json, "%s", rec);
            h->s[i].used = 1; h->inserts++;
            return 0;
        }
    }
    return 2;
}

static int host_replace(void *user, const char *rec) {
    Host *h = (Host *)user;
    char id[64];
    if (!find_id(rec, id, sizeof id)) return 1;
    Slot *s = slot_for(h, id);
    if (!s) return 1;
    snprintf(s->json, sizeof s->json, "%s", rec);
    h->replaces++;
    return 0;
}

static int host_remove(void *user, const char *client_id) {
    Host *h = (Host *)user;
    Slot *s = slot_for(h, client_id);
    if (!s) return 1;
    s->used = 0; h->removes++;
    return 0;
}

static char *dup_text(AuthlasBuf *b) {
    static char buf[8192];
    snprintf(buf, sizeof buf, "%.*s", (int)b->len, (const char *)b->data);
    return buf;
}

int main(void) {
    Host host; memset(&host, 0, sizeof host);
    AuthlasClientStore store = { &host, host_get, host_insert, host_replace, host_remove };
    const char *endpoint = "https://as.example/register";
    const char *body = "{\"redirect_uris\":[\"https://app.example/cb\"],\"token_endpoint_auth_method\":\"none\",\"application_type\":\"web\",\"grant_types\":[\"authorization_code\"],\"response_types\":[\"code\"]}";

    /* Open registration is refused without an initial access token (secure default). */
    AuthlasBuf r = { NULL, 0 };
    int st = authlas_client_register(store, endpoint, NULL, body, NULL, 1000, &r);
    CHECK(st != AUTHLAS_STATUS_OK, "registration without an initial access token is refused by default");
    CHECK(host.inserts == 0, "nothing stored when refused");
    authlas_buf_free(&r);

    /* With open registration enabled in policy, the client is stored and the response carries an id. */
    const char *policy = "{\"open\":true}";
    AuthlasBuf reg = { NULL, 0 };
    st = authlas_client_register(store, endpoint, policy, body, NULL, 1000, &reg);
    CHECK(st == AUTHLAS_STATUS_OK, "registration with open policy succeeds");
    CHECK(host.inserts == 1, "host stored one client");
    char id[64] = {0};
    find_id(dup_text(&reg), id, sizeof id);
    CHECK(id[0] != 0, "response carries client_id");
    /* Registration response must include a registration access token for later read/delete. */
    char *resp = dup_text(&reg);
    CHECK(strstr(resp, "registration_access_token") != NULL, "response includes registration_access_token");
    char token[256] = {0};
    const char *tp = strstr(resp, "\"registration_access_token\":\"");
    if (tp) { tp += strlen("\"registration_access_token\":\""); const char *e = strchr(tp, '"'); if (e) { size_t n = (size_t)(e - tp); if (n >= sizeof token) n = sizeof token - 1; memcpy(token, tp, n); } }
    authlas_buf_free(&reg);

    /* Read with the right token returns metadata. */
    AuthlasBuf rd = { NULL, 0 };
    st = authlas_client_read(store, endpoint, policy, id, token, &rd);
    CHECK(st == AUTHLAS_STATUS_OK && strstr(dup_text(&rd), "app.example/cb") != NULL, "read with the registration token returns metadata");
    authlas_buf_free(&rd);

    /* Read with a wrong token is refused. */
    AuthlasBuf bad = { NULL, 0 };
    CHECK(authlas_client_read(store, endpoint, policy, id, "not-the-token", &bad) != AUTHLAS_STATUS_OK, "read with a wrong token is refused");
    authlas_buf_free(&bad);

    /* Delete with the right token removes the record. */
    AuthlasBuf del = { NULL, 0 };
    st = authlas_client_delete(store, id, token, &del);
    CHECK(st == AUTHLAS_STATUS_OK && host.removes == 1, "delete with the registration token removes the client");
    authlas_buf_free(&del);

    /* Once deleted, read reports the client is gone. */
    AuthlasBuf gone = { NULL, 0 };
    CHECK(authlas_client_read(store, endpoint, policy, id, token, &gone) != AUTHLAS_STATUS_OK, "read after delete is refused");
    authlas_buf_free(&gone);

    printf(failures ? "%d FAILURES\n" : "client callback checks passed\n", failures);
    return failures ? 1 : 0;
}
