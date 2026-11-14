/* Revocation through host callbacks (RFC 7009). The "host" stores tokens in a small table. */
#include <stdio.h>
#include <string.h>
#include "authlas.h"

#define MAX 4
typedef struct { char token[64]; char client[32]; char grant[32]; char jti[32]; int kind; /* 1 refresh, 2 access */ int revoked; } Tok;
typedef struct { Tok t[MAX]; int grant_revokes; int jti_revokes; } Host;

static int failures = 0;
#define CHECK(c, m) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, m); failures++; } } while (0)

static int lookup(void *user, const char *token, const char *hint, AuthlasBuf *out) {
    (void)hint;
    Host *h = (Host *)user;
    for (int i = 0; i < MAX; i++) {
        if (h->t[i].kind && strcmp(h->t[i].token, token) == 0 && !h->t[i].revoked) {
            char json[256];
            if (h->t[i].kind == 1)
                snprintf(json, sizeof json, "{\"kind\":\"refresh\",\"client_id\":\"%s\",\"grant_id\":\"%s\"}", h->t[i].client, h->t[i].grant);
            else
                snprintf(json, sizeof json, "{\"kind\":\"access\",\"client_id\":\"%s\",\"grant_id\":\"%s\",\"jti\":\"%s\"}", h->t[i].client, h->t[i].grant, h->t[i].jti);
            return authlas_buf_write(out, (const unsigned char *)json, strlen(json));
        }
    }
    return authlas_buf_write(out, NULL, 0);
}

static int revoke_grant(void *user, const char *grant_id) {
    Host *h = (Host *)user;
    h->grant_revokes++;
    for (int i = 0; i < MAX; i++) if (strcmp(h->t[i].grant, grant_id) == 0) h->t[i].revoked = 1;
    return 0;
}

static int revoke_jti(void *user, const char *jti) {
    Host *h = (Host *)user;
    h->jti_revokes++;
    for (int i = 0; i < MAX; i++) if (strcmp(h->t[i].jti, jti) == 0) h->t[i].revoked = 1;
    return 0;
}

static const char *run_revoke(AuthlasRevocationStore s, const char *client, const char *body, char *word, size_t n) {
    AuthlasBuf o = { NULL, 0 };
    int st = authlas_revoke(s, client, body, &o);
    if (st != AUTHLAS_STATUS_OK) { snprintf(word, n, "ERR%d", st); authlas_buf_free(&o); return word; }
    snprintf(word, n, "%.*s", (int)o.len, (const char *)o.data);
    authlas_buf_free(&o);
    return word;
}

int main(void) {
    Host host; memset(&host, 0, sizeof host);
    snprintf(host.t[0].token, sizeof host.t[0].token, "%s", "rt-alice"); snprintf(host.t[0].client, sizeof host.t[0].client, "%s", "app");   snprintf(host.t[0].grant, sizeof host.t[0].grant, "%s", "g1"); host.t[0].kind = 1;
    snprintf(host.t[1].token, sizeof host.t[1].token, "%s", "at-bob");   snprintf(host.t[1].client, sizeof host.t[1].client, "%s", "other"); snprintf(host.t[1].grant, sizeof host.t[1].grant, "%s", "g2"); snprintf(host.t[1].jti, sizeof host.t[1].jti, "%s", "j2"); host.t[1].kind = 2;
    snprintf(host.t[2].token, sizeof host.t[2].token, "%s", "at-alice"); snprintf(host.t[2].client, sizeof host.t[2].client, "%s", "app");   snprintf(host.t[2].grant, sizeof host.t[2].grant, "%s", "g1"); snprintf(host.t[2].jti, sizeof host.t[2].jti, "%s", "j1"); host.t[2].kind = 2;

    AuthlasRevocationStore s = { &host, lookup, revoke_grant, revoke_jti };
    char w[32];

    CHECK(strcmp(run_revoke(s, "app", "token=at-bob", w, sizeof w), "not_yours") == 0, "another client's token is not revoked");
    CHECK(host.jti_revokes == 0 && host.grant_revokes == 0, "no state changed for another client's token");
    CHECK(strcmp(run_revoke(s, "app", "token=missing", w, sizeof w), "nothing") == 0, "unknown token reports nothing");
    CHECK(strcmp(run_revoke(s, "app", "token=at-alice", w, sizeof w), "revoked") == 0, "own access token is revoked");
    CHECK(host.jti_revokes == 1, "access token revoked by jti");
    CHECK(strcmp(run_revoke(s, "app", "token=rt-alice", w, sizeof w), "revoked") == 0, "own refresh token is revoked");
    CHECK(host.grant_revokes == 1, "refresh revocation revokes the grant");
    {
        AuthlasBuf o = { NULL, 0 };
        int st = authlas_revoke(s, "app", "token_type_hint=refresh_token", &o);
        CHECK(st != AUTHLAS_STATUS_OK, "a request without a token is refused");
        authlas_buf_free(&o);
    }

    printf(failures ? "%d FAILURES\n" : "revocation callback checks passed\n", failures);
    return failures ? 1 : 0;
}
