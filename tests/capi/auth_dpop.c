/* Client authentication and DPoP through the C ABI (RFC 6749 2.3, RFC 9449). */
#include <stdio.h>
#include <string.h>
#include "authlas.h"

static int failures = 0;
#define CHECK(c, m) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, m); failures++; } } while (0)

/* Replay store: remembers keys it has seen. Returns 1 for new, 0 for replay. */
#define RMAX 32
typedef struct { char keys[RMAX][256]; int n; int calls; } Replay;

static int first_use(void *user, const char *key, unsigned long long exp, unsigned long long now) {
    Replay *r = (Replay *)user;
    (void)exp; (void)now;
    r->calls++;
    for (int i = 0; i < r->n; i++) if (strcmp(r->keys[i], key) == 0) return 0;
    if (r->n >= RMAX) return -1;
    snprintf(r->keys[r->n++], sizeof r->keys[0], "%s", key);
    return 1;
}

static char *text_of(AuthlasBuf *b) {
    static char buf[8192];
    snprintf(buf, sizeof buf, "%.*s", (int)b->len, (const char *)b->data);
    return buf;
}

static int auth(const char *presented, const char *registered, AuthlasReplayCache rc, AuthlasBuf *out) {
    return authlas_client_authenticate(presented, registered, "https://as.example/token", NULL, rc, 1000, out);
}

int main(void) {
    Replay rp; memset(&rp, 0, sizeof rp);
    AuthlasReplayCache rc = { &rp, first_use };
    AuthlasReplayCache none = { NULL, NULL };

    /* Plain-text registration (secret_is_hash = false). The hashed path is covered by the Rust tests. */
    const char *reg_basic =
        "{\"client_id\":\"app\",\"method\":\"client_secret_basic\",\"secret\":\"s3cret\",\"secret_is_hash\":false}";

    AuthlasBuf o = { NULL, 0 };
    int st = auth("{\"method\":\"client_secret_basic\",\"client_id\":\"app\",\"secret\":\"s3cret\"}", reg_basic, none, &o);
    CHECK(st == AUTHLAS_STATUS_OK && strcmp(text_of(&o), "app") == 0, "correct basic secret authenticates");
    authlas_buf_free(&o);

    AuthlasBuf bad = { NULL, 0 };
    CHECK(auth("{\"method\":\"client_secret_basic\",\"client_id\":\"app\",\"secret\":\"wrong\"}", reg_basic, none, &bad) != AUTHLAS_STATUS_OK,
          "wrong secret is refused");
    authlas_buf_free(&bad);

    AuthlasBuf wrongid = { NULL, 0 };
    CHECK(auth("{\"method\":\"client_secret_basic\",\"client_id\":\"other\",\"secret\":\"s3cret\"}", reg_basic, none, &wrongid) != AUTHLAS_STATUS_OK,
          "right secret for a different client_id is refused");
    authlas_buf_free(&wrongid);

    AuthlasBuf wrongmethod = { NULL, 0 };
    CHECK(auth("{\"method\":\"client_secret_post\",\"client_id\":\"app\",\"secret\":\"s3cret\"}", reg_basic, none, &wrongmethod) != AUTHLAS_STATUS_OK,
          "presenting the secret by a method the client did not register is refused");
    authlas_buf_free(&wrongmethod);

    /* Public client: method none, client_id only. */
    const char *reg_none = "{\"client_id\":\"spa\",\"method\":\"none\"}";
    AuthlasBuf pub = { NULL, 0 };
    CHECK(auth("{\"method\":\"none\",\"client_id\":\"spa\"}", reg_none, none, &pub) == AUTHLAS_STATUS_OK, "public client authenticates with client_id only");
    authlas_buf_free(&pub);

    /* DPoP proof: build a proof and check the rest of the path. */
    const char *ec_key =
        "{\"kty\":\"EC\",\"crv\":\"P-256\","
        "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","
        "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\","
        "\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\"}";
    AuthlasBuf proof = { NULL, 0 };
    st = authlas_dpop_build(ec_key, "POST", "https://rs.example/resource", NULL, NULL, "ES256", &proof);
    CHECK(st == AUTHLAS_STATUS_OK && proof.len > 0, "a DPoP proof is built");
    CHECK(proof.len > 0 && strchr(text_of(&proof), '.') != NULL, "the proof is a compact JWT");
    authlas_buf_free(&proof);

    /* A public key must not sign a proof. */
    const char *pub_only = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}";
    AuthlasBuf nopriv = { NULL, 0 };
    CHECK(authlas_dpop_build(pub_only, "POST", "https://rs.example/r", NULL, NULL, "ES256", &nopriv) != AUTHLAS_STATUS_OK,
          "a proof is refused without a private key");
    authlas_buf_free(&nopriv);

    /* HMAC algorithms are not allowed for DPoP. */
    AuthlasBuf hmac = { NULL, 0 };
    CHECK(authlas_dpop_build(ec_key, "POST", "https://rs.example/r", NULL, NULL, "HS256", &hmac) != AUTHLAS_STATUS_OK,
          "an HMAC algorithm is refused for DPoP");
    authlas_buf_free(&hmac);

    /* Access token hash is stable and non-empty. */
    AuthlasBuf ath1 = { NULL, 0 }, ath2 = { NULL, 0 };
    CHECK(authlas_dpop_ath("token-abc", &ath1) == AUTHLAS_STATUS_OK, "ath computed");
    CHECK(authlas_dpop_ath("token-abc", &ath2) == AUTHLAS_STATUS_OK && strcmp(text_of(&ath1), text_of(&ath2)) == 0, "ath is deterministic");
    authlas_buf_free(&ath1); authlas_buf_free(&ath2);

    /* Nonce: valid when fresh, refused when tampered with or when the secret differs. */
    const unsigned char secret[32] = "0123456789abcdef0123456789abcdef";
    AuthlasBuf nonce = { NULL, 0 };
    CHECK(authlas_dpop_nonce_issue(secret, sizeof secret, 300, 1000, &nonce) == AUTHLAS_STATUS_OK, "nonce is issued");
    char nv[512] = {0};
    snprintf(nv, sizeof nv, "%s", text_of(&nonce));
    authlas_buf_free(&nonce);
    AuthlasBuf chk = { NULL, 0 };
    CHECK(authlas_dpop_nonce_check(secret, sizeof secret, 300, nv, 1010, &chk) == AUTHLAS_STATUS_OK, "fresh nonce is valid");
    authlas_buf_free(&chk);

    char tampered[512];
    snprintf(tampered, sizeof tampered, "%sX", nv);
    AuthlasBuf tc = { NULL, 0 };
    CHECK(authlas_dpop_nonce_check(secret, sizeof secret, 300, tampered, 1010, &tc) != AUTHLAS_STATUS_OK, "tampered nonce is refused");
    authlas_buf_free(&tc);

    const unsigned char other[32] = "fedcba9876543210fedcba9876543210";
    AuthlasBuf oc = { NULL, 0 };
    CHECK(authlas_dpop_nonce_check(other, sizeof other, 300, nv, 1010, &oc) != AUTHLAS_STATUS_OK, "nonce from another secret is refused");
    authlas_buf_free(&oc);

    AuthlasBuf ex = { NULL, 0 };
    CHECK(authlas_dpop_nonce_check(secret, sizeof secret, 300, nv, 1000 + 301, &ex) != AUTHLAS_STATUS_OK, "expired nonce is refused");
    authlas_buf_free(&ex);

    /* A short secret is refused. */
    AuthlasBuf sh = { NULL, 0 };
    CHECK(authlas_dpop_nonce_issue(secret, 8, 300, 1000, &sh) != AUTHLAS_STATUS_OK, "a short nonce secret is refused");
    authlas_buf_free(&sh);

    printf(failures ? "%d FAILURES\n" : "client auth and DPoP checks passed\n", failures);
    return failures ? 1 : 0;
}
