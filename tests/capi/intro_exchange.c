/* Token introspection (RFC 7662, RFC 9701) and token exchange (RFC 8693) through the C ABI. */
#include <stdio.h>
#include <string.h>
#include "authlas.h"

static int failures = 0;
#define CHECK(c, m) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, m); failures++; } } while (0)

static char *text_of(AuthlasBuf *b) {
    static char buf[16384];
    snprintf(buf, sizeof buf, "%.*s", (int)b->len, (const char *)b->data);
    return buf;
}

static int has(AuthlasBuf *b, const char *s) { return strstr(text_of(b), s) != NULL; }

int main(void) {
    /* ---- introspection request ---- */
    AuthlasBuf r = { NULL, 0 };
    int st = authlas_introspection_parse_request("token=abc123&token_type_hint=access_token", &r);
    CHECK(st == AUTHLAS_STATUS_OK && has(&r, "\"token\":\"abc123\""), "introspection request parses the token");
    CHECK(has(&r, "\"token_type_hint\":\"access_token\""), "introspection request keeps the hint");
    authlas_buf_free(&r);

    AuthlasBuf nt = { NULL, 0 };
    CHECK(authlas_introspection_parse_request("token_type_hint=access_token", &nt) != AUTHLAS_STATUS_OK, "a request without a token is refused");
    authlas_buf_free(&nt);

    /* ---- introspection response ---- */
    AuthlasBuf inactive = { NULL, 0 };
    st = authlas_introspection_parse_response("{\"active\":false}", &inactive);
    CHECK(st == AUTHLAS_STATUS_OK && has(&inactive, "\"active\":false"), "an inactive response parses");
    authlas_buf_free(&inactive);

    const char *active_resp =
        "{\"active\":true,\"scope\":\"read write\",\"client_id\":\"app\",\"sub\":\"alice\","
        "\"exp\":2000,\"nbf\":900,\"aud\":[\"https://rs.example\"],\"iss\":\"https://as.example\"}";

    AuthlasBuf ok = { NULL, 0 };
    CHECK(authlas_introspection_check(active_resp, "https://rs.example", 1000, 0, &ok) == AUTHLAS_STATUS_OK, "an active token for this resource is usable");
    authlas_buf_free(&ok);

    AuthlasBuf wrongaud = { NULL, 0 };
    CHECK(authlas_introspection_check(active_resp, "https://other-rs.example", 1000, 0, &wrongaud) != AUTHLAS_STATUS_OK,
          "a token issued for another resource is refused");
    authlas_buf_free(&wrongaud);

    AuthlasBuf expired = { NULL, 0 };
    CHECK(authlas_introspection_check(active_resp, "https://rs.example", 2500, 0, &expired) != AUTHLAS_STATUS_OK, "an expired token is refused");
    authlas_buf_free(&expired);

    AuthlasBuf notyet = { NULL, 0 };
    CHECK(authlas_introspection_check(active_resp, "https://rs.example", 100, 0, &notyet) != AUTHLAS_STATUS_OK, "a token before nbf is refused");
    authlas_buf_free(&notyet);

    AuthlasBuf inact = { NULL, 0 };
    CHECK(authlas_introspection_check("{\"active\":false}", "https://rs.example", 1000, 0, &inact) != AUTHLAS_STATUS_OK, "an inactive response is not usable");
    authlas_buf_free(&inact);

    /* ---- RFC 9701: signed introspection response ---- */
    AuthlasBuf key = { NULL, 0 };
    CHECK(authlas_jwk_generate_ec("P-256", &key) == AUTHLAS_STATUS_OK, "an EC signing key is generated");
    char key_json[2048];
    snprintf(key_json, sizeof key_json, "%s", text_of(&key));
    authlas_buf_free(&key);

    AuthlasBuf signed_b = { NULL, 0 };
    st = authlas_introspection_sign_jwt("ES256", key_json, "https://as.example", "https://rs.example", active_resp, &signed_b);
    CHECK(st == AUTHLAS_STATUS_OK && strchr(text_of(&signed_b), '.') != NULL, "an introspection response is signed as a JWT");
    char jwt[8192];
    snprintf(jwt, sizeof jwt, "%s", text_of(&signed_b));
    authlas_buf_free(&signed_b);

    /* The verifier needs the public key; the library strips the private part. */
    AuthlasBuf pubb = { NULL, 0 };
    CHECK(authlas_jwk_public(key_json, &pubb) == AUTHLAS_STATUS_OK, "public key derived from the signing key");
    char pub_json[2048];
    snprintf(pub_json, sizeof pub_json, "%s", text_of(&pubb));
    authlas_buf_free(&pubb);

    AuthlasBuf verified = { NULL, 0 };
    st = authlas_introspection_verify_jwt(jwt, pub_json, "[\"ES256\"]", "https://as.example", "https://rs.example", 0, &verified);  /* 0 = system clock, same clock the signer uses */
    CHECK(st == AUTHLAS_STATUS_OK && has(&verified, "\"sub\":\"alice\""), "a signed response verifies and returns the result");
    authlas_buf_free(&verified);

    AuthlasBuf noalg = { NULL, 0 };
    CHECK(authlas_introspection_verify_jwt(jwt, pub_json, "[]", "https://as.example", "https://rs.example", 1000, &noalg) != AUTHLAS_STATUS_OK,
          "an empty algorithm list is refused");
    authlas_buf_free(&noalg);

    AuthlasBuf wrongiss = { NULL, 0 };
    CHECK(authlas_introspection_verify_jwt(jwt, pub_json, "[\"ES256\"]", "https://evil.example", "https://rs.example", 1000, &wrongiss) != AUTHLAS_STATUS_OK,
          "a response from the wrong issuer is refused");
    authlas_buf_free(&wrongiss);

    AuthlasBuf other = { NULL, 0 };
    CHECK(authlas_jwk_generate_ec("P-256", &other) == AUTHLAS_STATUS_OK, "a second key is generated");
    char other_json[2048];
    snprintf(other_json, sizeof other_json, "%s", text_of(&other));
    authlas_buf_free(&other);
    AuthlasBuf otherpub = { NULL, 0 };
    CHECK(authlas_jwk_public(other_json, &otherpub) == AUTHLAS_STATUS_OK, "public key derived from the second key");
    snprintf(other_json, sizeof other_json, "%s", text_of(&otherpub));
    authlas_buf_free(&otherpub);
    AuthlasBuf wrongkey = { NULL, 0 };
    CHECK(authlas_introspection_verify_jwt(jwt, other_json, "[\"ES256\"]", "https://as.example", "https://rs.example", 1000, &wrongkey) != AUTHLAS_STATUS_OK,
          "a response checked against the wrong public key is refused");
    authlas_buf_free(&wrongkey);

    /* ---- token exchange ---- */
    const char *rules =
        "[{\"client_id\":\"gateway\",\"subject_token_types\":[\"urn:ietf:params:oauth:token-type:access_token\"],"
        "\"requested_token_types\":[\"urn:ietf:params:oauth:token-type:access_token\"],"
        "\"allowed_targets\":[\"https://billing.example\"],\"allow_delegation\":false}]";
    const char *subj = "{\"sub\":\"alice\",\"iss\":\"https://as.example\"}";

    AuthlasBuf ex = { NULL, 0 };
    st = authlas_exchange_decide(rules, "gateway", subj, "read write", NULL,
        "{\"subject_token_type\":\"urn:ietf:params:oauth:token-type:access_token\",\"audiences\":[\"https://billing.example\"],\"scope\":\"read\"}", &ex);
    CHECK(st == AUTHLAS_STATUS_OK && has(&ex, "\"subject\":\"alice\""), "an allowed exchange is decided for alice");
    CHECK(has(&ex, "\"scope\":\"read\""), "the exchanged scope is the narrowed scope");
    authlas_buf_free(&ex);

    AuthlasBuf target = { NULL, 0 };
    CHECK(authlas_exchange_decide(rules, "gateway", subj, "read", NULL,
        "{\"subject_token_type\":\"urn:ietf:params:oauth:token-type:access_token\",\"audiences\":[\"https://evil.example\"]}", &target) != AUTHLAS_STATUS_OK,
          "an exchange for an unlisted target is refused");
    authlas_buf_free(&target);

    AuthlasBuf grow = { NULL, 0 };
    CHECK(authlas_exchange_decide(rules, "gateway", subj, "read", NULL,
        "{\"subject_token_type\":\"urn:ietf:params:oauth:token-type:access_token\",\"audiences\":[\"https://billing.example\"],\"scope\":\"read write admin\"}", &grow) != AUTHLAS_STATUS_OK,
          "a scope larger than the subject token is refused");
    authlas_buf_free(&grow);

    AuthlasBuf unknown = { NULL, 0 };
    CHECK(authlas_exchange_decide(rules, "stranger", subj, "read", NULL,
        "{\"subject_token_type\":\"urn:ietf:params:oauth:token-type:access_token\",\"audiences\":[\"https://billing.example\"]}", &unknown) != AUTHLAS_STATUS_OK,
          "a client with no exchange rule is refused");
    authlas_buf_free(&unknown);

    AuthlasBuf deleg = { NULL, 0 };
    CHECK(authlas_exchange_decide(rules, "gateway", subj, "read", "{\"sub\":\"svc-bot\",\"iss\":\"https://as.example\"}",
        "{\"subject_token_type\":\"urn:ietf:params:oauth:token-type:access_token\",\"actor_token_type\":\"urn:ietf:params:oauth:token-type:access_token\",\"audiences\":[\"https://billing.example\"]}", &deleg) != AUTHLAS_STATUS_OK,
          "delegation is refused when the rule does not allow it");
    authlas_buf_free(&deleg);

    AuthlasBuf resp = { NULL, 0 };
    st = authlas_exchange_response("tok-xyz", "urn:ietf:params:oauth:token-type:access_token", 300, "read", &resp);
    CHECK(st == AUTHLAS_STATUS_OK && has(&resp, "\"token_type\":\"Bearer\"") && has(&resp, "\"expires_in\":300"), "the exchange response has the RFC 8693 fields");
    authlas_buf_free(&resp);

    printf(failures ? "%d FAILURES\n" : "introspection and exchange checks passed\n", failures);
    return failures ? 1 : 0;
}
