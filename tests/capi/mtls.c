/* Mutual-TLS client authentication and certificate-bound tokens (RFC 8705) through the C ABI.
   The certificates are independent fixtures produced by Python cryptography (tests/vectors/certs.json). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "authlas.h"

static int failures = 0;
#define CHECK(c, m) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, m); failures++; } } while (0)

#define NOW 1800000000ULL /* 2027-01-15: inside ec256's window */

static unsigned char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc((size_t)n);
    if (b) *len = fread(b, 1, (size_t)n, f);
    fclose(f);
    return b;
}

static char *text_of(AuthlasBuf *b) {
    static char buf[8192];
    snprintf(buf, sizeof buf, "%.*s", (int)b->len, (const char *)b->data);
    return buf;
}

int main(void) {
    size_t n1 = 0, n2 = 0;
    unsigned char *ec = read_file("tests/capi/fixtures/ec256.der", &n1);
    unsigned char *expired = read_file("tests/capi/fixtures/expired.der", &n2);
    if (!ec || !expired) { printf("cannot read fixtures (run from the repo root)\n"); return 2; }

    const char *reg_pki =
        "{\"client_id\":\"svc\",\"method\":\"tls_client_auth\","
        "\"subject_dn\":\"CN=client.example.org,O=Example\\\\, Inc.,C=US\"}";
    const char *body_ok = "client_id=svc&grant_type=client_credentials";

    /* Verified chain, matching subject: authenticates. */
    AuthlasBuf id = { NULL, 0 };
    int st = authlas_mtls_authenticate(ec, n1, 1, NULL, body_ok, reg_pki, NOW, &id);
    CHECK(st == AUTHLAS_STATUS_OK && strcmp(text_of(&id), "svc") == 0, "a verified certificate with the registered subject authenticates");
    authlas_buf_free(&id);

    /* The TLS layer did not verify the chain: refused, even with the right subject. */
    AuthlasBuf unverified = { NULL, 0 };
    CHECK(authlas_mtls_authenticate(ec, n1, 0, NULL, body_ok, reg_pki, NOW, &unverified) != AUTHLAS_STATUS_OK,
          "the PKI method refuses without a verified chain");
    authlas_buf_free(&unverified);

    /* A client secret next to a certificate is two methods: refused. */
    AuthlasBuf mixed = { NULL, 0 };
    CHECK(authlas_mtls_authenticate(ec, n1, 1, NULL, "client_id=svc&client_secret=x&grant_type=client_credentials", reg_pki, NOW, &mixed) != AUTHLAS_STATUS_OK,
          "mTLS plus a client secret is refused");
    authlas_buf_free(&mixed);

    /* The body names a different client: refused. */
    AuthlasBuf other = { NULL, 0 };
    CHECK(authlas_mtls_authenticate(ec, n1, 1, NULL, "client_id=intruder&grant_type=client_credentials", reg_pki, NOW, &other) != AUTHLAS_STATUS_OK,
          "a certificate presented for a different client_id is refused");
    authlas_buf_free(&other);

    /* Wrong registered subject: refused. */
    const char *reg_wrong =
        "{\"client_id\":\"svc\",\"method\":\"tls_client_auth\",\"subject_dn\":\"CN=someone.else,C=US\"}";
    AuthlasBuf wrongsub = { NULL, 0 };
    CHECK(authlas_mtls_authenticate(ec, n1, 1, NULL, body_ok, reg_wrong, NOW, &wrongsub) != AUTHLAS_STATUS_OK,
          "a certificate whose subject is not the registered one is refused");
    authlas_buf_free(&wrongsub);

    /* Expired certificate: refused even with a verified chain and the right subject. */
    const char *reg_old =
        "{\"client_id\":\"svc\",\"method\":\"tls_client_auth\",\"subject_dn\":\"CN=old\"}";
    AuthlasBuf exp = { NULL, 0 };
    CHECK(authlas_mtls_authenticate(expired, n2, 1, NULL, body_ok, reg_old, NOW, &exp) != AUTHLAS_STATUS_OK,
          "an expired certificate is refused");
    authlas_buf_free(&exp);

    /* Exactly one expected subject: two are refused at registration time. */
    const char *reg_two =
        "{\"client_id\":\"svc\",\"method\":\"tls_client_auth\",\"subject_dn\":\"CN=a\",\"san_dns\":\"b.example\"}";
    AuthlasBuf two = { NULL, 0 };
    CHECK(authlas_mtls_authenticate(ec, n1, 1, NULL, body_ok, reg_two, NOW, &two) != AUTHLAS_STATUS_OK,
          "a registration with two expected subjects is refused");
    authlas_buf_free(&two);

    /* cnf: the thumbprint must equal the fixture's known x5t#S256. */
    AuthlasBuf cnf = { NULL, 0 };
    CHECK(authlas_mtls_cnf(ec, n1, &cnf) == AUTHLAS_STATUS_OK, "cnf is produced");
    CHECK(strstr(text_of(&cnf), "\"x5t#S256\":\"DVQl1OGosbneKBdtIyzo0_Q6WXXpOGv3mrZe1FYXRWo\"") != NULL,
          "cnf carries the certificate thumbprint");
    authlas_buf_free(&cnf);

    /* Resource server: a token bound to this certificate passes; one bound to another fails; an unbound token fails. */
    const char *bound =
        "{\"sub\":\"svc\",\"cnf\":{\"x5t#S256\":\"DVQl1OGosbneKBdtIyzo0_Q6WXXpOGv3mrZe1FYXRWo\"}}";
    const char *bound_other =
        "{\"sub\":\"svc\",\"cnf\":{\"x5t#S256\":\"9mqD4Rhw6ZT69KA2XRVC2LRqxQN4cOF4P236hS37NXM\"}}";
    const char *unbound = "{\"sub\":\"svc\"}";

    AuthlasBuf b1 = { NULL, 0 };
    CHECK(authlas_mtls_check_binding(ec, n1, bound, &b1) == AUTHLAS_STATUS_OK, "a token bound to this certificate is accepted");
    authlas_buf_free(&b1);

    AuthlasBuf b2 = { NULL, 0 };
    CHECK(authlas_mtls_check_binding(ec, n1, bound_other, &b2) != AUTHLAS_STATUS_OK, "a token bound to another certificate is refused");
    authlas_buf_free(&b2);

    AuthlasBuf b3 = { NULL, 0 };
    CHECK(authlas_mtls_check_binding(ec, n1, unbound, &b3) != AUTHLAS_STATUS_OK, "an unbound token is refused at a certificate-bound resource");
    authlas_buf_free(&b3);

    /* Refresh token reuse with the same certificate is allowed; with another certificate it is refused. */
    AuthlasBuf s1 = { NULL, 0 };
    CHECK(authlas_mtls_same_certificate(ec, n1, "DVQl1OGosbneKBdtIyzo0_Q6WXXpOGv3mrZe1FYXRWo", &s1) == AUTHLAS_STATUS_OK, "the bound certificate is the same");
    authlas_buf_free(&s1);
    AuthlasBuf s2 = { NULL, 0 };
    CHECK(authlas_mtls_same_certificate(ec, n1, "9mqD4Rhw6ZT69KA2XRVC2LRqxQN4cOF4P236hS37NXM", &s2) != AUTHLAS_STATUS_OK, "a different certificate is refused");
    authlas_buf_free(&s2);

    free(ec); free(expired);
    printf(failures ? "%d FAILURES\n" : "mtls checks passed\n", failures);
    return failures ? 1 : 0;
}
