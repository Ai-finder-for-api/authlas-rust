/* C smoke test for the Authlas ABI. Compiled with the generated header; links against authlas.dll.lib.
 * Exit code 0 means every check passed. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "authlas.h"

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL line %d: %s\n", __LINE__, msg); failures++; } } while (0)

static AuthlasBuf B(void) { AuthlasBuf b = { NULL, 0 }; return b; }
static int has(const AuthlasBuf *b, const char *needle) { return b->data && strstr((const char *)b->data, needle) != NULL; }
static int err_has(const char *needle) { return strstr(authlas_last_error(), needle) != NULL; }

int main(void) {
    CHECK(authlas_abi_version() == AUTHLAS_ABI_VERSION, "abi version");
    CHECK(strlen(authlas_version()) > 0, "version");
    CHECK(strlen(authlas_backend()) > 0, "backend name");
    printf("authlas %s abi %u backend %s\n", authlas_version(), authlas_abi_version(), authlas_backend());

    /* keys */
    AuthlasBuf key = B(), pub = B(), tp = B();
    CHECK(authlas_jwk_generate_ec("P-256", &key) == AUTHLAS_STATUS_OK, "generate ec");
    CHECK(has(&key, "\"d\""), "private key has d");
    CHECK(authlas_jwk_public((const char *)key.data, &pub) == AUTHLAS_STATUS_OK, "public");
    CHECK(!has(&pub, "\"d\""), "public key has no d");
    CHECK(authlas_jwk_thumbprint((const char *)pub.data, &tp) == AUTHLAS_STATUS_OK && tp.len == 43, "thumbprint length");

    /* JWT sign + verify */
    time_t now = time(NULL);
    char claims[512];
    snprintf(claims, sizeof claims, "{\"iss\":\"https://as.example\",\"aud\":\"rs\",\"sub\":\"alice\",\"exp\":%lld,\"iat\":%lld}", (long long)now + 300, (long long)now);
    AuthlasBuf tok = B();
    CHECK(authlas_jwt_sign("ES256", (const char *)key.data, claims, NULL, &tok) == AUTHLAS_STATUS_OK, "jwt sign");
    const char *opts = "{\"algs\":[\"ES256\"],\"issuer\":\"https://as.example\",\"audience\":\"rs\"}";
    AuthlasBuf v = B();
    CHECK(authlas_jwt_verify((const char *)tok.data, (const char *)pub.data, opts, NULL, &v) == AUTHLAS_STATUS_OK, "jwt verify");
    CHECK(has(&v, "\"alice\""), "claims returned");
    authlas_buf_free(&v);

    /* wrong audience -> claim error with JSON detail */
    const char *bad = "{\"algs\":[\"ES256\"],\"issuer\":\"https://as.example\",\"audience\":\"other\"}";
    v = B();
    CHECK(authlas_jwt_verify((const char *)tok.data, (const char *)pub.data, bad, NULL, &v) == AUTHLAS_STATUS_CLAIM, "wrong audience");
    CHECK(v.data == NULL && v.len == 0, "no output on failure");
    CHECK(err_has("\"kind\":\"claim\""), "error json kind");

    /* algs is mandatory */
    CHECK(authlas_jwt_verify((const char *)tok.data, (const char *)pub.data, "{\"issuer\":\"https://as.example\",\"audience\":\"rs\"}", NULL, &v) == AUTHLAS_STATUS_INVALID_ARGUMENT, "algs required");
    /* tampered token */
    char *t2 = strdup((const char *)tok.data);
    t2[tok.len - 3] = (t2[tok.len - 3] == 'A') ? 'B' : 'A';
    CHECK(authlas_jwt_verify(t2, (const char *)pub.data, opts, NULL, &v) == AUTHLAS_STATUS_BAD_SIGNATURE, "tampered");
    free(t2);
    /* alg confusion: HS256 allowed list does not include ES256 */
    CHECK(authlas_jwt_verify((const char *)tok.data, (const char *)pub.data, "{\"algs\":[\"HS256\"],\"issuer\":\"https://as.example\",\"audience\":\"rs\"}", NULL, &v) != AUTHLAS_STATUS_OK, "alg not allowed");

    /* null handling never crashes */
    CHECK(authlas_jwt_verify(NULL, (const char *)pub.data, opts, NULL, &v) == AUTHLAS_STATUS_INVALID_ARGUMENT, "null token");
    CHECK(authlas_jwt_verify((const char *)tok.data, NULL, opts, NULL, &v) == AUTHLAS_STATUS_INVALID_ARGUMENT, "null key");
    CHECK(authlas_jwt_verify((const char *)tok.data, (const char *)pub.data, opts, NULL, NULL) == AUTHLAS_STATUS_INVALID_ARGUMENT, "null out");
    CHECK(authlas_jws_sign("ES256", (const char *)key.data, NULL, NULL, 0, &v) == AUTHLAS_STATUS_OK, "empty payload with null pointer");
    authlas_buf_free(&v);
    CHECK(authlas_jws_sign("ES256", (const char *)key.data, NULL, NULL, 5, &v) == AUTHLAS_STATUS_INVALID_ARGUMENT, "null payload with length");
    /* invalid UTF-8 */
    CHECK(authlas_jwk_public("\xff\xfe", &v) == AUTHLAS_STATUS_INVALID_ARGUMENT, "bad utf-8");

    /* replay cache */
    AuthlasReplay *rc = authlas_replay_new();
    char c2[512];
    snprintf(c2, sizeof c2, "{\"iss\":\"https://as.example\",\"aud\":\"rs\",\"sub\":\"a\",\"jti\":\"j1\",\"exp\":%lld}", (long long)now + 300);
    AuthlasBuf t3 = B();
    CHECK(authlas_jwt_sign("ES256", (const char *)key.data, c2, NULL, &t3) == AUTHLAS_STATUS_OK, "sign jti");
    const char *ropts = "{\"algs\":[\"ES256\"],\"issuer\":\"https://as.example\",\"audience\":\"rs\"}";
    v = B();
    CHECK(authlas_jwt_verify((const char *)t3.data, (const char *)pub.data, ropts, rc, &v) == AUTHLAS_STATUS_OK, "first use");
    authlas_buf_free(&v);
    CHECK(authlas_jwt_verify((const char *)t3.data, (const char *)pub.data, ropts, rc, &v) == AUTHLAS_STATUS_CLAIM, "replayed");
    authlas_replay_free(rc);
    authlas_replay_free(NULL);
    authlas_buf_free(&t3);

    /* PKCE */
    AuthlasBuf p = B(), ok = B();
    CHECK(authlas_pkce_new(&p) == AUTHLAS_STATUS_OK && has(&p, "\"S256\""), "pkce");
    authlas_buf_free(&p);
    CHECK(authlas_pkce_verify("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", &ok) == AUTHLAS_STATUS_OK, "rfc7636 vector");
    CHECK(authlas_pkce_verify("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "wrongverifierwrongverifierwrongverifierwrongverifier", &ok) != AUTHLAS_STATUS_OK, "wrong verifier");

    /* redirect URIs */
    int m = -1;
    CHECK(authlas_redirect_matches("https://a.example/cb", "https://a.example/cb", &m) == 0 && m == 1, "same uri");
    CHECK(authlas_redirect_matches("https://a.example/cb", "https://a.example/cb/", &m) == 0 && m == 0, "trailing slash differs");
    CHECK(authlas_redirect_validate("http://app.example/cb", "web", &ok) != AUTHLAS_STATUS_OK, "http web uri");
    CHECK(authlas_redirect_validate("https://app.example/cb", "web", &ok) == AUTHLAS_STATUS_OK, "https web uri");

    /* bearer */
    AuthlasBuf r = B();
    CHECK(authlas_bearer_parse("Bearer abc.def", &r) == AUTHLAS_STATUS_OK && has(&r, "\"Bearer\""), "bearer parse");
    authlas_buf_free(&r);
    CHECK(authlas_bearer_parse("Basic Zm9v", &r) == AUTHLAS_STATUS_OAUTH, "basic is not a bearer token");
    CHECK(err_has("\"error\":\"invalid_token\"") && err_has("\"status\":401"), "oauth error json");

    /* DPoP round trip */
    AuthlasBuf proof = B(), dv = B();
    CHECK(authlas_dpop_proof("ES256", (const char *)key.data, "GET", "https://rs.example/data", "tok", NULL, &proof) == AUTHLAS_STATUS_OK, "dpop proof");
    char dopts[512];
    snprintf(dopts, sizeof dopts, "{\"algs\":[\"ES256\"],\"method\":\"GET\",\"url\":\"https://rs.example/data\",\"access_token\":\"tok\"}");
    CHECK(authlas_dpop_verify((const char *)proof.data, dopts, NULL, &dv) == AUTHLAS_STATUS_OK && has(&dv, (const char *)tp.data), "dpop verify, jkt equals thumbprint");
    authlas_buf_free(&dv);
    snprintf(dopts, sizeof dopts, "{\"algs\":[\"ES256\"],\"method\":\"POST\",\"url\":\"https://rs.example/data\",\"access_token\":\"tok\"}");
    CHECK(authlas_dpop_verify((const char *)proof.data, dopts, NULL, &dv) == AUTHLAS_STATUS_OAUTH && err_has("invalid_dpop_proof"), "dpop wrong method");
    authlas_buf_free(&proof);

    /* JWE round trip with a fresh symmetric key */
    const char *oct = "{\"kty\":\"oct\",\"k\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\"}";
    AuthlasBuf e = B(), d = B();
    CHECK(authlas_jwe_encrypt("A256KW", "A256GCM", oct, NULL, (const uint8_t *)"secret", 6, &e) == AUTHLAS_STATUS_OK, "jwe encrypt");
    CHECK(authlas_jwe_decrypt((const char *)e.data, oct, "{\"algs\":[\"A256KW\"],\"encs\":[\"A256GCM\"]}", &d) == AUTHLAS_STATUS_OK && d.len == 6 && memcmp(d.data, "secret", 6) == 0, "jwe decrypt");
    authlas_buf_free(&d);
    CHECK(authlas_jwe_decrypt((const char *)e.data, oct, "{\"algs\":[\"A128KW\"],\"encs\":[\"A256GCM\"]}", &d) != AUTHLAS_STATUS_OK, "alg not on the accept list");
    CHECK(authlas_jwe_decrypt((const char *)e.data, oct, "{}", &d) == AUTHLAS_STATUS_INVALID_ARGUMENT, "accept lists required");
    CHECK(authlas_jwe_encrypt("RSA1_5", "A256GCM", oct, NULL, (const uint8_t *)"x", 1, &d) == AUTHLAS_STATUS_ALGORITHM, "RSA1_5 refused");
    authlas_buf_free(&e);

    /* SD-JWT: issue, present with key binding, verify */
    AuthlasBuf hkey = B(), hpub = B();
    CHECK(authlas_jwk_generate_ec("P-256", &hkey) == AUTHLAS_STATUS_OK && authlas_jwk_public((const char *)hkey.data, &hpub) == AUTHLAS_STATUS_OK, "holder key");
    char iopts[2048];
    snprintf(iopts, sizeof iopts, "{\"alg\":\"ES256\",\"typ\":\"example+sd-jwt\",\"decoys\":2,\"hide\":[\"given_name\",\"family_name\"],\"holder_jwk\":%s}", (const char *)hpub.data);
    char sdc[512];
    snprintf(sdc, sizeof sdc, "{\"iss\":\"https://issuer.example\",\"sub\":\"u1\",\"exp\":%lld,\"given_name\":\"John\",\"family_name\":\"Doe\"}", (long long)now + 3600);
    AuthlasBuf iss = B();
    CHECK(authlas_sdjwt_issue(sdc, (const char *)key.data, iopts, &iss) == AUTHLAS_STATUS_OK, "sdjwt issue");
    /* pull "sd_jwt" value out of the JSON */
    char *sd = strstr((char *)iss.data, "\"sd_jwt\":\""); CHECK(sd != NULL, "sd_jwt member");
    sd += 10; char *end = strchr(sd, '"'); *end = 0;
    char popts[4096];
    snprintf(popts, sizeof popts, "{\"reveal\":[0],\"key_binding\":{\"alg\":\"ES256\",\"jwk\":%s,\"audience\":\"https://verifier.example\",\"nonce\":\"n-1\"}}", (const char *)hkey.data);
    AuthlasBuf pres = B();
    CHECK(authlas_sdjwt_present(sd, popts, &pres) == AUTHLAS_STATUS_OK, "sdjwt present");
    const char *vopts = "{\"algs\":[\"ES256\"],\"issuer\":\"https://issuer.example\",\"key_binding\":{\"algs\":[\"ES256\"],\"audience\":\"https://verifier.example\",\"nonce\":\"n-1\"}}";
    AuthlasBuf sv = B();
    CHECK(authlas_sdjwt_verify((const char *)pres.data, (const char *)pub.data, vopts, &sv) == AUTHLAS_STATUS_OK, "sdjwt verify");
    CHECK(has(&sv, "\"key_binding_verified\":true"), "key binding verified");
    CHECK((has(&sv, "John") ? 1 : 0) + (has(&sv, "Doe") ? 1 : 0) == 1, "exactly one of the two hidden claims was revealed");
    authlas_buf_free(&sv);
    const char *wrong_nonce = "{\"algs\":[\"ES256\"],\"issuer\":\"https://issuer.example\",\"key_binding\":{\"algs\":[\"ES256\"],\"audience\":\"https://verifier.example\",\"nonce\":\"other\"}}";
    CHECK(authlas_sdjwt_verify((const char *)pres.data, (const char *)pub.data, wrong_nonce, &sv) != AUTHLAS_STATUS_OK, "replayed presentation with another nonce");
    authlas_buf_free(&pres); authlas_buf_free(&iss); authlas_buf_free(&hkey); authlas_buf_free(&hpub);

    /* slice 1: JOSE inspection, nested JWT, SD-JWT helpers, SSRF, time */
    {
        AuthlasBuf ek = B(), epub = B(), ph = B(), pc = B(), nested = B(), dec = B();
        CHECK(authlas_jwk_generate_ec("P-256", &ek) == AUTHLAS_STATUS_OK, "slice1 key");
        CHECK(authlas_jwk_public((const char *)ek.data, &epub) == AUTHLAS_STATUS_OK, "slice1 public");
        char inner_claims[256];
        snprintf(inner_claims, sizeof inner_claims, "{\"iss\":\"https://as.example\",\"aud\":\"rs\",\"sub\":\"bob\",\"exp\":%lld,\"iat\":%lld}", (long long)now + 300, (long long)now);
        AuthlasBuf inner = B();
        CHECK(authlas_jwt_sign("ES256", (const char *)ek.data, inner_claims, NULL, &inner) == AUTHLAS_STATUS_OK, "slice1 inner jwt");

        CHECK(authlas_jws_peek_header((const char *)inner.data, &ph) == AUTHLAS_STATUS_OK && has(&ph, "\"ES256\""), "jws peek header");
        CHECK(authlas_jwt_peek_claims((const char *)inner.data, &pc) == AUTHLAS_STATUS_OK && has(&pc, "\"bob\""), "jwt peek claims");
        authlas_buf_free(&ph); authlas_buf_free(&pc);

        const char *enc_opts = "{\"alg\":\"ECDH-ES\",\"enc\":\"A256GCM\",\"key\":";
        char nopts[2048];
        snprintf(nopts, sizeof nopts, "%s%s}", enc_opts, (const char *)epub.data);
        CHECK(authlas_jwt_encrypt_nested((const char *)inner.data, nopts, &nested) == AUTHLAS_STATUS_OK, "nested encrypt");
        AuthlasBuf je = B();
        CHECK(authlas_jwe_peek_header((const char *)nested.data, &je) == AUTHLAS_STATUS_OK && has(&je, "\"A256GCM\""), "jwe peek header");
        authlas_buf_free(&je);

        authlas_buf_free(&ek); authlas_buf_free(&epub); authlas_buf_free(&inner); authlas_buf_free(&nested); authlas_buf_free(&dec);
    }

    {
        AuthlasBuf sp = B(), dsc = B(), dg = B(), nm = B();
        const char *sd = "eyJhbGc.payload.sig~WyJzYWx0IiwgIm5hbWUiLCAiSm9obiJd~";
        CHECK(authlas_sdjwt_split(sd, &sp) == AUTHLAS_STATUS_OK && has(&sp, "\"disclosures\""), "sdjwt split");
        const char *disc = "WyJzYWx0IiwgIm5hbWUiLCAiSm9obiJd";
        CHECK(authlas_sdjwt_describe(disc, &dsc) == AUTHLAS_STATUS_OK && has(&dsc, "\"name\":\"name\"") && has(&dsc, "John"), "sdjwt describe");
        CHECK(authlas_sdjwt_disclosure_digest(disc, "sha-256", &dg) == AUTHLAS_STATUS_OK && dg.len > 0, "sdjwt digest");
        CHECK(authlas_status_name(0, &nm) == AUTHLAS_STATUS_OK && has(&nm, "VALID"), "status name");
        authlas_buf_free(&sp); authlas_buf_free(&dsc); authlas_buf_free(&dg); authlas_buf_free(&nm);
    }

    {
        AuthlasBuf su = B();
        CHECK(authlas_ssrf_check("https://example.com/jwks", &su) == AUTHLAS_STATUS_OK, "ssrf public https allowed");
        authlas_buf_free(&su);
        CHECK(authlas_ssrf_check("http://example.com/jwks", &su) != AUTHLAS_STATUS_OK, "ssrf refuses plain http");
        CHECK(authlas_ssrf_check("https://127.0.0.1/", &su) != AUTHLAS_STATUS_OK, "ssrf refuses loopback literal");
        int pub_flag = -1;
        CHECK(authlas_is_public_ip("8.8.8.8", &pub_flag) == AUTHLAS_STATUS_OK && pub_flag == 1, "8.8.8.8 is public");
        CHECK(authlas_is_public_ip("10.0.0.1", &pub_flag) == AUTHLAS_STATUS_OK && pub_flag == 0, "10.0.0.1 is private");
        CHECK(authlas_unix_now() > 1700000000ULL, "unix_now is sane");
    }

    /* slice 2: PKCE, scopes, metadata, MCP discovery, WWW-Authenticate, RAR */
    {
        AuthlasBuf pk = B(), sc = B(), ch = B(), wa = B(), mu = B(), ru = B(), rar = B(), bh = B();
        CHECK(authlas_pkce_generate(&pk) == AUTHLAS_STATUS_OK && has(&pk, "\"S256\""), "pkce generate");
        CHECK(authlas_pkce_s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", &ch) == AUTHLAS_STATUS_OK
              && strncmp((const char *)ch.data, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", 43) == 0, "rfc7636 challenge");
        CHECK(authlas_pkce_valid_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == 1, "valid verifier");
        CHECK(authlas_pkce_valid_verifier("short") == 0, "short verifier refused");
        CHECK(authlas_scope_parse("read write", &sc) == AUTHLAS_STATUS_OK && has(&sc, "\"read\""), "scope parse");
        CHECK(authlas_scope_parse("", &sc) != AUTHLAS_STATUS_OK, "empty scope refused");
        CHECK(authlas_mcp_resource_metadata_urls("https://mcp.example/server", &mu) == AUTHLAS_STATUS_OK && mu.len > 0, "mcp metadata urls");
        CHECK(authlas_mcp_as_discovery_urls("https://as.example", &ru) == AUTHLAS_STATUS_OK && ru.len > 0, "as discovery urls");
        CHECK(authlas_www_authenticate_parse("Bearer realm=\"x\", resource_metadata=\"https://rs.example/.well-known/oauth-protected-resource\"", &wa) == AUTHLAS_STATUS_OK
              && has(&wa, "resource_metadata"), "www-authenticate parse");
        CHECK(authlas_rar_is_reduction("[{\"type\":\"payment\"}]", "[{\"type\":\"payment\"}]", "{\"types\":[\"payment\"]}") == 1, "rar reduction");
        CHECK(authlas_basic_header("id", "s3cret", &bh) == AUTHLAS_STATUS_OK && has(&bh, "Basic "), "basic header");
        authlas_buf_free(&pk); authlas_buf_free(&sc); authlas_buf_free(&ch); authlas_buf_free(&wa);
        authlas_buf_free(&mu); authlas_buf_free(&ru); authlas_buf_free(&rar); authlas_buf_free(&bh);
    }

    /* buffer hygiene */
    AuthlasBuf z = B();
    authlas_buf_free(&z); authlas_buf_free(&z); authlas_buf_free(NULL);
    AuthlasBuf twice = B();
    authlas_jwk_generate_ec("P-384", &twice);
    authlas_buf_free(&twice);
    CHECK(twice.data == NULL && twice.len == 0, "freed buffer is cleared");
    authlas_buf_free(&twice);

    /* concurrency on the thread-local error slot is checked by the Rust tests; here: unknown curve */
    CHECK(authlas_jwk_generate_ec("P-999", &z) != AUTHLAS_STATUS_OK, "unknown curve");

    authlas_buf_free(&key); authlas_buf_free(&pub); authlas_buf_free(&tp); authlas_buf_free(&tok);
    printf(failures ? "%d FAILURES\n" : "all C checks passed\n", failures);
    return failures ? 1 : 0;
}
