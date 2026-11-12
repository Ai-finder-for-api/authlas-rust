#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#endif
// End-to-end tests of the transport against a local TLS server that the test starts itself. Certificates are generated in-process.
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
using Sock = SOCKET;
static void sclose(Sock s) { closesocket(s); }
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using Sock = int;
static void sclose(Sock s) { ::close(s); }
#endif

#include "net/net_internal.hpp"

using namespace authlas::net;

static int g_fail = 0, g_run = 0;
#define CHECK(c) do { g_run++; if (!(c)) { g_fail++; std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

// ---- certificates ------------------------------------------------------------------------------------------------------------

static EVP_PKEY* new_key() { return EVP_EC_gen("P-256"); }

static X509* make_cert(EVP_PKEY* key, const char* cn, X509* issuer, EVP_PKEY* issuer_key, const char* san, long not_before_off, long not_after_off, bool is_ca) {
    X509* x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER* sn = ASN1_INTEGER_new();
    unsigned char rnd[7];
    RAND_bytes(rnd, sizeof rnd);
    uint64_t v = 1;
    for (unsigned char b : rnd) v = (v << 8) | b;
    ASN1_INTEGER_set_uint64(sn, v >> 1);
    X509_set_serialNumber(x, sn);
    ASN1_INTEGER_free(sn);
    X509_gmtime_adj(X509_getm_notBefore(x), not_before_off);
    X509_gmtime_adj(X509_getm_notAfter(x), not_after_off);
    X509_set_pubkey(x, key);
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);
    X509_set_subject_name(x, name);
    X509_set_issuer_name(x, issuer ? X509_get_subject_name(issuer) : X509_get_subject_name(x));
    X509_NAME_free(name);
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer ? issuer : x, x, nullptr, nullptr, 0);
    auto add = [&](int nid, const char* val) {
        X509_EXTENSION* e = X509V3_EXT_conf_nid(nullptr, &ctx, nid, val);
        if (e) { X509_add_ext(x, e, -1); X509_EXTENSION_free(e); }
    };
    add(NID_basic_constraints, is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    add(NID_key_usage, is_ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature");
    if (san) add(NID_subject_alt_name, san);
    X509_sign(x, issuer_key ? issuer_key : key, EVP_sha256());
    return x;
}

static void write_pem(const std::string& path, X509* x) {
    BIO* b = BIO_new_file(path.c_str(), "wb");  // not FILE*: a C runtime handle must not cross into the OpenSSL DLL on Windows
    PEM_write_bio_X509(b, x);
    BIO_free(b);
}

// ---- server ------------------------------------------------------------------------------------------------------------------

struct Server {
    Sock ls{};
    int port = 0;
    std::thread th;
    std::atomic<bool> stop{false};
    std::function<void(SSL*, Sock)> handler;
    SSL_CTX* ctx = nullptr;

    bool start(X509* cert, EVP_PKEY* key, int min_ver, int max_ver, std::function<void(SSL*, Sock)> h) {
        handler = std::move(h);
        ctx = SSL_CTX_new(TLS_server_method());
        SSL_CTX_set_security_level(ctx, 0);
        SSL_CTX_set_min_proto_version(ctx, min_ver);
        SSL_CTX_set_max_proto_version(ctx, max_ver);
        if (SSL_CTX_use_certificate(ctx, cert) != 1 || SSL_CTX_use_PrivateKey(ctx, key) != 1) return false;
        ls = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a;
        std::memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_port = 0;
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (bind(ls, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) return false;
        listen(ls, 8);
#ifdef _WIN32
        int len = sizeof a;
#else
        socklen_t len = sizeof a;
#endif
        getsockname(ls, reinterpret_cast<sockaddr*>(&a), &len);
        port = ntohs(a.sin_port);
        th = std::thread([this] {
            Sock c = accept(ls, nullptr, nullptr);
            if (stop) { if (c != static_cast<Sock>(-1)) sclose(c); return; }
            if (c == static_cast<Sock>(-1)) return;
            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, static_cast<int>(c));
            if (SSL_accept(ssl) == 1) handler(ssl, c);
            SSL_free(ssl);
            sclose(c);
        });
        return true;
    }
    // Joins the server thread, unblocking accept() first when the test never connected.
    void finish() {
        stop = true;
        Sock c = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a;
        std::memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_port = htons(static_cast<uint16_t>(port));
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        connect(c, reinterpret_cast<sockaddr*>(&a), sizeof a);
        sclose(c);
        if (th.joinable()) th.join();
        sclose(ls);
        SSL_CTX_free(ctx);
    }
};

static std::string read_request(SSL* ssl) {
    std::string req;
    char b[1024];
    while (req.find("\r\n\r\n") == std::string::npos && req.size() < 65536) {
        int n = SSL_read(ssl, b, sizeof b);
        if (n <= 0) break;
        req.append(b, static_cast<size_t>(n));
    }
    size_t cl = req.find("Content-Length: ");
    size_t he = req.find("\r\n\r\n");
    if (cl != std::string::npos && he != std::string::npos) {
        size_t want = static_cast<size_t>(std::stoul(req.substr(cl + 16)));
        while (req.size() < he + 4 + want) {
            int n = SSL_read(ssl, b, sizeof b);
            if (n <= 0) break;
            req.append(b, static_cast<size_t>(n));
        }
    }
    return req;
}
static void send_all(SSL* ssl, const std::string& s) { SSL_write(ssl, s.data(), static_cast<int>(s.size())); }

// ---- tests -------------------------------------------------------------------------------------------------------------------

static Request req_for(const Server& s, const std::string& ca_file, const std::string& path = "/echo") {
    Request r;
    r.url = "https://127.0.0.1:" + std::to_string(s.port) + path;
    r.ca_file = ca_file;
    r.allow_internal = true;
    r.timeout_ms = 5000;
    return r;
}
static bool fails_with(const Request& r, Err code, std::string* msg = nullptr) {
    try { fetch(r); } catch (const NetError& e) { if (msg) *msg = e.message; return e.code == code; }
    if (msg) *msg = "(no error)";
    return false;
}

int main() {
#ifdef _WIN32
    WSADATA d;
    WSAStartup(MAKEWORD(2, 2), &d);
#endif
    std::string CA = "_authlas_ca.pem", OTHER = "_authlas_other_ca.pem";
    EVP_PKEY* ca_key = new_key();
    X509* ca = make_cert(ca_key, "Authlas Test CA", nullptr, nullptr, nullptr, -3600, 86400, true);
    EVP_PKEY* other_ca_key = new_key();
    X509* other_ca = make_cert(other_ca_key, "Some Other CA", nullptr, nullptr, nullptr, -3600, 86400, true);
    write_pem(CA, ca);
    write_pem(OTHER, other_ca);

    EVP_PKEY* good_key = new_key();
    X509* good = make_cert(good_key, "good", ca, ca_key, "IP:127.0.0.1,DNS:localhost", -3600, 86400, false);
    EVP_PKEY* wrong_key = new_key();
    X509* wrong_host = make_cert(wrong_key, "wrong", ca, ca_key, "DNS:other.example", -3600, 86400, false);
    EVP_PKEY* old_key = new_key();
    X509* expired = make_cert(old_key, "old", ca, ca_key, "IP:127.0.0.1", -7200, -3600, false);

    auto respond_echo = [&](SSL* ssl, Sock) {
        std::string req = read_request(ssl);
        send_all(ssl, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + std::to_string(req.size()) + "\r\nConnection: close\r\n\r\n" + req);
        SSL_shutdown(ssl);
    };

    // 1. Happy path: verified TLS, request line and fixed headers are right, custom header passes, no compression offered.
    {
        Server s; CHECK(s.start(good, good_key, TLS1_2_VERSION, TLS1_3_VERSION, respond_echo));
        Request r = req_for(s, CA, "/echo?x=1");
        r.headers.push_back({"Authorization", "Bearer tkn"});
        Response resp = fetch(r);
        CHECK(resp.status == 200);
        CHECK(resp.body.rfind("GET /echo?x=1 HTTP/1.1\r\n", 0) == 0);
        CHECK(resp.body.find("Host: 127.0.0.1:" + std::to_string(s.port) + "\r\n") != std::string::npos);
        CHECK(resp.body.find("Authorization: Bearer tkn\r\n") != std::string::npos);
        CHECK(resp.body.find("Accept-Encoding: identity\r\n") != std::string::npos);
        CHECK(resp.body.find("Connection: close\r\n") != std::string::npos);
        CHECK(resp.peer_address == "127.0.0.1");
        CHECK(resp.tls_version == "TLSv1.3" || resp.tls_version == "TLSv1.2");
        s.finish();
    }
    // 2. POST with a body.
    {
        Server s; CHECK(s.start(good, good_key, TLS1_2_VERSION, TLS1_3_VERSION, respond_echo));
        Request r = req_for(s, CA, "/token");
        r.method = "POST";
        r.body = "grant_type=authorization_code&code=abc";
        r.headers.push_back({"Content-Type", "application/x-www-form-urlencoded"});
        Response resp = fetch(r);
        CHECK(resp.body.find("Content-Length: " + std::to_string(r.body.size()) + "\r\n") != std::string::npos);
        CHECK(resp.body.find("grant_type=authorization_code&code=abc") != std::string::npos);
        s.finish();
    }
    // 3. Host name (not IP) verification works too.
    {
        Server s; CHECK(s.start(good, good_key, TLS1_2_VERSION, TLS1_3_VERSION, respond_echo));
        Request r = req_for(s, CA);
        r.url = "https://localhost:" + std::to_string(s.port) + "/echo";
        CHECK(fetch(r).status == 200);
        s.finish();
    }
    // 4. Chunked response.
    {
        Server s; CHECK(s.start(good, good_key, TLS1_2_VERSION, TLS1_3_VERSION, [&](SSL* ssl, Sock) {
            read_request(ssl);
            send_all(ssl, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            send_all(ssl, "5\r\nhello\r\n");
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
            send_all(ssl, "6\r\n world\r\n0\r\n\r\n");
            SSL_shutdown(ssl);
        }));
        CHECK(fetch(req_for(s, CA)).body == "hello world");
        s.finish();
    }
    // 5. Redirects are returned, never followed (the Location here points at the cloud metadata address).
    {
        Server s; CHECK(s.start(good, good_key, TLS1_2_VERSION, TLS1_3_VERSION, [&](SSL* ssl, Sock) {
            read_request(ssl);
            send_all(ssl, "HTTP/1.1 302 Found\r\nLocation: https://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\n\r\n");
            SSL_shutdown(ssl);
        }));
        Response resp = fetch(req_for(s, CA));
        CHECK(resp.status == 302);
        bool found = false;
        for (auto& h : resp.headers) if (h.first == "location") found = true;
        CHECK(found);
        s.finish();
    }
    // 6. Certificate problems fail closed with a TLS error.
    {
        std::string msg;
        Server s; CHECK(s.start(good, good_key, TLS1_2_VERSION, TLS1_3_VERSION, respond_echo));
        CHECK(fails_with(req_for(s, OTHER), Err::Tls, &msg));  // chain does not lead to a trusted CA
        CHECK(msg.find("certificate verification failed") != std::string::npos);
        s.finish();
        Server s2; CHECK(s2.start(wrong_host, wrong_key, TLS1_2_VERSION, TLS1_3_VERSION, respond_echo));
        CHECK(fails_with(req_for(s2, CA), Err::Tls, &msg));  // trusted CA, certificate is for another name
        CHECK(msg.find("certificate verification failed") != std::string::npos);
        s2.finish();
        Server s3; CHECK(s3.start(expired, old_key, TLS1_2_VERSION, TLS1_3_VERSION, respond_echo));
        CHECK(fails_with(req_for(s3, CA), Err::Tls, &msg));
        CHECK(msg.find("expired") != std::string::npos);
        s3.finish();
    }
    // 7. Self-signed server certificate that is not trusted.
    {
        Server s; CHECK(s.start(ca, ca_key, TLS1_2_VERSION, TLS1_3_VERSION, respond_echo));
        CHECK(fails_with(req_for(s, OTHER), Err::Tls));
        s.finish();
    }
    // 8. Old protocol versions are refused.
    {
        Server s; CHECK(s.start(good, good_key, TLS1_VERSION, TLS1_1_VERSION, respond_echo));
        CHECK(fails_with(req_for(s, CA), Err::Tls));
        s.finish();
    }
    // 9. A server that promises 100 bytes, sends 10 and drops the connection without close_notify.
    {
        Server s; CHECK(s.start(good, good_key, TLS1_2_VERSION, TLS1_3_VERSION, [&](SSL* ssl, Sock c) {
            read_request(ssl);
            send_all(ssl, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789");
            sclose(c);
        }));
        bool failed = false;
        try { fetch(req_for(s, CA)); } catch (const NetError& e) { failed = e.code == Err::Io || e.code == Err::Protocol; }
        CHECK(failed);
        s.finish();
    }
    // 10. A read-until-close body that ends without close_notify is truncation, not a complete message.
    {
        Server s; CHECK(s.start(good, good_key, TLS1_2_VERSION, TLS1_3_VERSION, [&](SSL* ssl, Sock c) {
            read_request(ssl);
            send_all(ssl, "HTTP/1.1 200 OK\r\n\r\n{\"partial\":");
            sclose(c);
        }));
        CHECK(fails_with(req_for(s, CA), Err::Io));
        s.finish();
    }
    // 11. A server that never answers: the single deadline applies.
    {
        Server s; CHECK(s.start(good, good_key, TLS1_2_VERSION, TLS1_3_VERSION, [&](SSL* ssl, Sock) {
            read_request(ssl);
            std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        }));
        Request r = req_for(s, CA);
        r.timeout_ms = 400;
        auto t0 = std::chrono::steady_clock::now();
        CHECK(fails_with(r, Err::Timeout));
        CHECK(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count() < 1200);
        s.finish();
    }
    // 12. A slow trickle cannot stretch the deadline by sending one byte at a time.
    {
        Server s; CHECK(s.start(good, good_key, TLS1_2_VERSION, TLS1_3_VERSION, [&](SSL* ssl, Sock) {
            read_request(ssl);
            send_all(ssl, "HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n");
            for (int i = 0; i < 50; i++) { send_all(ssl, "x"); std::this_thread::sleep_for(std::chrono::milliseconds(60)); }
        }));
        Request r = req_for(s, CA);
        r.timeout_ms = 500;
        auto t0 = std::chrono::steady_clock::now();
        CHECK(fails_with(r, Err::Timeout));
        CHECK(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count() < 1500);
        s.finish();
    }
    // 13. Body limits, announced and streamed.
    {
        Server s; CHECK(s.start(good, good_key, TLS1_2_VERSION, TLS1_3_VERSION, [&](SSL* ssl, Sock) {
            read_request(ssl);
            send_all(ssl, "HTTP/1.1 200 OK\r\nContent-Length: 5000000\r\n\r\n");
            SSL_shutdown(ssl);
        }));
        Request r = req_for(s, CA);
        r.max_response_bytes = 1000;
        CHECK(fails_with(r, Err::TooLarge));
        s.finish();
        Server s2; CHECK(s2.start(good, good_key, TLS1_2_VERSION, TLS1_3_VERSION, [&](SSL* ssl, Sock) {
            read_request(ssl);
            send_all(ssl, "HTTP/1.1 200 OK\r\n\r\n");
            std::string blk(4096, 'a');
            for (int i = 0; i < 64; i++) { if (SSL_write(ssl, blk.data(), static_cast<int>(blk.size())) <= 0) break; }
            SSL_shutdown(ssl);
        }));
        Request r2 = req_for(s2, CA);
        r2.max_response_bytes = 10000;
        CHECK(fails_with(r2, Err::TooLarge));
        s2.finish();
    }
    // 14. Malformed framing from the server is a protocol error.
    {
        Server s; CHECK(s.start(good, good_key, TLS1_2_VERSION, TLS1_3_VERSION, [&](SSL* ssl, Sock) {
            read_request(ssl);
            send_all(ssl, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
            SSL_shutdown(ssl);
        }));
        CHECK(fails_with(req_for(s, CA), Err::Protocol));
        s.finish();
    }
    // 15. Anything refused locally never reaches the network (no server is running for these).
    {
        Request r;
        r.url = "https://127.0.0.1:9/";
        CHECK(fails_with(r, Err::BlockedAddress));
        r.url = "https://169.254.169.254/latest/meta-data/";
        CHECK(fails_with(r, Err::BlockedAddress));
        r.url = "https://localhost/";
        CHECK(fails_with(r, Err::BlockedAddress));
        r.url = "http://example.com/";
        CHECK(fails_with(r, Err::InvalidUrl));
        r.url = "https://example.com/";
        r.headers = {{"X-A", "a\r\nX-B: injected"}};
        CHECK(fails_with(r, Err::InvalidArgument));
        r.headers = {{"Host", "evil.example"}};
        CHECK(fails_with(r, Err::InvalidArgument));
        r.headers.clear();
        r.method = "TRACE";
        CHECK(fails_with(r, Err::InvalidArgument));
        r.method = "GET"; r.body = "x";
        CHECK(fails_with(r, Err::InvalidArgument));
        r.body.clear(); r.timeout_ms = 0;
        CHECK(fails_with(r, Err::InvalidArgument));
        r.timeout_ms = 1000; r.max_response_bytes = 0;
        CHECK(fails_with(r, Err::InvalidArgument));
    }
    // 16. Connection refused is reported as such.
    {
        Server s; CHECK(s.start(good, good_key, TLS1_2_VERSION, TLS1_3_VERSION, respond_echo));
        int port = s.port;
        s.finish();
        Request r;
        r.url = "https://127.0.0.1:" + std::to_string(port) + "/";
        r.allow_internal = true;
        r.ca_file = CA;
        r.timeout_ms = 3000;
        std::string msg;
        auto t0 = std::chrono::steady_clock::now();
        bool ok = fails_with(r, Err::Connect, &msg);
        std::printf("  refused: %s (%lld ms)\n", msg.c_str(), static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count()));
        CHECK(ok);
    }
    // 17. A missing CA file is an error, not a silent fallback to "trust everything".
    {
        Request r;
        r.url = "https://127.0.0.1:9/";
        r.allow_internal = true;
        r.ca_file = "does-not-exist.pem";
        CHECK(fails_with(r, Err::Tls));
    }

    std::remove(CA.c_str());
    std::remove(OTHER.c_str());
    std::printf("net_tls_tests: %d checks, %d failed\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
