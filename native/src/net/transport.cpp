#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#endif
// HTTPS transport: resolve, check every address, connect to the checked address, verify TLS, one request, strict response parsing.
//
// Design points that matter for security:
//  * The name is resolved once. Every returned address must be public (unless allow_internal) or the whole request is refused,
//    and the socket is connected to that checked address, never to the name again. That closes the DNS rebinding gap.
//  * TLS 1.2 minimum, peer verification always on, host name checked against the certificate, SNI set. No option turns these off.
//  * One deadline covers resolve, connect, handshake, request and response.
//  * No redirects (callers decide, and must re-check each hop), no compression, no proxies, no connection reuse.
#include "net_internal.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <thread>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace authlas::net {

using Clock = std::chrono::steady_clock;

static NetError fail(Err c, const std::string& m) { return NetError{c, m}; }

// ---- sockets ----------------------------------------------------------------------------------------------------------------

#ifdef _WIN32
using Sock = SOCKET;
static const Sock kBadSock = INVALID_SOCKET;
static void sock_close(Sock s) { if (s != kBadSock) closesocket(s); }
static void sock_init() {
    static std::once_flag f;
    std::call_once(f, [] { WSADATA d; WSAStartup(MAKEWORD(2, 2), &d); });
}
static bool set_nonblocking(Sock s) { u_long m = 1; return ioctlsocket(s, FIONBIO, &m) == 0; }
static bool in_progress() { int e = WSAGetLastError(); return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS; }
#else
using Sock = int;
static const Sock kBadSock = -1;
static void sock_close(Sock s) { if (s != kBadSock) ::close(s); }
static void sock_init() {}
static bool set_nonblocking(Sock s) { int f = fcntl(s, F_GETFL, 0); return f >= 0 && fcntl(s, F_SETFL, f | O_NONBLOCK) == 0; }
static bool in_progress() { return errno == EINPROGRESS || errno == EWOULDBLOCK || errno == EINTR; }
#endif

struct SockGuard {
    Sock s = kBadSock;
    ~SockGuard() { sock_close(s); }
};

static int ms_left(Clock::time_point deadline) {
    auto d = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    return d < 0 ? 0 : (d > 1000000 ? 1000000 : static_cast<int>(d));
}

// Waits for readiness. Returns false on timeout.
static bool wait_sock(Sock s, bool want_read, bool want_write, Clock::time_point deadline) {
    int ms = ms_left(deadline);
    if (ms == 0) return false;
#ifdef _WIN32
    WSAPOLLFD p;
    p.fd = s;
    p.events = static_cast<SHORT>((want_read ? POLLRDNORM : 0) | (want_write ? POLLWRNORM : 0));
    p.revents = 0;
    int r = WSAPoll(&p, 1, ms);
#else
    struct pollfd p;
    p.fd = s;
    p.events = static_cast<short>((want_read ? POLLIN : 0) | (want_write ? POLLOUT : 0));
    p.revents = 0;
    int r = poll(&p, 1, ms);
#endif
    if (r < 0) return true;  // let the caller's next call report the real error
    return r > 0;
}

// Waits for a non-blocking connect to finish, successfully or not. WSAPoll does not report a refused connect on Windows, so
// there it is select() with the exception set; elsewhere poll() reports POLLERR/POLLHUP and the SO_ERROR check decides.
static bool wait_connect(Sock s, Clock::time_point deadline) {
#ifdef _WIN32
    int ms = ms_left(deadline);
    if (ms == 0) return false;
    fd_set w, e;
    FD_ZERO(&w);
    FD_ZERO(&e);
    FD_SET(s, &w);
    FD_SET(s, &e);
    timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return select(0, nullptr, &w, &e, &tv) > 0;
#else
    return wait_sock(s, false, true, deadline);
#endif
}

// ---- name resolution --------------------------------------------------------------------------------------------------------

struct Resolved {
    std::vector<std::vector<uint8_t>> addrs;  // 4 or 16 bytes each
};

struct ResolveState {
    std::mutex m;
    std::condition_variable cv;
    bool done = false;
    int rc = 0;
    Resolved out;
};

static Resolved resolve(const std::string& host, const std::string& port, Clock::time_point deadline) {
    auto st = std::make_shared<ResolveState>();
    std::thread([st, host, port] {
        addrinfo hints;
        std::memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_ADDRCONFIG;
        addrinfo* res = nullptr;
        int rc = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
        if (rc != 0 && rc != EAI_NONAME) {  // AI_ADDRCONFIG can hide valid results on hosts without a global address
            hints.ai_flags = 0;
            rc = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
        }
        Resolved r;
        if (rc == 0) {
            for (addrinfo* a = res; a; a = a->ai_next) {
                if (a->ai_family == AF_INET) {
                    auto* sa = reinterpret_cast<sockaddr_in*>(a->ai_addr);
                    const uint8_t* b = reinterpret_cast<const uint8_t*>(&sa->sin_addr);
                    r.addrs.emplace_back(b, b + 4);
                } else if (a->ai_family == AF_INET6) {
                    auto* sa = reinterpret_cast<sockaddr_in6*>(a->ai_addr);
                    const uint8_t* b = reinterpret_cast<const uint8_t*>(&sa->sin6_addr);
                    r.addrs.emplace_back(b, b + 16);
                }
            }
            freeaddrinfo(res);
        }
        std::lock_guard<std::mutex> g(st->m);
        st->rc = rc;
        st->out = std::move(r);
        st->done = true;
        st->cv.notify_all();
    }).detach();
    std::unique_lock<std::mutex> lk(st->m);
    if (!st->cv.wait_until(lk, deadline, [&] { return st->done; })) throw fail(Err::Timeout, "name resolution timed out");
    if (st->rc != 0 || st->out.addrs.empty()) throw fail(Err::Resolve, "could not resolve host");
    return std::move(st->out);
}

static std::string addr_to_string(const std::vector<uint8_t>& a) {
    char buf[64] = {0};
    if (a.size() == 4) inet_ntop(AF_INET, a.data(), buf, sizeof buf);
    else inet_ntop(AF_INET6, a.data(), buf, sizeof buf);
    return buf;
}

// ---- connect ----------------------------------------------------------------------------------------------------------------

static Sock connect_to(const std::vector<uint8_t>& addr, int port, Clock::time_point deadline) {
    sockaddr_storage ss;
    std::memset(&ss, 0, sizeof ss);
    int len;
    int family;
    if (addr.size() == 4) {
        auto* s4 = reinterpret_cast<sockaddr_in*>(&ss);
        s4->sin_family = AF_INET;
        s4->sin_port = htons(static_cast<uint16_t>(port));
        std::memcpy(&s4->sin_addr, addr.data(), 4);
        len = sizeof(sockaddr_in);
        family = AF_INET;
    } else {
        auto* s6 = reinterpret_cast<sockaddr_in6*>(&ss);
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(static_cast<uint16_t>(port));
        std::memcpy(&s6->sin6_addr, addr.data(), 16);
        len = sizeof(sockaddr_in6);
        family = AF_INET6;
    }
    Sock s = ::socket(family, SOCK_STREAM, 0);
    if (s == kBadSock) throw fail(Err::Connect, "socket() failed");
    SockGuard g;
    g.s = s;
    if (!set_nonblocking(s)) throw fail(Err::Connect, "cannot make socket non-blocking");
    int one = 1;
    setsockopt(s, IPPROTO_TCP, 1 /* TCP_NODELAY */, reinterpret_cast<const char*>(&one), sizeof one);
    int rc = ::connect(s, reinterpret_cast<sockaddr*>(&ss), len);
    if (rc != 0) {
        if (!in_progress()) throw fail(Err::Connect, "connection refused or unreachable");
        if (!wait_connect(s, deadline)) throw fail(Err::Timeout, "connect timed out");
        int soerr = 0;
#ifdef _WIN32
        int sl = sizeof soerr;
#else
        socklen_t sl = sizeof soerr;
#endif
        getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &sl);
        if (soerr != 0) throw fail(Err::Connect, "connection failed");
    }
    g.s = kBadSock;
    return s;
}

// ---- TLS context ------------------------------------------------------------------------------------------------------------

void for_each_system_root(void (*cb)(const unsigned char*, unsigned long, void*), void* ctx) {
#ifdef _WIN32
    HCERTSTORE st = CertOpenSystemStoreA(0, "ROOT");
    if (!st) return;
    PCCERT_CONTEXT c = nullptr;
    while ((c = CertEnumCertificatesInStore(st, c)) != nullptr) cb(c->pbCertEncoded, c->cbCertEncoded, ctx);
    CertCloseStore(st, 0);
#else
    (void)cb; (void)ctx;
#endif
}

static std::string ssl_error_text() {
    unsigned long e = ERR_peek_last_error();
    char buf[256] = {0};
    if (e) ERR_error_string_n(e, buf, sizeof buf);
    ERR_clear_error();
    return buf[0] ? std::string(buf) : std::string("unknown TLS error");
}

struct CtxDeleter { void operator()(SSL_CTX* c) const { SSL_CTX_free(c); } };
struct SslDeleter { void operator()(SSL* s) const { SSL_free(s); } };
using CtxPtr = std::shared_ptr<SSL_CTX>;

static CtxPtr make_ctx(const std::string& ca_file) {
    SSL_CTX* raw = SSL_CTX_new(TLS_client_method());
    if (!raw) throw fail(Err::Tls, "cannot create TLS context");
    CtxPtr ctx(raw, CtxDeleter());
    if (!SSL_CTX_set_min_proto_version(raw, TLS1_2_VERSION)) throw fail(Err::Tls, "cannot set minimum TLS version");
    SSL_CTX_set_options(raw, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_verify(raw, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify_depth(raw, 8);
    SSL_CTX_set_session_cache_mode(raw, SSL_SESS_CACHE_OFF);
    if (!ca_file.empty()) {
        if (SSL_CTX_load_verify_locations(raw, ca_file.c_str(), nullptr) != 1) throw fail(Err::Tls, "cannot load CA file: " + ssl_error_text());
    } else {
#ifdef _WIN32
        struct Sink { X509_STORE* store; int added; } sink{SSL_CTX_get_cert_store(raw), 0};
        for_each_system_root(
            [](const unsigned char* der, unsigned long len, void* c) {
                auto* k = static_cast<Sink*>(c);
                const unsigned char* p = der;
                X509* x = d2i_X509(nullptr, &p, static_cast<long>(len));
                if (x) {
                    if (X509_STORE_add_cert(k->store, x) == 1) k->added++;
                    X509_free(x);
                }
            },
            &sink);
        ERR_clear_error();
        if (sink.added == 0) throw fail(Err::Tls, "no trusted root certificates available");
#else
        if (SSL_CTX_set_default_verify_paths(raw) != 1) throw fail(Err::Tls, "cannot load the system trust store");
#endif
    }
    return ctx;
}

static CtxPtr system_ctx() {
    static std::mutex m;
    static CtxPtr cached;
    std::lock_guard<std::mutex> g(m);
    if (!cached) cached = make_ctx("");
    return cached;
}

// ---- TLS I/O ----------------------------------------------------------------------------------------------------------------

static void tls_handshake(SSL* ssl, Sock s, Clock::time_point deadline) {
    for (;;) {
        ERR_clear_error();
        int r = SSL_connect(ssl);
        if (r == 1) return;
        int e = SSL_get_error(ssl, r);
        if (e == SSL_ERROR_WANT_READ) { if (!wait_sock(s, true, false, deadline)) throw fail(Err::Timeout, "TLS handshake timed out"); }
        else if (e == SSL_ERROR_WANT_WRITE) { if (!wait_sock(s, false, true, deadline)) throw fail(Err::Timeout, "TLS handshake timed out"); }
        else {
            long vr = SSL_get_verify_result(ssl);
            if (vr != X509_V_OK) throw fail(Err::Tls, std::string("certificate verification failed: ") + X509_verify_cert_error_string(vr));
            throw fail(Err::Tls, "TLS handshake failed: " + ssl_error_text());
        }
    }
}

static void tls_write_all(SSL* ssl, Sock s, const char* p, size_t n, Clock::time_point deadline) {
    size_t off = 0;
    while (off < n) {
        ERR_clear_error();
        int w = SSL_write(ssl, p + off, static_cast<int>(std::min<size_t>(n - off, 16384)));
        if (w > 0) { off += static_cast<size_t>(w); continue; }
        int e = SSL_get_error(ssl, w);
        if (e == SSL_ERROR_WANT_READ) { if (!wait_sock(s, true, false, deadline)) throw fail(Err::Timeout, "write timed out"); }
        else if (e == SSL_ERROR_WANT_WRITE) { if (!wait_sock(s, false, true, deadline)) throw fail(Err::Timeout, "write timed out"); }
        else throw fail(Err::Io, "write failed: " + ssl_error_text());
    }
}

// Returns bytes read, 0 for a clean TLS close. Throws on timeout and on any unclean end (truncation).
static size_t tls_read_some(SSL* ssl, Sock s, uint8_t* buf, size_t cap, Clock::time_point deadline) {
    for (;;) {
        ERR_clear_error();
        int r = SSL_read(ssl, buf, static_cast<int>(std::min<size_t>(cap, 16384)));
        if (r > 0) return static_cast<size_t>(r);
        int e = SSL_get_error(ssl, r);
        if (e == SSL_ERROR_ZERO_RETURN) return 0;
        if (e == SSL_ERROR_WANT_READ) { if (!wait_sock(s, true, false, deadline)) throw fail(Err::Timeout, "read timed out"); }
        else if (e == SSL_ERROR_WANT_WRITE) { if (!wait_sock(s, false, true, deadline)) throw fail(Err::Timeout, "read timed out"); }
        else throw fail(Err::Io, "connection ended without a TLS close (possible truncation): " + ssl_error_text());
    }
}

// ---- fetch ------------------------------------------------------------------------------------------------------------------

Response fetch(const Request& r) {
    sock_init();
    static const char* kMethods[] = {"GET", "POST", "PUT", "DELETE", "HEAD"};
    if (std::none_of(std::begin(kMethods), std::end(kMethods), [&](const char* m) { return r.method == m; })) throw fail(Err::InvalidArgument, "unsupported method");
    if (r.timeout_ms < 1 || r.timeout_ms > 120000) throw fail(Err::InvalidArgument, "timeout must be 1..120000 ms");
    if (r.max_response_bytes < 1 || r.max_response_bytes > (64u << 20)) throw fail(Err::InvalidArgument, "max_response_bytes must be 1..64 MiB");
    if (r.body.size() > (16u << 20)) throw fail(Err::InvalidArgument, "request body is too large");
    if (!r.body.empty() && r.method != "POST" && r.method != "PUT") throw fail(Err::InvalidArgument, "body is only allowed with POST and PUT");
    if (r.headers.size() > 64) throw fail(Err::InvalidArgument, "too many request headers");
    for (auto& h : r.headers) check_request_header(h.first, h.second);

    Url u = parse_url(r.url, r.allow_internal);
    auto deadline = Clock::now() + std::chrono::milliseconds(r.timeout_ms);
    int port = std::stoi(u.port);

    // Resolve, then check every address before touching the network.
    std::vector<std::vector<uint8_t>> addrs;
    if (u.host_is_ip) {
        std::vector<uint8_t> a(16);
        uint8_t v4[4];
        if (parse_v4(u.host, v4)) addrs.emplace_back(v4, v4 + 4);
        else if (parse_v6(u.host, a.data())) addrs.push_back(a);
        else throw fail(Err::InvalidUrl, "invalid address literal");
    } else {
        addrs = resolve(u.host, u.port, deadline).addrs;
    }
    if (!r.allow_internal) {
        for (auto& a : addrs) {
            bool ok = a.size() == 4 ? is_public_v4(a.data()) : is_public_v6(a.data());
            if (!ok) throw fail(Err::BlockedAddress, "host resolves to a private or reserved address");
        }
    }

    CtxPtr ctx = r.ca_file.empty() ? system_ctx() : make_ctx(r.ca_file);

    Sock sock = kBadSock;
    std::vector<uint8_t> peer;
    std::string last_err = "no address could be reached";
    Err last_code = Err::Connect;
    size_t tried = 0;
    const size_t max_attempts = std::min<size_t>(addrs.size(), 4);
    for (auto& a : addrs) {
        if (tried >= max_attempts) break;
        // Split what is left of the deadline over the addresses still to try, so one dead address cannot use up the whole budget
        // while a host with a single address gets all of it.
        auto share = std::chrono::milliseconds(std::max(1, ms_left(deadline) / static_cast<int>(max_attempts - tried)));
        auto attempt_deadline = std::min(deadline, Clock::now() + share);
        tried++;
        try {
            sock = connect_to(a, port, attempt_deadline);
            peer = a;
            break;
        } catch (NetError& e) {
            last_err = e.message;
            last_code = e.code;
            if (ms_left(deadline) == 0) throw fail(Err::Timeout, "timed out connecting");
        }
    }
    if (sock == kBadSock) throw fail(last_code, last_err);
    SockGuard guard;
    guard.s = sock;

    std::unique_ptr<SSL, SslDeleter> ssl(SSL_new(ctx.get()));
    if (!ssl) throw fail(Err::Tls, "cannot create TLS session");
    SSL_set_fd(ssl.get(), static_cast<int>(sock));
    if (!u.host_is_ip) {
        if (SSL_set_tlsext_host_name(ssl.get(), u.host.c_str()) != 1) throw fail(Err::Tls, "cannot set SNI");
        if (SSL_set1_host(ssl.get(), u.host.c_str()) != 1) throw fail(Err::Tls, "cannot set expected host name");
    } else {
        X509_VERIFY_PARAM* vp = SSL_get0_param(ssl.get());
        if (X509_VERIFY_PARAM_set1_ip_asc(vp, u.host.c_str()) != 1) throw fail(Err::Tls, "cannot set expected IP address");
    }
    tls_handshake(ssl.get(), sock, deadline);

    // Request.
    std::string req = r.method + " " + u.target + " HTTP/1.1\r\nHost: " + u.host_header +
                      "\r\nUser-Agent: authlas/0.1\r\nAccept-Encoding: identity\r\nConnection: close\r\n";
    bool has_body_method = r.method == "POST" || r.method == "PUT";
    if (has_body_method) req += "Content-Length: " + std::to_string(r.body.size()) + "\r\n";
    for (auto& h : r.headers) req += h.first + ": " + h.second + "\r\n";
    req += "\r\n";
    req += r.body;
    tls_write_all(ssl.get(), sock, req.data(), req.size(), deadline);

    ResponseParser parser(static_cast<size_t>(r.max_response_bytes), r.method == "HEAD");
    std::vector<uint8_t> buf(16384);
    while (!parser.done()) {
        size_t n = tls_read_some(ssl.get(), sock, buf.data(), buf.size(), deadline);
        if (n == 0) { parser.eof(); break; }
        parser.feed(buf.data(), n);
    }

    Response resp;
    resp.status = parser.status;
    resp.headers = std::move(parser.headers);
    resp.body = std::move(parser.body);
    resp.peer_address = addr_to_string(peer);
    resp.tls_version = SSL_get_version(ssl.get());
    SSL_shutdown(ssl.get());  // best effort; the peer is not waited for
    return resp;
}

}  // namespace authlas::net
