// C ABI over the network layer. No exception escapes any function here.
#include "../include/authlas_net.h"

#include <cstdlib>
#include <cstring>
#include <string>

#include "net/net_internal.hpp"

using namespace authlas::net;

namespace {

thread_local std::string g_error;

int record(const NetError& e) {
    g_error = e.message;
    return static_cast<int>(e.code);
}

char* dup_cstr(const std::string& s) {
    char* p = static_cast<char*>(std::malloc(s.size() + 1));
    if (!p) throw NetError{Err::Io, "out of memory"};
    std::memcpy(p, s.data(), s.size());
    p[s.size()] = 0;
    return p;
}

void fill(AuthlasHttpResponse* out, const Response& r) {
    std::memset(out, 0, sizeof *out);
    out->status = r.status;
    std::string hs;
    for (auto& h : r.headers) hs += h.first + ": " + h.second + "\n";
    try {
        out->headers = dup_cstr(hs);
        out->body = reinterpret_cast<uint8_t*>(dup_cstr(r.body));
        out->body_len = r.body.size();
        out->peer_address = dup_cstr(r.peer_address);
        out->tls_version = dup_cstr(r.tls_version);
    } catch (...) {
        authlas_net_response_free(out);
        throw;
    }
}

template <class F>
int guarded(F&& f) {
    try {
        f();
        g_error.clear();
        return AUTHLAS_NET_OK;
    } catch (const NetError& e) {
        return record(e);
    } catch (const std::exception& e) {
        g_error = std::string("internal error: ") + e.what();
        return AUTHLAS_NET_INTERNAL;
    } catch (...) {
        g_error = "internal error";
        return AUTHLAS_NET_INTERNAL;
    }
}

}  // namespace

extern "C" {

int authlas_net_abi_version(void) { return AUTHLAS_NET_ABI_VERSION; }

const char* authlas_net_last_error(void) { return g_error.c_str(); }

void authlas_net_response_free(AuthlasHttpResponse* r) {
    if (!r) return;
    std::free(r->headers);
    if (r->body) {
        volatile uint8_t* p = r->body;  // responses can carry tokens: wipe before releasing
        for (size_t i = 0; i < r->body_len; ++i) p[i] = 0;
    }
    std::free(r->body);
    std::free(r->peer_address);
    std::free(r->tls_version);
    std::memset(r, 0, sizeof *r);
}

int authlas_net_fetch(const AuthlasHttpRequest* req, AuthlasHttpResponse* out) {
    if (out) std::memset(out, 0, sizeof *out);
    return guarded([&] {
        if (!req || !out || !req->url) throw NetError{Err::InvalidArgument, "null argument"};
        Request r;
        r.method = req->method ? req->method : "GET";
        r.url = req->url;
        if (req->header_count) {
            if (!req->header_names || !req->header_values) throw NetError{Err::InvalidArgument, "null header array"};
            if (req->header_count > 64) throw NetError{Err::InvalidArgument, "too many request headers"};
            for (size_t i = 0; i < req->header_count; i++) {
                if (!req->header_names[i] || !req->header_values[i]) throw NetError{Err::InvalidArgument, "null header entry"};
                r.headers.emplace_back(req->header_names[i], req->header_values[i]);
            }
        }
        if (req->body_len) {
            if (!req->body) throw NetError{Err::InvalidArgument, "null body"};
            r.body.assign(reinterpret_cast<const char*>(req->body), req->body_len);
        }
        if (req->timeout_ms) r.timeout_ms = req->timeout_ms;
        if (req->max_response_bytes) r.max_response_bytes = req->max_response_bytes;
        if (req->ca_file) r.ca_file = req->ca_file;
        r.allow_internal = req->allow_internal != 0;
        Response resp = fetch(r);
        fill(out, resp);
    });
}

int authlas_net_fetch_err(const AuthlasHttpRequest* req, AuthlasHttpResponse* out, char* err, size_t err_cap) {
    int rc = authlas_net_fetch(req, out);
    if (err && err_cap) {
        size_t n = rc == AUTHLAS_NET_OK ? 0 : g_error.size();
        if (n >= err_cap) n = err_cap - 1;
        std::memcpy(err, g_error.data(), n);
        err[n] = 0;
    }
    return rc;
}

int authlas_net_url_check(const char* url, int allow_internal) {
    return guarded([&] {
        if (!url) throw NetError{Err::InvalidArgument, "null url"};
        parse_url(url, allow_internal != 0);
    });
}

int authlas_net_ip_is_public(const char* ip, int* is_public) {
    return guarded([&] {
        if (!ip || !is_public) throw NetError{Err::InvalidArgument, "null argument"};
        uint8_t a4[4], a6[16];
        std::string s = ip;
        if (parse_v4(s, a4)) *is_public = is_public_v4(a4) ? 1 : 0;
        else if (parse_v6(s, a6)) *is_public = is_public_v6(a6) ? 1 : 0;
        else throw NetError{Err::InvalidArgument, "not an IP literal"};
    });
}

int authlas_net_parse_response(const uint8_t* data, size_t len, uint64_t max_body, int head_request, AuthlasHttpResponse* out) {
    if (out) std::memset(out, 0, sizeof *out);
    return guarded([&] {
        if (!out || (len && !data)) throw NetError{Err::InvalidArgument, "null argument"};
        if (max_body < 1 || max_body > (64u << 20)) throw NetError{Err::InvalidArgument, "max_body must be 1..64 MiB"};
        ResponseParser p(static_cast<size_t>(max_body), head_request != 0);
        if (len) p.feed(data, len);
        if (!p.done()) p.eof();
        Response r;
        r.status = p.status;
        r.headers = std::move(p.headers);
        r.body = std::move(p.body);
        fill(out, r);
    });
}

}  // extern "C"
