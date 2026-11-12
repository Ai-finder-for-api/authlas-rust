// Address classification, strict URL parsing and request-header checks.
#include "net_internal.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace authlas::net {

static NetError fail(Err c, const std::string& m) { return NetError{c, m}; }

// ---- addresses --------------------------------------------------------------------------------------------------------------

bool is_public_v4(const uint8_t o[4]) {
    if (o[0] == 0 || o[0] == 10 || o[0] == 127) return false;
    if (o[0] == 169 && o[1] == 254) return false;                 // link-local
    if (o[0] == 172 && (o[1] & 0xf0) == 16) return false;         // 172.16.0.0/12
    if (o[0] == 192 && o[1] == 168) return false;
    if (o[0] == 100 && o[1] >= 64 && o[1] <= 127) return false;   // 100.64.0.0/10 carrier-grade NAT
    if (o[0] == 192 && o[1] == 0 && o[2] == 0) return false;      // IETF protocol assignments
    if (o[0] == 192 && o[1] == 0 && o[2] == 2) return false;      // documentation
    if (o[0] == 198 && o[1] == 51 && o[2] == 100) return false;
    if (o[0] == 203 && o[1] == 0 && o[2] == 113) return false;
    if (o[0] == 198 && (o[1] == 18 || o[1] == 19)) return false;  // benchmarking
    if (o[0] >= 224) return false;                                 // multicast, reserved, broadcast
    return true;
}

bool is_public_v6(const uint8_t a[16]) {
    uint16_t s[8];
    for (int i = 0; i < 8; i++) s[i] = static_cast<uint16_t>((a[2 * i] << 8) | a[2 * i + 1]);
    bool first6_zero = s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0;
    if (first6_zero) return false;  // ::, ::1 and the deprecated IPv4-compatible range
    if (a[0] == 0xff) return false;  // multicast
    if (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0xffff) {  // ::ffff:a.b.c.d
        uint8_t v4[4] = {a[12], a[13], a[14], a[15]};
        return is_public_v4(v4);
    }
    if (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0) {  // NAT64
        uint8_t v4[4] = {a[12], a[13], a[14], a[15]};
        return is_public_v4(v4);
    }
    if (s[0] == 0x2002) {  // 6to4 embeds an IPv4 address
        uint8_t v4[4] = {a[2], a[3], a[4], a[5]};
        return is_public_v4(v4);
    }
    if ((s[0] & 0xfe00) == 0xfc00) return false;                          // unique local
    if ((s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xffc0) == 0xfec0) return false;  // link-local, site-local
    if (s[0] == 0x2001 && s[1] == 0) return false;                        // Teredo
    if (s[0] == 0x2001 && s[1] == 0x0db8) return false;                   // documentation
    if (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0) return false;  // discard prefix
    return true;
}

bool parse_v4(const std::string& s, uint8_t out[4]) {
    int part = 0;
    size_t i = 0;
    while (part < 4) {
        size_t start = i;
        unsigned v = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            v = v * 10 + static_cast<unsigned>(s[i] - '0');
            if (v > 255) return false;
            i++;
            if (i - start > 3) return false;
        }
        if (i == start) return false;
        if (i - start > 1 && s[start] == '0') return false;  // no leading zeros: 010 is not 8 and not 10
        out[part++] = static_cast<uint8_t>(v);
        if (part < 4) {
            if (i >= s.size() || s[i] != '.') return false;
            i++;
        }
    }
    return i == s.size();
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool parse_v6(const std::string& s, uint8_t out[16]) {
    if (s.empty() || s.size() > 45) return false;
    uint16_t head[8], tail[8];
    int nh = 0, nt = 0;
    bool seen_gap = false;
    size_t i = 0;
    if (s[0] == ':') {
        if (s.size() < 2 || s[1] != ':') return false;
        seen_gap = true;
        i = 2;
    }
    bool last_was_group = false;
    while (i < s.size()) {
        // Embedded IPv4 in the last 32 bits.
        size_t dot = s.find('.', i);
        size_t colon = s.find(':', i);
        if (dot != std::string::npos && (colon == std::string::npos || dot < colon)) {
            uint8_t v4[4];
            if (!parse_v4(s.substr(i), v4)) return false;
            uint16_t g1 = static_cast<uint16_t>((v4[0] << 8) | v4[1]), g2 = static_cast<uint16_t>((v4[2] << 8) | v4[3]);
            auto& arr = seen_gap ? tail : head;
            int& n = seen_gap ? nt : nh;
            if (n + 2 > 8) return false;
            arr[n++] = g1;
            arr[n++] = g2;
            i = s.size();
            last_was_group = true;
            break;
        }
        size_t start = i;
        unsigned v = 0;
        while (i < s.size() && hexval(s[i]) >= 0) {
            v = (v << 4) | static_cast<unsigned>(hexval(s[i]));
            i++;
            if (i - start > 4) return false;
        }
        if (i == start) return false;
        auto& arr = seen_gap ? tail : head;
        int& n = seen_gap ? nt : nh;
        if (n >= 8) return false;
        arr[n++] = static_cast<uint16_t>(v);
        last_was_group = true;
        if (i == s.size()) break;
        if (s[i] != ':') return false;
        i++;
        if (i < s.size() && s[i] == ':') {
            if (seen_gap) return false;  // only one "::"
            seen_gap = true;
            i++;
            last_was_group = false;
            if (i == s.size()) break;
        } else if (i == s.size()) {
            return false;  // trailing single ':'
        }
    }
    (void)last_was_group;
    int total = nh + nt;
    if (seen_gap ? total > 7 : total != 8) return false;
    uint16_t full[8] = {0};
    for (int k = 0; k < nh; k++) full[k] = head[k];
    for (int k = 0; k < nt; k++) full[8 - nt + k] = tail[k];
    for (int k = 0; k < 8; k++) {
        out[2 * k] = static_cast<uint8_t>(full[k] >> 8);
        out[2 * k + 1] = static_cast<uint8_t>(full[k] & 0xff);
    }
    return true;
}

bool ip_string_is_public(const std::string& s) {
    uint8_t a4[4], a6[16];
    if (parse_v4(s, a4)) return is_public_v4(a4);
    if (parse_v6(s, a6)) return is_public_v6(a6);
    return false;
}

// ---- URLs -------------------------------------------------------------------------------------------------------------------

static bool ends_with(const std::string& s, const char* suf) {
    size_t n = std::strlen(suf);
    return s.size() >= n && s.compare(s.size() - n, n, suf) == 0;
}

Url parse_url(const std::string& url, bool allow_internal) {
    if (url.empty() || url.size() > 2048) throw fail(Err::InvalidUrl, "URL is empty or too long");
    for (unsigned char c : url) {
        if (c <= 0x20 || c >= 0x7f) throw fail(Err::InvalidUrl, "URL contains a control, space or non-ASCII character");
        if (c == '\\') throw fail(Err::InvalidUrl, "URL contains a backslash");
        if (c == '#') throw fail(Err::InvalidUrl, "URL contains a fragment");
    }
    static const char kScheme[] = "https://";
    if (url.size() < sizeof(kScheme) - 1) throw fail(Err::InvalidUrl, "only https is supported");
    for (size_t i = 0; i < sizeof(kScheme) - 1; i++)
        if (std::tolower(static_cast<unsigned char>(url[i])) != kScheme[i]) throw fail(Err::InvalidUrl, "only https is supported");
    size_t auth_start = sizeof(kScheme) - 1;
    size_t auth_end = url.find_first_of("/?", auth_start);
    std::string authority = url.substr(auth_start, auth_end == std::string::npos ? std::string::npos : auth_end - auth_start);
    std::string rest = auth_end == std::string::npos ? "" : url.substr(auth_end);
    if (authority.empty()) throw fail(Err::InvalidUrl, "no host");
    if (authority.find('@') != std::string::npos) throw fail(Err::InvalidUrl, "credentials in URL");
    if (authority.find('%') != std::string::npos) throw fail(Err::InvalidUrl, "percent-encoding in host");

    Url u;
    std::string host, port = "443";
    if (authority[0] == '[') {
        size_t close = authority.find(']');
        if (close == std::string::npos) throw fail(Err::InvalidUrl, "unterminated IPv6 literal");
        host = authority.substr(1, close - 1);
        std::string after = authority.substr(close + 1);
        if (!after.empty()) {
            if (after[0] != ':') throw fail(Err::InvalidUrl, "junk after IPv6 literal");
            port = after.substr(1);
            if (port.empty()) throw fail(Err::InvalidUrl, "empty port");
        }
        uint8_t a[16];
        if (!parse_v6(host, a)) throw fail(Err::InvalidUrl, "invalid IPv6 literal");
        if (!allow_internal && !is_public_v6(a)) throw fail(Err::BlockedAddress, "private or reserved address");
        u.host_is_ip = true;
        std::transform(host.begin(), host.end(), host.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    } else {
        size_t colon = authority.find(':');
        host = authority.substr(0, colon);
        if (colon != std::string::npos) {
            port = authority.substr(colon + 1);
            if (port.empty()) throw fail(Err::InvalidUrl, "empty port");
        }
        if (host.empty()) throw fail(Err::InvalidUrl, "no host");
        std::transform(host.begin(), host.end(), host.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (host.back() == '.') host.pop_back();
        if (host.empty() || host.size() > 253) throw fail(Err::InvalidUrl, "invalid host");
        // Labels: letters, digits, '-' and '_' only.
        size_t label_start = 0;
        std::string last_label;
        for (size_t i = 0; i <= host.size(); i++) {
            if (i == host.size() || host[i] == '.') {
                size_t len = i - label_start;
                if (len == 0 || len > 63) throw fail(Err::InvalidUrl, "invalid host label");
                last_label = host.substr(label_start, len);
                label_start = i + 1;
            } else {
                char c = host[i];
                if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.')) throw fail(Err::InvalidUrl, "invalid character in host");
            }
        }
        // 127.1, 0x7f.1, 2130706433 and 017700000001 are all "the same host" to some resolvers. Anything that looks numeric must
        // be a strict dotted quad, otherwise it is refused outright.
        bool numeric_tail = !last_label.empty() && std::all_of(last_label.begin(), last_label.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
        if (numeric_tail || last_label.rfind("0x", 0) == 0) {
            uint8_t a[4];
            if (!parse_v4(host, a)) throw fail(Err::InvalidUrl, "ambiguous numeric host");
            if (!allow_internal && !is_public_v4(a)) throw fail(Err::BlockedAddress, "private or reserved address");
            u.host_is_ip = true;
        } else if (!allow_internal) {
            bool internal = host == "localhost" || host.find('.') == std::string::npos;
            for (const char* suf : {".localhost", ".local", ".internal", ".localdomain", ".lan", ".home", ".corp", ".intranet"})
                if (ends_with(host, suf)) internal = true;
            if (internal) throw fail(Err::BlockedAddress, "internal-looking host name");
        }
    }
    if (port.size() > 5 || !std::all_of(port.begin(), port.end(), [](unsigned char c) { return std::isdigit(c) != 0; })) throw fail(Err::InvalidUrl, "invalid port");
    int pn = std::stoi(port);
    if (pn < 1 || pn > 65535) throw fail(Err::InvalidUrl, "port out of range");
    u.port = std::to_string(pn);
    u.host = host;
    if (rest.empty()) rest = "/";
    else if (rest[0] == '?') rest = "/" + rest;
    u.target = rest;
    bool v6 = host.find(':') != std::string::npos;
    u.host_header = (v6 ? "[" + host + "]" : host) + (pn == 443 ? "" : ":" + u.port);
    return u;
}

// ---- headers ----------------------------------------------------------------------------------------------------------------

static bool is_tchar(unsigned char c) {
    if (std::isalnum(c)) return true;
    return std::strchr("!#$%&'*+-.^_`|~", c) != nullptr && c != 0;
}

void check_request_header(const std::string& name, const std::string& value) {
    if (name.empty() || name.size() > 256) throw fail(Err::InvalidArgument, "bad header name");
    for (unsigned char c : name)
        if (!is_tchar(c)) throw fail(Err::InvalidArgument, "header name is not an HTTP token");
    if (value.size() > 8192) throw fail(Err::InvalidArgument, "header value too long");
    for (unsigned char c : value)
        if ((c < 0x20 && c != '\t') || c == 0x7f) throw fail(Err::InvalidArgument, "header value contains a control character");
    std::string low = name;
    std::transform(low.begin(), low.end(), low.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    static const char* kOwned[] = {"host", "content-length", "connection", "transfer-encoding", "te", "trailer", "upgrade", "expect",
                                   "accept-encoding", "keep-alive", "proxy-connection", "proxy-authorization", "http2-settings"};
    for (const char* o : kOwned)
        if (low == o) throw fail(Err::InvalidArgument, "header is set by the transport: " + low);
}

}  // namespace authlas::net
