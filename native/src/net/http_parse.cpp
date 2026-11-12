// Strict incremental HTTP/1.1 response parser.
#include "net_internal.hpp"

#include <algorithm>
#include <cctype>

namespace authlas::net {

static NetError proto(const std::string& m) { return NetError{Err::Protocol, "http: " + m}; }

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static bool token_char(unsigned char c) {
    if (std::isalnum(c)) return true;
    switch (c) {
        case '!': case '#': case '$': case '%': case '&': case '\'': case '*': case '+': case '-': case '.': case '^': case '_': case '`': case '|': case '~':
            return true;
        default:
            return false;
    }
}

ResponseParser::ResponseParser(size_t max_body, bool head_request, size_t max_head)
    : max_body_(max_body), max_head_(max_head), head_request_(head_request) {}

bool ResponseParser::feed(const uint8_t* p, size_t n) {
    if (state_ == State::Done) return true;
    buf_.append(reinterpret_cast<const char*>(p), n);
    run();
    return state_ == State::Done;
}

void ResponseParser::eof() {
    switch (state_) {
        case State::Done: return;
        case State::UntilClose: state_ = State::Done; return;
        case State::Head: throw proto("connection closed before a complete response head");
        default: throw proto("connection closed in the middle of the body");
    }
}

static void check_no_bare_lf(const std::string& s) {
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '\0') throw proto("NUL byte in message head");
        if (s[i] == '\n' && (i == 0 || s[i - 1] != '\r')) throw proto("bare LF in message head");
    }
}

void ResponseParser::parse_head(const std::string& head) {
    check_no_bare_lf(head);
    std::vector<std::string> lines;
    size_t pos = 0;
    while (true) {
        size_t e = head.find("\r\n", pos);
        if (e == std::string::npos) { lines.push_back(head.substr(pos)); break; }
        lines.push_back(head.substr(pos, e - pos));
        pos = e + 2;
    }
    const std::string& sl = lines[0];
    if (sl.size() < 12 || (sl.compare(0, 9, "HTTP/1.1 ") != 0 && sl.compare(0, 9, "HTTP/1.0 ") != 0)) throw proto("bad status line");
    for (int i = 9; i < 12; i++)
        if (!std::isdigit(static_cast<unsigned char>(sl[i]))) throw proto("bad status code");
    if (sl.size() > 12 && sl[12] != ' ') throw proto("bad status line");
    int code = (sl[9] - '0') * 100 + (sl[10] - '0') * 10 + (sl[11] - '0');
    if (code < 100 || code > 599) throw proto("status code out of range");
    if (code == 101) throw proto("protocol upgrade is not accepted");
    if (code >= 100 && code < 200) {
        if (++informational_ > 8) throw proto("too many informational responses");
        return;  // skip it; the final response follows
    }

    status = code;
    headers.clear();
    if (lines.size() - 1 > 200) throw proto("too many header fields");
    for (size_t i = 1; i < lines.size(); i++) {
        const std::string& l = lines[i];
        if (l.empty()) throw proto("empty header line");
        if (l[0] == ' ' || l[0] == '\t') throw proto("obsolete header line folding");
        size_t c = l.find(':');
        if (c == std::string::npos || c == 0) throw proto("malformed header field");
        std::string name = l.substr(0, c);
        for (unsigned char ch : name)
            if (!token_char(ch)) throw proto("invalid character in header name");
        size_t vb = c + 1, ve = l.size();
        while (vb < ve && (l[vb] == ' ' || l[vb] == '\t')) vb++;
        while (ve > vb && (l[ve - 1] == ' ' || l[ve - 1] == '\t')) ve--;
        std::string value = l.substr(vb, ve - vb);
        for (unsigned char ch : value)
            if ((ch < 0x20 && ch != '\t') || ch == 0x7f) throw proto("control character in header value");
        headers.emplace_back(lower(name), std::move(value));
    }

    // ---- framing (RFC 9112 6.3) ----
    std::vector<std::string> cls, tes, encs;
    for (auto& h : headers) {
        if (h.first == "content-length") cls.push_back(h.second);
        else if (h.first == "transfer-encoding") tes.push_back(h.second);
        else if (h.first == "content-encoding") encs.push_back(h.second);
    }
    bool no_body = head_request_ || code == 204 || code == 304;
    if (!tes.empty() && !cls.empty()) throw proto("both Transfer-Encoding and Content-Length");
    bool chunked = false;
    if (!tes.empty()) {
        if (tes.size() != 1 || lower(tes[0]) != "chunked") throw proto("unsupported Transfer-Encoding");
        chunked = true;
    }
    uint64_t cl = 0;
    bool have_cl = false;
    if (!cls.empty()) {
        for (auto& v : cls) {
            if (v.empty() || v.size() > 18 || !std::all_of(v.begin(), v.end(), [](unsigned char ch) { return std::isdigit(ch) != 0; })) throw proto("invalid Content-Length");
            uint64_t n = std::stoull(v);
            if (have_cl && n != cl) throw proto("conflicting Content-Length values");
            cl = n;
            have_cl = true;
        }
    }
    if (no_body) { state_ = State::Done; return; }
    for (auto& e : encs)
        if (lower(e) != "identity") throw proto("compressed responses are not accepted");
    if (chunked) { state_ = State::ChunkSize; return; }
    if (have_cl) {
        if (cl > max_body_) throw NetError{Err::TooLarge, "response body exceeds the limit"};
        remaining_ = cl;
        state_ = cl == 0 ? State::Done : State::Fixed;
        return;
    }
    state_ = State::UntilClose;
}

void ResponseParser::run() {
    for (;;) {
        switch (state_) {
            case State::Head: {
                size_t pos = buf_.find("\r\n\r\n");
                if (pos == std::string::npos) {
                    if (buf_.size() > max_head_) throw NetError{Err::TooLarge, "response head is too large"};
                    check_no_bare_lf(buf_);
                    return;
                }
                if (pos > max_head_) throw NetError{Err::TooLarge, "response head is too large"};
                std::string head = buf_.substr(0, pos);
                buf_.erase(0, pos + 4);
                parse_head(head);
                break;  // re-dispatch on the new state (or stay in Head after a 1xx)
            }
            case State::Fixed: {
                size_t take = static_cast<size_t>(std::min<uint64_t>(remaining_, buf_.size()));
                body.append(buf_, 0, take);
                buf_.erase(0, take);
                remaining_ -= take;
                if (remaining_ == 0) { state_ = State::Done; return; }
                return;
            }
            case State::ChunkSize: {
                size_t e = buf_.find("\r\n");
                if (e == std::string::npos) {
                    if (buf_.size() > 1024) throw proto("chunk size line is too long");
                    check_no_bare_lf(buf_);
                    return;
                }
                std::string line = buf_.substr(0, e);
                check_no_bare_lf(line + "\r\n");
                buf_.erase(0, e + 2);
                size_t semi = line.find(';');
                std::string hex = line.substr(0, semi);
                if (hex.empty() || hex.size() > 15) throw proto("invalid chunk size");
                uint64_t n = 0;
                for (unsigned char ch : hex) {
                    int v = std::isdigit(ch) ? ch - '0' : (ch >= 'a' && ch <= 'f') ? ch - 'a' + 10 : (ch >= 'A' && ch <= 'F') ? ch - 'A' + 10 : -1;
                    if (v < 0) throw proto("invalid chunk size");
                    n = (n << 4) | static_cast<uint64_t>(v);
                }
                if (n > max_body_ || body.size() + n > max_body_) throw NetError{Err::TooLarge, "response body exceeds the limit"};
                remaining_ = n;
                state_ = n == 0 ? State::Trailers : State::ChunkData;
                break;
            }
            case State::ChunkData: {
                size_t take = static_cast<size_t>(std::min<uint64_t>(remaining_, buf_.size()));
                body.append(buf_, 0, take);
                buf_.erase(0, take);
                remaining_ -= take;
                if (remaining_ > 0) return;
                state_ = State::ChunkCrlf;
                break;
            }
            case State::ChunkCrlf: {
                if (buf_.size() < 2) return;
                if (buf_[0] != '\r' || buf_[1] != '\n') throw proto("chunk data not followed by CRLF");
                buf_.erase(0, 2);
                state_ = State::ChunkSize;
                break;
            }
            case State::Trailers: {
                size_t e = buf_.find("\r\n");
                if (e == std::string::npos) {
                    if (buf_.size() > 8192) throw proto("trailers are too large");
                    check_no_bare_lf(buf_);
                    return;
                }
                if (e == 0) { buf_.erase(0, 2); state_ = State::Done; return; }
                trailer_bytes_ += e + 2;
                if (trailer_bytes_ > 8192) throw proto("trailers are too large");
                check_no_bare_lf(buf_.substr(0, e + 2));
                buf_.erase(0, e + 2);  // trailer fields are discarded
                break;
            }
            case State::UntilClose: {
                if (body.size() + buf_.size() > max_body_) throw NetError{Err::TooLarge, "response body exceeds the limit"};
                body += buf_;
                buf_.clear();
                return;
            }
            case State::Done: return;
        }
    }
}

}  // namespace authlas::net
