// Authlas native network layer: internals shared by the transport, the C ABI and the tests.
//
// Everything here is written to be driven by input an attacker chose (URLs from client metadata, redirect targets, response bytes).
// Failures are reported by throwing NetError; nothing crosses the C ABI as an exception.
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace authlas::net {

enum class Err : int {
    Ok = 0,
    InvalidUrl = 1,
    BlockedAddress = 2,
    Resolve = 3,
    Connect = 4,
    Tls = 5,
    Timeout = 6,
    Protocol = 7,
    TooLarge = 8,
    InvalidArgument = 9,
    Io = 10,
};

struct NetError {
    Err code;
    std::string message;
};

// ---- addresses --------------------------------------------------------------------------------------------------------------

// True for addresses on the public internet. Mirrors crates/authlas/src/ssrf.rs and adds nothing it does not have.
bool is_public_v4(const uint8_t a[4]);
bool is_public_v6(const uint8_t a[16]);

// Strict textual parsers. IPv4: exactly four decimal parts, no leading zeros (so no octal or hex forms). IPv6: no zone id.
bool parse_v4(const std::string& s, uint8_t out[4]);
bool parse_v6(const std::string& s, uint8_t out[16]);

// True if `s` is an IP literal (either family) that is public. False for non-literals and for anything not public.
bool ip_string_is_public(const std::string& s);

// ---- URLs -------------------------------------------------------------------------------------------------------------------

struct Url {
    std::string host;         // lower case, no brackets, no trailing dot
    std::string port;         // decimal
    std::string target;       // path and query, always starts with '/'
    std::string host_header;  // value for the Host header
    bool host_is_ip = false;
};

// https only. Rejects credentials, fragments, backslashes, control characters, non-ASCII hosts, odd numeric hosts such as 0x7f.1,
// and (unless allow_internal) internal-looking names and private IP literals.
Url parse_url(const std::string& url, bool allow_internal);

// ---- request headers --------------------------------------------------------------------------------------------------------

// Throws InvalidArgument for a name that is not an RFC 9110 token, a value with CR, LF, NUL or other control bytes, or a header the
// transport sets itself (Host, Content-Length, Connection, Transfer-Encoding, Accept-Encoding, ...).
void check_request_header(const std::string& name, const std::string& value);

// ---- responses --------------------------------------------------------------------------------------------------------------

// Incremental HTTP/1.1 response parser. Strict on purpose: bare LF, folded headers, conflicting framing (Transfer-Encoding with
// Content-Length, differing Content-Length values), compressed bodies and oversized messages are all errors.
class ResponseParser {
public:
    ResponseParser(size_t max_body, bool head_request, size_t max_head = 65536);

    // Feeds bytes. Returns true once the message is complete. Throws NetError.
    bool feed(const uint8_t* p, size_t n);
    // Call on a clean end of stream. Completes a read-until-close body, throws if anything else is unfinished.
    void eof();
    bool done() const { return state_ == State::Done; }
    // True when the body can only be delimited by the connection closing.
    bool needs_close() const { return state_ == State::UntilClose; }

    int status = 0;
    std::vector<std::pair<std::string, std::string>> headers;  // names lower case
    std::string body;

private:
    enum class State { Head, Fixed, ChunkSize, ChunkData, ChunkCrlf, Trailers, UntilClose, Done };
    void parse_head(const std::string& head);
    void run();

    size_t max_body_, max_head_;
    bool head_request_;
    State state_ = State::Head;
    std::string buf_;
    uint64_t remaining_ = 0;
    size_t trailer_bytes_ = 0;
    int informational_ = 0;
};

// ---- transport --------------------------------------------------------------------------------------------------------------

struct Request {
    std::string method = "GET";  // GET, POST, PUT, DELETE or HEAD
    std::string url;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    uint32_t timeout_ms = 10000;            // covers connect, handshake, request and response together; 1..120000
    uint64_t max_response_bytes = 1 << 20;  // body limit; 1..64 MiB
    std::string ca_file;                    // PEM bundle that replaces the system trust store; empty = system store
    bool allow_internal = false;            // permit loopback, private and link-local targets (tests, intranet deployments)
};

struct Response {
    int status = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    std::string peer_address;  // the address the connection was actually made to
    std::string tls_version;
};

// One request, one connection, no redirects. Throws NetError.
Response fetch(const Request& r);

// Calls `cb` with the DER of every certificate in the Windows ROOT store. No-op elsewhere.
void for_each_system_root(void (*cb)(const unsigned char* der, unsigned long len, void* ctx), void* ctx);

}  // namespace authlas::net
