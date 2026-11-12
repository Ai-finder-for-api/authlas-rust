// Unit tests for addresses, URLs, request headers and the strict response parser. No network.
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>

#include "net/net_internal.hpp"

using namespace authlas::net;

static int g_fail = 0, g_run = 0;
#define CHECK(c) do { g_run++; if (!(c)) { g_fail++; std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

static bool throws(const std::function<void()>& f, Err want) {
    try { f(); } catch (const NetError& e) { return e.code == want; }
    return false;
}
static bool throws_any(const std::function<void()>& f) {
    try { f(); } catch (const NetError&) { return true; }
    return false;
}

static ResponseParser parse_all(const std::string& raw, size_t max_body = 1 << 20, bool head = false) {
    ResponseParser p(max_body, head);
    p.feed(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
    if (!p.done()) p.eof();
    return p;
}
static bool parse_fails(const std::string& raw, size_t max_body = 1 << 20) {
    try { parse_all(raw, max_body); } catch (const NetError&) { return true; }
    return false;
}

static void test_addresses() {
    struct { const char* ip; bool pub; } cases[] = {
        {"8.8.8.8", true}, {"1.1.1.1", true}, {"93.184.216.34", true}, {"172.15.255.255", true}, {"172.32.0.1", true}, {"100.63.255.255", true}, {"100.128.0.1", true},
        {"127.0.0.1", false}, {"127.255.255.254", false}, {"10.0.0.1", false}, {"172.16.0.1", false}, {"172.31.255.255", false}, {"192.168.1.1", false},
        {"169.254.169.254", false}, {"0.0.0.0", false}, {"100.64.0.1", false}, {"100.127.255.255", false}, {"192.0.0.1", false}, {"192.0.2.1", false},
        {"198.51.100.1", false}, {"203.0.113.1", false}, {"198.18.0.1", false}, {"198.19.255.255", false}, {"224.0.0.1", false}, {"240.0.0.1", false},
        {"255.255.255.255", false},
        {"2606:4700:4700::1111", true}, {"2001:4860:4860::8888", true},
        {"::1", false}, {"::", false}, {"fe80::1", false}, {"fc00::1", false}, {"fd12:3456::1", false}, {"ff02::1", false}, {"2001:db8::1", false},
        {"2001:0:4136:e378:8000:63bf:3fff:fdd2", false}, {"::ffff:127.0.0.1", false}, {"::ffff:8.8.8.8", true}, {"::ffff:10.0.0.1", false}, {"::127.0.0.1", false},
        {"64:ff9b::7f00:1", false}, {"64:ff9b::808:808", true}, {"2002:7f00:1::1", false}, {"2002:808:808::1", true}, {"fec0::1", false},
    };
    for (auto& c : cases) CHECK(ip_string_is_public(c.ip) == c.pub);

    // Textual forms that resolvers disagree about must not parse as IPv4 at all.
    uint8_t a[4], b[16];
    for (const char* bad : {"127.1", "0x7f.0.0.1", "2130706433", "017700000001", "010.0.0.1", "1.2.3", "1.2.3.4.5", "1.2.3.256", "1..2.3", "1.2.3.", ".1.2.3", "+1.2.3.4", "1.2.3.-4", " 1.2.3.4", "1.2.3.4 ", "1.2.3.0x4", "00.0.0.0", ""})
        CHECK(!parse_v4(bad, a));
    CHECK(parse_v4("0.0.0.0", a) && parse_v4("255.255.255.255", a) && parse_v4("1.2.3.4", a));
    for (const char* bad : {"", ":", ":::", "1::2::3", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7", "12345::1", "g::1", "::1%eth0", "1:2:3:4:5:6:7:", ":1:2:3:4:5:6:7", "::1.2.3", "::1.2.3.256", "1.2.3.4::", "[::1]"})
        CHECK(!parse_v6(bad, b));
    CHECK(parse_v6("::", b) && parse_v6("::1", b) && parse_v6("1::", b) && parse_v6("1:2:3:4:5:6:7:8", b) && parse_v6("1:2:3:4:5:6:7::", b) && parse_v6("::2:3:4:5:6:7:8", b) && parse_v6("::ffff:1.2.3.4", b) && parse_v6("64:ff9b::1.2.3.4", b));
    CHECK(parse_v6("::ffff:1.2.3.4", b) && b[10] == 0xff && b[11] == 0xff && b[12] == 1 && b[15] == 4);
    CHECK(parse_v6("1::8", b) && b[0] == 0 && b[1] == 1 && b[15] == 8 && b[14] == 0);
}

static void test_urls() {
    Url u = parse_url("https://Example.COM/a/b?x=1", false);
    CHECK(u.host == "example.com" && u.port == "443" && u.target == "/a/b?x=1" && u.host_header == "example.com");
    u = parse_url("https://example.com", false);
    CHECK(u.target == "/");
    u = parse_url("https://example.com?x=1", false);
    CHECK(u.target == "/?x=1");
    u = parse_url("https://example.com:8443/p", false);
    CHECK(u.port == "8443" && u.host_header == "example.com:8443");
    u = parse_url("HTTPS://example.com./p", false);
    CHECK(u.host == "example.com");
    u = parse_url("https://[2606:4700:4700::1111]:8443/p", false);
    CHECK(u.host == "2606:4700:4700::1111" && u.host_is_ip && u.host_header == "[2606:4700:4700::1111]:8443");
    u = parse_url("https://8.8.8.8/", false);
    CHECK(u.host_is_ip);

    for (const char* bad : {"http://example.com/", "ftp://example.com/", "example.com", "//example.com", "https:/example.com", "https://", "https:///x", "https://user@example.com/", "https://user:pw@example.com/",
                            "https://example.com/#frag", "https://example.com/a b", "https://example.com/\r\nHost: evil", "https://example.com/\x01", "https://example.com\\@evil.com/", "https://example.com/a\\b",
                            "https://exa mple.com/", "https://example.com:/", "https://example.com:0/", "https://example.com:65536/", "https://example.com:99999999/", "https://example.com:80a/", "https://example.com:-1/",
                            "https://ex%61mple.com/", "https://[::1/", "https://[::1]x/", "https://[zz]/", "https://exa..mple.com/", "https://.example.com/", "https://exa$mple.com/", "https://\xc3\xa9xample.com/",
                            "https://127.1/", "https://0x7f.0.0.1/", "https://2130706433/", "https://017700000001/", "https://1.2.3/", "https://0x7f000001/", "https://10.1/"})
        CHECK(throws_any([&] { parse_url(bad, false); }));
    CHECK(throws(std::function<void()>([] { parse_url(std::string(2100, 'a'), false); }), Err::InvalidUrl));

    // Internal targets are blocked by default and by the right error.
    for (const char* blocked : {"https://127.0.0.1/", "https://10.0.0.5/", "https://192.168.0.1/", "https://169.254.169.254/latest/meta-data/", "https://[::1]/", "https://[fe80::1]/", "https://[::ffff:127.0.0.1]/",
                                "https://localhost/", "https://LOCALHOST./", "https://foo.localhost/", "https://printer.local/", "https://db.internal/", "https://intranet/", "https://host.lan/", "https://x.corp/"})
        CHECK(throws(std::function<void()>([&] { parse_url(blocked, false); }), Err::BlockedAddress));
    // ... and let through when the caller says so.
    CHECK(parse_url("https://127.0.0.1:8443/", true).port == "8443");
    CHECK(parse_url("https://localhost:8443/", true).host == "localhost");
    CHECK(parse_url("https://[::1]:8443/", true).host_is_ip);
    // Garbage stays garbage even with allow_internal.
    CHECK(throws_any([] { parse_url("http://localhost/", true); }));
    CHECK(throws_any([] { parse_url("https://0x7f.1/", true); }));
}

static void test_headers() {
    check_request_header("Authorization", "Bearer abc.def");
    check_request_header("X-Custom_1", "a\tb");
    for (const char* name : {"Host", "host", "Content-Length", "CONTENT-LENGTH", "Connection", "Transfer-Encoding", "TE", "Upgrade", "Expect", "Accept-Encoding", "Keep-Alive", "Proxy-Authorization", "Trailer", "HTTP2-Settings"})
        CHECK(throws(std::function<void()>([&] { check_request_header(name, "x"); }), Err::InvalidArgument));
    for (const char* name : {"", "Bad Name", "Bad:Name", "Bad\r\nName", "Na\tme", "Na(me", "Name\x80", "A@B"})
        CHECK(throws(std::function<void()>([&] { check_request_header(name, "x"); }), Err::InvalidArgument));
    for (const char* val : {"a\r\nX-Injected: 1", "a\nb", "a\rb", "a\x01" "b", "a\x7f" "b"}) {
        std::string v = val;
        CHECK(throws(std::function<void()>([&] { check_request_header("X-A", v); }), Err::InvalidArgument));
    }
    std::string nul("a\0b", 3);
    CHECK(throws(std::function<void()>([&] { check_request_header("X-A", nul); }), Err::InvalidArgument));
    CHECK(throws(std::function<void()>([] { check_request_header("X-A", std::string(9000, 'a')); }), Err::InvalidArgument));
}

static void test_parser_ok() {
    auto p = parse_all("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"a\":\"b\"}\n\n");
    CHECK(p.status == 200 && p.body == "{\"a\":\"b\"}\n\n" && p.headers.size() == 2 && p.headers[0].first == "content-type");

    p = parse_all("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n");
    CHECK(p.body == "hello world" && p.done());

    p = parse_all("HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n");
    CHECK(p.body == "0123456789");

    p = parse_all("HTTP/1.0 200 OK\r\n\r\nuntil close");
    CHECK(p.body == "until close");

    p = parse_all("HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n");
    CHECK(p.status == 204 && p.body.empty());
    p = parse_all("HTTP/1.1 304 Not Modified\r\n\r\n");
    CHECK(p.status == 304 && p.body.empty());
    p = parse_all("HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n", 1 << 20, true);
    CHECK(p.status == 200 && p.body.empty() && p.done());

    p = parse_all("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok");
    CHECK(p.status == 201 && p.body == "ok");

    p = parse_all("HTTP/1.1 404\r\nContent-Length: 0\r\n\r\n");
    CHECK(p.status == 404);
    p = parse_all("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc");
    CHECK(p.body == "abc");
    p = parse_all("HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Length: 1\r\n\r\nx");
    CHECK(p.body == "x");
    p = parse_all("HTTP/1.1 200 OK\r\nX-Pad:   spaced value \t \r\nContent-Length: 0\r\n\r\n");
    CHECK(p.headers[0].second == "spaced value");

    // Byte-at-a-time delivery gives the same answer.
    std::string raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n";
    ResponseParser q(1 << 20, false);
    for (char c : raw) q.feed(reinterpret_cast<const uint8_t*>(&c), 1);
    CHECK(q.done() && q.body == "abcdef");
    // Nothing is read past the end of the message.
    ResponseParser r2(1 << 20, false);
    std::string two = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nEVIL";
    r2.feed(reinterpret_cast<const uint8_t*>(two.data()), two.size());
    CHECK(r2.done() && r2.body == "ok");
}

static void test_parser_rejects() {
    // Request smuggling shapes.
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n0\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nContent-Length: 3, 4\r\n\r\nabcd"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nContent-Length: +3\r\n\r\nabc"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nContent-Length: 0x3\r\n\r\nabc"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nContent-Length: \r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\n\r\nabc"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n"));   // space before colon
    // Malformed head.
    CHECK(parse_fails("HTTP/1.1 200 OK\nContent-Length: 0\n\n"));                               // bare LF
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nContent-Length: 0\n\r\n"));                          // bare LF in a header line
    CHECK(parse_fails("HTTP/2 200 OK\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.2 200 OK\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 20 OK\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 2000 OK\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 099 X\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 600 X\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 200OK\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nBad Name: x\r\nContent-Length: 0\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\n: x\r\nContent-Length: 0\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nNoColon\r\nContent-Length: 0\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nX: a\r\n b\r\nContent-Length: 0\r\n\r\n"));        // obs-fold
    CHECK(parse_fails("HTTP/1.1 200 OK\r\n X: a\r\nContent-Length: 0\r\n\r\n"));
    CHECK(parse_fails(std::string("HTTP/1.1 200 OK\r\nX: a\0b\r\nContent-Length: 0\r\n\r\n", 48)));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nX: a\x01" "b\r\nContent-Length: 0\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: 1\r\n\r\nx"));
    // Chunk framing.
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\nabc\r\n0\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\r\n0\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0x3\r\nabc\r\n0\r\n\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\n"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX0\r\n\r\n"));   // data not followed by CRLF
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\nabc\r\n0\r\n\r\n"));     // bare LF after size
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n"));       // truncated before final CRLF
    // Truncation is an error, not a short body.
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel"));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\nContent-Length: 1"));
    CHECK(parse_fails(""));
    CHECK(parse_fails("HTTP/1.1 200 OK\r\n"));
}

static void test_parser_limits() {
    // Body limit applies to every framing, and is checked before the data is buffered when the size is announced.
    CHECK(throws(std::function<void()>([] { parse_all("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n01234567890", 10); }), Err::TooLarge));
    CHECK(throws(std::function<void()>([] { parse_all("HTTP/1.1 200 OK\r\nContent-Length: 4000000000\r\n\r\n", 1000); }), Err::TooLarge));
    CHECK(throws(std::function<void()>([] { parse_all("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nB\r\n01234567890\r\n0\r\n\r\n", 10); }), Err::TooLarge));
    CHECK(throws(std::function<void()>([] { parse_all("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\n012345\r\n6\r\n012345\r\n0\r\n\r\n", 10); }), Err::TooLarge));
    CHECK(throws(std::function<void()>([] { parse_all("HTTP/1.1 200 OK\r\n\r\n01234567890", 10); }), Err::TooLarge));
    CHECK(parse_all("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789", 10).body.size() == 10);
    // Head limits.
    std::string big_header = "HTTP/1.1 200 OK\r\nX: " + std::string(70000, 'a') + "\r\nContent-Length: 0\r\n\r\n";
    CHECK(throws(std::function<void()>([&] { parse_all(big_header); }), Err::TooLarge));
    ResponseParser endless(1 << 20, false);
    std::string chunk(4096, 'a');
    bool rejected = false;
    try { for (int i = 0; i < 100; i++) endless.feed(reinterpret_cast<const uint8_t*>(chunk.data()), chunk.size()); } catch (const NetError&) { rejected = true; }
    CHECK(rejected);  // a head that never ends is cut off, not buffered forever
    std::string many = "HTTP/1.1 200 OK\r\n";
    for (int i = 0; i < 300; i++) many += "X-" + std::to_string(i) + ": 1\r\n";
    many += "Content-Length: 0\r\n\r\n";
    CHECK(parse_fails(many));
    std::string infos;
    for (int i = 0; i < 20; i++) infos += "HTTP/1.1 100 Continue\r\n\r\n";
    CHECK(parse_fails(infos + "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
    std::string trailers = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n";
    for (int i = 0; i < 400; i++) trailers += "X-T: " + std::string(40, 'a') + "\r\n";
    CHECK(parse_fails(trailers + "\r\n"));
}

int main() {
    test_addresses();
    test_urls();
    test_headers();
    test_parser_ok();
    test_parser_rejects();
    test_parser_limits();
    std::printf("net_tests: %d checks, %d failed\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
