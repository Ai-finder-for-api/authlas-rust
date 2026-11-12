/* Authlas native network layer: C ABI.
 *
 * A flat C interface (no JSON, no C++ types) over the C++ transport so that Python, C#, Go and anything else with an FFI can call
 * it. Every function returns an AuthlasNetStatus and never throws. The message for the last failure on this thread is available
 * from authlas_net_last_error().
 */
#ifndef AUTHLAS_NET_H
#define AUTHLAS_NET_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#  ifdef AUTHLAS_NET_BUILD
#    define AUTHLAS_NET_API __declspec(dllexport)
#  else
#    define AUTHLAS_NET_API __declspec(dllimport)
#  endif
#else
#  define AUTHLAS_NET_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define AUTHLAS_NET_ABI_VERSION 1

typedef enum {
  AUTHLAS_NET_OK = 0,
  AUTHLAS_NET_INVALID_URL = 1,
  AUTHLAS_NET_BLOCKED_ADDRESS = 2, /* SSRF guard: the target is private, reserved or internal-looking */
  AUTHLAS_NET_RESOLVE = 3,
  AUTHLAS_NET_CONNECT = 4,
  AUTHLAS_NET_TLS = 5, /* handshake failure, bad certificate, wrong host name, protocol too old */
  AUTHLAS_NET_TIMEOUT = 6,
  AUTHLAS_NET_PROTOCOL = 7, /* the peer sent something that is not a well-formed HTTP/1.1 response */
  AUTHLAS_NET_TOO_LARGE = 8,
  AUTHLAS_NET_INVALID_ARGUMENT = 9,
  AUTHLAS_NET_IO = 10,
  AUTHLAS_NET_INTERNAL = 11
} AuthlasNetStatus;

typedef struct {
  const char *method;                 /* "GET", "POST", "PUT", "DELETE" or "HEAD"; NULL means GET */
  const char *url;                    /* https only */
  const char *const *header_names;    /* header_count entries; NULL when header_count is 0 */
  const char *const *header_values;
  size_t header_count;
  const uint8_t *body;                /* NULL when body_len is 0 */
  size_t body_len;
  uint32_t timeout_ms;                /* 0 = 10000. Covers resolve, connect, handshake, request and response */
  uint64_t max_response_bytes;        /* 0 = 1 MiB. Limit on the body. */
  const char *ca_file;                /* PEM bundle replacing the system trust store; NULL = system store */
  int allow_internal;                 /* nonzero lets loopback/private targets through (tests, intranets). Default 0. */
} AuthlasHttpRequest;

typedef struct {
  int status;
  char *headers;        /* "name: value\n" per header, names lower case, NUL-terminated */
  uint8_t *body;        /* NUL-terminated for convenience; body_len does not count the NUL */
  size_t body_len;
  char *peer_address;   /* the address actually connected to */
  char *tls_version;
} AuthlasHttpResponse;

AUTHLAS_NET_API int authlas_net_abi_version(void);

/* One HTTPS request on a fresh connection. No redirects are followed; the caller decides (and must check each hop). */
AUTHLAS_NET_API int authlas_net_fetch(const AuthlasHttpRequest *req, AuthlasHttpResponse *out);
AUTHLAS_NET_API void authlas_net_response_free(AuthlasHttpResponse *resp);

/* Static URL check without any network I/O. */
AUTHLAS_NET_API int authlas_net_url_check(const char *url, int allow_internal);

/* *is_public = 1 if `ip` is a public IPv4 or IPv6 literal, else 0. Returns INVALID_ARGUMENT if `ip` is not an IP literal. */
AUTHLAS_NET_API int authlas_net_ip_is_public(const char *ip, int *is_public);

/* Parses one complete HTTP/1.1 response from memory with the same strict parser the transport uses.
 * Useful for tests and for callers that bring their own socket. `head_request` != 0 means the response answers a HEAD. */
AUTHLAS_NET_API int authlas_net_parse_response(const uint8_t *data, size_t len, uint64_t max_body, int head_request,
                                              AuthlasHttpResponse *out);

/* Same as authlas_net_fetch, but the failure message is copied into `err` (NUL-terminated, truncated to `err_cap` bytes) instead of
 * being left in thread-local storage. Use this from runtimes that move work between threads (Node worker threads, Go, .NET tasks):
 * authlas_net_last_error() would be read on a different thread than the one that failed. `err` may be NULL when err_cap is 0. */
AUTHLAS_NET_API int authlas_net_fetch_err(const AuthlasHttpRequest *req, AuthlasHttpResponse *out, char *err, size_t err_cap);

/* Message for the last failure on this thread. Never NULL. Valid until the next call on this thread. */
AUTHLAS_NET_API const char *authlas_net_last_error(void);

#ifdef __cplusplus
}
#endif
#endif
