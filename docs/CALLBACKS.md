# Authlas C ABI: design for callbacks and the stateful flows

Status: adopted in slice 2. Every binding (Python, C++, Java) implements the same contract.

## Why callbacks

Some flows need state the library must not own: the registered-client store, the revocation list, the device-code
store, the pushed-request (PAR) store, the authorization-code and refresh-token stores. Those belong to the host
application, which has its own database. The library asks for data through **one callback table per store**, and the
host answers from its own storage.

Stateless one-shot calls (sign, verify, parse, check) take JSON and return JSON. They need no callbacks.

## The contract

Each stateful store is a C struct of function pointers plus a `void *user` context:

    typedef struct AuthlasClientStore {
        void *user;
        /* Return 0 and fill `out` with the client JSON, or return AUTHLAS_STATUS_NOT_FOUND. The library frees `out`. */
        int (*get_client)(void *user, const char *client_id, AuthlasBuf *out);
        int (*put_client)(void *user, const char *client_json);
        int (*delete_client)(void *user, const char *client_id);
    } AuthlasClientStore;

Rules every store follows:

1. A callback returns a status code. `0` is success. Any other value is an error, and the library turns it into an
   `AUTHLAS_STATUS_*` return with a message.
2. Any buffer a callback fills is allocated with the library's allocator and released by the library. Callbacks write
   into `AuthlasBuf` with `authlas_buf_set` (a helper we export), so ownership is never ambiguous.
3. A callback must not unwind into C. Each binding wraps its callback in a catch that converts an exception into an
   error status.
4. Callbacks may be called from any thread the caller uses. The store is responsible for its own locking.
5. Time comes from the caller through `now` arguments, so tests do not depend on the wall clock.

## Which stores exist

| Flow | Store | Callbacks |
|---|---|---|
| Dynamic client registration (RFC 7591/7592) | client store | get, put, delete |
| Token revocation (RFC 7009) | revoker | find_token, revoke_token |
| Device grant (RFC 8628) | device store | start, lookup_user_code, decide, poll |
| PAR (RFC 9126) | PAR store | push, redeem |
| Token exchange and step-up | rule set | (rules are data, no callback) |

The authorization-code and refresh-token stores are host application code and are not part of the library ABI. The
library's job is to check a code or refresh request, not to hold codes.

## Slice order

- Slice 2: JSON one-shot OAuth functions (metadata parse, PKCE, scopes, redirect checks, RAR, introspection parse,
  introspection JWT response, token exchange response, PAR response, request-object sign and verify, client
  authentication helpers, mTLS binding).
- Slice 3: store callbacks for client registration, revocation, PAR and the device grant.
- Slice 4: OIDC ID-token and claims helpers. SD-JWT VC and status list helpers.
- Slice 5: MCP (resource metadata, WWW-Authenticate challenges, CIMD check, token audience check).
