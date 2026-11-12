# authlas (Rust crate)

One crate, `authlas`, with three parts:

- the Rust OAuth 2.x and JOSE core (default feature `backend-awslc`),
- a stable C ABI (feature `capi`, exports 32 `authlas_*` functions, header in `include/authlas.h`),
- a C++ HTTPS transport (feature `net`, sources in `native/`, compiled by `build.rs`).

```toml
[dependencies]
authlas = "0.1"
```

Enable the C ABI or transport with `features = ["capi"]` or `features = ["net"]`. The `net` feature needs OpenSSL 3 at build
time; set `OPENSSL_DIR` if OpenSSL is not on the default search path.

# authlas 0.1.0

OAuth 2.0 and JOSE as one stable C ABI with bindings for C++, Python, TypeScript/Node and C#. "authlas" is a working name. The final name
and the license are not decided yet, so this release carries no license file and is not for redistribution.

## What is in the box

| Piece | What it is |
|---|---|
| `lib/authlas.dll` | Rust core behind `include/authlas.h`: JOSE (JWS, JWE, JWK, JWT), PKCE, redirect rules, bearer, RFC 9068 access tokens, DPoP, SD-JWT, certificate reading. Crypto backend chosen at build time (this build: aws-lc). |
| `lib/authlas_net.dll` | C++ HTTPS client behind `include/authlas_net.h`. TLS 1.2+, SSRF guard, strict HTTP/1.1 parser, no redirects, no compression. |
| `lib/libssl-3-x64.dll`, `lib/libcrypto-3-x64.dll` | OpenSSL 3 runtime that `authlas_net.dll` needs. |
| `cpp/` | Header-only C++17 wrapper (`authlas/authlas.hpp`). |
| `python/authlas/` | Protocol layer: discovery, OAuth client, CIBA, OpenID4VCI wallet, OpenID4VP wallet and verifier, DCQL, MCP authorization (client and resource server). Needs `cryptography>=42`. |
| `ts/` | Node binding (ESM, TypeScript types, koffi 2.16.3). |
| `dotnet/` | C# binding (net8.0, no NuGet dependencies). |

## Using it

Every binding finds the two libraries the same way: `AUTHLAS_CORE_LIB` / `AUTHLAS_NET_LIB` (a file), then `AUTHLAS_LIB_DIR` (a directory),
then next to the application. Point `AUTHLAS_LIB_DIR` at `lib/` and everything works.

```
set AUTHLAS_LIB_DIR=%CD%\lib
```

Python:

```python
import sys; sys.path.insert(0, "python")
import authlas
from authlas import core
key = core.generate_ec_key("P-256")
```

Node: `import * as authlas from "./ts/dist/src/index.js"` (run `npm install koffi@2.16.3` next to it).

C#: reference `dotnet/bin/AuthlasDotNet.dll`.

C++: add `cpp/include`, `include/`, link `lib/authlas.dll.lib` and `lib/authlas_net.lib`.

## Rules the library keeps

- Algorithm allow-lists are required on every verify call. There is no default. `alg: none` is refused in this build.
- `iss`, `aud` and `exp` are mandatory for JWTs. Keys from `jwk`, `jku`, `x5u` or `x5c` headers are never used to pick a verification key.
- PKCE S256 is mandatory. Redirect URIs match exactly (loopback IP literals may vary the port; `localhost` may not).
- JSON with duplicate member names, lone surrogates or trailing data is rejected by every binding.
- Network: https only, every resolved address is checked and the checked address is the one connected to, redirects are off by default
  and checked hop by hop when on, credentials are dropped when the origin changes.
- Secrets are wiped where the language allows (C++ `Secret`, C# `Secret.Dispose`, Node `Secret.wipe`) and never print.

## Known limits of 0.1.0

- Windows x64 only has been built and tested. Linux and macOS need the same sources built there.
- Rust is frozen at its current feature set. It is not exposed through the C ABI for: mTLS, dynamic registration, assertion grants, FAPI 2.0,
  introspection, revocation, device grant, token exchange, PAR/JAR/RAR, OIDC, SD-JWT VC and Token Status List. Python implements the client
  side of most of these on top of the C ABI; the Rust modules are reachable only from Rust.
- Not implemented: JWE/JWS JSON serialization, RFC 7797 `b64=false`, OAuth 1.0, CWT/COSE, OpenID4VP `transaction_data`, Digital Credentials
  API, mdoc and W3C credential formats.
- TS and C# have the C ABI surface (JOSE, tokens, DPoP, SD-JWT, HTTPS), not the Python protocol flows. Use Python for the flows.
- The transport opens one connection per request (no keep-alive, no HTTP/2).

## Verifying the bundle

`SHA256SUMS` lists every file. `smoke/run.bat` runs a self-check using only files in this folder.
