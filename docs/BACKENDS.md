# Crypto backends

Cargo features decide what is **compiled**. `crypto_backends=` decides which compiled backend is **active** (the first entry).

| name | what | needs |
|---|---|---|
| `awslc` | aws-lc-rs (default) | C toolchain |
| `openssl` | system OpenSSL | OpenSSL 3 |
| `rustcrypto` | pure Rust. RSA private operations are not constant time (RUSTSEC-2023-0071), so avoid it for RSA decryption on servers | none |
| `qscrypt` | quantum-suite `qs_crypt`, loaded at run time | `qs_crypt.dll` / `libqs_crypt.so` |
| `hardened` | runs every operation through 2+ of the others and fails closed on any disagreement | at least two other backends |

## Setting it

Put one line next to your package. The first match wins, searched upward from the build directory:

- `authlas.conf`: `crypto_backends=awslc,qscrypt`
- `pyproject.toml`: section `[tool.authlas]`, `crypto_backends = ["awslc", "qscrypt"]`
- `package.json`: `{"authlas": {"crypto_backends": ["awslc", "qscrypt"]}}`
- `CMakeLists.txt`: `set(AUTHLAS_CRYPTO_BACKENDS "awslc;qscrypt")`
- environment variable `AUTHLAS_CRYPTO_BACKENDS` (overrides the files)

`python tools/backends.py --print cargo` turns that line into `--no-default-features --features ...` for cargo, maturin, napi or CMake.

`build.rs` stops the build if a requested backend was not compiled in, or the name is unknown. Nothing is guessed.
To make `hardened` active, list it first: `crypto_backends=hardened,awslc,openssl`.

## qscrypt

- `AUTHLAS_QSCRYPT_PATH`: full path to the library (default: next to the executable).
- `AUTHLAS_QSCRYPT_SHA256`: if set, the file must match before it is loaded. Without it the library loads unpinned.
- The library must report version 0.2.x and export every symbol used.
- qs_crypt has no: ECDSA P-384/P-521, ECDH or key generation on NIST curves, RSA-OAEP with SHA-1, AES-192-GCM.
  These return `Error::Unsupported`. `hardened` routes them to another backend.
- AES in qs_crypt is table based, so it has a cache-timing exposure on shared hardware.
