# authlas-core (Python)

ctypes binding to the Rust C ABI (`authlas.dll`, `libauthlas.so`, `libauthlas.dylib`). Stateless calls return plain
Python values. Stateful flows (PAR, revocation, client registration, device grant, client-auth replay) take a store
class whose methods the library calls back into.

Load the library with `AUTHLAS_CORE_LIB` (full path), or `AUTHLAS_LIB_DIR` (a folder). On Windows, set
`AUTHLAS_DLL_DIRS` to the folder holding the OpenSSL DLLs (`libcrypto-3-x64.dll`, `libssl-3-x64.dll`).

Run the tests:

    AUTHLAS_CORE_LIB=/path/to/authlas.dll AUTHLAS_DLL_DIRS=/path/to/openssl/bin python -m pytest tests -q

A store that raises an exception fails the call. The library never treats a store error as success.
