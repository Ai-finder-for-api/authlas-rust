//! Build-time crypto backend selection.
//!
//! The developer using the library chooses backends with a `crypto_backends=` line:
//!
//!   * environment variable `AUTHLAS_CRYPTO_BACKENDS=awslc,qscrypt`, or
//!   * a file `authlas.conf` containing `crypto_backends=awslc,qscrypt`, found by walking up
//!     from the build output directory (so it can sit next to the consumer's Cargo.toml,
//!     CMakeLists.txt, pyproject.toml or package.json).
//!
//! Cargo features decide what is *compiled*. This script decides which compiled backend is the
//! *active* one and refuses to build if the request cannot be met, so a typo never silently
//! falls back to something weaker. With no request, the default is aws-lc-rs, then OpenSSL,
//! then whichever other backend is compiled in. `tools/backends.py` turns the same
//! `crypto_backends=` line into the Cargo feature flags for CMake, maturin and npm builds.
use std::{env, fs, path::{Path, PathBuf}};

const ALL: &[(&str, &str)] = &[
    ("awslc", "BACKEND_AWSLC"),
    ("openssl", "BACKEND_OPENSSL"),
    ("rustcrypto", "BACKEND_RUSTCRYPTO"),
    ("qscrypt", "BACKEND_QSCRYPT"),
    ("hardened", "BACKEND_HARDENED"),
];
const DEFAULT_ORDER: &[&str] = &["awslc", "openssl", "rustcrypto", "qscrypt"];

fn enabled(name: &str) -> bool {
    let var = ALL.iter().find(|(n, _)| *n == name).map(|(_, v)| format!("CARGO_FEATURE_{v}")).unwrap();
    env::var_os(var).is_some()
}

fn parse_conf(text: &str) -> Option<Vec<String>> {
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some(rest) = line.strip_prefix("crypto_backends") {
            let rest = rest.trim_start().strip_prefix('=')?;
            let v: Vec<String> = rest.split(',').map(|s| s.trim().trim_matches('"').to_ascii_lowercase())
                .filter(|s| !s.is_empty()).collect();
            return Some(v);
        }
    }
    None
}

fn find_conf(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let c = d.join("authlas.conf");
        if c.is_file() { return Some(c); }
        dir = d.parent();
    }
    None
}

fn fail(msg: &str) -> ! {
    println!("cargo:warning=authlas: {msg}");
    eprintln!("error: authlas: {msg}");
    std::process::exit(1);
}

fn main() {
    build_net();
    println!("cargo:rerun-if-env-changed=AUTHLAS_CRYPTO_BACKENDS");
    println!("cargo:rerun-if-env-changed=AUTHLAS_CONFIG");
    println!("cargo:rerun-if-changed=build.rs");
    for (n, _) in ALL { println!("cargo::rustc-check-cfg=cfg(authlas_active, values(\"{n}\"))"); }

    let mut requested: Option<(Vec<String>, String)> = None;
    if let Ok(v) = env::var("AUTHLAS_CRYPTO_BACKENDS") {
        requested = Some((v.split(',').map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect(), "AUTHLAS_CRYPTO_BACKENDS".into()));
    } else {
        let explicit = env::var_os("AUTHLAS_CONFIG").map(PathBuf::from);
        let out = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_default());
        let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
        let found = explicit.filter(|p| p.is_file()).or_else(|| find_conf(&out)).or_else(|| find_conf(&manifest));
        if let Some(path) = found {
            println!("cargo:rerun-if-changed={}", path.display());
            if let Ok(text) = fs::read_to_string(&path) {
                if let Some(v) = parse_conf(&text) { requested = Some((v, path.display().to_string())); }
            }
        }
    }

    let compiled: Vec<&str> = ALL.iter().map(|(n, _)| *n).filter(|n| enabled(n)).collect();
    if compiled.is_empty() { fail("no crypto backend feature is enabled (backend-awslc, backend-openssl, backend-rustcrypto, backend-qscrypt, backend-hardened)"); }

    let active: String = match requested {
        Some((list, src)) => {
            if list.is_empty() { fail(&format!("crypto_backends in {src} is empty")); }
            for r in &list {
                if !ALL.iter().any(|(n, _)| n == r) { fail(&format!("crypto_backends in {src}: unknown backend {r:?}")); }
                if !enabled(r) { fail(&format!("crypto_backends in {src} asks for {r:?}, but it was not compiled in. Pass --features backend-{r} (tools/backends.py prints the flags)")); }
            }
            // The first entry is the active backend; the others stay available to `hardened`.
            list[0].clone()
        }
        None => DEFAULT_ORDER.iter().find(|n| enabled(n)).map(|s| s.to_string())
            .unwrap_or_else(|| "hardened".into()),
    };
    if active == "hardened" && compiled.iter().filter(|n| **n != "hardened").count() < 2 {
        fail("the hardened backend cross-checks several implementations; compile at least two others besides it");
    }
    println!("cargo:rustc-cfg=authlas_active=\"{active}\"");
    println!("cargo:rustc-env=AUTHLAS_ACTIVE_BACKEND={active}");
    println!("cargo:rustc-env=AUTHLAS_COMPILED_BACKENDS={}", compiled.join(","));
}

/// C++ HTTPS transport (native/). Built only with the `net` feature. The sources are compiled into this crate,
/// so the published crate is self-contained. OpenSSL 3 is found through openssl-sys (OPENSSL_DIR, pkg-config or vcpkg).
fn build_net() {
    if env::var_os("CARGO_FEATURE_NET").is_none() { return; }
    println!("cargo:rerun-if-changed=native");
    let mut b = cc::Build::new();
    b.cpp(true).std("c++17")
        .include("native/include").include("native/src")
        .define("AUTHLAS_NET_BUILD", None)
        .file("native/src/capi.cpp")
        .file("native/src/net/addr.cpp")
        .file("native/src/net/http_parse.cpp")
        .file("native/src/net/transport.cpp");
    // openssl-sys exports the include and library locations it resolved; fall back to OPENSSL_DIR (vcpkg, Homebrew, Linux prefix).
    if let Some(inc) = env::var_os("DEP_OPENSSL_INCLUDE") {
        b.include(inc);
    } else if let Some(dir) = env::var_os("OPENSSL_DIR") {
        b.include(PathBuf::from(dir).join("include"));
    }
    b.compile("authlas_net");
    // Library folder: OPENSSL_DIR/lib (vcpkg, Homebrew, Linux prefix) when openssl-sys did not export one.
    if let Some(dir) = env::var_os("OPENSSL_DIR") {
        println!("cargo:rustc-link-search=native={}", PathBuf::from(dir).join("lib").display());
    }
    println!("cargo:rustc-link-lib=static=authlas_net");
    // vcpkg's Windows OpenSSL ships libssl.lib / libcrypto.lib; other platforms use ssl / crypto.
    let windows = env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let (ssl, crypto) = if windows { ("libssl", "libcrypto") } else { ("ssl", "crypto") };
    println!("cargo:rustc-link-lib={ssl}");
    println!("cargo:rustc-link-lib={crypto}");
    if windows {
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=crypt32");
    }
}
