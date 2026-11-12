#!/usr/bin/env python3
"""Turns a `crypto_backends=` line into Cargo flags, for build systems that are not Cargo.

Where the line lives (first match wins):
  1. --backends awslc,qscrypt                     (command line)
  2. environment variable AUTHLAS_CRYPTO_BACKENDS
  3. authlas.conf             crypto_backends=awslc,qscrypt
  4. pyproject.toml           [tool.authlas]  crypto_backends = ["awslc", "qscrypt"]
  5. package.json             {"authlas": {"crypto_backends": ["awslc", "qscrypt"]}}
  6. CMakeLists.txt           set(AUTHLAS_CRYPTO_BACKENDS "awslc;qscrypt")

Search starts in --dir (default: current directory) and walks up. Output modes:
  --print features   backend-awslc,backend-qscrypt            (for `cargo --features`)
  --print env        AUTHLAS_CRYPTO_BACKENDS=awslc,qscrypt    (what build.rs reads)
  --print cargo      --no-default-features --features ...     (whole flag string)
  --print cmake      -DAUTHLAS_CARGO_FLAGS=...                (for CMake add_custom_command)
"""
import argparse, json, os, re, sys
KNOWN = ["awslc", "openssl", "rustcrypto", "qscrypt", "hardened"]

def from_conf(path):
    for line in open(path, encoding="utf8"):
        m = re.match(r"\s*crypto_backends\s*=\s*(.*?)\s*(#.*)?$", line)
        if m: return m.group(1)
def from_pyproject(path):
    txt = open(path, encoding="utf8").read()
    sec = re.search(r"^\[tool\.authlas\]\s*$(.*?)(?=^\[|\Z)", txt, re.M | re.S)
    if sec:
        m = re.search(r"crypto_backends\s*=\s*(\[.*?\]|\".*?\")", sec.group(1), re.S)
        if m: return m.group(1)
def from_package_json(path):
    v = json.load(open(path, encoding="utf8")).get("authlas", {}).get("crypto_backends")
    if v is not None: return v if isinstance(v, str) else ",".join(v)
def from_cmake(path):
    m = re.search(r"set\s*\(\s*AUTHLAS_CRYPTO_BACKENDS\s+\"?([^\")]*)\"?\s*\)", open(path, encoding="utf8").read(), re.I)
    if m: return m.group(1).replace(";", ",")

SOURCES = [("authlas.conf", from_conf), ("pyproject.toml", from_pyproject), ("package.json", from_package_json), ("CMakeLists.txt", from_cmake)]

def find(start):
    d = os.path.abspath(start)
    while True:
        for name, fn in SOURCES:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                try: v = fn(p)
                except Exception as e: sys.exit(f"error: cannot read {p}: {e}")
                if v: return v, p
        parent = os.path.dirname(d)
        if parent == d: return None, None
        d = parent

def normalise(raw):
    raw = re.sub(r"[\[\]\"']", "", raw)
    items = [x.strip().lower() for x in re.split(r"[,;\s]+", raw) if x.strip()]
    for i in items:
        if i not in KNOWN: sys.exit(f"error: unknown backend {i!r}; known: {', '.join(KNOWN)}")
    if not items: sys.exit("error: crypto_backends is empty")
    if len(set(items)) != len(items): sys.exit("error: duplicate backend in crypto_backends")
    if "hardened" in items and len([i for i in items if i != "hardened"]) < 2:
        sys.exit("error: 'hardened' needs at least two other backends listed")
    return items

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backends"); ap.add_argument("--dir", default=".")
    ap.add_argument("--print", dest="mode", default="cargo", choices=["features", "env", "cargo", "cmake"])
    a = ap.parse_args()
    src = "--backends"
    raw = a.backends
    if raw is None and os.environ.get("AUTHLAS_CRYPTO_BACKENDS"): raw, src = os.environ["AUTHLAS_CRYPTO_BACKENDS"], "environment"
    if raw is None: raw, src = find(a.dir)
    if raw is None:
        sys.exit("error: no crypto_backends found (see --help). Nothing is assumed; refusing to guess.")
    items = normalise(raw)
    feats = ",".join("backend-" + i for i in items)
    flags = f"--no-default-features --features {feats}"
    sys.stderr.write(f"authlas: crypto_backends={','.join(items)} (from {src}); active={items[0]}\n")
    print({"features": feats, "env": "AUTHLAS_CRYPTO_BACKENDS=" + ",".join(items), "cargo": flags, "cmake": f"-DAUTHLAS_CARGO_FLAGS={flags}"}[a.mode])
if __name__ == "__main__": main()
