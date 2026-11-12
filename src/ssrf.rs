//! Guards for fetching URLs that someone else chose (client metadata documents, `jwks_uri`, `sector_identifier_uri`, logos).
//!
//! This crate does no network I/O, so it cannot stop a request by itself. What it gives you is the decision:
//! [`ssrf_check`] on the URL before you resolve it, and [`is_public_ip`] on every address the name resolves to, immediately before
//! you connect to *that* address. Checking only the name leaves a DNS rebinding gap; connecting to the name after checking the
//! address leaves the same gap. Also: do not follow redirects blindly (run the check on each hop), cap the response size, and set a
//! short timeout.
use crate::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::{Host, Url};


fn v4_public(a: Ipv4Addr) -> bool {
    let o = a.octets();
    !(a.is_unspecified() || a.is_loopback() || a.is_private() || a.is_link_local() || a.is_broadcast() || a.is_multicast() || o[0] == 0
        || (o[0] == 100 && (64..=127).contains(&o[1]))                      // 100.64.0.0/10 carrier-grade NAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)                          // 192.0.0.0/24 IETF protocol assignments
        || (o[0] == 192 && o[1] == 0 && o[2] == 2) || (o[0] == 198 && o[1] == 51 && o[2] == 100) || (o[0] == 203 && o[1] == 0 && o[2] == 113) // documentation
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))                      // 198.18.0.0/15 benchmarking
        || o[0] >= 240)                                                     // 240.0.0.0/4 reserved
}

fn v6_public(a: Ipv6Addr) -> bool {
    let s = a.segments();
    if a.is_unspecified() || a.is_loopback() || a.is_multicast() { return false; }
    if let Some(v4) = a.to_ipv4_mapped() { return v4_public(v4); }
    if s[0..6] == [0, 0, 0, 0, 0, 0] { return false; }                      // ::/96 IPv4-compatible
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {          // 64:ff9b::/96 NAT64 carries an IPv4 address
        return v4_public(Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8));
    }
    if s[0] == 0x2002 { return v4_public(Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8)); } // 6to4
    !((s[0] & 0xfe00) == 0xfc00                                             // fc00::/7 unique local
        || (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xffc0) == 0xfec0           // link-local, site-local
        || (s[0] == 0x2001 && s[1] == 0)                                    // Teredo
        || (s[0] == 0x2001 && s[1] == 0x0db8)                               // documentation
        || s[0] == 0x0100 && s[1..4] == [0, 0, 0])                          // discard prefix
}

/// True for addresses on the public internet. Call it on every address a name resolves to, immediately before connecting,
/// and connect to that address: checking the name alone leaves a DNS rebinding gap.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip { IpAddr::V4(a) => v4_public(a), IpAddr::V6(a) => v6_public(a) }
}

/// Static checks on a URL the server is about to fetch because a client named it. Returns the parsed URL.
/// Allowed: `https`, no credentials, a host that is not an internal-looking name and not a private or reserved IP literal.
/// This cannot see what a name resolves to; pair it with [`is_public_ip`] on the resolved addresses.
pub fn ssrf_check(url: &str) -> Result<Url> {
    let bad = |m: &str| Error::Malformed(format!("refusing to fetch: {m}"));
    if url.len() > 2048 || url.bytes().any(|b| b <= 0x20 || b == 0x7f) || url.contains('\\') { return Err(bad("malformed URL")); }
    let u = Url::parse(url).map_err(|_| bad("not a URL"))?;
    if u.scheme() != "https" { return Err(bad("only https")); }
    if !u.username().is_empty() || u.password().is_some() { return Err(bad("credentials in URL")); }
    match u.host() {
        None => Err(bad("no host")),
        Some(Host::Ipv4(a)) => if v4_public(a) { Ok(u) } else { Err(bad("private or reserved address")) },
        Some(Host::Ipv6(a)) => if v6_public(a) { Ok(u) } else { Err(bad("private or reserved address")) },
        Some(Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            let internal = d == "localhost" || !d.contains('.') || [".localhost", ".local", ".internal", ".localdomain", ".lan", ".home", ".corp", ".intranet"].iter().any(|s| d.ends_with(s));
            if internal { Err(bad("internal-looking host name")) } else { Ok(u) }
        }
    }
}

