//! Minimal strict X.509 reader for mutual-TLS client authentication (RFC 8705).
//!
//! This is not a validator. The TLS stack validates the chain and proves possession of the private key. This module only reads
//! the fields OAuth needs from the certificate the TLS stack accepted: subject, subject alternative names, validity, the
//! public key (as a JWK) and the SHA-256 thumbprint.
//!
//! RFC 8705 7.5 warns that certificate parsing is a source of bugs. The reader therefore accepts canonical DER only:
//! definite lengths, minimal length encoding, no trailing bytes, bounded size.
use crate::{b64, crypto, error::{Error, Result}, jwa::Hash, jwk::Jwk};

pub const MAX_CERT_LEN: usize = 16 * 1024;

fn bad(m: &str) -> Error { Error::Malformed(format!("x509: {m}")) }

struct Der<'a> { b: &'a [u8] }

impl<'a> Der<'a> {
    fn new(b: &'a [u8]) -> Self { Der { b } }
    fn is_empty(&self) -> bool { self.b.is_empty() }
    fn peek_tag(&self) -> Option<u8> { self.b.first().copied() }
    /// Reads one TLV and returns (tag, contents).
    fn next(&mut self) -> Result<(u8, &'a [u8])> {
        let b = self.b;
        if b.len() < 2 { return Err(bad("truncated")); }
        let tag = b[0];
        if tag & 0x1f == 0x1f { return Err(bad("multi-byte tags are not used here")); }
        let (len, hdr) = match b[1] {
            l if l < 0x80 => (l as usize, 2),
            0x80 => return Err(bad("indefinite length")),
            n @ 0x81..=0x84 => {
                let n = (n & 0x7f) as usize;
                if b.len() < 2 + n { return Err(bad("truncated length")); }
                let mut l = 0usize;
                for &x in &b[2..2 + n] { l = (l << 8) | x as usize; }
                // Minimal encoding: no leading zero, and long form only when the value does not fit the short form.
                if b[2] == 0 || l < 0x80 { return Err(bad("length is not minimally encoded")); }
                (l, 2 + n)
            }
            _ => return Err(bad("length too large")),
        };
        if b.len() < hdr + len { return Err(bad("truncated value")); }
        let v = &b[hdr..hdr + len];
        self.b = &b[hdr + len..];
        Ok((tag, v))
    }
    fn expect(&mut self, tag: u8) -> Result<&'a [u8]> {
        let (t, v) = self.next()?;
        if t != tag { return Err(bad("unexpected element")); }
        Ok(v)
    }
}

const SEQ: u8 = 0x30;
const SET: u8 = 0x31;
const OID: u8 = 0x06;
const INT: u8 = 0x02;
const BITS: u8 = 0x03;

fn oid_to_string(v: &[u8]) -> Result<String> {
    if v.is_empty() { return Err(bad("empty OID")); }
    let mut parts: Vec<u64> = vec![];
    let mut acc: u64 = 0;
    let mut first = true;
    for (i, &x) in v.iter().enumerate() {
        if acc == 0 && x == 0x80 { return Err(bad("OID arc not minimal")); }
        acc = acc.checked_mul(128).ok_or_else(|| bad("OID arc too large"))? | (x & 0x7f) as u64;
        if x & 0x80 == 0 {
            if first { let (a, b) = if acc < 40 { (0, acc) } else if acc < 80 { (1, acc - 40) } else { (2, acc - 80) }; parts.push(a); parts.push(b); first = false; }
            else { parts.push(acc); }
            acc = 0;
        } else if i == v.len() - 1 { return Err(bad("OID truncated")); }
    }
    Ok(parts.iter().map(u64::to_string).collect::<Vec<_>>().join("."))
}

fn short_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN", "2.5.4.7" => "L", "2.5.4.8" => "ST", "2.5.4.10" => "O", "2.5.4.11" => "OU", "2.5.4.6" => "C",
        "2.5.4.9" => "STREET", "0.9.2342.19200300.100.1.25" => "DC", "0.9.2342.19200300.100.1.1" => "UID",
        _ => return None,
    })
}

fn decode_string(tag: u8, v: &[u8]) -> Result<String> {
    match tag {
        0x0c | 0x13 | 0x16 | 0x12 => String::from_utf8(v.to_vec()).map_err(|_| bad("invalid string")),
        0x14 => Ok(v.iter().map(|&b| b as char).collect()), // TeletexString as Latin-1
        0x1e => { // BMPString
            if v.len() % 2 != 0 { return Err(bad("invalid BMPString")); }
            let u: Vec<u16> = v.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            String::from_utf16(&u).map_err(|_| bad("invalid BMPString"))
        }
        0x1c => { // UniversalString
            if v.len() % 4 != 0 { return Err(bad("invalid UniversalString")); }
            v.chunks(4).map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])).ok_or_else(|| bad("invalid UniversalString"))).collect()
        }
        _ => Err(bad("unsupported string type in a name")),
    }
}

/// RFC 4514 section 2.4 escaping.
fn escape(v: &str) -> String {
    let mut o = String::with_capacity(v.len());
    let n = v.chars().count();
    for (i, c) in v.chars().enumerate() {
        match c {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' => { o.push('\\'); o.push(c); }
            '\0' => o.push_str("\\00"),
            ' ' if i == 0 || i == n - 1 => o.push_str("\\ "),
            '#' if i == 0 => o.push_str("\\#"),
            c => o.push(c),
        }
    }
    o
}

/// One subject alternative name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum San { Dns(String), Uri(String), Ip(std::net::IpAddr), Email(String) }

#[derive(Debug, Clone)]
pub struct Certificate {
    der: Vec<u8>,
    pub subject_rfc4514: String,
    pub sans: Vec<San>,
    pub not_before: u64,
    pub not_after: u64,
    spki_alg: String,
    spki_params: Option<String>,
    spki_key: Vec<u8>,
}

fn parse_name(v: &[u8]) -> Result<String> {
    let mut rdns: Vec<String> = vec![];
    let mut seq = Der::new(v);
    while !seq.is_empty() {
        let set = seq.expect(SET)?;
        let mut items = Der::new(set);
        let mut parts = vec![];
        while !items.is_empty() {
            let atv = items.expect(SEQ)?;
            let mut a = Der::new(atv);
            let oid = oid_to_string(a.expect(OID)?)?;
            let (tag, val) = a.next()?;
            if !a.is_empty() { return Err(bad("trailing data in an attribute")); }
            let rendered = match short_name(&oid) {
                Some(n) => format!("{n}={}", escape(&decode_string(tag, val)?)),
                None => { // RFC 4514 2.4: unknown types are dotted OID = # + hex of the BER value
                    let mut ber = vec![tag];
                    if val.len() < 0x80 { ber.push(val.len() as u8); } else { let l = val.len().to_be_bytes(); let l: Vec<u8> = l.iter().copied().skip_while(|&x| x == 0).collect(); ber.push(0x80 | l.len() as u8); ber.extend(l); }
                    ber.extend_from_slice(val);
                    format!("{oid}=#{}", ber.iter().map(|b| format!("{b:02x}")).collect::<String>())
                }
            };
            parts.push(rendered);
        }
        if parts.is_empty() { return Err(bad("empty RDN")); }
        rdns.push(parts.join("+"));
    }
    rdns.reverse(); // RFC 4514 2.1: most specific RDN first
    Ok(rdns.join(","))
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn parse_time(tag: u8, v: &[u8]) -> Result<u64> {
    let s = std::str::from_utf8(v).map_err(|_| bad("time"))?;
    let (digits, year_len) = match tag { 0x17 => (12, 2), 0x18 => (14, 4), _ => return Err(bad("time type")) };
    if s.len() != digits + 1 || !s.ends_with('Z') || !s[..digits].bytes().all(|b| b.is_ascii_digit()) { return Err(bad("time format")); }
    let n = |a: usize, l: usize| s[a..a + l].parse::<i64>().unwrap();
    let mut y = n(0, year_len);
    if year_len == 2 { y += if y >= 50 { 1900 } else { 2000 }; }
    let o = year_len;
    let (mo, d, h, mi, se) = (n(o, 2), n(o + 2, 2), n(o + 4, 2), n(o + 6, 2), n(o + 8, 2));
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 { return Err(bad("time value")); }
    let t = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se;
    u64::try_from(t).map_err(|_| bad("time before 1970"))
}

impl Certificate {
    pub fn from_der(der: &[u8]) -> Result<Certificate> {
        if der.is_empty() || der.len() > MAX_CERT_LEN { return Err(bad("size")); }
        let mut top = Der::new(der);
        let cert = top.expect(SEQ)?;
        if !top.is_empty() { return Err(bad("trailing bytes after the certificate")); }
        let mut c = Der::new(cert);
        let tbs = c.expect(SEQ)?;
        let _alg = c.expect(SEQ)?;
        let _sig = c.expect(BITS)?;
        if !c.is_empty() { return Err(bad("trailing data in the certificate")); }
        let mut t = Der::new(tbs);
        if t.peek_tag() == Some(0xa0) { t.next()?; } // version
        t.expect(INT)?; // serial
        t.expect(SEQ)?; // signature algorithm
        t.expect(SEQ)?; // issuer
        let validity = t.expect(SEQ)?;
        let mut v = Der::new(validity);
        let (t1, b1) = v.next()?;
        let (t2, b2) = v.next()?;
        if !v.is_empty() { return Err(bad("validity")); }
        let (not_before, not_after) = (parse_time(t1, b1)?, parse_time(t2, b2)?);
        if not_after < not_before { return Err(bad("validity ends before it starts")); }
        let subject = parse_name(t.expect(SEQ)?)?;
        let spki = t.expect(SEQ)?;
        let mut s = Der::new(spki);
        let alg = s.expect(SEQ)?;
        let mut a = Der::new(alg);
        let spki_alg = oid_to_string(a.expect(OID)?)?;
        let spki_params = if a.is_empty() { None } else {
            let (tag, v) = a.next()?;
            if tag == OID { Some(oid_to_string(v)?) } else if tag == 0x05 && v.is_empty() { None } else { return Err(bad("unsupported key parameters")); }
        };
        let bits = s.expect(BITS)?;
        if bits.first() != Some(&0) { return Err(bad("key bit string has unused bits")); }
        let spki_key = bits[1..].to_vec();
        // Extensions: [3] EXPLICIT SEQUENCE OF Extension. Optional fields [1] and [2] come first.
        let mut sans = vec![];
        let mut seen_san = false;
        while !t.is_empty() {
            let (tag, body) = t.next()?;
            if tag != 0xa3 { continue; }
            let mut e = Der::new(body);
            let list = e.expect(SEQ)?;
            let mut l = Der::new(list);
            while !l.is_empty() {
                let ext = l.expect(SEQ)?;
                let mut x = Der::new(ext);
                let oid = oid_to_string(x.expect(OID)?)?;
                if x.peek_tag() == Some(0x01) { x.next()?; } // critical
                let value = x.expect(0x04)?;
                if oid == "2.5.29.17" {
                    if seen_san { return Err(bad("duplicate subjectAltName extension")); }
                    seen_san = true;
                    sans = parse_sans(value)?;
                }
            }
        }
        Ok(Certificate { der: der.to_vec(), subject_rfc4514: subject, sans, not_before, not_after, spki_alg, spki_params, spki_key })
    }

    pub fn der(&self) -> &[u8] { &self.der }

    /// RFC 8705 3.1: base64url of the SHA-256 of the DER certificate, for `cnf["x5t#S256"]`.
    pub fn x5t_s256(&self) -> Result<String> { Ok(b64::encode(crypto::digest(Hash::Sha256, &self.der)?)) }

    pub fn valid_at(&self, now: u64) -> bool { self.not_before <= now && now <= self.not_after }

    /// The certificate's public key as a JWK (RSA, EC P-256/384/521, Ed25519).
    pub fn public_jwk(&self) -> Result<Jwk> {
        let j = match (self.spki_alg.as_str(), self.spki_params.as_deref()) {
            ("1.2.840.113549.1.1.1", _) => {
                let mut o = Der::new(&self.spki_key);
                let seq = o.expect(SEQ)?;
                if !o.is_empty() { return Err(bad("trailing data in RSA key")); }
                let mut s = Der::new(seq);
                let strip = |v: &[u8]| -> Vec<u8> { let mut v = v; while v.len() > 1 && v[0] == 0 { v = &v[1..]; } v.to_vec() };
                let n = strip(s.expect(INT)?);
                let e = strip(s.expect(INT)?);
                serde_json::json!({"kty": "RSA", "n": b64::encode(n), "e": b64::encode(e)})
            }
            ("1.2.840.10045.2.1", Some(curve)) => {
                let (crv, len) = match curve { "1.2.840.10045.3.1.7" => ("P-256", 32), "1.3.132.0.34" => ("P-384", 48), "1.3.132.0.35" => ("P-521", 66), _ => return Err(Error::Key("unsupported curve".into())) };
                let k = &self.spki_key;
                if k.len() != 1 + 2 * len || k[0] != 4 { return Err(Error::Key("EC point must be uncompressed".into())); }
                serde_json::json!({"kty": "EC", "crv": crv, "x": b64::encode(&k[1..1 + len]), "y": b64::encode(&k[1 + len..])})
            }
            ("1.3.101.112", _) => {
                if self.spki_key.len() != 32 { return Err(Error::Key("Ed25519 key must be 32 bytes".into())); }
                serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": b64::encode(&self.spki_key)})
            }
            _ => return Err(Error::Key("unsupported public key type".into())),
        };
        Jwk::parse(&j.to_string())
    }
}

fn parse_sans(ext_value: &[u8]) -> Result<Vec<San>> {
    let mut d = Der::new(ext_value);
    let seq = d.expect(SEQ)?;
    if !d.is_empty() { return Err(bad("trailing data in SAN")); }
    let mut g = Der::new(seq);
    let mut out = vec![];
    while !g.is_empty() {
        let (tag, v) = g.next()?;
        match tag {
            0x81 => out.push(San::Email(ia5(v)?)),
            0x82 => out.push(San::Dns(ia5(v)?)),
            0x86 => out.push(San::Uri(ia5(v)?)),
            0x87 => match v.len() {
                4 => out.push(San::Ip(std::net::IpAddr::from(<[u8; 4]>::try_from(v).unwrap()))),
                16 => out.push(San::Ip(std::net::IpAddr::from(<[u8; 16]>::try_from(v).unwrap()))),
                _ => return Err(bad("IP address SAN has the wrong length")),
            },
            _ => {} // otherName, directoryName, ...: not used by RFC 8705
        }
    }
    Ok(out)
}

fn ia5(v: &[u8]) -> Result<String> {
    if !v.is_ascii() { return Err(bad("SAN is not IA5String")); }
    Ok(String::from_utf8(v.to_vec()).unwrap())
}

/// Reads a certificate that a TLS-terminating proxy forwarded in a header (RFC 8705 6.5).
/// Accepts base64 DER, PEM, and URL-encoded PEM (the nginx `$ssl_client_escaped_cert` form).
///
/// Only call this for a header your own proxy sets, after it has removed any copy sent by the client.
pub fn from_forwarded_header(value: &str) -> Result<Certificate> {
    if value.len() > 4 * MAX_CERT_LEN { return Err(bad("header too large")); }
    let mut s: String = if value.contains('%') {
        url::form_urlencoded::parse(format!("x={}", value.replace('+', "%2B")).as_bytes()).next().map(|(_, v)| v.into_owned()).unwrap_or_default()
    } else { value.to_string() };
    if s.contains("-----BEGIN CERTIFICATE-----") {
        let begin = s.find("-----BEGIN CERTIFICATE-----").unwrap() + "-----BEGIN CERTIFICATE-----".len();
        let end = s.find("-----END CERTIFICATE-----").ok_or_else(|| bad("PEM has no end marker"))?;
        if end < begin { return Err(bad("PEM markers out of order")); }
        if s[end + "-----END CERTIFICATE-----".len()..].contains("-----BEGIN") { return Err(bad("more than one certificate")); }
        s = s[begin..end].to_string();
    }
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    use base64::{engine::general_purpose::STANDARD, Engine};
    let der = STANDARD.decode(compact).map_err(|_| bad("certificate is not base64"))?;
    Certificate::from_der(&der)
}
