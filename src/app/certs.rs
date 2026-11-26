//! TLS certificates: reading one (a small DER reader) and showing it in full on a secret's page.

use super::*;

/// What one certificate says about itself.
#[derive(Clone, Debug, Default)]
pub(super) struct CertInfo {
    /// The subject's and issuer's common names (or organisations), for short mentions.
    pub subject: String,
    pub issuer: String,
    /// The same in full: "C=US, O=Let's Encrypt, CN=YR2".
    pub subject_full: String,
    pub issuer_full: String,
    pub version: u8,
    pub serial: String,
    pub signature: String,
    pub key: String,
    pub is_ca: bool,
    /// "DNS", "IP"... and the name.
    pub alt_names: Vec<(&'static str, String)>,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
}

// ---------- reading ----------

/// One DER value: its tag, its content, and what follows it.
fn der(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let l0 = *b.get(1)? as usize;
    let (len, hdr) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let n = l0 & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    let content = b.get(hdr..end)?;
    Some((tag, content, &b[end..]))
}

/// An object identifier as "2.5.4.3".
fn oid(b: &[u8]) -> String {
    let mut parts: Vec<u64> = vec![];
    let mut v: u64 = 0;
    for x in b {
        v = (v << 7) | (x & 0x7f) as u64;
        if x & 0x80 == 0 {
            if parts.is_empty() {
                let first = (v / 40).min(2);
                parts.push(first);
                parts.push(v - first * 40);
            } else {
                parts.push(v);
            }
            v = 0;
        }
    }
    parts.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(".")
}

fn text_of(tag: u8, b: &[u8]) -> String {
    if tag == 0x1e {
        // BMPString: UTF-16, big end first.
        let u: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&u);
    }
    String::from_utf8_lossy(b).to_string()
}

/// A name's parts in order: ("CN", "example.com").
fn name_parts(name: &[u8]) -> Vec<(String, String)> {
    // Name = SEQUENCE OF SET OF SEQUENCE { OID, value }
    let mut out = vec![];
    let mut rest = name;
    while let Some((_, set, r)) = der(rest) {
        rest = r;
        let mut atvs = set;
        while let Some((_, atv, ar)) = der(atvs) {
            atvs = ar;
            let Some((0x06, id, after)) = der(atv) else { continue };
            let Some((tag, val, _)) = der(after) else { continue };
            let id = oid(id);
            let label = match id.as_str() {
                "2.5.4.3" => "CN",
                "2.5.4.5" => "serialNumber",
                "2.5.4.6" => "C",
                "2.5.4.7" => "L",
                "2.5.4.8" => "ST",
                "2.5.4.9" => "street",
                "2.5.4.10" => "O",
                "2.5.4.11" => "OU",
                "2.5.4.17" => "postalCode",
                "1.2.840.113549.1.9.1" => "emailAddress",
                "0.9.2342.19200300.100.1.25" => "DC",
                "0.9.2342.19200300.100.1.1" => "UID",
                other => other,
            };
            out.push((label.to_string(), text_of(tag, val)));
        }
    }
    out
}

fn short_name(parts: &[(String, String)]) -> String {
    let get = |k: &str| parts.iter().find(|p| p.0 == k).map(|p| p.1.clone());
    get("CN").or_else(|| get("O")).unwrap_or_default()
}

fn full_name(parts: &[(String, String)]) -> String {
    if parts.is_empty() {
        return "(empty)".into();
    }
    parts.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ")
}

fn der_time(tag: u8, t: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(t).ok()?;
    let full = match tag {
        0x17 => {
            // UTCTime YYMMDDHHMMSSZ: years 50-99 are 19xx.
            let yy: i64 = s.get(0..2)?.parse().ok()?;
            format!("{}{}", if yy >= 50 { "19" } else { "20" }, s)
        }
        0x18 => s.to_string(),
        _ => return None,
    };
    let iso = format!("{}-{}-{}T{}:{}:{}Z", full.get(0..4)?, full.get(4..6)?, full.get(6..8)?, full.get(8..10)?, full.get(10..12)?, full.get(12..14)?);
    kube::parse_time(&iso)
}

fn signature_name(id: &str) -> String {
    match id {
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        other => other,
    }
    .to_string()
}

/// A public key's kind and size: "RSA 2048 bit", "EC P-256".
fn key_name(spki: &[u8]) -> Option<String> {
    let (_, alg, rest) = der(spki)?;
    let (_, id, params) = der(alg)?;
    Some(match oid(id).as_str() {
        "1.2.840.113549.1.1.1" => {
            let (_, bits, _) = der(rest)?;
            // A bit string (first byte: unused bits) holding SEQUENCE { modulus, exponent }.
            let (_, seq, _) = der(bits.get(1..)?)?;
            let (_, modulus, _) = der(seq)?;
            let zeros = modulus.iter().take_while(|b| **b == 0).count();
            let m = &modulus[zeros..];
            let bits = m.len() * 8 - m.first().map(|b| b.leading_zeros() as usize).unwrap_or(0);
            format!("RSA {bits} bit")
        }
        "1.2.840.10045.2.1" => {
            let curve = der(params).map(|(_, c, _)| oid(c)).unwrap_or_default();
            format!("EC {}", match curve.as_str() { "1.2.840.10045.3.1.7" => "P-256", "1.3.132.0.34" => "P-384", "1.3.132.0.35" => "P-521", c => c })
        }
        "1.3.101.112" => "Ed25519".into(),
        "1.3.101.113" => "Ed448".into(),
        other => other.into(),
    })
}

fn ip_text(b: &[u8]) -> String {
    if let Ok(v4) = <[u8; 4]>::try_from(b) {
        return std::net::Ipv4Addr::from(v4).to_string();
    }
    match <[u8; 16]>::try_from(b) {
        Ok(v6) => std::net::Ipv6Addr::from(v6).to_string(),
        Err(_) => hex(b),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")
}

pub(super) fn parse_cert(der_bytes: &[u8]) -> Option<CertInfo> {
    let (_, cert, _) = der(der_bytes)?;
    let (_, tbs, _) = der(cert)?;
    let mut out = CertInfo { version: 1, ..Default::default() };
    let mut rest = tbs;
    let (tag, v, r) = der(rest)?;
    if tag == 0xa0 {
        out.version = der(v).and_then(|(_, n, _)| n.last().copied()).unwrap_or(0).saturating_add(1);
        rest = r;
    }
    let (_, serial, r) = der(rest)?;
    // A leading zero only keeps the number positive.
    out.serial = hex(if serial.len() > 1 && serial[0] == 0 { &serial[1..] } else { serial });
    let (_, sig, r) = der(r)?;
    out.signature = der(sig).map(|(_, id, _)| signature_name(&oid(id))).unwrap_or_default();
    let (_, issuer, r) = der(r)?;
    let (_, validity, r) = der(r)?;
    let (_, subject, r) = der(r)?;
    let (issuer, subject) = (name_parts(issuer), name_parts(subject));
    (out.issuer, out.issuer_full) = (short_name(&issuer), full_name(&issuer));
    (out.subject, out.subject_full) = (short_name(&subject), full_name(&subject));
    let (t1, nb, vr) = der(validity)?;
    let (t2, na, _) = der(vr)?;
    out.not_before = der_time(t1, nb);
    out.not_after = der_time(t2, na);
    let (_, spki, r) = der(r)?;
    out.key = key_name(spki).unwrap_or_default();
    // Extensions: [3] SEQUENCE OF SEQUENCE { OID, critical?, OCTET STRING }.
    let mut rest = r;
    while let Some((tag, body, r)) = der(rest) {
        rest = r;
        if tag != 0xa3 {
            continue;
        }
        let mut exts = der(body).map(|x| x.1).unwrap_or(&[]);
        while let Some((_, ext, r)) = der(exts) {
            exts = r;
            let Some((_, id, mut val)) = der(ext) else { continue };
            if let Some((0x01, _, after)) = der(val) {
                val = after;
            }
            let Some((0x04, octets, _)) = der(val) else { continue };
            match oid(id).as_str() {
                "2.5.29.17" => {
                    let mut names = der(octets).map(|x| x.1).unwrap_or(&[]);
                    while let Some((t, n, r)) = der(names) {
                        names = r;
                        let s = || String::from_utf8_lossy(n).to_string();
                        match t {
                            0x81 => out.alt_names.push(("Email", s())),
                            0x82 => out.alt_names.push(("DNS", s())),
                            0x86 => out.alt_names.push(("URI", s())),
                            0x87 => out.alt_names.push(("IP", ip_text(n))),
                            _ => {}
                        }
                    }
                }
                "2.5.29.19" => {
                    let seq = der(octets).map(|x| x.1).unwrap_or(&[]);
                    out.is_ca = matches!(der(seq), Some((0x01, [b, ..], _)) if *b != 0);
                }
                _ => {}
            }
        }
    }
    Some(out)
}

/// Every certificate in a PEM text (a chain has several).
pub(super) fn certs_from_pem(pem: &str) -> Vec<CertInfo> {
    let mut out = vec![];
    let mut rest = pem;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let body = &rest[start + 27..];
        let Some(end) = body.find("-----END CERTIFICATE-----") else { break };
        if let Some(c) = b64_decode(&body[..end].replace(['\n', '\r', ' '], "")).and_then(|d| parse_cert(&d)) {
            out.push(c);
        }
        rest = &body[end..];
    }
    out
}

/// From a secret's base64 `tls.crt` (a PEM bundle) to the first certificate's details.
pub(super) fn cert_from_secret_b64(b64: &str) -> Result<CertInfo, String> {
    let pem = b64_decode(b64.trim()).ok_or("tls.crt is not valid base64")?;
    let pem = String::from_utf8_lossy(&pem).to_string();
    let start = pem.find("-----BEGIN CERTIFICATE-----").ok_or("no certificate in tls.crt")?;
    let body = &pem[start + 27..];
    let end = body.find("-----END CERTIFICATE-----").ok_or("certificate is cut off")?;
    let der_bytes = b64_decode(&body[..end].replace(['\n', '\r', ' '], "")).ok_or("certificate is not valid base64")?;
    parse_cert(&der_bytes).ok_or_else(|| "couldn't read the certificate".to_string())
}

// ---------- showing ----------

/// "Jan 26 10:23:37 2027 UTC"
fn long_date(t: i64) -> String {
    let d = netmap::iso_date(t);
    let month: usize = d[5..7].parse().unwrap_or(1);
    let name = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][(month - 1).min(11)];
    let s = t.rem_euclid(86400);
    format!("{name} {:>2} {:02}:{:02}:{:02} {} UTC", d[8..10].parse::<u8>().unwrap_or(0), s / 3600, s / 60 % 60, s % 60, &d[..4])
}

/// "26d ago", "in 64d"
fn from_now(t: i64, now: i64) -> String {
    let d = (t - now).abs();
    let span = if d >= 2 * 86400 { format!("{}d", d / 86400) } else { kube::human_duration(d) };
    if t > now { format!("in {span}") } else { format!("{span} ago") }
}

/// Whether a certificate is good now, in a word and a colour.
pub(super) fn verdict(c: &CertInfo, now: i64) -> (&'static str, Tone) {
    match (c.not_before, c.not_after) {
        (_, Some(na)) if na < now => ("Expired", Tone::Danger),
        (Some(nb), _) if nb > now => ("Not valid yet", Tone::Warning),
        (_, Some(na)) if na - now < 14 * 86400 => ("Valid, expires soon", Tone::Warning),
        (_, Some(_)) => ("Valid", Tone::Success),
        _ => ("Unknown", Tone::Muted),
    }
}

/// One certificate's fields, one per line.
fn cert_lines(ui: &mut Ui, c: &CertInfo) {
    let mono = |t: &str, col: Color32| RichText::new(t).monospace().size(z(12.5)).color(col);
    let field = |ui: &mut Ui, indent: f32, label: &str, value: &str, note: &str| {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = z(7.0);
            ui.add_space(indent);
            ui.label(mono(label, TEXT_SUBTLE()));
            ui.label(mono(value, TEXT_DEFAULT()));
            if !note.is_empty() {
                ui.label(mono(note, TEXT_SUBTLE()));
            }
        });
    };
    let now = kube::now_secs();
    let step = z(26.0);
    ui.spacing_mut().item_spacing.y = 3.0;
    field(ui, 0.0, "Version:", &format!("V{}", c.version), "");
    field(ui, 0.0, "Serial Number:", &c.serial, "");
    field(ui, 0.0, "Signature Algorithm:", &c.signature, "");
    if !c.key.is_empty() {
        field(ui, 0.0, "Public Key:", &c.key, "");
    }
    field(ui, 0.0, "Issuer:", &c.issuer_full, "");
    field(ui, 0.0, "Subject:", &c.subject_full, if c.is_ca { "(a certificate authority)" } else { "" });
    let (word, tone) = verdict(c, now);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = z(7.0);
        ui.label(mono("Validity:", TEXT_SUBTLE()));
        ui.label(mono(word, tone_color(tone)).strong());
    });
    for (label, t) in [("Not Before:", c.not_before), ("Not After:", c.not_after)] {
        if let Some(t) = t {
            field(ui, step, label, &long_date(t), &from_now(t, now));
        }
    }
    if !c.alt_names.is_empty() {
        ui.label(mono("Subject Alternative Names:", TEXT_SUBTLE()));
        for (kind, name) in &c.alt_names {
            field(ui, step, &format!("{kind}:"), name, "");
        }
    }
}

/// Every certificate in a text, with a line between them.
pub(super) fn cert_panel(ui: &mut Ui, pem: &str) {
    let certs = certs_from_pem(pem);
    if certs.is_empty() {
        ui.label(RichText::new("This certificate couldn't be read; its PEM text is behind the page icon.").size(z(12.5)).color(WARNING()));
    }
    let n = certs.len();
    for (i, c) in certs.iter().enumerate() {
        ui.scope(|ui| cert_lines(ui, c));
        if i + 1 < n {
            ui.add_space(8.0);
            let y = ui.cursor().top();
            let x = ui.max_rect().left();
            ui.painter().hline(x..=(x + z(460.0)).min(ui.max_rect().right()), y, Stroke::new(1.0, BORDER_DEFAULT()));
            ui.add_space(10.0);
        }
    }
}

/// A key's panel: a title bar with the key's name and buttons, the content below.
pub(super) fn key_panel(ui: &mut Ui, title: &str, buttons: impl FnOnce(&mut Ui), content: impl FnOnce(&mut Ui)) {
    Frame::new().fill(BG_CARD()).stroke(Stroke::new(1.0, BORDER_SUBTLE())).corner_radius(CornerRadius::same(8)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        Frame::new().fill(BG_MUTED()).corner_radius(CornerRadius { nw: 8, ne: 8, sw: 0, se: 0 }).inner_margin(Margin::symmetric(12, 4)).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.set_width(ui.available_width());
                ui.set_min_height(u(26.0));
                ui.label(RichText::new(title).monospace().size(z(12.5)).color(PRIMARY_TEXT()));
                buttons(ui);
            });
        });
        Frame::new().inner_margin(Margin::symmetric(12, 10)).show(ui, |ui| {
            ui.vertical(|ui| {
                ui.set_width(ui.available_width());
                content(ui);
            });
        });
    });
    ui.add_space(10.0);
}

/// A copy icon: two sheets.
pub(super) fn draw_copy(p: &egui::Painter, r: egui::Rect, col: Color32) {
    let s = Stroke::new(1.3, col);
    let c = r.center();
    p.rect_stroke(egui::Rect::from_min_size(c + egui::vec2(-2.0, -2.0), egui::vec2(8.0, 8.5)), CornerRadius::same(2), s, egui::StrokeKind::Inside);
    let (l, t) = (c.x - 5.5, c.y - 6.0);
    p.add(egui::Shape::line(vec![egui::pos2(l + 1.8, t + 8.2), egui::pos2(l, t + 8.2), egui::pos2(l, t), egui::pos2(l + 7.6, t), egui::pos2(l + 7.6, t + 2.0)], s));
}

/// A blurred block standing in for a long secret. Always the same, so it gives nothing away.
pub(super) fn blurred_block(ui: &mut Ui) -> egui::Response {
    let (rows, line) = (7usize, z(17.0));
    let (r, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width().min(z(560.0)), rows as f32 * line + 8.0), Sense::click());
    let p = ui.painter().with_clip_rect(ui.clip_rect().intersect(r));
    let mut seed = 12345u32;
    for i in 0..rows {
        let w = if i == 0 || i + 1 == rows { r.width() * 0.42 } else { r.width() * 0.96 };
        let x0 = if i == 0 || i + 1 == rows { r.left() + r.width() * 0.08 } else { r.left() + 6.0 };
        let y = r.top() + 4.0 + line * (i as f32 + 0.5);
        let mut x = x0;
        while x < x0 + w {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            let len = 14.0 + ((seed >> 16) % 46) as f32;
            for grow in [15.0f32, 11.0, 8.0, 5.0] {
                let b = egui::Rect::from_center_size(egui::pos2(x + len / 2.0, y), egui::vec2(len + grow, 3.0 + grow));
                p.rect_filled(b, CornerRadius::same(6), TEXT_MUTED().gamma_multiply(if resp.hovered() { 0.10 } else { 0.065 }));
            }
            x += len * 0.9;
        }
    }
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    // Made with openssl for this test; no private keys are kept.
    const PEM: &str = include_str!("test-certs.pem");

    #[test]
    fn reads_everything() {
        let c = certs_from_pem(PEM);
        assert_eq!(c.len(), 2);
        let a = &c[0];
        assert_eq!((a.version, a.serial.as_str(), a.signature.as_str(), a.key.as_str()), (3, "06:8a:c7:e7:6c:04", "sha256WithRSAEncryption", "RSA 2048 bit"));
        assert_eq!((a.subject.as_str(), a.issuer.as_str()), ("shop.example.com", "shop.example.com"));
        assert_eq!(a.subject_full, "C=NL, O=Example, Inc, OU=Test, CN=shop.example.com");
        let names: Vec<String> = a.alt_names.iter().map(|(k, n)| format!("{k}:{n}")).collect();
        assert_eq!(names, ["DNS:shop.example.com", "DNS:*.shop.example.com", "IP:10.1.2.3", "Email:a@example.com"]);
        let (nb, na) = (a.not_before.unwrap(), a.not_after.unwrap());
        assert_eq!(na - nb, 3650 * 86400);
        assert_eq!((c[1].key.as_str(), c[1].signature.as_str(), c[1].subject_full.as_str()), ("EC P-256", "ecdsa-with-SHA256", "CN=ec.example.com"));
        assert_eq!(verdict(a, nb + 10).0, "Valid");
        assert_eq!(verdict(a, nb - 10).0, "Not valid yet");
        assert_eq!(verdict(a, na - 86400).0, "Valid, expires soon");
        assert_eq!(verdict(a, na + 1), ("Expired", Tone::Danger));
    }

    #[test]
    fn broken_input_is_refused() {
        // Every cut-off length, and noise, without panicking.
        let body: String = PEM.lines().skip(1).take_while(|l| !l.starts_with("---")).collect();
        let d = b64_decode(&body).unwrap();
        for n in 0..d.len() {
            let _ = parse_cert(&d[..n]);
        }
        for i in 0..d.len() {
            let mut x = d.clone();
            x[i] = x[i].wrapping_add(0x55);
            let _ = parse_cert(&x);
        }
        assert!(certs_from_pem("-----BEGIN CERTIFICATE-----\nnope").is_empty());
    }

    #[test]
    fn dates() {
        let t = kube::parse_time("2027-01-26T10:23:37Z").unwrap();
        assert_eq!(long_date(t), "Jan 26 10:23:37 2027 UTC");
        assert_eq!(from_now(t, t - 64 * 86400 - 5), "in 64d");
        assert_eq!(from_now(t, t + 26 * 86400), "26d ago");
    }
}
