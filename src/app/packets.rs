//! Network Lab: packets. Reads capture files (pcap and pcapng), decodes headers only, and says what went
//! wrong: names that aren't found, refused and unanswered connections, resets, packets sent again, TLS
//! alerts, packets that are too big. Contents aren't kept: each packet is decoded and its bytes dropped.
//!
//! The decoder began as a rewrite of parts of PathViz by Ivan Velichko (MIT licence, see THIRD-PARTY.md).

use super::dash::line;
use super::face::{many, Face, Fact, Side};
use super::incident::chip_button;
use super::nethelp::{self, Make};
use super::ops::{ns_of, table, text, Item};
use super::pg::{label_at, panel};
use super::podxray::Go;
use super::work::{name_of, said};
use super::*;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// What's read at most.
const MOST_BYTES: u64 = 256 * 1024 * 1024;
const MOST_PACKETS: usize = 400_000;

// ---------- decoding ----------

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Info {
    None,
    /// (id, name, kind, is it an answer, code, addresses)
    Dns { id: u16, name: String, kind: String, answer: bool, code: u8, addrs: Vec<String> },
    /// A request or the answer's first line, without what follows ? in it.
    Http(String),
    /// A hello of a client, with the name it asks for.
    Hello(String),
    /// (is it fatal, what)
    Alert(bool, String),
}

/// A packet, as far as its headers go.
#[derive(Clone, Debug)]
pub(super) struct Pkt {
    pub at: f64,
    pub len: u32,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub win: u16,
    /// Bytes after the headers.
    pub data: u32,
    /// (type, code, the size that's allowed)
    pub icmp: Option<(u8, u8, u16)>,
    pub info: Info,
}

const FIN: u8 = 1;
const SYN: u8 = 2;
const RST: u8 = 4;
const ACK: u8 = 16;

/// Reading past the end gives nothing, so a cut or damaged packet can't make it fail.
struct B<'a>(&'a [u8]);

impl<'a> B<'a> {
    fn u8(&self, o: usize) -> Option<u8> {
        self.0.get(o).copied()
    }
    fn u16(&self, o: usize) -> Option<u16> {
        Some(u16::from_be_bytes(self.0.get(o..o.checked_add(2)?)?.try_into().ok()?))
    }
    fn u32(&self, o: usize) -> Option<u32> {
        Some(u32::from_be_bytes(self.0.get(o..o.checked_add(4)?)?.try_into().ok()?))
    }
    fn cut(&self, o: usize, n: usize) -> Option<&'a [u8]> {
        self.0.get(o..o.checked_add(n)?)
    }
    fn rest(&self, o: usize) -> &'a [u8] {
        self.0.get(o..).unwrap_or(&[])
    }
}

fn v4(b: &[u8]) -> Option<IpAddr> {
    <[u8; 4]>::try_from(b).ok().map(IpAddr::from)
}
fn v6(b: &[u8]) -> Option<IpAddr> {
    <[u8; 16]>::try_from(b).ok().map(IpAddr::from)
}

/// Only what can be shown.
fn printable(b: &[u8]) -> String {
    b.iter().map(|c| if (0x20..0x7f).contains(c) { *c as char } else { '.' }).collect()
}

/// Where the IP header begins, by the kind of link.
fn ip_start(link: u32, b: &[u8]) -> Option<usize> {
    let x = B(b);
    let ether = |mut at: usize| -> Option<usize> {
        // Skips VLAN tags.
        for _ in 0..3 {
            match x.u16(at)? {
                0x8100 | 0x88a8 => at += 4,
                0x0800 | 0x86dd => return Some(at + 2),
                _ => return None,
            }
        }
        None
    };
    match link {
        1 => ether(12),
        // Raw IP.
        12 | 14 | 101 | 228 | 229 => Some(0),
        // Linux "any": cooked, the old and the new one.
        113 => match x.u16(14)? {
            0x0800 | 0x86dd => Some(16),
            0x8100 => ether(14),
            _ => None,
        },
        276 => match x.u16(0)? {
            0x0800 | 0x86dd => Some(20),
            _ => None,
        },
        // Loopback.
        0 | 108 => Some(4),
        _ => None,
    }
}

/// Where the headers of a packet end (IP and what's right after it), for cutting a saved file.
fn headers_end(b: &[u8], ip: usize) -> usize {
    let x = B(b);
    let Some((_, at, proto)) = ip_header(&x, ip) else { return (ip + 20).min(b.len()) };
    let n = match proto {
        6 => x.u8(at + 12).map(|v| (v >> 4) as usize * 4).filter(|n| *n >= 20).unwrap_or(20),
        1 | 17 | 58 => 8,
        // A later piece of a packet, or something that isn't known: nothing more.
        _ => 0,
    };
    (at + n).min(b.len())
}

/// (source and destination and length of the packet, where what's in it begins, what that is)
#[allow(clippy::type_complexity)]
fn ip_header(x: &B, ip: usize) -> Option<((IpAddr, IpAddr, usize), usize, u8)> {
    match x.u8(ip)? >> 4 {
        4 => {
            let ihl = (x.u8(ip)? & 15) as usize * 4;
            if ihl < 20 {
                return None;
            }
            let frag = x.u16(ip + 6)? & 0x1fff;
            // A later fragment has no header of its own.
            let proto = if frag != 0 { 255 } else { x.u8(ip + 9)? };
            Some(((v4(x.cut(ip + 12, 4)?)?, v4(x.cut(ip + 16, 4)?)?, x.u16(ip + 2)? as usize), ip + ihl, proto))
        }
        6 => {
            let len = 40 + x.u16(ip + 4)? as usize;
            let (s, d) = (v6(x.cut(ip + 8, 16)?)?, v6(x.cut(ip + 24, 16)?)?);
            let (mut next, mut at) = (x.u8(ip + 6)?, ip + 40);
            for _ in 0..8 {
                match next {
                    0 | 43 | 60 => {
                        next = x.u8(at)?;
                        at += (x.u8(at + 1)? as usize + 1) * 8;
                    }
                    44 => {
                        let off = x.u16(at + 2)? >> 3;
                        next = if off != 0 { 255 } else { x.u8(at)? };
                        at += 8;
                    }
                    _ => break,
                }
            }
            Some(((s, d, len), at, next))
        }
        _ => None,
    }
}

/// A domain name; pointers count from `base`. Follows at most 16 of them.
fn dns_name(x: &B, base: usize, mut o: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = vec![];
    let mut next = None;
    let mut jumps = 0;
    loop {
        let n = x.u8(o)? as usize;
        match n {
            0 => {
                let end = next.unwrap_or(o + 1);
                return Some((if labels.is_empty() { ".".into() } else { labels.join(".") }, end));
            }
            n if n & 0xc0 == 0xc0 => {
                next = next.or(Some(o + 2));
                o = base.checked_add((x.u16(o)? & 0x3fff) as usize)?;
                jumps += 1;
                if jumps > 16 {
                    return None;
                }
            }
            n if n & 0xc0 != 0 => return None,
            n => {
                if labels.len() > 127 {
                    return None;
                }
                labels.push(printable(x.cut(o + 1, n)?));
                o += 1 + n;
            }
        }
    }
}

fn dns(b: &[u8]) -> Option<Info> {
    let x = B(b);
    let flags = x.u16(2)?;
    let (q, a) = (x.u16(4)?, x.u16(6)?);
    if q != 1 || flags & 0x7800 != 0 {
        return None;
    }
    let (name, at) = dns_name(&x, 0, 12)?;
    let kind = match x.u16(at)? {
        1 => "A".to_string(),
        28 => "AAAA".into(),
        5 => "CNAME".into(),
        33 => "SRV".into(),
        12 => "PTR".into(),
        16 => "TXT".into(),
        6 => "SOA".into(),
        15 => "MX".into(),
        65 => "HTTPS".into(),
        n => format!("TYPE{n}"),
    };
    let mut addrs = vec![];
    let mut o = at + 4;
    for _ in 0..a.min(32) {
        let Some((_, p)) = dns_name(&x, 0, o) else { break };
        let (Some(t), Some(n)) = (x.u16(p), x.u16(p + 8)) else { break };
        // Only addresses of an answer are kept.
        match (t, x.cut(p + 10, n as usize)) {
            (1, Some(d)) => addrs.extend(v4(d).map(|i| i.to_string())),
            (28, Some(d)) => addrs.extend(v6(d).map(|i| i.to_string())),
            _ => {}
        }
        o = p + 10 + n as usize;
    }
    Some(Info::Dns { id: x.u16(0)?, name, kind, answer: flags & 0x8000 != 0, code: (flags & 15) as u8, addrs })
}

/// The first line of HTTP, without a question's part.
fn http(b: &[u8]) -> Option<Info> {
    const WAYS: [&str; 7] = ["GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH "];
    let l: Vec<u8> = b.iter().take(400).take_while(|c| !matches!(c, b'\r' | b'\n')).copied().collect();
    let t = printable(&l);
    if let Some(w) = WAYS.iter().find(|w| t.starts_with(**w)) {
        let path = t[w.len()..].split([' ', '?', '#']).next().unwrap_or("");
        return Some(Info::Http(format!("{w}{}", truncate(path, 120))));
    }
    if t.starts_with("HTTP/1.") {
        // The words after the code are the server's own.
        return Some(Info::Http(t.split(' ').take(2).collect::<Vec<_>>().join(" ")));
    }
    None
}

fn alert_name(n: u8) -> &'static str {
    match n {
        0 => "close notify",
        10 => "unexpected message",
        20 => "bad record",
        40 => "handshake failure: no way to talk that both know",
        42 => "bad certificate",
        43 => "unsupported certificate",
        44 => "certificate withdrawn",
        45 => "certificate expired",
        46 => "certificate unknown",
        48 => "unknown certificate authority",
        49 => "access denied",
        50 | 51 => "decode or decrypt error",
        70 => "this version of TLS isn't accepted",
        71 => "not secure enough",
        80 => "internal error",
        86 => "inappropriate fallback",
        90 => "cancelled",
        112 => "unknown name",
        116 => "certificate required",
        120 => "no common protocol",
        _ => "other",
    }
}

fn tls(b: &[u8]) -> Option<Info> {
    let x = B(b);
    let (kind, major) = (x.u8(0)?, x.u8(1)?);
    if major != 3 || x.u8(2)? > 4 {
        return None;
    }
    match kind {
        21 if x.u16(3)? == 2 => {
            let (level, n) = (x.u8(5)?, x.u8(6)?);
            if !matches!(level, 1 | 2) {
                return None;
            }
            (n != 0).then(|| Info::Alert(level == 2, alert_name(n).to_string()))
        }
        22 if x.u8(5)? == 1 => {
            // Client hello: skip to the extensions for the name.
            let mut o = 5 + 4 + 2 + 32;
            o += 1 + x.u8(o)? as usize;
            o += 2 + x.u16(o)? as usize;
            o += 1 + x.u8(o)? as usize;
            let end = o + 2 + x.u16(o)? as usize;
            o += 2;
            while o + 4 <= end {
                let (t, n) = (x.u16(o)?, x.u16(o + 2)? as usize);
                if t == 0 {
                    let len = x.u16(o + 7)? as usize;
                    return Some(Info::Hello(printable(x.cut(o + 9, len.min(255))?)));
                }
                o += 4 + n;
            }
            Some(Info::Hello(String::new()))
        }
        _ => None,
    }
}

/// A packet from its bytes. None: not IP, or too little of it.
pub(super) fn decode(at: f64, link: u32, b: &[u8], real: u32) -> Option<Pkt> {
    let ip = ip_start(link, b)?;
    let x = B(b);
    let ((src, dst, total), o, proto) = ip_header(&x, ip)?;
    let mut p = Pkt { at, len: real, src, dst, proto, sport: 0, dport: 0, flags: 0, seq: 0, ack: 0, win: 0, data: 0, icmp: None, info: Info::None };
    // The packet ends where its header says (links pad short ones).
    let stop = (ip + total).clamp(o.min(b.len()), b.len());
    match proto {
        6 => {
            (p.sport, p.dport, p.seq, p.ack) = (x.u16(o)?, x.u16(o + 2)?, x.u32(o + 4)?, x.u32(o + 8)?);
            let h = (x.u8(o + 12)? >> 4) as usize * 4;
            p.flags = x.u8(o + 13)? & 0x3f;
            p.win = x.u16(o + 14)?;
            p.data = (ip + total).saturating_sub(o + h) as u32;
            let body = B(&b[..stop]).rest(o + h.max(20));
            if !body.is_empty() {
                p.info = if p.sport == 53 || p.dport == 53 { body.get(2..).and_then(dns) } else { None }.or_else(|| tls(body)).or_else(|| http(body)).unwrap_or(Info::None);
            }
        }
        17 => {
            (p.sport, p.dport) = (x.u16(o)?, x.u16(o + 2)?);
            p.data = (x.u16(o + 4)? as u32).saturating_sub(8);
            if [p.sport, p.dport].iter().any(|n| matches!(n, 53 | 5353 | 5355)) {
                p.info = dns(B(&b[..stop]).rest(o + 8)).unwrap_or(Info::None);
            }
        }
        1 => p.icmp = Some((x.u8(o)?, x.u8(o + 1)?, x.u16(o + 6).unwrap_or(0))),
        58 => p.icmp = Some((x.u8(o)?, x.u8(o + 1)?, x.u32(o + 4).unwrap_or(0).min(65535) as u16)),
        _ => {}
    }
    Some(p)
}

// ---------- files ----------

/// A capture: its packets, and what there is to say about the file itself.
#[derive(Clone, Debug, Default)]
pub(super) struct Capture {
    pub name: String,
    pub packets: Vec<Pkt>,
    /// Packets that weren't IP, or couldn't be read.
    pub other: usize,
    /// It went on, but wasn't read further.
    pub cut: bool,
    pub notes: Vec<String>,
}

/// Goes over a file's packets: (time, link, bytes, real length). Returns why it stopped, if not at the end.
fn each(file: &[u8], mut f: impl FnMut(f64, u32, &[u8], u32) -> bool) -> Result<Option<String>, String> {
    let le16 = |o: usize| file.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let raw = |o: usize, big: bool| file.get(o..o.checked_add(4)?).map(|b| if big { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) } else { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) });
    let magic = raw(0, false).ok_or("That's too short for a capture.")?;
    match magic {
        0xa1b2c3d4 | 0xa1b23c4d | 0xd4c3b2a1 | 0x4d3cb2a1 => {
            let big = matches!(magic, 0xd4c3b2a1 | 0x4d3cb2a1);
            let nano = matches!(magic, 0xa1b23c4d | 0x4d3cb2a1);
            let link = raw(20, big).ok_or("It's cut off.")? & 0xffff;
            let mut o = 24;
            while o < file.len() {
                let (Some(s), Some(u), Some(n), Some(real)) = (raw(o, big), raw(o + 4, big), raw(o + 8, big), raw(o + 12, big)) else { return Ok(Some("the last packet is cut off".into())) };
                if n > 1 << 20 {
                    return Ok(Some("the rest is damaged".into()));
                }
                let Some(b) = file.get(o + 16..o + 16 + n as usize) else { return Ok(Some("the last packet is cut off".into())) };
                if !f(s as f64 + u as f64 / if nano { 1e9 } else { 1e6 }, link, b, real) {
                    return Ok(None);
                }
                o += 16 + n as usize;
            }
            Ok(None)
        }
        0x0a0d0d0a => {
            let mut big = false;
            // Per interface: (link, seconds per unit)
            let mut ifs: Vec<(u32, f64)> = vec![];
            let mut o = 0;
            while o + 12 <= file.len() {
                let kind = if raw(o, false) == Some(0x0a0d0d0a) { 0x0a0d0d0a } else { raw(o, big).unwrap_or(0) };
                if kind == 0x0a0d0d0a {
                    big = raw(o + 8, true) == Some(0x1a2b3c4d);
                    ifs.clear();
                }
                let Some(len) = raw(o + 4, big).map(|n| n as usize).filter(|n| *n >= 12 && n % 4 == 0) else { return Ok(Some("the rest is damaged".into())) };
                let Some(body) = file.get(o + 8..(o + len).saturating_sub(4)).filter(|_| o + len <= file.len()) else { return Ok(Some("the last part is cut off".into())) };
                let n32 = |at: usize| body.get(at..at + 4).map(|b| if big { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) } else { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) });
                let n16 = |at: usize| body.get(at..at + 2).map(|b| if big { u16::from_be_bytes([b[0], b[1]]) } else { u16::from_le_bytes([b[0], b[1]]) });
                match kind {
                    1 => {
                        let link = n16(0).unwrap_or(0) as u32;
                        let mut unit = 1e-6;
                        let mut at = 8;
                        while let (Some(c), Some(l)) = (n16(at), n16(at + 2)) {
                            if c == 0 {
                                break;
                            }
                            if c == 9 {
                                let v = body.get(at + 4).copied().unwrap_or(6);
                                unit = if v & 0x80 != 0 { 0.5f64.powi((v & 0x7f) as i32) } else { 0.1f64.powi(v as i32) };
                            }
                            at += 4 + (l as usize).div_ceil(4) * 4;
                        }
                        ifs.push((link, unit));
                    }
                    6 => {
                        if let (Some(i), Some(h), Some(l), Some(n), Some(real)) = (n32(0), n32(4), n32(8), n32(12), n32(16)) {
                            if let (Some((link, unit)), Some(b)) = (ifs.get(i as usize), body.get(20..20 + (n as usize).min(1 << 20))) {
                                if !f((((h as u64) << 32) | l as u64) as f64 * unit, *link, b, real) {
                                    return Ok(None);
                                }
                            }
                        }
                    }
                    3 => {
                        if let (Some(real), Some((link, _))) = (n32(0), ifs.first()) {
                            let n = (real as usize).min(body.len().saturating_sub(4));
                            if !f(0.0, *link, &body[4..4 + n], real) {
                                return Ok(None);
                            }
                        }
                    }
                    _ => {}
                }
                o += len;
            }
            Ok(None)
        }
        _ if le16(0) == Some(0x8b1f) => Err("It's compressed (gzip): unpack it first.".into()),
        _ => Err("That isn't a capture: pcap and pcapng files can be read.".into()),
    }
}

pub(super) fn read(name: &str, file: &[u8]) -> Result<Capture, String> {
    let mut c = Capture { name: name.into(), ..Default::default() };
    let mut links: HashSet<u32> = HashSet::new();
    let mut cut = false;
    let why = each(file, |at, link, b, real| {
        if c.packets.len() >= MOST_PACKETS {
            cut = true;
            return false;
        }
        match decode(at, link, b, real) {
            Some(p) => c.packets.push(p),
            None => {
                c.other += 1;
                if !matches!(link, 0 | 1 | 12 | 14 | 101 | 108 | 113 | 228 | 229 | 276) {
                    links.insert(link);
                }
            }
        }
        true
    })?;
    c.cut = cut;
    c.notes.extend(why);
    if !links.is_empty() {
        c.notes.push(format!("a kind of link that isn't known here ({})", links.iter().map(|l| l.to_string()).collect::<Vec<_>>().join(", ")));
    }
    Ok(c)
}

/// The same file with every packet cut to its headers.
pub(super) fn only_headers(file: &[u8]) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = vec![];
    let mut first = true;
    each(file, |at, link, b, real| {
        if first {
            first = false;
            for v in [0xa1b23c4du32, 0x0004_0002, 0, 0, 65535, link] {
                out.extend(v.to_le_bytes());
            }
        }
        // What isn't IP could hold anything: left out.
        let Some(ip) = ip_start(link, b) else {
            return true;
        };
        let keep = &b[..headers_end(b, ip).min(b.len())];
        for v in [at as u32, (at.fract() * 1e9) as u32, keep.len() as u32, real] {
            out.extend(v.to_le_bytes());
        }
        out.extend(keep);
        true
    })?;
    Ok(out)
}

// ---------- what happened ----------

/// Two ends that talk.
#[derive(Clone, Debug)]
pub(super) struct Talk {
    pub proto: u8,
    /// Who began, and the other.
    pub a: (IpAddr, u16),
    pub b: (IpAddr, u16),
    pub packets: usize,
    pub bytes: u64,
    pub from: f64,
    pub to: f64,
    pub syns: usize,
    pub syn_ack: bool,
    /// From the first SYN to its answer.
    pub wait: Option<f64>,
    pub reset_by_a: bool,
    pub reset_by_b: bool,
    pub data: bool,
    /// The other side sent something.
    pub back: bool,
    pub again: usize,
    pub full: usize,
    pub name: String,
    pub web: Vec<String>,
    pub alerts: Vec<String>,
}

impl Talk {
    /// (tone, what became of it)
    pub fn state(&self) -> (Tone, String) {
        if !self.alerts.is_empty() {
            return (Tone::Danger, format!("TLS: {}", self.alerts[0]));
        }
        if self.proto == 6 {
            if self.syns > 0 && !self.syn_ack && !self.data {
                if self.reset_by_b {
                    return (Tone::Danger, "refused".into());
                }
                return (Tone::Danger, format!("no answer ({} tried)", many(self.syns as i64, "time")));
            }
            if self.reset_by_a || self.reset_by_b {
                return (Tone::Warning, format!("reset by {}", if self.reset_by_b { "the other side" } else { "who began it" }));
            }
            if self.again * 50 > self.packets && self.again > 2 {
                return (Tone::Warning, format!("{} sent again", many(self.again as i64, "packet")));
            }
            if self.full > 3 {
                return (Tone::Warning, "a receiver that can't keep up".into());
            }
        }
        if self.proto == 17 {
            return (Tone::Success, if self.back { "answered".into() } else { "one way only".into() });
        }
        if let Some(w) = self.web.iter().find(|w| w.starts_with("HTTP/") && w.contains(" 5")) {
            return (Tone::Warning, w.clone());
        }
        (Tone::Success, "fine".into())
    }
}

/// Every conversation, in the order they began.
pub(super) fn talks(c: &Capture) -> Vec<Talk> {
    let mut at: HashMap<(u8, IpAddr, u16, IpAddr, u16), usize> = HashMap::new();
    let mut out: Vec<Talk> = vec![];
    // Per conversation and way: how far it has sent.
    let mut far: HashMap<(usize, bool), u32> = HashMap::new();
    // On a whole node one packet is seen at several of its network cards: that's not sending it again.
    let mut same: HashMap<(IpAddr, u16, IpAddr, u16, u32, u32, u8, u32), f64> = HashMap::new();
    for p in c.packets.iter().filter(|p| matches!(p.proto, 6 | 17)) {
        if p.proto == 6 {
            let k = (p.src, p.sport, p.dst, p.dport, p.seq, p.ack, p.flags, p.data);
            if same.insert(k, p.at).map(|t| (p.at - t).abs() < 0.002).unwrap_or(false) {
                continue;
            }
        }
        let (k, r) = ((p.proto, p.src, p.sport, p.dst, p.dport), (p.proto, p.dst, p.dport, p.src, p.sport));
        let fresh = p.flags & (SYN | ACK) == SYN;
        let known = at.get(&k).or(at.get(&r)).copied();
        // The same ports, used once more after it was over.
        let over = known.map(|i| fresh && (out[i].reset_by_a || out[i].reset_by_b) && out[i].data).unwrap_or(false);
        let i = match known.filter(|_| !over) {
            Some(i) => i,
            None => {
                // Seen first from the one that answers.
                let turned = (p.flags & (SYN | ACK) == SYN | ACK) || (!fresh && p.sport < p.dport && p.sport < 1024);
                let (a, b) = if turned { ((p.dst, p.dport), (p.src, p.sport)) } else { ((p.src, p.sport), (p.dst, p.dport)) };
                out.push(Talk { proto: p.proto, a, b, packets: 0, bytes: 0, from: p.at, to: p.at, syns: 0, syn_ack: false, wait: None, reset_by_a: false, reset_by_b: false, data: false, back: false, again: 0, full: 0, name: String::new(), web: vec![], alerts: vec![] });
                at.insert(k, out.len() - 1);
                at.insert(r, out.len() - 1);
                out.len() - 1
            }
        };
        let t = &mut out[i];
        let by_a = (p.src, p.sport) == t.a;
        t.packets += 1;
        t.bytes += p.len as u64;
        t.to = p.at.max(t.to);
        t.back |= !by_a;
        if p.proto == 6 {
            if fresh {
                t.syns += 1;
            }
            if p.flags & (SYN | ACK) == SYN | ACK {
                t.wait = t.wait.or((t.syns > 0).then_some(p.at - t.from));
                t.syn_ack = true;
            }
            if p.flags & RST != 0 {
                if by_a { t.reset_by_a = true } else { t.reset_by_b = true }
            }
            if p.data > 0 {
                t.data = true;
                let end = p.seq.wrapping_add(p.data);
                match far.get_mut(&(i, by_a)) {
                    // Wholly behind what was sent before (numbers go round). One byte: a keep-alive.
                    Some(f) if f.wrapping_sub(end) < 1 << 31 && p.data > 1 => t.again += 1,
                    Some(f) => *f = end,
                    None => {
                        far.insert((i, by_a), end);
                    }
                }
            }
            if p.win == 0 && p.flags & (RST | SYN | FIN) == 0 {
                t.full += 1;
            }
        }
        match &p.info {
            Info::Hello(n) if t.name.is_empty() => t.name = n.clone(),
            Info::Http(l) if t.web.len() < 12 => t.web.push(l.clone()),
            // Going away without having talked isn't a failure.
            Info::Alert(fatal, w) if *fatal && t.alerts.len() < 4 => t.alerts.push(w.clone()),
            _ => {}
        }
    }
    out
}

/// What went wrong, the worst first: (tone, what, more).
pub(super) fn finds(c: &Capture, l: &[Talk]) -> Vec<(Tone, String, String)> {
    let mut v: Vec<(Tone, String, String)> = vec![];
    let end = |x: &(IpAddr, u16)| format!("{}:{}", x.0, x.1);
    // Connections, by what they went to.
    let mut by: HashMap<(String, &str), (usize, Vec<String>)> = HashMap::new();
    for t in l.iter().filter(|t| t.proto == 6) {
        let what = match t.state().1 {
            s if s == "refused" => "refused",
            s if s.starts_with("no answer") => "no answer",
            s if s.starts_with("reset by the other") => "reset by the other side",
            s if s.starts_with("reset") => "reset by who began it",
            s if s.contains("sent again") => "packets sent again",
            s if s.contains("keep up") => "a receiver that can't keep up",
            _ => continue,
        };
        let e = by.entry((end(&t.b), what)).or_default();
        e.0 += 1;
        let who = t.a.0.to_string();
        if !e.1.contains(&who) && e.1.len() < 5 {
            e.1.push(who);
        }
    }
    for ((to, what), (n, who)) in by {
        let tone = if matches!(what, "refused" | "no answer") { Tone::Danger } else { Tone::Warning };
        let hint = match what {
            "refused" => "nothing listens on that port, or something in between says no",
            "no answer" => "usually a policy or firewall that drops it, or no route back",
            "packets sent again" => "packets get lost on the way: a busy or faulty link, or a size that doesn't fit",
            "a receiver that can't keep up" => "its buffer is full: the app reads too slowly",
            _ => "it was cut off while it was used",
        };
        v.push((tone, format!("{to}: {what}, {}", many(n as i64, "connection")), format!("from {}; {hint}", who.join(", "))));
    }
    // Names.
    let mut asked: HashMap<(IpAddr, u16, IpAddr, u16), (String, String)> = HashMap::new();
    let mut fails: HashMap<(String, u8), usize> = HashMap::new();
    let mut good: HashSet<String> = HashSet::new();
    for p in &c.packets {
        if let Info::Dns { id, name, kind, answer, code, addrs } = &p.info {
            if matches!(p.dport, 5353 | 5355) {
                continue;
            }
            if *answer {
                asked.remove(&(p.dst, p.dport, p.src, *id));
                if *code != 0 {
                    *fails.entry((name.to_lowercase(), *code)).or_default() += 1;
                } else if !addrs.is_empty() {
                    good.insert(name.to_lowercase());
                }
            } else {
                asked.insert((p.src, p.sport, p.dst, *id), (name.clone(), kind.clone()));
            }
        }
    }
    let last = c.packets.last().map(|p| p.at).unwrap_or(0.0);
    let mut missing = 0;
    let mut which: Vec<String> = vec![];
    for (n, _) in asked.values() {
        missing += 1;
        if which.len() < 4 && !which.contains(n) {
            which.push(n.clone());
        }
    }
    if missing > 0 && last > 0.0 {
        v.push((Tone::Danger, format!("{} without an answer", many(missing, "name look-up")), which.join(", ")));
    }
    // Searching through the cluster's own names first is normal: those end in another that's found.
    let mut nx: Vec<String> = vec![];
    for ((n, code), k) in &fails {
        match code {
            3 => {
                let part = n.split(".svc.").next().unwrap_or(n);
                let searched = n.contains(".cluster.local") && good.iter().any(|g| part.starts_with(g.as_str()) || g.starts_with(part) || n.starts_with(&format!("{g}.")));
                if !searched {
                    nx.push(n.clone());
                }
            }
            2 => v.push((Tone::Danger, format!("{n}: the name server failed ({k} times)"), "SERVFAIL: the servers behind it can't be reached or don't answer".into())),
            5 => v.push((Tone::Warning, format!("{n}: the name server refused ({k} times)"), String::new())),
            c => v.push((Tone::Warning, format!("{n}: code {c} from the name server"), String::new())),
        }
    }
    nx.sort();
    if !nx.is_empty() {
        v.push((Tone::Warning, format!("{} found nowhere", many(nx.len() as i64, "name")), truncate(&nx.join(", "), 400)));
    }
    // TLS.
    let mut alerts: HashMap<(String, String), usize> = HashMap::new();
    for t in l {
        for a in &t.alerts {
            *alerts.entry((if t.name.is_empty() { end(&t.b) } else { format!("{} ({})", t.name, end(&t.b)) }, a.clone())).or_default() += 1;
        }
    }
    for ((to, a), n) in alerts {
        v.push((Tone::Danger, format!("TLS with {to}: {a}"), many(n as i64, "time")));
    }
    // ICMP.
    let mut too_big: HashMap<(IpAddr, u16), usize> = HashMap::new();
    let mut nope: HashMap<(IpAddr, &str), usize> = HashMap::new();
    for p in &c.packets {
        match (p.proto, p.icmp) {
            (1, Some((3, 4, m))) | (58, Some((2, 0, m))) => *too_big.entry((p.src, m)).or_default() += 1,
            (1, Some((3, n, _))) => *nope.entry((p.src, match n { 0 => "network", 1 => "host", 3 => "port", 9 | 10 | 13 => "forbidden", _ => "other" })).or_default() += 1,
            (58, Some((1, n, _))) => *nope.entry((p.src, match n { 1 | 5 | 6 => "forbidden", 4 => "port", _ => "host" })).or_default() += 1,
            (1 | 58, Some((11 | 3, 0, _))) => *nope.entry((p.src, "loop")).or_default() += 1,
            _ => {}
        }
    }
    for ((who, m), n) in too_big {
        v.push((Tone::Danger, format!("{who} says packets are too big: {m} bytes fit"), format!("{}; the MTU of the network or a tunnel in between is smaller than the sender thinks", many(n as i64, "time"))));
    }
    for ((who, w), n) in nope {
        let (t, x) = match w {
            "forbidden" => (Tone::Danger, "says it's forbidden (a firewall)"),
            "port" => (Tone::Warning, "says nothing listens on that UDP port"),
            "loop" => (Tone::Danger, "says it was passed on too often: routes may go in a circle"),
            _ => (Tone::Danger, "says it can't be reached"),
        };
        v.push((t, format!("{who} {x}"), many(n as i64, "time")));
    }
    v.sort_by(|a, b| (a.0 != Tone::Danger, &a.1).cmp(&(b.0 != Tone::Danger, &b.1)));
    v
}


// ---------- capturing ----------

/// What runs in the helper on the node: into the pod's network when there is one, then tcpdump with a
/// filter, a time and a number of packets, sent back as text. All of it are arguments.
const SCRIPT: &str = r#"u=$1; s=$2; n=$3; z=$4; f=$5; r=
if [ -n "$u" ]; then
v=$(printf %s "$u" | tr - _)
o=$(readlink /proc/self/ns/net); p=
for q in $(grep -l -s -e "$u" -e "$v" /proc/[0-9]*/cgroup | cut -d/ -f3); do
w=$(readlink "/proc/$q/ns/net" 2>/dev/null)
if [ -n "$w" ] && [ "$w" != "$o" ]; then p=$q; break; fi
done
if [ -z "$p" ]; then echo "KD none"; exit 0; fi
r="nsenter -t $p -n"
fi
echo "KD pcap"
timeout -k 5 $((s+10)) $r timeout -s INT "$s" tcpdump -i any -n -p -U -s "$z" -c "$n" -w - "$f" 2>/tmp/kd | base64
echo "KD said"
cat /tmp/kd
echo "KD done"
"#;

/// Bytes kept of each packet, when only headers are wanted: enough for a name in DNS or TLS.
const SNAP: u32 = 512;

#[derive(Clone, PartialEq, Debug)]
pub(super) struct Grab {
    pub ctx: String,
    pub node: String,
    /// The pod whose network it's in; empty: the node's.
    pub uid: String,
    pub label: String,
    pub filter: String,
    pub secs: u64,
    pub count: u64,
    pub contents: bool,
    pub image: String,
    pub ns: String,
    pub control: bool,
}

impl Grab {
    fn command(&self) -> Vec<String> {
        ["sh", "-c", SCRIPT, "grab", &self.uid, &self.secs.to_string(), &self.count.to_string(), &(if self.contents { 0 } else { SNAP }).to_string(), &self.filter].iter().map(|s| s.to_string()).collect()
    }
}

/// The filter, from what was filled in; one is needed.
pub(super) fn filter(proto: &str, port: &str, host: &str) -> Result<String, String> {
    let mut v: Vec<String> = vec![];
    match proto {
        "" => {}
        "tcp" | "udp" | "icmp" => v.push(proto.into()),
        _ => return Err("That protocol isn't known.".into()),
    }
    if !port.trim().is_empty() {
        v.push(format!("port {}", port.trim().parse::<u16>().ok().filter(|p| *p > 0).ok_or("The port is a number from 1 to 65535.")?));
    }
    if !host.trim().is_empty() {
        v.push(format!("host {}", host.trim().parse::<IpAddr>().map_err(|_| "Give the address as numbers, like 192.0.2.1.")?));
    }
    if v.is_empty() || v == ["tcp"] || v == ["udp"] {
        return Err("Give a port or an address: a narrow filter keeps a busy node well.".into());
    }
    Ok(v.join(" and "))
}

/// The capture out of what came back, and what tcpdump said.
fn unpack(out: &str) -> Result<(Vec<u8>, String), String> {
    if out.contains("KD none") {
        return Err("The pod's network wasn't found on its node.".into());
    }
    let said: String = out.split("KD said").nth(1).unwrap_or("").replace("KD done", "").trim().to_string();
    let b = out.split("KD pcap").nth(1).and_then(|r| r.split("KD said").next()).unwrap_or("").split_whitespace().collect::<String>();
    let file = b64_decode(&b).unwrap_or_default();
    if file.len() < 24 {
        return Err(format!("Nothing came back: {}", truncate(said.lines().last().unwrap_or("tcpdump said nothing"), 160)));
    }
    Ok((file, said))
}

/// Captures, with a helper on the node. What's kept is cut to headers unless contents were chosen.
fn grab(k: &Kubectl, g: &Grab) -> Result<(Open, Vec<u8>), String> {
    let name = nethelp::new_name("capture");
    let out = nethelp::run_in_pod(k, &g.ctx, &g.ns, &name, &nethelp::pod_json(&name, &g.ns, &g.image, &Make::Node(g.node.clone()), g.secs + 20, false), &g.command(), g.secs + 20)?;
    let (file, said) = unpack(&out)?;
    let mut c = read(&g.label, &file)?;
    if let Some(d) = said.lines().find(|l| l.contains("dropped by kernel") && !l.trim().starts_with("0 ")) {
        c.notes.push(format!("{} (the node was too busy for this)", d.trim()));
    }
    let keep = if g.contents { file } else { only_headers(&file)? };
    Ok((Open::new(c), keep))
}

// ---------- the page ----------

/// A capture with what was made of it.
pub(super) struct Open {
    pub cap: Capture,
    pub talks: Vec<Talk>,
    pub finds: Vec<(Tone, String, String)>,
}

impl Open {
    pub fn new(cap: Capture) -> Open {
        let talks = talks(&cap);
        let finds = finds(&cap, &talks);
        Open { cap, talks, finds }
    }
}

type Slot = Arc<Mutex<Option<Result<(Open, Option<Vec<u8>>), String>>>>;

#[derive(Default)]
pub(super) struct Packets {
    path: String,
    error: String,
    busy: bool,
    slot: Slot,
    pub open: Option<Open>,
    /// The conversation whose packets are shown.
    talk: Option<usize>,
    bad_only: bool,
    /// A capture that was made here, for saving; in memory only.
    kept: Option<Vec<u8>>,
    // What to capture.
    find: String,
    at: Option<Selected>,
    proto: usize,
    port: String,
    host: String,
    secs: usize,
    contents: bool,
    grabbing: bool,
}

const PROTOS: [(&str, &str); 4] = [("any", ""), ("TCP", "tcp"), ("UDP", "udp"), ("ICMP", "icmp")];
const TIMES: [u64; 4] = [15, 30, 60, 120];
const COUNT: u64 = 5000;

/// How a conversation is called.
fn ends(t: &Talk) -> (String, String) {
    let e = |x: &(IpAddr, u16)| if x.0.is_ipv6() { format!("[{}]:{}", x.0, x.1) } else { format!("{}:{}", x.0, x.1) };
    (e(&t.a), e(&t.b))
}

fn flags(f: u8) -> String {
    [(SYN, "SYN"), (FIN, "FIN"), (RST, "RST"), (8, "PSH"), (ACK, "ACK")].iter().filter(|x| f & x.0 != 0).map(|x| x.1).collect::<Vec<_>>().join(" ")
}

fn in_words(p: &Pkt) -> String {
    match &p.info {
        Info::Dns { name, kind, answer, code, addrs, .. } => {
            if !*answer { format!("DNS: {kind} of {name}?") } else if *code == 3 { format!("DNS: no such name {name}") } else if *code != 0 { format!("DNS: code {code} for {name}") } else if addrs.is_empty() { format!("DNS: nothing of kind {kind} for {name}") } else { format!("DNS: {name} is {}", addrs.join(", ")) }
        }
        Info::Http(l) => l.clone(),
        Info::Hello(n) => format!("TLS hello{}", if n.is_empty() { String::new() } else { format!(" for {n}") }),
        Info::Alert(fatal, w) => format!("TLS alert{}: {w}", if *fatal { "" } else { " (warning)" }),
        Info::None => match p.icmp {
            Some((t, c, _)) => format!("ICMP {t}/{c}"),
            None if p.proto == 6 => flags(p.flags),
            None => String::new(),
        },
    }
}

impl KubedogApp {
    /// Reads a file away from the drawing.
    pub(super) fn open_capture(&mut self, path: String) {
        let path = match path.trim().strip_prefix("~/") {
            Some(r) => std::env::var("HOME").map(|h| format!("{h}/{r}")).unwrap_or_else(|_| path.clone()),
            None => path.trim().to_string(),
        };
        if path.is_empty() || self.netlab.packets.busy {
            return;
        }
        self.netlab.packets.busy = true;
        self.netlab.packets.error.clear();
        let slot = self.netlab.packets.slot.clone();
        self.spawn(move |_| {
            let r = std::fs::metadata(&path).map_err(|e| e.to_string()).and_then(|m| if !m.is_file() { Err("That isn't a file.".into()) } else if m.len() > MOST_BYTES { Err("That's too big: 256 MB at most.".into()) } else { std::fs::read(&path).map_err(|e| e.to_string()) }).and_then(|b| read(path.rsplit('/').next().unwrap_or(&path), &b)).map(|c| (Open::new(c), None));
            if let Ok(mut s) = slot.lock() {
                *s = Some(r);
            }
            Msg::Text { key: "packets|".into(), result: Ok(String::new()) }
        });
    }

    /// A capture that's in memory.
    pub(super) fn show_capture(&mut self, name: &str, file: &[u8]) -> Result<(), String> {
        let c = read(name, file)?;
        self.netlab.packets.open = Some(Open::new(c));
        self.netlab.packets.talk = None;
        Ok(())
    }

    pub(super) fn on_packets(&mut self, key: &str, result: &Result<String, String>) -> bool {
        match key {
            "pickcapture" => {
                if let Ok(p) = result {
                    if !p.is_empty() {
                        self.netlab.packets.path = p.clone();
                        self.open_capture(p.clone());
                    }
                }
                true
            }
            "packets|" => {
                self.netlab.packets.busy = false;
                self.netlab.packets.grabbing = false;
                let r = self.netlab.packets.slot.lock().ok().and_then(|mut s| s.take());
                match r {
                    Some(Ok((o, kept))) => {
                        self.netlab.packets.open = Some(o);
                        self.netlab.packets.kept = kept;
                        self.netlab.packets.talk = None;
                    }
                    Some(Err(e)) => self.netlab.packets.error = e,
                    None => self.netlab.packets.error = result.as_ref().err().map(|e| truncate(e, 200)).unwrap_or("It couldn't be read.".into()),
                }
                true
            }
            _ => false,
        }
    }

    pub(super) fn net_packets(&mut self, ui: &mut Ui) -> Option<Go> {
        // For pictures.
        if self.screenshot.is_some() && self.netlab.packets.open.is_none() {
            if let Some(b) = std::env::var("KUBEDOG_SHOT_PCAP").ok().and_then(|p| std::fs::read(p).ok()) {
                let _ = self.show_capture("made-up.pcap", &b);
                self.netlab.packets.talk = std::env::var("KUBEDOG_SHOT_OBJ").ok().and_then(|t| t.parse().ok());
            }
        }
        let mut file: Option<String> = None;
        let dropped = ui.input(|i| i.raw.dropped_files.first().map(|f| f.path().to_path_buf()));
        if let Some(p) = dropped {
            file = Some(p.to_string_lossy().to_string());
        }
        let mut pick = false;
        card(ui, |ui| {
            panel(ui, "Open a capture", "pcap and pcapng, from tcpdump or Wireshark; or drop one here");
            ui.horizontal_wrapped(|ui| {
                let r = filter_box(ui, &mut self.netlab.packets.path, "path of the file", u(420.0));
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                if button(ui, "Open", true, false) || enter {
                    file = Some(self.netlab.packets.path.clone());
                }
                pick = cfg!(target_os = "macos") && button(ui, "Choose…", false, false);
                if self.netlab.packets.busy {
                    ui.spinner();
                }
            });
            if !self.netlab.packets.error.is_empty() {
                said(ui, &self.netlab.packets.error, DANGER());
            }
            said(ui, "Only headers are read: addresses, ports, sizes and times, the names asked for in DNS and TLS, the first line of HTTP. What's in the packets isn't kept or shown, and nothing goes to AI.", TEXT_PLACEHOLDER());
        });
        if pick && self.screenshot.is_none() {
            self.spawn(|_| {
                let out = std::process::Command::new("/usr/bin/osascript").args(["-e", "POSIX path of (choose file with prompt \"Choose a capture\")"]).output();
                Msg::Text { key: "pickcapture".into(), result: out.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).map_err(|e| e.to_string()) }
            });
        }
        if let Some(f) = file.filter(|_| self.screenshot.is_none()) {
            self.open_capture(f);
        }
        ui.add_space(10.0);
        self.grab_part(ui);
        ui.add_space(10.0);
        self.packets_read(ui);
        let a = self.leftovers(ui);
        self.ran_list(ui).or(a)
    }

    /// Choosing what to capture.
    fn grab_part(&mut self, ui: &mut Ui) {
        let mut ask = false;
        let mut save = false;
        card(ui, |ui| {
            panel(ui, "Capture", "at a pod or a node, for a short time, with a helper");
            ui.horizontal_wrapped(|ui| {
                filter_box(ui, &mut self.netlab.packets.find, "pod or node", u(320.0));
                if let Some(s) = &self.netlab.packets.at {
                    pg::pill(ui, &if s.ns.is_empty() { format!("node {}", s.name) } else { format!("{}/{}", s.ns, s.name) }, PRIMARY_TEXT());
                }
            });
            if !self.netlab.packets.find.is_empty() || self.netlab.packets.at.is_none() {
                let l = self.find_ends(&self.netlab.packets.find, &[Kind::Pods, Kind::Nodes]);
                ui.horizontal_wrapped(|ui| {
                    for s in l {
                        if chip_button(ui, &if s.ns.is_empty() { format!("node {}", s.name) } else { format!("{}/{}", s.ns, s.name) }, false) {
                            self.netlab.packets.at = Some(s);
                            self.netlab.packets.find.clear();
                        }
                    }
                });
            }
            let p = &mut self.netlab.packets;
            ui.horizontal_wrapped(|ui| {
                for (i, x) in PROTOS.iter().enumerate() {
                    if chip_button(ui, x.0, p.proto == i) {
                        p.proto = i;
                    }
                }
                ui.add_space(8.0);
                ui.add(egui::TextEdit::singleline(&mut p.port).hint_text("port").desired_width(u(70.0)));
                ui.add(egui::TextEdit::singleline(&mut p.host).hint_text("or/and address").desired_width(u(150.0)));
                ui.add_space(8.0);
                for (i, t) in TIMES.iter().enumerate() {
                    if chip_button(ui, &format!("{t} s"), p.secs == i) {
                        p.secs = i;
                    }
                }
            });
            ui.checkbox(&mut p.contents, "Contents too, for a file to save (they can hold passwords)");
            ui.horizontal_wrapped(|ui| {
                if p.grabbing {
                    ui.spinner();
                    said(ui, &format!("Capturing: at most {} seconds and {COUNT} packets…", TIMES[p.secs.min(3)]), TEXT_MUTED());
                } else {
                    ask = button(ui, "Capture", true, false);
                }
                if p.kept.is_some() && !p.grabbing {
                    save = button(ui, "Save as pcap", false, false);
                }
                said(ui, "Shown are headers only. Without contents, the rest is dropped as soon as it's read, and a saved file holds headers.", TEXT_PLACEHOLDER());
            });
        });
        if ask && self.screenshot.is_none() {
            match self.make_grab() {
                Ok(g) => {
                    let body = format!("Capture packets at {} for {} seconds (at most {COUNT}), with the filter “{}”{}?\n\n{}", g.label, g.secs, g.filter, if g.contents { ", with what's in them" } else { ", headers only" }, nethelp::in_words(&Make::Node(g.node.clone()), &g.image, g.secs + 20, &g.ns, g.control));
                    self.request(Action::Grab { grab: Box::new(g) }, "Capture".into(), body, "Capture", true);
                }
                Err(e) => self.toast(e, true),
            }
        }
        if save {
            self.save_capture();
        }
    }

    fn make_grab(&self) -> Result<Grab, String> {
        let p = &self.netlab.packets;
        let Some(s) = &p.at else { return Err("Pick a pod or a node.".into()) };
        let filter = filter(PROTOS[p.proto.min(3)].1, &p.port, &p.host)?;
        let image = self.helper_ready(&s.ctx)?;
        let (node, uid, label) = if s.kind == Kind::Nodes {
            (s.name.clone(), String::new(), format!("node {}", s.name))
        } else {
            let pod = self.refs(&s.ctx, Kind::Pods, &s.ns).unwrap_or_default().into_iter().find(|x| name_of(x) == s.name && ns_of(x) == s.ns).ok_or("That pod isn't there any more.")?;
            if pod["status"]["phase"] != "Running" {
                return Err("That pod doesn't run.".into());
            }
            // On the node's network it has none of its own.
            let uid = if pod["spec"]["hostNetwork"] == true { String::new() } else { text(&pod["metadata"]["uid"]) };
            if !uid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
                return Err("That pod's id can't be used.".into());
            }
            let label = if uid.is_empty() { format!("the whole network of node {} (pod {}/{} uses that)", text(&pod["spec"]["nodeName"]), s.ns, s.name) } else { format!("pod {}/{}", s.ns, s.name) };
            (text(&pod["spec"]["nodeName"]), uid, label)
        };
        Ok(Grab { ctx: s.ctx.clone(), control: self.control_plane(&s.ctx, &node), node, uid, label, filter, secs: TIMES[p.secs.min(3)], count: COUNT, contents: p.contents, image, ns: self.helper_home() })
    }

    /// Only after a confirmation.
    pub(super) fn start_grab(&mut self, g: Grab) {
        if self.netlab.packets.busy {
            return self.toast("Something is being read already.".into(), true);
        }
        self.note_run(&g.ctx, format!("capture, {} s, “{}”{}", g.secs, g.filter, if g.contents { ", with contents" } else { "" }), format!("{}, with a helper on node {} from {}", g.label, g.node, g.image));
        let p = &mut self.netlab.packets;
        p.busy = true;
        p.grabbing = true;
        p.error.clear();
        p.kept = None;
        let slot = p.slot.clone();
        self.spawn(move |k| {
            let r = grab(k, &g).map(|(o, b)| (o, Some(b)));
            if let Ok(mut s) = slot.lock() {
                *s = Some(r);
            }
            Msg::Text { key: "packets|".into(), result: Ok(String::new()) }
        });
    }

    /// Into Downloads, readable only by the person.
    fn save_capture(&mut self) {
        let Some(b) = self.netlab.packets.kept.clone() else { return };
        let Some(home) = kube::home() else { return };
        let dir = home.join("Downloads");
        let path = dir.join(format!("{}.pcap", nethelp::new_name("capture")));
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        match o.open(&path).and_then(|mut f| std::io::Write::write_all(&mut f, &b)) {
            Ok(()) => self.toast(format!("Saved as {}", path.display()), false),
            Err(e) => self.toast(format!("It couldn't be saved: {e}"), true),
        }
    }

    fn packets_read(&mut self, ui: &mut Ui) {
        let q = self.search.to_lowercase();
        let st = &mut self.netlab.packets;
        let Some(o) = &st.open else { return };
        let c = &o.cap;
        let (first, last) = (c.packets.iter().map(|p| p.at).fold(f64::MAX, f64::min), c.packets.iter().map(|p| p.at).fold(0.0, f64::max));
        let bad = o.finds.iter().filter(|f| f.0 == Tone::Danger).count();
        let mut notes = vec![];
        if c.cut {
            notes.push(format!("only the first {} packets were read", MOST_PACKETS));
        }
        notes.extend(c.notes.clone());
        let f = Face {
            tone: if c.packets.is_empty() { Tone::Muted } else if bad > 0 { Tone::Danger } else if !o.finds.is_empty() { Tone::Warning } else { Tone::Success },
            head: if c.packets.is_empty() { "No IP packets in it".into() } else if o.finds.is_empty() { "Nothing wrong in it".into() } else { format!("{} to look at", many(o.finds.len() as i64, "thing")) },
            sub: c.name.clone(),
            notes,
            pills: vec![],
            facts: vec![
                Fact::new("Packets", (c.packets.len() + c.other).to_string()),
                Fact::new("Not IP or not readable", c.other.to_string()),
                Fact::new("Conversations", o.talks.len().to_string()),
                Fact::new("Time", if c.packets.is_empty() { "-".into() } else { format!("{:.1} s", last - first) }),
            ],
        };
        face::show(ui, &f, Side::None);
        ui.add_space(10.0);
        if let Some(i) = st.talk.filter(|i| *i < o.talks.len()) {
            let t = &o.talks[i];
            let mut close = false;
            ui.horizontal(|ui| close = button(ui, "← All conversations", false, false));
            ui.add_space(6.0);
            let (a, b) = ends(t);
            card(ui, |ui| {
                panel(ui, &format!("{a} to {b}"), &t.state().1);
                let start = t.from;
                let mut n = 0;
                for p in c.packets.iter().filter(|p| p.proto == t.proto && p.at >= t.from && p.at <= t.to && ((p.src, p.sport) == t.a && (p.dst, p.dport) == t.b || (p.src, p.sport) == t.b && (p.dst, p.dport) == t.a)) {
                    n += 1;
                    if n > 400 {
                        continue;
                    }
                    let by_a = (p.src, p.sport) == t.a;
                    let (r, resp) = line(ui, u(22.0), false);
                    let mid = r.left() + u(150.0);
                    label_at(ui, ui.painter(), egui::pos2(r.left(), r.center().y), &format!("{:.4} s", p.at - start), 11.5, TEXT_SUBTLE(), u(76.0));
                    let col = if p.flags & RST != 0 || matches!(p.info, Info::Alert(true, _)) { DANGER() } else if by_a { PRIMARY_TEXT() } else { SUCCESS() };
                    // An arrow: to the right from who began it.
                    let (x0, x1) = (mid - u(50.0), mid + u(50.0));
                    let y = r.center().y;
                    ui.painter().line_segment([egui::pos2(x0, y), egui::pos2(x1, y)], Stroke::new(1.5, col));
                    let (tip, back) = if by_a { (x1, -u(6.0)) } else { (x0, u(6.0)) };
                    for d in [-u(4.0), u(4.0)] {
                        ui.painter().line_segment([egui::pos2(tip, y), egui::pos2(tip + back, y + d)], Stroke::new(1.5, col));
                    }
                    label_at(ui, ui.painter(), egui::pos2(mid + u(66.0), y), &in_words(p), 12.5, if col == DANGER() { col } else { TEXT_DEFAULT() }, r.width() - u(330.0));
                    dash::at_end(ui, r, 1.0, &format!("{} bytes", p.data), 11.5, TEXT_SUBTLE());
                    resp.on_hover_text(format!("{} → {}\n{}\nseq {} ack {} window {}", p.src, p.dst, flags(p.flags), p.seq, p.ack, p.win));
                }
                if n > 400 {
                    said(ui, &format!("and {} more", n - 400), TEXT_PLACEHOLDER());
                }
            });
            if close {
                st.talk = None;
            }
            return;
        }
        let items: Vec<Item> = o.finds.iter().filter(|f| q.is_empty() || f.1.to_lowercase().contains(&q) || f.2.to_lowercase().contains(&q)).map(|f| Item::new(f.0, vec![f.1.clone(), f.2.clone()])).collect();
        table(ui, "What went wrong", "", &[("What", 0.46), ("More", 0.54)], &items, 60, "Nothing that shows in headers.");
        ui.horizontal(|ui| {
            if chip_button(ui, "only what failed", st.bad_only) {
                st.bad_only = !st.bad_only;
            }
        });
        ui.add_space(6.0);
        let mut l: Vec<usize> = (0..o.talks.len())
            .filter(|i| {
                let t = &o.talks[*i];
                let (a, b) = ends(t);
                (!st.bad_only || t.state().0 != Tone::Success) && (q.is_empty() || [a, b, t.name.to_lowercase(), t.state().1].iter().any(|x| x.contains(&q)))
            })
            .collect();
        l.sort_by_key(|i| match o.talks[*i].state().0 {
            Tone::Danger => 0,
            Tone::Warning => 1,
            _ => 2,
        });
        let mut open = None;
        card(ui, |ui| {
            panel(ui, &format!("Conversations ({})", l.len()), "click one for its packets");
            ui.spacing_mut().item_spacing.y = 0.0;
            for i in l.iter().take(150) {
                let t = &o.talks[*i];
                let (tone, word) = t.state();
                let (a, b) = ends(t);
                let (r, resp) = line(ui, u(28.0), true);
                let w = r.width() - u(18.0);
                let x = r.left() + u(18.0);
                let y = r.center().y;
                ui.painter().circle_filled(egui::pos2(r.left() + u(5.0), y), u(4.5), if t.proto == 17 { TEXT_PLACEHOLDER() } else { tone_color(tone) });
                label_at(ui, ui.painter(), egui::pos2(x, y), &format!("{a} → {b}"), 13.0, PRIMARY_TEXT(), w * 0.36);
                label_at(ui, ui.painter(), egui::pos2(x + w * 0.37, y), if t.proto == 6 { "TCP" } else { "UDP" }, 12.0, TEXT_SUBTLE(), w * 0.05);
                label_at(ui, ui.painter(), egui::pos2(x + w * 0.43, y), &word, 12.5, if tone == Tone::Success { TEXT_MUTED() } else { tone_color(tone) }, w * 0.22);
                label_at(ui, ui.painter(), egui::pos2(x + w * 0.66, y), if t.name.is_empty() { t.web.first().map(|s| s.as_str()).unwrap_or("") } else { &t.name }, 12.5, TEXT_MUTED(), w * 0.2);
                dash::at_end(ui, r, 1.0, &format!("{} · {}{}", many(t.packets as i64, "packet"), pg::bytes(t.bytes as f64), t.wait.map(|w| format!(" · {:.1} ms", w * 1000.0)).unwrap_or_default()), 11.5, TEXT_SUBTLE());
                if resp.on_hover_text("Its packets").clicked() {
                    open = Some(*i);
                }
            }
            if l.len() > 150 {
                said(ui, &format!("and {} more: filter to see them", l.len() - 150), TEXT_PLACEHOLDER());
            }
        });
        if open.is_some() {
            st.talk = open;
        }
    }

    pub(super) fn packets_sub(&self) -> Option<usize> {
        self.netlab.packets.talk
    }
    pub(super) fn packets_close(&mut self) {
        self.netlab.packets.talk = None;
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A packet's bytes: Ethernet, IPv4, TCP or UDP, and what's in it.
    pub(in crate::app) fn tcp(a: [u8; 4], ap: u16, b: [u8; 4], bp: u16, seq: u32, fl: u8, body: &[u8]) -> Vec<u8> {
        let mut t: Vec<u8> = vec![];
        t.extend(ap.to_be_bytes());
        t.extend(bp.to_be_bytes());
        t.extend(seq.to_be_bytes());
        t.extend([0; 4]);
        t.extend([0x50, fl, 1, 0, 0, 0, 0, 0]);
        t.extend(body);
        ip(a, b, 6, &t)
    }
    fn udp(a: [u8; 4], ap: u16, b: [u8; 4], bp: u16, body: &[u8]) -> Vec<u8> {
        let mut t: Vec<u8> = vec![];
        t.extend(ap.to_be_bytes());
        t.extend(bp.to_be_bytes());
        t.extend((8 + body.len() as u16).to_be_bytes());
        t.extend([0, 0]);
        t.extend(body);
        ip(a, b, 17, &t)
    }
    fn ip(a: [u8; 4], b: [u8; 4], proto: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![0; 12];
        v.extend([8, 0, 0x45, 0]);
        v.extend((20 + body.len() as u16).to_be_bytes());
        v.extend([0, 1, 0x40, 0, 64, proto, 0, 0]);
        v.extend(a);
        v.extend(b);
        v.extend(body);
        v
    }
    /// A file: (seconds, bytes).
    fn pcap(l: &[(f64, Vec<u8>)]) -> Vec<u8> {
        let mut o = vec![];
        for v in [0xa1b2c3d4u32, 0x0004_0002, 0, 0, 65535, 1] {
            o.extend(v.to_le_bytes());
        }
        for (t, b) in l {
            for v in [*t as u32, (t.fract() * 1e6) as u32, b.len() as u32, b.len() as u32] {
                o.extend(v.to_le_bytes());
            }
            o.extend(b);
        }
        o
    }
    fn name(n: &str) -> Vec<u8> {
        let mut v = vec![];
        for p in n.split('.') {
            v.push(p.len() as u8);
            v.extend(p.as_bytes());
        }
        v.push(0);
        v
    }
    fn question(id: u16, n: &str) -> Vec<u8> {
        let mut v = id.to_be_bytes().to_vec();
        v.extend([1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        v.extend(name(n));
        v.extend([0, 1, 0, 1]);
        v
    }
    fn reply(id: u16, n: &str, code: u8, addr: Option<[u8; 4]>) -> Vec<u8> {
        let mut v = id.to_be_bytes().to_vec();
        v.extend([0x81, 0x80 | code, 0, 1, 0, addr.is_some() as u8, 0, 0, 0, 0]);
        v.extend(name(n));
        v.extend([0, 1, 0, 1]);
        if let Some(a) = addr {
            v.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
            v.extend(a);
        }
        v
    }
    fn hello(n: &str) -> Vec<u8> {
        let sni: Vec<u8> = {
            let mut s = vec![];
            s.extend((n.len() as u16 + 3).to_be_bytes());
            s.push(0);
            s.extend((n.len() as u16).to_be_bytes());
            s.extend(n.as_bytes());
            s
        };
        let mut h = vec![3, 3];
        h.extend([7; 32]);
        h.push(0);
        h.extend([0, 2, 0x13, 1, 1, 0]);
        let mut e = vec![0, 0];
        e.extend((sni.len() as u16).to_be_bytes());
        e.extend(sni);
        h.extend((e.len() as u16).to_be_bytes());
        h.extend(e);
        let mut v = vec![22, 3, 1];
        v.extend((h.len() as u16 + 4).to_be_bytes());
        v.extend([1, 0]);
        v.extend((h.len() as u16).to_be_bytes());
        v.extend(h);
        v
    }
    const A: [u8; 4] = [10, 128, 2, 5];
    const DB: [u8; 4] = [10, 128, 2, 6];
    const NS: [u8; 4] = [172, 30, 0, 10];

    fn sample() -> Vec<u8> {
        pcap(&[
            (1.0, udp(A, 40000, NS, 53, &question(1, "db.shop.svc.cluster.local"))),
            (1.001, udp(NS, 53, A, 40000, &reply(1, "db.shop.svc.cluster.local", 0, Some(DB)))),
            (1.002, udp(A, 40001, NS, 53, &question(2, "nope.example.com"))),
            (1.003, udp(NS, 53, A, 40001, &reply(2, "nope.example.com", 3, None))),
            (1.004, udp(A, 40002, NS, 53, &question(3, "slow.example.com"))),
            // Answered, talked over TLS, refused by the other's alert.
            (1.1, tcp(A, 50000, DB, 443, 100, SYN, &[])),
            (1.102, tcp(DB, 443, A, 50000, 900, SYN | ACK, &[])),
            (1.103, tcp(A, 50000, DB, 443, 101, ACK | 8, &hello("web.example.com"))),
            (1.104, tcp(DB, 443, A, 50000, 901, ACK | 8, &[21, 3, 3, 0, 2, 2, 48])),
            (1.105, tcp(DB, 443, A, 50000, 908, RST, &[])),
            // Nobody answers.
            (2.0, tcp(A, 50001, DB, 6379, 1, SYN, &[])),
            (3.0, tcp(A, 50001, DB, 6379, 1, SYN, &[])),
            // Refused.
            (2.5, tcp(A, 50002, DB, 81, 1, SYN, &[])),
            (2.501, tcp(DB, 81, A, 50002, 0, RST | ACK, &[])),
            // A web page that fails, with its query left out.
            (4.0, tcp(A, 50003, DB, 80, 1, SYN, &[])),
            (4.001, tcp(DB, 80, A, 50003, 1, SYN | ACK, &[])),
            (4.002, tcp(A, 50003, DB, 80, 2, ACK | 8, b"GET /login?token=sesame HTTP/1.1\r\nCookie: sesame\r\n\r\n")),
            (4.003, tcp(DB, 80, A, 50003, 2, ACK | 8, b"HTTP/1.1 503 sesame words\r\n\r\nsesame")),
            (5.0, ip([192, 0, 2, 1], A, 1, &[3, 4, 0, 0, 0, 0, 0x05, 0x14])),
        ])
    }

    #[test]
    fn reads_a_capture() {
        let c = read("x", &sample()).unwrap();
        assert_eq!((c.packets.len(), c.other, c.cut), (19, 0, false));
        let l = talks(&c);
        let state = |port: u16| l.iter().find(|t| t.b.1 == port).unwrap().state().1;
        assert_eq!(state(443), "TLS: unknown certificate authority");
        assert_eq!(state(6379), "no answer (2 times tried)");
        assert_eq!(state(81), "refused");
        assert_eq!(state(80), "HTTP/1.1 503");
        let t = l.iter().find(|t| t.b.1 == 443).unwrap();
        assert_eq!((t.name.as_str(), t.wait.map(|w| (w * 1000.0).round())), ("web.example.com", Some(2.0)));
        let f: Vec<String> = finds(&c, &l).into_iter().map(|f| f.1).collect();
        for want in ["10.128.2.6:6379: no answer, 1 connection", "10.128.2.6:81: refused, 1 connection", "1 name look-up without an answer", "1 name found nowhere", "TLS with web.example.com (10.128.2.6:443): unknown certificate authority", "192.0.2.1 says packets are too big: 1300 bytes fit"] {
            assert!(f.iter().any(|x| x == want), "{want}: {f:#?}");
        }
        // Nothing of what's in the packets is kept.
        let all = format!("{:?}{l:?}{f:?}", c.packets);
        assert!(!all.contains("sesame"), "{all}");
        assert!(all.contains("GET /login"));
        // Nor in a file cut to headers, which still reads.
        let cut = only_headers(&sample()).unwrap();
        assert!(!cut.windows(6).any(|w| w == b"sesame") && !cut.windows(3).any(|w| w == b"web"));
        let c2 = read("x", &cut).unwrap();
        assert_eq!(c2.packets.len(), 19);
        assert_eq!(c2.packets[16].data, c.packets[16].data);
        assert!((c2.packets[16].at - c.packets[16].at).abs() < 1e-5);
    }

    #[test]
    fn counts_what_is_sent_again() {
        let mut l = vec![(1.0, tcp(A, 5, DB, 80, 1, SYN, &[])), (1.1, tcp(DB, 80, A, 5, 1, SYN | ACK, &[]))];
        for (i, seq) in [2u32, 102, 202, 102, 102, 102, 302].iter().enumerate() {
            l.push((1.2 + i as f64 / 10.0, tcp(A, 5, DB, 80, *seq, ACK, &[9; 100])));
        }
        // A keep-alive isn't one.
        l.push((3.0, tcp(A, 5, DB, 80, 401, ACK, &[0])));
        let c = read("x", &pcap(&l)).unwrap();
        let t = talks(&c);
        assert_eq!((t.len(), t[0].again), (1, 3));
        assert_eq!(t[0].state(), (Tone::Warning, "3 packets sent again".into()));
        // Seen twice at once, on two network cards: one packet.
        let c = read("x", &pcap(&[(1.0, tcp(A, 5, DB, 80, 1, ACK, &[9; 100])), (1.0005, tcp(A, 5, DB, 80, 1, ACK, &[9; 100])), (1.3, tcp(A, 5, DB, 80, 1, ACK, &[9; 100]))])).unwrap();
        assert_eq!((talks(&c)[0].packets, talks(&c)[0].again), (2, 1));
        // Numbers that go round.
        let far = u32::MAX - 49;
        let c = read("x", &pcap(&[(1.0, tcp(A, 5, DB, 80, far, ACK, &[9; 100])), (1.1, tcp(A, 5, DB, 80, 50, ACK, &[9; 100]))])).unwrap();
        assert_eq!(talks(&c)[0].again, 0);
    }

    #[test]
    fn other_files_and_links() {
        assert!(read("x", b"hello world, not a capture").is_err());
        assert!(read("x", &[0x1f, 0x8b, 8, 0, 0]).unwrap_err().contains("gzip"));
        assert!(read("x", b"").is_err());
        // Cut off in the middle.
        let s = sample();
        let c = read("x", &s[..s.len() - 5]).unwrap();
        assert_eq!((c.packets.len(), c.notes.len()), (18, 1));
        // pcapng: a section, an interface with nanoseconds, a packet.
        let p = tcp(A, 5, DB, 80, 1, SYN, &[]);
        let block = |kind: u32, body: Vec<u8>| {
            let mut b = body;
            while b.len() % 4 != 0 {
                b.push(0);
            }
            let n = (b.len() + 12) as u32;
            [kind.to_le_bytes().to_vec(), n.to_le_bytes().to_vec(), b, n.to_le_bytes().to_vec()].concat()
        };
        let mut f = block(0x0a0d0d0a, [0x1a2b3c4du32.to_le_bytes().to_vec(), vec![1, 0, 0, 0], vec![255; 8]].concat());
        f.extend(block(1, [vec![1, 0, 0, 0], 65535u32.to_le_bytes().to_vec(), vec![9, 0, 1, 0, 9, 0, 0, 0], vec![0; 4]].concat()));
        let ts: u64 = 1_700_000_000_500_000_000;
        f.extend(block(6, [0u32.to_le_bytes().to_vec(), ((ts >> 32) as u32).to_le_bytes().to_vec(), (ts as u32).to_le_bytes().to_vec(), (p.len() as u32).to_le_bytes().to_vec(), (p.len() as u32).to_le_bytes().to_vec(), p.clone()].concat()));
        let c = read("x", &f).unwrap();
        assert_eq!((c.packets.len(), c.packets[0].dport, c.packets[0].at.round()), (1, 80, 1_700_000_001.0));
        // Cooked Linux links, raw IP and VLAN tags.
        let raw = &p[14..];
        assert_eq!(decode(0.0, 101, raw, 40).unwrap().dport, 80);
        assert_eq!(decode(0.0, 113, &[vec![0; 14], vec![8, 0], raw.to_vec()].concat(), 40).unwrap().dport, 80);
        assert_eq!(decode(0.0, 276, &[vec![8, 0], vec![0; 18], raw.to_vec()].concat(), 40).unwrap().dport, 80);
        assert_eq!(decode(0.0, 1, &[vec![0; 12], vec![0x81, 0, 0, 7, 8, 0], raw.to_vec()].concat(), 40).unwrap().dport, 80);
        assert!(decode(0.0, 1, &[vec![0; 12], vec![8, 6], vec![0; 28]].concat(), 42).is_none());
        assert!(decode(0.0, 999, raw, 40).is_none());
    }

    #[test]
    fn nothing_makes_it_fail() {
        // Every packet of the sample cut everywhere, with every byte turned over.
        let s = sample();
        let mut o = 24;
        while o < s.len() {
            let n = u32::from_le_bytes(s[o + 8..o + 12].try_into().unwrap()) as usize;
            let p = &s[o + 16..o + 16 + n];
            for cut in 0..=p.len() {
                let _ = decode(0.0, 1, &p[..cut], n as u32);
            }
            for i in 0..p.len() {
                for x in [0u8, 0x3f, 0x7f, 0xc0, 0xff] {
                    let mut q = p.to_vec();
                    q[i] = x;
                    let _ = decode(0.0, 1, &q, n as u32);
                    let _ = headers_end(&q, 14);
                }
            }
            o += 16 + n;
        }
        // Whole files of nonsense, by a small generator.
        let mut x = 12345u32;
        for kind in [0xa1b2c3d4u32, 0xd4c3b2a1, 0x0a0d0d0a] {
            for _ in 0..400 {
                let mut f = kind.to_le_bytes().to_vec();
                for _ in 0..200 {
                    x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                    f.push((x >> 24) as u8 & if x & 0x10 == 0 { 0x0f } else { 0xff });
                }
                if let Ok(c) = read("x", &f) {
                    finds(&c, &talks(&c));
                }
                let _ = only_headers(&f);
            }
        }
        // A name that points to itself.
        let mut d = question(1, "a");
        d[12] = 0xc0;
        d[13] = 12;
        assert!(dns(&d).is_none());
    }

    #[test]
    fn filters() {
        assert_eq!(filter("tcp", "443", "192.0.2.1").unwrap(), "tcp and port 443 and host 192.0.2.1");
        assert_eq!(filter("", "53", "").unwrap(), "port 53");
        assert_eq!(filter("icmp", "", "").unwrap(), "icmp");
        for (p, n, h) in [("", "", ""), ("tcp", "", ""), ("", "0", ""), ("", "x", ""), ("", "1", "web.example.com"), ("", "", "192.0.2.1 or port 22"), ("ip", "1", "")] {
            assert!(filter(p, n, h).is_err(), "{p} {n} {h}");
        }
        let g = Grab { ctx: "c".into(), node: "n".into(), uid: "u".into(), label: String::new(), filter: "port 1; rm".into(), secs: 15, count: 9, contents: false, image: "i".into(), ns: "d".into(), control: false };
        let c = g.command();
        assert_eq!(&c[3..], &["grab".to_string(), "u".into(), "15".into(), "9".into(), "512".into(), "port 1; rm".into()]);
        assert_eq!(Grab { contents: true, ..g }.command()[7], "0");
        let s = sample();
        let (f, said) = unpack(&format!("KD pcap\n{}\nKD said\n3 packets captured\n0 packets dropped by kernel\nKD done\n", b64_encode(&s))).unwrap();
        assert!(f == s && said.starts_with("3 packets"));
        assert!(unpack("KD pcap\n\nKD said\ntcpdump: syntax error\nKD done").unwrap_err().contains("syntax error"));
        assert!(unpack("KD none").unwrap_err().contains("wasn't found"));
    }

    /// In the throwaway cluster only: KUBEDOG_GRAB is "node uid filter".
    #[test]
    #[ignore]
    fn grabs_in_kind() {
        let k = nethelp::tests::kind();
        let w = std::env::var("KUBEDOG_GRAB").unwrap();
        let w: Vec<&str> = w.splitn(3, ' ').collect();
        let g = Grab { ctx: "kind-kubedog-netlab".into(), node: w[0].into(), uid: w[1].trim_matches('-').into(), label: "x".into(), filter: w[2].into(), secs: 12, count: 2000, contents: false, image: std::env::var("KUBEDOG_IMAGE").unwrap_or("nicolaka/netshoot:v0.13".into()), ns: "default".into(), control: true };
        match grab(&k, &g) {
            Ok((o, b)) => {
                println!("{} packets, {} other, {:?}", o.cap.packets.len(), o.cap.other, o.cap.notes);
                o.finds.iter().for_each(|f| println!("FIND {f:?}"));
                o.talks.iter().take(12).for_each(|t| println!("TALK {:?} {:?} {:?} {} {:?}", t.a, t.b, t.state(), t.name, t.web));
                println!("kept {} bytes, reads {}", b.len(), read("x", &b).unwrap().packets.len());
            }
            Err(e) => println!("FAILED {e}"),
        }
    }

    /// Writes the sample for pictures: KUBEDOG_WRITE_PCAP=path.
    #[test]
    #[ignore]
    fn writes_sample() {
        if let Ok(p) = std::env::var("KUBEDOG_WRITE_PCAP") {
            std::fs::write(p, sample()).unwrap();
        }
    }
}
