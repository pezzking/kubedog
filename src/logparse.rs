//! How serious a log line is. Rather than knowing every logger's layout, this reads a line the way
//! a person does: a JSON field or `level=` first, then the marks at the start of the line, and
//! then a level word among the first few words, where loggers put it.

use serde_json::Value;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
    Other,
}

impl Level {
    pub const ALL: [Level; 7] = [Level::Fatal, Level::Error, Level::Warn, Level::Info, Level::Debug, Level::Trace, Level::Other];

    pub fn label(self) -> &'static str {
        match self {
            Level::Trace => "Trace",
            Level::Debug => "Debug",
            Level::Info => "Info",
            Level::Warn => "Warning",
            Level::Error => "Error",
            Level::Fatal => "Fatal",
            Level::Other => "Other",
        }
    }

    /// The level a word names, in any case.
    fn named(word: &str) -> Option<Level> {
        let w = word.to_ascii_lowercase();
        Some(match w.as_str() {
            "trace" | "trc" | "verbose" | "finest" | "silly" => Level::Trace,
            "debug" | "dbg" | "fine" => Level::Debug,
            "info" | "inf" | "information" | "notice" | "log" => Level::Info,
            "warn" | "wrn" | "warning" => Level::Warn,
            "error" | "err" | "eror" | "failure" => Level::Error,
            "fatal" | "ftl" | "panic" | "critical" | "crit" | "severe" | "alert" | "emerg" | "emergency" => Level::Fatal,
            _ => return None,
        })
    }

    /// Syslog's severity is what's left of the priority after taking out the facility.
    fn from_priority(p: u32) -> Level {
        [Level::Fatal, Level::Fatal, Level::Fatal, Level::Error, Level::Warn, Level::Info, Level::Info, Level::Debug][(p & 7) as usize]
    }

    /// Numbers as Node loggers write them, in tens.
    fn from_tens(n: i64) -> Level {
        match n / 10 {
            i64::MIN..=1 => Level::Trace,
            2 => Level::Debug,
            3 => Level::Info,
            4 => Level::Warn,
            5 => Level::Error,
            _ => Level::Fatal,
        }
    }
}

/// The text without terminal codes (colours, cursor moves, window titles).
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match it.next() {
            // A control sequence ends at its letter.
            Some('[') => {
                for c in it.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            // A title ends at a bell, or at an escape and a backslash.
            Some(']') => {
                while let Some(c) = it.next() {
                    if c == '\u{7}' {
                        break;
                    }
                    if c == '\u{1b}' {
                        it.next_if_eq(&'\\');
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Whether a word is a moment like 2024-01-02T15:04:05.1Z.
fn is_moment(w: &str) -> bool {
    let b = w.as_bytes();
    b.len() >= 20 && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-' && b[7] == b'-' && b[10] == b'T' && b[13] == b':' && b[16] == b':'
}

/// Split off what kubectl adds in front ("[pod/name/container]" and the time).
pub fn split_prefixes(line: &str) -> (&str, &str) {
    let mut rest = line;
    if rest.starts_with("[pod/") {
        if let Some((_, after)) = rest.split_once("] ") {
            rest = after;
        }
    }
    if let Some((first, after)) = rest.split_once(' ') {
        if is_moment(first) {
            rest = after;
        }
    }
    line.split_at(line.len() - rest.len())
}

/// Names loggers give the field.
fn is_level_field(k: &str) -> bool {
    let k = k.trim_start_matches('@').to_ascii_lowercase().replace(['_', '-', '.'], "");
    matches!(k.as_str(), "level" | "lvl" | "l" | "severity" | "severitytext" | "loglevel" | "levelname")
}

fn from_json(v: &Value) -> Option<Level> {
    let o = v.as_object()?;
    let value = |v: &Value| match v {
        Value::String(s) => Level::named(s.trim()),
        Value::Number(n) => n.as_i64().map(Level::from_tens),
        _ => None,
    };
    o.iter()
        .filter(|(k, _)| is_level_field(k))
        .find_map(|(_, v)| value(v))
        // One level down: {"log": {"level": ...}}.
        .or_else(|| o.get("log").and_then(|l| l.as_object()).and_then(|l| l.iter().filter(|(k, _)| is_level_field(k)).find_map(|(_, v)| value(v))))
}

/// `level=warn`, `severity="error"` anywhere in the line.
fn from_pairs(t: &str) -> Option<Level> {
    t.split_whitespace().find_map(|w| {
        let (k, v) = w.split_once('=')?;
        if is_level_field(k) { Level::named(v.trim_matches(|c| c == '"' || c == '\'' || c == ',')) } else { None }
    })
}

/// Kubernetes' own programs: a letter, the month and day, then the time ("E0102 15:04:05...").
fn from_klog(t: &str) -> Option<Level> {
    let (head, after) = t.split_once(' ')?;
    let b = head.as_bytes();
    if b.len() != 5 || !b[1..].iter().all(u8::is_ascii_digit) || !after.trim_start().starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    match b[0] {
        b'I' => Some(Level::Info),
        b'W' => Some(Level::Warn),
        b'E' => Some(Level::Error),
        b'F' => Some(Level::Fatal),
        _ => None,
    }
}

/// A level among the first words. It counts when it's in capitals, in brackets, or followed by a
/// colon or a dash at the start, so "no error found" stays what it is.
fn from_words(t: &str) -> Option<Level> {
    for (i, w) in t.split_whitespace().take(7).enumerate() {
        let mark = |c: char| !c.is_alphanumeric();
        let bare = w.trim_matches(mark);
        // "main|WARN|text" holds several.
        for part in bare.split('|') {
            let Some(l) = Level::named(part) else { continue };
            let capitals = part.chars().all(|c| c.is_ascii_uppercase()) && part != "LOG";
            let bracketed = w.starts_with(['[', '(', '<']) && w.ends_with([']', ')', '>', ':']);
            let opening = i == 0 && w.ends_with([':', '-']) || i == 0 && t[w.len().min(t.len())..].trim_start().starts_with("- ");
            if capitals || bracketed || opening {
                return Some(l);
            }
        }
    }
    None
}

/// The level of one log line (the part after kubectl's prefixes).
pub fn level_of(body: &str) -> Level {
    let t = body.trim();
    if t.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(t) {
            return from_json(&v).unwrap_or(Level::Other);
        }
    }
    if let Some(n) = t.strip_prefix('<').and_then(|r| r.split_once('>')).and_then(|x| x.0.parse::<u32>().ok()).filter(|n| *n < 192) {
        return Level::from_priority(n);
    }
    from_klog(t).or_else(|| from_pairs(t)).or_else(|| from_words(t)).unwrap_or(Level::Other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels() {
        for (line, want) in [
            (r#"{"level":"warn","msg":"x"}"#, Level::Warn),
            (r#"{"log.level":"error"}"#, Level::Error),
            (r#"{"log":{"level":"debug"}}"#, Level::Debug),
            (r#"{"severity":"INFO","level_detail":"error"}"#, Level::Info),
            (r#"{"level":50,"msg":"x"}"#, Level::Error),
            (r#"{"msg":"ERROR in text"}"#, Level::Other),
            ("E0102 15:04:05.123456    1234 main.go:42] boom", Level::Error),
            ("2024-01-02 15:04:05,123 - app - WARNING - careful", Level::Warn),
            ("2024-01-02 15:04:05.123  INFO 1 --- [main] c.e.App : started", Level::Info),
            ("[2024-01-02 15:04:05 +0000] [7] [ERROR] worker died", Level::Error),
            ("E, [2024-01-02T15:04:05.1 #12] ERROR -- : no", Level::Error),
            ("<11>1 2024-01-02T15:04:05Z host app 1 - - failed", Level::Error),
            (r#"time=2024 level=debug msg="x""#, Level::Debug),
            (r#"ts=1 severity="error" ERR"#, Level::Error),
            ("[error] something broke", Level::Error),
            ("WARN: low disk", Level::Warn),
            ("warning: low disk", Level::Warn),
            ("12:00:01|main|FATAL|gone", Level::Fatal),
            ("just text", Level::Other),
            ("no error found", Level::Other),
            ("the cache had an error: none", Level::Other),
            ("one two three four five six seven ERROR", Level::Other),
            ("", Level::Other),
        ] {
            assert_eq!(level_of(line), want, "{line}");
        }
    }

    #[test]
    fn prefixes_and_codes() {
        let (head, body) = split_prefixes("[pod/a/b] 2024-01-02T15:04:05.1Z ERROR x");
        assert_eq!((head, body), ("[pod/a/b] 2024-01-02T15:04:05.1Z ", "ERROR x"));
        assert_eq!(split_prefixes("2024-01-02T15:04:05Z hé").1, "hé");
        assert_eq!(split_prefixes("plain text"), ("", "plain text"));
        assert_eq!(strip_ansi("\u{1b}[31;1mred\u{1b}[0m \u{1b}]0;title\u{7}ok\u{1b}[2K"), "red ok");
        assert_eq!(strip_ansi("cut \u{1b}["), "cut ");
    }
}
