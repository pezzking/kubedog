//! Errors in logs: the logs of several apps read at once, the same errors put together, those that
//! are new since the last rollout marked. Read only after a click; kept in memory.

use super::face::many;
use super::incident::chip_button;
use super::ops::{ago, ns_of, table, Item};
use super::pg::panel;
use super::podxray::Go;
use super::work::{name_of, said};
use super::*;

#[derive(Default)]
pub(super) struct Hunt {
    pub picked: HashSet<String>,
    pub back: String,
    pub warn: bool,
    pub key: Option<String>,
    /// The clusters that were searched.
    pub ctxs: Vec<String>,
    n: u64,
}

/// The same error with different numbers, ids and times is one: what varies is taken out.
pub(super) fn shape(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    for w in line.split_whitespace().take(60) {
        let core = w.trim_matches(|c: char| !c.is_alphanumeric());
        let digits = core.bytes().filter(|b| b.is_ascii_digit()).count();
        let hex = core.len() >= 8 && core.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') && digits > 0;
        let word = if hex || (digits > 0 && digits * 2 >= core.len()) {
            "#".to_string()
        } else if digits > 0 {
            // Numbers within a word.
            let mut t = String::new();
            let mut was = false;
            for c in w.chars() {
                if c.is_ascii_digit() {
                    if !was {
                        t.push('#');
                    }
                    was = true;
                } else {
                    was = false;
                    t.push(c);
                }
            }
            t
        } else {
            w.to_string()
        };
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&word);
    }
    truncate(&out, 400)
}

#[derive(Debug, PartialEq, Clone)]
pub(super) struct Group {
    pub shape: String,
    pub level: Level,
    pub count: usize,
    pub first: i64,
    pub last: i64,
    pub pods: Vec<String>,
    pub sample: String,
    /// Not there before the app's last rollout.
    pub new: bool,
}

/// One pod's log: (app, pod, when its app was last rolled out, text of `kubectl logs --timestamps`).
pub(super) fn group(logs: &[(String, String, i64, String)], warn: bool) -> Vec<Group> {
    let mut m: HashMap<String, Group> = HashMap::new();
    for (app, pod_name, rolled, text) in logs {
        for raw in text.lines() {
            let line = logparse::strip_ansi(raw);
            let (pre, body) = logparse::split_prefixes(&line);
            let level = logparse::level_of(body);
            if !(matches!(level, Level::Error | Level::Fatal) || (warn && level == Level::Warn)) {
                continue;
            }
            let at = pre.split_whitespace().chain(body.split_whitespace().take(1)).find_map(kube::parse_time).unwrap_or(0);
            let body = if pre.is_empty() && kube::parse_time(body.split_whitespace().next().unwrap_or("")).is_some() { body.split_once(' ').map(|x| x.1).unwrap_or(body) } else { body };
            let key = format!("{app}|{}", shape(body));
            let g = m.entry(key).or_insert_with(|| Group { shape: shape(body), level, count: 0, first: at, last: at, pods: vec![], sample: truncate(body, 2000), new: false });
            g.count += 1;
            if at > 0 {
                g.first = if g.first == 0 { at } else { g.first.min(at) };
                g.last = g.last.max(at);
            }
            let who = format!("{app}: {pod_name}");
            if !g.pods.contains(&who) {
                g.pods.push(who);
            }
            g.new = *rolled > 0 && g.first >= *rolled;
        }
    }
    let mut v: Vec<Group> = m.into_values().collect();
    v.sort_by(|a, b| b.new.cmp(&a.new).then(b.count.cmp(&a.count)).then(a.shape.cmp(&b.shape)));
    v.truncate(300);
    v
}

impl KubedogApp {
    pub(super) fn log_hunt(&mut self, ui: &mut Ui) -> Option<Go> {
        if self.incident.hunt.back.is_empty() {
            self.incident.hunt.back = "1h".into();
        }
        // Apps to choose from.
        let mut apps: Vec<Selected> = vec![];
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            for k in [Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets] {
                for o in self.refs(c, k, "").unwrap_or_default().into_iter().filter(|o| self.ns_ok(ns_of(o))) {
                    apps.push(Selected { ctx: c.clone(), kind: k, ns: ns_of(o).into(), name: name_of(o).into() });
                }
            }
        }
        let q = self.search.to_lowercase();
        let total = apps.len();
        let shown: Vec<&Selected> = apps.iter().filter(|s| self.incident.hunt.picked.contains(&s.key()) || q.is_empty() || format!("{}/{}", s.ns, s.name).to_lowercase().contains(&q)).take(60).collect();
        let mut start = false;
        let mut flip: Option<String> = None;
        card(ui, |ui| {
            panel(ui, "Whose logs", "pick apps; narrow them with the namespace and the filter above");
            ui.horizontal_wrapped(|ui| {
                for s in &shown {
                    let on = self.incident.hunt.picked.contains(&s.key());
                    if chip_button(ui, &format!("{}/{}", s.ns, s.name), on) {
                        flip = Some(s.key());
                    }
                }
                if total > shown.len() {
                    ui.label(RichText::new(format!("and {} more", total - shown.len())).size(z(12.0)).color(TEXT_PLACEHOLDER()));
                }
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                for t in ["15m", "1h", "6h", "24h"] {
                    if chip_button(ui, &format!("last {t}"), self.incident.hunt.back == t) {
                        self.incident.hunt.back = t.into();
                    }
                }
                ui.checkbox(&mut self.incident.hunt.warn, "Warnings too");
                let n = self.incident.hunt.picked.len();
                if ui.add_enabled(n > 0, egui::Button::new(RichText::new(if n == 0 { "Pick at least one".to_string() } else { format!("Search the logs of {}", many(n as i64, "app")) }).color(Color32::WHITE)).fill(PRIMARY())).clicked() {
                    start = true;
                }
                if n > 0 && button(ui, "Pick none", false, false) {
                    self.incident.hunt.picked.clear();
                }
            });
        });
        if let Some(k) = flip {
            if !self.incident.hunt.picked.remove(&k) {
                self.incident.hunt.picked.insert(k);
            }
        }
        // (Never in screenshot mode.)
        if start && self.screenshot.is_none() {
            let chosen: Vec<Selected> = apps.into_iter().filter(|s| self.incident.hunt.picked.contains(&s.key())).collect();
            self.start_hunt(&chosen);
        }
        ui.add_space(12.0);
        let now = kube::now_secs();
        let key = self.incident.hunt.key.clone()?;
        match self.powers.answers.get(&key) {
            Some(None) => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    said(ui, "Reading logs…", TEXT_SUBTLE());
                });
            }
            Some(Some(Err(e))) => said(ui, e, WARNING()),
            Some(Some(Ok(v))) => {
                let mut items: Vec<Item> = v["groups"].as_array().into_iter().flatten().map(|g| {
                    let new = g["new"] == true;
                    let pods: Vec<&str> = g["pods"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).collect();
                    Item::new(if g["fatal"] == true || new { Tone::Danger } else { Tone::Warning }, vec![
                        ops::text(&g["shape"]),
                        if new { "new since the rollout".into() } else { "seen before".into() },
                        format!("×{}", g["count"]),
                        some_names(&pods.iter().map(|p| p.split(": ").next().unwrap_or(p).to_string()).collect::<std::collections::BTreeSet<_>>().into_iter().collect::<Vec<_>>()),
                        ago(now, g["first"].as_i64().filter(|t| *t > 0)),
                        ago(now, g["last"].as_i64().filter(|t| *t > 0)),
                    ])
                    .tip(format!("{}\n\n{}", ops::text(&g["sample"]), pods.join("\n")))
                }).collect();
                items = self.op_filter(items);
                let errs = v["problems"].as_array().map(|a| a.len()).unwrap_or(0);
                said(ui, &format!("{} read, {}{}.", many(v["pods"].as_i64().unwrap_or(0), "pod"), many(v["lines"].as_i64().unwrap_or(0), "line"), if errs > 0 { format!("; {} couldn't be read", many(errs as i64, "pod")) } else { String::new() }), TEXT_SUBTLE());
                if !items.is_empty() && self.ai_button(ui) {
                    if let Some(f) = self.hunt_facts() {
                        self.ai_explain(f);
                    }
                }
                ui.add_space(6.0);
                return table(ui, &format!("Kinds of errors ({})", items.len()), "numbers and ids are shown as #; hover for a whole line and where", &[("Error", 0.56), ("", 0.13), ("Times", 0.06), ("App", 0.11), ("First", 0.07), ("Last", 0.07)], &items, 200, "No errors: a quiet time.");
            }
            None => {}
        }
        None
    }

    fn start_hunt(&mut self, apps: &[Selected]) {
        let mut todo: Vec<(String, String, String, String, i64)> = vec![];
        for s in apps {
            let Some(o) = self.object_of(s) else { continue };
            let pods = self.pods_of(s, &o).unwrap_or_default();
            // When its newest version came.
            let rolled = match s.kind {
                Kind::Deployments => self.refs(&s.ctx, Kind::ReplicaSets, &s.ns).unwrap_or_default().into_iter().filter(|r| r["metadata"]["ownerReferences"][0]["name"].as_str() == Some(&s.name) && r["spec"]["replicas"].as_i64().unwrap_or(0) > 0).filter_map(|r| pod::time_of(&r["metadata"]["creationTimestamp"])).max().unwrap_or(0),
                _ => pods.iter().filter_map(|p| pod::time_of(&p["metadata"]["creationTimestamp"])).min().unwrap_or(0),
            };
            for p in pods.into_iter().filter(|p| p["status"]["phase"] != "Pending").take(6) {
                todo.push((s.ctx.clone(), s.ns.clone(), s.name.clone(), name_of(p).to_string(), rolled));
            }
        }
        todo.truncate(40);
        self.incident.hunt.ctxs = todo.iter().map(|t| t.0.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        self.incident.hunt.n += 1;
        let key = format!("hunt|{}", self.incident.hunt.n);
        if let Some(old) = self.incident.hunt.key.replace(key.clone()) {
            self.powers.answers.remove(&old);
        }
        let (back, warn) = (kubectl_since(&self.incident.hunt.back), self.incident.hunt.warn);
        self.ask(&key, 0, true, move |k| {
            let mut logs = vec![];
            let mut problems = vec![];
            let mut lines = 0;
            for (ctx, ns, app, pod, rolled) in &todo {
                match k.run(&log_args(ctx, ns, pod, &back)) {
                    Ok(t) => {
                        lines += t.lines().count();
                        logs.push((app.clone(), pod.clone(), *rolled, t));
                    }
                    Err(e) => problems.push(format!("{pod}: {}", truncate(&e, 160))),
                }
            }
            let g: Vec<Value> = group(&logs, warn).iter().map(|g| serde_json::json!({"shape": g.shape, "fatal": g.level == Level::Fatal, "count": g.count, "first": g.first, "last": g.last, "pods": g.pods, "sample": g.sample, "new": g.new})).collect();
            Ok(serde_json::json!({"groups": g, "pods": logs.len(), "lines": lines, "problems": problems}).to_string())
        });
    }
}

fn log_args(ctx: &str, ns: &str, pod: &str, back: &str) -> Vec<String> {
    ["--context", ctx, "-n", ns, "logs", pod, "--all-containers", "--timestamps", "--tail=4000", "--limit-bytes=3000000", &format!("--since={back}"), &format!("--request-timeout={}", kube::REQUEST_TIMEOUT)].iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_error() {
        assert_eq!(shape("ERROR order 1234 failed after 30s for user 8f14e45f-ceea-467f"), shape("ERROR order 99 failed after 2s for user 11111111-aaaa-bbbb"));
        assert_ne!(shape("ERROR a"), shape("ERROR b"));
        assert_eq!(shape("host store12 gone"), "host store# gone");
    }

    #[test]
    fn groups() {
        let log = |lines: &[&str]| lines.join("\n");
        let g = group(
            &[
                ("web".into(), "web-1".into(), 0, log(&["2026-01-02T00:00:00Z ERROR order 1 failed", "2026-01-02T00:05:00Z ERROR order 2 failed", "2026-01-02T00:06:00Z INFO fine", "2026-01-02T00:07:00Z WARN slow"])),
                ("web".into(), "web-2".into(), kube::parse_time("2026-01-01T00:00:00Z").unwrap(), log(&["2026-01-02T00:01:00Z ERROR order 3 failed"])),
            ],
            false,
        );
        assert_eq!(g.len(), 1);
        assert_eq!((g[0].count, g[0].pods.len()), (3, 2));
        assert_eq!(g[0].last - g[0].first, 300);
        assert!(g[0].new);
        assert!(log_args("c", "n", "p", "1h").join(" ").contains("logs p --all-containers --timestamps"));
    }
}
