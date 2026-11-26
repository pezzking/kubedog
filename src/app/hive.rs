//! The Pod Hive: every pod is a cell of a honeycomb, filled as far as it uses what it may use.
//! Built only from what an account with a few namespaces can read: pods, their usage, events and
//! quotas. Also: the nodes seen from the pods on them, which workloads are sized badly, and what
//! the account may do.

use super::dash::{at, at_end, bar, grid, line, nothing, pair, section, tile};
use super::pg::{label_at, spark};
use super::*;

#[derive(Default)]
pub(super) struct Hive {
    /// What fills the cells: memory (the default) or CPU.
    cpu: bool,
    group: Group,
    /// Only the pods on this node.
    pub node: Option<String>,
    /// "rights|context|namespace" -> the rules found, or why not (None while asking).
    rights: HashMap<String, Option<Result<Vec<Rule>, String>>>,
}

#[derive(Default, Clone, Copy, PartialEq)]
enum Group {
    Workload,
    #[default]
    Namespace,
    Node,
}

/// One running (or waiting) pod.
#[derive(Clone, Debug, Default)]
struct Cell6 {
    ctx: String,
    ns: String,
    name: String,
    node: String,
    owner: String,
    status: String,
    /// Not running as it should.
    bad: bool,
    cpu: Option<f64>,
    mem: Option<f64>,
    /// Highest reading so far.
    peak: (f64, f64),
    /// Requested and limit (cpu m, memory B); 0 = none.
    ask: (f64, f64),
    limit: (f64, f64),
    restarts: f64,
    /// Seconds since the last restart, and why.
    last: Option<f64>,
    why: String,
}

impl Cell6 {
    /// How full it is: of its limit, else of what it asks for. None when neither is set.
    fn fill(&self, cpu: bool) -> Option<f64> {
        let (v, ask, lim) = if cpu { (self.cpu?, self.ask.0, self.limit.0) } else { (self.mem?, self.ask.1, self.limit.1) };
        let of = if lim > 0.0 { lim } else { ask };
        (of > 0.0).then(|| v / of)
    }
    /// Its colour: up to red near a limit. Above what's only asked for is allowed, so no more than amber.
    fn colour(&self, cpu: bool) -> Option<Color32> {
        let limited = if cpu { self.limit.0 } else { self.limit.1 } > 0.0;
        self.fill(cpu).map(|f| heat(if limited { f } else { f.min(0.6) }))
    }
    fn troubled(&self) -> bool {
        self.bad || self.last.map(|s| s < 3600.0).unwrap_or(false)
    }
}

/// What a pod asks for and may use: (cpu ask, memory ask, cpu limit, memory limit). A limit only
/// counts when every container has one, since the others may use any amount.
fn bounds(o: &Value) -> [f64; 4] {
    let main = o["spec"]["containers"].as_array().into_iter().flatten();
    // Sidecars run along with the rest.
    let side = o["spec"]["initContainers"].as_array().into_iter().flatten().filter(|c| c["restartPolicy"] == "Always");
    let (mut out, mut all) = ([0.0; 4], [true; 2]);
    for c in main.chain(side) {
        let r = &c["resources"];
        let get = |a: &str, k: &str| r[a][k].as_str().unwrap_or("").to_string();
        let (lc, lm) = (resources::cpu_milli(&get("limits", "cpu")), resources::mem_bytes(&get("limits", "memory")));
        // Without a request, Kubernetes takes the limit.
        let or = |v: f64, l: f64| if v > 0.0 { v } else { l };
        out[0] += or(resources::cpu_milli(&get("requests", "cpu")), lc);
        out[1] += or(resources::mem_bytes(&get("requests", "memory")), lm);
        out[2] += lc;
        out[3] += lm;
        all[0] &= lc > 0.0;
        all[1] &= lm > 0.0;
    }
    if !all[0] {
        out[2] = 0.0;
    }
    if !all[1] {
        out[3] = 0.0;
    }
    out
}

/// A workload's pods together.
#[derive(Clone, Debug, Default)]
struct Sized {
    ctx: String,
    ns: String,
    name: String,
    pod: String,
    pods: usize,
    /// The busiest pod.
    peak: (f64, f64),
    ask: (f64, f64),
    limit: (f64, f64),
    killed: bool,
}

fn by_workload(cells: &[Cell6]) -> Vec<Sized> {
    let mut out: Vec<Sized> = vec![];
    let mut seen: HashMap<(&str, &str, &str), usize> = HashMap::new();
    for c in cells.iter().filter(|c| c.mem.is_some()) {
        let i = *seen.entry((&c.ctx, &c.ns, &c.owner)).or_insert_with(|| {
            out.push(Sized { ctx: c.ctx.clone(), ns: c.ns.clone(), name: c.owner.clone(), pod: c.name.clone(), ask: c.ask, limit: c.limit, ..Default::default() });
            out.len() - 1
        });
        let s = &mut out[i];
        s.pods += 1;
        if c.peak.1 > s.peak.1 {
            s.pod = c.name.clone();
        }
        s.peak = (s.peak.0.max(c.peak.0), s.peak.1.max(c.peak.1));
        s.ask = (s.ask.0.max(c.ask.0), s.ask.1.max(c.ask.1));
        s.limit = (s.limit.0.max(c.limit.0), s.limit.1.max(c.limit.1));
        s.killed |= c.why.contains("OOMKilled") && c.last.map(|s| s < 86400.0).unwrap_or(false);
    }
    out
}

/// Close to a limit: (how bad, what, share), worst first.
fn edges(list: &[Sized]) -> Vec<(&Sized, Tone, &'static str, f64)> {
    let mut out = vec![];
    for s in list {
        let (cf, mf) = (if s.limit.0 > 0.0 { s.peak.0 / s.limit.0 } else { 0.0 }, if s.limit.1 > 0.0 { s.peak.1 / s.limit.1 } else { 0.0 });
        if s.killed {
            out.push((s, Tone::Danger, "ran out of memory within a day", mf.max(1.0)));
        } else if mf >= 0.8 {
            out.push((s, if mf >= 0.9 { Tone::Danger } else { Tone::Warning }, "of its memory limit", mf));
        }
        if cf >= 0.85 {
            out.push((s, Tone::Warning, "of its CPU limit", cf));
        }
    }
    out.sort_by(|a, b| (a.1 != Tone::Danger).cmp(&(b.1 != Tone::Danger)).then(b.3.partial_cmp(&a.3).unwrap_or(std::cmp::Ordering::Equal)));
    out
}

/// Asks for far more than it has used: (workload, cpu m to spare, memory B to spare), most first.
fn roomy(list: &[Sized]) -> Vec<(&Sized, f64, f64)> {
    let mut out: Vec<(&Sized, f64, f64)> = list
        .iter()
        .filter_map(|s| {
            let spare = |ask: f64, peak: f64, least: f64| if ask >= least && peak < ask * 0.4 { (ask - peak * 1.5).max(0.0) * s.pods as f64 } else { 0.0 };
            let (c, m) = (spare(s.ask.0, s.peak.0, 100.0), spare(s.ask.1, s.peak.1, 256.0 * 1048576.0));
            (c > 0.0 || m > 0.0).then_some((s, c, m))
        })
        .collect();
    // A core weighs about as much as 4 GiB.
    let weight = |x: &(&Sized, f64, f64)| x.1 / 1000.0 + x.2 / (4.0 * 1073741824.0);
    out.sort_by(|a, b| weight(b).partial_cmp(&weight(a)).unwrap_or(std::cmp::Ordering::Equal));
    out
}

// ---------- rights ----------

#[derive(Clone, Debug, PartialEq)]
struct Rule {
    resource: String,
    named: bool,
    verbs: Vec<String>,
}

/// The table of `kubectl auth can-i --list`.
fn parse_rules(text: &str) -> Vec<Rule> {
    text.lines()
        .filter_map(|l| {
            let (res, rest) = l.split_at(l.find(char::is_whitespace)?);
            let parts: Vec<&str> = rest.split('[').skip(1).map(|p| p.split(']').next().unwrap_or("")).collect();
            if res.is_empty() || parts.len() < 3 {
                return None;
            }
            Some(Rule { resource: res.to_string(), named: !parts[1].trim().is_empty(), verbs: parts[2].split_whitespace().map(String::from).collect() })
        })
        .collect()
}

/// Whether the rules allow a verb on a resource ("pods/exec", "deployments.apps").
fn allows(rules: &[Rule], verb: &str, res: &str) -> bool {
    let (name, sub) = res.split_once('/').map(|(a, b)| (a, Some(b))).unwrap_or((res, None));
    let group = name.split_once('.').map(|x| x.1);
    rules.iter().filter(|r| !r.named && r.verbs.iter().any(|v| v == verb || v == "*")).any(|r| {
        let x = r.resource.as_str();
        // "*" alone is the core group; "*.*" is everything.
        x == res || x == "*.*" || (x == "*" && group.is_none()) || group.map(|g| x == format!("*.{g}")).unwrap_or(false) || sub.map(|s| x == format!("*/{s}")).unwrap_or(false)
    })
}

const ASKED: [(&str, &str, &str); 11] = [
    ("See pods", "list", "pods"),
    ("Read logs", "get", "pods/log"),
    ("Pod usage", "list", "pods.metrics.k8s.io"),
    ("Read secrets", "get", "secrets"),
    ("Shell", "create", "pods/exec"),
    ("Port forward", "create", "pods/portforward"),
    ("Delete pods", "delete", "pods"),
    ("Restart", "patch", "deployments.apps"),
    ("Scale", "patch", "deployments.apps/scale"),
    ("Edit secrets", "update", "secrets"),
    ("Edit config", "update", "configmaps"),
];

// ---------- drawing ----------

/// Cold to hot.
pub(super) fn heat(f: f64) -> Color32 {
    let mix = |a: Color32, b: Color32, t: f64| {
        let t = t.clamp(0.0, 1.0) as f32;
        let l = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t) as u8;
        Color32::from_rgb(l(a.r(), b.r()), l(a.g(), b.g()), l(a.b(), b.b()))
    };
    let honey = Color32::from_rgb(0xF5, 0x9E, 0x0B);
    if f < 0.6 {
        mix(SUCCESS(), honey, (f - 0.25) / 0.35)
    } else {
        mix(honey, DANGER(), (f - 0.6) / 0.35)
    }
}

/// A hexagon standing on a corner.
fn hexagon(c: egui::Pos2, r: f32) -> Vec<egui::Pos2> {
    (0..6)
        .map(|i| {
            let a = std::f32::consts::FRAC_PI_3 * i as f32 - std::f32::consts::FRAC_PI_2;
            c + egui::vec2(a.cos(), a.sin()) * r
        })
        .collect()
}

/// The part of a shape below a height.
fn below(poly: &[egui::Pos2], y: f32) -> Vec<egui::Pos2> {
    let mut out = vec![];
    for i in 0..poly.len() {
        let (a, b) = (poly[i], poly[(i + 1) % poly.len()]);
        if a.y >= y {
            out.push(a);
        }
        if (a.y >= y) != (b.y >= y) {
            let t = (y - a.y) / (b.y - a.y);
            out.push(egui::pos2(a.x + (b.x - a.x) * t, y));
        }
    }
    out
}

/// Where n cells of radius r sit in a block of hexagons, and the block's size.
fn comb(n: usize, r: f32, max_w: f32) -> (Vec<egui::Vec2>, egui::Vec2) {
    let w = r * 3f32.sqrt();
    let fit = ((max_w / w).floor() as usize).saturating_sub(1).max(1);
    // Big groups make a wide comb.
    let cols = ((n as f32 * if n > 12 { 5.0 } else { 1.6 }).sqrt().ceil() as usize).clamp(1, fit);
    let rows = n.div_ceil(cols).max(1);
    let spots = (0..n).map(|i| egui::vec2(w * (i % cols) as f32 + w / 2.0 + if (i / cols) % 2 == 1 { w / 2.0 } else { 0.0 }, r + r * 1.5 * (i / cols) as f32)).collect();
    (spots, egui::vec2(w * cols as f32 + if rows > 1 { w / 2.0 } else { 0.0 }, r * 2.0 + r * 1.5 * (rows - 1) as f32))
}

/// A name in two short lines ("shop-api-intern" → "shop-api", "intern").
fn cell_name(s: &str) -> Vec<String> {
    let max = 9;
    let mut lines: Vec<String> = vec![String::new()];
    for part in s.split(['-', '.']) {
        let i = lines.len() - 1;
        if lines[i].is_empty() {
            lines[i] = part.to_string();
        } else if lines[i].chars().count() + 1 + part.chars().count() <= max {
            lines[i] += &format!("-{part}");
        } else if i == 0 {
            lines.push(part.to_string());
        } else {
            break;
        }
    }
    lines.iter().map(|l| if l.chars().count() > max { l.chars().take(max - 1).collect::<String>() + "…" } else { l.clone() }).collect()
}

pub(super) fn cores(m: f64) -> String {
    if m >= 1000.0 {
        format!("{:.1} cores", m / 1000.0)
    } else {
        format!("{m:.0}m")
    }
}

impl KubedogApp {
    /// The pods of the open clusters and chosen namespaces that are running or should be.
    fn cells6(&self) -> Vec<Cell6> {
        let mut out = vec![];
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            let Some(l) = self.lists.get(&Self::list_key(c, Kind::Pods)) else { continue };
            let m = self.metrics.get(c);
            for (o, r) in l.items.iter().zip(&l.rows) {
                let phase = o["status"]["phase"].as_str().unwrap_or("");
                if !self.ns_ok(&r.ns) || phase == "Succeeded" {
                    continue;
                }
                let key = (r.ns.clone(), r.name.clone());
                let use_ = m.and_then(|m| m.pods.get(&key)).copied();
                let peak = m.and_then(|m| m.pod_hist.get(&key)).map(|h| h.iter().fold((0.0f64, 0.0f64), |a, x| (a.0.max(x.1 as f64), a.1.max(x.2 as f64)))).unwrap_or_default();
                let b = bounds(o);
                let status = r.cells.get(1).map(|c| c.text.clone()).unwrap_or_default();
                let num = |i: usize| match r.cells.get(i).map(|c| &c.sort) {
                    Some(SortKey::Num(x)) => Some(*x),
                    _ => None,
                };
                let text = |i: usize| r.cells.get(i).map(|c| c.text.clone()).unwrap_or_default();
                let ready = o["status"]["conditions"].as_array().into_iter().flatten().any(|c| c["type"] == "Ready" && c["status"] == "True");
                let restarts = num(4).unwrap_or(0.0);
                out.push(Cell6 {
                    ctx: c.clone(),
                    ns: r.ns.clone(),
                    name: r.name.clone(),
                    node: o["spec"]["nodeName"].as_str().unwrap_or("").to_string(),
                    owner: match &r.workload {
                        Some((_, n)) => n.clone(),
                        None => o["metadata"]["ownerReferences"][0]["name"].as_str().unwrap_or(&r.name).to_string(),
                    },
                    bad: !ready,
                    status,
                    cpu: use_.map(|x| x.0),
                    mem: use_.map(|x| x.1),
                    peak,
                    ask: (b[0], b[1]),
                    limit: (b[2], b[3]),
                    restarts,
                    last: num(5).filter(|x| restarts > 0.0 && x.is_finite() && *x < 1e12),
                    why: text(6),
                });
            }
        }
        out
    }

    /// Nodes under the pods of some clusters: (name, pods, cpu, memory), busiest first.
    pub(super) fn pod_nodes(&self, ctxs: &[String]) -> Vec<(String, usize, f64, f64)> {
        let mut m: HashMap<String, (usize, f64, f64)> = HashMap::new();
        for c in self.cells6().into_iter().filter(|c| ctxs.contains(&c.ctx) && !c.node.is_empty()) {
            let e = m.entry(c.node).or_default();
            e.0 += 1;
            e.1 += c.cpu.unwrap_or(0.0);
            e.2 += c.mem.unwrap_or(0.0);
        }
        let mut v: Vec<_> = m.into_iter().map(|(n, x)| (n, x.0, x.1, x.2)).collect();
        v.sort_by(|a, b| b.3.partial_cmp(&a.3).unwrap_or(std::cmp::Ordering::Equal).then(a.0.cmp(&b.0)));
        v
    }

    /// (nodes, cpu used, memory used, cpu asked, memory asked) of the pods shown.
    pub(super) fn pods_summary(&self) -> (usize, f64, f64, f64, f64) {
        let cells = self.cells6();
        let nodes: HashSet<&str> = cells.iter().map(|c| c.node.as_str()).filter(|n| !n.is_empty()).collect();
        let sum = |f: fn(&Cell6) -> f64| cells.iter().map(f).fold(0.0, |a, b| a + b);
        (nodes.len(), sum(|c| c.cpu.unwrap_or(0.0)), sum(|c| c.mem.unwrap_or(0.0)), sum(|c| c.ask.0), sum(|c| c.ask.1))
    }

    /// A card per node under the pods. Returns the one clicked.
    pub(super) fn nodes_from_pods(&self, ui: &mut Ui, ctxs: &[String], height: f32) -> Option<String> {
        let nodes = self.pod_nodes(ctxs);
        if nodes.is_empty() {
            ui.label(RichText::new("No running pods found in your namespaces.").color(TEXT_SUBTLE()));
            return None;
        }
        let mut open = None;
        let top = |f: fn(&(String, usize, f64, f64)) -> f64| nodes.iter().map(f).fold(1.0, f64::max);
        let (tc, tm) = (top(|x| x.2), top(|x| x.3));
        grid(ui, nodes.len().min(24), u(190.0), height, 12.0, |ui, i, r| {
            let (name, n, cpu, mem) = &nodes[i];
            let resp = ui.interact(r, egui::Id::new(("pod-node", i)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
            ui.painter().rect_filled(r, CornerRadius::same(8), if resp.hovered() { BG_HOVER() } else { BG_CARD() });
            ui.painter().rect_stroke(r, CornerRadius::same(8), Stroke::new(1.0, BORDER_SUBTLE()), egui::StrokeKind::Inside);
            let inner = r.shrink2(egui::vec2(12.0, 0.0));
            let part = |f: f32| egui::Rect::from_center_size(egui::pos2(inner.center().x, r.top() + r.height() * f), egui::vec2(inner.width(), u(18.0)));
            at(ui, part(0.22), 0.0, 0.66, name, 12.5, TEXT_DEFAULT());
            at_end(ui, part(0.22), 1.0, &format!("{n} pod{}", if *n == 1 { "" } else { "s" }), 11.5, TEXT_SUBTLE());
            for (f, label, x, t, text, col) in [(0.52, "CPU", *cpu, tc, cores(*cpu), CPU_BAR()), (0.8, "Mem", *mem, tm, gib(*mem), MEM_BAR())] {
                let l = part(f);
                at(ui, l, 0.0, 0.24, label, 11.0, TEXT_SUBTLE());
                bar(ui, l, 0.2, 0.44, x / t, col);
                at_end(ui, l, 1.0, &text, 11.0, TEXT_MUTED());
            }
            if resp.on_hover_text(format!("{name}\nWhat your pods use on it, compared with your other nodes. Click to see them in the hive.")).clicked() {
                open = Some(name.clone());
            }
        });
        open
    }

    pub(super) fn open_hive(&mut self, node: Option<String>) {
        if node.is_some() {
            self.hive.group = Group::Node;
        }
        self.hive.node = node;
        self.navigate(View::Hive, None);
        self.refresh_current(false);
    }

    pub(super) fn hive_ready(&self) -> bool {
        self.active.iter().all(|c| self.metrics.get(c).map(|m| m.fetched.is_some()).unwrap_or(false))
    }

    /// Use of the pods shown over time, oldest first: (cpu, memory) per reading.
    fn hive_history(&self, cells: &[Cell6]) -> Vec<(f64, f64)> {
        // Clusters are read about together; with several, the newest readings are lined up.
        let mut out: Vec<(f64, f64)> = vec![];
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            let Some(m) = self.metrics.get(c) else { continue };
            let first = m.times.front().map(|t| t.0).unwrap_or(0);
            let mut sums = vec![(0.0, 0.0); m.times.len()];
            for p in cells.iter().filter(|p| &p.ctx == c) {
                for (n, x, y) in m.pod_hist.get(&(p.ns.clone(), p.name.clone())).into_iter().flatten() {
                    if let Some(s) = n.checked_sub(first).and_then(|i| sums.get_mut(i as usize)) {
                        s.0 += *x as f64;
                        s.1 += *y as f64;
                    }
                }
            }
            while out.len() < sums.len() {
                out.insert(0, (0.0, 0.0));
            }
            let off = out.len() - sums.len();
            for (i, s) in sums.iter().enumerate() {
                out[off + i].0 += s.0;
                out[off + i].1 += s.1;
            }
        }
        out
    }

    pub(super) fn hive_view(&mut self, ui: &mut Ui) {
        let mut cells = self.cells6();
        if let Some(n) = &self.hive.node {
            cells.retain(|c| &c.node == n);
        }
        self.header(ui, true, Some(format!("{} pods", cells.len())), true);
        let mut open: Option<Selected> = None;
        self.page_scroll().show(ui, |ui| {
            ui.add_space(6.0);
            self.hive_tiles(ui, &cells);
            ui.add_space(14.0);
            if let Some(p) = self.hive_comb(ui, &cells) {
                open = Some(p);
            }
            let hist = self.hive_history(&cells);
            self.hive_pulse(ui, &hist);
            if let Some(p) = self.hive_sizes(ui, &cells) {
                open = Some(p);
            }
            self.hive_quotas(ui);
            self.hive_rights(ui);
            ui.add_space(20.0);
        });
        if let Some(s) = open {
            self.navigate(View::Resource(Kind::Pods), Some(s));
        }
        if cells.iter().any(|c| c.troubled()) && ui.input(|i| i.viewport().focused.unwrap_or(false)) {
            ui.ctx().request_repaint_after(Duration::from_millis(50));
        }
    }

    fn hive_tiles(&self, ui: &mut Ui, cells: &[Cell6]) {
        let ready = cells.iter().filter(|c| !c.bad).count();
        let (_, cu, mu, ca, ma) = {
            let sum = |f: fn(&Cell6) -> f64| cells.iter().map(f).fold(0.0, |a, b| a + b);
            (0, sum(|c| c.cpu.unwrap_or(0.0)), sum(|c| c.mem.unwrap_or(0.0)), sum(|c| c.ask.0), sum(|c| c.ask.1))
        };
        let have = cells.iter().any(|c| c.cpu.is_some());
        let restarted = cells.iter().filter(|c| c.last.map(|s| s < 3600.0).unwrap_or(false)).count();
        let warned = self.active.iter().filter(|c| self.ctx_shown(c)).filter_map(|c| self.lists.get(&Self::list_key(c, Kind::Events))).flat_map(|l| &l.rows).filter(|r| self.ns_ok(&r.ns) && r.cells.get(3).map(|c| c.text == "Warning").unwrap_or(false) && matches!(r.cells.get(5).map(|c| &c.sort), Some(SortKey::Num(x)) if *x < 3600.0)).count();
        let share = |a: f64, b: f64| if b > 0.0 { format!("{:.0}% of what they ask for", a / b * 100.0) } else { "nothing asked for".into() };
        let tiles: Vec<(&str, String, String, Color32)> = vec![
            ("Pods ready", format!("{ready}/{}", cells.len()), if ready == cells.len() { "all of them".into() } else { format!("{} need a look", cells.len() - ready) }, if ready == cells.len() { SUCCESS() } else { DANGER() }),
            ("CPU now", if have { cores(cu) } else { "–".into() }, if have { share(cu, ca) } else { "no usage yet".into() }, PRIMARY_TEXT()),
            ("Memory now", if have { gib(mu) } else { "–".into() }, if have { share(mu, ma) } else { "no usage yet".into() }, PRIMARY_TEXT()),
            ("Restarted, last hour", restarted.to_string(), if restarted == 0 { "quiet".into() } else { "pulsing in the hive".into() }, if restarted == 0 { SUCCESS() } else { WARNING() }),
            ("Warnings, last hour", warned.to_string(), if warned == 0 { "quiet".into() } else { "see Events".into() }, if warned == 0 { SUCCESS() } else { WARNING() }),
        ];
        grid(ui, tiles.len(), u(170.0), u(100.0), 14.0, |ui, i, r| {
            let t = &tiles[i];
            tile(ui, r, t.0, &t.1, &t.2, t.3);
        });
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            if let Some(e) = self.metrics.get(c).and_then(|m| m.error.as_ref()) {
                ui.add_space(6.0);
                ui.label(RichText::new(format!("{}: {}", ctx_label(c), if is_refusal(e) { "your account can't read pod usage".to_string() } else { format!("pod usage couldn't be read: {}", truncate(e, 160)) })).size(z(12.5)).color(WARNING()));
            }
        }
    }

    fn hive_comb(&mut self, ui: &mut Ui, cells: &[Cell6]) -> Option<Selected> {
        let mut open = None;
        Frame::new().fill(BG_SUBTLE()).stroke(Stroke::new(1.0, BORDER_SUBTLE())).corner_radius(CornerRadius::same(12)).inner_margin(Margin::symmetric(16, 12)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("The hive").size(z(17.0)).color(TEXT_DEFAULT()));
                ui.label(RichText::new("a cell is a pod, filled as far as it uses its limit (or what it asks for)").size(z(12.0)).color(TEXT_PLACEHOLDER()));
                if let Some(n) = self.hive.node.clone() {
                    if ui.button(format!("only {n}  ✕")).clicked() {
                        self.hive.node = None;
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    for (g, t) in [(Group::Node, "Node"), (Group::Namespace, "Namespace"), (Group::Workload, "Workload")] {
                        if ui.selectable_label(self.hive.group == g, t).clicked() {
                            self.hive.group = g;
                        }
                    }
                    ui.label(RichText::new("by").color(TEXT_SUBTLE()));
                    ui.add_space(12.0);
                    for (cpu, t) in [(true, "CPU"), (false, "Memory")] {
                        if ui.selectable_label(self.hive.cpu == cpu, t).clicked() {
                            self.hive.cpu = cpu;
                        }
                    }
                });
            });
            ui.add_space(8.0);
            if cells.is_empty() {
                let loading = self.is_loading();
                ui.horizontal(|ui| {
                    if loading {
                        ui.spinner();
                    }
                    ui.label(RichText::new(if loading { "Reading pods…" } else { "No running pods here." }).color(TEXT_SUBTLE()));
                });
                return;
            }
            // Groups, the biggest first.
            let multi_ns = cells.iter().map(|c| (&c.ctx, &c.ns)).collect::<HashSet<_>>().len() > 1;
            let mut groups: Vec<(String, String, Vec<&Cell6>)> = vec![];
            let mut index: HashMap<(String, String, String), usize> = HashMap::new();
            for c in cells {
                let (name, sub) = match self.hive.group {
                    Group::Workload => (c.owner.clone(), if multi_ns { c.ns.clone() } else { String::new() }),
                    Group::Namespace => (c.ns.clone(), if self.active.len() > 1 { ctx_label(&c.ctx).to_string() } else { String::new() }),
                    Group::Node => (if c.node.is_empty() { "not placed yet".into() } else { c.node.clone() }, if self.active.len() > 1 { ctx_label(&c.ctx).to_string() } else { String::new() }),
                };
                let i = *index.entry((c.ctx.clone(), name.clone(), sub.clone())).or_insert_with(|| {
                    groups.push((name, sub, vec![]));
                    groups.len() - 1
                });
                groups[i].2.push(c);
            }
            groups.sort_by(|a, b| b.2.len().cmp(&a.2.len()).then(a.1.cmp(&b.1)).then(a.0.cmp(&b.0)));
            let cpu = self.hive.cpu;
            for g in &mut groups {
                g.2.sort_by(|a, b| b.fill(cpu).partial_cmp(&a.fill(cpu)).unwrap_or(std::cmp::Ordering::Equal).then(a.name.cmp(&b.name)));
            }
            let rad = u(match (self.hive.group, cells.len()) {
                (Group::Workload, 0..=60) => 26.0,
                (Group::Workload, 61..=200) => 21.0,
                (Group::Workload, _) => 14.0,
                (_, 0..=160) => 34.0,
                (_, 161..=400) => 24.0,
                _ => 17.0,
            });
            let avail = ui.available_width();
            let (gap, label_h) = (u(20.0), u(36.0));
            // Place the blocks in rows.
            let min_w = u(104.0);
            let mut spots = vec![];
            let (mut x, mut y, mut row_h) = (0.0f32, 0.0f32, 0.0f32);
            for g in &groups {
                let (cs, size) = comb(g.2.len(), rad, avail);
                let w = size.x.max(min_w);
                if x > 0.0 && x + w > avail {
                    x = 0.0;
                    y += row_h + gap;
                    row_h = 0.0;
                }
                spots.push((egui::vec2(x, y), w, cs));
                x += w + gap;
                row_h = row_h.max(label_h + size.y);
            }
            let (area, resp) = ui.allocate_exact_size(egui::vec2(avail, y + row_h + 6.0), Sense::click());
            let pointer = resp.hover_pos();
            let search = self.search.to_lowercase();
            let time = ui.input(|i| i.time) as f32;
            let p = ui.painter().clone();
            let mut hit: Option<&Cell6> = None;
            for ((name, sub, pods), (off, w, cs)) in groups.iter().zip(&spots) {
                let o = area.min + *off;
                if !ui.is_rect_visible(egui::Rect::from_min_size(o, egui::vec2(*w, label_h + rad * 40.0))) {
                    continue;
                }
                label_at(ui, &p, o + egui::vec2(0.0, u(9.0)), name, 12.5, TEXT_MUTED(), *w);
                let note = if sub.is_empty() { format!("{} pod{}", pods.len(), if pods.len() == 1 { "" } else { "s" }) } else { sub.clone() };
                label_at(ui, &p, o + egui::vec2(0.0, u(24.0)), &note, 10.5, TEXT_PLACEHOLDER(), *w);
                for (c, at) in pods.iter().zip(cs) {
                    let center = o + egui::vec2(0.0, label_h) + *at;
                    let shown = search.is_empty() || c.name.contains(&search) || c.ns.contains(&search) || c.node.contains(&search) || c.owner.contains(&search);
                    let dim = if shown { 1.0 } else { 0.15 };
                    let hover = pointer.map(|q| (q - center).length() < rad * 0.9).unwrap_or(false);
                    let r = rad - 1.5 + if hover { 2.0 } else { 0.0 };
                    let hex = hexagon(center, r);
                    p.add(egui::Shape::convex_polygon(hex.clone(), BG_CARD().gamma_multiply(dim), Stroke::NONE));
                    let f = c.fill(cpu);
                    if let Some(f) = f {
                        let level = center.y + r - 2.0 * r * (f.clamp(0.04, 1.0) as f32);
                        let honey = below(&hex, level);
                        if honey.len() > 2 {
                            let col = c.colour(cpu).unwrap_or_default();
                            p.add(egui::Shape::convex_polygon(honey, col.gamma_multiply(0.82 * dim), Stroke::NONE));
                        }
                    }
                    let edge = if c.bad { DANGER() } else { c.colour(cpu).unwrap_or(TEXT_PLACEHOLDER()) };
                    p.add(egui::Shape::closed_line(hex, Stroke::new(if hover { 2.2 } else { 1.2 }, edge.gamma_multiply(dim))));
                    // Room for a name.
                    if rad >= u(30.0) && self.hive.group != Group::Workload {
                        let level = center.y + r - 2.0 * r * (f.map(|f| f.clamp(0.04, 1.0)).unwrap_or(0.0) as f32);
                        let lines = cell_name(&c.owner);
                        let high = u(5.25) * lines.len() as f32;
                        let spot = |i: usize| center + egui::vec2(0.0, u(10.5) * i as f32 - u(5.25) * (lines.len() as f32 - 1.0));
                        // Dark on the honey, light above it; on a patch where the honey ends in between.
                        let col = if level < center.y - high {
                            Color32::BLACK
                        } else {
                            if level < center.y + high {
                                for (i, t) in lines.iter().enumerate() {
                                    let w = u(5.1) * t.chars().count() as f32 + 6.0;
                                    p.rect_filled(egui::Rect::from_center_size(spot(i), egui::vec2(w.min(r * 1.7), u(10.5))), CornerRadius::same(3), BG_CARD().gamma_multiply(0.85 * dim));
                                }
                            }
                            TEXT_DEFAULT()
                        };
                        for (i, t) in lines.iter().enumerate() {
                            p.text(spot(i), egui::Align2::CENTER_CENTER, t, FontId::proportional(z(8.8)), col.gamma_multiply(dim));
                        }
                    }
                    if c.troubled() {
                        let t = (time * 0.7 + center.x * 0.004).fract();
                        let col = if c.bad { DANGER() } else { WARNING() };
                        p.add(egui::Shape::closed_line(hexagon(center, rad + t * rad * 0.55), Stroke::new(1.6, col.gamma_multiply((1.0 - t) * dim))));
                    }
                    if hover {
                        hit = Some(c);
                    }
                }
            }
            if let Some(c) = hit {
                let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
                if resp.clicked() {
                    open = Some(Selected { ctx: c.ctx.clone(), kind: Kind::Pods, ns: c.ns.clone(), name: c.name.clone() });
                }
                let hist = self.metrics.get(&c.ctx).and_then(|m| m.pod_hist.get(&(c.ns.clone(), c.name.clone())));
                resp.on_hover_ui_at_pointer(|ui| hive_card(ui, c, cpu, hist));
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(egui::vec2(u(150.0), 8.0), Sense::hover());
                for i in 0..30 {
                    let x = r.left() + r.width() * i as f32 / 30.0;
                    ui.painter().rect_filled(egui::Rect::from_min_size(egui::pos2(x, r.top()), egui::vec2(r.width() / 30.0 + 0.5, 8.0)), CornerRadius::ZERO, heat(i as f64 / 29.0));
                }
                ui.label(RichText::new("0 to 100% of the limit; without a limit, of what's asked for (at most amber)  ·  grey edge: neither set, or no usage  ·  red edge: not ready  ·  pulsing: not ready or restarted within the hour").size(z(11.0)).color(TEXT_PLACEHOLDER()));
            });
        });
        open
    }

    fn hive_pulse(&self, ui: &mut Ui, hist: &[(f64, f64)]) {
        let h = u(96.0);
        let since = self.active.iter().filter(|c| self.ctx_shown(c)).filter_map(|c| self.metrics.get(c)?.times.front().map(|t| t.1)).min();
        let title = |t: &str| match since {
            Some(s) if hist.len() > 1 => format!("{t}, last {}", kube::human_duration(kube::now_secs() - s)),
            _ => t.to_string(),
        };
        let one = |ui: &mut Ui, vals: Vec<f64>, col: Color32, fmt: fn(f64) -> String| {
            if vals.len() < 2 {
                nothing(ui, h, "Collecting readings while this page is open…", TEXT_SUBTLE());
            } else {
                spark(ui, &vals, h, col, fmt);
            }
        };
        pair(ui, &mut (), (&title("CPU of these pods"), h), (&title("Memory of these pods"), h), |ui, _| one(ui, hist.iter().map(|x| x.0).collect(), CPU_BAR(), cores), |ui, _| one(ui, hist.iter().map(|x| x.1).collect(), MEM_BAR(), gib));
    }

    fn hive_sizes(&self, ui: &mut Ui, cells: &[Cell6]) -> Option<Selected> {
        let mut open = None;
        let list = by_workload(cells);
        let (edge, room) = (edges(&list), roomy(&list));
        let readings = self.active.iter().filter_map(|c| self.metrics.get(c)).map(|m| m.times.len()).max().unwrap_or(0);
        let lh = u(27.0);
        let max = 10;
        let high = |n: usize| lh * n.clamp(1, max) as f32 + if n > max { u(24.0) } else { 0.0 };
        let (cpu, mem) = room.iter().fold((0.0, 0.0), |a, x| (a.0 + x.1, a.1 + x.2));
        let title = if room.is_empty() { "Asks for more than it uses".to_string() } else { format!("Asks for more than it uses: {} and {} to spare", cores(cpu), gib(mem)) };
        let pick = |s: &Sized| Selected { ctx: s.ctx.clone(), kind: Kind::Pods, ns: s.ns.clone(), name: s.pod.clone() };
        pair(
            ui,
            &mut open,
            ("Close to the edge", high(edge.len())),
            (&title, high(room.len())),
            |ui, open| {
                if edge.is_empty() {
                    nothing(ui, lh, if list.is_empty() { "No usage read yet." } else { "Nothing is near its limits." }, SUCCESS());
                }
                for (s, tone, what, f) in edge.iter().take(max) {
                    let (r, resp) = line(ui, lh, true);
                    let col = tone_color(*tone);
                    at(ui, r, 0.0, 0.42, &format!("{}/{}", s.ns, s.name), 12.5, PRIMARY_TEXT());
                    bar(ui, r, 0.43, 0.17, *f, col);
                    let t = if what.starts_with("of") { format!("{:.0}% {what}", f * 100.0) } else { what.to_string() };
                    at_end(ui, r, 1.0, &t, 12.0, col);
                    if resp.on_hover_text(format!("{}/{}\npeak {} of {} CPU, {} of {} memory\nClick for its busiest pod", s.ns, s.name, cores(s.peak.0), if s.limit.0 > 0.0 { cores(s.limit.0) } else { "any".into() }, gib(s.peak.1), if s.limit.1 > 0.0 { gib(s.limit.1) } else { "any".into() })).clicked() {
                        *open = Some(pick(s));
                    }
                }
                if edge.len() > max {
                    let (r, _) = line(ui, u(24.0), false);
                    at(ui, r, 0.0, 1.0, &format!("and {} more", edge.len() - max), 12.0, TEXT_SUBTLE());
                }
            },
            |ui, open| {
                if room.is_empty() {
                    nothing(ui, lh, if list.is_empty() { "No usage read yet." } else { "Everything uses a fair part of what it asks for." }, SUCCESS());
                }
                for (s, c, m) in room.iter().take(max) {
                    let (r, resp) = line(ui, lh, true);
                    at(ui, r, 0.0, 0.5, &format!("{}/{}{}", s.ns, s.name, if s.pods > 1 { format!("  ×{}", s.pods) } else { String::new() }), 12.5, PRIMARY_TEXT());
                    let t: Vec<String> = [(*c > 0.0).then(|| cores(*c)), (*m > 0.0).then(|| gib(*m))].into_iter().flatten().collect();
                    at_end(ui, r, 1.0, &t.join(" + "), 12.0, TEXT_MUTED());
                    if resp.on_hover_text(format!("{}/{}\nper pod: asks for {} CPU and {} memory,\nits busiest pod has used {} and {}\nKeeping half as much again on top would free {}", s.ns, s.name, cores(s.ask.0), gib(s.ask.1), cores(s.peak.0), gib(s.peak.1), t.join(" and "))).clicked() {
                        *open = Some(pick(s));
                    }
                }
                if room.len() > max {
                    let (r, _) = line(ui, u(24.0), false);
                    at(ui, r, 0.0, 1.0, &format!("and {} more", room.len() - max), 12.0, TEXT_SUBTLE());
                }
            },
        );
        ui.add_space(4.0);
        ui.label(RichText::new(format!("From {readings} reading{} since Kubedog connected. Busy hours it hasn't seen aren't counted, so let it run through a normal day before making anything smaller.", if readings == 1 { "" } else { "s" })).size(z(11.5)).color(TEXT_PLACEHOLDER()));
        open
    }

    fn hive_quotas(&self, ui: &mut Ui) {
        let mut rows: Vec<(String, f64, String)> = vec![];
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            for q in self.lists.get(&Self::list_key(c, Kind::ResourceQuotas)).map(|l| l.items.as_slice()).unwrap_or(&[]) {
                let ns = q["metadata"]["namespace"].as_str().unwrap_or("");
                if !self.ns_ok(ns) {
                    continue;
                }
                for (k, hard) in q["status"]["hard"].as_object().into_iter().flatten() {
                    let (h, v) = (hard.as_str().unwrap_or(""), q["status"]["used"][k].as_str().unwrap_or("0"));
                    let num = |s: &str| if k.contains("cpu") { resources::cpu_milli(s) } else { resources::mem_bytes(s) };
                    if num(h) > 0.0 {
                        rows.push((format!("{ns}  ·  {k}"), num(v) / num(h), format!("{v} of {h}")));
                    }
                }
            }
        }
        if rows.is_empty() {
            return;
        }
        rows.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        section(ui, "Quotas", "how much of each namespace's allowance is taken");
        card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for (name, f, text) in rows.iter().take(14) {
                let (r, _) = line(ui, u(27.0), false);
                at(ui, r, 0.0, 0.42, name, 12.5, TEXT_DEFAULT());
                bar(ui, r, 0.43, 0.3, *f, if *f >= 0.9 { DANGER() } else if *f >= 0.75 { WARNING() } else { SUCCESS() });
                at_end(ui, r, 0.8, &format!("{:.0}%", f * 100.0), 12.5, TEXT_MUTED());
                at_end(ui, r, 1.0, text, 12.0, TEXT_SUBTLE());
            }
        });
    }

    pub(super) fn on_rights(&mut self, key: &str, result: &Result<String, String>) -> bool {
        if !key.starts_with("rights|") {
            return false;
        }
        self.hive.rights.insert(key.to_string(), Some(result.as_ref().map(|t| parse_rules(t)).map_err(|e| e.clone())));
        true
    }

    /// What the account may do: what was refused, and (when asked) the rules per namespace.
    fn hive_rights(&mut self, ui: &mut Ui) {
        section(ui, "Your access", "what the cluster lets this account do");
        let ctxs: Vec<String> = self.active.iter().filter(|c| self.ctx_shown(c)).cloned().collect();
        for c in ctxs {
            let mut names: Vec<String> = self.namespaces.get(&c).cloned().unwrap_or_default();
            if names.is_empty() {
                names = self.lists.get(&Self::list_key(&c, Kind::Pods)).map(|l| l.rows.iter().map(|r| r.ns.clone()).collect::<HashSet<_>>().into_iter().collect()).unwrap_or_default();
                names.sort();
            }
            names.retain(|n| self.ns_ok(n));
            let limit = 8;
            let refused: Vec<String> = GROUPS.iter().flat_map(|g| g.1.iter().copied()).filter(|k| self.refused(&c, *k)).map(|k| k.label().to_string()).chain(self.metrics.get(&c).filter(|m| m.nodes_refused).map(|_| "node usage".to_string())).collect();
            let mut ask = false;
            card(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 4.0;
                if self.active.len() > 1 {
                    ui.label(RichText::new(ctx_label(&c)).strong().color(TEXT_DEFAULT()));
                }
                ui.add(egui::Label::new(RichText::new(if refused.is_empty() { "Nothing has been refused so far.".to_string() } else { format!("Refused so far: {}", refused.join(", ")) }).size(z(13.0)).color(if refused.is_empty() { SUCCESS() } else { WARNING() })).wrap());
                if !self.prefs.ctx_namespaces.contains_key(&c) && (self.refused(&c, Kind::Pods) || self.refused(&c, Kind::Namespaces)) {
                    self.namespaces_field(ui, &c, true);
                }
                let key = |n: &str| format!("rights|{c}|{n}");
                let asked = names.iter().take(limit).any(|n| self.hive.rights.contains_key(&key(n)));
                if !asked {
                    ui.horizontal(|ui| {
                        ask = !names.is_empty() && button(ui, "What may I do in these namespaces?", false, false);
                        if names.len() > limit {
                            ui.label(RichText::new(format!("asks about the first {limit}; choose namespaces at the top for others")).size(z(11.5)).color(TEXT_PLACEHOLDER()));
                        }
                    });
                } else {
                    ui.add_space(4.0);
                    let first = 0.2;
                    let step = (1.0 - first) / ASKED.len() as f32;
                    let (r, _) = line(ui, u(24.0), false);
                    for (i, a) in ASKED.iter().enumerate() {
                        at(ui, r, first + step * i as f32, step * 1.05, a.0, 11.0, TEXT_SUBTLE());
                    }
                    for n in names.iter().take(limit) {
                        let (r, _) = line(ui, u(26.0), false);
                        at(ui, r, 0.0, first, n, 13.0, TEXT_DEFAULT());
                        match self.hive.rights.get(&key(n)) {
                            Some(Some(Ok(rules))) => {
                                for (i, a) in ASKED.iter().enumerate() {
                                    let yes = allows(rules, a.1, a.2);
                                    let risky = i >= 6;
                                    let pos = egui::pos2(r.left() + r.width() * (first + step * i as f32) + u(8.0), r.center().y);
                                    let col = if !yes { TEXT_PLACEHOLDER() } else if risky { WARNING() } else { SUCCESS() };
                                    if yes {
                                        ui.painter().circle_filled(pos, u(5.0), col);
                                    } else {
                                        ui.painter().circle_stroke(pos, u(4.0), Stroke::new(1.4, col));
                                    }
                                }
                            }
                            Some(Some(Err(e))) => at(ui, r, first, 1.0 - first, &truncate(e, 200), 12.0, WARNING()),
                            _ => at(ui, r, first, 1.0 - first, "asking…", 12.0, TEXT_SUBTLE()),
                        }
                    }
                    ui.add(egui::Label::new(RichText::new("Green: allowed. Amber: allowed, and it changes things. A ring: not in the list of rules Kubernetes gave; that list can be incomplete, so it may still work.").size(z(11.5)).color(TEXT_PLACEHOLDER())).wrap());
                }
            });
            if ask || (self.screenshot.is_some() && std::env::var("KUBEDOG_SHOT_RIGHTS").is_ok() && !names.is_empty() && !self.hive.rights.keys().any(|k| k.starts_with(&format!("rights|{c}|")))) {
                for n in names.iter().take(limit) {
                    let key = format!("rights|{c}|{n}");
                    self.hive.rights.insert(key.clone(), None);
                    let args: Vec<String> = ["--context", &c, "-n", n, "auth", "can-i", "--list", "--no-headers", &format!("--request-timeout={}", kube::REQUEST_TIMEOUT)].iter().map(|s| s.to_string()).collect();
                    self.fetch_text(key, args);
                }
            }
            ui.add_space(8.0);
        }
    }
}

/// What's shown for the cell under the pointer.
fn hive_card(ui: &mut Ui, c: &Cell6, cpu: bool, hist: Option<&std::collections::VecDeque<(u32, f32, f32)>>) {
    ui.set_width(u(320.0));
    ui.spacing_mut().item_spacing.y = 3.0;
    ui.add(egui::Label::new(RichText::new(&c.name).size(z(13.5)).strong().color(PRIMARY_TEXT())).wrap());
    ui.label(RichText::new(format!("{}  ·  {}", c.ns, if c.node.is_empty() { "not placed yet" } else { &c.node })).size(z(12.0)).color(TEXT_SUBTLE()));
    let mut s = c.status.clone();
    if c.restarts > 0.0 {
        s += &format!("  ·  {:.0} restarts", c.restarts);
        if let Some(l) = c.last {
            s += &format!(", last {} ago", kube::human_duration(l as i64));
        }
    }
    ui.label(RichText::new(s).size(z(12.0)).color(if c.bad { DANGER() } else { TEXT_MUTED() }));
    if c.troubled() && !c.why.is_empty() && c.why != "-" {
        ui.label(RichText::new(&c.why).size(z(12.0)).color(WARNING()));
    }
    let of = |v: Option<f64>, ask: f64, lim: f64, f: fn(f64) -> String| match v {
        None => "no usage read".to_string(),
        Some(v) => format!("{}{}{}", f(v), if lim > 0.0 { format!(" of {} limit", f(lim)) } else { ", no limit".into() }, if ask > 0.0 { format!(", asks for {}", f(ask)) } else { String::new() }),
    };
    ui.label(RichText::new(format!("CPU  {}", of(c.cpu, c.ask.0, c.limit.0, cores))).size(z(12.0)).color(TEXT_DEFAULT()));
    ui.label(RichText::new(format!("Memory  {}", of(c.mem, c.ask.1, c.limit.1, gib))).size(z(12.0)).color(TEXT_DEFAULT()));
    if let Some(h) = hist.filter(|h| h.len() > 1) {
        let v: Vec<f64> = h.iter().map(|x| if cpu { x.1 } else { x.2 } as f64).collect();
        spark(ui, &v, u(40.0), if cpu { CPU_BAR() } else { MEM_BAR() }, if cpu { cores } else { gib });
    }
    ui.label(RichText::new("click to open").size(z(11.0)).color(TEXT_PLACEHOLDER()));
}

#[cfg(test)]
mod tests {
    use super::*;

    const GI: f64 = 1073741824.0;

    fn cell(name: &str, owner: &str, cpu: f64, mem: f64, ask: (f64, f64), limit: (f64, f64)) -> Cell6 {
        Cell6 { name: name.into(), owner: owner.into(), cpu: Some(cpu), mem: Some(mem), peak: (cpu, mem), ask, limit, ..Default::default() }
    }

    #[test]
    fn sizes() {
        let cells = vec![
            cell("a-1", "a", 10.0, 0.95 * GI, (100.0, GI), (0.0, GI)),
            cell("a-2", "a", 10.0, 0.2 * GI, (100.0, GI), (0.0, GI)),
            cell("b-1", "b", 50.0, 0.1 * GI, (2000.0, 4.0 * GI), (0.0, 0.0)),
            cell("c-1", "c", 990.0, 0.1 * GI, (500.0, 0.1 * GI), (1000.0, 0.0)),
        ];
        let w = by_workload(&cells);
        assert_eq!((w.len(), w[0].pods, w[0].pod.as_str()), (3, 2, "a-1"));
        let e = edges(&w);
        assert_eq!(e.iter().map(|x| (x.0.name.as_str(), x.1)).collect::<Vec<_>>(), vec![("a", Tone::Danger), ("c", Tone::Warning)]);
        let r = roomy(&w);
        assert_eq!(r[0].0.name, "b");
        assert!((r[0].1 - (2000.0 - 75.0)).abs() < 0.01);
        // A pod with no bounds has no fill; a limit wins over the request.
        assert_eq!(cell("x", "x", 1.0, 1.0, (0.0, 0.0), (0.0, 0.0)).fill(true), None);
        // Without a limit it's never red.
        let over = cell("x", "x", 900.0, 1.0, (100.0, 0.0), (0.0, 0.0));
        assert_eq!(over.colour(true), Some(heat(0.6)));
        assert_eq!(cell("x", "x", 50.0, 1.0, (100.0, 0.0), (200.0, 0.0)).fill(true), Some(0.25));
    }

    #[test]
    fn limits_need_every_container() {
        let o = serde_json::json!({"spec": {"containers": [
            {"resources": {"requests": {"cpu": "100m", "memory": "1Gi"}, "limits": {"cpu": "200m", "memory": "2Gi"}}},
            {"resources": {"limits": {"memory": "1Gi"}}}
        ], "initContainers": [{"resources": {"requests": {"cpu": "5"}}}, {"restartPolicy": "Always", "resources": {"requests": {"cpu": "50m"}, "limits": {"memory": "1Gi"}}}]}});
        assert_eq!(bounds(&o), [150.0, 3.0 * GI, 0.0, 4.0 * GI]);
    }

    #[test]
    fn rights() {
        let text = "Resources   Non-Resource URLs   Resource Names   Verbs\npods/exec      []      []      [create get]\n*.apps   []   []   [get list patch]\nsecrets   []   [one]   [get]\n            [/api]   []   [get]\npods   []   []   [*]\n";
        let r = parse_rules(text);
        assert!(allows(&r, "create", "pods/exec") && allows(&r, "patch", "deployments.apps") && allows(&r, "delete", "pods"));
        assert!(!allows(&r, "get", "secrets") && !allows(&r, "get", "pods/log") && !allows(&r, "update", "configmaps"));
        let all = parse_rules("*.*   []   []   [*]");
        assert!(ASKED.iter().all(|a| allows(&all, a.1, a.2)));
    }

    #[test]
    fn honeycomb() {
        let (c, size) = comb(7, 10.0, 500.0);
        assert_eq!(c.len(), 7);
        assert!(c.iter().all(|p| p.x <= size.x && p.y <= size.y));
        for (i, a) in c.iter().enumerate() {
            for b in &c[i + 1..] {
                assert!((*a - *b).length() > 17.0);
            }
        }
        assert_eq!(cell_name("shop-api-intern"), vec!["shop-api", "intern"]);
        assert_eq!(cell_name("elasticsearch"), vec!["elastics…"]);
        assert_eq!(cell_name("a-b-c"), vec!["a-b-c"]);
        let hex = hexagon(egui::pos2(0.0, 0.0), 10.0);
        assert_eq!(below(&hex, -20.0).len(), 6);
        assert!(below(&hex, 20.0).is_empty());
        assert!(below(&hex, 0.0).iter().all(|p| p.y >= -0.001));
    }
}
