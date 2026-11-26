//! The Incident Room: what changed and when (the time machine), why something is broken
//! (detect.rs), errors in logs (loghunt.rs), can A reach B (connect.rs), and two clusters or Git
//! against what runs (compare.rs).


use super::ops::{ago, ns_of, text};
use super::pg::{label_at, panel};
use super::podxray::Go;
use super::work::{name_of, said};
use super::*;
use std::collections::{BTreeMap, VecDeque};

pub(super) const TABS: [&str; 7] = ["What changed", "Why is it broken", "Errors in logs", "Can A reach B", "Compare clusters", "Drift from Git", "Ai-health-agent"];

/// Kinds that are watched for changes.
const WATCH: &[Kind] = &[
    Kind::Deployments,
    Kind::StatefulSets,
    Kind::DaemonSets,
    Kind::CronJobs,
    Kind::ConfigMaps,
    Kind::Services,
    Kind::Ingresses,
    Kind::NetworkPolicies,
    Kind::HorizontalPodAutoscalers,
    Kind::PersistentVolumeClaims,
    Kind::Nodes,
];
const WATCH_EVERY: u64 = 60;

pub(super) type Digest = BTreeMap<String, String>;

/// A change Kubedog saw happen: (what, before, after).
#[derive(Clone, Debug)]
pub(super) struct Change {
    pub at: i64,
    pub ctx: String,
    pub kind: Kind,
    pub ns: String,
    pub name: String,
    pub what: Vec<(String, String, String)>,
}

#[derive(Default)]
pub(super) struct Room {
    pub tab: usize,
    /// The object the detective looks at.
    pub sel: Option<Selected>,
    pub changes: VecDeque<Change>,
    /// (cluster, kind, namespace, name) -> (version, what matters in it).
    seen: HashMap<(String, Kind, String, String), (String, Digest)>,
    /// Lists that were read at least once: (cluster, kind).
    started: HashSet<(String, Kind)>,
    asked: HashMap<(String, Kind), Instant>,
    /// When watching began.
    pub since: i64,
    /// Seconds the timeline goes back.
    pub range: i64,
    pub open: Option<usize>,
    pub hide: [bool; 4],
    pub hunt: loghunt::Hunt,
    pub conn: connect::Conn,
    pub cmp: compare::Cmp,
    pub find: String,
}

/// What matters in an object, as short texts. Never a secret's value.
pub(super) fn digest(kind: Kind, o: &Value) -> Digest {
    let mut d = Digest::new();
    let mut put = |k: &str, v: String| {
        if !v.is_empty() && v != "null" {
            d.insert(k.to_string(), v);
        }
    };
    let spec = &o["spec"];
    let any = |v: &Value| match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        v => v.to_string(),
    };
    match kind {
        Kind::Deployments | Kind::StatefulSets | Kind::DaemonSets | Kind::CronJobs => {
            put("replicas", any(&spec["replicas"]));
            put("schedule", any(&spec["schedule"]));
            put("suspended", any(&spec["suspend"]));
            put("paused", any(&spec["paused"]));
            put("strategy", any(&spec["strategy"]["type"]));
            let ps = workload::pod_spec(kind, o);
            put("service account", any(&ps["serviceAccountName"]));
            put("node selector", any(&ps["nodeSelector"]));
            put("priority class", any(&ps["priorityClassName"]));
            for (list, word) in [("containers", ""), ("initContainers", "init ")] {
                for c in ps[list].as_array().into_iter().flatten() {
                    let n = format!("{word}{}", c["name"].as_str().unwrap_or(""));
                    put(&format!("{n} image"), any(&c["image"]));
                    for (a, w) in [("requests", "request"), ("limits", "limit")] {
                        for r in ["cpu", "memory"] {
                            put(&format!("{n} {r} {w}"), any(&c["resources"][a][r]));
                        }
                    }
                    for e in c["env"].as_array().into_iter().flatten() {
                        let v = if e["valueFrom"].is_object() {
                            let f = &e["valueFrom"];
                            match (f["secretKeyRef"]["name"].as_str(), f["configMapKeyRef"]["name"].as_str()) {
                                (Some(s), _) => format!("from secret {s}, {}", any(&f["secretKeyRef"]["key"])),
                                (_, Some(c)) => format!("from config map {c}, {}", any(&f["configMapKeyRef"]["key"])),
                                _ => "from the pod".into(),
                            }
                        } else {
                            truncate(&any(&e["value"]), 300)
                        };
                        put(&format!("{n} env {}", e["name"].as_str().unwrap_or("")), v);
                    }
                    put(&format!("{n} arguments"), truncate(&[&c["command"], &c["args"]].iter().flat_map(|a| a.as_array().into_iter().flatten()).filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" "), 300));
                    for p in ["readinessProbe", "livenessProbe", "startupProbe"] {
                        put(&format!("{n} {p}"), truncate(&any(&c[p]), 300));
                    }
                }
            }
            for v in ps["volumes"].as_array().into_iter().flatten() {
                let from = v["configMap"]["name"].as_str().map(|n| format!("config map {n}")).or_else(|| v["secret"]["secretName"].as_str().map(|n| format!("secret {n}"))).or_else(|| v["persistentVolumeClaim"]["claimName"].as_str().map(|n| format!("claim {n}"))).unwrap_or_default();
                put(&format!("volume {}", v["name"].as_str().unwrap_or("")), from);
            }
        }
        Kind::ConfigMaps => {
            for (k, v) in o["data"].as_object().into_iter().flatten() {
                put(&format!("key {k}"), truncate(v.as_str().unwrap_or(""), 4000));
            }
            for (k, _) in o["binaryData"].as_object().into_iter().flatten() {
                put(&format!("key {k}"), "binary".into());
            }
        }
        Kind::Services => {
            put("type", any(&spec["type"]));
            put("selector", any(&spec["selector"]));
            put("ports", spec["ports"].as_array().into_iter().flatten().map(|p| format!("{}→{}", p["port"], any(&p["targetPort"]))).collect::<Vec<_>>().join(", "));
            put("external name", any(&spec["externalName"]));
        }
        Kind::Ingresses => {
            put("class", any(&spec["ingressClassName"]));
            put("rules", podxray::pick_ingress(o).iter().map(|e| format!("{} → {}", e.address(), e.service)).collect::<Vec<_>>().join(", "));
            put("TLS secrets", spec["tls"].as_array().into_iter().flatten().filter_map(|t| t["secretName"].as_str()).collect::<Vec<_>>().join(", "));
        }
        Kind::NetworkPolicies => put("rules", truncate(&any(spec), 2000)),
        Kind::HorizontalPodAutoscalers => {
            put("min", any(&spec["minReplicas"]));
            put("max", any(&spec["maxReplicas"]));
        }
        Kind::PersistentVolumeClaims => {
            put("state", any(&o["status"]["phase"]));
            put("size", any(&o["status"]["capacity"]["storage"]));
            put("asked size", any(&spec["resources"]["requests"]["storage"]));
        }
        Kind::Nodes => {
            put("scheduling", if spec["unschedulable"] == true { "off".into() } else { "on".into() });
            put("kubelet", any(&o["status"]["nodeInfo"]["kubeletVersion"]));
            put("OS image", any(&o["status"]["nodeInfo"]["osImage"]));
            put("taints", any(&spec["taints"]));
            for c in o["status"]["conditions"].as_array().into_iter().flatten() {
                put(c["type"].as_str().unwrap_or(""), any(&c["status"]));
            }
        }
        _ => {}
    }
    d
}

/// (what, before, after) of what differs.
pub(super) fn differences(a: &Digest, b: &Digest) -> Vec<(String, String, String)> {
    let keys: std::collections::BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    keys.into_iter()
        .filter_map(|k| {
            let (x, y) = (a.get(k).cloned().unwrap_or_default(), b.get(k).cloned().unwrap_or_default());
            (x != y).then(|| (k.clone(), x, y))
        })
        .collect()
}

/// A point on the timeline.
#[derive(Clone)]
pub(super) struct Moment {
    pub at: i64,
    /// 0 changes, 1 warnings, 2 restarts, 3 writes.
    pub lane: usize,
    pub tone: Tone,
    pub title: String,
    pub detail: String,
    pub diff: Vec<(String, String, String)>,
    pub go: Option<Go>,
    pub sel: Option<Selected>,
}

const LANES: [&str; 4] = ["Changes", "Warnings", "Restarts", "Written by"];

impl KubedogApp {
    pub(super) fn incident_kinds(&self) -> Vec<Kind> {
        let mut v = vec![Kind::Pods, Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::ReplicaSets, Kind::Events];
        match self.incident.tab {
            1 => v.extend([Kind::CronJobs, Kind::Nodes, Kind::Services, Kind::Ingresses, Kind::EndpointSlices, Kind::ConfigMaps, Kind::PersistentVolumeClaims, Kind::HorizontalPodAutoscalers]),
            3 => v.extend(Self::path_kinds().into_iter().filter(|k| !matches!(k, Kind::Pods | Kind::Deployments | Kind::StatefulSets | Kind::DaemonSets | Kind::ReplicaSets))),
            4 => v.extend([Kind::ConfigMaps, Kind::Services, Kind::Ingresses, Kind::CronJobs, Kind::HorizontalPodAutoscalers]),
            _ => {}
        }
        v
    }

    /// Read the watched kinds now and then, whatever page is open.
    pub(super) fn refresh_incident(&mut self, force: bool) {
        if self.demo || self.power_off("incident") || (self.screenshot.is_some() && self.view != View::Incident) {
            return;
        }
        if self.incident.since == 0 {
            self.incident.since = kube::now_secs();
            self.incident.range = 6 * 3600;
        }
        for c in self.active.clone() {
            for k in WATCH {
                let key = (c.clone(), *k);
                let due = self.incident.asked.get(&key).map(|t| t.elapsed() >= Duration::from_secs(WATCH_EVERY)).unwrap_or(true);
                let fresh = self.lists.get(&Self::list_key(&c, *k)).and_then(|l| l.fetched).map(|t| t.elapsed() < Duration::from_secs(WATCH_EVERY)).unwrap_or(false);
                if due && !fresh && !self.refused(&c, *k) {
                    self.incident.asked.insert(key, Instant::now());
                    self.fetch_list(&c, *k);
                }
            }
            if self.view == View::Incident && matches!(self.incident.tab, 0 | 1 | 5) {
                self.ask_writers(&c, force);
            }
        }
        if self.view == View::Incident && self.incident.tab == 3 {
            self.refresh_path(force);
        }
        if self.view == View::Incident && self.incident.tab == 5 {
            self.read_custom(argo::APPS, 30, force);
        }
    }

    /// Compare a list that was just read with how it was. (From handle_messages.)
    pub(super) fn watch_list(&mut self, ctx: &str, kind: Kind) {
        if !WATCH.contains(&kind) || self.demo || self.power_off("incident") {
            return;
        }
        let Some(l) = self.lists.get(&Self::list_key(ctx, kind)).filter(|l| l.error.is_none()) else { return };
        let first = self.incident.started.insert((ctx.to_string(), kind));
        let now = kube::now_secs();
        let room = &mut self.incident;
        let mut here: HashSet<(String, String)> = HashSet::with_capacity(l.items.len());
        let mut out: Vec<Change> = vec![];
        for o in &l.items {
            let (ns, name) = (ns_of(o).to_string(), name_of(o).to_string());
            here.insert((ns.clone(), name.clone()));
            let rv = text(&o["metadata"]["resourceVersion"]);
            let key = (ctx.to_string(), kind, ns.clone(), name.clone());
            if room.seen.get(&key).map(|s| s.0 == rv).unwrap_or(false) {
                continue;
            }
            let d = digest(kind, o);
            let what = match room.seen.get(&key) {
                Some((_, old)) => differences(old, &d),
                None if first => vec![],
                None => vec![("created".to_string(), String::new(), String::new())],
            };
            room.seen.insert(key, (rv, d));
            if !what.is_empty() {
                out.push(Change { at: now, ctx: ctx.into(), kind, ns, name, what });
            }
        }
        if !first {
            let mut gone: Vec<(String, Kind, String, String)> = room.seen.keys().filter(|k| k.0 == ctx && k.1 == kind && !here.contains(&(k.2.clone(), k.3.clone()))).cloned().collect();
            gone.sort_by(|a, b| (&a.2, &a.3).cmp(&(&b.2, &b.3)));
            // All gone at once is a hiccup, not a change.
            if !l.items.is_empty() {
                for k in gone {
                    room.seen.remove(&k);
                    out.push(Change { at: now, ctx: ctx.into(), kind, ns: k.2, name: k.3, what: vec![("deleted".into(), String::new(), String::new())] });
                }
            }
        }
        for c in out {
            room.changes.push_back(c);
        }
        while room.changes.len() > 3000 {
            room.changes.pop_front();
        }
    }

    /// Who wrote objects and when (names of writers only).
    fn ask_writers(&mut self, ctx: &str, force: bool) {
        let c = ctx.to_string();
        self.ask(&format!("writers|{ctx}"), 120, force, move |k| {
            let a: Vec<String> = ["--context", &c, "get", "deployments.apps,statefulsets.apps,daemonsets.apps,configmaps,services,ingresses.networking.k8s.io", "--all-namespaces", "-o", "json", "--show-managed-fields", &format!("--request-timeout={}", kube::REQUEST_TIMEOUT)].iter().map(|s| s.to_string()).collect();
            let items = kube::parse_items(&k.run(&a)?)?;
            Ok(Value::Array(items.iter().map(compare::slim_writers).collect()).to_string())
        });
    }

    /// Everything that happened in the range, the newest first.
    pub(super) fn moments(&self, range: i64) -> Vec<Moment> {
        let now = kube::now_secs();
        let from = now - range;
        let mut v: Vec<Moment> = vec![];
        for c in self.incident.changes.iter().filter(|c| c.at >= from) {
            let sel = Selected { ctx: c.ctx.clone(), kind: c.kind, ns: c.ns.clone(), name: c.name.clone() };
            let words = match c.what.as_slice() {
                [(w, a, b)] if a.is_empty() && b.is_empty() => w.clone(),
                l => l.iter().map(|x| x.0.as_str()).take(4).collect::<Vec<_>>().join(", "),
            };
            v.push(Moment { at: c.at, lane: 0, tone: Tone::Info, title: format!("{} {}/{}", c.kind.singular(), c.ns, c.name), detail: words, diff: c.what.clone(), go: Some(Go::Object(sel.clone())), sel: Some(sel) });
        }
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            // Rollouts, also from before Kubedog was opened: each replica set is a version.
            let mut by: BTreeMap<(String, String), Vec<&Value>> = BTreeMap::new();
            for r in self.refs(c, Kind::ReplicaSets, "").unwrap_or_default() {
                if let Some(n) = r["metadata"]["ownerReferences"][0]["name"].as_str().filter(|_| r["metadata"]["ownerReferences"][0]["kind"] == "Deployment") {
                    by.entry((ns_of(r).to_string(), n.to_string())).or_default().push(r);
                }
            }
            let made = |r: &Value| pod::time_of(&r["metadata"]["creationTimestamp"]).unwrap_or(0);
            let fake = |r: &Value| digest(Kind::Deployments, &serde_json::json!({"spec": {"template": r["spec"]["template"]}}));
            for ((ns, name), mut l) in by {
                l.sort_by_key(|r| made(r));
                for (i, r) in l.iter().enumerate().filter(|(_, r)| made(r) >= from) {
                    let diff = if i > 0 { differences(&fake(l[i - 1]), &fake(r)) } else { vec![] };
                    let sel = Selected { ctx: c.clone(), kind: Kind::Deployments, ns: ns.clone(), name: name.clone() };
                    let words = if diff.is_empty() { "a new version".to_string() } else { diff.iter().map(|x| x.0.as_str()).take(4).collect::<Vec<_>>().join(", ") };
                    v.push(Moment { at: made(r), lane: 0, tone: Tone::Info, title: format!("rollout of {ns}/{name}"), detail: words, diff, go: Some(Go::Object(sel.clone())), sel: Some(sel) });
                }
            }
            for e in self.refs(c, Kind::Events, "").unwrap_or_default().into_iter().filter(|e| e["type"] == "Warning") {
                let at = pod::time_of(&e["lastTimestamp"]).or_else(|| pod::time_of(&e["series"]["lastObservedTime"])).or_else(|| pod::time_of(&e["eventTime"])).unwrap_or(0);
                if at < from {
                    continue;
                }
                let i = &e["involvedObject"];
                let sel = event_kind(i["kind"].as_str().unwrap_or("")).map(|k| Selected { ctx: c.clone(), kind: k, ns: if k.namespaced() { text(&i["namespace"]) } else { String::new() }, name: text(&i["name"]) });
                let n = e["count"].as_i64().or(e["series"]["count"].as_i64()).unwrap_or(1);
                v.push(Moment { at, lane: 1, tone: Tone::Warning, title: format!("{} {}/{}", face::spaced(e["reason"].as_str().unwrap_or("")), text(&i["namespace"]), text(&i["name"])), detail: format!("{}{}", if n > 1 { format!("{n} times: ") } else { String::new() }, truncate(e["message"].as_str().unwrap_or(""), 400)), diff: vec![], go: sel.clone().map(Go::Object), sel });
            }
            for p in self.refs(c, Kind::Pods, "").unwrap_or_default() {
                for s in p["status"]["containerStatuses"].as_array().into_iter().flatten() {
                    let t = &s["lastState"]["terminated"];
                    let Some(at) = pod::time_of(&t["finishedAt"]).filter(|a| *a >= from) else { continue };
                    let sel = Selected { ctx: c.clone(), kind: Kind::Pods, ns: ns_of(p).into(), name: name_of(p).into() };
                    let code = t["exitCode"].as_i64().unwrap_or(0);
                    v.push(Moment { at, lane: 2, tone: if code == 0 { Tone::Muted } else { Tone::Danger }, title: format!("{}/{} restarted", ns_of(p), name_of(p)), detail: format!("{}: {} (exit {code})", text(&s["name"]), text(&t["reason"])), diff: vec![], go: Some(Go::Object(sel.clone())), sel: Some(sel) });
                }
            }
            if let Some(Ok(Value::Array(l))) = self.answer(&format!("writers|{c}")) {
                for o in l {
                    for f in o["by"].as_array().into_iter().flatten().filter(|f| f["sub"] != "status") {
                        let Some(at) = pod::time_of(&f["at"]).filter(|a| *a >= from) else { continue };
                        let sel = workload::kind_named(o["kind"].as_str().unwrap_or("")).map(|k| Selected { ctx: c.clone(), kind: k, ns: text(&o["ns"]), name: text(&o["name"]) });
                        v.push(Moment { at, lane: 3, tone: Tone::Muted, title: format!("{} {}/{}", text(&o["kind"]), text(&o["ns"]), text(&o["name"])), detail: format!("last written by {}", text(&f["m"])), diff: vec![], go: sel.clone().map(Go::Object), sel });
                    }
                }
            }
        }
        v.retain(|m| m.sel.as_ref().map(|s| !s.kind.namespaced() || self.ns_ok(&s.ns)).unwrap_or(true));
        v.sort_by_key(|m| std::cmp::Reverse(m.at));
        v
    }

    pub(super) fn incident_view(&mut self, ui: &mut Ui) {
        if self.power_off("incident") {
            self.header(ui, false, None, false);
            said(ui, "The Incident Room is switched off in Settings > Superpowers.", TEXT_SUBTLE());
            return;
        }
        if self.screenshot.is_some() {
            if let Some(t) = std::env::var("KUBEDOG_SHOT_TAB").ok().and_then(|t| t.parse().ok()).filter(|t| *t < TABS.len()) {
                if self.incident.tab != t {
                    self.incident.tab = t;
                    self.refresh_current(false);
                }
            }
        }
        self.header(ui, true, Some("Incident Room".into()), true);
        let mut tab = self.incident.tab;
        ui.horizontal(|ui| tab_strip(ui, &TABS, &mut tab));
        if tab != self.incident.tab {
            self.incident.tab = tab;
            self.refresh_current(false);
        }
        ui.add_space(8.0);
        let mut go: Option<Go> = None;
        // Lines of logs, and what things are set to, are told apart for the AI.
        aipage::class(match tab {
            2 => aifacts::Class::Log,
            4 | 5 => aifacts::Class::Value,
            _ => aifacts::Class::State,
        });
        self.page_scroll().id_salt(("incident", tab)).show(ui, |ui| {
            go = match tab {
                0 => self.timeline(ui),
                1 => self.detective(ui),
                2 => self.log_hunt(ui),
                3 => self.connection(ui),
                4 => self.cluster_compare(ui),
                5 => self.drift(ui),
                _ => self.companion_view(ui),
            };
            ui.add_space(20.0);
        });
        if let Some(g) = go {
            self.go_to(g);
        }
    }

    fn timeline(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        let now = kube::now_secs();
        let mut range = if self.incident.range == 0 { 6 * 3600 } else { self.incident.range };
        ui.horizontal(|ui| {
            for (t, s) in [("1 hour", 3600), ("6 hours", 6 * 3600), ("1 day", 86400), ("7 days", 7 * 86400)] {
                if chip_button(ui, t, range == s) {
                    range = s;
                    self.incident.open = None;
                }
            }
            ui.add_space(14.0);
            for (i, t) in LANES.iter().enumerate() {
                if chip_button(ui, t, !self.incident.hide[i]) {
                    self.incident.hide[i] = !self.incident.hide[i];
                    self.incident.open = None;
                }
            }
        });
        self.incident.range = range;
        said(ui, &format!("Watching for {}: details of changes are kept while Kubedog is open. Rollouts, warnings, restarts and who wrote what also reach back before that.", kube::human_duration((now - self.incident.since).max(0))), TEXT_PLACEHOLDER());
        ui.add_space(6.0);
        let q = self.search.to_lowercase();
        let hide = self.incident.hide;
        let all: Vec<Moment> = self.moments(range).into_iter().filter(|m| !hide[m.lane] && (q.is_empty() || m.title.to_lowercase().contains(&q) || m.detail.to_lowercase().contains(&q))).collect();
        // The picture: a lane each, dots over time.
        card(ui, |ui| {
            let h = u(34.0);
            let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), h * 4.0 + u(22.0)), Sense::hover());
            let left = r.left() + u(90.0);
            let x = |t: i64| left + (r.right() - 8.0 - left) * (1.0 - (now - t) as f32 / range as f32).clamp(0.0, 1.0);
            for (i, t) in LANES.iter().enumerate() {
                let y = r.top() + h * (i as f32 + 0.5);
                label_at(ui, ui.painter(), egui::pos2(r.left(), y), t, 12.0, if hide[i] { TEXT_PLACEHOLDER() } else { TEXT_MUTED() }, u(86.0));
                ui.painter().hline(left..=r.right(), y, Stroke::new(1.0, BORDER_SUBTLE()));
            }
            for i in 0..=6 {
                let t = now - range + range * i / 6;
                let px = x(t);
                ui.painter().vline(px, r.top()..=(r.top() + h * 4.0), Stroke::new(1.0, BORDER_SUBTLE().gamma_multiply(0.5)));
                let w = if i == 6 { "now".to_string() } else { format!("{} ago", kube::human_duration(now - t)) };
                ui.painter().text(egui::pos2(px, r.bottom()), if i == 0 { egui::Align2::LEFT_BOTTOM } else if i == 6 { egui::Align2::RIGHT_BOTTOM } else { egui::Align2::CENTER_BOTTOM }, w, FontId::proportional(z(10.5)), TEXT_PLACEHOLDER());
            }
            // Dots that fall together make a bigger one.
            let mut heap: HashMap<(usize, i32), (usize, Tone)> = HashMap::new();
            for m in &all {
                let e = heap.entry((m.lane, (x(m.at) / 7.0) as i32)).or_insert((0, m.tone));
                e.0 += 1;
                if m.tone == Tone::Danger {
                    e.1 = Tone::Danger;
                }
            }
            for ((lane, cell), (n, tone)) in heap {
                let y = r.top() + h * (lane as f32 + 0.5);
                let col = if tone == Tone::Muted { TEXT_SUBTLE() } else { tone_color(tone) };
                ui.painter().circle_filled(egui::pos2(cell as f32 * 7.0 + 3.5, y), u(3.0) + (n as f32).sqrt().min(7.0) * 1.1, col.gamma_multiply(0.75));
            }
        });
        ui.add_space(10.0);
        card(ui, |ui| {
            panel(ui, &format!("What happened ({})", all.len()), "newest first; click a line for before and after, or to open the object");
            ui.spacing_mut().item_spacing.y = 0.0;
            if all.is_empty() {
                said(ui, "Nothing in this time.", TEXT_SUBTLE());
            }
            for (i, m) in all.iter().enumerate().take(250) {
                let (r, resp) = dash::line(ui, u(28.0), true);
                let col = if m.tone == Tone::Muted { TEXT_SUBTLE() } else { tone_color(m.tone) };
                ui.painter().circle_filled(egui::pos2(r.left() + u(5.0), r.center().y), u(4.5), col);
                label_at(ui, ui.painter(), egui::pos2(r.left() + u(18.0), r.center().y), &ago(now, Some(m.at)), 12.0, TEXT_SUBTLE(), u(80.0));
                label_at(ui, ui.painter(), egui::pos2(r.left() + u(104.0), r.center().y), &m.title, 13.0, TEXT_DEFAULT(), r.width() * 0.38);
                label_at(ui, ui.painter(), egui::pos2(r.left() + u(120.0) + r.width() * 0.38, r.center().y), &m.detail.replace('\n', " "), 12.5, col, r.width() * 0.62 - u(130.0));
                if resp.on_hover_text(format!("{}\n{}\n{}", pod::when(m.at), m.title, m.detail)).clicked() {
                    self.incident.open = if self.incident.open == Some(i) { None } else { Some(i) };
                }
                if self.incident.open == Some(i) {
                    Frame::new().fill(BG_SUBTLE()).corner_radius(CornerRadius::same(8)).inner_margin(Margin::same(10)).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.spacing_mut().item_spacing.y = 4.0;
                        said(ui, &format!("{}: {}", pod::when(m.at), m.detail), TEXT_MUTED());
                        diff_table(ui, &m.diff);
                        ui.horizontal(|ui| {
                            if m.go.is_some() && button(ui, "Open it", false, false) {
                                go = m.go.clone();
                            }
                            if let Some(s) = m.sel.clone().filter(|s| work::is_work(s.kind) || matches!(s.kind, Kind::Pods | Kind::Services | Kind::Ingresses)) {
                                if button(ui, "Why is it broken?", false, false) {
                                    self.incident.sel = Some(s);
                                    self.incident.tab = 1;
                                }
                            }
                        });
                    });
                }
            }
            if all.len() > 250 {
                said(ui, &format!("and {} more: pick a shorter time or filter", all.len() - 250), TEXT_PLACEHOLDER());
            }
        });
        go
    }
}

/// Before and after, next to each other.
pub(super) fn diff_table(ui: &mut Ui, diff: &[(String, String, String)]) {
    for (what, a, b) in diff.iter().filter(|d| !d.1.is_empty() || !d.2.is_empty()).take(60) {
        // Of long texts only what's around the first difference.
        let (a, b) = if a.len() + b.len() > 600 { around(a, b) } else { (a.clone(), b.clone()) };
        ui.horizontal_top(|ui| {
            let w = ui.available_width();
            left_cell(ui, [w * 0.22, z(18.0)], egui::Label::new(RichText::new(what).size(z(12.5)).color(TEXT_MUTED())).truncate());
            for (t, col) in [(&a, DANGER()), (&b, SUCCESS())] {
                ui.allocate_ui_with_layout(egui::vec2(w * 0.37, 0.0), Layout::top_down(Align::Min), |ui| {
                    ui.set_width(w * 0.37);
                    let none = t.is_empty();
                    ui.add(egui::Label::new(RichText::new(if none { "(not there)" } else { t.as_str() }).monospace().size(z(12.0)).color(if none { TEXT_PLACEHOLDER() } else { col })).wrap());
                });
            }
        });
    }
}

/// The lines around the first difference of two texts.
fn around(a: &str, b: &str) -> (String, String) {
    let (la, lb): (Vec<&str>, Vec<&str>) = (a.lines().collect(), b.lines().collect());
    let first = la.iter().zip(&lb).take_while(|(x, y)| x == y).count();
    let from = first.saturating_sub(2);
    let cut = |l: &[&str]| l.iter().skip(from).take(12).copied().collect::<Vec<_>>().join("\n");
    (cut(&la), cut(&lb))
}

pub(super) fn tab_strip(ui: &mut Ui, tabs: &[&str], at: &mut usize) {
    for (i, t) in tabs.iter().enumerate() {
        let on = *at == i;
        if ui.add(egui::Button::new(RichText::new(*t).color(if on { TEXT_DEFAULT() } else { TEXT_SUBTLE() })).fill(if on { BG_MUTED() } else { Color32::TRANSPARENT }).stroke(Stroke::NONE)).clicked() {
            *at = i;
        }
    }
}

pub(super) fn chip_button(ui: &mut Ui, t: &str, on: bool) -> bool {
    ui.add(egui::Button::new(RichText::new(t).size(z(12.5)).color(if on { PRIMARY_TEXT() } else { TEXT_SUBTLE() })).fill(if on { PRIMARY_TEXT().gamma_multiply(0.14) } else { BG_MUTED() }).stroke(Stroke::NONE).corner_radius(CornerRadius::same(6))).clicked()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn what_changed() {
        let dep = |img: &str, n: i64, env: Value| json!({"spec": {"replicas": n, "template": {"spec": {"containers": [{"name": "web", "image": img, "env": env}]}}}});
        let a = digest(Kind::Deployments, &dep("web:1", 2, json!([{"name": "A", "value": "x"}, {"name": "P", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}])));
        let b = digest(Kind::Deployments, &dep("web:2", 2, json!([{"name": "A", "value": "x"}])));
        assert_eq!(a["web env P"], "from secret s, k");
        let d = differences(&a, &b);
        assert_eq!(d, vec![("web env P".to_string(), "from secret s, k".into(), String::new()), ("web image".into(), "web:1".into(), "web:2".into())]);
        assert!(differences(&a, &a).is_empty());
        let n = digest(Kind::Nodes, &json!({"spec": {"unschedulable": true}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}));
        assert_eq!((n["scheduling"].as_str(), n["Ready"].as_str()), ("off", "True"));
        // Secrets have nothing to compare.
        assert!(digest(Kind::Secrets, &json!({"data": {"k": "dmFsdWU="}})).is_empty());
        assert_eq!(around("a\nb\nc\nd", "a\nb\nX\nd"), ("a\nb\nc\nd".to_string(), "a\nb\nX\nd".to_string()));
    }
}
