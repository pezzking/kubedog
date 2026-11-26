//! A pod's page: is it well, a live X-ray of what goes in and out, a card per container, how it
//! came up, and what it is made of. Its other tabs are in podnet.rs (environment, network),
//! podplace.rs (scheduling, what if) and podfiles.rs (storage, files).

use super::dash::{at, at_end, grid, line};
use super::face::{Face, Fact};
use super::pg::{label_at, pill, spark};
use super::*;
use std::collections::VecDeque;

/// What a request of this page was for. Answers for a page that's closed are dropped.
pub(super) enum Ask {
    Top,
    SecretValue(String, String),
    SecretKeys(String),
    List(String),
    Open(String),
    Df(String),
    Changed(Vec<String>),
    /// Routes of the namespace (for a context).
    Routes(String),
}

pub(super) type Reading = (i64, HashMap<String, (f64, f64)>);

#[derive(Default)]
pub(super) struct PodPage {
    next: u64,
    asked: HashMap<u64, Ask>,
    /// CPU (m) and memory (B) of each container, oldest first.
    pub tops: VecDeque<Reading>,
    top_at: Option<Instant>,
    pub top_err: Option<String>,
    /// Secret values shown: (secret, key) -> the value, or None while it's read. Memory only.
    pub shown: HashMap<(String, String), Option<Result<String, String>>>,
    pub keys: HashMap<String, Option<Result<Vec<String>, String>>>,
    /// The Environment tab is sorted by source instead of name.
    pub env_by_source: bool,
    pub files: podfiles::Files,
    pub df: HashMap<String, Option<Result<Vec<podfiles::Df>, String>>>,
    /// "configmap/name" -> when it was last changed.
    pub changed: HashMap<String, i64>,
    pub changed_asked: HashSet<String>,
    /// Routes that lead to services of its namespace.
    pub routes: Vec<podxray::Entry>,
    routes_at: Option<Instant>,
    /// Clusters that don't know OpenShift routes (kept between pods).
    no_routes: HashSet<String>,
}

impl PodPage {
    pub fn reset(&mut self) {
        let next = self.next;
        let no_routes = std::mem::take(&mut self.no_routes);
        *self = PodPage { next, no_routes, ..Default::default() };
    }
}

// ---------- reading a pod ----------

pub(super) fn cond<'a>(o: &'a Value, t: &str) -> Option<&'a Value> {
    o["status"]["conditions"].as_array()?.iter().find(|c| c["type"] == t)
}

pub(super) fn time_of(v: &Value) -> Option<i64> {
    v.as_str().and_then(kube::parse_time)
}

pub(super) fn containers(o: &Value) -> &[Value] {
    o["spec"]["containers"].as_array().map(|a| a.as_slice()).unwrap_or(&[])
}

pub(super) fn status_of<'a>(o: &'a Value, list: &str, name: &str) -> Option<&'a Value> {
    o["status"][list].as_array()?.iter().find(|s| s["name"].as_str() == Some(name))
}

/// A container's state in a word, and how bad it is.
pub(super) fn state_word(s: Option<&Value>) -> (String, Tone) {
    let Some(s) = s else { return ("Not started".into(), Tone::Muted) };
    let st = &s["state"];
    if st["running"].is_object() {
        if s["ready"].as_bool() == Some(true) { ("Running".into(), Tone::Success) } else { ("Not ready".into(), Tone::Warning) }
    } else if let Some(r) = st["waiting"]["reason"].as_str() {
        (r.to_string(), if matches!(r, "ContainerCreating" | "PodInitializing") { Tone::Info } else { Tone::Danger })
    } else if st["terminated"].is_object() {
        let code = st["terminated"]["exitCode"].as_i64().unwrap_or(0);
        let r = st["terminated"]["reason"].as_str().unwrap_or("Ended");
        // The node made this up, exit code and all: the container was gone when it looked.
        if r == "ContainerStatusUnknown" {
            return ("Container lost".into(), Tone::Danger);
        }
        (if code == 0 { r.to_string() } else { format!("{r} (exit {code})") }, if code == 0 { Tone::Muted } else { Tone::Danger })
    } else {
        ("Waiting".into(), Tone::Info)
    }
}

/// How the last run of a container ended: "OOMKilled (exit 137), 2h ago".
fn last_end(s: &Value, now: i64) -> Option<(String, i64)> {
    let t = &s["lastState"]["terminated"];
    let at = time_of(&t["finishedAt"])?;
    let reason = t["reason"].as_str().unwrap_or("ended");
    Some((format!("{reason} (exit {}), {} ago", t["exitCode"].as_i64().unwrap_or(0), kube::human_duration((now - at).max(0))), at))
}

/// Is it well? A sentence, how bad, and what else to know.
pub(super) fn verdict(o: &Value, now: i64) -> (Tone, String, Vec<String>) {
    let st = &o["status"];
    let mut notes: Vec<String> = vec![];
    let ago = |t: Option<i64>| t.map(|t| format!("{} ago", kube::human_duration((now - t).max(0)))).unwrap_or_default();
    if let Some(t) = time_of(&o["metadata"]["deletionTimestamp"]) {
        if now > t {
            notes.push(format!("It should have been gone {} ago; something holds it back (a finalizer, or its node doesn't answer).", kube::human_duration(now - t)));
        }
        return (Tone::Info, "Shutting down".into(), notes);
    }
    let phase = st["phase"].as_str().unwrap_or("");
    if phase == "Succeeded" {
        return (Tone::Muted, "Finished its work".into(), notes);
    }
    if phase == "Failed" {
        if let Some(m) = st["message"].as_str().or(st["reason"].as_str()) {
            notes.push(m.to_string());
        }
        for s in st["containerStatuses"].as_array().into_iter().flatten() {
            // When the pod itself is why, that nobody saw its containers end says nothing.
            if s["state"]["terminated"]["reason"] == "ContainerStatusUnknown" && resources::pod_over(o).is_some() {
                continue;
            }
            if let Some(c) = s["state"]["terminated"]["exitCode"].as_i64().filter(|c| *c != 0) {
                notes.push(format!("{} ended with {c} ({})", s["name"].as_str().unwrap_or(""), s["state"]["terminated"]["reason"].as_str().unwrap_or("no reason given")));
            }
        }
        return (Tone::Danger, if st["reason"] == "Evicted" { if resources::rejected(o) { "Rejected by its node" } else { "Evicted from its node" }.into() } else { "Failed".into() }, notes);
    }
    if let Some(c) = cond(o, "PodScheduled").filter(|c| c["status"] == "False") {
        notes.push(c["message"].as_str().unwrap_or("No node fits yet.").to_string());
        return (Tone::Danger, "No node found for it yet".into(), notes);
    }
    for (list, init) in [("initContainerStatuses", true), ("containerStatuses", false)] {
        for s in st[list].as_array().into_iter().flatten() {
            let name = s["name"].as_str().unwrap_or("");
            let w = &s["state"]["waiting"];
            let reason = w["reason"].as_str().unwrap_or("");
            let failed_init = init && s["state"]["terminated"]["exitCode"].as_i64().map(|c| c != 0).unwrap_or(false);
            let head = match reason {
                "CrashLoopBackOff" => format!("{name} keeps crashing"),
                "ImagePullBackOff" | "ErrImagePull" | "InvalidImageName" | "ErrImageNeverPull" => format!("The image of {name} can't be fetched"),
                "CreateContainerConfigError" | "CreateContainerError" | "RunContainerError" => format!("{name} can't be started"),
                _ if failed_init => format!("{name} failed before the pod could start"),
                _ => continue,
            };
            if reason.contains("mage") {
                notes.push(s["image"].as_str().unwrap_or("").to_string());
            }
            if let Some((t, _)) = last_end(s, now) {
                notes.push(format!("Last time: {t}; {} restarts so far.", s["restartCount"].as_i64().unwrap_or(0)));
            } else if let Some(m) = w["message"].as_str() {
                notes.push(m.to_string());
            }
            return (Tone::Danger, if init { format!("Stuck at the start: {head}") } else { head }, notes);
        }
    }
    let ready = cond(o, "Ready").map(|c| c["status"] == "True").unwrap_or(false);
    if !ready {
        let waiting: Vec<&str> = st["containerStatuses"].as_array().into_iter().flatten().filter(|s| s["ready"].as_bool() != Some(true)).filter_map(|s| s["name"].as_str()).collect();
        if phase == "Pending" || cond(o, "Initialized").map(|c| c["status"] == "False").unwrap_or(false) {
            let busy = st["initContainerStatuses"].as_array().into_iter().flatten().find(|s| s["state"]["running"].is_object()).and_then(|s| s["name"].as_str());
            if let Some(b) = busy {
                notes.push(format!("Busy with {b}."));
            }
            return (Tone::Info, "Starting".into(), notes);
        }
        let since = cond(o, "Ready").and_then(|c| time_of(&c["lastTransitionTime"]));
        notes.push(format!("Waiting for {}{}. It gets no traffic meanwhile.", if waiting.is_empty() { "a readiness gate".to_string() } else { waiting.join(", ") }, since.map(|t| format!(" since {}", ago(Some(t)))).unwrap_or_default()));
        return (Tone::Warning, "Running, but not ready".into(), notes);
    }
    let recent = st["containerStatuses"].as_array().into_iter().flatten().filter_map(|s| last_end(s, now).map(|e| (s["name"].as_str().unwrap_or("").to_string(), e))).filter(|x| now - x.1 .1 < 86_400).max_by_key(|x| x.1 .1);
    if let Some((name, (t, _))) = recent {
        notes.push(format!("{name}: {t}"));
        return (Tone::Warning, "Running, after a restart".into(), notes);
    }
    (Tone::Success, "Running well".into(), notes)
}

/// How it came up: (phase, seconds), from being made to being ready. None when a restart hid it.
pub(super) fn startup(o: &Value) -> Option<Vec<(String, i64)>> {
    let st = &o["status"];
    let fresh = |l: &str| st[l].as_array().into_iter().flatten().all(|s| s["restartCount"].as_i64().unwrap_or(0) == 0);
    if !fresh("containerStatuses") || !fresh("initContainerStatuses") {
        return None;
    }
    let met = |t: &str| cond(o, t).filter(|c| c["status"] == "True").and_then(|c| time_of(&c["lastTransitionTime"]));
    let mut now = time_of(&o["metadata"]["creationTimestamp"])?;
    let mut out: Vec<(String, i64)> = vec![];
    let mut step = |name: String, until: Option<i64>| {
        if let Some(t) = until {
            out.push((name, (t - now).max(0)));
            now = now.max(t);
        }
    };
    step("finding a node".into(), Some(met("PodScheduled")?));
    step("network and volumes".into(), met("PodReadyToStartContainers"));
    for c in o["spec"]["initContainers"].as_array().into_iter().flatten() {
        let name = c["name"].as_str().unwrap_or("");
        step(format!("init: {name}"), status_of(o, "initContainerStatuses", name).and_then(|s| time_of(&s["state"]["terminated"]["finishedAt"])));
    }
    let started: Vec<i64> = st["containerStatuses"].as_array()?.iter().filter_map(|s| time_of(&s["state"]["running"]["startedAt"])).collect();
    step("images and start".into(), Some(*started.iter().max()?));
    step("getting ready".into(), Some(met("Ready")?));
    // A readiness that changed much later says nothing about the start.
    let total: i64 = out.iter().map(|x| x.1).sum();
    (total < 6 * 3600).then_some(out)
}

/// What a container asks for and may use: (cpu ask, cpu limit, memory ask, memory limit); 0 = none.
pub(super) fn asks(c: &Value) -> (f64, f64, f64, f64) {
    let r = &c["resources"];
    let g = |a: &str, k: &str| r[a][k].as_str().unwrap_or("").to_string();
    let (cl, ml) = (resources::cpu_milli(&g("limits", "cpu")), resources::mem_bytes(&g("limits", "memory")));
    let or = |v: f64, l: f64| if v > 0.0 { v } else { l };
    (or(resources::cpu_milli(&g("requests", "cpu")), cl), cl, or(resources::mem_bytes(&g("requests", "memory")), ml), ml)
}

pub(super) fn plain(b: f64, cpu: bool) -> String {
    if cpu { hive::cores(b) } else { gib(b) }
}

// ---------- requests ----------

impl KubedogApp {
    pub(super) fn pod_ask(&mut self, what: Ask, f: impl FnOnce(&Kubectl) -> Result<String, String> + Send + 'static) {
        if self.demo {
            return;
        }
        self.pod.next += 1;
        let id = self.pod.next;
        self.pod.asked.insert(id, what);
        self.spawn(move |k| Msg::Text { key: format!("podx|{id}"), result: f(k) });
    }

    pub(super) fn on_pod(&mut self, key: &str, result: &Result<String, String>) -> bool {
        let Some(id) = key.strip_prefix("podx|").and_then(|x| x.parse::<u64>().ok()) else { return false };
        let Some(what) = self.pod.asked.remove(&id) else { return true };
        match what {
            Ask::Top => match result {
                Ok(t) => {
                    let m = parse_top(t);
                    self.pod.top_err = None;
                    if !m.is_empty() {
                        self.pod.tops.push_back((kube::now_secs(), m));
                        while self.pod.tops.len() > 240 {
                            self.pod.tops.pop_front();
                        }
                    }
                }
                Err(e) => self.pod.top_err = Some(if is_refusal(e) { "your account can't read usage".into() } else { truncate(e, 160) }),
            },
            Ask::SecretValue(s, k) => {
                self.pod.shown.insert((s, k), Some(result.clone()));
            }
            Ask::SecretKeys(s) => {
                self.pod.keys.insert(s, Some(result.as_ref().map(|t| t.lines().map(|l| l.to_string()).filter(|l| !l.is_empty()).collect()).map_err(|e| e.clone())));
            }
            Ask::List(path) => self.pod.files.listed(&path, result),
            Ask::Open(path) => self.pod.files.opened(&path, result),
            Ask::Df(c) => {
                self.pod.df.insert(c, Some(result.as_ref().map(|t| podfiles::parse_df(t)).map_err(|e| e.clone())));
            }
            Ask::Routes(ctx) => {
                if let Some((list, known)) = result.as_ref().ok().and_then(|t| podxray::unpack(t)) {
                    self.pod.routes = list;
                    if !known {
                        self.pod.no_routes.insert(ctx);
                    }
                }
            }
            Ask::Changed(_) => {
                if let Ok(t) = result {
                    for (k, t) in podplace::parse_changed(t) {
                        self.pod.changed.insert(k, t);
                    }
                }
            }
        }
        true
    }

    /// Usage of each container of the open pod.
    pub(super) fn refresh_pod(&mut self, force: bool) {
        let Some(s) = self.selected.clone().filter(|s| s.kind == Kind::Pods || s.kind == Kind::Services || work::is_work(s.kind)) else { return };
        // The routes to its services, once a minute.
        let asking = self.pod.asked.values().any(|a| matches!(a, Ask::Routes(_)));
        if !asking && (force || self.pod.routes_at.map(|t| t.elapsed() >= Duration::from_secs(60)).unwrap_or(true)) {
            self.pod.routes_at = Some(Instant::now());
            self.sync_crds();
            let openshift = !self.pod.no_routes.contains(&s.ctx);
            let http = self.crd_index("httproutes.gateway.networking.k8s.io").is_some();
            if openshift || http {
                let (ctx, ns) = (s.ctx.clone(), s.ns.clone());
                self.pod_ask(Ask::Routes(s.ctx.clone()), move |k| {
                    let (list, known) = podxray::read_routes(k, &ctx, &ns, openshift, http);
                    Ok(podxray::pack(&list, known || !openshift))
                });
            }
        }
        if s.kind != Kind::Pods {
            return;
        }
        let every = Duration::from_secs(self.prefs.metrics_secs.max(1));
        let busy = self.pod.asked.values().any(|a| matches!(a, Ask::Top));
        if busy || !(force || self.pod.top_at.map(|t| t.elapsed() >= every).unwrap_or(true)) {
            return;
        }
        self.pod.top_at = Some(Instant::now());
        let args: Vec<String> = ["--context", &s.ctx, "-n", &s.ns, "top", "pod", &s.name, "--containers", "--no-headers", &format!("--request-timeout={}", kube::REQUEST_TIMEOUT)].iter().map(|x| x.to_string()).collect();
        self.pod_ask(Ask::Top, move |k| k.run(&args));
    }

    /// Put a secret's value on the page, after a click.
    pub(super) fn pod_reveal(&mut self, sel: &Selected, secret: &str, key: &str) {
        if self.screenshot.is_some() {
            return;
        }
        let (ctx, ns, s, k) = (sel.ctx.clone(), sel.ns.clone(), secret.to_string(), key.to_string());
        self.pod.shown.insert((s.clone(), k.clone()), None);
        self.pod_ask(Ask::SecretValue(s.clone(), k.clone()), move |kc| login::secret_value(kc, &ctx, &ns, &s, &k));
    }

    /// The names in a secret, without their values.
    pub(super) fn pod_secret_keys(&mut self, sel: &Selected, secret: &str) {
        self.pod.keys.insert(secret.to_string(), None);
        let args: Vec<String> = ["--context", &sel.ctx, "-n", &sel.ns, "get", "secret", secret, "-o", "go-template={{range $k, $v := .data}}{{$k}}{{\"\\n\"}}{{end}}"].iter().map(|x| x.to_string()).collect();
        self.pod_ask(Ask::SecretKeys(secret.to_string()), move |k| k.run(&args));
    }

    pub(super) fn pod_logs_of(&mut self, sel: &Selected, container: &str) {
        self.log_prefs.container = container.to_string();
        self.set_tab(Tab::Logs, sel);
    }

    // ---------- the overview ----------

    pub(super) fn pod_overview(&mut self, ui: &mut Ui, sel: &Selected, o: &Value) {
        let mut open: Option<Selected> = None;
        let mut go = None;
        let now = kube::now_secs();
        self.page_scroll().id_salt("pod-overview").show(ui, |ui| {
            self.pg_pod_panel(ui, sel, o);
            self.pod_health(ui, o, now, &mut open, sel);
            ui.add_space(12.0);
            go = self.pod_xray(ui, sel, o);
            ui.add_space(12.0);
            self.pod_cards(ui, sel, o, now);
            ui.add_space(12.0);
            startup_panel(ui, o, now);
            if let Some(s) = face::meta(ui, &sel.key(), &self.refs_of(sel, o), o) {
                open = Some(s);
            }
            ui.add_space(20.0);
        });
        if let Some(g) = go {
            self.follow(g, sel);
        }
        if let Some(s) = open {
            self.navigate(View::Resource(s.kind), Some(s));
        }
        if ui.input(|i| i.viewport().focused.unwrap_or(false)) {
            ui.ctx().request_repaint_after(Duration::from_millis(45));
        }
    }

    /// Go where a click in an X-ray leads.
    pub(super) fn follow(&mut self, go: podxray::Go, sel: &Selected) {
        match go {
            podxray::Go::Object(s) => self.navigate(View::Resource(s.kind), Some(s)),
            podxray::Go::Tab(t) => self.set_tab(t, sel),
            podxray::Go::Custom(s) => {
                let i = s.idx;
                self.open_custom(i);
                self.custom_tab = 0;
                self.custom_sel = Some(s);
                self.refresh_custom(i, true);
            }
        }
    }

    /// What owns it, as a link when Kubedog knows the kind.
    pub(super) fn owner_fact(&self, sel: &Selected, o: &Value) -> Fact {
        let own = &o["metadata"]["ownerReferences"][0];
        let (k, n) = (own["kind"].as_str().unwrap_or(""), own["name"].as_str().unwrap_or(""));
        let f = Fact::new("Controlled by", format!("{k} {n}"));
        match workload::kind_named(k) {
            Some(kind) => f.to(Selected { ctx: sel.ctx.clone(), kind, ns: if kind.namespaced() { sel.ns.clone() } else { String::new() }, name: n.into() }),
            None => f,
        }
    }

    /// Is it well: the sentence, the heartbeat, the conditions, and the facts people look for.
    fn pod_health(&self, ui: &mut Ui, o: &Value, now: i64, open: &mut Option<Selected>, sel: &Selected) {
        let (tone, head, notes) = verdict(o, now);
        let st = &o["status"];
        // Conditions, in the order they're met.
        let mut pills = vec![];
        for (t, name) in [("PodScheduled", "Scheduled"), ("PodReadyToStartContainers", "Sandbox ready"), ("Initialized", "Initialized"), ("ContainersReady", "Containers ready"), ("Ready", "Ready")] {
            let Some(c) = cond(o, t) else { continue };
            let yes = c["status"] == "True";
            let at = time_of(&c["lastTransitionTime"]);
            let done = matches!(st["phase"].as_str(), Some("Succeeded"));
            let cc = if yes { SUCCESS() } else if done { TEXT_SUBTLE() } else { WARNING() };
            let tip = format!("{t}: {}{}\n{}", c["status"].as_str().unwrap_or(""), at.map(|t| format!(", since {}", when(t))).unwrap_or_default(), c["message"].as_str().or(c["reason"].as_str()).unwrap_or(""));
            pills.push((format!("{} {name}{}", if yes { "●" } else { "○" }, at.map(|t| format!("  {}", kube::human_duration((now - t).max(0)))).unwrap_or_default()), cc, tip.trim().to_string()));
        }
        // Others, such as readiness gates.
        for c in st["conditions"].as_array().into_iter().flatten() {
            let t = c["type"].as_str().unwrap_or("");
            if !matches!(t, "PodScheduled" | "PodReadyToStartContainers" | "Initialized" | "ContainersReady" | "Ready") {
                pills.push((format!("{t}: {}", c["status"].as_str().unwrap_or("")), TEXT_MUTED(), c["message"].as_str().unwrap_or("").to_string()));
            }
        }
        let (ready, total) = (st["containerStatuses"].as_array().into_iter().flatten().filter(|s| s["ready"] == true).count(), containers(o).len());
        let restarts: i64 = st["containerStatuses"].as_array().into_iter().flatten().map(|s| s["restartCount"].as_i64().unwrap_or(0)).sum();
        let node = match o["spec"]["nodeName"].as_str() {
            Some(n) => Fact::new("Node", n).to(Selected { ctx: sel.ctx.clone(), kind: Kind::Nodes, ns: String::new(), name: n.into() }),
            None => Fact::new("Node", "none yet").col(WARNING()),
        };
        let owner = match o["metadata"]["ownerReferences"][0]["name"].as_str() {
            Some(_) => self.owner_fact(sel, o),
            None => Fact::new("Controlled by", "nothing: not recreated if deleted"),
        };
        let warn = |on: bool| if on { WARNING() } else { TEXT_DEFAULT() };
        let f = Face {
            tone,
            head,
            sub: time_of(&st["startTime"]).map(|t| format!("started {} ago, {}", kube::human_duration((now - t).max(0)), when(t))).unwrap_or_else(|| "not started yet".into()),
            notes,
            pills,
            facts: vec![
                Fact::new("Containers ready", format!("{ready} of {total}")).col(warn(ready != total)),
                Fact::new("Restarts", restarts.to_string()).col(warn(restarts > 0)),
                node,
                owner,
                Fact::new("Pod IP", st["podIP"].as_str().unwrap_or("-")),
                Fact::new("Service account", o["spec"]["serviceAccountName"].as_str().unwrap_or("default")),
                Fact::new("QoS class", match st["qosClass"].as_str().unwrap_or("") { x => x }),
                Fact::new("Created", o["metadata"]["creationTimestamp"].as_str().map(kube::age).map(|a| format!("{a} ago")).unwrap_or_default()),
            ],
        };
        let share = self.pod.tops.back().map(|t| t.1.values().map(|x| x.0).sum::<f64>()).unwrap_or(0.0);
        if let Some(s) = face::show(ui, &f, face::Side::Beat(share)) {
            *open = Some(s);
        }
    }

    /// A card per container.
    fn pod_cards(&mut self, ui: &mut Ui, sel: &Selected, o: &Value, now: i64) {
        let cs = containers(o).to_vec();
        let mut act: Option<(u8, String)> = None;
        let tops = &self.pod.tops;
        grid(ui, cs.len(), u(400.0), u(240.0), 12.0, |ui, i, r| {
            let c = &cs[i];
            let name = c["name"].as_str().unwrap_or("").to_string();
            let s = status_of(o, "containerStatuses", &name);
            let (word, tone) = state_word(s);
            let p = ui.painter().clone();
            p.rect_filled(r, CornerRadius::same(10), BG_CARD());
            p.rect_stroke(r, CornerRadius::same(10), Stroke::new(1.0, if tone == Tone::Success { BORDER_SUBTLE() } else { tone_color(tone).gamma_multiply(0.7) }), egui::StrokeKind::Inside);
            let inner = r.shrink2(egui::vec2(16.0, 12.0));
            // (A child of its own, so the grid keeps its place on the page.)
            let mut child = ui.new_child(egui::UiBuilder::new().max_rect(inner).layout(Layout::top_down(Align::Min)));
            (|ui: &mut Ui| {
                ui.set_clip_rect(ui.clip_rect().intersect(r));
                ui.spacing_mut().item_spacing.y = 4.0;
                let (h, _) = ui.allocate_exact_size(egui::vec2(inner.width(), u(22.0)), Sense::hover());
                let p = ui.painter();
                p.circle_filled(egui::pos2(h.left() + u(5.0), h.center().y), u(5.0), tone_color(tone));
                label_at(ui, p, egui::pos2(h.left() + u(18.0), h.center().y), &name, 15.0, TEXT_DEFAULT(), h.width() * 0.5);
                let since = s.and_then(|s| time_of(&s["state"]["running"]["startedAt"])).map(|t| format!(" for {}", kube::human_duration((now - t).max(0)))).unwrap_or_default();
                at_end(ui, h, 1.0, &format!("{word}{since}"), 12.0, tone_color(tone));
                let img = c["image"].as_str().unwrap_or("");
                let digest = s.and_then(|s| s["imageID"].as_str()).unwrap_or("");
                let (l, resp) = line(ui, u(20.0), true);
                at(ui, l, 0.0, 1.0, img, 12.0, TEXT_MUTED());
                if resp.on_hover_text(format!("{img}\n{digest}\nClick to copy")).clicked() {
                    ui.ctx().copy_text(img.to_string());
                }
                ui.add_space(2.0);
                let (cr, cl, mr, ml) = asks(c);
                let last = tops.back().and_then(|t| t.1.get(&name)).copied();
                for (cpu, label, used, ask, lim, col) in [(true, "CPU", last.map(|x| x.0), cr, cl, CPU_BAR()), (false, "Memory", last.map(|x| x.1), mr, ml, MEM_BAR())] {
                    usage_row(ui, label, used, ask, lim, cpu, col);
                    let v: Vec<f64> = tops.iter().filter_map(|t| t.1.get(&name)).map(|x| if cpu { x.0 } else { x.1 }).collect();
                    if v.len() > 1 {
                        spark(ui, &v, u(26.0), col, |x| plain(x, cpu));
                    } else {
                        let (e, _) = ui.allocate_exact_size(egui::vec2(inner.width(), u(26.0)), Sense::hover());
                        label_at(ui, ui.painter(), e.left_center(), "the chart fills while this page is open", 11.0, TEXT_PLACEHOLDER(), e.width());
                    }
                }
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    for (n, t) in [(0u8, "≡ Logs"), (1, ">_ Shell"), (2, "Files")] {
                        if button(ui, t, false, false) {
                            act = Some((n, name.clone()));
                        }
                    }
                    let rc = s.and_then(|s| s["restartCount"].as_i64()).unwrap_or(0);
                    if rc > 0 {
                        let end = s.and_then(|s| last_end(s, now)).map(|e| format!(", last: {}", e.0)).unwrap_or_default();
                        ui.add(egui::Label::new(RichText::new(format!("{rc} restart{}{end}", if rc == 1 { "" } else { "s" })).size(z(12.0)).color(WARNING())).truncate());
                    } else {
                        let ports: Vec<String> = c["ports"].as_array().into_iter().flatten().map(|p| p["containerPort"].to_string()).collect();
                        if !ports.is_empty() {
                            ui.add(egui::Label::new(RichText::new(format!("port {}", ports.join(", "))).size(z(12.0)).color(TEXT_SUBTLE())).truncate());
                        }
                    }
                });
            })(&mut child);
        });
        match act {
            Some((0, n)) => self.pod_logs_of(sel, &n),
            Some((1, n)) => self.open_shell(sel, &n),
            Some((_, n)) => {
                self.set_tab(Tab::Files, sel);
                self.files_start(sel, &n);
            }
            None => {}
        }
    }

    // ---------- containers in detail ----------

    pub(super) fn pod_containers(&mut self, ui: &mut Ui, sel: &Selected, o: &Value) {
        self.page_scroll().id_salt("pod-containers").show(ui, |ui| {
            for (list, stat, what) in [("containers", "containerStatuses", ""), ("initContainers", "initContainerStatuses", "Init container"), ("ephemeralContainers", "ephemeralContainerStatuses", "Ephemeral container")] {
                for c in o["spec"][list].as_array().into_iter().flatten() {
                    let name = c["name"].as_str().unwrap_or("");
                    let s = status_of(o, stat, name);
                    let (word, tone) = state_word(s);
                    card(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new(name).size(z(16.0)).color(TEXT_DEFAULT()));
                            if sel.kind == Kind::Pods {
                                pill(ui, &word, tone_color(tone));
                            }
                            let w = if c["restartPolicy"] == "Always" { "Sidecar: starts first and keeps running" } else { what };
                            if !w.is_empty() {
                                ui.label(RichText::new(w).size(z(12.0)).color(TEXT_SUBTLE()));
                            }
                        });
                        ui.add_space(4.0);
                        kv(ui, "Image", c["image"].as_str().unwrap_or(""));
                        if let Some(d) = s.and_then(|s| s["imageID"].as_str()).and_then(|d| d.split_once('@')).map(|x| x.1) {
                            kv(ui, "Image digest", d);
                        }
                        kv(ui, "Pull policy", match c["imagePullPolicy"].as_str() { Some("Always") => "Always", Some("Never") => "Never", _ => "IfNotPresent" });
                        let words = |k: &str| c[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" ")).filter(|x| !x.is_empty());
                        for (k, t) in [("command", "Command"), ("args", "Arguments")] {
                            let Some(x) = words(k) else { continue };
                            if x.lines().count() < 2 && x.chars().count() < 160 {
                                kv(ui, t, x);
                                continue;
                            }
                            // A script: folded.
                            kv(ui, t, format!("{}…", truncate(x.lines().next().unwrap_or(""), 140)));
                            egui::CollapsingHeader::new(RichText::new(format!("all {} lines", x.lines().count())).size(z(12.0)).color(TEXT_SUBTLE())).id_salt(("cmd", list, name, k)).show(ui, |ui| {
                                ui.add(egui::Label::new(RichText::new(truncate(&x, 20_000)).monospace().size(z(12.0)).color(TEXT_MUTED())).wrap());
                            });
                        }
                        if let Some(d) = c["workingDir"].as_str() {
                            kv(ui, "Working directory", d);
                        }
                        let ports: Vec<String> = c["ports"].as_array().into_iter().flatten().map(|p| format!("{}{}/{}", p["name"].as_str().map(|n| format!("{n} ")).unwrap_or_default(), p["containerPort"], p["protocol"].as_str().unwrap_or("TCP"))).collect();
                        if !ports.is_empty() {
                            kv(ui, "Ports", ports.join(", "));
                        }
                        let (cr, cl, mr, ml) = asks(c);
                        let some = |v: f64, cpu: bool| if v > 0.0 { plain(v, cpu) } else { "none".into() };
                        kv(ui, "CPU", format!("request {}, limit {}", some(cr, true), some(cl, true)));
                        kv(ui, "Memory", format!("request {}, limit {}", some(mr, false), some(ml, false)));
                        for (k, t) in [("startupProbe", "Startup probe"), ("readinessProbe", "Readiness probe"), ("livenessProbe", "Liveness probe")] {
                            if c[k].is_object() {
                                kv(ui, t, probe_words(&c[k]));
                            }
                        }
                        let sec = security_words(&c["securityContext"], &o["spec"]["securityContext"]);
                        kv(ui, "Security", sec.0);
                        if let Some(w) = sec.1 {
                            ui.label(RichText::new(w).size(z(12.5)).color(WARNING()));
                        }
                        let mounts = c["volumeMounts"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
                        if !mounts.is_empty() {
                            egui::CollapsingHeader::new(RichText::new(format!("{} mounts", mounts.len())).size(z(12.5)).color(TEXT_SUBTLE())).id_salt(("mounts", list, name)).show(ui, |ui| {
                                for m in mounts {
                                    ui.label(RichText::new(format!("{}  ←  {}{}", m["mountPath"].as_str().unwrap_or(""), m["name"].as_str().unwrap_or(""), if m["readOnly"] == true { "  (read only)" } else { "" })).monospace().size(z(12.0)).color(TEXT_MUTED()));
                                }
                            });
                        }
                    });
                    ui.add_space(8.0);
                }
            }
            ui.add_space(16.0);
        });
    }
}

/// `kubectl top pod --containers`: pod, container, cpu, memory.
fn parse_top(t: &str) -> HashMap<String, (f64, f64)> {
    t.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 4).then(|| (f[1].to_string(), (resources::cpu_milli(f[2]), resources::mem_bytes(f[3]))))
        })
        .collect()
}

pub(super) fn when(t: i64) -> String {
    let (h, m) = ((t.rem_euclid(86_400)) / 3600, (t.rem_euclid(3600)) / 60);
    format!("{} {h:02}:{m:02} UTC", netmap::iso_date(t))
}

fn probe_words(p: &Value) -> String {
    let what = if p["httpGet"].is_object() {
        format!("{} {}:{}{}", p["httpGet"]["scheme"].as_str().unwrap_or("HTTP").to_lowercase(), "port", p["httpGet"]["port"].to_string().trim_matches('"'), p["httpGet"]["path"].as_str().unwrap_or("/"))
    } else if p["tcpSocket"].is_object() {
        format!("port {} answers", p["tcpSocket"]["port"].to_string().trim_matches('"'))
    } else if p["grpc"].is_object() {
        format!("gRPC on port {}", p["grpc"]["port"])
    } else {
        format!("runs {}", truncate(&p["exec"]["command"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" ")).unwrap_or_default(), 120))
    };
    let n = |k: &str, d: i64| p[k].as_i64().unwrap_or(d);
    format!("{what}; every {}s, waits {}s, fails after {} misses", n("periodSeconds", 10), n("timeoutSeconds", 1), n("failureThreshold", 3))
}

/// In words, and a warning.
fn security_words(c: &Value, pod: &Value) -> (String, Option<String>) {
    let either = |k: &str| if c[k].is_null() { &pod[k] } else { &c[k] };
    let mut w = vec![];
    let uid = either("runAsUser").as_i64();
    match (uid, either("runAsNonRoot").as_bool()) {
        (Some(0), _) => w.push("runs as root".to_string()),
        (Some(u), _) => w.push(format!("runs as user {u}")),
        (None, Some(true)) => w.push("never as root".into()),
        _ => w.push("user set by the image".into()),
    }
    if c["readOnlyRootFilesystem"] == true {
        w.push("can't write to its own files".into());
    }
    if c["allowPrivilegeEscalation"] == false {
        w.push("can't gain rights".into());
    }
    let add: Vec<&str> = c["capabilities"]["add"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).collect();
    if !add.is_empty() {
        w.push(format!("extra rights: {}", add.join(", ")));
    }
    let warn = if c["privileged"] == true {
        Some("Privileged: it can do anything on its node.".to_string())
    } else if uid == Some(0) {
        Some("Root inside the container.".to_string())
    } else {
        None
    };
    (w.join(", "), warn)
}

// ---------- drawing ----------

pub(super) fn usage_row(ui: &mut Ui, label: &str, used: Option<f64>, ask: f64, lim: f64, cpu: bool, col: Color32) {
    let (r, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(30.0)), Sense::hover());
    let top = egui::Rect::from_min_size(r.min, egui::vec2(r.width(), u(17.0)));
    at(ui, top, 0.0, 0.2, label, 11.5, TEXT_SUBTLE());
    let v = used.map(|v| plain(v, cpu)).unwrap_or("–".into());
    at(ui, top, 0.18, 0.3, &v, 13.0, TEXT_DEFAULT());
    let share = |of: f64| used.filter(|_| of > 0.0).map(|v| format!(" ({:.0}%)", v / of * 100.0)).unwrap_or_default();
    let words = match (ask > 0.0, lim > 0.0) {
        (true, true) => format!("request {} · limit {}{}", plain(ask, cpu), plain(lim, cpu), share(lim)),
        (true, false) => format!("request {}{} · no limit", plain(ask, cpu), share(ask)),
        (false, true) => format!("limit {}{}", plain(lim, cpu), share(lim)),
        _ => "no request, no limit".into(),
    };
    at_end(ui, top, 1.0, &words, 11.5, TEXT_MUTED());
    let max = lim.max(ask).max(used.unwrap_or(0.0)).max(1.0);
    let b = egui::Rect::from_min_size(egui::pos2(r.left(), r.bottom() - 9.0), egui::vec2(r.width(), 7.0));
    let p = ui.painter();
    p.rect_filled(b, CornerRadius::same(3), BG_MUTED());
    // Against nothing there is no share to show.
    if let Some(v) = used.filter(|_| ask > 0.0 || lim > 0.0) {
        let near = lim > 0.0 && v / lim >= 0.9;
        p.rect_filled(egui::Rect::from_min_size(b.min, egui::vec2((b.width() * (v / max) as f32).max(2.0), b.height())), CornerRadius::same(3), if near { DANGER() } else if ask > 0.0 && v > ask { WARNING() } else { col });
    }
    if ask > 0.0 {
        let x = b.left() + b.width() * (ask / max) as f32;
        p.vline(x.min(b.right() - 1.0), (b.top() - 2.0)..=(b.bottom() + 2.0), Stroke::new(1.5, TEXT_MUTED()));
    }
    resp.on_hover_text("The bar ends at the limit; the mark is the request.");
}

/// Memory as a liquid: the level is the share used, the waves grow with CPU.
pub(super) fn tank(p: &egui::Painter, r: egui::Rect, level: f32, col: Color32, time: f32, cpu: f32, seed: f32) {
    let y = r.bottom() - r.height() * level.clamp(0.02, 1.0);
    let amp = (2.2 + cpu * 5.0).min((y - r.top()).max(0.6)).min((r.bottom() - y).max(0.6));
    let n = 72;
    for (k, a) in [(0.0f32, 0.28f32), (1.9, 0.36)] {
        let mut mesh = egui::Mesh::default();
        for i in 0..=n {
            let t = i as f32 / n as f32;
            let x = r.left() + r.width() * t;
            // Stay inside the rounded corners.
            let edge = (t.min(1.0 - t) * r.width()).min(12.0);
            let floor = r.bottom() - (12.0 - (144.0 - (12.0 - edge) * (12.0 - edge)).max(0.0).sqrt());
            let wave = y + (t * 7.0 + time * (0.8 + cpu * 3.0) + k + seed).sin() * amp;
            mesh.colored_vertex(egui::pos2(x, wave.clamp(r.top() + 12.0 - (144.0 - (12.0 - edge) * (12.0 - edge)).max(0.0).sqrt(), floor)), col.gamma_multiply(a));
            mesh.colored_vertex(egui::pos2(x, floor), col.gamma_multiply(a * 0.75));
            if i > 0 {
                let b = (i * 2) as u32;
                mesh.add_triangle(b - 2, b - 1, b);
                mesh.add_triangle(b - 1, b, b + 1);
            }
        }
        p.add(egui::Shape::mesh(mesh));
    }
}

/// A pulse that runs while the pod is well: faster with more CPU, flat when nothing runs.
pub(super) fn heartbeat(ui: &Ui, r: egui::Rect, col: Color32, tone: Tone, cpu: f64) {
    let p = ui.painter();
    let mid = r.center().y;
    let alive = matches!(tone, Tone::Success | Tone::Warning | Tone::Info);
    if !alive {
        p.hline(r.x_range(), mid, Stroke::new(1.5, col.gamma_multiply(0.6)));
        return;
    }
    let t = ui.input(|i| i.time) as f32;
    let rate = 0.55 + (cpu as f32 / 1000.0).sqrt().min(1.6) * 0.7;
    let beat = u(96.0);
    let shape = |x: f32| -> f32 {
        let d = |c: f32, w: f32| (-((x - c) / w).powi(2)).exp();
        d(0.30, 0.04) * 0.16 - d(0.42, 0.018) * 0.22 + d(0.47, 0.02) - d(0.53, 0.02) * 0.34 + d(0.70, 0.05) * 0.24
    };
    let n = (r.width() / 2.0) as usize;
    let mut pts = Vec::with_capacity(n);
    for i in 0..n {
        let x = r.left() + i as f32 * 2.0;
        let ph = ((x - r.left()) / beat - t * rate * 0.6).rem_euclid(1.0);
        pts.push(egui::pos2(x, mid - shape(ph) * r.height() * 0.42));
    }
    for (i, w) in pts.windows(2).enumerate() {
        let fade = (i as f32 / n as f32).powf(0.7);
        p.line_segment([w[0], w[1]], Stroke::new(1.7, col.gamma_multiply(0.12 + 0.75 * fade)));
    }
}

/// How it came up, as one bar.
fn startup_panel(ui: &mut Ui, o: &Value, now: i64) {
    let phases = startup(o);
    card(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("How it came up").size(z(14.5)).color(TEXT_DEFAULT()));
            match &phases {
                Some(l) => {
                    let total: i64 = l.iter().map(|x| x.1).sum();
                    ui.label(RichText::new(format!("ready {} after it was made", kube::human_duration(total))).size(z(12.0)).color(TEXT_SUBTLE()));
                }
                None => {
                    let again = o["status"]["containerStatuses"].as_array().into_iter().flatten().filter_map(|s| time_of(&s["state"]["running"]["startedAt"])).max().map(|t| format!(" The last container started {} ago.", kube::human_duration((now - t).max(0)))).unwrap_or_default();
                    ui.label(RichText::new(format!("Can't be seen anymore, or it isn't up yet: restarts and changes overwrite it.{again}")).size(z(12.0)).color(TEXT_SUBTLE()));
                }
            }
        });
        let Some(l) = phases else { return };
        let total = l.iter().map(|x| x.1).sum::<i64>().max(1) as f32;
        let cols = [INFO(), PRIMARY_TEXT(), WARNING(), CPU_BAR(), SUCCESS()];
        let colour = |i: usize| if i + 1 == l.len() { SUCCESS() } else if i + 2 == l.len() { CPU_BAR() } else { cols[i % 3] };
        ui.add_space(4.0);
        let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(20.0)), Sense::hover());
        // Every phase gets at least a sliver.
        let least = 4.0;
        let free = (r.width() - least * l.len() as f32).max(1.0);
        let mut x = r.left();
        for (i, (name, s)) in l.iter().enumerate() {
            let w = least + free * *s as f32 / total;
            let b = egui::Rect::from_min_size(egui::pos2(x, r.top()), egui::vec2((w - 1.5).max(1.0), r.height()));
            ui.painter().rect_filled(b, CornerRadius::same(4), colour(i).gamma_multiply(0.75));
            ui.interact(b, egui::Id::new(("startup", i)), Sense::hover()).on_hover_text(format!("{name}: {}", kube::human_duration(*s)));
            x += w;
        }
        ui.add_space(2.0);
        ui.horizontal_wrapped(|ui| {
            for (i, (name, s)) in l.iter().enumerate() {
                ui.label(RichText::new("●").size(z(10.0)).color(colour(i)));
                ui.label(RichText::new(format!("{name} {}", kube::human_duration(*s))).size(z(12.0)).color(TEXT_MUTED()));
                ui.add_space(8.0);
            }
        });
    });
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub fn pod(conds: &[(&str, &str, &str)], containers: Value) -> Value {
        serde_json::json!({
            "metadata": {"creationTimestamp": "2026-01-01T10:00:00Z"},
            "spec": {"containers": [{"name": "a", "image": "x/y:1"}], "initContainers": [{"name": "i"}]},
            "status": {"phase": "Running", "startTime": "2026-01-01T10:00:01Z",
                "conditions": conds.iter().map(|c| serde_json::json!({"type": c.0, "status": c.1, "lastTransitionTime": c.2})).collect::<Vec<_>>(),
                "initContainerStatuses": [{"name": "i", "restartCount": 0, "state": {"terminated": {"exitCode": 0, "finishedAt": "2026-01-01T10:00:10Z"}}}],
                "containerStatuses": containers}
        })
    }

    const UP: [(&str, &str, &str); 4] = [("PodScheduled", "True", "2026-01-01T10:00:01Z"), ("PodReadyToStartContainers", "True", "2026-01-01T10:00:04Z"), ("Initialized", "True", "2026-01-01T10:00:10Z"), ("Ready", "True", "2026-01-01T10:00:40Z")];

    #[test]
    fn well_and_unwell() {
        let now = kube::parse_time("2026-01-02T12:00:00Z").unwrap();
        let running = serde_json::json!([{"name": "a", "ready": true, "restartCount": 0, "state": {"running": {"startedAt": "2026-01-01T10:00:25Z"}}}]);
        let ok = pod(&UP, running.clone());
        assert_eq!(verdict(&ok, now).1, "Running well");
        assert_eq!(startup(&ok).unwrap().iter().map(|x| x.1).collect::<Vec<_>>(), vec![1, 3, 6, 15, 15]);
        // A restart within the day.
        let re = pod(&UP, serde_json::json!([{"name": "a", "ready": true, "restartCount": 1, "lastState": {"terminated": {"reason": "OOMKilled", "exitCode": 137, "finishedAt": "2026-01-02T10:00:00Z"}}, "state": {"running": {"startedAt": "2026-01-02T10:00:05Z"}}}]));
        let v = verdict(&re, now);
        assert!(v.0 == Tone::Warning && v.2[0].contains("OOMKilled (exit 137), 120m ago"), "{v:?}");
        assert!(startup(&re).is_none());
        let cases = [
            (serde_json::json!([{"name": "a", "ready": false, "restartCount": 9, "lastState": {"terminated": {"reason": "Error", "exitCode": 1, "finishedAt": "2026-01-02T11:59:00Z"}}, "state": {"waiting": {"reason": "CrashLoopBackOff"}}}]), "a keeps crashing"),
            (serde_json::json!([{"name": "a", "image": "x/y:1", "ready": false, "state": {"waiting": {"reason": "ImagePullBackOff", "message": "no"}}}]), "The image of a can't be fetched"),
            (serde_json::json!([{"name": "a", "ready": false, "state": {"waiting": {"reason": "CreateContainerConfigError", "message": "secret \"x\" not found"}}}]), "a can't be started"),
        ];
        for (c, want) in cases {
            let v = verdict(&pod(&[("PodScheduled", "True", "2026-01-01T10:00:01Z"), ("Ready", "False", "2026-01-02T11:00:00Z")], c), now);
            assert_eq!((v.0, v.1.as_str()), (Tone::Danger, want));
            assert!(!v.2.is_empty());
        }
        let nr = pod(&[("PodScheduled", "True", ""), ("Initialized", "True", ""), ("Ready", "False", "2026-01-02T11:00:00Z")], serde_json::json!([{"name": "a", "ready": false, "restartCount": 0, "state": {"running": {}}}]));
        let v = verdict(&nr, now);
        assert!(v.1 == "Running, but not ready" && v.2[0].contains("a since 60m") || v.2[0].contains("a since 1h"), "{v:?}");
        let mut pending = pod(&[("PodScheduled", "False", "")], Value::Null);
        pending["status"]["phase"] = "Pending".into();
        pending["status"]["conditions"][0]["message"] = "0/3 nodes are available".into();
        assert_eq!(verdict(&pending, now).2, vec!["0/3 nodes are available".to_string()]);
        let mut gone = ok.clone();
        gone["metadata"]["deletionTimestamp"] = "2026-01-02T11:00:00Z".into();
        assert_eq!(verdict(&gone, now).1, "Shutting down");
        let mut evicted = ok.clone();
        evicted["status"]["phase"] = "Failed".into();
        evicted["status"]["reason"] = "Evicted".into();
        assert_eq!(verdict(&evicted, now).1, "Evicted from its node");
        evicted["status"]["message"] = "Pod was rejected: The node had condition: [MemoryPressure]. ".into();
        assert_eq!(verdict(&evicted, now).1, "Rejected by its node");
        assert!(startup(&Value::Null).is_none());
        let _ = verdict(&Value::Null, now);
    }

    #[test]
    fn usage_and_words() {
        let m = parse_top("p a 196m 15519Mi\np b 2m 109Mi\nnoise\n");
        assert_eq!(m["a"].0, 196.0);
        assert_eq!(m.len(), 2);
        assert_eq!(asks(&serde_json::json!({"resources": {"limits": {"cpu": "2", "memory": "1Gi"}}})), (2000.0, 2000.0, 1073741824.0, 1073741824.0));
        assert!(probe_words(&serde_json::json!({"httpGet": {"path": "/ok", "port": 8080}})).starts_with("http port:8080/ok; every 10s"));
        assert!(security_words(&serde_json::json!({"privileged": true}), &Value::Null).1.unwrap().contains("Privileged"));
        assert_eq!(security_words(&Value::Null, &serde_json::json!({"runAsUser": 1000})).0, "runs as user 1000");
    }
}
