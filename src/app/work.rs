//! A workload's page (Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob): is it well, a
//! map of what goes in and out with a tank per pod, how it's rolled out and spread, what scales and
//! guards it, its usage, containers and pods.

use super::dash::{at, at_end, grid, line};
use super::face::{many, Face, Fact, Side};
use super::pg::{label_at, spark};
use super::podxray::{Go, Look};
use super::*;

pub(super) fn is_work(k: Kind) -> bool {
    matches!(k, Kind::Deployments | Kind::StatefulSets | Kind::DaemonSets | Kind::ReplicaSets | Kind::Jobs | Kind::CronJobs)
}

/// What a workload's page loads.
pub(super) fn needs(k: Kind) -> Vec<Kind> {
    let mut v = vec![k, Kind::Pods, Kind::Services, Kind::Ingresses, Kind::PodDisruptionBudgets];
    match k {
        Kind::Deployments => v.extend([Kind::ReplicaSets, Kind::HorizontalPodAutoscalers]),
        Kind::StatefulSets | Kind::ReplicaSets => v.push(Kind::HorizontalPodAutoscalers),
        Kind::CronJobs => v.push(Kind::Jobs),
        _ => {}
    }
    v
}

/// A pod made from a workload's template, for the parts of the app that read pods.
pub(super) fn sample(kind: Kind, o: &Value) -> Value {
    let t = match kind {
        Kind::CronJobs => &o["spec"]["jobTemplate"]["spec"]["template"],
        _ => &o["spec"]["template"],
    };
    let mut md = if t["metadata"].is_object() { t["metadata"].clone() } else { serde_json::json!({}) };
    md["namespace"] = o["metadata"]["namespace"].clone();
    let mut spec = t["spec"].clone();
    // Disks that are made for each pod stand in for what the template says.
    let made: Vec<&str> = o["spec"]["volumeClaimTemplates"].as_array().into_iter().flatten().filter_map(|c| c["metadata"]["name"].as_str()).collect();
    if let Some(v) = spec["volumes"].as_array_mut() {
        v.retain(|v| !made.contains(&v["name"].as_str().unwrap_or("")));
    }
    serde_json::json!({ "metadata": md, "spec": spec, "status": {} })
}

fn owned_by(p: &Value, uid: &str) -> bool {
    !uid.is_empty() && p["metadata"]["ownerReferences"].as_array().into_iter().flatten().any(|r| r["uid"].as_str() == Some(uid))
}

fn uid(o: &Value) -> &str {
    o["metadata"]["uid"].as_str().unwrap_or("")
}

pub(super) fn name_of(o: &Value) -> &str {
    o["metadata"]["name"].as_str().unwrap_or("")
}

/// A pod as it's drawn here.
pub(super) struct Cell<'a> {
    pub pod: &'a Value,
    pub name: String,
    pub short: String,
    pub tone: Tone,
    pub head: String,
    pub word: String,
    pub usage: Option<(f64, f64)>,
    /// cpu ask, cpu limit, memory ask, memory limit
    pub req: [f64; 4],
    /// Made from an old revision.
    pub old: bool,
}

/// How pods are laid out: (width, height, columns, how many are shown).
pub(super) fn cells_for(n: usize) -> (f32, f32, usize, usize) {
    match n {
        0 | 1 => (200.0, 150.0, 1, 1),
        2..=3 => (150.0, 150.0, n, n),
        4..=12 => (108.0, 84.0, ((n as f32 * 1.2).sqrt().ceil() as usize).clamp(2, 4), n),
        13..=40 => (60.0, 46.0, ((n as f32 * 1.6).sqrt().ceil() as usize).clamp(5, 8), n),
        _ => (24.0, 20.0, 20, n.min(200)),
    }
}

const CELL_GAP: f32 = 8.0;

/// (wide, narrowest, tall) of the pods drawn together.
pub(super) fn cells_size(n: usize) -> (f32, f32, f32) {
    let (w, h, cols, shown) = cells_for(n);
    let rows = shown.div_ceil(cols).max(1);
    let wide = |w: f32| cols as f32 * u(w) + (cols as f32 - 1.0) * CELL_GAP + 44.0;
    (wide(w), wide(w.min(34.0)), rows as f32 * (u(h) + CELL_GAP) + u(if n > shown { 20.0 } else { 0.0 }))
}

/// Pods as little tanks. Returns the one clicked.
pub(super) fn draw_cells(ui: &mut Ui, sel: &Selected, p: &egui::Painter, body: egui::Rect, time: f32, cells: &[Cell], none: &str) -> Option<Selected> {
    let mut open = None;
    let n = cells.len();
    if n == 0 {
        let g = p.layout(none.to_string(), FontId::proportional(z(13.0)), TEXT_SUBTLE(), body.width() - 40.0);
        p.galley(body.center() - g.size() / 2.0, g, TEXT_SUBTLE());
        return None;
    }
    let (w, h, cols, shown) = cells_for(n);
    let w = u(w).min((body.width() - 44.0 - (cols as f32 - 1.0) * CELL_GAP) / cols as f32).max(8.0);
    let h = u(h);
    let rows = shown.div_ceil(cols);
    let tall = rows as f32 * h + (rows as f32 - 1.0) * CELL_GAP;
    let top = body.center().y - tall / 2.0;
    for (i, c) in cells.iter().take(shown).enumerate() {
        let in_row = if i / cols + 1 == rows { shown - (rows - 1) * cols } else { cols };
        let row_w = in_row as f32 * w + (in_row as f32 - 1.0) * CELL_GAP;
        let r = egui::Rect::from_min_size(egui::pos2(body.center().x - row_w / 2.0 + (i % cols) as f32 * (w + CELL_GAP), top + (i / cols) as f32 * (h + CELL_GAP)), egui::vec2(w, h));
        let col = tone_color(c.tone);
        let resp = ui.interact(r, ui.id().with(("pod-cell", &c.name)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
        let round = CornerRadius::same(if h > u(60.0) { 12 } else { 5 });
        p.rect_filled(r, round, BG_DEFAULT());
        let [cr, cl, mr, ml] = c.req;
        let cap = if ml > 0.0 { ml } else { mr };
        let frac = c.usage.filter(|_| cap > 0.0).map(|x| x.1 / cap);
        let cpu = c.usage.map(|x| x.0 / cl.max(cr).max(1.0)).unwrap_or(0.0).clamp(0.02, 1.0) as f32;
        if h > u(60.0) {
            match frac {
                Some(f) => pod::tank(p, r.shrink(2.0), f as f32, if ml > 0.0 { hive::heat(f) } else { hive::heat(f.min(0.6)) }, time, cpu, i as f32),
                None if c.usage.is_some() => pod::tank(p, r.shrink(2.0), 0.07, TEXT_SUBTLE(), time, 0.02, i as f32),
                None => {}
            }
        } else if c.usage.is_some() {
            let f = frac.unwrap_or(0.0).clamp(0.0, 1.0);
            let fill = egui::Rect::from_min_max(egui::pos2(r.left(), r.bottom() - r.height() * (f as f32).max(0.06)), r.max);
            p.rect_filled(fill, round, if ml > 0.0 { hive::heat(f) } else { hive::heat(f.min(0.6)) }.gamma_multiply(0.55));
        } else {
            p.rect_filled(r, round, col.gamma_multiply(0.15));
        }
        p.rect_stroke(r, round, Stroke::new(if resp.hovered() { 2.4 } else { 1.4 }, col.gamma_multiply(if resp.hovered() { 1.0 } else { 0.8 })), egui::StrokeKind::Inside);
        let label = |dy: f32, text: &str, size: f32, c: Color32| {
            let t = fit(ui, text, w - 8.0, z(size));
            let g = p.layout_no_wrap(t, FontId::proportional(z(size)), c);
            let at = egui::pos2(r.center().x - g.size().x / 2.0, r.center().y + dy - g.size().y / 2.0);
            p.rect_filled(egui::Rect::from_min_size(at, g.size()).expand2(egui::vec2(4.0, 0.5)), CornerRadius::same(4), BG_DEFAULT().gamma_multiply(0.7));
            p.galley(at, g, c);
        };
        let ended = matches!(c.pod["status"]["phase"].as_str(), Some("Succeeded" | "Failed"));
        let mem = c.usage.map(|x| format!("{}{}", gib(x.1), if cap > 0.0 && w > u(140.0) { format!(" of {}", gib(cap)) } else { String::new() }));
        let word = if c.old { format!("old · {}", c.word) } else { c.word.clone() };
        if h > u(120.0) {
            label(-u(40.0), &c.short, 13.0, TEXT_DEFAULT());
            label(-u(19.0), &word, 11.0, col);
            match (&mem, c.usage) {
                (Some(m), Some(x)) => {
                    label(u(6.0), m, 12.5, TEXT_DEFAULT());
                    label(u(27.0), &format!("{} CPU", hive::cores(x.0)), 11.5, TEXT_MUTED());
                }
                _ if ended => {}
                _ => label(u(8.0), "no usage yet", 11.0, TEXT_PLACEHOLDER()),
            }
        } else if h > u(60.0) {
            label(-u(24.0), &c.short, 12.0, TEXT_DEFAULT());
            label(-u(6.0), &word, 10.5, col);
            match (&mem, c.usage) {
                (Some(m), Some(x)) => {
                    label(u(13.0), m, 11.5, TEXT_DEFAULT());
                    label(u(29.0), &hive::cores(x.0), 10.5, TEXT_MUTED());
                }
                _ if ended => {}
                _ => label(u(14.0), "no usage yet", 10.0, TEXT_PLACEHOLDER()),
            }
        } else if h > u(30.0) {
            label(-u(8.0), &c.short, 10.5, TEXT_DEFAULT());
            if let Some(m) = &mem {
                label(u(9.0), m, 10.0, TEXT_MUTED());
            }
        }
        let tip = format!(
            "{}\n{}{}{}\n{}",
            c.name,
            c.head,
            if c.old { ", from an old revision" } else { "" },
            c.usage.map(|x| format!("\n{} CPU, {} memory", hive::cores(x.0), gib(x.1))).unwrap_or_default(),
            c.pod["spec"]["nodeName"].as_str().unwrap_or("no node yet")
        );
        if resp.on_hover_text(tip).clicked() {
            open = Some(Selected { ctx: sel.ctx.clone(), kind: Kind::Pods, ns: sel.ns.clone(), name: c.name.clone() });
        }
    }
    if n > shown {
        p.text(egui::pos2(body.center().x, body.bottom() - u(9.0)), egui::Align2::CENTER_CENTER, format!("and {} more", n - shown), FontId::proportional(z(11.0)), TEXT_PLACEHOLDER());
    }
    open
}

/// A line of the panels: what, a bar, and a number.
pub(super) fn meter(ui: &mut Ui, label: &str, n: f64, of: f64, words: &str, col: Color32) {
    let (r, _) = line(ui, u(26.0), false);
    at(ui, r, 0.0, 0.3, label, 12.5, TEXT_MUTED());
    let b = egui::Rect::from_min_size(egui::pos2(r.left() + r.width() * 0.3, r.center().y - 4.0), egui::vec2(r.width() * 0.46, 8.0));
    ui.painter().rect_filled(b, CornerRadius::same(4), BG_MUTED());
    if n > 0.0 {
        ui.painter().rect_filled(egui::Rect::from_min_size(b.min, egui::vec2((b.width() * (n / of.max(1e-9)).min(1.0) as f32).max(3.0), b.height())), CornerRadius::same(4), col);
    }
    at_end(ui, r, 1.0, words, 12.5, TEXT_DEFAULT());
}

pub(super) fn said(ui: &mut Ui, text: &str, col: Color32) {
    ui.add(egui::Label::new(RichText::new(text).size(z(12.5)).color(col)).wrap());
}

impl KubedogApp {
    /// Whether a list is there, and if not, why.
    pub(super) fn missing(&self, ctx: &str, kind: Kind) -> Option<String> {
        if self.refused(ctx, kind) {
            return Some(format!("your account can't see {}", kind.label()));
        }
        match self.lists.get(&Self::list_key(ctx, kind)) {
            Some(l) if l.fetched.is_some() => None,
            Some(l) if l.error.is_some() => Some(format!("{} couldn't be read", kind.label())),
            _ => Some(format!("reading {}…", kind.label())),
        }
    }

    /// The pods a workload runs.
    pub(super) fn pods_of<'a>(&'a self, sel: &Selected, o: &Value) -> Option<Vec<&'a Value>> {
        let mut pods = self.refs(&sel.ctx, Kind::Pods, &sel.ns)?;
        let via = |kind: Kind| -> Option<HashSet<String>> { Some(self.refs(&sel.ctx, kind, &sel.ns)?.into_iter().filter(|x| owned_by(x, uid(o))).map(|x| uid(x).to_string()).collect()) };
        let by = |p: &Value, set: &HashSet<String>| p["metadata"]["ownerReferences"].as_array().into_iter().flatten().any(|r| r["uid"].as_str().map(|u| set.contains(u)).unwrap_or(false));
        match sel.kind {
            Kind::Deployments => match via(Kind::ReplicaSets) {
                Some(set) => pods.retain(|p| by(p, &set)),
                // Without replica sets, by name.
                None => pods.retain(|p| {
                    let r = &p["metadata"]["ownerReferences"][0];
                    r["kind"] == "ReplicaSet" && r["name"].as_str().and_then(|n| n.rsplit_once('-')).map(|x| x.0 == sel.name).unwrap_or(false)
                }),
            },
            Kind::CronJobs => {
                let set = via(Kind::Jobs)?;
                pods.retain(|p| by(p, &set));
            }
            _ => pods.retain(|p| owned_by(p, uid(o))),
        }
        pods.sort_by(|a, b| natural(name_of(a), name_of(b)));
        Some(pods)
    }

    pub(super) fn cells<'a>(&self, ctx: &str, prefix: &str, pods: &[&'a Value], old: &dyn Fn(&Value) -> bool) -> Vec<Cell<'a>> {
        let m = self.metrics.get(ctx);
        let now = kube::now_secs();
        let common = if prefix.is_empty() { common_start(&pods.iter().map(|p| name_of(p)).collect::<Vec<_>>()) } else { prefix.to_string() };
        let prefix = common.as_str();
        pods.iter()
            .map(|p| {
                let name = name_of(p).to_string();
                let ns = p["metadata"]["namespace"].as_str().unwrap_or("").to_string();
                let rest = name.strip_prefix(prefix).map(|r| r.trim_start_matches('-')).filter(|r| !r.is_empty()).unwrap_or(&name);
                let hashed = p["metadata"]["labels"]["pod-template-hash"].is_string();
                let short = if hashed { rest.rsplit('-').next().unwrap_or(rest) } else { rest };
                let (tone, head, _) = pod::verdict(p, now);
                let usage = m.and_then(|m| m.pods.get(&(ns, name.clone()))).copied();
                Cell { pod: p, short: short.to_string(), name, tone, head, word: resources::pod_status(p), usage, req: resources::requests(Kind::Pods, p), old: old(p) }
            })
            .collect()
    }

    /// Is a pod from an old revision of its workload?
    fn is_old<'a>(&'a self, sel: &'a Selected, o: &'a Value) -> Box<dyn Fn(&Value) -> bool + 'a> {
        match sel.kind {
            Kind::Deployments => {
                let rev = o["metadata"]["annotations"]["deployment.kubernetes.io/revision"].as_str();
                let hash = rev.and_then(|rev| self.refs(&sel.ctx, Kind::ReplicaSets, &sel.ns)?.into_iter().find(|r| owned_by(r, uid(o)) && r["metadata"]["annotations"]["deployment.kubernetes.io/revision"].as_str() == Some(rev))?["metadata"]["labels"]["pod-template-hash"].as_str());
                Box::new(move |p| hash.map(|h| p["metadata"]["labels"]["pod-template-hash"].as_str() != Some(h)).unwrap_or(false))
            }
            Kind::StatefulSets => {
                let want = o["status"]["updateRevision"].as_str();
                Box::new(move |p| want.map(|w| p["metadata"]["labels"]["controller-revision-hash"].as_str() != Some(w)).unwrap_or(false))
            }
            _ => Box::new(|_| false),
        }
    }

    pub(super) fn work_overview(&mut self, ui: &mut Ui, sel: &Selected, o: &Value) {
        let mut open: Option<Selected> = None;
        let mut go: Option<Go> = None;
        let mut logs: Option<String> = None;
        let now = kube::now_secs();
        let pod = sample(sel.kind, o);
        self.page_scroll().id_salt("work-overview").show(ui, |ui| {
            let pods = self.pods_of(sel, o);
            let old = self.is_old(sel, o);
            let all = self.cells(&sel.ctx, &sel.name, pods.as_deref().unwrap_or(&[]), &*old);
            let cpu: f64 = all.iter().filter_map(|c| c.usage).map(|x| x.0).sum();
            let f = self.work_face(sel, o, now, &all);
            if let Some(s) = face::show(ui, &f, if matches!(sel.kind, Kind::Jobs | Kind::CronJobs) { Side::None } else { Side::Beat(cpu) }) {
                open = Some(s);
            }
            ui.add_space(12.0);
            // The map. A job's old pods are in the list below.
            let mapped: Vec<Cell> = if sel.kind == Kind::CronJobs { self.cells(&sel.ctx, &sel.name, &self.latest_run(sel, o, pods.as_deref().unwrap_or(&[])), &|_| false) } else { self.cells(&sel.ctx, &sel.name, pods.as_deref().unwrap_or(&[]), &*old) };
            let (want, least, tall) = cells_size(mapped.len());
            let ready = mapped.iter().any(|c| pod::cond(c.pod, "Ready").map(|c| c["status"] == "True").unwrap_or(false));
            let mut claims: Vec<String> = vec![];
            for c in &all {
                for v in c.pod["spec"]["volumes"].as_array().into_iter().flatten() {
                    if let Some(n) = v["persistentVolumeClaim"]["claimName"].as_str() {
                        if !claims.iter().any(|x| x == n) {
                            claims.push(n.to_string());
                        }
                    }
                }
            }
            let none = match self.missing(&sel.ctx, Kind::Pods) {
                Some(w) => w,
                None => match sel.kind {
                    Kind::Jobs | Kind::CronJobs => "no pods kept from its runs".into(),
                    _ if f.tone == Tone::Muted => f.head.clone(),
                    _ => "no pods".into(),
                },
            };
            let look = Look {
                title: if sel.kind == Kind::CronJobs { "Latest run" } else { "Map" },
                note: if mapped.is_empty() { String::new() } else { "one tank per pod, filled with memory up to its limit; the waves move with CPU; click a pod to open it".into() },
                pod: &pod,
                only: None,
                claims,
                tone: f.tone,
                running: !mapped.is_empty(),
                ready,
                want: want.max(u(220.0)),
                least,
                tall,
                storage: false,
                doors: !matches!(sel.kind, Kind::Jobs | Kind::CronJobs),
            };
            if let Some(g) = self.xray(ui, sel, &look, |ui, p, body, time| draw_cells(ui, sel, p, body, time, &mapped, &none)) {
                go = Some(g);
            }
            ui.add_space(12.0);
            let mut other = None;
            pg::two(ui, |ui| self.work_state(ui, sel, o, now, &mut open), |ui| {
                self.work_places(ui, sel, &all, &mut other);
                if !matches!(sel.kind, Kind::Jobs | Kind::CronJobs) {
                    self.work_guards(ui, sel, o, now, &mut other);
                }
            });
            open = open.take().or(other);
            ui.add_space(12.0);
            if !matches!(sel.kind, Kind::Jobs | Kind::CronJobs) {
                self.work_usage(ui, sel, &all);
                ui.add_space(12.0);
            }
            self.work_containers(ui, sel, &pod, &mut logs);
            self.work_pods(ui, sel, &all, now, &mut open);
            if let Some(s) = face::meta(ui, &sel.key(), &self.refs_of(sel, o), o) {
                open = Some(s);
            }
            ui.add_space(20.0);
        });
        if let Some(c) = logs {
            self.pod_logs_of(sel, &c);
        }
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

    /// The pods of a cron job's newest job.
    fn latest_run<'a>(&self, sel: &Selected, o: &Value, pods: &[&'a Value]) -> Vec<&'a Value> {
        let jobs = self.runs(sel, o);
        let Some(j) = jobs.first() else { return vec![] };
        pods.iter().filter(|p| owned_by(p, uid(j))).copied().collect()
    }

    /// A cron job's jobs, newest first.
    fn runs(&self, sel: &Selected, o: &Value) -> Vec<&Value> {
        let mut jobs: Vec<&Value> = self.refs(&sel.ctx, Kind::Jobs, &sel.ns).unwrap_or_default().into_iter().filter(|j| owned_by(j, uid(o))).collect();
        jobs.sort_by_key(|j| std::cmp::Reverse(pod::time_of(&j["metadata"]["creationTimestamp"]).unwrap_or(0)));
        jobs
    }

    fn work_face(&self, sel: &Selected, o: &Value, now: i64, cells: &[Cell]) -> Face {
        let (tone, head, mut notes) = face::verdict(sel.kind, o, now);
        let (spec, st) = (&o["spec"], &o["status"]);
        let md = &o["metadata"];
        // The first thing wrong with its pods, in words.
        if matches!(tone, Tone::Danger | Tone::Warning) {
            let mut seen: Vec<(String, usize)> = vec![];
            for c in cells.iter().filter(|c| matches!(c.tone, Tone::Danger | Tone::Warning)) {
                match seen.iter_mut().find(|x| x.0 == c.head) {
                    Some(x) => x.1 += 1,
                    None => seen.push((c.head.clone(), 1)),
                }
            }
            notes.extend(seen.into_iter().take(3).map(|(h, n)| format!("{}: {h}.", many(n as i64, "pod"))));
        }
        let restarts: i64 = cells.iter().flat_map(|c| c.pod["status"]["containerStatuses"].as_array().into_iter().flatten()).map(|s| s["restartCount"].as_i64().unwrap_or(0)).sum();
        let created = md["creationTimestamp"].as_str().unwrap_or("");
        let mut facts = vec![];
        let n = |k: &str| st[k].as_i64().unwrap_or(0);
        let mut sub = format!("created {} ago", kube::age(created));
        match sel.kind {
            Kind::Deployments | Kind::StatefulSets | Kind::ReplicaSets => {
                let want = spec["replicas"].as_i64().unwrap_or(1);
                facts.push(Fact::new("Pods ready", format!("{} of {want}", n("readyReplicas"))).col(if n("readyReplicas") < want { WARNING() } else { TEXT_DEFAULT() }));
            }
            Kind::DaemonSets => facts.push(Fact::new("Nodes ready", format!("{} of {}", n("numberReady"), n("desiredNumberScheduled"))).col(if n("numberReady") < n("desiredNumberScheduled") { WARNING() } else { TEXT_DEFAULT() })),
            Kind::Jobs => facts.push(Fact::new("Succeeded", format!("{} of {}", n("succeeded"), spec["completions"].as_i64().unwrap_or(1)))),
            Kind::CronJobs => {
                facts.push(Fact::new("Schedule", face::cron_words(spec["schedule"].as_str().unwrap_or(""))));
                facts.push(Fact::new("Time zone", spec["timeZone"].as_str().unwrap_or("controller default")));
                facts.push(Fact::new("Last schedule", pod::time_of(&st["lastScheduleTime"]).map(|t| format!("{} ago", kube::human_duration((now - t).max(0)))).unwrap_or("never".into())));
                facts.push(Fact::new("Last success", pod::time_of(&st["lastSuccessfulTime"]).map(|t| format!("{} ago", kube::human_duration((now - t).max(0)))).unwrap_or("never".into())));
                sub = format!("runs {}{}", face::cron_words(spec["schedule"].as_str().unwrap_or("")), spec["timeZone"].as_str().map(|t| format!(", {t} time")).unwrap_or_default());
            }
            _ => {}
        }
        if !matches!(sel.kind, Kind::Jobs | Kind::CronJobs) {
            facts.push(Fact::new("Restarts", restarts.to_string()).col(if restarts > 0 { WARNING() } else { TEXT_DEFAULT() }));
        }
        if sel.kind == Kind::Deployments {
            let rev = md["annotations"]["deployment.kubernetes.io/revision"].as_str().unwrap_or("-");
            facts.push(Fact::new("Revision", rev));
            let changed = self.refs(&sel.ctx, Kind::ReplicaSets, &sel.ns).into_iter().flatten().filter(|r| owned_by(r, uid(o))).filter(|r| r["metadata"]["annotations"]["deployment.kubernetes.io/revision"].as_str() == Some(rev)).find_map(|r| pod::time_of(&r["metadata"]["creationTimestamp"]));
            if let Some(t) = changed {
                sub = format!("current revision since {} ago, {}", kube::human_duration((now - t).max(0)), pod::when(t));
            }
        }
        if md["ownerReferences"][0]["name"].is_string() {
            facts.push(self.owner_fact(sel, o));
        }
        let ps = workload::pod_spec(sel.kind, o);
        let sa = ps["serviceAccountName"].as_str().unwrap_or("default");
        facts.push(Fact::new("Service account", sa).to(Selected { ctx: sel.ctx.clone(), kind: Kind::ServiceAccounts, ns: sel.ns.clone(), name: sa.into() }));
        let images: Vec<&str> = ps["containers"].as_array().into_iter().flatten().filter_map(|c| c["image"].as_str()).collect();
        facts.push(Fact::new(if images.len() > 1 { "Images" } else { "Image" }, match images.as_slice() {
            [one] => one.rsplit('/').next().unwrap_or(one).to_string(),
            l => l.len().to_string(),
        }));
        let sel_words = resources::selector(&spec["selector"]["matchLabels"]);
        if !sel_words.is_empty() && sel_words != "-" && !matches!(sel.kind, Kind::Jobs | Kind::CronJobs) {
            facts.push(Fact::new("Selector", sel_words));
        }
        if let Some(h) = md["labels"]["app.kubernetes.io/managed-by"].as_str() {
            facts.push(Fact::new("Managed by", h));
        }
        facts.push(Fact::new("Created", format!("{} ago", kube::age(created))));
        Face { tone, head, sub, notes, pills: face::pills(o, now), facts }
    }

    /// How far along it is and how it changes.
    fn work_state(&self, ui: &mut Ui, sel: &Selected, o: &Value, now: i64, open: &mut Option<Selected>) {
        let (spec, st) = (&o["spec"], &o["status"]);
        let n = |k: &str| st[k].as_i64().unwrap_or(0) as f64;
        ui.spacing_mut().item_spacing.y = 3.0;
        match sel.kind {
            Kind::CronJobs => {
                let runs = self.runs(sel, o);
                pg::panel(ui, "Job history", "how long each job took, newest at the right");
                if let Some(w) = self.missing(&sel.ctx, Kind::Jobs) {
                    said(ui, &w, TEXT_SUBTLE());
                } else if runs.is_empty() {
                    said(ui, "No jobs kept.", TEXT_SUBTLE());
                } else {
                    let l: Vec<(&Value, i64, Tone)> = runs.iter().take(24).rev().map(|j| {
                        let a = pod::time_of(&j["status"]["startTime"]).unwrap_or(now);
                        let b = pod::time_of(&j["status"]["completionTime"]).or_else(|| pod::time_of(&pod::cond(j, "Failed")?["lastTransitionTime"])).unwrap_or(now);
                        (*j, (b - a).max(1), face::verdict(Kind::Jobs, j, now).0)
                    }).collect();
                    let max = l.iter().map(|x| x.1).max().unwrap_or(1) as f32;
                    let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(84.0)), Sense::hover());
                    let w = (r.width() / l.len() as f32).min(u(90.0));
                    for (i, (j, took, tone)) in l.iter().enumerate() {
                        let x = r.left() + i as f32 * w;
                        let spot = egui::Rect::from_min_size(egui::pos2(x, r.top()), egui::vec2(w, r.height()));
                        let h = (r.height() - u(34.0)) * (*took as f32 / max).max(0.06);
                        let b = egui::Rect::from_min_max(egui::pos2(x + 4.0, r.bottom() - u(18.0) - h), egui::pos2(x + w - 4.0, r.bottom() - u(18.0)));
                        let resp = ui.interact(spot, ui.id().with(("run", i)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                        let p = ui.painter();
                        p.rect_filled(b, CornerRadius::same(4), tone_color(*tone).gamma_multiply(if resp.hovered() { 1.0 } else { 0.75 }));
                        p.text(egui::pos2(b.center().x, b.top() - 2.0), egui::Align2::CENTER_BOTTOM, kube::human_duration(*took), FontId::proportional(z(10.5)), TEXT_MUTED());
                        let ago = pod::time_of(&j["metadata"]["creationTimestamp"]).map(|t| kube::human_duration((now - t).max(0))).unwrap_or_default();
                        p.text(egui::pos2(b.center().x, r.bottom()), egui::Align2::CENTER_BOTTOM, &ago, FontId::proportional(z(10.0)), TEXT_PLACEHOLDER());
                        if resp.on_hover_text(format!("{}\n{}, {ago} ago", name_of(j), face::verdict(Kind::Jobs, j, now).1)).clicked() {
                            *open = Some(Selected { ctx: sel.ctx.clone(), kind: Kind::Jobs, ns: sel.ns.clone(), name: name_of(j).into() });
                        }
                    }
                }
                ui.add_space(4.0);
                said(ui, &format!("Concurrency policy: {}", match spec["concurrencyPolicy"].as_str() { Some("Forbid") => "Forbid (a run is skipped while another runs)", Some("Replace") => "Replace (a new run stops the running one)", _ => "Allow (runs may overlap)" }), TEXT_MUTED());
                said(ui, &format!("History limits: {} successful, {} failed", spec["successfulJobsHistoryLimit"].as_i64().unwrap_or(3), spec["failedJobsHistoryLimit"].as_i64().unwrap_or(1)), TEXT_MUTED());
            }
            Kind::Jobs => {
                pg::panel(ui, "Progress", "");
                let of = spec["completions"].as_i64().unwrap_or(1).max(1) as f64;
                meter(ui, "Succeeded", n("succeeded"), of, &format!("{:.0} of {of:.0}", n("succeeded")), SUCCESS());
                meter(ui, "Running", n("active"), of, &format!("{:.0}", n("active")), INFO());
                let tries = spec["backoffLimit"].as_i64().unwrap_or(6);
                meter(ui, "Failed", n("failed"), (tries + 1) as f64, &format!("{:.0}, backoff limit {tries}", n("failed")), DANGER());
                if let Some(t) = spec["ttlSecondsAfterFinished"].as_i64() {
                    said(ui, &format!("TTL after finished: {}", kube::human_duration(t)), TEXT_MUTED());
                }
                if let Some(t) = spec["activeDeadlineSeconds"].as_i64() {
                    said(ui, &format!("Active deadline: {}", kube::human_duration(t)), TEXT_MUTED());
                }
            }
            _ => {
                let (want, rows, ways): (f64, Vec<(&str, f64)>, String) = match sel.kind {
                    Kind::DaemonSets => (n("desiredNumberScheduled"), vec![("Ready", n("numberReady")), ("Updated", n("updatedNumberScheduled")), ("Available", n("numberAvailable"))], if spec["updateStrategy"]["type"] == "OnDelete" { "Update strategy: OnDelete".into() } else { format!("Update strategy: RollingUpdate, maxUnavailable {}", count_of(&spec["updateStrategy"]["rollingUpdate"]["maxUnavailable"], "1")) }),
                    Kind::StatefulSets => (spec["replicas"].as_i64().unwrap_or(1) as f64, vec![("Ready", n("readyReplicas")), ("Updated", if st["updatedReplicas"].is_null() && st["currentRevision"] == st["updateRevision"] { n("currentReplicas") } else { n("updatedReplicas") }), ("Available", n("availableReplicas"))], format!("Update strategy: {} · pod management: {}", spec["updateStrategy"]["type"].as_str().unwrap_or("RollingUpdate"), spec["podManagementPolicy"].as_str().unwrap_or("OrderedReady"))),
                    Kind::ReplicaSets => (spec["replicas"].as_i64().unwrap_or(1) as f64, vec![("Ready", n("readyReplicas")), ("Available", n("availableReplicas"))], String::new()),
                    _ => {
                        let ru = &spec["strategy"]["rollingUpdate"];
                        (
                            spec["replicas"].as_i64().unwrap_or(1) as f64,
                            vec![("Ready", n("readyReplicas")), ("Updated", n("updatedReplicas")), ("Available", n("availableReplicas"))],
                            if spec["strategy"]["type"] == "Recreate" { "Strategy: Recreate (all pods stop before new ones start)".into() } else { format!("Strategy: RollingUpdate, maxSurge {}, maxUnavailable {}", count_of(&ru["maxSurge"], "25%"), count_of(&ru["maxUnavailable"], "25%")) },
                        )
                    }
                };
                pg::panel(ui, "Rollout status", "");
                for (l, v) in rows {
                    meter(ui, l, v, want, &format!("{v:.0} of {want:.0}"), if v >= want { SUCCESS() } else { WARNING() });
                }
                if !ways.is_empty() {
                    said(ui, &ways, TEXT_MUTED());
                }
            }
        }
    }

    /// What scales it and what guards it.
    fn work_guards(&self, ui: &mut Ui, sel: &Selected, o: &Value, now: i64, open: &mut Option<Selected>) {
        let spec = &o["spec"];
        let want = spec["replicas"].as_i64().or(o["status"]["desiredNumberScheduled"].as_i64()).unwrap_or(1) as f64;
        ui.add_space(8.0);
                // What scales it.
                pg::panel(ui, "Autoscaler and disruption budget", "");
                let kind = match sel.kind { Kind::Deployments => "Deployment", Kind::StatefulSets => "StatefulSet", Kind::ReplicaSets => "ReplicaSet", _ => "" };
                let mut scaled = false;
                if !kind.is_empty() {
                    match self.missing(&sel.ctx, Kind::HorizontalPodAutoscalers) {
                        Some(w) => said(ui, &w, TEXT_PLACEHOLDER()),
                        None => {
                            for h in self.refs(&sel.ctx, Kind::HorizontalPodAutoscalers, &sel.ns).unwrap_or_default() {
                                let t = &h["spec"]["scaleTargetRef"];
                                if t["kind"] == kind && t["name"].as_str() == Some(&sel.name) {
                                    scaled = true;
                                    let (min, max, cur) = (h["spec"]["minReplicas"].as_i64().unwrap_or(1), h["spec"]["maxReplicas"].as_i64().unwrap_or(0), h["status"]["currentReplicas"].as_i64().unwrap_or(0));
                                    let v = face::verdict(Kind::HorizontalPodAutoscalers, h, now);
                                    self.link_line(ui, &format!("{}: min {min}, max {max}, now {cur}", name_of(h)), &v.1, tone_color(v.0), Selected { ctx: sel.ctx.clone(), kind: Kind::HorizontalPodAutoscalers, ns: sel.ns.clone(), name: name_of(h).into() }, open);
                                }
                            }
                            if !scaled {
                                said(ui, "No autoscaler.", TEXT_SUBTLE());
                            }
                        }
                    }
                }
                match self.missing(&sel.ctx, Kind::PodDisruptionBudgets) {
                    Some(w) => said(ui, &w, TEXT_PLACEHOLDER()),
                    None => {
                        let labels = &spec["template"]["metadata"]["labels"];
                        let mut any = false;
                        for b in self.refs(&sel.ctx, Kind::PodDisruptionBudgets, &sel.ns).unwrap_or_default() {
                            if b["spec"]["selector"].is_object() && podnet::selector_matches(&b["spec"]["selector"], labels) {
                                any = true;
                                let v = face::verdict(Kind::PodDisruptionBudgets, b, now);
                                self.link_line(ui, name_of(b), &v.1, tone_color(v.0), Selected { ctx: sel.ctx.clone(), kind: Kind::PodDisruptionBudgets, ns: sel.ns.clone(), name: name_of(b).into() }, open);
                            }
                        }
                        if !any {
                            said(ui, if want > 1.0 { "No disruption budget: draining nodes may evict all its pods at once." } else { "No disruption budget." }, TEXT_SUBTLE());
                        }
                    }
                }
    }

    /// A line with a dot, a name that opens something, and words about it.
    pub(super) fn link_line(&self, ui: &mut Ui, name: &str, words: &str, col: Color32, to: Selected, open: &mut Option<Selected>) {
        let (r, resp) = line(ui, u(26.0), true);
        ui.painter().circle_filled(egui::pos2(r.left() + u(5.0), r.center().y), u(4.0), col);
        let g = ui.painter().layout_no_wrap(fit(ui, words, r.width() * 0.5, z(12.0)), FontId::proportional(z(12.0)), col);
        let w = g.size().x;
        ui.painter().galley(egui::pos2(r.right() - w, r.center().y - g.size().y / 2.0), g, col);
        label_at(ui, ui.painter(), egui::pos2(r.left() + u(18.0), r.center().y), name, 13.0, PRIMARY_TEXT(), r.width() - w - u(30.0));
        if resp.on_hover_text(format!("{name}\n{words}")).clicked() {
            *open = Some(to);
        }
    }

    /// Where its pods run.
    fn work_places(&self, ui: &mut Ui, sel: &Selected, cells: &[Cell], open: &mut Option<Selected>) {
        ui.spacing_mut().item_spacing.y = 3.0;
        pg::panel(ui, "Pod placement", "one dot per pod");
        let live: Vec<&Cell> = cells.iter().filter(|c| !matches!(c.pod["status"]["phase"].as_str(), Some("Succeeded" | "Failed"))).collect();
        let mut by: Vec<(String, Vec<&Cell>)> = vec![];
        for c in &live {
            let n = c.pod["spec"]["nodeName"].as_str().unwrap_or("").to_string();
            match by.iter_mut().find(|x| x.0 == n) {
                Some(x) => x.1.push(c),
                None => by.push((n, vec![c])),
            }
        }
        by.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
        if live.is_empty() {
            said(ui, &self.missing(&sel.ctx, Kind::Pods).unwrap_or("No pods scheduled.".into()), TEXT_SUBTLE());
            return;
        }
        let shown = if by.len() > 9 { 8 } else { by.len() };
        for (n, list) in by.iter().take(shown) {
            let (r, resp) = line(ui, u(26.0), !n.is_empty());
            at(ui, r, 0.0, 0.5, if n.is_empty() { "no node yet" } else { n }, 12.5, if n.is_empty() { WARNING() } else { PRIMARY_TEXT() });
            let mut x = r.left() + r.width() * 0.5;
            let step = u(15.0).min((r.width() * 0.4) / list.len() as f32);
            for c in list {
                ui.painter().circle_filled(egui::pos2(x + u(6.0), r.center().y), u(5.0).min(step * 0.45), tone_color(c.tone).gamma_multiply(0.85));
                x += step;
            }
            at_end(ui, r, 1.0, &list.len().to_string(), 12.5, TEXT_MUTED());
            if resp.on_hover_text(list.iter().map(|c| format!("{}: {}", c.name, c.head)).take(20).collect::<Vec<_>>().join("\n")).clicked() && !n.is_empty() {
                *open = Some(Selected { ctx: sel.ctx.clone(), kind: Kind::Nodes, ns: String::new(), name: n.clone() });
            }
        }
        if by.len() > shown {
            said(ui, &format!("and {} more nodes", by.len() - shown), TEXT_PLACEHOLDER());
        }
        ui.add_space(2.0);
        let words = match (live.len(), by.len()) {
            (1, _) if sel.kind != Kind::DaemonSets && !matches!(sel.kind, Kind::Jobs | Kind::CronJobs) => Some(("Single replica: not available while its pod is replaced or its node fails.".to_string(), TEXT_SUBTLE())),
            (n, 1) if n > 1 => Some((format!("All {n} pods run on one node: a node failure takes them all."), WARNING())),
            _ => None,
        };
        if let Some((w, c)) = words {
            said(ui, &w, c);
        }
    }

    /// CPU and memory of all its pods together.
    fn work_usage(&self, ui: &mut Ui, sel: &Selected, cells: &[Cell]) {
        let m = self.metrics.get(&sel.ctx);
        let live: Vec<&Cell> = cells.iter().filter(|c| c.usage.is_some()).collect();
        let (cpu, mem) = live.iter().filter_map(|c| c.usage).fold((0.0, 0.0), |a, x| (a.0 + x.0, a.1 + x.1));
        let mut req = [0.0; 4];
        for c in &live {
            for i in 0..4 {
                req[i] += c.req[i];
            }
        }
        // A limit that some pods don't have is no limit on the whole.
        for i in [1, 3] {
            if live.iter().any(|c| c.req[i] <= 0.0) {
                req[i] = 0.0;
            }
        }
        let mut hist: std::collections::BTreeMap<u32, (f64, f64)> = Default::default();
        if let Some(m) = m {
            for c in &live {
                for (t, a, b) in m.pod_hist.get(&(sel.ns.clone(), c.name.clone())).into_iter().flatten() {
                    let e = hist.entry(*t).or_default();
                    e.0 += *a as f64;
                    e.1 += *b as f64;
                }
            }
        }
        let hist: Vec<(f64, f64)> = hist.into_values().collect();
        let why = match m {
            _ if cells.is_empty() => "no pods".to_string(),
            Some(m) if m.error.is_some() => truncate(m.error.as_deref().unwrap_or(""), 140),
            Some(m) if m.fetched.is_some() => "no metrics for its pods".into(),
            _ => "reading usage…".into(),
        };
        grid(ui, 2, u(340.0), u(104.0), 12.0, |ui, i, r| {
            let p = ui.painter().clone();
            p.rect_filled(r, CornerRadius::same(10), BG_CARD());
            p.rect_stroke(r, CornerRadius::same(10), Stroke::new(1.0, BORDER_SUBTLE()), egui::StrokeKind::Inside);
            let is_cpu = i == 0;
            let mut child = ui.new_child(egui::UiBuilder::new().max_rect(r.shrink2(egui::vec2(16.0, 12.0))).layout(Layout::top_down(Align::Min)));
            let ui = &mut child;
            ui.spacing_mut().item_spacing.y = 4.0;
            let used = (!live.is_empty()).then_some(if is_cpu { cpu } else { mem });
            pod::usage_row(ui, if is_cpu { "CPU" } else { "Memory" }, used, req[if is_cpu { 0 } else { 2 }], req[if is_cpu { 1 } else { 3 }], is_cpu, if is_cpu { CPU_BAR() } else { MEM_BAR() });
            let v: Vec<f64> = hist.iter().map(|x| if is_cpu { x.0 } else { x.1 }).collect();
            if v.len() > 1 {
                spark(ui, &v, u(40.0), if is_cpu { CPU_BAR() } else { MEM_BAR() }, |x| pod::plain(x, is_cpu));
            } else {
                let (e, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(40.0)), Sense::hover());
                label_at(ui, ui.painter(), e.left_center(), if live.is_empty() { &why } else { "the chart fills while Kubedog is open" }, 11.5, TEXT_PLACEHOLDER(), e.width());
            }
        });
    }

    /// Its containers, as they're set.
    fn work_containers(&self, ui: &mut Ui, sel: &Selected, pod: &Value, logs: &mut Option<String>) {
        let mut list: Vec<(&Value, bool)> = pod["spec"]["initContainers"].as_array().into_iter().flatten().map(|c| (c, true)).collect();
        list.extend(pod["spec"]["containers"].as_array().into_iter().flatten().map(|c| (c, false)));
        grid(ui, list.len(), u(400.0), u(132.0), 12.0, |ui, i, r| {
            let (c, init) = list[i];
            let name = c["name"].as_str().unwrap_or("");
            let p = ui.painter().clone();
            p.rect_filled(r, CornerRadius::same(10), BG_CARD());
            p.rect_stroke(r, CornerRadius::same(10), Stroke::new(1.0, BORDER_SUBTLE()), egui::StrokeKind::Inside);
            let mut child = ui.new_child(egui::UiBuilder::new().max_rect(r.shrink2(egui::vec2(16.0, 12.0))).layout(Layout::top_down(Align::Min)));
            let ui = &mut child;
            ui.set_clip_rect(ui.clip_rect().intersect(r));
            ui.spacing_mut().item_spacing.y = 3.0;
            let (h, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(22.0)), Sense::hover());
            label_at(ui, ui.painter(), h.left_center(), name, 15.0, TEXT_DEFAULT(), h.width() * 0.6);
            let what = match (init, c["restartPolicy"] == "Always") { (_, true) => "sidecar", (true, _) => "init container", _ => "" };
            at_end(ui, h, 1.0, what, 11.5, TEXT_SUBTLE());
            let img = c["image"].as_str().unwrap_or("");
            let (l, resp) = line(ui, u(20.0), true);
            at(ui, l, 0.0, 1.0, img, 12.0, TEXT_MUTED());
            if resp.on_hover_text(format!("{img}\nClick to copy")).clicked() {
                ui.ctx().copy_text(img.to_string());
            }
            let (cr, cl, mr, ml) = pod::asks(c);
            let some = |v: f64, cpu: bool| if v > 0.0 { pod::plain(v, cpu) } else { "none".into() };
            let (l, _) = line(ui, u(20.0), false);
            at(ui, l, 0.0, 1.0, &if cr + cl + mr + ml > 0.0 { format!("CPU: request {}, limit {} · memory: request {}, limit {}", some(cr, true), some(cl, true), some(mr, false), some(ml, false)) } else { "no requests, no limits".to_string() }, 12.0, if init || (mr > 0.0 && ml > 0.0) { TEXT_SUBTLE() } else { WARNING() });
            let checks: Vec<&str> = [("startupProbe", "startup"), ("readinessProbe", "readiness"), ("livenessProbe", "liveness")].iter().filter(|x| c[x.0].is_object()).map(|x| x.1).collect();
            let ports: Vec<String> = c["ports"].as_array().into_iter().flatten().map(|p| p["containerPort"].to_string()).collect();
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                if sel.kind.has_logs() && !init && button(ui, "≡ Logs", false, false) {
                    *logs = Some(name.to_string());
                }
                let mut w = vec![];
                if !ports.is_empty() {
                    w.push(format!("port {}", ports.join(", ")));
                }
                if !init {
                    w.push(if checks.is_empty() { "no probes".to_string() } else { format!("probes: {}", checks.join(", ")) });
                }
                ui.add(egui::Label::new(RichText::new(w.join(" · ")).size(z(12.0)).color(TEXT_SUBTLE())).truncate());
            });
        });
    }

    /// Its pods, those in trouble first.
    pub(super) fn work_pods(&self, ui: &mut Ui, sel: &Selected, cells: &[Cell], now: i64, open: &mut Option<Selected>) {
        dash::section(ui, &format!("Pods ({})", cells.len()), "");
        if cells.is_empty() {
            said(ui, &self.missing(&sel.ctx, Kind::Pods).map(|w| format!("{w}.")).unwrap_or("None.".into()), TEXT_SUBTLE());
            return;
        }
        let rank = |t: Tone| match t { Tone::Danger => 0, Tone::Warning => 1, Tone::Info => 2, _ => 3 };
        let mut l: Vec<&Cell> = cells.iter().collect();
        l.sort_by_key(|c| rank(c.tone));
        let (mc, mm) = cells.iter().filter_map(|c| c.usage).fold((1.0f64, 1.0f64), |a, x| (a.0.max(x.0), a.1.max(x.1)));
        card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            let (r, _) = line(ui, u(22.0), false);
            for (x, t) in [(0.0, "Name"), (0.34, "Status"), (0.50, "CPU"), (0.64, "Memory"), (0.79, "Node")] {
                at(ui, r, x, 0.16, t, 11.5, TEXT_SUBTLE());
            }
            at_end(ui, r, 1.0, "Age", 11.5, TEXT_SUBTLE());
            for c in l.iter().take(80) {
                let (r, resp) = line(ui, u(28.0), true);
                ui.painter().circle_filled(egui::pos2(r.left() + u(5.0), r.center().y), u(4.5), tone_color(c.tone));
                label_at(ui, ui.painter(), egui::pos2(r.left() + u(18.0), r.center().y), &c.name, 13.0, PRIMARY_TEXT(), r.width() * 0.34 - u(26.0));
                let rc: i64 = c.pod["status"]["containerStatuses"].as_array().into_iter().flatten().map(|s| s["restartCount"].as_i64().unwrap_or(0)).sum();
                at(ui, r, 0.34, 0.16, &format!("{}{}{}", c.word, if rc > 0 { format!(", {}", many(rc, "restart")) } else { String::new() }, if c.old { ", old" } else { "" }), 12.5, if rc > 0 && c.tone == Tone::Success { WARNING() } else { tone_color(c.tone) });
                if let Some((a, b)) = c.usage {
                    for (x, v, max, t, col) in [(0.50, a, mc, hive::cores(a), CPU_BAR()), (0.64, b, mm, gib(b), MEM_BAR())] {
                        dash::bar(ui, r, x, 0.06, v / max, col);
                        at(ui, r, x + 0.067, 0.08, &t, 12.0, TEXT_MUTED());
                    }
                }
                at(ui, r, 0.79, 0.15, c.pod["spec"]["nodeName"].as_str().unwrap_or("-"), 12.5, TEXT_MUTED());
                at_end(ui, r, 1.0, &pod::time_of(&c.pod["metadata"]["creationTimestamp"]).map(|t| kube::human_duration((now - t).max(0))).unwrap_or_default(), 12.0, TEXT_SUBTLE());
                if resp.on_hover_text(format!("{}\n{}", c.name, c.head)).clicked() {
                    *open = Some(Selected { ctx: sel.ctx.clone(), kind: Kind::Pods, ns: c.pod["metadata"]["namespace"].as_str().unwrap_or("").to_string(), name: c.name.clone() });
                }
            }
            if l.len() > 80 {
                let (r, _) = line(ui, u(24.0), false);
                at(ui, r, 0.0, 1.0, &format!("and {} more in Pods", l.len() - 80), 12.5, TEXT_SUBTLE());
            }
        });
    }
}

/// "25%" or "1".
fn count_of(v: &Value, default: &str) -> String {
    let t = v.as_str().map(String::from).or_else(|| v.as_i64().map(|n| n.to_string())).unwrap_or(default.into());
    t
}

/// What all names begin with, up to a dash; nothing for a single one.
fn common_start(names: &[&str]) -> String {
    let Some(first) = names.first().filter(|_| names.len() > 1) else { return String::new() };
    let n = names.iter().map(|x| x.bytes().zip(first.bytes()).take_while(|(a, b)| a == b).count()).min().unwrap_or(0);
    first.get(..n).and_then(|t| t.rfind('-').map(|i| t[..i].to_string())).unwrap_or_default()
}

/// "web-2" before "web-10".
fn natural(a: &str, b: &str) -> std::cmp::Ordering {
    let split = |s: &str| {
        let d = s.len() - s.chars().rev().take_while(|c| c.is_ascii_digit()).count();
        (s[..d].to_string(), s[d..].parse::<u64>().ok())
    };
    split(a).cmp(&split(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn layout_of_pods() {
        for n in 0..400 {
            let (w, h, cols, shown) = cells_for(n);
            assert!(w > 0.0 && h > 0.0 && cols >= 1 && shown >= 1 && shown <= 200, "{n}");
            let (a, b, c) = cells_size(n);
            assert!(b <= a && c > 0.0 && a < 900.0, "{n}");
        }
        assert_eq!(cells_for(3).3, 3);
        assert_eq!(cells_for(500).3, 200);
    }

    #[test]
    fn samples_and_owners() {
        let cron = json!({"metadata": {"name": "nightly", "namespace": "shop"}, "spec": {"jobTemplate": {"spec": {"template": {"metadata": {"labels": {"a": "b"}}, "spec": {"containers": [{"name": "c"}]}}}}}});
        let s = sample(Kind::CronJobs, &cron);
        assert_eq!(s["spec"]["containers"][0]["name"], "c");
        assert_eq!(s["metadata"]["namespace"], "shop");
        assert_eq!(s["metadata"]["labels"]["a"], "b");
        assert!(sample(Kind::Deployments, &json!({}))["metadata"].is_object());
        let p = json!({"metadata": {"ownerReferences": [{"uid": "x"}]}});
        assert!(owned_by(&p, "x") && !owned_by(&p, "y") && !owned_by(&p, ""));
        assert_eq!(common_start(&["db-nodes-0", "db-nodes-1"]), "db-nodes");
        assert_eq!(common_start(&["db-nodes-0"]), "");
        assert_eq!(common_start(&["a", "b"]), "");
        let set = json!({"metadata": {}, "spec": {"volumeClaimTemplates": [{"metadata": {"name": "data"}}], "template": {"spec": {"volumes": [{"name": "data"}, {"name": "x"}]}}}});
        assert_eq!(sample(Kind::StatefulSets, &set)["spec"]["volumes"].as_array().unwrap().len(), 1);
        assert_eq!(natural("web-2", "web-10"), std::cmp::Ordering::Less);
        assert_eq!(count_of(&json!(1), "25%"), "1");
        assert_eq!(count_of(&json!(null), "25%"), "25%");
    }
}
