//! Two clusters next to each other (or one and a saved snapshot), and what runs against Git.

use super::face::{many, Face, Side};
use super::incident::{chip_button, diff_table, digest, differences, Digest};
use super::ops::{ago, ns_of, summary, table, text, worst_first, Item};
use super::pg::panel;
use super::podxray::Go;
use super::work::{name_of, said};
use super::*;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Cmp {
    pub a: String,
    pub b: String,
    pub path: String,
    pub open: Option<String>,
    pub only: bool,
    /// A snapshot that was opened: its name and what's in it.
    pub snap: Option<(String, Picture)>,
    pub note: String,
}

const KINDS: [Kind; 7] = [Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::CronJobs, Kind::ConfigMaps, Kind::Services, Kind::Ingresses];

/// "kind namespace/name" → what matters in it.
pub(super) type Picture = BTreeMap<String, Digest>;

/// A short fingerprint: the same text gives the same one on every computer.
fn print(t: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in t.bytes() {
        h = (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("fingerprint {h:016x}")
}

/// For a file: values of variables, arguments and configuration as fingerprints only.
pub(super) fn guarded(d: &Digest) -> Digest {
    d.iter().map(|(k, v)| (k.clone(), if (k.contains(" env ") && !v.starts_with("from ")) || k.starts_with("key ") || k.ends_with(" arguments") || k == "rules" { print(v) } else { v.clone() })).collect()
}

/// Who wrote an object, from its managed fields: names and times only.
pub(super) fn slim_writers(o: &Value) -> Value {
    let md = &o["metadata"];
    let by: Vec<Value> = md["managedFields"].as_array().into_iter().flatten().map(|f| serde_json::json!({"m": f["manager"], "at": f["time"], "op": f["operation"], "sub": f["subresource"], "spec": f["fieldsV1"]["f:spec"].as_object().map(|m| m.keys().map(|k| k.trim_start_matches("f:").to_string()).collect::<Vec<_>>()), "data": f["fieldsV1"]["f:data"].is_object()})).collect();
    let tracked = md["annotations"]["argocd.argoproj.io/tracking-id"].as_str().and_then(|t| t.split(':').next()).map(String::from);
    serde_json::json!({"kind": o["kind"], "ns": md["namespace"], "name": md["name"], "app": tracked, "by": by})
}

/// Writers that are people with a tool, rather than a controller.
fn by_hand(m: &str) -> bool {
    let m = m.to_lowercase();
    m.starts_with("kubectl") || matches!(m.as_str(), "mozilla" | "k9s" | "lens" | "oc" | "kubedog" | "headlamp" | "freelens")
}

impl KubedogApp {
    fn picture(&self, ctx: &str) -> Picture {
        let mut p = Picture::new();
        for k in KINDS {
            for o in self.refs(ctx, k, "").unwrap_or_default().into_iter().filter(|o| self.ns_ok(ns_of(o))) {
                // What every namespace gets says nothing.
                if matches!(name_of(o), "kube-root-ca.crt" | "openshift-service-ca.crt") {
                    continue;
                }
                p.insert(format!("{} {}/{}", k.singular(), ns_of(o), name_of(o)), digest(k, o));
            }
        }
        p
    }

    pub(super) fn cluster_compare(&mut self, ui: &mut Ui) -> Option<Go> {
        let ctxs = self.active.clone();
        if self.incident.cmp.a.is_empty() || !ctxs.contains(&self.incident.cmp.a) {
            self.incident.cmp.a = ctxs.first().cloned().unwrap_or_default();
        }
        if self.incident.cmp.b.is_empty() || (self.incident.cmp.b != "snapshot" && !ctxs.contains(&self.incident.cmp.b)) {
            self.incident.cmp.b = ctxs.get(1).cloned().unwrap_or("snapshot".into());
        }
        let mut save = false;
        let mut load = false;
        card(ui, |ui| {
            panel(ui, "Compare", "workloads, config maps, services and ingresses with the same namespace and name; secrets are left out");
            ui.horizontal_wrapped(|ui| {
                said(ui, "This", TEXT_SUBTLE());
                for c in &ctxs {
                    if chip_button(ui, &ctx_label(c), self.incident.cmp.a == *c) {
                        self.incident.cmp.a = c.clone();
                    }
                }
            });
            ui.horizontal_wrapped(|ui| {
                said(ui, "with", TEXT_SUBTLE());
                for c in &ctxs {
                    if chip_button(ui, &ctx_label(c), self.incident.cmp.b == *c) {
                        self.incident.cmp.b = c.clone();
                    }
                }
                let t = self.incident.cmp.snap.as_ref().map(|s| format!("snapshot {}", s.0)).unwrap_or("a snapshot".into());
                if chip_button(ui, &t, self.incident.cmp.b == "snapshot") {
                    self.incident.cmp.b = "snapshot".into();
                }
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.incident.cmp.path).hint_text("path of a snapshot file").desired_width(u(360.0)));
                load = button(ui, "Open snapshot", false, false);
                save = button(ui, "Save a snapshot of the first", false, false);
            });
            said(ui, "A snapshot holds names, images, numbers and where values come from. Values of variables and config maps are in it as fingerprints only, so they can be compared but not read.", TEXT_PLACEHOLDER());
            if !self.incident.cmp.note.is_empty() {
                said(ui, &self.incident.cmp.note.clone(), INFO());
            }
            ui.checkbox(&mut self.incident.cmp.only, "Also what's in one only");
        });
        if load {
            let p = self.incident.cmp.path.trim().replace('~', &std::env::var("HOME").unwrap_or_default());
            let r = std::fs::metadata(&p).map_err(|e| e.to_string()).and_then(|m| if m.len() > 50_000_000 { Err("the file is too big".into()) } else { std::fs::read_to_string(&p).map_err(|e| e.to_string()) }).and_then(|t| read_snapshot(&t));
            match r {
                Ok(s) => {
                    self.incident.cmp.note = format!("Opened {}.", s.0);
                    self.incident.cmp.snap = Some(s);
                    self.incident.cmp.b = "snapshot".into();
                }
                Err(e) => self.incident.cmp.note = format!("Couldn't open it: {e}"),
            }
        }
        // (Screenshots write nothing.)
        if save && self.screenshot.is_none() {
            let a = self.incident.cmp.a.clone();
            let label = ctx_label(&a);
            let t = write_snapshot(&label, &self.picture(&a));
            let file: String = label.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
            let path = format!("{}/Downloads/kubedog-{file}-{}.json", std::env::var("HOME").unwrap_or(".".into()), kube::now_secs());
            self.incident.cmp.note = match std::fs::write(&path, t) {
                Ok(()) => format!("Saved as {path}"),
                Err(e) => format!("Couldn't save it: {e}"),
            };
        }
        ui.add_space(10.0);
        let (a, b) = (self.incident.cmp.a.clone(), self.incident.cmp.b.clone());
        if a == b {
            said(ui, "Pick two different ones. One cluster can be compared with a snapshot of itself from earlier.", TEXT_SUBTLE());
            return None;
        }
        if let Some(w) = KINDS.iter().find_map(|k| self.missing(&a, *k)) {
            said(ui, &w, TEXT_SUBTLE());
        }
        let left = self.picture(&a);
        let (right, left) = if b == "snapshot" {
            let Some((_, s)) = &self.incident.cmp.snap else {
                said(ui, "Open a snapshot file.", TEXT_SUBTLE());
                return None;
            };
            let keep = |k: &str| k.split_once(' ').and_then(|x| x.1.split_once('/')).map(|x| self.ns_ok(x.0.rsplit(' ').next().unwrap_or(x.0))).unwrap_or(true);
            (s.iter().filter(|x| keep(x.0)).map(|(k, v)| (k.clone(), v.clone())).collect::<Picture>(), left.iter().map(|(k, v)| (k.clone(), guarded(v))).collect())
        } else {
            (self.picture(&b), left)
        };
        let q = self.search.to_lowercase();
        let mut rows: Vec<(Tone, String, String, Vec<(String, String, String)>)> = vec![];
        let mut same = 0;
        let mut ones = 0;
        for k in left.keys().chain(right.keys().filter(|k| !left.contains_key(*k))) {
            match (left.get(k), right.get(k)) {
                (Some(x), Some(y)) => {
                    let d = differences(x, y);
                    if d.is_empty() {
                        same += 1;
                    } else {
                        rows.push((Tone::Warning, k.clone(), d.iter().map(|x| x.0.as_str()).take(5).collect::<Vec<_>>().join(", "), d));
                    }
                }
                (x, _) => {
                    ones += 1;
                    if self.incident.cmp.only {
                        rows.push((Tone::Info, k.clone(), format!("only in the {}", if x.is_some() { "first" } else { "second" }), vec![]));
                    }
                }
            }
        }
        rows.retain(|r| q.is_empty() || r.1.to_lowercase().contains(&q) || r.2.to_lowercase().contains(&q));
        let differ = rows.iter().filter(|r| r.0 == Tone::Warning).count();
        face::show(ui, &Face { tone: if differ == 0 { Tone::Success } else { Tone::Warning }, head: if differ == 0 { "What's in both is the same".into() } else { format!("{} in both but different", many(differ as i64, "thing")) }, sub: format!("{same} the same, {ones} in one only"), notes: vec![], pills: vec![], facts: vec![] }, Side::None);
        ui.add_space(10.0);
        card(ui, |ui| {
            panel(ui, "Differences", "click one for both sides: the first in red, the second in green");
            ui.spacing_mut().item_spacing.y = 0.0;
            if rows.is_empty() {
                said(ui, "None.", TEXT_SUBTLE());
            }
            for (t, k, w, d) in rows.iter().take(300) {
                let (r, resp) = dash::line(ui, u(28.0), !d.is_empty());
                ui.painter().circle_filled(egui::pos2(r.left() + u(5.0), r.center().y), u(4.5), tone_color(*t));
                pg::label_at(ui, ui.painter(), egui::pos2(r.left() + u(18.0), r.center().y), k, 13.0, TEXT_DEFAULT(), r.width() * 0.45);
                pg::label_at(ui, ui.painter(), egui::pos2(r.left() + u(30.0) + r.width() * 0.45, r.center().y), w, 12.5, TEXT_MUTED(), r.width() * 0.5);
                if resp.clicked() {
                    self.incident.cmp.open = if self.incident.cmp.open.as_ref() == Some(k) { None } else { Some(k.clone()) };
                }
                if self.incident.cmp.open.as_ref() == Some(k) {
                    Frame::new().fill(BG_SUBTLE()).corner_radius(CornerRadius::same(8)).inner_margin(Margin::same(10)).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.spacing_mut().item_spacing.y = 4.0;
                        diff_table(ui, d);
                    });
                }
            }
            if rows.len() > 300 {
                said(ui, &format!("and {} more: filter or pick a namespace", rows.len() - 300), TEXT_PLACEHOLDER());
            }
        });
        None
    }

    /// What runs against what Argo CD says, and who changed what by hand.
    pub(super) fn drift(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        let now = kube::now_secs();
        let mut off: Vec<Item> = vec![];
        let mut synced: HashMap<(String, String), i64> = HashMap::new();
        for (c, o) in self.op_items(argo::APPS) {
            if let Some(t) = pod::time_of(&o["status"]["operationState"]["finishedAt"]) {
                synced.insert((c.to_string(), name_of(o).to_string()), t);
            }
            for r in o["status"]["resources"].as_array().into_iter().flatten().filter(|r| r["status"] == "OutOfSync") {
                off.push(Item::new(Tone::Warning, vec![text(&r["name"]), if r["requiresPruning"] == true { "not in Git any more".into() } else { "differs from Git".into() }, text(&r["kind"]), text(&r["namespace"]), name_of(o).to_string(), ago(now, pod::time_of(&o["status"]["operationState"]["finishedAt"]))]).go(argo::resource_go(self, c, r)));
            }
        }
        let mut hand: Vec<(i64, Item)> = vec![];
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            let Some(Ok(Value::Array(l))) = self.answer(&format!("writers|{c}")) else { continue };
            for o in l.iter().filter(|o| self.ns_ok(o["ns"].as_str().unwrap_or(""))) {
                for f in o["by"].as_array().into_iter().flatten().filter(|f| f["op"] == "Update" && f["sub"].is_null() && by_hand(f["m"].as_str().unwrap_or(""))) {
                    let Some(at) = pod::time_of(&f["at"]) else { continue };
                    let app = text(&o["app"]);
                    // After the last sync it's drift; before, Argo CD has been over it.
                    let after = synced.get(&(c.clone(), app.clone())).map(|t| at > *t).unwrap_or(false);
                    let what: Vec<String> = f["spec"].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).chain((f["data"] == true).then(|| "data".to_string())).collect();
                    if what.is_empty() {
                        continue;
                    }
                    let sel = workload::kind_named(o["kind"].as_str().unwrap_or("")).map(|k| Go::Object(Selected { ctx: c.clone(), kind: k, ns: text(&o["ns"]), name: text(&o["name"]) }));
                    hand.push((at, Item::new(if after { Tone::Warning } else { Tone::Muted }, vec![format!("{}/{}", text(&o["ns"]), text(&o["name"])), if after { "after the last sync".into() } else if app.is_empty() { "not in Git".into() } else { "synced since".into() }, text(&o["kind"]), text(&f["m"]), what.join(", "), app, ago(now, Some(at))]).go(sel)));
                }
            }
        }
        hand.sort_by_key(|h| (std::cmp::Reverse(h.1.bad()), std::cmp::Reverse(h.0)));
        let all: Vec<Item> = off.iter().map(|i| Item::new(i.tone, i.cells.clone())).collect();
        let mut f = summary(&all, "object");
        if all.is_empty() {
            f.tone = Tone::Success;
            f.head = if self.crd_index(argo::APPS).is_some() { "Everything Argo CD manages is as in Git".into() } else { "Argo CD isn't here".into() };
        } else {
            f.head = format!("{} from Git", many(all.len() as i64, "object differs").replace("object differss", "objects differ"));
        }
        let n = hand.iter().filter(|h| h.1.bad()).count();
        if n > 0 {
            f.notes.push(format!("{} changed by hand after the last sync.", many(n as i64, "object")));
            f.tone = Tone::Warning;
        }
        f.pills.clear();
        face::show(ui, &f, Side::None);
        ui.add_space(10.0);
        let mut off = self.op_filter(off);
        worst_first(&mut off);
        go = table(ui, &format!("Not as in Git ({})", off.len()), "from Argo CD", &[("Object", 0.3), ("State", 0.16), ("Kind", 0.16), ("Namespace", 0.14), ("App", 0.16), ("Synced", 0.08)], &off, 100, &self.op_missing(argo::APPS).unwrap_or("Nothing.".into())).or(go);
        let hand = self.op_filter(hand.into_iter().map(|h| h.1).collect());
        let none = match self.active.iter().find_map(|c| match self.powers.answers.get(&format!("writers|{c}")) { Some(None) => Some("Reading who wrote what…".to_string()), Some(Some(Err(e))) => Some(truncate(e, 200)), _ => None }) {
            Some(w) => w,
            None => "No sign of it.".into(),
        };
        go = table(ui, &format!("Changed by hand ({})", hand.len()), "objects last written by a person's tool, from the marks Kubernetes keeps; which fields, not which values", &[("Object", 0.26), ("", 0.13), ("Kind", 0.1), ("With", 0.15), ("Fields", 0.2), ("App", 0.1), ("When", 0.06)], &hand, 120, &none).or(go);
        go
    }
}

pub(super) fn write_snapshot(name: &str, p: &Picture) -> String {
    let m: BTreeMap<&String, Digest> = p.iter().map(|(k, v)| (k, guarded(v))).collect();
    serde_json::json!({"kubedog": "snapshot", "version": 1, "name": name, "at": kube::now_secs(), "objects": m}).to_string()
}

pub(super) fn read_snapshot(t: &str) -> Result<(String, Picture), String> {
    let v: Value = serde_json::from_str(t).map_err(|e| e.to_string())?;
    if v["kubedog"] != "snapshot" {
        return Err("it isn't a Kubedog snapshot".into());
    }
    let p = v["objects"].as_object().into_iter().flatten().map(|(k, d)| (k.clone(), d.as_object().into_iter().flatten().map(|(a, b)| (a.clone(), text(b))).collect())).collect();
    Ok((text(&v["name"]), p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn snapshots_hide_values() {
        let dep = |img: &str, val: &str| digest(Kind::Deployments, &json!({"spec": {"replicas": 1, "template": {"spec": {"containers": [{"name": "web", "image": img, "args": ["--token=abc"], "env": [{"name": "TOKEN", "value": val}, {"name": "P", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}]}]}}}}));
        let mut p = Picture::new();
        p.insert("deployment shop/web".into(), dep("web:1", "hunter2"));
        p.insert("config map shop/cfg".into(), digest(Kind::ConfigMaps, &json!({"data": {"a": "hunter2"}})));
        let t = write_snapshot("lab", &p);
        assert!(!t.contains("hunter2") && !t.contains("--token") && t.contains("web:1") && t.contains("from secret s, k"));
        let (n, back) = read_snapshot(&t).unwrap();
        assert_eq!(n, "lab");
        // The same values still count as the same, other ones don't.
        assert!(differences(&guarded(&dep("web:1", "hunter2")), &back["deployment shop/web"]).is_empty());
        let d = differences(&guarded(&dep("web:2", "other")), &back["deployment shop/web"]);
        assert_eq!(d.iter().map(|x| x.0.as_str()).collect::<Vec<_>>(), vec!["web env TOKEN", "web image"]);
        assert!(read_snapshot("{}").is_err() && read_snapshot("x").is_err());
    }

    #[test]
    fn writers() {
        let w = slim_writers(&json!({"kind": "Deployment", "metadata": {"name": "web", "namespace": "shop", "annotations": {"argocd.argoproj.io/tracking-id": "shop:apps/Deployment:shop/web", "x": "SECRET"}, "managedFields": [{"manager": "kubectl-edit", "operation": "Update", "time": "2026-01-01T00:00:00Z", "fieldsV1": {"f:spec": {"f:replicas": {}}}}]}}));
        assert_eq!((w["app"].as_str(), w["by"][0]["spec"][0].as_str()), (Some("shop"), Some("replicas")));
        assert!(!w.to_string().contains("SECRET"));
        assert!(by_hand("kubectl-client-side-apply") && by_hand("Mozilla") && !by_hand("argocd-controller") && !by_hand("kube-controller-manager"));
    }
}
