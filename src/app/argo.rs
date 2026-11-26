//! Argo CD: which apps are out of step and why, what's in each, its history; sync and roll back.

use super::dash::line;
use super::face::{many, Face, Fact, Side};
use super::ops::{ago, ns_of, obj, summary, table, text, worst_first, Item};
use super::pg::{label_at, panel};
use super::podxray::Go;
use super::work::{name_of, said};
use super::*;

pub(super) const APPS: &str = "applications.argoproj.io";

/// How an app is, and why: (tone, word, reasons).
pub(super) fn app_state(o: &Value) -> (Tone, String, Vec<String>) {
    let st = &o["status"];
    let (sync, health) = (text(&st["sync"]["status"]), text(&st["health"]["status"]));
    let op = &st["operationState"];
    let phase = text(&op["phase"]);
    let mut why = vec![];
    for c in st["conditions"].as_array().into_iter().flatten() {
        why.push(format!("{}: {}", face::spaced(c["type"].as_str().unwrap_or("")), truncate(c["message"].as_str().unwrap_or(""), 300)));
    }
    let failed = matches!(phase.as_str(), "Failed" | "Error");
    if failed {
        why.push(format!("Last sync {}: {}", phase.to_lowercase(), truncate(op["message"].as_str().unwrap_or(""), 300)));
        for r in op["syncResult"]["resources"].as_array().into_iter().flatten().filter(|r| r["status"] == "SyncFailed").take(5) {
            why.push(format!("{} {}: {}", text(&r["kind"]), text(&r["name"]), truncate(r["message"].as_str().unwrap_or(""), 200)));
        }
    }
    let off: Vec<String> = st["resources"].as_array().into_iter().flatten().filter(|r| r["status"] == "OutOfSync").map(|r| format!("{} {}", text(&r["kind"]), text(&r["name"]))).collect();
    if !off.is_empty() {
        why.push(format!("Out of sync: {}", some_names(&off)));
    }
    let ill: Vec<String> = st["resources"].as_array().into_iter().flatten().filter(|r| matches!(r["health"]["status"].as_str(), Some("Degraded" | "Missing"))).map(|r| format!("{} {} is {}", text(&r["kind"]), text(&r["name"]), text(&r["health"]["status"]).to_lowercase())).collect();
    if !ill.is_empty() {
        why.push(some_names(&ill));
    }
    let running = phase == "Running";
    match (health.as_str(), sync.as_str()) {
        _ if running => (Tone::Info, "Syncing".into(), why),
        ("Degraded", _) | ("Missing", _) => (Tone::Danger, health, why),
        _ if failed && sync != "Synced" => (Tone::Danger, "Sync failed".into(), why),
        (_, "OutOfSync") => (Tone::Warning, "Out of sync".into(), why),
        ("Progressing", _) => (Tone::Info, "Progressing".into(), why),
        ("Suspended", _) => (Tone::Muted, "Suspended".into(), why),
        (_, "Synced") => (if why.is_empty() { Tone::Success } else { Tone::Warning }, if why.is_empty() { "Synced".into() } else { "Synced, with a warning".into() }, why),
        _ => (Tone::Warning, "Unknown".into(), why),
    }
}

fn revision(r: &str) -> String {
    if r.len() == 40 && r.bytes().all(|b| b.is_ascii_hexdigit()) { r[..8].to_string() } else { r.to_string() }
}

/// The change that asks Argo CD to sync, to a kept revision when given.
pub(super) fn sync_patch(o: &Value, back: Option<&Value>) -> String {
    let mut sync = serde_json::json!({ "prune": false });
    if o["spec"]["syncPolicy"]["syncOptions"].is_array() {
        sync["syncOptions"] = o["spec"]["syncPolicy"]["syncOptions"].clone();
    }
    if let Some(h) = back {
        sync["revision"] = h["revision"].clone();
        if h["source"].is_object() {
            sync["source"] = h["source"].clone();
        }
        for (k, v) in [("revisions", &h["revisions"]), ("sources", &h["sources"])] {
            if v.is_array() {
                sync[k] = v.clone();
            }
        }
    }
    serde_json::json!({ "operation": { "initiatedBy": { "username": "kubedog" }, "sync": sync } }).to_string()
}

pub(super) fn patch_args(ctx: &str, ns: &str, kind: &str, name: &str, patch: &str) -> Vec<String> {
    ["--context", ctx, "-n", ns, "patch", kind, name, "--type=merge", "-p", patch].iter().map(|s| s.to_string()).collect()
}

/// Where a resource of an app leads: its page, when Kubedog has one.
pub(super) fn resource_go(app: &KubedogApp, ctx: &str, r: &Value) -> Option<Go> {
    let (kind, ns, name) = (r["kind"].as_str()?, r["namespace"].as_str().unwrap_or(""), r["name"].as_str()?);
    let group = r["group"].as_str().unwrap_or("");
    if let Some((i, _)) = app.crds.iter().enumerate().find(|(_, k)| k.kind == kind && k.group == group) {
        return Some(Go::Custom(crds::CustomSel { ctx: ctx.into(), idx: i as u32, ns: ns.into(), name: name.into() }));
    }
    workload::kind_named(kind).map(|k| obj(ctx, k, ns, name))
}

impl KubedogApp {
    pub(super) fn argo_page(&mut self, ui: &mut Ui) -> Option<Go> {
        if let Some(s) = self.powers.sel.clone() {
            return self.argo_app(ui, &s);
        }
        let now = kube::now_secs();
        let apps: Vec<(String, Value)> = self.op_items(APPS).into_iter().map(|(c, o)| (c.to_string(), o.clone())).collect();
        let mut sels: Vec<crds::CustomSel> = vec![];
        let idx = self.crd_index(APPS).unwrap_or(0);
        let items: Vec<Item> = apps
            .iter()
            .map(|(c, o)| {
                let (t, w, why) = app_state(o);
                let st = &o["status"];
                let src = if o["spec"]["source"].is_object() { &o["spec"]["source"] } else { &o["spec"]["sources"][0] };
                let sel = crds::CustomSel { ctx: c.clone(), idx, ns: ns_of(o).into(), name: name_of(o).into() };
                let cells = vec![
                    self.full_name(c, o),
                    w,
                    why.first().cloned().unwrap_or_default(),
                    text(&o["spec"]["project"]),
                    text(&o["spec"]["destination"]["namespace"]),
                    format!("{}{}", text(&src["path"]), src["chart"].as_str().unwrap_or("")),
                    revision(st["sync"]["revision"].as_str().unwrap_or("")),
                    ago(now, pod::time_of(&st["operationState"]["finishedAt"])),
                ];
                sels.push(sel.clone());
                Item::new(t, cells).tip(format!("{}\n{}", self.full_name(c, o), why.join("\n"))).go(Some(Go::Custom(sel)))
            })
            .collect();
        face::show(ui, &{ let mut f = summary(&items, "app"); let sets = self.op_items("applicationsets.argoproj.io").len(); if sets > 0 { f.sub = format!("{}, {}", f.sub, many(sets as i64, "application set")); } f }, Side::None);
        ui.add_space(10.0);
        self.bad_switch(ui);
        let mut items = self.op_filter(items);
        worst_first(&mut items);
        let none = self.op_missing(APPS).unwrap_or("None.".into());
        let g = table(ui, &format!("Applications ({})", items.len()), "click one for what's in it, its history and syncing", &[("App", 0.2), ("State", 0.11), ("Why", 0.25), ("Project", 0.1), ("Namespace", 0.11), ("Path", 0.12), ("Revision", 0.06), ("Synced", 0.07)], &items, 200, &none);
        let mut go = None;
        match g {
            // Opens here, with its tree and history.
            Some(Go::Custom(s)) => self.powers.sel = Some(s),
            g => go = g,
        }
        let sets: Vec<Item> = self.op_items("applicationsets.argoproj.io").into_iter().map(|(c, o)| {
            let err = o["status"]["conditions"].as_array().into_iter().flatten().find(|x| x["type"] == "ErrorOccurred" && x["status"] == "True");
            let (t, w) = match err { Some(e) => (Tone::Danger, truncate(e["message"].as_str().unwrap_or(""), 200)), None => (Tone::Success, "Generating".into()) };
            Item::new(t, vec![self.full_name(c, o), w, many(o["status"]["resourcesCount"].as_i64().unwrap_or(0), "app")]).go(self.custom_go(c, "applicationsets.argoproj.io", o))
        }).collect();
        if !sets.is_empty() {
            let sets = self.op_filter(sets);
            go = table(ui, &format!("Application sets ({})", sets.len()), "", &[("Set", 0.4), ("State", 0.4), ("Makes", 0.2)], &sets, 60, "None.").or(go);
        }
        go
    }

    /// One app: what's in it, what the last sync said, and its history.
    fn argo_app(&mut self, ui: &mut Ui, s: &crds::CustomSel) -> Option<Go> {
        let mut go = None;
        let id = pg::PgId { ctx: s.ctx.clone(), ns: s.ns.clone(), name: s.name.clone() };
        if self.super_back(ui, &id, "Argo CD") {
            self.powers.sel = None;
            return None;
        }
        let Some(o) = self.op_all(&s.ctx, APPS).iter().find(|o| name_of(o) == s.name && ns_of(o) == s.ns).cloned() else {
            said(ui, "This app is no longer there.", TEXT_SUBTLE());
            return None;
        };
        let now = kube::now_secs();
        let (tone, head, why) = app_state(&o);
        let (spec, st) = (&o["spec"], &o["status"]);
        let src = if spec["source"].is_object() { &spec["source"] } else { &spec["sources"][0] };
        let auto = &spec["syncPolicy"]["automated"];
        let is_auto = auto.is_object() && auto["enabled"] != false;
        ui.horizontal(|ui| {
            ui.label(RichText::new(&s.name).size(z(20.0)).color(TEXT_DEFAULT()));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if button(ui, "Sync", true, false) {
                    let body = format!("Ask Argo CD to sync “{}” now? It applies what's in Git; nothing is pruned.", s.name);
                    self.request(Action::Run { sel: Selected { ctx: s.ctx.clone(), kind: Kind::Pods, ns: s.ns.clone(), name: s.name.clone() }, args: patch_args(&s.ctx, &s.ns, APPS, &s.name, &sync_patch(&o, None)), what: format!("Sync of {} asked for", s.name) }, "Sync".into(), body, "Sync", false);
                }
                if button(ui, "Compare again", false, false) {
                    let args = ["--context", &s.ctx, "-n", &s.ns, "annotate", APPS, &s.name, "argocd.argoproj.io/refresh=normal", "--overwrite"].iter().map(|x| x.to_string()).collect();
                    self.request(Action::Run { sel: Selected { ctx: s.ctx.clone(), kind: Kind::Pods, ns: s.ns.clone(), name: s.name.clone() }, args, what: format!("{} is compared with Git again", s.name) }, "Compare again".into(), format!("Ask Argo CD to compare “{}” with Git again? It sets an annotation; nothing is synced by it, unless auto-sync is on.", s.name), "Compare", false);
                }
                if button(ui, "Object page", false, false) {
                    go = Some(Go::Custom(s.clone()));
                }
            });
        });
        ui.add_space(6.0);
        let f = Face {
            tone,
            head,
            sub: format!("last sync {}", ago(now, pod::time_of(&st["operationState"]["finishedAt"]))),
            notes: why,
            pills: vec![],
            facts: vec![
                Fact::new("Project", text(&spec["project"])),
                Fact::new("Source", text(&src["repoURL"])),
                Fact::new("Path", format!("{}{}", text(&src["path"]), src["chart"].as_str().unwrap_or(""))),
                Fact::new("Target revision", text(&src["targetRevision"])),
                Fact::new("Synced revision", revision(st["sync"]["revision"].as_str().unwrap_or(""))),
                Fact::new("Namespace", text(&spec["destination"]["namespace"])),
                Fact::new("Auto-sync", if is_auto { format!("on{}{}", if auto["prune"] == true { ", prunes" } else { "" }, if auto["selfHeal"] == true { ", heals itself" } else { "" }) } else { "off".into() }),
                Fact::new("Health", text(&st["health"]["status"])),
                Fact::new("Sync", text(&st["sync"]["status"])),
            ],
        };
        face::show(ui, &f, Side::None);
        ui.add_space(12.0);
        self.bad_switch(ui);
        let mut items: Vec<Item> = st["resources"].as_array().into_iter().flatten().map(|r| {
            let (sy, h) = (text(&r["status"]), text(&r["health"]["status"]));
            let t = match (h.as_str(), sy.as_str()) { ("Degraded" | "Missing", _) => Tone::Danger, (_, "OutOfSync") => Tone::Warning, ("Progressing", _) => Tone::Info, (_, "Synced") => Tone::Success, _ => Tone::Muted };
            let word = match (sy.as_str(), h.as_str()) { (a, "") => a.to_string(), (a, b) => format!("{a}, {b}") };
            Item::new(t, vec![text(&r["name"]), word, text(&r["kind"]), text(&r["namespace"]), truncate(r["health"]["message"].as_str().unwrap_or(""), 200)]).go(resource_go(self, &s.ctx, r))
        }).collect();
        items = self.op_filter(items);
        worst_first(&mut items);
        go = table(ui, &format!("What's in it ({})", items.len()), "", &[("Name", 0.34), ("State", 0.18), ("Kind", 0.16), ("Namespace", 0.14), ("Message", 0.18)], &items, 200, "Nothing.").or(go);
        // History.
        let mut back: Option<Value> = None;
        card(ui, |ui| {
            panel(ui, "History", if is_auto { "auto-sync is on, so an older revision would be replaced at once: switch it off in Git first" } else { "" });
            ui.spacing_mut().item_spacing.y = 0.0;
            let h: Vec<&Value> = st["history"].as_array().into_iter().flatten().rev().collect();
            if h.is_empty() {
                said(ui, "None kept.", TEXT_SUBTLE());
            }
            for (i, e) in h.iter().enumerate().take(15) {
                let (r, _) = line(ui, u(30.0), false);
                let t = pod::time_of(&e["deployedAt"]);
                label_at(ui, ui.painter(), r.left_center(), &format!("#{}", e["id"]), 12.5, TEXT_SUBTLE(), u(50.0));
                label_at(ui, ui.painter(), egui::pos2(r.left() + u(60.0), r.center().y), &revision(e["revision"].as_str().or(e["revisions"][0].as_str()).unwrap_or("")), 13.0, TEXT_DEFAULT(), u(160.0));
                label_at(ui, ui.painter(), egui::pos2(r.left() + u(230.0), r.center().y), &format!("{}{}", ago(now, t), t.map(|t| format!(", {}", pod::when(t))).unwrap_or_default()), 12.5, TEXT_MUTED(), u(280.0));
                label_at(ui, ui.painter(), egui::pos2(r.left() + u(530.0), r.center().y), if e["initiatedBy"]["automated"] == true { "automatic" } else { e["initiatedBy"]["username"].as_str().unwrap_or("") }, 12.5, TEXT_SUBTLE(), u(140.0));
                if i == 0 {
                    label_at(ui, ui.painter(), egui::pos2(r.right() - u(80.0), r.center().y), "current", 12.0, SUCCESS(), u(80.0));
                } else if !is_auto {
                    let b = egui::Rect::from_min_size(egui::pos2(r.right() - u(96.0), r.top() + 2.0), egui::vec2(u(96.0), u(26.0)));
                    let mut c = ui.new_child(egui::UiBuilder::new().max_rect(b).layout(Layout::right_to_left(Align::Center)));
                    if button(&mut c, "Roll back", false, false) {
                        back = Some((*e).clone());
                    }
                }
            }
        });
        if let Some(h) = back {
            let body = format!("Roll “{}” back to #{} ({})? Argo CD applies that revision; nothing is pruned.", s.name, h["id"], revision(h["revision"].as_str().unwrap_or("")));
            self.request(Action::Run { sel: Selected { ctx: s.ctx.clone(), kind: Kind::Pods, ns: s.ns.clone(), name: s.name.clone() }, args: patch_args(&s.ctx, &s.ns, APPS, &s.name, &sync_patch(&o, Some(&h))), what: format!("Rollback of {} asked for", s.name) }, "Roll back".into(), body, "Roll back", false);
        }
        go
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn states() {
        let s = |sync: &str, health: &str, phase: &str| app_state(&json!({"status": {"sync": {"status": sync}, "health": {"status": health}, "operationState": {"phase": phase, "message": "m"}, "resources": [{"kind": "Service", "name": "web", "status": sync}]}}));
        assert_eq!(s("Synced", "Healthy", "Succeeded").0, Tone::Success);
        let o = s("OutOfSync", "Healthy", "Succeeded");
        assert_eq!((o.0, o.1.as_str(), o.2[0].as_str()), (Tone::Warning, "Out of sync", "Out of sync: Service web"));
        assert_eq!(s("OutOfSync", "Healthy", "Failed").1, "Sync failed");
        assert_eq!(s("Synced", "Degraded", "Succeeded").0, Tone::Danger);
        assert_eq!(s("OutOfSync", "Missing", "Running").0, Tone::Info);
        assert_eq!(s("", "", "").0, Tone::Warning);
    }

    #[test]
    fn asking() {
        let o = json!({"spec": {"syncPolicy": {"syncOptions": ["CreateNamespace=true"]}}});
        let p: Value = serde_json::from_str(&sync_patch(&o, None)).unwrap();
        assert_eq!(p["operation"]["sync"], json!({"prune": false, "syncOptions": ["CreateNamespace=true"]}));
        let b: Value = serde_json::from_str(&sync_patch(&o, Some(&json!({"id": 3, "revision": "abc", "source": {"path": "x"}})))).unwrap();
        assert_eq!((&b["operation"]["sync"]["revision"], &b["operation"]["sync"]["source"]["path"]), (&json!("abc"), &json!("x")));
        assert_eq!(patch_args("c", "n", APPS, "a", "{}").join(" "), "--context c -n n patch applications.argoproj.io a --type=merge -p {}");
        assert_eq!(revision("0123456789abcdef0123456789abcdef01234567"), "01234567");
        assert_eq!(revision("v1.2"), "v1.2");
    }
}
