//! What a right click on a row of a list offers: the things done most with that kind, the workload a pod belongs to,
//! and, when several are ticked, what can be done with all of them. Changes go through the same lock and question
//! as their buttons.

use super::picks::{self, Verb};
use super::*;

/// What was picked in the menu.
pub(super) enum RowDo {
    Open(Selected),
    Tab(Selected, Tab),
    Shell(Selected, String),
    PortForward(Selected),
    Restart(Selected),
    Scale(Selected),
    Cordon(Selected, bool),
    Drain(Selected),
    Delete(Selected),
    Node(String, String),
    Explain(Selected),
    Copy(String, &'static str),
    /// Everything that's ticked.
    Many(Verb),
}

/// The workload a pod belongs to, for restarting it: a deployment through its replica set, a stateful set or a daemon set.
pub(super) fn workload_of(pod: &Value, replica_sets: Option<&[Value]>) -> Option<(Kind, String)> {
    let o = pod["metadata"]["ownerReferences"].as_array()?.iter().find(|o| o["controller"] == true)?;
    let name = o["name"].as_str()?.to_string();
    match o["kind"].as_str()? {
        "StatefulSet" => Some((Kind::StatefulSets, name)),
        "DaemonSet" => Some((Kind::DaemonSets, name)),
        "ReplicaSet" => {
            let ns = pod["metadata"]["namespace"].as_str();
            // What the replica set itself says; without its list, its name less the template's hash.
            let rs = replica_sets.and_then(|l| l.iter().find(|r| r["metadata"]["name"].as_str() == Some(&name) && r["metadata"]["namespace"].as_str() == ns));
            let dep = match rs {
                Some(r) => r["metadata"]["ownerReferences"].as_array().and_then(|l| l.iter().find(|o| o["controller"] == true && o["kind"] == "Deployment")).and_then(|o| o["name"].as_str()).map(String::from),
                None => pod["metadata"]["labels"]["pod-template-hash"].as_str().and_then(|h| name.strip_suffix(&format!("-{h}"))).map(String::from),
            };
            dep.map(|d| (Kind::Deployments, d))
        }
        _ => None,
    }
}

/// One line of the menu: lit up while the mouse is on it.
fn item(ui: &mut Ui, text: &str, danger: bool) -> bool {
    let font = FontId::proportional(z(13.5));
    let color = if danger { DANGER() } else { TEXT_DEFAULT() };
    let g = ui.painter().layout_no_wrap(text.to_string(), font, color);
    // As wide as the widest line, which is known from the last frame (the menu is drawn every frame it's open).
    let key = ui.id().with("row-menu-width");
    let widest = ui.data(|d| d.get_temp::<f32>(key)).unwrap_or(u(220.0));
    let need = g.size().x + u(24.0);
    if need > widest {
        ui.data_mut(|d| d.insert_temp(key, need));
        ui.ctx().request_repaint();
    }
    let w = need.max(widest);
    let (rect, r) = ui.allocate_exact_size(egui::vec2(w, u(26.0)), Sense::click());
    if r.hovered() {
        let fill = if danger { DANGER().gamma_multiply(0.22) } else { PRIMARY().gamma_multiply(0.28) };
        ui.painter().rect_filled(rect, CornerRadius::same(4), fill);
    }
    ui.painter().galley(egui::pos2(rect.left() + u(8.0), rect.center().y - g.size().y / 2.0), g, color);
    let r = r.on_hover_cursor(egui::CursorIcon::PointingHand);
    if r.clicked() {
        ui.close();
        return true;
    }
    false
}

impl KubedogApp {
    /// The menu for one row. `picked`: how many are ticked, when this row is one of them.
    pub(super) fn row_menu(&self, ui: &mut Ui, sel: &Selected, picked: usize) -> Option<RowDo> {
        let mut out = None;
        let mut put = |d: RowDo| out = Some(d);
        ui.set_min_width(u(230.0));
        ui.spacing_mut().item_spacing.y = 1.0;
        let locked = !self.unlocked.contains(&sel.ctx);
        let lock = if locked { "  🔒" } else { "" };
        if picked > 1 {
            ui.horizontal(|ui| {
                ui.add_space(u(8.0));
                ui.label(RichText::new(format!("{picked} ticked")).size(z(12.0)).color(TEXT_SUBTLE()));
            });
            for v in picks::verbs(sel.kind) {
                let t = match v {
                    Verb::Restart => format!("Restart all {picked}…{lock}"),
                    Verb::Delete => format!("Delete all {picked}…{lock}"),
                };
                if item(ui, &t, *v == Verb::Delete) {
                    put(RowDo::Many(*v));
                }
            }
            ui.separator();
        }
        // The name on top counts for the width too.
        let head = ui.painter().layout_no_wrap(truncate(&sel.name, 40), FontId::proportional(z(12.0)), TEXT_SUBTLE()).size().x + u(24.0);
        let key = ui.id().with("row-menu-width");
        if ui.data(|d| d.get_temp::<f32>(key)).is_none_or(|w| w < head) {
            ui.data_mut(|d| d.insert_temp(key, head));
        }
        ui.horizontal(|ui| {
            ui.add_space(u(8.0));
            ui.label(RichText::new(truncate(&sel.name, 40)).size(z(12.0)).color(TEXT_SUBTLE()));
        });
        let obj = self.object_of(sel);
        if item(ui, "Open", false) {
            put(RowDo::Open(sel.clone()));
        }
        if sel.kind.has_logs() && item(ui, "Logs", false) {
            put(RowDo::Tab(sel.clone(), Tab::Logs));
        }
        if sel.kind == Kind::Pods {
            let o = obj.as_ref();
            let running = o.is_some_and(|o| o["status"]["phase"] == "Running");
            let containers: Vec<String> = o.and_then(|o| o["spec"]["containers"].as_array()).map(|l| l.iter().filter_map(|c| c["name"].as_str().map(String::from)).collect()).unwrap_or_default();
            if running && containers.len() > 1 {
                ui.menu_button(RichText::new("  Shell").size(z(13.5)), |ui| {
                    for c in &containers {
                        if item(ui, c, false) {
                            put(RowDo::Shell(sel.clone(), c.clone()));
                        }
                    }
                });
            } else if running && item(ui, "Shell", false) {
                let c = o.and_then(|o| o["metadata"]["annotations"]["kubectl.kubernetes.io/default-container"].as_str().map(String::from)).or_else(|| containers.first().cloned()).unwrap_or_default();
                put(RowDo::Shell(sel.clone(), c));
            }
        }
        if sel.kind.can_port_forward() && item(ui, "Port forward…", false) {
            put(RowDo::PortForward(sel.clone()));
        }
        if item(ui, "YAML", false) {
            put(RowDo::Tab(sel.clone(), Tab::Yaml));
        }
        if sel.kind != Kind::Events && item(ui, "Events", false) {
            put(RowDo::Tab(sel.clone(), Tab::Events));
        }
        if self.prefs.ai.on && item(ui, "Explain with AI", false) {
            put(RowDo::Explain(sel.clone()));
        }
        // What it belongs to and runs on.
        if let (Kind::Pods, Some(o)) = (sel.kind, obj.as_ref()) {
            let rs = self.lists.get(&Self::list_key(&sel.ctx, Kind::ReplicaSets)).filter(|l| l.fetched.is_some()).map(|l| l.items.as_slice());
            let owner = workload_of(o, rs);
            let node = o["spec"]["nodeName"].as_str().filter(|n| !n.is_empty());
            if owner.is_some() || node.is_some() {
                ui.separator();
            }
            if let Some((k, n)) = owner {
                let w = Selected { ctx: sel.ctx.clone(), kind: k, ns: sel.ns.clone(), name: n.clone() };
                if item(ui, &format!("Restart {} “{}”…{lock}", k.singular(), truncate(&n, 30)), false) {
                    put(RowDo::Restart(w.clone()));
                }
                if item(ui, &format!("Open {} “{}”", k.singular(), truncate(&n, 30)), false) {
                    put(RowDo::Open(w));
                }
            }
            if let Some(n) = node {
                if item(ui, &format!("Open node “{}”", truncate(n, 30)), false) {
                    put(RowDo::Node(sel.ctx.clone(), n.to_string()));
                }
            }
        }
        let changes = sel.kind.can_restart() || sel.kind.can_scale() || sel.kind == Kind::Nodes;
        if changes {
            ui.separator();
        }
        if sel.kind.can_restart() && item(ui, &format!("Restart…{lock}"), false) {
            put(RowDo::Restart(sel.clone()));
        }
        if sel.kind.can_scale() && item(ui, &format!("Scale…{lock}"), false) {
            put(RowDo::Scale(sel.clone()));
        }
        if sel.kind == Kind::Nodes {
            let off = obj.as_ref().is_some_and(|o| o["spec"]["unschedulable"] == true);
            if item(ui, &format!("{}…{lock}", if off { "Uncordon" } else { "Cordon" }), false) {
                put(RowDo::Cordon(sel.clone(), !off));
            }
            if item(ui, &format!("Drain…{lock}"), false) {
                put(RowDo::Drain(sel.clone()));
            }
        }
        ui.separator();
        if item(ui, "Copy name", false) {
            put(RowDo::Copy(sel.name.clone(), "name"));
        }
        if sel.kind.namespaced() && item(ui, "Copy namespace/name", false) {
            put(RowDo::Copy(format!("{}/{}", sel.ns, sel.name), "namespace/name"));
        }
        if sel.kind != Kind::Events {
            ui.separator();
            if item(ui, &format!("Delete {}…{lock}", sel.kind.singular()), true) {
                put(RowDo::Delete(sel.clone()));
            }
        }
        out
    }

    pub(super) fn row_do(&mut self, d: RowDo) {
        match d {
            RowDo::Open(s) => {
                if self.view == View::Resource(s.kind) {
                    self.select(s);
                } else {
                    self.navigate(View::Resource(s.kind), Some(s));
                }
            }
            RowDo::Tab(s, t) => {
                self.tab = t;
                self.select(s);
            }
            RowDo::Shell(s, c) => self.open_shell(&s, &c),
            RowDo::PortForward(s) => {
                let ports = self.object_of(&s).map(|o| ports_of(s.kind, &o)).unwrap_or_default();
                let remote = ports.first().map(|p| p.to_string()).unwrap_or_default();
                let local = ports.first().map(|p| suggest_local(*p).to_string()).unwrap_or_default();
                self.dialog = Some(Dialog::PortForward { sel: s, ports, remote, local, open_browser: false });
            }
            RowDo::Restart(s) => self.ask_restart(&s),
            RowDo::Scale(s) => {
                let cur = self.object_of(&s).and_then(|o| o["spec"]["replicas"].as_i64()).unwrap_or(1);
                if self.demo {
                    self.toast("Demo data: actions are turned off.".into(), true);
                } else if !self.unlocked.contains(&s.ctx) {
                    self.dialog = Some(Dialog::Protected { ctx: s.ctx.clone() });
                } else {
                    self.dialog = Some(Dialog::Scale { sel: s, replicas: cur.to_string() });
                }
            }
            RowDo::Cordon(s, on) => {
                let body = if on { format!("Stop new pods from being scheduled on node “{}”? Running pods stay.", s.name) } else { format!("Allow new pods to be scheduled on node “{}” again?", s.name) };
                let (t, w) = if on { ("Cordon node", "Cordon") } else { ("Uncordon node", "Uncordon") };
                self.request(Action::Cordon(s, on), t.into(), body, w, false);
            }
            RowDo::Drain(s) => {
                if self.demo {
                    self.toast("Demo data: actions are turned off.".into(), true);
                } else if !self.unlocked.contains(&s.ctx) {
                    self.dialog = Some(Dialog::Protected { ctx: s.ctx.clone() });
                } else {
                    self.fetch_list(&s.ctx, Kind::Pods);
                    self.dialog = Some(Dialog::Drain { sel: s, delete_emptydir: false, disable_eviction: false, force: false });
                }
            }
            RowDo::Delete(s) => self.ask_delete(&s),
            RowDo::Node(c, n) => self.open_node(&c, &n),
            RowDo::Explain(s) => {
                let f = self.object_facts(&s);
                self.ai_explain(f);
            }
            RowDo::Copy(t, what) => {
                self.egui_ctx.copy_text(t);
                self.toast(format!("The {what} is copied"), false);
            }
            RowDo::Many(v) => {
                let Some(what) = self.pick_what() else { return };
                let ctxs: std::collections::BTreeSet<String> = self.picks.set.keys().map(|k| k.0.clone()).collect();
                match ctxs.len() {
                    1 => {
                        let c = ctxs.into_iter().next().unwrap_or_default();
                        self.ask_many(&what, v, &c);
                    }
                    // A change is for one cluster at a time: the bar has a button for each.
                    _ => self.toast("These are in several clusters: use the buttons at the bottom, one cluster at a time.".into(), true),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod(kind: &str, owner: &str, hash: Option<&str>) -> Value {
        let mut p = serde_json::json!({"metadata": {"name": "p", "namespace": "shop", "ownerReferences": [{"kind": kind, "name": owner, "controller": true}], "labels": {}}});
        if let Some(h) = hash {
            p["metadata"]["labels"]["pod-template-hash"] = h.into();
        }
        p
    }

    #[test]
    fn the_workload_of_a_pod() {
        assert_eq!(workload_of(&pod("ReplicaSet", "web-5c9d8b7f6", Some("5c9d8b7f6")), None), Some((Kind::Deployments, "web".into())));
        assert_eq!(workload_of(&pod("StatefulSet", "db", None), None), Some((Kind::StatefulSets, "db".into())));
        assert_eq!(workload_of(&pod("DaemonSet", "agent", None), None), Some((Kind::DaemonSets, "agent".into())));
        // A replica set of its own: nothing to restart. Jobs aren't restarted.
        assert_eq!(workload_of(&pod("ReplicaSet", "lonely", None), None), None);
        assert_eq!(workload_of(&pod("Job", "once", None), None), None);
        assert_eq!(workload_of(&serde_json::json!({"metadata": {"name": "p"}}), None), None);
        // What the replica set says counts, also when the names don't fit.
        let rs = [serde_json::json!({"metadata": {"name": "odd-1", "namespace": "shop", "ownerReferences": [{"kind": "Deployment", "name": "front", "controller": true}]}}), serde_json::json!({"metadata": {"name": "odd-1", "namespace": "other", "ownerReferences": [{"kind": "Deployment", "name": "wrong", "controller": true}]}})];
        assert_eq!(workload_of(&pod("ReplicaSet", "odd-1", Some("zz")), Some(&rs)), Some((Kind::Deployments, "front".into())));
        // One that isn't in the list (yet): its name says it.
        assert_eq!(workload_of(&pod("ReplicaSet", "new-1", Some("1")), Some(&rs)), Some((Kind::Deployments, "new".into())));
    }
}
