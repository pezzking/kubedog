//! Can A reach B? The page: picking both ends, the path as it should be (netpath.rs) with the rule that
//! lets it through or stops it. A real try only after a click, behind the lock.

use super::face::{Face, Fact, Side};
use super::incident::chip_button;
use super::netpath::{End, Say};
use super::ops::ns_of;
use super::pg::panel;
use super::podxray::Go;
use super::work::{name_of, said};
use super::*;

#[derive(Default)]
pub(super) struct Conn {
    pub from: String,
    pub to: String,
    pub port: String,
    pub a: Option<End>,
    pub b: Option<End>,
}

impl KubedogApp {
    /// Workloads, pods and services whose name matches, best first.
    pub(super) fn find_ends(&self, q: &str, kinds: &[Kind]) -> Vec<Selected> {
        let q = q.trim().to_lowercase();
        let mut v = vec![];
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            for k in kinds {
                for o in self.refs(c, *k, "").unwrap_or_default() {
                    if format!("{}/{}", ns_of(o), name_of(o)).to_lowercase().contains(&q) && (!q.is_empty() || self.ns_ok(ns_of(o))) {
                        v.push(Selected { ctx: c.clone(), kind: *k, ns: ns_of(o).into(), name: name_of(o).into() });
                    }
                }
            }
        }
        v.sort_by_key(|s| (s.name.to_lowercase() != q, s.name.len(), s.ns.clone()));
        v.truncate(10);
        v
    }

    /// A running pod of an end.
    pub(super) fn pod_at(&self, s: &Selected) -> Option<&Value> {
        let pods = match s.kind {
            Kind::Pods => self.refs(&s.ctx, Kind::Pods, &s.ns)?.into_iter().filter(|p| name_of(p) == s.name).collect(),
            Kind::Services => {
                let svc = self.refs(&s.ctx, Kind::Services, &s.ns)?.into_iter().find(|x| name_of(x) == s.name)?;
                svc["spec"]["selector"].as_object().filter(|m| !m.is_empty())?;
                self.refs(&s.ctx, Kind::Pods, &s.ns)?.into_iter().filter(|p| podnet::selector_matches(&svc["spec"]["selector"], &p["metadata"]["labels"])).collect()
            }
            _ => self.pods_of(s, &self.object_of(s)?)?,
        };
        let mut pods: Vec<&Value> = pods;
        pods.sort_by_key(|p| p["status"]["phase"] != "Running");
        pods.into_iter().next()
    }

    /// Picking both ends. (from or to, which)
    fn pick_end(&mut self, ui: &mut Ui, from: bool) -> Option<End> {
        let works: &[Kind] = if from { &[Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::Pods] } else { &[Kind::Services, Kind::Deployments, Kind::StatefulSets, Kind::Pods] };
        let mut pick = None;
        let conn = &mut self.incident.conn;
        let now = if from { conn.a.clone() } else { conn.b.clone() };
        let outside = matches!(now, Some(End::Outside | End::Address(_)));
        let text = if from { &mut conn.from } else { &mut conn.to };
        ui.horizontal_wrapped(|ui| {
            if !outside {
                filter_box(ui, text, "name", u(320.0));
            } else if !from {
                let mut h = match &now {
                    Some(End::Address(h)) => h.clone(),
                    _ => String::new(),
                };
                if ui.add(egui::TextEdit::singleline(&mut h).hint_text("name or address outside").desired_width(u(320.0))).changed() {
                    pick = Some(End::Address(h.trim().to_string()));
                }
            } else {
                said(ui, "from anywhere outside", TEXT_MUTED());
            }
            if !from {
                ui.add(egui::TextEdit::singleline(&mut conn.port).hint_text("port").desired_width(u(70.0))).on_hover_text("5432, or 53/udp");
            }
            if chip_button(ui, "outside the cluster", outside) {
                pick = Some(if from { End::Outside } else { End::Address(String::new()) });
                if outside {
                    if from { conn.a = None } else { conn.b = None }
                    pick = None;
                }
            }
        });
        if outside {
            return pick;
        }
        // Picked, and not looking for another: no list.
        if now.is_some() && (if from { &self.incident.conn.from } else { &self.incident.conn.to }).is_empty() {
            return pick;
        }
        let q = if from { self.incident.conn.from.clone() } else { self.incident.conn.to.clone() };
        ui.horizontal_wrapped(|ui| {
            for s in self.find_ends(&q, works) {
                let e = End::Object(s.clone());
                if chip_button(ui, &format!("{}/{} · {}", s.ns, s.name, s.kind.singular()), now.as_ref() == Some(&e)) {
                    pick = Some(e);
                }
            }
        });
        pick
    }

    /// Can A reach B, in the Incident Room and the Network Lab.
    pub(super) fn connection(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut pick: Option<(bool, End)> = None;
        // For pictures: "from>to>port", with "out" for outside and names as namespace/name.
        if let (Some(t), None, true) = (std::env::var("KUBEDOG_SHOT_OBJ").ok(), self.incident.conn.a.as_ref().and(self.incident.conn.b.as_ref()), self.screenshot.is_some()) {
            let p: Vec<&str> = t.split('>').collect();
            if p.len() == 3 {
                let end = |k: &Self, t: &str, kinds: &[Kind]| match t {
                    "out" => Some(End::Outside),
                    t if t.starts_with("addr:") => Some(End::Address(t[5..].to_string())),
                    t => k.find_ends(t, kinds).into_iter().next().map(End::Object),
                };
                self.incident.conn.a = end(self, p[0], &[Kind::Deployments, Kind::StatefulSets, Kind::Pods]);
                self.incident.conn.b = end(self, p[1], &[Kind::Services, Kind::Pods]);
                self.incident.conn.port = p[2].to_string();
            }
        }
        card(ui, |ui| {
            panel(ui, "From", "a workload or a pod, or outside");
            chosen(ui, self.incident.conn.a.as_ref());
            if let Some(e) = self.pick_end(ui, true) {
                pick = Some((true, e));
            }
        });
        ui.add_space(8.0);
        card(ui, |ui| {
            panel(ui, "To", "a service, a workload or a pod, or outside, and the port");
            chosen(ui, self.incident.conn.b.as_ref());
            if let Some(e) = self.pick_end(ui, false) {
                pick = Some((false, e));
            }
        });
        if let Some((from, e)) = pick {
            if from {
                self.incident.conn.from.clear();
                self.incident.conn.a = Some(e);
            } else {
                // A service brings its first port.
                if let End::Object(s) = &e {
                    if let Some(p) = Some(s).filter(|s| s.kind == Kind::Services).and_then(|s| self.object_of(s)).map(|o| o["spec"]["ports"][0].clone()).filter(|p| p["port"].is_i64()) {
                        self.incident.conn.port = format!("{}{}", p["port"], match p["protocol"].as_str() { Some("TCP") | None => String::new(), Some(x) => format!("/{}", x.to_lowercase()) });
                    }
                }
                self.incident.conn.to.clear();
                self.incident.conn.b = Some(e);
            }
        }
        ui.add_space(12.0);
        let (Some(a), Some(b)) = (self.incident.conn.a.clone(), self.incident.conn.b.clone()) else {
            said(ui, "Pick both ends.", TEXT_SUBTLE());
            return None;
        };
        let ctx = match (&a, &b) {
            (End::Object(x), End::Object(y)) if x.ctx != y.ctx => {
                said(ui, "They're in different clusters.", WARNING());
                return None;
            }
            (End::Object(x), _) | (_, End::Object(x)) => x.ctx.clone(),
            _ => {
                said(ui, "One of the ends has to be in the cluster.", WARNING());
                return None;
            }
        };
        if let End::Address(h) = &b {
            if nettest::read_target(h).map(|t| t.host != h.to_lowercase()).unwrap_or(true) {
                said(ui, "Give a name or an address, without a port.", TEXT_SUBTLE());
                return None;
            }
        }
        let Some((port, proto)) = netpath::read_port(&self.incident.conn.port) else {
            said(ui, "Give a port, like 5432 or 53/udp.", TEXT_SUBTLE());
            return None;
        };
        let path = self.net_path(&ctx, &a, &b, port, proto);
        let all = netpath::sum(&path.steps);
        let label = |e: &End| match e {
            End::Outside => "outside".to_string(),
            End::Address(h) => h.clone(),
            End::Object(s) => format!("{}/{}", s.ns, s.name),
        };
        let why = path.steps.iter().find(|s| s.say == all).map(|s| s.text.clone()).unwrap_or_default();
        let head = match all {
            Say::No => "No",
            Say::Maybe => "Maybe",
            Say::Unknown => "Nothing that's known stops it",
            _ => "Yes, nothing stops it",
        };
        face::show(ui, &Face { tone: all.tone(), head: head.into(), sub: format!("{} to {} on port {port}{}", label(&a), label(&b), if proto == "TCP" { "" } else { " (UDP)" }), notes: if all == Say::Yes { vec![] } else { vec![why] }, pills: vec![], facts: vec![Fact::new("Pod port", path.target.to_string()), Fact::new("Pod network", self.net_name(&ctx).unwrap_or("not known".into()))] }, Side::None);
        ui.add_space(10.0);
        let l: Vec<ops::Item> = path.steps.iter().map(|s| ops::Item::new(s.say.tone(), vec![s.text.clone(), s.say.word().into()]).tip(s.text.clone()).go(s.go.clone())).collect();
        let go = ops::table(ui, "Step by step", "as it should be, from what the cluster's objects say; nothing is tried", &[("Step", 0.86), ("Says", 0.14)], &l, 40, "");
        // A real try, and what came of it.
        if let (Some(_), End::Object(s)) = (path.from_pod.as_ref(), &a) {
            if !path.host.is_empty() && proto == "TCP" {
                ui.horizontal(|ui| {
                    if button(ui, "Try it for real", false, false) {
                        self.ask_tries(vec![(s.clone(), b.clone(), port as u16)], nettest::Mode::Tcp);
                    }
                    said(ui, "runs a short command in the pod, after you confirm", TEXT_PLACEHOLDER());
                });
                if let Some(d) = self.tried(s, &b, port) {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| pg::pill(ui, d.verdict().1, tone_color(d.verdict().0)));
                    if let Some(f) = &d.failed {
                        said(ui, f, TEXT_SUBTLE());
                    }
                    nettry::steps_card(ui, "As it was", "tried from the pod", &d.steps);
                }
            }
            ui.add_space(6.0);
            self.trace_part(ui, &ctx, &a, &b, port, proto);
        }
        go
    }
}

/// The end that's picked.
fn chosen(ui: &mut Ui, e: Option<&End>) {
    if let Some(End::Object(s)) = e {
        ui.horizontal(|ui| pg::pill(ui, &format!("{}/{} · {}", s.ns, s.name, s.kind.singular()), PRIMARY_TEXT()));
        ui.add_space(4.0);
    }
}
