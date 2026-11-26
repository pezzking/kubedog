//! What the AI is told about the page that's open, so a question can be about what you're looking at.

use super::aifacts::{Class, Facts, Standins};
use super::ops::{ns_of, text, Item};
use super::podxray::Go;
use super::work::name_of;
use super::*;
use std::cell::RefCell;

// ---------- what pages draw ----------

#[derive(Default)]
struct Notes {
    on: bool,
    class: Option<Class>,
    list: Vec<(Class, String, Option<Go>)>,
}

thread_local! {
    static NOTES: RefCell<Notes> = RefCell::default();
}

/// From here on, tables and headings that are drawn are written down.
pub(super) fn begin(on: bool) {
    NOTES.with(|n| *n.borrow_mut() = Notes { on, ..Default::default() });
}

/// What kind of facts the page shows from here on.
pub(super) fn class(c: Class) {
    NOTES.with(|n| n.borrow_mut().class = Some(c));
}

pub(super) fn end() -> Vec<(Class, String, Option<Go>)> {
    NOTES.with(|n| std::mem::take(&mut n.borrow_mut().list))
}

fn note(t: String, go: Option<Go>) {
    NOTES.with(|n| {
        let mut n = n.borrow_mut();
        if n.on && n.list.len() < 160 {
            let c = n.class.unwrap_or(Class::State);
            n.list.push((c, t, go));
        }
    });
}

fn listening() -> bool {
    NOTES.with(|n| n.borrow().on)
}

/// A table, the worst first as it's drawn.
pub(super) fn note_table(title: &str, heads: &[(&str, f32)], items: &[Item], none: &str) {
    if !listening() {
        return;
    }
    if items.is_empty() {
        return note(format!("{title}: {none}"), None);
    }
    for it in items.iter().take(40) {
        let cells = heads.iter().zip(&it.cells).filter(|(_, c)| !c.is_empty() && *c != "-").map(|(h, c)| if h.0.is_empty() { c.clone() } else { format!("{}: {c}", h.0) }).collect::<Vec<_>>().join("; ");
        note(format!("{title}: {cells}{}", if it.bad() { " (bad)" } else { "" }), it.go.clone());
    }
    if items.len() > 40 {
        note(format!("{title}: {} more", items.len() - 40), None);
    }
}

pub(super) fn note_face(f: &face::Face) {
    if !listening() {
        return;
    }
    note(format!("{}{} {}", f.head, if f.sub.is_empty() { "" } else { ":" }, f.sub), None);
    for n in &f.notes {
        note(n.clone(), None);
    }
    for x in &f.facts {
        note(format!("{}: {}", x.label, x.text), x.to.clone().map(Go::Object));
    }
}

// ---------- pages ----------

/// A row of a list: its columns.
pub(super) fn row_text(kind: Kind, r: &Row) -> String {
    kind.all_columns().iter().zip(&r.cells).filter(|(h, c)| !matches!(**h, "Labels" | "Name" | "Namespace" | "Context" | "CPU Usage" | "Memory Usage" | "Usage") && !c.text.is_empty() && c.text != "-").map(|(h, c)| format!("{h} {}", truncate(&c.text, 200))).collect::<Vec<_>>().join(", ")
}

/// What an object says about itself at the top of its status; its settings are values.
pub(super) fn custom_facts(f: &mut Facts, kind: &str, o: &Value, go: Option<Go>, deep: bool) {
    let name = format!("{kind} {}{}", name_of(o), if ns_of(o).is_empty() { String::new() } else { format!(" in {}", ns_of(o)) });
    let plain = |v: &Value| match v {
        Value::String(s) if !s.is_empty() && s.len() < 200 => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    };
    let top = |v: &Value| v.as_object().map(|m| m.iter().filter_map(|(k, x)| Some(format!("{k}={}", plain(x)?))).take(14).collect::<Vec<_>>().join(", ")).unwrap_or_default();
    let st = top(&o["status"]);
    f.add(Class::State, format!("{name}{}{}", if st.is_empty() { "" } else { ": " }, st), go.clone());
    let conds = o["status"]["conditions"].as_array().cloned().unwrap_or_default();
    for c in conds.iter().take(if deep { 12 } else { 3 }) {
        // In a list only what isn't as it should be.
        if deep || c["status"] != "True" {
            f.add(Class::State, format!("{name}: condition {} is {} {} {}", text(&c["type"]), text(&c["status"]), text(&c["reason"]), truncate(c["message"].as_str().unwrap_or(""), 240)), go.clone());
        }
    }
    if deep {
        let sp = top(&o["spec"]);
        if !sp.is_empty() {
            f.add(Class::Value, format!("{name} is set to: {sp}"), go);
        }
    }
}

impl KubedogApp {
    /// The page's name, with what it's narrowed to.
    pub(super) fn page_name(&self) -> String {
        if let Some(s) = &self.selected {
            return format!("{} {}{}", s.kind.singular(), s.name, if s.ns.is_empty() { String::new() } else { format!(" in {}", s.ns) });
        }
        let sub = |id: &Option<pg::PgId>, what: &str| id.as_ref().map(|i| format!("{what} {} in {}", i.name, i.ns));
        let one = match self.view {
            View::Custom(i) => self.custom_sel.as_ref().filter(|s| s.idx == i).and_then(|s| Some(format!("{} {}", self.crds.get(i as usize)?.kind, s.name))),
            View::Postgres => sub(&self.pg_sel, "Postgres cluster"),
            View::Elastic => sub(&self.es_sel, "Elasticsearch"),
            View::Pulsar => sub(&self.pu_sel, "Pulsar"),
            View::Incident => self.incident.sel.as_ref().filter(|_| self.incident.tab == 1).map(|s| format!("Why is {} {} broken", s.kind.singular(), s.name)),
            _ => None,
        };
        if let Some(t) = one {
            return t;
        }
        let name = match self.view {
            View::Resource(k) => k.label().to_string(),
            View::Custom(i) => self.crds.get(i as usize).map(|k| k.kind.clone()).unwrap_or_default(),
            View::ClusterOverview => "Cluster Overview".into(),
            View::WorkloadsOverview => "Workloads Overview".into(),
            View::PortForwards => "Port Forwards".into(),
            View::Helm => "Helm Releases".into(),
            View::Settings => "Settings".into(),
            View::ServiceMap => "Service Map".into(),
            View::StorageUsage => "Storage Usage".into(),
            View::Postgres => "Postgres Clusters".into(),
            View::Elastic => "Elasticsearch".into(),
            View::Pulsar => "Pulsar".into(),
            View::Hive => "Pod Hive".into(),
            View::Observatory => "Nodes from Grafana".into(),
            View::Proxmox => "Proxmox".into(),
            View::NetLab => "Network Lab".into(),
            View::Shells => "Shell".into(),
            View::Op(i) => powers::OPS.get(i as usize).map(|o| o.label.to_string()).unwrap_or_default(),
            View::Incident => format!("Incident Room, {}", ["What changed", "Why is it broken", "Errors in logs", "Can A reach B", "Compare clusters", "Drift from Git", "Ai-health-agent"][self.incident.tab.min(6)]),
            View::Readiness => "Readiness".into(),
        };
        let ns = match &self.ns_filter {
            Some(n) => format!(" in {n}"),
            None if !self.ns_multi.is_empty() => format!(" in {} namespaces", self.ns_multi.len()),
            None => String::new(),
        };
        let q = if self.search.trim().is_empty() { String::new() } else { format!(", filtered on \"{}\"", self.search.trim()) };
        format!("{name}{ns}{q}")
    }

    /// The page in a sentence: "this pod", "these Pods", "Argo CD".
    pub(super) fn page_noun(&self) -> String {
        if let Some(s) = &self.selected {
            return format!("this {}", s.kind.singular());
        }
        match self.view {
            View::Resource(k) => format!("these {}", k.label()),
            View::Custom(i) => {
                let k = self.crds.get(i as usize).map(|k| k.kind.clone()).unwrap_or_default();
                if self.custom_sel.as_ref().map(|s| s.idx == i).unwrap_or(false) { format!("this {k}") } else if k.ends_with('s') { format!("these {k}") } else { format!("these {k}s") }
            }
            View::ClusterOverview | View::Settings => if self.active.len() > 1 { "these clusters".into() } else { "this cluster".into() },
            View::WorkloadsOverview => "these workloads".into(),
            View::PortForwards => "these port forwards".into(),
            View::Helm => "these Helm releases".into(),
            View::ServiceMap => "this service map".into(),
            View::StorageUsage => "this storage".into(),
            View::Postgres => if self.pg_sel.is_some() { "this Postgres cluster".into() } else { "these Postgres clusters".into() },
            View::Elastic => if self.es_sel.is_some() { "this Elasticsearch".into() } else { "Elasticsearch".into() },
            View::Pulsar => if self.pu_sel.is_some() { "this Pulsar".into() } else { "Pulsar".into() },
            View::Hive => "these pods".into(),
            View::Observatory => "these nodes".into(),
            View::Proxmox => "these nodes".into(),
            View::NetLab => "this network".into(),
            View::Shells => if self.active.len() > 1 { "these clusters".into() } else { "this cluster".into() },
            View::Op(i) => powers::OPS.get(i as usize).map(|o| o.label.to_string()).unwrap_or_default(),
            View::Incident => match (self.incident.tab, &self.incident.sel) {
                (0, _) => "what changed".into(),
                (1, Some(s)) => format!("this {}", s.kind.singular()),
                (1, None) => "what's broken".into(),
                (2, _) => "these log errors".into(),
                (3, _) => "this connection".into(),
                (4, _) => "these differences".into(),
                (6, _) => "the Ai-health-agent's cases".into(),
                _ => "this drift".into(),
            },
            View::Readiness => "readiness".into(),
        }
    }

    /// The facts of the page that's open.
    pub(super) fn page_facts(&self) -> Facts {
        let shown: Vec<String> = self.active.iter().filter(|c| self.ctx_shown(c)).cloned().collect();
        if let Some(s) = self.selected.clone() {
            return self.object_facts(&s);
        }
        let mut f = Facts { title: self.page_name(), ctxs: shown.clone(), list: vec![] };
        match self.view {
            View::Resource(k) => self.list_facts(&mut f, k, 60),
            View::ClusterOverview | View::WorkloadsOverview | View::Settings | View::PortForwards | View::Shells => self.health_facts(&mut f),
            View::Helm => {
                for c in &shown {
                    if let Some((_, Ok(l))) = self.helm.get(&format!("helm|{c}")) {
                        for r in l.iter().filter(|r| self.ns_ok(r["namespace"].as_str().unwrap_or(""))).take(60) {
                            f.add(Class::State, format!("Helm release {} in {}: {}, chart {}, app version {}, revision {}", text(&r["name"]), text(&r["namespace"]), text(&r["status"]), text(&r["chart"]), text(&r["app_version"]), text(&r["revision"])), None);
                        }
                    }
                }
            }
            View::ServiceMap => {
                self.list_facts(&mut f, Kind::Services, 40);
                self.list_facts(&mut f, Kind::Ingresses, 30);
            }
            View::StorageUsage => {
                self.list_facts(&mut f, Kind::PersistentVolumeClaims, 50);
                for c in &shown {
                    for p in self.refs(c, Kind::PersistentVolumeClaims, "").unwrap_or_default().into_iter().filter(|p| self.ns_ok(ns_of(p))) {
                        if let Some(x) = self.claim_usage(c, ns_of(p), name_of(p)) {
                            let part = x.used / x.capacity.max(1.0);
                            if part > 0.6 {
                                f.add(Class::State, format!("Volume claim {} in {} is {:.0}% full", name_of(p), ns_of(p), part * 100.0), Some(ops::obj(c, Kind::PersistentVolumeClaims, ns_of(p), name_of(p))));
                            }
                        }
                    }
                }
            }
            View::Custom(i) => self.custom_page_facts(&mut f, i),
            View::Postgres => {
                for c in &shown {
                    for o in self.pg_list(c, "clusters.postgresql.cnpg.io").iter().filter(|o| self.ns_ok(ns_of(o))) {
                        if let Some(id) = &self.pg_sel {
                            if id.ctx != *c || id.name != name_of(o) || id.ns != ns_of(o) {
                                continue;
                            }
                        }
                        custom_facts(&mut f, "Postgres cluster", o, None, true);
                    }
                }
                if let Some(id) = &self.pg_sel {
                    f.ctxs = vec![id.ctx.clone()];
                }
                self.pods_near(&mut f, self.pg_sel.clone());
            }
            View::Elastic => {
                for c in &shown {
                    for o in self.es_items(c).iter().filter(|o| self.ns_ok(ns_of(o))) {
                        if self.es_sel.as_ref().map(|i| i.ctx == *c && i.name == name_of(o) && i.ns == ns_of(o)).unwrap_or(true) {
                            custom_facts(&mut f, "Elasticsearch", o, None, true);
                        }
                    }
                }
                if let Some(id) = &self.es_sel {
                    f.ctxs = vec![id.ctx.clone()];
                }
                self.pods_near(&mut f, self.es_sel.clone());
            }
            View::Pulsar => {
                for c in &shown {
                    for x in self.pulsars(c) {
                        if self.ns_ok(&x.id.ns) && self.pu_sel.as_ref().map(|i| *i == x.id).unwrap_or(true) {
                            let parts = self.pu_parts(&x).iter().map(|(n, r, t)| format!("{r} of {t} {n} ready")).collect::<Vec<_>>().join(", ");
                            f.add(Class::State, format!("Pulsar {} in {}: {parts}", x.id.name, x.id.ns), None);
                        }
                    }
                }
                if let Some(id) = &self.pu_sel {
                    f.ctxs = vec![id.ctx.clone()];
                }
                self.pods_near(&mut f, self.pu_sel.clone());
            }
            View::Hive => self.hungry_facts(&mut f),
            View::Observatory | View::Proxmox => {
                // (The figures from Grafana and Proxmox stay out: they may be about more than these clusters.)
                self.list_facts(&mut f, Kind::Nodes, 60);
            }
            View::Op(_) | View::Incident | View::Readiness | View::NetLab => {
                if self.view == View::Incident && self.incident.tab == 0 {
                    for m in self.moments(6 * 3600).into_iter().take(50) {
                        f.add(Class::State, format!("{}: {} ({})", ops::ago(kube::now_secs(), Some(m.at)), m.title, m.detail), m.go);
                    }
                }
                if self.view == View::Incident && self.incident.tab == 6 {
                    for c in &self.companion.cases {
                        f.add(Class::State, format!("Case: {} {}{}: {}; {}{}", c.sel.kind.singular(), c.sel.name, if c.sel.ns.is_empty() { String::new() } else { format!(" in {}", c.sel.ns) }, c.head, c.cause, if c.gone.is_some() { " (solved)" } else { "" }), Some(Go::Object(c.sel.clone())));
                    }
                }
                if let (View::Incident, 1, Some(s)) = (self.view, self.incident.tab, &self.incident.sel) {
                    return self.object_facts(s);
                }
                if let (View::Incident, 2, Some(h)) = (self.view, self.incident.tab, self.hunt_facts()) {
                    f.ctxs = h.ctxs;
                    f.list.extend(h.list);
                } else {
                    for (c, t, go) in &self.ai.notes {
                        f.add(*c, t.clone(), go.clone());
                    }
                }
            }
        }
        if f.list.is_empty() {
            f.add(Class::State, "This page lists nothing, or it isn't read yet", None);
        }
        f
    }

    /// The rows of a list page, as it's filtered and with its columns; what's wrong first.
    fn list_facts(&self, f: &mut Facts, kind: Kind, most: usize) {
        let l = self.build_list_cache(kind, String::new(), "Name", true);
        for c in &f.ctxs.clone() {
            if let Some(why) = self.missing(c, kind) {
                f.add(Class::State, format!("Not complete: {why}"), None);
            }
        }
        let heads = kind.all_columns();
        let bad = |r: &Row| r.cells.iter().any(|c| matches!(c.tone, Tone::Danger | Tone::Warning));
        let n = l.rows.iter().filter(|x| bad(&x.1)).count();
        f.add(Class::State, format!("{} {} in the list{}", l.rows.len(), kind.label(), if n > 0 { format!(", {n} of them with something that isn't right") } else { String::new() }), None);
        let mut order: Vec<usize> = (0..l.rows.len()).collect();
        order.sort_by_key(|i| !bad(&l.rows[*i].1));
        let multi = f.ctxs.len() > 1;
        for i in order.into_iter().take(most) {
            let (ctx, r) = &l.rows[i];
            let mut cells: Vec<String> = heads.iter().zip(&r.cells).filter(|(h, c)| !matches!(**h, "Labels" | "Created" | "Name" | "Namespace" | "Context" | "CPU Usage" | "Memory Usage" | "Usage") && !c.text.is_empty() && c.text != "-").map(|(h, c)| format!("{h} {}", truncate(&c.text, 160))).collect();
            if let Some(x) = l.usage.get(i).copied().flatten() {
                cells.push(format!("uses {} CPU, {} memory", pod::plain(x.0, true), pod::plain(x.1, false)));
            }
            f.add(Class::State, format!("{} {}{}{}: {}", kind.singular(), r.name, if r.ns.is_empty() { String::new() } else { format!(" in {}", r.ns) }, if multi { format!(" ({})", ctx_label(ctx)) } else { String::new() }, cells.join(", ")), Some(ops::obj(ctx, kind, &r.ns, &r.name)));
        }
        if l.rows.len() > most {
            f.add(Class::State, format!("{} more {} aren't listed here", l.rows.len() - most, kind.label()), None);
        }
    }

    /// How the open clusters are doing: counts, and what isn't right.
    fn health_facts(&self, f: &mut Facts) {
        let now = kube::now_secs();
        for c in &f.ctxs.clone() {
            for k in [Kind::Nodes, Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::Jobs, Kind::Pods, Kind::PersistentVolumeClaims, Kind::Services, Kind::Ingresses] {
                let Some(l) = self.refs(c, k, "") else { continue };
                let l: Vec<&Value> = l.into_iter().filter(|o| !k.namespaced() || self.ns_ok(ns_of(o))).collect();
                let mut bad = vec![];
                for o in &l {
                    let (t, head, _) = if k == Kind::Pods { pod::verdict(o, now) } else { face::verdict(k, o, now) };
                    if matches!(t, Tone::Danger | Tone::Warning) {
                        bad.push((t != Tone::Danger, head, *o));
                    }
                }
                f.add(Class::State, format!("{}: {} {}, {} with something that isn't right", ctx_label(c), l.len(), k.label(), bad.len()), None);
                bad.sort_by_key(|b| b.0);
                for (_, head, o) in bad.into_iter().take(10) {
                    f.add(Class::State, format!("{} {}{}: {head}", k.singular(), name_of(o), if ns_of(o).is_empty() { String::new() } else { format!(" in {}", ns_of(o)) }), Some(ops::obj(c, k, ns_of(o), name_of(o))));
                }
            }
        }
        for m in self.moments(3 * 3600).into_iter().filter(|m| m.lane != 3).take(20) {
            f.add(Class::State, format!("{}: {} ({})", ops::ago(now, Some(m.at)), m.title, truncate(&m.detail, 200)), m.go);
        }
    }

    /// Pods that use the most of their memory limit.
    fn hungry_facts(&self, f: &mut Facts) {
        let l = self.build_list_cache(Kind::Pods, String::new(), "Name", true);
        let mut v: Vec<(f64, usize)> = l.rows.iter().enumerate().filter_map(|(i, (_, r))| Some((l.usage[i]?.1 / Some(r.req[3]).filter(|x| *x > 0.0)?, i))).collect();
        v.sort_by(|a, b| b.0.total_cmp(&a.0));
        f.add(Class::State, format!("{} pods, {} with a memory limit and a reading", l.rows.len(), v.len()), None);
        for (part, i) in v.into_iter().take(40) {
            let (c, r) = &l.rows[i];
            let x = l.usage[i].unwrap_or_default();
            f.add(Class::State, format!("pod {} in {} uses {:.0}% of its memory limit ({} of {}) and {} CPU", r.name, r.ns, part * 100.0, pod::plain(x.1, false), pod::plain(r.req[3], false), pod::plain(x.0, true)), Some(ops::obj(c, Kind::Pods, &r.ns, &r.name)));
        }
    }

    /// Pods and warnings in the namespace of a database's page.
    fn pods_near(&self, f: &mut Facts, id: Option<pg::PgId>) {
        let Some(id) = id else { return };
        let now = kube::now_secs();
        for p in self.refs(&id.ctx, Kind::Pods, &id.ns).unwrap_or_default().into_iter().filter(|p| name_of(p).contains(&id.name)).take(20) {
            let (t, head, _) = pod::verdict(p, now);
            f.add(Class::State, format!("pod {}: {head}{}", name_of(p), if matches!(t, Tone::Danger | Tone::Warning) { " (bad)" } else { "" }), Some(ops::obj(&id.ctx, Kind::Pods, &id.ns, name_of(p))));
        }
        for e in self.refs(&id.ctx, Kind::Events, &id.ns).unwrap_or_default().into_iter().filter(|e| e["type"] == "Warning" && e["involvedObject"]["name"].as_str().unwrap_or("").contains(&id.name)).take(10) {
            f.add(Class::State, format!("Warning {} on {}: {}", text(&e["reason"]), text(&e["involvedObject"]["name"]), truncate(e["message"].as_str().unwrap_or(""), 240)), None);
        }
    }

    fn custom_page_facts(&self, f: &mut Facts, i: u32) {
        let Some(k) = self.crds.get(i as usize) else { return };
        if let Some(s) = self.custom_sel.as_ref().filter(|s| s.idx == i) {
            if let Some(o) = self.custom_object(s) {
                f.ctxs = vec![s.ctx.clone()];
                custom_facts(f, &k.kind, &o, Some(Go::Custom(s.clone())), true);
                for e in self.refs(&s.ctx, Kind::Events, &s.ns).unwrap_or_default().into_iter().filter(|e| e["type"] == "Warning" && e["involvedObject"]["name"].as_str() == Some(&s.name)).take(8) {
                    f.add(Class::State, format!("Warning {}: {}", text(&e["reason"]), truncate(e["message"].as_str().unwrap_or(""), 240)), None);
                }
            }
            return;
        }
        let q = self.search.to_lowercase();
        let mut n = 0;
        for c in &f.ctxs.clone() {
            let Some(l) = self.lists.get(&Self::custom_list_key(c, k)) else { continue };
            for o in l.items.iter().filter(|o| !k.namespaced || self.ns_ok(ns_of(o))) {
                let cells = k.cols.iter().filter(|p| p.priority == 0).map(|p| (p.name.clone(), crds::cell_of(o, p).0)).filter(|x| !x.1.is_empty() && x.1 != "-").map(|x| format!("{} {}", x.0, truncate(&x.1, 160))).collect::<Vec<_>>().join(", ");
                if !q.is_empty() && !name_of(o).to_lowercase().contains(&q) && !ns_of(o).to_lowercase().contains(&q) && !cells.to_lowercase().contains(&q) {
                    continue;
                }
                n += 1;
                if n <= 60 {
                    f.add(Class::State, format!("{} {}{}: {cells}", k.kind, name_of(o), if ns_of(o).is_empty() { String::new() } else { format!(" in {}", ns_of(o)) }), Some(Go::Custom(crds::CustomSel { ctx: c.clone(), idx: i, ns: ns_of(o).into(), name: name_of(o).into() })));
                }
            }
        }
        f.add(Class::State, format!("{n} {} in the list", k.kind), None);
    }

    /// Stand-ins for the names in facts; ones that are there keep theirs.
    pub(super) fn add_standins(&self, s: &mut Standins, f: &Facts) {
        for c in &f.ctxs {
            s.add("CLUSTER", &ctx_label(c));
            s.add("CLUSTER", c);
            for n in self.namespaces.get(c).into_iter().flatten() {
                s.add("NS", n);
            }
            for n in self.refs(c, Kind::Nodes, "").unwrap_or_default() {
                s.add("NODE", name_of(n));
            }
            for p in self.refs(c, Kind::Pods, "").unwrap_or_default() {
                s.add("NS", ns_of(p));
                s.add("NODE", p["spec"]["nodeName"].as_str().unwrap_or(""));
            }
        }
        s.learn(&f.title);
        for x in &f.list {
            s.learn(&x.text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn drawn_tables_are_noted() {
        begin(false);
        note_table("T", &[("A", 1.0)], &[Item::new(Tone::Danger, vec!["x".into()])], "none");
        assert!(end().is_empty());
        begin(true);
        note_table("T", &[("A", 1.0), ("", 1.0)], &[Item::new(Tone::Danger, vec!["x".into(), "y".into()])], "none");
        class(Class::Log);
        note_table("L", &[("A", 1.0)], &[], "No errors");
        let l = end();
        assert_eq!((l[0].0, l[0].1.as_str()), (Class::State, "T: A: x; y (bad)"));
        assert_eq!((l[1].0, l[1].1.as_str()), (Class::Log, "L: No errors"));
        begin(false);
    }

    #[test]
    fn custom_objects() {
        let o = json!({"metadata": {"name": "db", "namespace": "shop"}, "spec": {"instances": 3, "secretKey": "x", "nested": {"a": 1}}, "status": {"phase": "Failing", "conditions": [{"type": "Ready", "status": "False", "reason": "NoLeader"}, {"type": "Backup", "status": "True"}]}});
        let mut f = Facts::default();
        custom_facts(&mut f, "Cluster", &o, None, false);
        assert_eq!(f.list.iter().map(|x| x.text.as_str()).collect::<Vec<_>>(), vec!["Cluster db in shop: phase=Failing", "Cluster db in shop: condition Ready is False NoLeader"]);
        custom_facts(&mut f, "Cluster", &o, None, true);
        let v = f.list.iter().find(|x| x.class == Class::Value).unwrap();
        assert!(v.text.contains("instances=3") && !v.text.contains("nested"));
        assert!(!super::super::aifacts::scrub(&v.text).contains("secretKey=x"));
    }
}
