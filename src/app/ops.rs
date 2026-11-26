//! Operators' pages: what they share (a health line, tables), and the page for operators without one
//! made for them, which shows what their own definitions say.

use super::dash::{at, line};
use super::face::{many, Face, Side};
use super::pg::{label_at, panel};
use super::podxray::Go;
use super::powers::OPS;
use super::work::{name_of, said};
use super::*;

/// A line of a table.
pub(super) struct Item {
    pub tone: Tone,
    pub cells: Vec<String>,
    pub tip: String,
    pub go: Option<Go>,
}

impl Item {
    pub fn new(tone: Tone, cells: Vec<String>) -> Item {
        Item { tone, cells, tip: String::new(), go: None }
    }
    pub fn tip(mut self, t: impl Into<String>) -> Item {
        self.tip = t.into();
        self
    }
    pub fn go(mut self, g: Option<Go>) -> Item {
        self.go = g;
        self
    }
    pub fn bad(&self) -> bool {
        matches!(self.tone, Tone::Danger | Tone::Warning)
    }
}

pub(super) fn obj(ctx: &str, kind: Kind, ns: &str, name: &str) -> Go {
    Go::Object(Selected { ctx: ctx.into(), kind, ns: if kind.namespaced() { ns.into() } else { String::new() }, name: name.into() })
}

pub(super) fn ns_of(o: &Value) -> &str {
    o["metadata"]["namespace"].as_str().unwrap_or("")
}

pub(super) fn text(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

pub(super) fn ago(now: i64, t: Option<i64>) -> String {
    t.map(|t| if t > now { format!("in {}", kube::human_duration(t - now)) } else { format!("{} ago", kube::human_duration(now - t)) }).unwrap_or("-".into())
}

fn rank(t: Tone) -> u8 {
    match t {
        Tone::Danger => 0,
        Tone::Warning => 1,
        Tone::Info => 2,
        Tone::Success => 3,
        _ => 4,
    }
}

/// The worst first.
pub(super) fn worst_first(v: &mut [Item]) {
    v.sort_by(|a, b| rank(a.tone).cmp(&rank(b.tone)).then(a.cells.cmp(&b.cells)));
}

/// The health line above a page, from its items.
pub(super) fn summary(items: &[Item], one: &str) -> Face {
    let n = items.len();
    let c = |f: &dyn Fn(Tone) -> bool| items.iter().filter(|i| f(i.tone)).count();
    let (bad, warn, info, good) = (c(&|t| t == Tone::Danger), c(&|t| t == Tone::Warning), c(&|t| t == Tone::Info), c(&|t| t == Tone::Success));
    let (tone, head) = if n == 0 {
        (Tone::Muted, format!("No {one}s here"))
    } else if bad > 0 {
        (Tone::Danger, format!("{} failing", many(bad as i64, one)))
    } else if warn > 0 {
        (Tone::Warning, format!("{} to look at", many(warn as i64, one)))
    } else if good + info == 0 {
        (Tone::Muted, many(n as i64, one))
    } else {
        (Tone::Success, format!("{} healthy", many((good + info) as i64, one)))
    };
    let mut pills = vec![];
    for (k, t, col) in [(good, "healthy", SUCCESS()), (info, "in progress", INFO()), (warn, "to look at", WARNING()), (bad, "failing", DANGER()), (n - bad - warn - info - good, "idle or unknown", TEXT_SUBTLE())] {
        if k > 0 {
            pills.push((format!("● {k} {t}"), col, String::new()));
        }
    }
    Face { tone, head, sub: many(n as i64, one), notes: vec![], pills, facts: vec![] }
}

/// A table in a card. `heads` are titles with their share of the width. Returns where a click leads.
pub(super) fn table(ui: &mut Ui, title: &str, hint: &str, heads: &[(&str, f32)], items: &[Item], max: usize, none: &str) -> Option<Go> {
    let mut go = None;
    aipage::note_table(title, heads, items, none);
    card(ui, |ui| {
        panel(ui, title, hint);
        ui.spacing_mut().item_spacing.y = 0.0;
        if items.is_empty() {
            said(ui, none, TEXT_SUBTLE());
            return;
        }
        let total: f32 = heads.iter().map(|h| h.1).sum::<f32>().max(0.01);
        let (h, _) = line(ui, u(24.0), false);
        let dot = u(18.0);
        let col = |r: egui::Rect, i: usize| -> (f32, f32) {
            let w = r.width() - dot;
            let x: f32 = heads[..i].iter().map(|h| h.1).sum();
            (r.left() + dot + w * x / total, w * heads[i].1 / total)
        };
        for (i, t) in heads.iter().enumerate() {
            let (x, w) = col(h, i);
            label_at(ui, ui.painter(), egui::pos2(x, h.center().y), t.0, 11.5, TEXT_SUBTLE(), w - 8.0);
        }
        for it in items.iter().take(max) {
            let (r, resp) = line(ui, u(28.0), it.go.is_some());
            ui.painter().circle_filled(egui::pos2(r.left() + u(5.0), r.center().y), u(4.5), if matches!(it.tone, Tone::Muted | Tone::Normal) { TEXT_PLACEHOLDER() } else { tone_color(it.tone) });
            for (i, c) in it.cells.iter().enumerate().take(heads.len()) {
                let (x, w) = col(r, i);
                let cc = if i == 0 { if it.go.is_some() { PRIMARY_TEXT() } else { TEXT_DEFAULT() } } else if i == 1 && it.bad() { tone_color(it.tone) } else { TEXT_MUTED() };
                label_at(ui, ui.painter(), egui::pos2(x, r.center().y), &c.replace('\n', " "), if i == 0 { 13.0 } else { 12.5 }, cc, w - 8.0);
            }
            let tip = if it.tip.is_empty() { it.cells.join("\n") } else { it.tip.clone() };
            if resp.on_hover_text(truncate(&tip, 1200)).clicked() {
                go = it.go.clone();
            }
        }
        if items.len() > max {
            let (r, _) = line(ui, u(24.0), false);
            at(ui, r, 0.0, 1.0, &format!("and {} more: filter to see them", items.len() - max), 12.0, TEXT_PLACEHOLDER());
        }
    });
    ui.add_space(12.0);
    go
}

impl KubedogApp {
    /// A custom kind's objects in the shown clusters and namespaces, with their cluster.
    pub(super) fn op_items(&self, key: &str) -> Vec<(&str, &Value)> {
        let Some(k) = self.crd_index(key).and_then(|i| self.crds.get(i as usize)) else { return vec![] };
        let mut out = vec![];
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            if let Some(l) = self.lists.get(&Self::custom_list_key(c, k)) {
                out.extend(l.items.iter().filter(|o| !k.namespaced || self.ns_ok(ns_of(o))).map(|o| (c.as_str(), o)));
            }
        }
        out
    }

    /// All of a kind in one cluster, whatever namespaces are picked.
    pub(super) fn op_all(&self, ctx: &str, key: &str) -> &[Value] {
        let Some(k) = self.crd_index(key).and_then(|i| self.crds.get(i as usize)) else { return &[] };
        self.lists.get(&Self::custom_list_key(ctx, k)).map(|l| l.items.as_slice()).unwrap_or(&[])
    }

    /// Why a custom kind's list isn't there, if it isn't.
    pub(super) fn op_missing(&self, key: &str) -> Option<String> {
        let Some(k) = self.crd_index(key).and_then(|i| self.crds.get(i as usize)) else {
            let reading = self.active.iter().any(|c| self.lists.get(&Self::list_key(c, Kind::CustomResourceDefinitions)).map(|l| l.fetched.is_none() && l.error.is_none()).unwrap_or(true));
            return Some(if reading { "Reading what the cluster has…" } else { "Not installed in the open clusters." }.into());
        };
        let mut why = None;
        for c in &self.active {
            match self.lists.get(&Self::custom_list_key(c, k)) {
                Some(l) if l.error.as_deref().map(is_refusal).unwrap_or(false) => why = Some(format!("your account can't see {}", k.plural)),
                Some(l) if l.fetched.is_some() => return None,
                Some(l) if l.error.is_some() => why = Some(format!("{} couldn't be read", k.plural)),
                Some(_) => return Some(format!("reading {}…", k.plural)),
                None => {}
            }
        }
        why
    }

    pub(super) fn custom_go(&self, ctx: &str, key: &str, o: &Value) -> Option<Go> {
        let idx = self.crd_index(key)?;
        Some(Go::Custom(crds::CustomSel { ctx: ctx.into(), idx, ns: ns_of(o).into(), name: name_of(o).into() }))
    }

    /// "namespace/name", with the cluster when several are open.
    pub(super) fn full_name(&self, ctx: &str, o: &Value) -> String {
        let ns = ns_of(o);
        let n = if ns.is_empty() { name_of(o).to_string() } else { format!("{ns}/{}", name_of(o)) };
        if self.active.len() > 1 { format!("{} · {n}", ctx_label(ctx)) } else { n }
    }

    /// Keep what the filter box and the problems switch let through.
    pub(super) fn op_filter(&self, items: Vec<Item>) -> Vec<Item> {
        let q = self.search.to_lowercase();
        items.into_iter().filter(|i| (!self.powers.bad_only || i.bad()) && (q.is_empty() || i.cells.iter().any(|c| c.to_lowercase().contains(&q)))).collect()
    }

    /// What's read for a page besides lists.
    pub(super) fn refresh_op_extra(&mut self, id: &str, force: bool) {
        match id {
            "gateways" => self.ask_routes(force),
            "prom" => self.ask_alerts(force),
            "backups" => self.ask_kasten(force),
            "openshift" => self.ask_openshift(force),
            _ => {}
        }
    }

    pub(super) fn op_view(&mut self, ui: &mut Ui, i: u8) {
        let Some(op) = OPS.get(i as usize) else { return };
        if self.power_off(op.id) {
            self.header(ui, false, None, false);
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new(format!("{} is switched off.", op.label)).color(TEXT_SUBTLE()));
                if button(ui, "Settings", false, false) {
                    self.settings_section = "Superpowers";
                    self.set_view(View::Settings);
                }
            });
            return;
        }
        self.header(ui, true, Some(op.label.to_string()), true);
        let mut go: Option<Go> = None;
        self.page_scroll().id_salt(("op", i)).show(ui, |ui| {
            ui.add_space(6.0);
            go = match op.id {
                "openshift" => self.openshift_page(ui),
                "argo" => self.argo_page(ui),
                "secrets" => self.secrets_page(ui),
                "certs" => self.certs_page(ui),
                "keda" => self.keda_page(ui),
                "ceph" => self.ceph_page(ui),
                "gpu" => self.gpu_page(ui),
                "prom" => self.prom_page(ui),
                "gateways" => self.gateways_page(ui),
                "backups" => self.backups_page(ui),
                _ => self.generic_page(ui, op),
            };
            ui.add_space(20.0);
        });
        if let Some(g) = go {
            self.go_to(g);
        }
    }

    pub(super) fn go_to(&mut self, g: Go) {
        let nowhere = Selected { ctx: String::new(), kind: Kind::Pods, ns: String::new(), name: String::new() };
        self.follow(g, &nowhere);
    }

    /// The switch that leaves only what needs a look.
    pub(super) fn bad_switch(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.powers.bad_only, "Only what needs a look");
        });
        ui.add_space(4.0);
    }

    /// A custom kind as a table, by its own columns and conditions: (title, heads, lines).
    pub(super) fn kind_items(&self, key: &str) -> Option<(String, Vec<(String, f32)>, Vec<Item>)> {
        let k = self.crd_index(key).and_then(|i| self.crds.get(i as usize))?;
        let cols: Vec<&crds::PCol> = k.cols.iter().filter(|c| c.priority == 0).take(4).collect();
        let mut heads: Vec<(String, f32)> = vec![("Name".into(), 0.3), ("State".into(), 0.2)];
        heads.extend(cols.iter().map(|c| (c.name.clone(), 0.4 / cols.len().max(1) as f32)));
        heads.push(("Age".into(), 0.1));
        let items = self
            .op_items(key)
            .into_iter()
            .map(|(c, o)| {
                let v = face::generic(o);
                let mut cells = vec![self.full_name(c, o), if v.1.is_empty() { "-".into() } else { v.1.clone() }];
                cells.extend(cols.iter().map(|p| crds::cell_of(o, p).0));
                cells.push(kube::age(o["metadata"]["creationTimestamp"].as_str().unwrap_or("")));
                Item::new(v.0, cells).tip(format!("{}\n{}", self.full_name(c, o), v.2.join("\n"))).go(self.custom_go(c, key, o))
            })
            .collect();
        Some((k.kind.clone(), heads, items))
    }

    /// The same, drawn; nothing when no open cluster has the kind.
    pub(super) fn kind_table(&self, ui: &mut Ui, key: &str) -> Option<Go> {
        let (title, heads, items) = self.kind_items(key)?;
        let mut items = self.op_filter(items);
        worst_first(&mut items);
        let heads: Vec<(&str, f32)> = heads.iter().map(|h| (h.0.as_str(), h.1)).collect();
        table(ui, &format!("{title} ({})", items.len()), "", &heads, &items, 40, &self.op_missing(key).unwrap_or("None.".into()))
    }

    /// An operator's kinds, by the columns and conditions they define themselves.
    fn generic_page(&mut self, ui: &mut Ui, op: &powers::Op) -> Option<Go> {
        let mut go = None;
        let mut all: Vec<Item> = vec![];
        let mut tables: Vec<(String, Vec<(String, f32)>, Vec<Item>, Option<String>)> = vec![];
        for key in op.find.iter().chain(op.more) {
            let Some((title, heads, items)) = self.kind_items(key) else { continue };
            if op.find.contains(key) {
                all.extend(items.iter().map(|i| Item::new(i.tone, i.cells.clone())));
            }
            tables.push((title, heads, items, self.op_missing(key)));
        }
        face::show(ui, &summary(&all, "object"), Side::None);
        ui.add_space(10.0);
        self.bad_switch(ui);
        if tables.is_empty() {
            said(ui, "The open clusters don't have it, or your account can't see it.", TEXT_SUBTLE());
        }
        for (title, heads, items, missing) in tables {
            let mut items = self.op_filter(items);
            worst_first(&mut items);
            let heads: Vec<(&str, f32)> = heads.iter().map(|h| (h.0.as_str(), h.1)).collect();
            if let Some(g) = table(ui, &format!("{title} ({})", items.len()), "", &heads, &items, 60, missing.as_deref().unwrap_or("None.")) {
                go = Some(g);
            }
        }
        // Its other kinds, unread.
        let groups: HashSet<String> = op.find.iter().filter_map(|f| f.split_once('.')).map(|x| x.1.to_string()).collect();
        let others: Vec<(u32, String)> = self.crds.iter().enumerate().filter(|(_, k)| groups.contains(&k.group) && !op.find.contains(&k.key.as_str()) && !op.more.contains(&k.key.as_str())).map(|(i, k)| (i as u32, k.kind.clone())).collect();
        if !others.is_empty() {
            let mut open = None;
            card(ui, |ui| {
                panel(ui, "Its other kinds", "");
                ui.horizontal_wrapped(|ui| {
                    for (i, k) in &others {
                        if button(ui, k, false, false) {
                            open = Some(*i);
                        }
                    }
                });
            });
            if let Some(i) = open {
                self.open_custom(i);
            }
        }
        go
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summaries_and_order() {
        let i = |t, n: &str| Item::new(t, vec![n.into()]);
        let mut v = vec![i(Tone::Success, "b"), i(Tone::Muted, "z"), i(Tone::Danger, "c"), i(Tone::Warning, "a")];
        assert_eq!(summary(&v, "app").head, "1 app failing");
        worst_first(&mut v);
        assert_eq!(v.iter().map(|x| x.cells[0].as_str()).collect::<String>(), "cabz");
        assert_eq!(summary(&[], "app").head, "No apps here");
        assert_eq!(summary(&[i(Tone::Success, "x")], "app").head, "1 app healthy");
        assert_eq!(ago(100, Some(160)), "in 60s");
        assert_eq!(ago(100, None), "-");
    }
}
