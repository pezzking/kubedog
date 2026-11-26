//! The companion: watches the open clusters with Kubedog's own rules, from the lists the Incident Room
//! reads anyway, and opens a case for each problem that stays. Off until it's switched on per cluster.

use super::aichat::{answer, Chat};
use super::face::{many, Face, Side};
use super::incident::chip_button;
use super::podxray::Go;
use super::work::{name_of, said};
use super::*;
use std::collections::VecDeque;

/// Seconds a problem has to stay before it's a case: broken, and not quite right.
const STAYS: (i64, i64) = (45, 300);
/// A moment for its pods and events to be read before an AI looks at it.
const READ: i64 = 20;

const NO_CAUSE: &str = "no clear cause yet";

type Key = (String, Kind, String, String);

pub(super) struct Case {
    pub id: u64,
    pub sel: Selected,
    pub tone: Tone,
    pub head: String,
    pub cause: String,
    pub first: i64,
    pub last: i64,
    pub gone: Option<i64>,
    /// It was there when watching began.
    pub old: bool,
    pub seen: bool,
    /// The AI's investigation, when there is one.
    pub chat: Option<Chat>,
    pub ai_err: Option<String>,
    tried: bool,
    /// When its cause was last looked for.
    looked: i64,
}

#[derive(Default)]
pub(super) struct Companion {
    pub cases: Vec<Case>,
    /// First seen, and whether that was in the first look.
    sights: HashMap<Key, (i64, bool)>,
    started: HashSet<String>,
    /// An investigation that runs: (case, conversation).
    pub chat: Option<Chat>,
    case: u64,
    asked: VecDeque<i64>,
    n: u64,
    list: bool,
}

/// What became of the problems, from the ones seen now. Returns the ones that are new cases.
fn sort_out(sights: &mut HashMap<Key, (i64, bool)>, ctx: &str, now: i64, first: bool, seen: &[(Key, Tone)]) -> Vec<(Key, bool)> {
    sights.retain(|k, _| k.0 != ctx || seen.iter().any(|s| s.0 == *k));
    let mut out = vec![];
    for (k, t) in seen {
        let (since, old) = *sights.entry(k.clone()).or_insert((now, first));
        let wait = if *t == Tone::Danger { STAYS.0 } else { STAYS.1 };
        if now - since >= wait {
            out.push((k.clone(), old));
        }
    }
    out
}

/// May the AI look by itself now? Only new problems, in clusters with that switch, a few an hour.
fn may_ask(asked: &mut VecDeque<i64>, now: i64, cap: u32, how: Option<&str>, old: bool) -> bool {
    while asked.front().map(|t| now - t >= 3600).unwrap_or(false) {
        asked.pop_front();
    }
    how == Some("ai") && !old && (asked.len() as u32) < cap
}

impl KubedogApp {
    fn watched(&self, ctx: &str) -> Option<&str> {
        self.prefs.ai.watch.get(ctx).map(|s| s.as_str())
    }

    pub(super) fn companion_new(&self) -> usize {
        self.companion.cases.iter().filter(|c| !c.seen && !c.old && c.gone.is_none()).count()
    }

    fn problems(&self, ctx: &str) -> Vec<(Selected, Tone, String)> {
        let now = kube::now_secs();
        let mut out = vec![];
        for k in [Kind::Nodes, Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::PersistentVolumeClaims] {
            for o in self.refs(ctx, k, "").unwrap_or_default() {
                let (t, head, _) = face::verdict(k, o, now);
                if matches!(t, Tone::Danger | Tone::Warning) {
                    out.push((Selected { ctx: ctx.into(), kind: k, ns: if k.namespaced() { ops::ns_of(o).into() } else { String::new() }, name: name_of(o).into() }, t, head));
                }
            }
        }
        out
    }

    /// After the watched lists of a cluster were read. No reading, no AI in here.
    pub(super) fn companion_look(&mut self, ctx: &str) {
        if self.demo || self.power_off("incident") || self.watched(ctx).is_none() {
            return;
        }
        // Not before everything that's watched is there.
        if [Kind::Nodes, Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::PersistentVolumeClaims].iter().any(|k| self.refs(ctx, *k, "").is_none() && !self.refused(ctx, *k)) {
            return;
        }
        // What couldn't be read now says nothing: neither broken nor solved.
        let read: Vec<Kind> = [Kind::Nodes, Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::PersistentVolumeClaims].into_iter().filter(|k| self.lists.get(&Self::list_key(ctx, *k)).map(|l| l.error.is_none() && l.fetched.is_some()).unwrap_or(false)).collect();
        let now = kube::now_secs();
        let l: Vec<(Selected, Tone, String)> = self.problems(ctx).into_iter().filter(|x| read.contains(&x.0.kind)).collect();
        let first = self.companion.started.insert(ctx.to_string());
        let key = |s: &Selected| -> Key { (s.ctx.clone(), s.kind, s.ns.clone(), s.name.clone()) };
        let seen: Vec<(Key, Tone)> = l.iter().map(|x| (key(&x.0), x.1)).collect();
        let due = sort_out(&mut self.companion.sights, ctx, now, first, &seen);
        for c in self.companion.cases.iter_mut().filter(|c| c.sel.ctx == ctx && c.gone.is_none() && read.contains(&c.sel.kind)) {
            match l.iter().find(|x| x.0 == c.sel) {
                Some((_, t, head)) => {
                    c.last = now;
                    c.tone = *t;
                    c.head = head.clone();
                }
                None => c.gone = Some(now),
            }
        }
        let mut news = vec![];
        for (k, old) in due {
            let Some((sel, t, head)) = l.iter().find(|x| key(&x.0) == k) else { continue };
            if self.companion.cases.iter().any(|c| c.sel == *sel && c.gone.is_none()) {
                continue;
            }
            self.companion.n += 1;
            self.companion.cases.push(Case { id: self.companion.n, sel: sel.clone(), tone: *t, head: head.clone(), cause: String::new(), first: now, last: now, gone: None, old, seen: false, chat: None, ai_err: None, tried: false, looked: now });
            news.push((sel.clone(), old));
        }
        // Its pods and warnings, read once, so that the cause can be named.
        if !news.is_empty() && self.screenshot.is_none() {
            for k in [Kind::Pods, Kind::Events] {
                if !self.refused(ctx, k) {
                    self.fetch_list(ctx, k);
                }
            }
        }
        match news.iter().filter(|n| !n.1).collect::<Vec<_>>().as_slice() {
            [] => {}
            [(s, _)] => self.toast(format!("Ai-health-agent: {} {} has a problem (Incident Room)", s.kind.singular(), s.name), true),
            l => self.toast(format!("Ai-health-agent: {} new problems (Incident Room)", l.len()), true),
        }
        // The longest gone are forgotten.
        let n = self.companion.cases.iter().filter(|c| c.gone.is_some()).count();
        if n > 100 {
            if let Some(i) = self.companion.cases.iter().position(|c| c.gone.is_some()) {
                self.companion.cases.remove(i);
            }
        }
    }

    /// Now and then: name causes that are known by now, and let the AI look where it may.
    pub(super) fn companion_tick(&mut self) {
        if self.companion.cases.is_empty() {
            return;
        }
        let now = kube::now_secs();
        if let Some(i) = self.companion.cases.iter().position(|c| c.gone.is_none() && (c.cause.is_empty() || c.cause == NO_CAUSE) && now - c.looked >= 15) {
            let sel = self.companion.cases[i].sel.clone();
            self.companion.cases[i].looked = now;
            let cause = self.investigate(&sel).into_iter().find(|c| c.weight >= 60).map(|c| c.title).unwrap_or(NO_CAUSE.into());
            self.companion.cases[i].cause = cause;
        }
        if self.companion.chat.is_some() || self.ai_gate().is_err() || self.screenshot.is_some() {
            return;
        }
        let Some(i) = self.companion.cases.iter().position(|c| !c.old && !c.tried && c.chat.is_none() && c.gone.is_none() && now - c.first >= READ && self.prefs.ai.watch.get(&c.sel.ctx).map(|w| w == "ai").unwrap_or(false)) else { return };
        if self.ai.seen.is_none() {
            self.ai_look(false);
            return;
        }
        let (sel, old) = (self.companion.cases[i].sel.clone(), self.companion.cases[i].old);
        let how = self.watched(&sel.ctx).map(String::from);
        if !may_ask(&mut self.companion.asked, now, self.prefs.ai.watch_cap, how.as_deref(), old) {
            return;
        }
        self.companion.asked.push_back(now);
        self.companion.cases[i].tried = true;
        self.companion.case = self.companion.cases[i].id;
        let f = self.object_facts(&sel);
        let mut names = aifacts::Standins::default();
        self.add_standins(&mut names, &f);
        self.companion.chat = Some(Chat::alone(f, names));
        self.as_companion(|app| app.ai_go_on());
        self.companion_done();
    }

    /// Does something with the companion's conversation in the place of the person's.
    pub(super) fn as_companion(&mut self, f: impl FnOnce(&mut Self)) {
        std::mem::swap(&mut self.ai.chat, &mut self.companion.chat);
        f(self);
        std::mem::swap(&mut self.ai.chat, &mut self.companion.chat);
    }

    /// Puts an investigation that ended with its case.
    pub(super) fn companion_done(&mut self) {
        if self.companion.chat.as_ref().map(|c| c.busy()).unwrap_or(true) {
            return;
        }
        let Some(mut c) = self.companion.chat.take() else { return };
        if let Some(x) = self.companion.cases.iter_mut().find(|x| x.id == self.companion.case) {
            match c.trouble() {
                Some(e) => x.ai_err = Some(e),
                None => {
                    x.chat = Some(c);
                    x.seen = false;
                }
            }
        }
    }

    pub(super) fn companion_view(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        if self.screenshot.is_some() && self.companion.cases.is_empty() && std::env::var("KUBEDOG_SHOT_CASES").is_ok() {
            let (ctx, now) = (self.active.first().cloned().unwrap_or_default(), kube::now_secs());
            for (i, (kind, name, head, cause)) in [(Kind::Deployments, "web", "0/3 pods ready", "It runs out of memory"), (Kind::StatefulSets, "db", "2/3 pods ready", "It can't be placed on a node"), (Kind::Nodes, "worker-9", "Not ready", "no clear cause yet"), (Kind::PersistentVolumeClaims, "data-db-2", "Pending", "No storage class has room")].into_iter().enumerate() {
                let sel = Selected { ctx: ctx.clone(), kind, ns: if kind.namespaced() { "shop".into() } else { String::new() }, name: name.into() };
                let chat = (i == 0).then(|| Chat::made_up(&sel));
                self.companion.cases.push(Case { id: i as u64, sel, tone: if i == 1 { Tone::Warning } else { Tone::Danger }, head: head.into(), cause: cause.into(), first: now - 420, last: now, gone: (i == 3).then_some(now - 60), old: i == 2, seen: i > 0, chat, ai_err: (i == 1).then(|| "Its usage limit is reached. Try later.".to_string()), tried: false, looked: now });
            }
        }
        let on: Vec<String> = self.active.iter().filter(|c| self.watched(c).is_some()).cloned().collect();
        let now = kube::now_secs();
        let open = self.companion.cases.iter().filter(|c| c.gone.is_none()).count();
        let f = if on.is_empty() && open == 0 {
            Face { tone: Tone::Muted, head: "The Ai-health-agent is off".into(), sub: "switch it on per cluster: it watches workloads, nodes and volumes, and opens a case when something stays broken".into(), notes: vec![], pills: vec![], facts: vec![] }
        } else if open == 0 && on.iter().any(|c| !self.companion.started.contains(c)) {
            Face { tone: Tone::Muted, head: "Having a first look".into(), sub: "workloads, nodes and volumes are read once a minute".into(), notes: vec![], pills: vec![], facts: vec![] }
        } else if open == 0 {
            Face { tone: Tone::Success, head: "Nothing stays broken".into(), sub: format!("workloads, nodes and volumes in {}; a problem becomes a case when it stays for a minute, or five when it's minor", on.iter().map(|c| ctx_label(c)).collect::<Vec<_>>().join(", ")), notes: vec![], pills: vec![], facts: vec![] }
        } else {
            Face { tone: Tone::Warning, head: many(open as i64, "open case"), sub: format!("watching {}", on.iter().map(|c| ctx_label(c)).collect::<Vec<_>>().join(", ")), notes: vec![], pills: vec![], facts: vec![] }
        };
        face::show(ui, &f, Side::None);
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            for c in self.active.clone() {
                let how = self.watched(&c).map(String::from);
                let (d, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), Sense::hover());
                ui.painter().circle_filled(d.center(), 3.5, context_color(&c));
                ui.label(RichText::new(ctx_label(&c)).size(z(13.0)).color(TEXT_MUTED()));
                for (t, v) in [("Off", None), ("Watch", Some("watch")), ("Watch, and let AI investigate", Some("ai"))] {
                    if v == Some("ai") && !self.prefs.ai.on {
                        continue;
                    }
                    if chip_button(ui, t, how.as_deref() == v) && self.screenshot.is_none() {
                        self.companion_set(&c, v);
                    }
                }
                ui.add_space(16.0);
            }
            if self.companion.cases.iter().any(|c| c.gone.is_some()) && button(ui, "Forget what's solved", false, false) {
                self.companion.cases.retain(|c| c.gone.is_none());
            }
        });
        if self.power_off("incident") {
            said(ui, "The Incident Room is off in Settings > Superpowers, so nothing is watched.", WARNING());
        }
        if self.prefs.ai.on {
            said(ui, &format!("\"Let AI investigate\" sends facts without asking each time: for new problems, at most {} an hour, following Settings > AI.", self.prefs.ai.watch_cap), INFO());
        }
        ui.add_space(10.0);
        let mut order: Vec<usize> = (0..self.companion.cases.len()).collect();
        order.sort_by_key(|i| {
            let c = &self.companion.cases[*i];
            (c.gone.is_some(), c.old, c.tone != Tone::Danger, std::cmp::Reverse(c.first))
        });
        let mut explain: Option<usize> = None;
        let mut take: Option<usize> = None;
        let mut why: Option<Selected> = None;
        let running = self.companion.chat.is_some().then_some(self.companion.case);
        let mut list = self.companion.list;
        for i in order {
            let c = &self.companion.cases[i];
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    let (d, _) = ui.allocate_exact_size(egui::vec2(u(12.0), u(12.0)), Sense::hover());
                    ui.painter().circle_filled(d.center(), u(5.0), if c.gone.is_some() { SUCCESS() } else { tone_color(c.tone) });
                    ui.label(RichText::new(format!("{} {}", c.sel.kind.singular(), c.sel.name)).size(z(15.0)).color(TEXT_DEFAULT()));
                    if !c.sel.ns.is_empty() {
                        ui.label(RichText::new(format!("in {}", c.sel.ns)).size(z(13.0)).color(TEXT_SUBTLE()));
                    }
                    if !c.seen && !c.old && c.gone.is_none() {
                        pg::pill(ui, "new", PRIMARY_TEXT());
                    }
                    let t = match c.gone {
                        Some(g) => format!("solved {}", ops::ago(now, Some(g))),
                        None if c.old => "there since watching began".into(),
                        None => format!("since {}", ops::ago(now, Some(c.first))),
                    };
                    ui.label(RichText::new(t).size(z(12.5)).color(TEXT_PLACEHOLDER()));
                });
                said(ui, &format!("{}{}", c.head, if c.cause.is_empty() { String::new() } else { format!("; {}", c.cause.to_lowercase()) }), if c.gone.is_some() { TEXT_SUBTLE() } else { TEXT_MUTED() });
                if let Some(x) = &c.chat {
                    if let Some(t) = x.last_answer() {
                        ui.add_space(6.0);
                        if let Some(g) = answer(ui, t, &x.facts, &mut list) {
                            go = Some(g);
                        }
                        said(ui, "Investigated by AI, by itself: it can be wrong.", TEXT_PLACEHOLDER());
                    }
                }
                if let Some(e) = &c.ai_err {
                    said(ui, &format!("The AI couldn't investigate it: {e}"), WARNING());
                }
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if button(ui, "Open it", false, false) {
                        go = Some(Go::Object(c.sel.clone()));
                    }
                    if button(ui, "Why is it broken?", false, false) {
                        why = Some(c.sel.clone());
                    }
                    if running == Some(c.id) {
                        ui.spinner();
                        ui.label(RichText::new("The AI is looking at it…").size(z(12.5)).color(TEXT_SUBTLE()));
                    } else if c.chat.is_some() {
                        if button(ui, "Go on in the chat", false, false) {
                            take = Some(i);
                        }
                    } else if self.ai_button(ui) {
                        explain = Some(i);
                    }
                });
            });
            ui.add_space(8.0);
        }
        self.companion.list = list;
        for c in &mut self.companion.cases {
            c.seen = true;
        }
        if let Some(i) = explain {
            let f = self.object_facts(&self.companion.cases[i].sel.clone());
            self.ai_explain(f);
        }
        if let Some(i) = take {
            if let Some(mut c) = self.companion.cases[i].chat.take() {
                c.by_hand();
                self.ai.chat = Some(c);
                self.ai.hidden = false;
            }
        }
        if let Some(s) = why {
            self.incident.tab = 1;
            self.incident.sel = Some(s);
            self.refresh_current(false);
        }
        go
    }

    pub(super) fn companion_set(&mut self, ctx: &str, how: Option<&str>) {
        match how {
            Some(h) => {
                self.prefs.ai.watch.insert(ctx.to_string(), h.to_string());
            }
            None => {
                self.prefs.ai.watch.remove(ctx);
                self.companion.started.remove(ctx);
                self.companion.sights.retain(|k, _| k.0 != ctx);
                self.companion.cases.retain(|c| c.sel.ctx != ctx);
            }
        }
        if how != Some("ai") && self.companion.chat.as_ref().map(|c| c.facts.ctxs.iter().any(|x| x == ctx)).unwrap_or(false) {
            self.companion.chat = None;
        }
        self.save();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_what_stays() {
        let k = |n: &str| -> Key { ("c".into(), Kind::Deployments, "ns".into(), n.into()) };
        let mut s = HashMap::new();
        // There at the first look: an old one.
        assert!(sort_out(&mut s, "c", 100, true, &[(k("a"), Tone::Danger)]).is_empty());
        assert_eq!(sort_out(&mut s, "c", 160, false, &[(k("a"), Tone::Danger), (k("b"), Tone::Danger), (k("w"), Tone::Warning)]), vec![(k("a"), true)]);
        // A new one, when it stays; a blip is forgotten; not quite right takes longer.
        assert_eq!(sort_out(&mut s, "c", 220, false, &[(k("b"), Tone::Danger), (k("w"), Tone::Warning)]), vec![(k("b"), false)]);
        assert!(sort_out(&mut s, "c", 230, false, &[(k("a"), Tone::Danger), (k("w"), Tone::Warning)]).is_empty());
        assert_eq!(sort_out(&mut s, "c", 470, false, &[(k("w"), Tone::Warning)]), vec![(k("w"), false)]);
        // Another cluster's are left alone.
        sort_out(&mut s, "d", 480, true, &[]);
        assert!(s.contains_key(&k("w")));
    }

    #[test]
    fn the_ai_by_itself() {
        let mut q = VecDeque::new();
        assert!(!may_ask(&mut q, 0, 3, None, false) && !may_ask(&mut q, 0, 3, Some("watch"), false));
        assert!(!may_ask(&mut q, 0, 3, Some("ai"), true) && !may_ask(&mut q, 0, 0, Some("ai"), false));
        for t in [0, 10, 20] {
            assert!(may_ask(&mut q, t, 3, Some("ai"), false));
            q.push_back(t);
        }
        assert!(!may_ask(&mut q, 3000, 3, Some("ai"), false));
        assert!(may_ask(&mut q, 3601, 3, Some("ai"), false));
    }
}
