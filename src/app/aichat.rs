//! The panel where an AI explains: what's sent, the answer with the facts it rests on, and more questions.

use super::ai::{label, place_color, place_label, place_words, Place, Running, Turns, Use};
use super::aifacts::{brief, scrub, Fact, Facts, Standins};
use super::podxray::Go;
use super::work::said;
use super::aitools::{self, Look};
use super::face::many;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use super::*;

pub(super) const FIRST: &str = "What's going on here, why did it most likely happen, and what should I check next?";

pub(super) struct Chat {
    pub facts: Facts,
    names: Standins,
    pub to: Option<Use>,
    /// How it was sent: when this changes, a new conversation starts.
    way: Option<(&'static str, Place, [bool; 3])>,
    /// From here on a new conversation, with nothing of the earlier one.
    fresh: Option<usize>,
    /// What was shown: (question, text).
    shown: Vec<(bool, String)>,
    /// What was sent, word for word.
    sent: Turns,
    kept: (usize, usize),
    /// Follows the page that's open: each question gets its facts.
    page: bool,
    /// How many facts it began with, and those of the page at the last question.
    base: usize,
    cur: Vec<usize>,
    /// What was sent with each question.
    logs: Vec<Log>,
    /// Facts that were sent in this conversation, and those that go with the next question.
    told: HashSet<usize>,
    next_ids: Vec<usize>,
    next: String,
    what: String,
    what_told: String,
    /// Look-ups: the rounds of this question, those that wait for a yes (with the ones that were
    /// refused), those that run, and what was looked at.
    rounds: usize,
    ask_look: Option<(Vec<Look>, Vec<String>)>,
    looking: Option<(u64, Arc<AtomicBool>, Vec<Look>, Vec<String>)>,
    steps: Vec<Step>,
    always: bool,
    /// Where this question began in what was sent, and the facts it brought.
    turn: usize,
    turn_ids: Vec<usize>,
    /// The companion's own: without asking first, and without a page.
    alone: bool,
    /// The page as it is now, looked at every other second.
    peek: Option<(Instant, String, Facts)>,
    /// Waits for a look around, or for a yes.
    pending: Option<String>,
    confirm: bool,
    run: Option<Running>,
    err: Option<String>,
    input: String,
    see: bool,
    list: bool,
}

/// What went with one question.
struct Log {
    /// The question, in what's shown.
    at: usize,
    text: String,
    kept: (usize, usize),
    names: usize,
    open: bool,
}

/// A round of look-ups: shown before what's at this place.
struct Step {
    at: usize,
    words: String,
    text: String,
    open: bool,
}

/// A piece of an answer: text, code, or a fact's number.
#[derive(Debug, PartialEq)]
enum Bit {
    Text(String),
    Code(String),
    Fact(usize),
}

/// A line taken apart: facts' numbers become links, marks for bold and code go.
fn bits(line: &str) -> Vec<Bit> {
    let mut out: Vec<Bit> = vec![];
    let mut push = |b: Bit| match (out.last_mut(), b) {
        (Some(Bit::Text(a)), Bit::Text(t)) => a.push_str(&t),
        (_, b) => out.push(b),
    };
    let mut s = line;
    while !s.is_empty() {
        let next = s.find(['[', '`']).unwrap_or(s.len());
        if next > 0 {
            push(Bit::Text(s[..next].replace("**", "").replace("__", "")));
            s = &s[next..];
            continue;
        }
        if let Some(r) = s.strip_prefix('`') {
            if let Some(e) = r.find('`') {
                push(Bit::Code(r[..e].to_string()));
                s = &r[e + 1..];
            } else {
                push(Bit::Text("`".into()));
                s = r;
            }
            continue;
        }
        let end = s.find(']');
        let nums: Option<Vec<usize>> = end.map(|e| &s[1..e]).and_then(|x| x.split([',', ' ', ';']).filter(|p| !p.is_empty()).map(|p| p.strip_prefix(['F', 'f'])?.parse::<usize>().ok()).collect::<Option<Vec<_>>>()).filter(|l| !l.is_empty());
        match (nums, end) {
            (Some(l), Some(e)) => {
                for n in l {
                    push(Bit::Fact(n));
                }
                s = &s[e + 1..];
            }
            _ => {
                push(Bit::Text("[".into()));
                s = &s[1..];
            }
        }
    }
    out
}

/// A fact without what changes by itself (ages, usage), to see whether it's a new one.
fn same(t: &str) -> String {
    let w: Vec<&str> = t.split(", uses ").next().unwrap_or(t).split_whitespace().collect();
    let mut out = String::new();
    for (i, x) in w.iter().enumerate() {
        let age = w.get(i + 1).map(|n| n.starts_with("ago")).unwrap_or(false) || (i > 0 && w[i - 1].ends_with("Age"));
        out.push_str(if age { "#" } else { x });
        out.push(' ');
    }
    out
}

/// More than this many characters, and a new conversation starts.
const LONG: usize = 60_000;

impl Chat {
    fn new(facts: Facts, names: Standins) -> Chat {
        Chat { base: facts.list.len(), facts, names, to: None, way: None, fresh: None, shown: vec![], sent: vec![], kept: (0, 0), logs: vec![], page: false, cur: vec![], told: HashSet::new(), next_ids: vec![], next: String::new(), what: String::new(), what_told: String::new(), rounds: 0, ask_look: None, looking: None, steps: vec![], always: false, turn: 0, turn_ids: vec![], alone: false, peek: None, pending: Some(FIRST.into()), confirm: false, run: None, err: None, input: String::new(), see: false, list: false }
    }

    /// The companion's: no question to the person first.
    pub(super) fn alone(facts: Facts, names: Standins) -> Chat {
        Chat { alone: true, ..Chat::new(facts, names) }
    }

    /// For pictures.
    pub(super) fn made_up(sel: &Selected) -> Chat {
        let mut f = Facts { title: sel.name.clone(), ctxs: vec![sel.ctx.clone()], list: vec![] };
        f.add(super::aifacts::Class::State, "made up", None);
        let mut c = Chat::new(f, Standins::default());
        c.pending = None;
        c.shown = vec![(false, "**What's going on.** A made-up answer: all three pods end with OOMKilled [F1].\n\n**Likely cause.** The memory limit is too low since the last rollout; that's a guess.".into())];
        c
    }

    /// From here on it's the person's.
    pub(super) fn by_hand(&mut self) {
        self.alone = false;
    }

    pub(super) fn busy(&self) -> bool {
        self.run.is_some() || self.looking.is_some()
    }

    pub(super) fn waits_for(&self, id: &str) -> bool {
        self.run.as_ref().map(|r| r.id.to_string() == id).unwrap_or(false) || self.looking.as_ref().map(|l| l.0.to_string() == id).unwrap_or(false)
    }

    pub(super) fn trouble(&self) -> Option<String> {
        self.err.clone().or(self.last_answer().is_none().then(|| "there's no answer".to_string()))
    }

    pub(super) fn last_answer(&self) -> Option<&str> {
        self.shown.iter().rev().find(|x| !x.0).map(|x| x.1.as_str())
    }

    /// Takes in facts that were looked up; returns their numbers (from 0).
    fn add(&mut self, f: &Facts) -> Vec<usize> {
        let (what, cur) = (self.what.clone(), self.cur.clone());
        self.take(&what, f);
        std::mem::replace(&mut self.cur, cur)
    }

    /// Takes in a page's facts; numbers that are there stay the same.
    fn take(&mut self, what: &str, f: &Facts) {
        for c in &f.ctxs {
            if !self.facts.ctxs.contains(c) {
                self.facts.ctxs.push(c.clone());
            }
        }
        self.cur = f.list.iter().map(|x| {
            let still = same(&x.text);
            self.facts.list.iter().position(|y| y.class == x.class && same(&y.text) == still).unwrap_or_else(|| {
                self.facts.list.push(Fact { class: x.class, text: x.text.clone(), go: x.go.clone() });
                self.facts.list.len() - 1
            })
        }).collect();
        self.what = what.to_string();
    }

    /// Which facts go with the next question.
    fn due(&self) -> Vec<usize> {
        let mut v: Vec<usize> = (0..self.base).chain(self.cur.iter().copied()).filter(|i| !self.told.contains(i)).collect();
        v.dedup();
        v
    }

    /// The last question didn't get an answer: as if it wasn't asked.
    fn undo(&mut self) {
        if let Some((true, q)) = self.shown.last().cloned() {
            self.shown.pop();
            self.pending = Some(q);
            let n = self.shown.len();
            self.logs.retain(|l| l.at < n);
        }
        // With every round of look-ups it had.
        self.sent.truncate(self.turn);
        for i in std::mem::take(&mut self.turn_ids) {
            self.told.remove(&i);
        }
        let n = self.shown.len();
        // (Its steps come after the question, which was at n.)
        self.steps.retain(|s| s.at <= n);
        self.rounds = 0;
        self.ask_look = None;
        self.looking = None;
        self.what_told.clear();
    }
}

/// Explain, as a small star in a list.
pub(super) fn explain_icon(ui: &mut Ui) -> egui::Response {
    icon_button(ui, |p, r, col| star(p, r.center(), r.width() * 0.5, col))
}

fn star(p: &egui::Painter, c: egui::Pos2, big: f32, col: Color32) {
    let one = |c: egui::Pos2, l: f32| {
        let pts: Vec<egui::Pos2> = (0..8).map(|i| {
            let a = i as f32 * std::f32::consts::FRAC_PI_4 - std::f32::consts::FRAC_PI_2;
            let d = if i % 2 == 0 { l } else { l * 0.36 };
            c + egui::vec2(a.cos() * d, a.sin() * d)
        }).collect();
        // Four thin points and a middle, so that it's filled right.
        for i in [0, 2, 4, 6] {
            p.add(egui::Shape::convex_polygon(vec![pts[(i + 7) % 8], pts[i], pts[i + 1], c], col, Stroke::NONE));
        }
    };
    one(c + egui::vec2(-big * 0.18, big * 0.12), big * 0.86);
    one(c + egui::vec2(big * 0.66, -big * 0.6), big * 0.36);
}

impl KubedogApp {
    /// Explain buttons exist only when AI is on.
    pub(super) fn ai_button(&self, ui: &mut Ui) -> bool {
        self.prefs.ai.on && ui.add(egui::Button::new(RichText::new("✨ Explain").size(z(13.5)).color(PRIMARY_TEXT())).fill(BG_MUTED())).on_hover_text("Ask an AI to explain what Kubedog found (Settings > AI)").clicked()
    }

    /// The AI button at the top right: opens or hides the chat.
    pub(super) fn ai_top(&mut self, ui: &mut Ui) {
        let on = self.prefs.ai.on;
        if !on && self.prefs.ai.hide_note {
            return;
        }
        let open = on && self.ai.chat.is_some() && !self.ai.hidden;
        let (bg, fg) = if open { (PRIMARY(), Color32::WHITE) } else if on { (PRIMARY_TEXT().gamma_multiply(0.14), PRIMARY_TEXT()) } else { (BG_MUTED(), TEXT_SUBTLE()) };
        let (r, resp) = ui.allocate_exact_size(egui::vec2(u(64.0), u(30.0)), Sense::click());
        let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text(if !on { "AI is off: turn it on in Settings > AI".to_string() } else if open { "Hide the chat; it stays as it is".into() } else { format!("Ask AI about {}", self.page_noun()) });
        ui.painter().rect(r, CornerRadius::same(8), bg, Stroke::new(1.0, if on { PRIMARY_TEXT().gamma_multiply(if resp.hovered() { 1.0 } else { 0.5 }) } else { BORDER_DEFAULT() }), egui::StrokeKind::Inside);
        star(ui.painter(), egui::pos2(r.left() + u(20.0), r.center().y), u(8.0), fg);
        ui.painter().text(egui::pos2(r.left() + u(34.0), r.center().y), egui::Align2::LEFT_CENTER, "AI", FontId::proportional(z(14.5)), fg);
        if resp.clicked() {
            if !on {
                self.settings_section = "AI";
                self.navigate(View::Settings, None);
            } else if open {
                self.ai.hidden = true;
            } else {
                self.ai_open();
            }
        }
    }

    /// The same at the end of a page's first line, with Explain where that makes sense.
    pub(super) fn ai_corner(&mut self, ui: &mut Ui, explain: bool) {
        let mut now = false;
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            self.ai_top(ui);
            now = explain && self.ai_button(ui);
            drag_area(ui, ui.available_width(), 24.0);
        });
        if now {
            let f = self.page_facts();
            self.ai_explain(f);
        }
    }

    /// The chat: the one that's there, or a new one about the page that's open.
    fn ai_open(&mut self) {
        self.ai.hidden = false;
        if self.ai.chat.is_none() {
            let mut c = Chat::new(Facts { title: "Ask AI".into(), ..Default::default() }, Standins::default());
            c.page = true;
            c.pending = None;
            self.ai.chat = Some(c);
        }
        self.ai_look(false);
    }

    pub(super) fn ai_explain(&mut self, facts: Facts) {
        let mut names = Standins::default();
        self.add_standins(&mut names, &facts);
        self.ai.chat = Some(Chat::new(facts, names));
        self.ai.hidden = false;
        if self.ai.seen.is_some() {
            self.ai_go_on();
        } else {
            self.ai_look(false);
            if let (Err(e), Some(c)) = (self.ai_gate(), self.ai.chat.as_mut()) {
                c.err = Some(e);
            }
        }
    }

    /// Which way questions about these clusters go.
    fn ai_route(&self, ctxs: &[String]) -> Result<Use, String> {
        let seen = self.ai.seen.clone().unwrap_or_default();
        let to = super::ai::route(&self.prefs.ai, &seen, ctxs)?;
        if self.prefs.ai.facts[to.place as usize] { Ok(to) } else { Err("Facts may not be sent there (Settings > AI).".into()) }
    }

    /// With what's on this computer known: ask, or show first what will be sent.
    pub(super) fn ai_go_on(&mut self) {
        let Some(c) = &self.ai.chat else { return };
        let Some(q) = c.pending.clone() else { return };
        if self.ai.seen.is_none() {
            return;
        }
        // The page that's open, read now. Nothing of it is taken in when its cluster doesn't allow it.
        let page = c.page.then(|| (self.page_name(), self.page_facts()));
        let mut ctxs = c.facts.ctxs.clone();
        for x in page.iter().flat_map(|p| &p.1.ctxs) {
            if !ctxs.contains(x) {
                ctxs.push(x.clone());
            }
        }
        let to = match self.ai_route(&ctxs) {
            Ok(to) => to,
            Err(e) => {
                if let Some(c) = self.ai.chat.as_mut() {
                    c.err = Some(e);
                }
                return;
            }
        };
        if let Some((what, f)) = &page {
            let mut names = self.ai.chat.as_ref().map(|c| c.names.clone()).unwrap_or_default();
            self.add_standins(&mut names, f);
            if let Some(c) = self.ai.chat.as_mut() {
                c.names = names;
                c.take(what, f);
            }
        } else if let Some(c) = self.ai.chat.as_mut() {
            c.cur.clear();
        }
        let alone = self.ai.chat.as_ref().map(|c| c.alone).unwrap_or(false);
        let new = !alone && to.place == Place::Cloud && ctxs.iter().any(|x| !self.ai.shown.contains(&(x.clone(), to.id.to_string())));
        self.ai_prepare(&to);
        if let Some(c) = self.ai.chat.as_mut() {
            c.err = None;
            c.to = Some(to.clone());
            c.confirm = new;
            c.see = c.see || new;
        }
        if !new {
            self.ai_ask(to, q);
        }
    }

    /// The facts as they'd go there with the next question.
    fn ai_prepare(&mut self, to: &Use) {
        let Some(c) = &self.ai.chat else { return };
        let i = to.place as usize;
        let p = &self.prefs.ai;
        let way = (to.id, to.place, [p.logs[i], p.values[i], p.names[i]]);
        // Another way, or too much already: nothing of the old conversation goes along.
        let anew = c.way.as_ref() != Some(&way) || c.sent.iter().map(|t| t.1.len()).sum::<usize>() > LONG;
        if let Some(c) = self.ai.chat.as_mut().filter(|_| anew) {
            if !c.sent.is_empty() {
                c.fresh = Some(c.shown.len());
            }
            c.sent.clear();
            c.told.clear();
            c.what_told.clear();
            c.way = Some(way);
        }
        let Some(c) = &self.ai.chat else { return };
        let ids = c.due();
        let names = p_names(self, to).then_some(&c.names);
        let (t, l, v) = self.ai_sheet(&c.facts, &ids, to.place, names, 24_000);
        let mut next = String::new();
        if c.page && c.what != c.what_told {
            let w = scrub(&c.what);
            next.push_str(&format!("The page that's open now: {}\n", names.map(|n| n.hide(&w)).unwrap_or(w)));
        }
        if !t.is_empty() {
            next.push_str(&format!("{}\n{t}", if c.sent.is_empty() { "Facts:" } else { "More facts (these replace earlier ones that say otherwise):" }));
        }
        if let Some(c) = self.ai.chat.as_mut() {
            c.next = next;
            c.next_ids = ids;
            c.kept = (l, v);
        }
    }

    fn ai_ask(&mut self, to: Use, q: String) {
        let hide = self.prefs.ai.names[to.place as usize];
        let Some(c) = self.ai.chat.as_mut() else { return };
        c.pending = None;
        c.confirm = false;
        c.err = None;
        let mut asked = scrub(&q);
        if hide {
            asked = c.names.hide(&asked);
        }
        let text = format!("{}{}Question: {asked}", c.next, if c.next.is_empty() { "" } else { "\n" });
        let names = if hide { c.names.used(&text) } else { 0 };
        c.logs.push(Log { at: c.shown.len(), text: text.clone(), kept: c.kept, names, open: false });
        c.see = false;
        c.list = false;
        c.turn = c.sent.len();
        c.turn_ids = c.next_ids.clone();
        c.rounds = 0;
        c.sent.push((true, text));
        c.next.clear();
        c.told.extend(c.next_ids.iter().copied());
        c.what_told = c.what.clone();
        c.shown.push((true, q));
        let turns = c.sent.clone();
        // (Ollama can be here for one model and a cloud for the next.)
        if to.place == Place::Cloud && !c.alone {
            for x in &c.facts.ctxs {
                self.ai.shown.insert((x.clone(), to.id.to_string()));
            }
        }
        let b = self.ai_brief(&to);
        let r = self.ai_send(to, b, turns, false);
        if let Some(c) = self.ai.chat.as_mut() {
            match r {
                Ok(r) => c.run = Some(r),
                Err(e) => {
                    c.undo();
                    c.err = Some(e);
                }
            }
        }
    }

    fn ai_agent_of(&self, c: &Chat) -> &str {
        if c.always && self.prefs.ai.agent == "ask" { "auto" } else { &self.prefs.ai.agent }
    }

    /// How look-ups go in this conversation: "off", "ask" or "auto".
    fn ai_agent(&self) -> &str {
        let a = self.prefs.ai.agent.as_str();
        match self.ai.chat.as_ref() {
            Some(c) if c.alone && a != "auto" => "off",
            Some(c) if c.always && a == "ask" => "auto",
            _ => a,
        }
    }

    /// What it's told about its job, with the look-ups where they're allowed.
    fn ai_brief(&self, to: &Use) -> String {
        let Some(c) = self.ai.chat.as_ref().filter(|c| self.ai_agent() != "off" && !c.facts.ctxs.is_empty()) else { return brief(self.prefs.ai.suggest, None) };
        let hide = p_names(self, to);
        let clusters: Vec<String> = c.facts.ctxs.iter().map(|x| if hide { c.names.hide(x) } else { ctx_label(x) }).collect();
        brief(self.prefs.ai.suggest, Some(&aitools::manual(self.prefs.ai.may(super::aifacts::Class::Log, to.place), &clusters)))
    }

    /// An answer asks for look-ups: checks them, and runs them or asks the person.
    fn ai_wants(&mut self, l: &[Value]) {
        let Some(c) = self.ai.chat.as_ref() else { return };
        let Some(to) = c.to.clone() else { return };
        let ctxs: Vec<(String, String)> = c.facts.ctxs.iter().map(|x| (x.clone(), ctx_label(x))).collect();
        let allowed = aitools::Allowed { ctxs: &ctxs, limits: &self.prefs.ctx_namespaces, logs: self.prefs.ai.may(super::aifacts::Class::Log, to.place) };
        let mut good = vec![];
        let mut refused = vec![];
        for (i, v) in l.iter().enumerate() {
            // Real names again.
            let v: Value = serde_json::from_str(&c.names.back(&v.to_string())).unwrap_or(Value::Null);
            if i >= aitools::EACH {
                refused.push(format!("only {} look-ups at a time", aitools::EACH));
                break;
            }
            match aitools::check(&v, &allowed) {
                Ok(x) => good.push(x),
                Err(e) => refused.push(format!("{}: {e}", truncate(&v.to_string(), 120))),
            }
        }
        if good.is_empty() {
            self.ai_more(&Facts::default(), &refused, "Nothing: it was refused".into());
        } else if self.ai_agent() == "auto" {
            self.ai_run_looks(good, refused);
        } else if let Some(c) = self.ai.chat.as_mut() {
            c.ask_look = Some((good, refused));
        }
    }

    fn ai_run_looks(&mut self, l: Vec<Look>, refused: Vec<String>) {
        if let Err(e) = self.ai_gate() {
            if let Some(c) = self.ai.chat.as_mut() {
                c.undo();
                c.err = Some(e);
            }
            return;
        }
        self.ai.n += 1;
        let id = self.ai.n;
        let stop = Arc::new(AtomicBool::new(false));
        let Some(c) = self.ai.chat.as_mut() else { return };
        c.ask_look = None;
        c.looking = Some((id, stop.clone(), l.clone(), refused));
        self.spawn(move |k| Msg::Text { key: format!("ai|looked|{id}"), result: Ok(aitools::run(k, &l, &stop).to_string()) });
    }

    pub(super) fn ai_looked(&mut self, id: &str, result: &Result<String, String>) {
        let Some(c) = self.ai.chat.as_mut().filter(|c| c.looking.as_ref().map(|l| l.0.to_string() == id).unwrap_or(false)) else { return };
        let Some((_, _, l, refused)) = c.looking.take() else { return };
        let v: Value = result.as_ref().ok().and_then(|t| serde_json::from_str(t).ok()).unwrap_or(Value::Null);
        let f = self.look_facts(&l, &v);
        let words = l.iter().map(|x| x.words()).collect::<Vec<_>>().join("; ");
        self.ai_more(&f, &refused, words);
    }

    /// Goes on with what was looked up.
    fn ai_more(&mut self, f: &Facts, refused: &[String], words: String) {
        let Some(c) = self.ai.chat.as_ref() else { return };
        let Some(was) = c.to.clone() else { return };
        // Where it goes may have changed in the meantime.
        let now = self.ai_route(&c.facts.ctxs);
        let same = now.as_ref().map(|n| n.id == was.id && n.place == was.place).unwrap_or(false) && c.way.as_ref().map(|w| {
            let i = was.place as usize;
            w.2 == [self.prefs.ai.logs[i], self.prefs.ai.values[i], self.prefs.ai.names[i]]
        }).unwrap_or(false);
        if !same || self.ai_agent() == "off" {
            if let Some(c) = self.ai.chat.as_mut() {
                c.undo();
                c.err = Some(now.err().unwrap_or("The settings changed while it was looking. Ask again.".into()));
            }
            return;
        }
        let mut names = c.names.clone();
        // Only clusters that are part of the conversation.
        let f = Facts { ctxs: vec![], title: String::new(), list: f.list.clone() };
        self.add_standins(&mut names, &f);
        let Some(c) = self.ai.chat.as_mut() else { return };
        c.names = names;
        let ids: Vec<usize> = c.add(&f).into_iter().filter(|i| !c.told.contains(i)).collect();
        c.rounds += 1;
        let last = c.rounds >= aitools::ROUNDS;
        let Some(c) = self.ai.chat.as_ref() else { return };
        let hide = p_names(self, &was).then_some(&c.names);
        let (t, l, v) = self.ai_sheet(&c.facts, &ids, was.place, hide, 9_000);
        let mut text = format!("Results of the look-ups:\n{t}");
        if t.is_empty() && refused.is_empty() {
            text.push_str("nothing new\n");
        }
        for (n, what) in [(l, "log line"), (v, "value")] {
            if n > 0 {
                text.push_str(&format!("({} kept back: they may not be sent to you)\n", many(n as i64, what)));
            }
        }
        for e in refused {
            let e = scrub(e);
            text.push_str(&format!("Refused: {}\n", hide.map(|n| n.hide(&e)).unwrap_or(e)));
        }
        if last {
            text.push_str("No more look-ups: answer now with what you have.\n");
        }
        let Some(c) = self.ai.chat.as_mut() else { return };
        c.steps.push(Step { at: c.shown.len(), words, text: text.clone(), open: false });
        c.told.extend(ids.iter().copied());
        c.turn_ids.extend(ids);
        c.sent.push((true, text));
        let turns = c.sent.clone();
        let b = self.ai_brief(&was);
        let r = self.ai_send(was, b, turns, false);
        if let Some(c) = self.ai.chat.as_mut() {
            match r {
                Ok(r) => c.run = Some(r),
                Err(e) => {
                    c.undo();
                    c.err = Some(e);
                }
            }
        }
    }

    pub(super) fn ai_said(&mut self, id: &str, result: &Result<String, String>) {
        let agent = self.ai_agent() != "off";
        let Some(c) = self.ai.chat.as_mut().filter(|c| c.run.as_ref().map(|r| r.id.to_string() == id).unwrap_or(false)) else { return };
        c.run = None;
        match result {
            Ok(t) => {
                let (rest, wants) = if agent { aitools::asked(t) } else { (t.clone(), vec![]) };
                c.sent.push((false, t.clone()));
                if !wants.is_empty() && c.rounds < aitools::ROUNDS {
                    self.ai_wants(&wants);
                    return;
                }
                let said = if rest.trim().is_empty() { "It didn't come to an answer within its look-ups. Ask again, or more precisely.".to_string() } else { rest };
                c.shown.push((false, c.names.back(&said)));
            }
            Err(e) => {
                // The question can be asked again.
                c.err = Some(e.clone());
                c.undo();
            }
        }
    }

    pub(super) fn ai_panel(&mut self, ui: &mut Ui) {
        let Some(mut c) = self.ai.chat.take() else { return };
        let mut keep = true;
        let mut go: Option<Go> = None;
        let mut again = false;
        let mut send: Option<(Use, String)> = None;
        let mut anew = false;
        let mut may: Option<bool> = None;
        if c.page && !c.busy() && c.ask_look.is_none() && c.peek.as_ref().map(|p| p.0.elapsed() > Duration::from_secs(if p.2.list.len() < 2 { 0 } else { 2 }) || p.1 != self.page_name()).unwrap_or(true) {
            c.peek = Some((Instant::now(), self.page_name(), self.page_facts()));
        }
        if !c.busy() && c.ask_look.is_none() && !c.confirm && c.pending.is_none() && c.err.is_none() && self.ai.seen.is_some() {
            let mut ctxs = c.facts.ctxs.clone();
            ctxs.extend(c.peek.iter().filter(|_| c.page).flat_map(|p| p.2.ctxs.clone()));
            if let Ok(to) = self.ai_route(&ctxs) {
                c.to = Some(to);
            }
        }
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("✨").size(z(16.0)).color(PRIMARY_TEXT()));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.add(egui::Button::new(RichText::new("×").size(z(18.0)).color(TEXT_SUBTLE())).frame(false)).on_hover_text("Close; the conversation isn't kept").clicked() {
                    keep = false;
                }
                if ui.add(egui::Button::new(RichText::new("–").size(z(18.0)).color(TEXT_SUBTLE())).frame(false)).on_hover_text("Hide; the AI button brings it back").clicked() {
                    self.ai.hidden = true;
                }
                if (!c.shown.is_empty() || !c.page) && ui.add(egui::Button::new(RichText::new("New chat").size(z(12.5)).color(TEXT_SUBTLE())).frame(false)).on_hover_text(format!("Start over, about {}", self.page_noun())).clicked() {
                    anew = true;
                }
                ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                    ui.add(egui::Label::new(RichText::new(&c.facts.title).size(z(15.0)).strong().color(TEXT_DEFAULT())).truncate());
                });
            });
        });
        if let Some(t) = c.to.clone() {
            ui.horizontal(|ui| {
                ui.label(RichText::new(label(t.id)).size(z(13.0)).color(TEXT_MUTED()));
                if t.id != "command" {
                    let was = self.prefs.ai.models.get(t.id).cloned().unwrap_or_default();
                    let mut m = was.clone();
                    let list = self.ai_models(t.id);
                    let w = (ui.available_width() - u(10.0)).min(u(260.0));
                    let fetch = ui.add_enabled_ui(!c.busy() && c.ask_look.is_none(), |ui| self.model_menu(ui, "chat", t.id, &mut m, &list, w)).inner;
                    if fetch {
                        self.ai_fetch(t.id);
                    }
                    if m != was {
                        if m.is_empty() {
                            self.prefs.ai.models.remove(t.id);
                        } else {
                            self.prefs.ai.models.insert(t.id.to_string(), m);
                        }
                        self.save();
                        // Where that model runs decides what may be sent; asked again before anything goes.
                        let seen = self.ai.seen.clone().unwrap_or_default();
                        match super::ai::route(&self.prefs.ai, &seen, &c.facts.ctxs) {
                            Ok(to) => {
                                c.to = Some(to);
                                if c.pending.is_none() {
                                    c.err = None;
                                }
                            }
                            Err(e) => c.err = Some(e),
                        }
                        again = c.confirm;
                    }
                }
            });
            let place = c.to.as_ref().map(|t| t.place).unwrap_or_default();
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                pg::pill(ui, place_label(place), place_color(place));
                ui.label(RichText::new(place_words(place)).size(z(12.5)).color(TEXT_SUBTLE()));
            });
        }
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.checkbox(&mut c.page, "").on_hover_text("With it, every question gets the facts of where you are in Kubedog").changed() && !c.page {
                c.peek = None;
            }
            let t = match (&c.peek, c.page) {
                (Some(p), true) => format!("{} ({})", up(&p.1), many(p.2.list.len() as i64, "fact")),
                (_, true) => up(&self.page_name()),
                _ => format!("Follow me: now {}", self.page_noun()),
            };
            ui.add(egui::Label::new(RichText::new(t).size(z(12.5)).color(TEXT_MUTED())).truncate());
        });
        ui.horizontal(|ui| {
            ui.label(RichText::new("Look-ups").size(z(12.5)).color(TEXT_SUBTLE()));
            for (id, t) in super::ai::AGENT {
                if incident::chip_button(ui, t, self.prefs.ai.agent == id) && self.prefs.ai.agent != id && !c.busy() && c.ask_look.is_none() {
                    self.prefs.ai.agent = id.into();
                    c.always = false;
                    self.save();
                }
            }
        });
        ui.add_space(4.0);
        ui.separator();
        // At the bottom: the question's box, or Send it and Don't.
        if c.confirm || c.to.is_some() {
            egui::Panel::bottom("ai-foot").resizable(false).frame(Frame::new().fill(BG_DEFAULT()).inner_margin(Margin { left: 0, right: 0, top: 8, bottom: 8 })).show(ui, |ui| {
                if c.confirm {
                    said(ui, "This is what will be sent. It's the first question about this cluster to this service.", TEXT_DEFAULT());
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if button(ui, "Send it", true, false) {
                            if let (Some(t), Some(q)) = (c.to.clone(), c.pending.clone()) {
                                send = Some((t, q));
                            }
                        }
                        if button(ui, "Don't", false, false) {
                            // A chat stays, with the question back in its box.
                            match c.pending.take() {
                                Some(q) if c.page || !c.shown.is_empty() => {
                                    c.input = q;
                                    c.confirm = false;
                                    c.next.clear();
                                    c.next_ids.clear();
                                }
                                _ => keep = false,
                            }
                        }
                    });
                } else if let Some((l, _)) = &c.ask_look {
                    said(ui, "To answer, the AI wants Kubedog to read:", TEXT_DEFAULT());
                    for x in l {
                        said(ui, &format!("•  {}{}", x.words(), if c.facts.ctxs.len() > 1 { format!(" ({})", ctx_label(&x.ctx)) } else { String::new() }), PRIMARY_TEXT());
                    }
                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        if button(ui, "Read it", true, false) {
                            may = Some(true);
                        }
                        if button(ui, "Always in this chat", false, false) {
                            c.always = true;
                            may = Some(true);
                        }
                        if button(ui, "No", false, false) {
                            may = Some(false);
                        }
                    });
                } else if c.busy() {
                    if button(ui, "Stop", false, false) {
                        if let Some(l) = &c.looking {
                            l.1.store(true, Ordering::Relaxed);
                        }
                        c.run = None;
                        c.err = Some("Stopped.".into());
                        c.undo();
                    }
                } else if c.err.is_none() {
                    let mut q = None;
                    ui.horizontal_wrapped(|ui| {
                        let sum = format!("Sum up {}", self.page_noun());
                        let first = ["What stands out here?", "What should I look at first?", sum.as_str()];
                        let later = ["Is it serious?", "How do I check that?", "Put it shorter"];
                        for t in if c.shown.is_empty() { first } else { later } {
                            if incident::chip_button(ui, t, false) {
                                q = Some(t.to_string());
                            }
                        }
                    });
                    ui.add_space(4.0);
                    if question_box(ui, &mut c.input, if c.shown.is_empty() { "How can I help you?" } else { "Ask more, in any language" }) {
                        q = Some(std::mem::take(&mut c.input).trim().to_string());
                    }
                    if let Some(q) = q {
                        c.pending = Some(q);
                        again = true;
                    }
                }
            });
        }
        egui::ScrollArea::vertical().id_salt("ai-chat").auto_shrink([false, false]).max_height(ui.available_height().max(60.0)).stick_to_bottom(c.run.is_some()).show(ui, |ui| {
            if c.shown.is_empty() && c.pending.is_none() && c.page {
                ui.add_space(8.0);
                said(ui, &format!("Ask anything about {}, in any language. Go somewhere else and ask on: those facts come along. {} It can't change anything.", self.page_noun(), match self.ai_agent_of(&c) {
                    "off" => "The AI gets only these facts and can't look anything up.",
                    "ask" => "It may ask to look up more; you decide each time.",
                    _ => "It looks up more by itself when it needs to, and shows what.",
                }), TEXT_SUBTLE());
                if let Some((_, _, f)) = &c.peek {
                    ui.add_space(8.0);
                    let place = c.to.as_ref().map(|t| t.place);
                    let off = |x: &Fact| place.map(|p| !self.prefs.ai.may(x.class, p)).unwrap_or(false);
                    let back = f.list.iter().filter(|x| off(x)).count();
                    let head = format!("{}  What goes along: {}{}", if c.list { "▾" } else { "▸" }, many((f.list.len() - back) as i64, "fact"), if back > 0 { format!("; {back} kept back") } else { String::new() });
                    if ui.add(egui::Label::new(RichText::new(head).size(z(12.5)).color(TEXT_SUBTLE())).sense(Sense::click())).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                        c.list = !c.list;
                    }
                    if c.list {
                        for x in &f.list {
                            let r = ui.add(egui::Label::new(RichText::new(format!("{}{}", if off(x) { "(kept back) " } else { "" }, scrub(&x.text))).size(z(12.5)).color(if off(x) { TEXT_PLACEHOLDER() } else { TEXT_MUTED() })).wrap().sense(Sense::click()));
                            if r.clicked() && x.go.is_some() {
                                go = x.go.clone();
                            }
                        }
                    }
                }
            }
            let last = c.shown.iter().rposition(|x| x.0);
            for i in 0..c.shown.len() {
                steps(ui, &mut c.steps, i);
                let (me, t) = c.shown[i].clone();
                if c.fresh == Some(i) {
                    ui.add_space(8.0);
                    said(ui, "A new conversation: what's above wasn't sent along.", TEXT_PLACEHOLDER());
                }
                if me {
                    if t != FIRST || c.base == 0 {
                        ui.add_space(8.0);
                        Frame::new().fill(BG_MUTED()).corner_radius(CornerRadius::same(8)).inner_margin(Margin::symmetric(10, 6)).show(ui, |ui| said(ui, &t, TEXT_DEFAULT()));
                    }
                    // What went with it, and under that the answer.
                    if let Some(l) = c.logs.iter_mut().find(|l| l.at == i) {
                        ui.add_space(4.0);
                        let more = if i > 0 && c.fresh != Some(i) { ", with the conversation above" } else { "" };
                        fold(ui, &format!("{}{more}", sent_words("What was sent", &l.text, l.kept, l.names)), &mut l.open);
                        if l.open {
                            mono(ui, &l.text);
                        }
                    }
                    if last == Some(i) {
                        facts_list(ui, &c.facts, &mut c.list, &mut go);
                    }
                } else {
                    ui.add_space(6.0);
                    if let Some(g) = answer(ui, &t, &c.facts, &mut c.list) {
                        go = Some(g);
                    }
                    said(ui, "Written by an AI: it can be wrong. Numbers lead to the facts.", TEXT_PLACEHOLDER());
                }
            }
            steps(ui, &mut c.steps, c.shown.len());
            if let Some((_, _, l, _)) = &c.looking {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.spinner();
                    said(ui, &format!("Looking at {}…", l.iter().map(|x| x.words()).collect::<Vec<_>>().join("; ")), TEXT_SUBTLE());
                });
                ui.ctx().request_repaint_after(Duration::from_millis(200));
            }
            if let Some(r) = &c.run {
                let t = r.part.lock().map(|p| p.clone()).unwrap_or_default();
                ui.add_space(6.0);
                // A request for look-ups isn't an answer.
                let t = if t.trim_start_matches(['`', '-', '*', ' ', '\n']).starts_with("LOOK") || "LOOK".starts_with(t.trim()) { String::new() } else { aitools::asked(&t).0 };
                if t.is_empty() {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        said(ui, &format!("Asking… {} s", r.began.elapsed().as_secs()), TEXT_SUBTLE());
                    });
                } else if let Some(g) = answer(ui, &c.names.back(&t), &c.facts, &mut c.list) {
                    go = Some(g);
                }
                ui.ctx().request_repaint_after(Duration::from_millis(150));
            }
            if self.ai.looking {
                ui.horizontal(|ui| {
                    ui.spinner();
                    said(ui, "Looking at what's on this computer…", TEXT_SUBTLE());
                });
            }
            if let Some(e) = &c.err {
                ui.add_space(6.0);
                said(ui, e, WARNING());
                ui.horizontal(|ui| {
                    if button(ui, "Try again", false, false) {
                        again = true;
                    }
                    if button(ui, "Settings", false, false) {
                        self.settings_section = "AI";
                        self.navigate(View::Settings, None);
                    }
                });
            }
            if c.confirm {
                ui.add_space(8.0);
                let hide = c.way.as_ref().map(|w| w.2[2]).unwrap_or(false);
                let mut q = scrub(c.pending.as_deref().unwrap_or(""));
                if hide {
                    q = c.names.hide(&q);
                }
                // With what was said before, which goes along again.
                let before = c.sent.iter().map(|(me, t)| if *me { t.clone() } else { format!("(its answer)\n{t}") }).collect::<Vec<_>>().join("\n\n");
                let all = format!("{before}{}{}{}Question: {q}", if before.is_empty() { "" } else { "\n\n" }, c.next, if c.next.is_empty() { "" } else { "\n" });
                let names = if hide { c.names.used(&all) } else { 0 };
                fold(ui, &sent_words("What will be sent", &all, c.kept, names), &mut c.see);
                if c.see {
                    mono(ui, &all);
                }
                facts_list(ui, &c.facts, &mut c.list, &mut go);
            }
        });
        if keep && !anew {
            self.ai.chat = Some(c);
        }
        match (may, self.ai.chat.as_mut().and_then(|c| if may.is_some() { c.ask_look.take() } else { None })) {
            (Some(true), Some((l, refused))) => self.ai_run_looks(l, refused),
            (Some(false), Some((l, _))) => {
                let no: Vec<String> = l.iter().map(|x| format!("{}: the person didn't allow it", x.words())).collect();
                self.ai_more(&Facts::default(), &no, "Not allowed".into());
            }
            _ => {}
        }
        if anew {
            self.ai_open();
        } else if let Some((t, q)) = send {
            self.ai_ask(t, q);
        } else if again {
            if self.ai.seen.is_some() {
                self.ai_go_on();
            } else {
                self.ai_look(true);
            }
        }
        if let Some(g) = go {
            let sel = self.selected.clone().unwrap_or(Selected { ctx: String::new(), kind: Kind::Pods, ns: String::new(), name: String::new() });
            self.follow(g, &sel);
        }
    }

    /// For pictures: a panel with a made-up answer. Nothing is asked.
    pub(super) fn ai_canned(&mut self, f: Facts) {
        let mut names = Standins::default();
        self.add_standins(&mut names, &f);
        if self.ai.seen.is_none() {
            self.ai.seen = Some(super::ai::made_up());
        }
        let mut c = Chat::new(f, names);
        let to = Use { id: "claude", model: String::new(), place: Place::Cloud };
        c.to = Some(to.clone());
        self.ai.chat = Some(c);
        self.ai_prepare(&to);
        let Some(c) = self.ai.chat.as_mut() else { return };
        if std::env::var("KUBEDOG_SHOT_AI").map(|v| v == "confirm").unwrap_or(false) {
            c.confirm = true;
            c.see = true;
            return;
        }
        c.pending = None;
        let first = std::mem::take(&mut c.next);
        c.logs = [(0, first.clone()), (2, "Question: Is het ernstig?".to_string())].into_iter().map(|(at, text)| Log { at, names: c.names.used(&text), text, kept: c.kept, open: false }).collect();
        if std::env::var("KUBEDOG_SHOT_AI").map(|v| v == "look").unwrap_or(false) {
            let ctx = c.facts.ctxs.first().cloned().unwrap_or_default();
            let look = |tool, name: &str, previous| Look { tool, ctx: ctx.clone(), kind: Kind::Pods, ns: "shop".into(), name: name.into(), container: String::new(), previous, find: String::new() };
            c.steps.push(Step { at: 1, words: look(aitools::Tool::Show, "web-1", false).words(), text: "Results of the look-ups:\n[F30] made up".into(), open: false });
            c.steps.push(Step { at: 3, words: look(aitools::Tool::Events, "web-1", false).words(), text: "Results of the look-ups:\n[F31] made up".into(), open: true });
            c.ask_look = Some((vec![look(aitools::Tool::Logs, "web-1", true), look(aitools::Tool::Usage, "", false)], vec![]));
        }
        c.sent = vec![(true, first)];
        c.shown = vec![(true, FIRST.into()), (false, "**What's going on.** This is a made-up answer, to show the panel [F1]. The state is as described [F2, F3].\n\n**Likely cause.** Probably a limit that's too low; that's a guess.\n\n**Check next**\n- The last exit code [F4]\n- `kubectl top pod` for how much it uses\n\n```\nresources:\n  limits:\n    memory: 256Mi\n```\nA number that doesn't exist [F99] is marked.".into()), (true, "Is het ernstig?".into()), (false, "Nee, het is verzonnen [F2].".into())];
    }

    /// For pictures: the chat about a page, before anything is asked.
    pub(super) fn ai_canned_chat(&mut self) {
        if self.ai.seen.is_none() {
            self.ai.seen = Some(super::ai::made_up());
        }
        self.ai_open();
        if let Some(c) = self.ai.chat.as_mut() {
            c.list = true;
            c.input = std::env::var("KUBEDOG_SHOT_TYPED").unwrap_or_default();
        }
    }
}

/// An answer; returns what a fact's number leads to.
pub(super) fn answer(ui: &mut Ui, t: &str, f: &Facts, open_list: &mut bool) -> Option<Go> {
    let mut go = None;
    let mut code: Option<String> = None;
    ui.spacing_mut().item_spacing.y = 4.0;
    for line in t.lines() {
        if line.trim_start().starts_with("```") {
            match code.take() {
                Some(c) => block(ui, &c),
                None => code = Some(String::new()),
            }
            continue;
        }
        if let Some(c) = code.as_mut() {
            c.push_str(line);
            c.push('\n');
            continue;
        }
        if line.trim().is_empty() {
            ui.add_space(4.0);
            continue;
        }
        let (head, line) = match line.trim_start().trim_start_matches('#') {
            l if l.len() < line.trim_start().len() => (true, l.trim_start()),
            l => (l.starts_with("**") && l.trim_end().ends_with("**"), l),
        };
        let (dot, line) = match line.strip_prefix("- ").or(line.strip_prefix("* ")).or(line.strip_prefix("• ")) {
            Some(l) => (true, l),
            None => (false, line),
        };
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = egui::vec2(3.0, 2.0);
            if dot {
                ui.label(RichText::new("  •").size(z(13.5)).color(TEXT_SUBTLE()));
            }
            for b in bits(line) {
                match b {
                    Bit::Text(t) => {
                        let mut r = RichText::new(t.trim_start_matches(' ')).size(z(13.5)).color(TEXT_DEFAULT());
                        if head {
                            r = r.strong();
                        }
                        ui.add(egui::Label::new(r).wrap());
                    }
                    Bit::Code(t) => {
                        ui.label(RichText::new(t).font(FontId::monospace(z(12.5))).color(TEXT_DEFAULT()).background_color(BG_MUTED()));
                    }
                    Bit::Fact(n) => match n.checked_sub(1).and_then(|i| f.list.get(i)) {
                        Some(x) => {
                            let r = ui.add(egui::Label::new(RichText::new(format!("F{n}")).size(z(11.5)).color(PRIMARY_TEXT()).background_color(BG_MUTED())).sense(Sense::click())).on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text(&x.text);
                            if r.clicked() {
                                match &x.go {
                                    Some(g) => go = Some(g.clone()),
                                    None => *open_list = true,
                                }
                            }
                        }
                        None => {
                            ui.label(RichText::new(format!("F{n}?")).size(z(11.5)).color(WARNING())).on_hover_text("There's no such fact");
                        }
                    },
                }
            }
        });
    }
    if let Some(c) = code {
        block(ui, &c);
    }
    go
}

/// What was looked at, before what's at this place.
fn steps(ui: &mut Ui, l: &mut [Step], at: usize) {
    for s in l.iter_mut().filter(|s| s.at == at) {
        ui.add_space(2.0);
        fold(ui, &format!("Looked at: {}", s.words), &mut s.open);
        if s.open {
            mono(ui, &s.text);
        }
    }
}

fn mono(ui: &mut Ui, t: &str) {
    ui.add(egui::Label::new(RichText::new(t).font(FontId::monospace(z(11.5))).color(TEXT_MUTED())).wrap());
}

/// A line that folds what's under it.
fn fold(ui: &mut Ui, head: &str, open: &mut bool) {
    let t = format!("{}  {head}", if *open { "▾" } else { "▸" });
    if ui.add(egui::Label::new(RichText::new(t).size(z(12.5)).color(TEXT_SUBTLE())).wrap().sense(Sense::click())).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
        *open = !*open;
    }
}

fn sent_words(head: &str, text: &str, kept: (usize, usize), names: usize) -> String {
    let back = [(kept.0, "log line"), (kept.1, "value")].into_iter().filter(|x| x.0 > 0).map(|x| many(x.0 as i64, x.1)).collect::<Vec<_>>().join(" and ");
    format!("{head}: about {} tokens{}{}", text.len() / 4, if back.is_empty() { String::new() } else { format!("; {back} kept back") }, if names > 0 { format!("; {} replaced", many(names as i64, "name")) } else { String::new() })
}

fn facts_list(ui: &mut Ui, f: &Facts, open: &mut bool, go: &mut Option<Go>) {
    fold(ui, &format!("Facts ({})", f.list.len()), open);
    if *open {
        for (i, x) in f.list.iter().enumerate() {
            let r = ui.add(egui::Label::new(RichText::new(format!("F{}  {}", i + 1, truncate(&x.text, 260))).size(z(12.5)).color(if x.go.is_some() { PRIMARY_TEXT() } else { TEXT_MUTED() })).wrap().sense(Sense::click()));
            if r.clicked() && x.go.is_some() {
                *go = x.go.clone();
            }
        }
    }
}

/// Two lines to type in, and a button to send. True when it's to be sent: Enter does that too,
/// with Shift it's a new line.
fn question_box(ui: &mut Ui, text: &mut String, hint: &str) -> bool {
    let full = !text.trim().is_empty();
    let mut go = false;
    ui.horizontal(|ui| {
        let w = ui.available_width() - u(50.0);
        let h = u(62.0);
        let r = egui::ScrollArea::vertical().id_salt("ai-input").max_height(u(150.0)).max_width(w).show(ui, |ui| {
            ui.add(egui::TextEdit::multiline(text).hint_text(hint).desired_width(w).desired_rows(2).min_size(egui::vec2(w, h)).return_key(egui::KeyboardShortcut::new(egui::Modifiers::SHIFT, Key::Enter)))
        }).inner;
        go = r.has_focus() && ui.input(|i| i.events.iter().any(|e| matches!(e, egui::Event::Key { key: Key::Enter, pressed: true, modifiers, .. } if !modifiers.shift)));
        if send_button(ui, full).clicked() {
            go = true;
            r.request_focus();
        }
    });
    go && full
}

/// A paper plane.
fn send_button(ui: &mut Ui, on: bool) -> egui::Response {
    let (r, resp) = ui.allocate_exact_size(egui::vec2(u(40.0), u(40.0)), if on { Sense::click() } else { Sense::hover() });
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, on, "Send"));
    let col = if on { Color32::WHITE } else { TEXT_PLACEHOLDER() };
    let bg = if !on { BG_MUTED() } else if resp.hovered() { PRIMARY().gamma_multiply(0.85) } else { PRIMARY() };
    let p = ui.painter();
    p.rect_filled(r, CornerRadius::same(10), bg);
    let s = r.width() * 0.25;
    let c = r.center();
    let at = |x: f32, y: f32| c + egui::vec2(x * s, y * s);
    // Two wings with a fold between them.
    p.add(egui::Shape::convex_polygon(vec![at(1.1, 0.0), at(-1.0, -1.0), at(-0.62, -0.1)], col, Stroke::NONE));
    p.add(egui::Shape::convex_polygon(vec![at(1.1, 0.0), at(-0.62, 0.1), at(-1.0, 1.0)], col, Stroke::NONE));
    if on {
        resp.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Send (Enter; Shift+Enter for a new line)")
    } else {
        resp
    }
}

/// With a capital.
fn up(t: &str) -> String {
    let mut c = t.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

fn p_names(app: &KubedogApp, to: &Use) -> bool {
    app.prefs.ai.names[to.place as usize]
}

fn block(ui: &mut Ui, t: &str) {
    Frame::new().fill(BG_MUTED()).corner_radius(CornerRadius::same(6)).inner_margin(Margin::symmetric(10, 8)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.add(egui::Label::new(RichText::new(t.trim_end()).font(FontId::monospace(z(12.5))).color(TEXT_DEFAULT())).wrap().selectable(true));
        if ui.add(egui::Button::new(RichText::new("Copy").size(z(12.0)).color(TEXT_SUBTLE())).frame(false)).clicked() {
            ui.ctx().copy_text(t.trim_end().to_string());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_come_along() {
        use super::super::aifacts::Class;
        let page = |ctx: &str, l: &[&str]| {
            let mut f = Facts { ctxs: vec![ctx.into()], ..Default::default() };
            for t in l {
                f.add(Class::State, *t, None);
            }
            f
        };
        let mut c = Chat::new(page("a", &["base"]), Standins::default());
        c.take("Pods", &page("a", &["x", "y"]));
        assert_eq!(c.due(), vec![0, 1, 2]);
        c.next_ids = c.due();
        c.told.extend(c.due());
        // The same page again: nothing new. Another page: only what's new, with numbers that go on.
        c.take("Pods", &page("a", &["x", "y"]));
        assert!(c.due().is_empty());
        c.take("Events", &page("b", &["y", "z"]));
        assert_eq!((c.due(), c.facts.list.len()), (vec![3], 4));
        assert_eq!(c.facts.ctxs, vec!["a".to_string(), "b".into()]);
        c.take("Pods", &page("a", &["pod w: Age 5m, uses 1 CPU", "seen 9s ago"]));
        let n = c.facts.list.len();
        c.take("Pods", &page("a", &["pod w: Age 6m, uses 2 CPU", "seen 10s ago"]));
        assert_eq!(c.facts.list.len(), n);
        c.take("Events", &page("b", &["y", "z"]));
        // No answer: it can be asked again, with the same facts.
        c.next_ids = c.due();
        c.told.extend(c.due());
        // With a round of look-ups in between.
        c.turn = 0;
        c.turn_ids = c.next_ids.clone();
        c.sent.push((true, "s".into()));
        c.sent.push((false, "LOOK {}".into()));
        c.sent.push((true, "results".into()));
        c.steps.push(Step { at: 1, words: "w".into(), text: "t".into(), open: false });
        c.logs.push(Log { at: 0, text: "s".into(), kept: (0, 0), names: 0, open: false });
        c.shown.push((true, "q".into()));
        c.undo();
        assert!(c.logs.is_empty() && c.steps.is_empty());
        assert_eq!((c.due(), c.pending.as_deref(), c.sent.len(), c.shown.len()), (vec![3], Some("q"), 0, 0));
    }

    #[test]
    fn enter_sends() {
        let ctx = egui::Context::default();
        let mut text = String::from("why");
        let mut frame = |events: Vec<egui::Event>, text: &mut String| {
            let mut sent = false;
            let mut out = ctx.run_ui(egui::RawInput { events, screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(500.0, 300.0))), ..Default::default() }, |ui| {
                sent = question_box(ui, text, "");
            });
            out.textures_delta.clear();
            sent
        };
        let key = |m: egui::Modifiers| egui::Event::Key { key: Key::Enter, physical_key: None, pressed: true, repeat: false, modifiers: m };
        let press = |d: bool| egui::Event::PointerButton { pos: egui::pos2(80.0, 25.0), button: egui::PointerButton::Primary, pressed: d, modifiers: Default::default() };
        frame(vec![egui::Event::PointerMoved(egui::pos2(80.0, 25.0))], &mut text);
        frame(vec![press(true)], &mut text);
        frame(vec![press(false)], &mut text);
        assert!(!frame(vec![key(egui::Modifiers::SHIFT)], &mut text) && text.contains('\n'));
        let before = text.clone();
        assert!(frame(vec![key(egui::Modifiers::NONE)], &mut text) && text == before);
        text.clear();
        assert!(!frame(vec![key(egui::Modifiers::NONE)], &mut text) && text.is_empty());
    }

    #[test]
    fn numbers_become_links() {
        assert_eq!(bits("**It** stops [F1][F2, F3]."), vec![Bit::Text("It stops ".into()), Bit::Fact(1), Bit::Fact(2), Bit::Fact(3), Bit::Text(".".into())]);
        assert_eq!(bits("a [link](https://x) `b`"), vec![Bit::Text("a [link](https://x) ".into()), Bit::Code("b".into())]);
        assert_eq!(bits("[F1 `x"), vec![Bit::Text("[F1 `x".into())]);
    }
}
