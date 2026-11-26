//! The top of every object's page: is it well, in a sentence, with its conditions and the facts
//! people look for. What the sentence is for each kind is worked out here, from the object alone.

use super::dash::grid;
use super::pg::{label_at, pill};
use super::pod::{cond, heartbeat, time_of, when};
use super::*;

pub(super) struct Fact {
    pub label: String,
    pub text: String,
    pub col: Color32,
    pub to: Option<Selected>,
}

impl Fact {
    pub fn new(label: impl Into<String>, text: impl Into<String>) -> Fact {
        let t: String = text.into();
        Fact { label: label.into(), text: if t.is_empty() { "-".into() } else { t }, col: TEXT_DEFAULT(), to: None }
    }
    pub fn col(mut self, col: Color32) -> Fact {
        self.col = col;
        self
    }
    pub fn to(mut self, to: Selected) -> Fact {
        self.col = PRIMARY_TEXT();
        self.to = Some(to);
        self
    }
}

pub(super) struct Face {
    pub tone: Tone,
    pub head: String,
    pub sub: String,
    pub notes: Vec<String>,
    /// (text, colour, more)
    pub pills: Vec<(String, Color32, String)>,
    pub facts: Vec<Fact>,
}

/// What's drawn at the right of the sentence.
pub(super) enum Side {
    None,
    /// A pulse that beats with CPU (millicores).
    Beat(f64),
    /// A share, what it is, and more about it.
    Ring(f64, String, String),
}

pub(super) fn show(ui: &mut Ui, f: &Face, side: Side) -> Option<Selected> {
    let mut open = None;
    aipage::note_face(f);
    let col = tone_color(f.tone);
    let edge = if matches!(f.tone, Tone::Muted | Tone::Normal) { BORDER_DEFAULT() } else { col.gamma_multiply(0.45) };
    Frame::new().fill(BG_CARD()).stroke(Stroke::new(1.0, edge)).corner_radius(CornerRadius::same(12)).inner_margin(Margin::symmetric(18, 14)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(46.0)), Sense::hover());
        let side_w = match side {
            Side::None => 0.0,
            Side::Beat(_) => (r.width() * 0.34).clamp(u(120.0), u(420.0)),
            Side::Ring(..) => u(210.0).min(r.width() * 0.4),
        };
        let at = egui::Rect::from_min_max(egui::pos2(r.right() - side_w, r.top()), r.max);
        match &side {
            Side::None => {}
            Side::Beat(cpu) => heartbeat(ui, at, col, f.tone, *cpu),
            Side::Ring(share, big, small) => {
                let p = ui.painter();
                let rad = at.height() * 0.46;
                let c = egui::pos2(at.right() - rad - 2.0, at.center().y);
                p.circle_stroke(c, rad - 3.0, Stroke::new(u(5.0), BG_MUTED()));
                let n = 60;
                let end = std::f32::consts::TAU * (*share as f32).clamp(0.0, 1.0);
                let pts: Vec<egui::Pos2> = (0..=n).map(|i| c + egui::vec2((end * i as f32 / n as f32).sin(), -(end * i as f32 / n as f32).cos()) * (rad - 3.0)).collect();
                if *share > 0.0 {
                    p.add(egui::Shape::line(pts, Stroke::new(u(5.0), col)));
                }
                let x = c.x - rad - 12.0;
                p.text(egui::pos2(x, at.top() + u(13.0)), egui::Align2::RIGHT_CENTER, big, FontId::proportional(z(17.0)), TEXT_DEFAULT());
                p.text(egui::pos2(x, at.top() + u(36.0)), egui::Align2::RIGHT_CENTER, small, FontId::proportional(z(12.0)), TEXT_SUBTLE());
            }
        }
        let p = ui.painter();
        p.circle_filled(egui::pos2(r.left() + u(9.0), r.center().y), u(7.0), col);
        p.circle_stroke(egui::pos2(r.left() + u(9.0), r.center().y), u(11.0), Stroke::new(1.5, col.gamma_multiply(0.35)));
        let room = r.width() - side_w - u(40.0);
        if f.sub.is_empty() {
            label_at(ui, p, egui::pos2(r.left() + u(30.0), r.center().y), &f.head, 19.0, TEXT_DEFAULT(), room);
        } else {
            label_at(ui, p, egui::pos2(r.left() + u(30.0), r.top() + u(13.0)), &f.head, 19.0, TEXT_DEFAULT(), room);
            label_at(ui, p, egui::pos2(r.left() + u(30.0), r.top() + u(36.0)), &f.sub, 12.5, TEXT_SUBTLE(), room);
        }
        for n in &f.notes {
            ui.add(egui::Label::new(RichText::new(n).size(z(13.0)).color(col)).wrap());
        }
        if !f.pills.is_empty() {
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                for (t, c, tip) in &f.pills {
                    let resp = ui.scope(|ui| pill(ui, t, *c)).response;
                    if !tip.is_empty() {
                        resp.on_hover_text(tip);
                    }
                }
            });
        }
        if !f.facts.is_empty() {
            ui.add_space(10.0);
        }
        grid(ui, f.facts.len(), u(150.0), u(44.0), 10.0, |ui, i, r| {
            let x = &f.facts[i];
            label_at(ui, ui.painter(), r.left_top() + egui::vec2(0.0, u(10.0)), &x.label, 11.5, TEXT_SUBTLE(), r.width() - 6.0);
            label_at(ui, ui.painter(), r.left_top() + egui::vec2(0.0, u(29.0)), &x.text, 14.0, x.col, r.width() - 6.0);
            let resp = ui.interact(r, ui.id().with(("fact", i)), if x.to.is_some() { Sense::click() } else { Sense::hover() });
            let resp = if x.to.is_some() { resp.on_hover_cursor(egui::CursorIcon::PointingHand) } else { resp };
            if resp.on_hover_text(&x.text).clicked() {
                open = x.to.clone();
            }
        });
    });
    open
}

/// How it's related, what kind, its name, and where a click leads.
pub(super) type Ref = (&'static str, String, String, Option<Selected>);

/// The widths of the three columns: references and labels as wide as what's in them, annotations the rest.
/// When it doesn't all fit, none of the first two takes more than its share.
fn three(total: f32, refs: f32, labels: f32, notes: f32) -> [f32; 3] {
    let least = 150.0f32.min(total / 3.0);
    let mut a = refs.max(least).min(total * 0.3);
    let mut b = labels.max(least).min(total * 0.36);
    // Short annotations don't need the rest: what the first two lack goes to them first.
    let mut c = total - a - b;
    let spare = (c - notes.max(least)).max(0.0);
    let (la, lb) = ((refs - a).max(0.0), (labels - b).max(0.0));
    let give = spare.min(la + lb);
    if give > 0.0 {
        a += give * la / (la + lb);
        b += give * lb / (la + lb);
        c -= give;
    }
    [a, b, c]
}

/// References, labels and annotations as one table of three columns. Returns the object clicked.
pub(super) fn meta(ui: &mut Ui, key: &str, refs: &[Ref], o: &Value) -> Option<Selected> {
    let mut open = None;
    let md = &o["metadata"];
    let list = |k: &str| -> Vec<(String, String)> { md[k].as_object().into_iter().flatten().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect() };
    let (labels, notes) = (list("labels"), list("annotations"));
    ui.add_space(12.0);
    Frame::new().fill(BG_CARD()).stroke(Stroke::new(1.0, BORDER_SUBTLE())).corner_radius(CornerRadius::same(10)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
        let total = ui.available_width();
        let side = total >= u(760.0);
        // As wide as what's in them.
        let p = ui.painter().clone();
        let plain = |t: &str, size: f32| p.layout_no_wrap(truncate(t, 200), FontId::proportional(z(size)), TEXT_DEFAULT()).size().x;
        let mono = |t: &str| p.layout_no_wrap(truncate(&t.replace('\n', " "), 200), FontId::monospace(z(12.5)), TEXT_DEFAULT()).size().x;
        let kinds = refs.iter().map(|r| plain(&r.1, 12.0)).fold(0.0, f32::max).min(u(170.0)) + u(18.0);
        let pairs = |l: &[(String, String)]| l.iter().map(|(k, v)| plain(k, 11.5).max(mono(v))).fold(u(90.0), f32::max) + 44.0;
        let names = refs.iter().map(|r| plain(&r.2, 13.0)).fold(u(60.0), f32::max);
        let ws = if side { three(total, kinds + names + 44.0, pairs(&labels), pairs(&notes)) } else { [total; 3] };
        let top = ui.cursor().top();
        let mut cols = |ui: &mut Ui| {
            for i in 0..3 {
                let w = ws[i];
                let (title, n) = [("References", refs.len()), ("Labels", labels.len()), ("Annotations", notes.len())][i];
                ui.allocate_ui_with_layout(egui::vec2(w, 0.0), Layout::top_down(Align::Min), |ui| {
                    ui.set_width(w);
                    // The header.
                    let (h, _) = ui.allocate_exact_size(egui::vec2(w, u(36.0)), Sense::hover());
                    let round = match (side, i) { (true, 0) => CornerRadius { nw: 10, ..Default::default() }, (true, 2) => CornerRadius { ne: 10, ..Default::default() }, (false, 0) => CornerRadius { nw: 10, ne: 10, ..Default::default() }, _ => CornerRadius::ZERO };
                    ui.painter().rect_filled(h, round, BG_MUTED().gamma_multiply(0.55));
                    ui.painter().hline(h.x_range(), h.bottom(), Stroke::new(1.0, BORDER_SUBTLE()));
                    let g = ui.painter().layout_no_wrap(title.to_string(), FontId::proportional(z(14.0)), TEXT_DEFAULT());
                    let gw = g.size().x;
                    ui.painter().galley(egui::pos2(h.left() + 16.0, h.center().y - g.size().y / 2.0), g, TEXT_DEFAULT());
                    ui.painter().text(egui::pos2(h.left() + 26.0 + gw, h.center().y), egui::Align2::LEFT_CENTER, n.to_string(), FontId::proportional(z(12.0)), TEXT_PLACEHOLDER());
                    Frame::new().inner_margin(Margin { left: 16, right: 16, top: 4, bottom: 10 }).show(ui, |ui| {
                        ui.set_width(w - 32.0);
                        if n == 0 {
                            ui.add_space(u(6.0));
                            ui.label(RichText::new("None").size(z(12.5)).color(TEXT_PLACEHOLDER()));
                            return;
                        }
                        // Long lists show their start.
                        let all_id = egui::Id::new(("meta-all", key, i));
                        let mut all = ui.data(|d| d.get_temp::<bool>(all_id).unwrap_or(false));
                        let max = if all { n } else { n.min(14) };
                        match i {
                            0 => refs.iter().take(max).enumerate().for_each(|(j, r)| {
                                if j == 0 || refs[j - 1].0 != r.0 {
                                    let (h, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(if j == 0 { 24.0 } else { 32.0 })), Sense::hover());
                                    label_at(ui, ui.painter(), egui::pos2(h.left(), h.bottom() - u(11.0)), r.0, 11.5, TEXT_SUBTLE(), h.width());
                                }
                                if let Some(s) = ref_row(ui, r, kinds) {
                                    open = Some(s);
                                }
                            }),
                            1 => labels.iter().take(max).enumerate().for_each(|(j, (k, v))| pair_row(ui, key, k, v, j > 0)),
                            _ => notes.iter().take(max).enumerate().for_each(|(j, (k, v))| pair_row(ui, key, k, v, j > 0)),
                        }
                        if n > 14 {
                            ui.add_space(u(6.0));
                            if ui.add(egui::Label::new(RichText::new(if all { "show fewer".to_string() } else { format!("show all {n}") }).size(z(12.0)).color(PRIMARY_TEXT())).sense(Sense::click())).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                                all = !all;
                                ui.data_mut(|d| d.insert_temp(all_id, all));
                            }
                        }
                    });
                });
            }
        };
        let left = ui.cursor().left();
        if side {
            let r = ui.horizontal_top(|ui| cols(ui)).response.rect;
            for x in [ws[0], ws[0] + ws[1]] {
                ui.painter().vline(left + x, top..=r.bottom(), Stroke::new(1.0, BORDER_SUBTLE()));
            }
        } else {
            cols(ui);
        }
    });
    open
}

fn split_line(ui: &Ui, r: egui::Rect, on: bool) {
    if on {
        ui.painter().hline(r.x_range(), r.top(), Stroke::new(1.0, BORDER_SUBTLE().gamma_multiply(0.7)));
    }
}

fn ref_row(ui: &mut Ui, (_, kind, name, to): &Ref, kinds: f32) -> Option<Selected> {
    let (r, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(26.0)), if to.is_some() { Sense::click() } else { Sense::hover() });
    if to.is_some() && resp.hovered() {
        ui.painter().rect_filled(r.expand2(egui::vec2(8.0, 0.0)), CornerRadius::same(6), BG_HOVER());
    }
    split_line(ui, r, true);
    let kw = kinds.min(r.width() * 0.45);
    label_at(ui, ui.painter(), r.left_center(), kind, 12.0, TEXT_MUTED(), kw - 8.0);
    label_at(ui, ui.painter(), egui::pos2(r.left() + kw, r.center().y), name, 13.0, if to.is_some() { PRIMARY_TEXT() } else { TEXT_DEFAULT() }, r.width() - kw);
    let resp = if to.is_some() { resp.on_hover_cursor(egui::CursorIcon::PointingHand) } else { resp };
    resp.on_hover_text(format!("{kind} {name}")).clicked().then(|| to.clone()).flatten()
}

/// A label or annotation: its key, and its value under it, over at most three lines. A click copies;
/// longer values open.
fn pair_row(ui: &mut Ui, key: &str, k: &str, v: &str, line: bool) {
    let flat = v.split_whitespace().collect::<Vec<_>>().join(" ");
    let w = ui.available_width();
    let id = egui::Id::new(("meta-open", key, k));
    let col = if v.is_empty() { TEXT_PLACEHOLDER() } else { TEXT_DEFAULT() };
    let mut job = egui::text::LayoutJob::simple(if v.is_empty() { "(empty)".to_string() } else { truncate(&flat, 1200) }, FontId::monospace(z(12.5)), col, w);
    job.wrap.max_rows = 3;
    job.wrap.break_anywhere = true;
    let g = ui.painter().layout_job(job);
    let wide = g.elided || flat.chars().count() > 1200 || v.trim().lines().count() > 3;
    let mut opened = wide && ui.data(|d| d.get_temp::<bool>(id).unwrap_or(false));
    let (r, resp) = ui.allocate_exact_size(egui::vec2(w, if opened { u(23.0) } else { u(22.0) + g.size().y + u(6.0) }), Sense::click());
    split_line(ui, r, line);
    if resp.hovered() {
        ui.painter().rect_filled(r.expand2(egui::vec2(8.0, 0.0)), CornerRadius::same(6), BG_HOVER().gamma_multiply(0.6));
    }
    let mw = if wide { u(34.0) } else { 0.0 };
    label_at(ui, ui.painter(), egui::pos2(r.left(), r.top() + u(13.0)), k, 11.5, TEXT_SUBTLE(), w - mw);
    if wide {
        let mr = egui::Rect::from_min_size(egui::pos2(r.right() - mw, r.top()), egui::vec2(mw, u(24.0)));
        let m = ui.interact(mr, ui.id().with(("meta-more", k)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
        ui.painter().text(egui::pos2(mr.right(), r.top() + u(13.0)), egui::Align2::RIGHT_CENTER, if opened { "less" } else { "more" }, FontId::proportional(z(11.5)), if m.hovered() { TEXT_DEFAULT() } else { PRIMARY_TEXT() });
        if m.clicked() {
            opened = !opened;
            ui.data_mut(|d| d.insert_temp(id, opened));
        }
    }
    if !opened {
        ui.painter().galley(egui::pos2(r.left(), r.top() + u(22.0)), g, col);
    } else {
        let t = serde_json::from_str::<Value>(v).ok().filter(|j| j.is_object() || j.is_array()).and_then(|j| serde_json::to_string_pretty(&j).ok()).unwrap_or_else(|| v.to_string());
        Frame::new().fill(LOG_BG()).corner_radius(CornerRadius::same(6)).inner_margin(Margin::same(8)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::ScrollArea::vertical().id_salt(("meta-text", key, k)).max_height(u(320.0)).min_scrolled_height(u(320.0)).show(ui, |ui| {
                ui.add(egui::Label::new(RichText::new(truncate(&t, 20_000)).monospace().size(z(11.5)).color(TEXT_MUTED())).wrap());
            });
        });
        ui.add_space(u(6.0));
    }
    // (The whole value only when it isn't there already: a big tip hides the rows under it.)
    if resp.on_hover_text(if wide && !opened { format!("{}\n\nClick to copy", truncate(v, 300)) } else { "Click to copy".into() }).clicked() {
        ui.ctx().copy_text(format!("{k}={v}"));
    }
}

// ---------- conditions ----------

/// A condition that's good when it's True. (The others report trouble, or say nothing by themselves.)
pub(super) fn good_when_true(t: &str) -> Option<bool> {
    let bad = t.ends_with("Pressure") || t.ends_with("Failure") || t.contains("Failed") || t.contains("Remaining") || matches!(t, "NetworkUnavailable" | "FailureTarget" | "Degraded" | "Stalled" | "Denied" | "NonStructuralSchema" | "Dangling" | "Error" | "Warning" | "Terminating" | "Deleting");
    if bad {
        return Some(false);
    }
    if matches!(t, "ScalingLimited" | "Suspended" | "SuccessCriteriaMet" | "Progressing" | "Resizing" | "FileSystemResizePending" | "Reconciling") {
        return None;
    }
    Some(true)
}

pub(super) fn pills(o: &Value, now: i64) -> Vec<(String, Color32, String)> {
    o["status"]["conditions"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| {
            let t = c["type"].as_str().unwrap_or("");
            let yes = c["status"] == "True";
            let ok = good_when_true(t).map(|g| g == yes);
            let col = match ok {
                _ if c["status"] == "Unknown" => WARNING(),
                Some(true) => SUCCESS(),
                Some(false) if yes => DANGER(),
                Some(false) => WARNING(),
                None => INFO(),
            };
            let at = time_of(&c["lastTransitionTime"]).or_else(|| time_of(&c["lastUpdateTime"]));
            let done = t == "Progressing" && c["reason"] == "NewReplicaSetAvailable";
            let col = if done { SUCCESS() } else { col };
            let word = match c["status"].as_str() {
                Some("True") if done => "Rolled out".to_string(),
                Some("True") => spaced(t),
                Some("False") if good_when_true(t) == Some(false) => format!("No {}", spaced(t).to_lowercase()),
                Some("False") => format!("Not {}", spaced(t).to_lowercase()),
                _ => format!("{}: unknown", spaced(t)),
            };
            let tip = format!("{t}: {}{}\n{} {}", c["status"].as_str().unwrap_or(""), at.map(|t| format!(", since {}", when(t))).unwrap_or_default(), c["reason"].as_str().unwrap_or(""), c["message"].as_str().unwrap_or(""));
            (format!("{} {word}{}", if ok == Some(false) { "○" } else { "●" }, at.map(|t| format!("  {}", kube::human_duration((now - t).max(0)))).unwrap_or_default()), col, tip.trim().to_string())
        })
        .collect()
}

/// "ReplicaFailure" → "Replica failure".
pub(super) fn spaced(t: &str) -> String {
    let c: Vec<char> = t.chars().collect();
    let mut out = String::new();
    for (i, ch) in c.iter().enumerate() {
        let start = i > 0 && ch.is_uppercase() && (c[i - 1].is_lowercase() || c.get(i + 1).map(|n| n.is_lowercase()).unwrap_or(false));
        if start && c[i - 1] != '-' && c[i - 1] != '/' && c[i - 1] != '.' {
            out.push(' ');
        }
        let word = c.get(i + 1).map(|n| n.is_lowercase()).unwrap_or(false);
        out.extend(if start && word { ch.to_lowercase().collect::<Vec<_>>() } else { vec![*ch] });
    }
    out
}

pub(super) fn many(n: i64, one: &str) -> String {
    format!("{n} {one}{}", if n == 1 { "" } else { "s" })
}

// ---------- is it well ----------

type Verdict = (Tone, String, Vec<String>);

fn msg(c: &Value) -> Vec<String> {
    c["message"].as_str().filter(|m| !m.is_empty()).map(|m| vec![truncate(m, 300)]).unwrap_or_default()
}

fn copies(ready: i64, want: i64) -> Verdict {
    match (ready, want) {
        (r, w) if r >= w => (Tone::Success, format!("{r}/{w} pods ready"), vec![]),
        (0, w) => (Tone::Danger, format!("0/{w} pods ready"), vec![]),
        (r, w) => (Tone::Warning, format!("{r}/{w} pods ready"), vec![]),
    }
}

/// How an object is doing, from what it says itself.
pub(super) fn verdict(kind: Kind, o: &Value, now: i64) -> Verdict {
    let (spec, st) = (&o["spec"], &o["status"]);
    let n = |v: &Value| v.as_i64().unwrap_or(0);
    let s = |v: &Value| v.as_str().unwrap_or("").to_string();
    if let (Some(t), true) = (time_of(&o["metadata"]["deletionTimestamp"]), kind != Kind::Namespaces) {
        let held = o["metadata"]["finalizers"].as_array().filter(|f| !f.is_empty()).map(|f| format!("Finalizers: {}.", f.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")));
        return (Tone::Warning, format!("Terminating for {}", kube::human_duration((now - t).max(0))), held.into_iter().collect());
    }
    match kind {
        Kind::Deployments => {
            let want = spec["replicas"].as_i64().unwrap_or(1);
            let (ready, new, all) = (n(&st["readyReplicas"]), n(&st["updatedReplicas"]), n(&st["replicas"]));
            let seen = st["observedGeneration"].as_i64().unwrap_or(0) >= o["metadata"]["generation"].as_i64().unwrap_or(0);
            let mut v = if let Some(c) = cond(o, "ReplicaFailure").filter(|c| c["status"] == "True") {
                (Tone::Danger, "Replica failure: it can't create its pods".to_string(), msg(c))
            } else if let Some(c) = cond(o, "Progressing").filter(|c| c["status"] == "False") {
                (Tone::Danger, "Rollout stuck: progress deadline exceeded".into(), msg(c))
            } else if want == 0 && all == 0 {
                (Tone::Muted, "Scaled to 0".into(), vec![])
            } else if !seen || new < want || all > new {
                let t = if ready == 0 { Tone::Warning } else { Tone::Info };
                (t, if new < want { format!("Rolling out: {new}/{want} pods updated") } else { format!("Rolling out: {} terminating", many(all - new, "old pod")) }, vec![])
            } else {
                copies(ready, want)
            };
            if spec["paused"] == true {
                v.2.push("The rollout is paused: changes wait until it's resumed.".into());
                if v.0 == Tone::Success {
                    v.0 = Tone::Warning;
                }
            }
            v
        }
        Kind::StatefulSets => {
            let want = spec["replicas"].as_i64().unwrap_or(1);
            let (ready, new) = (n(&st["readyReplicas"]), n(&st["updatedReplicas"]));
            let rolling = st["updateRevision"].is_string() && st["currentRevision"] != st["updateRevision"];
            if want == 0 && n(&st["replicas"]) == 0 {
                (Tone::Muted, "Scaled to 0".into(), vec![])
            } else if rolling && new < want {
                let by_hand = spec["updateStrategy"]["type"] == "OnDelete";
                (if ready == 0 { Tone::Warning } else { Tone::Info }, format!("{}{new}/{want} pods updated", if by_hand { "" } else { "Rolling out: " }), if by_hand { vec!["Update strategy OnDelete: a pod is updated when it's deleted.".into()] } else { vec![] })
            } else {
                copies(ready, want)
            }
        }
        Kind::DaemonSets => {
            let want = n(&st["desiredNumberScheduled"]);
            let (ready, new) = (n(&st["numberReady"]), n(&st["updatedNumberScheduled"]));
            let mut notes = vec![];
            if n(&st["numberMisscheduled"]) > 0 {
                notes.push(format!("{} misscheduled.", many(n(&st["numberMisscheduled"]), "pod")));
            }
            let mut v = if want == 0 {
                (Tone::Muted, "No matching nodes".to_string(), vec![])
            } else if new < want && spec["updateStrategy"]["type"] != "OnDelete" && ready > 0 {
                (Tone::Info, format!("Rolling out: {new}/{want} nodes updated"), vec![])
            } else if ready >= want {
                (Tone::Success, format!("{ready}/{want} nodes ready"), vec![])
            } else {
                (if ready == 0 { Tone::Danger } else { Tone::Warning }, format!("{ready}/{want} nodes ready"), vec![])
            };
            v.2.extend(notes);
            v
        }
        Kind::ReplicaSets => {
            let want = spec["replicas"].as_i64().unwrap_or(1);
            if want == 0 {
                let kept = o["metadata"]["ownerReferences"][0]["kind"] == "Deployment";
                return (Tone::Muted, if kept { "Old revision, kept for rollback".into() } else { "Scaled to 0".into() }, vec![]);
            }
            if let Some(c) = cond(o, "ReplicaFailure").filter(|c| c["status"] == "True") {
                return (Tone::Danger, "Replica failure: it can't create its pods".into(), msg(c));
            }
            copies(n(&st["readyReplicas"]), want)
        }
        Kind::Jobs => {
            let took = |end: Option<i64>| time_of(&st["startTime"]).and_then(|a| end.map(|b| format!(" in {}", kube::human_duration((b - a).max(0))))).unwrap_or_default();
            if let Some(c) = cond(o, "Failed").filter(|c| c["status"] == "True") {
                (Tone::Danger, "Failed".into(), msg(c))
            } else if cond(o, "Complete").map(|c| c["status"] == "True").unwrap_or(false) {
                (Tone::Success, format!("Complete{}", took(time_of(&st["completionTime"]))), vec![])
            } else if spec["suspend"] == true {
                (Tone::Muted, "Suspended".into(), vec![])
            } else if n(&st["active"]) > 0 {
                let failed = n(&st["failed"]);
                (if failed > 0 { Tone::Warning } else { Tone::Info }, format!("Running{}", time_of(&st["startTime"]).map(|t| format!(" for {}", kube::human_duration((now - t).max(0)))).unwrap_or_default()), if failed > 0 { vec![format!("{} so far.", many(failed, "failed pod"))] } else { vec![] })
            } else {
                (Tone::Warning, "Pending".into(), vec![])
            }
        }
        Kind::CronJobs => {
            let (last, good) = (time_of(&st["lastScheduleTime"]), time_of(&st["lastSuccessfulTime"]));
            let active = st["active"].as_array().map(|a| a.len()).unwrap_or(0);
            if spec["suspend"] == true {
                (Tone::Muted, "Suspended".into(), vec![])
            } else if active > 0 {
                (Tone::Info, "Running now".into(), vec![])
            } else {
                match (last, good) {
                    (None, _) => (Tone::Muted, "Not run yet".into(), vec![]),
                    (Some(l), Some(g)) if g >= l => (Tone::Success, "Last run succeeded".into(), vec![]),
                    (Some(_), Some(g)) => (Tone::Warning, "Last run did not succeed".into(), vec![format!("Last success {} ago.", kube::human_duration((now - g).max(0)))]),
                    (Some(_), None) => (Tone::Warning, "No run has succeeded yet".into(), vec![]),
                }
            }
        }
        Kind::PersistentVolumeClaims => match st["phase"].as_str().unwrap_or("") {
            "Bound" => (Tone::Success, "Bound".into(), vec![]),
            "Lost" => (Tone::Danger, "Lost: its volume is gone".into(), vec![]),
            "Pending" => (Tone::Warning, "Pending: waiting for a volume".into(), vec![]),
            x => (Tone::Warning, x.to_string(), vec![]),
        },
        Kind::PersistentVolumes => match st["phase"].as_str().unwrap_or("") {
            "Bound" => (Tone::Success, "Bound".into(), vec![]),
            "Available" => (Tone::Info, "Available".into(), vec![]),
            "Released" => (Tone::Warning, "Released: its claim is gone, the data is still there".into(), vec![]),
            "Failed" => (Tone::Danger, "Failed".into(), msg(st)),
            x => (Tone::Warning, x.to_string(), vec![]),
        },
        Kind::Namespaces => match st["phase"].as_str().unwrap_or("Active") {
            "Terminating" => (Tone::Warning, "Terminating".into(), st["conditions"].as_array().into_iter().flatten().filter(|c| c["status"] == "True").flat_map(msg).collect()),
            _ => (Tone::Success, "Active".into(), vec![]),
        },
        Kind::Nodes => {
            let mut bad = vec![];
            for c in st["conditions"].as_array().into_iter().flatten() {
                if good_when_true(c["type"].as_str().unwrap_or("")) == Some(false) && c["status"] == "True" {
                    bad.push(format!("{}: {}", spaced(c["type"].as_str().unwrap_or("")), c["message"].as_str().unwrap_or("")));
                }
            }
            let ready = cond(o, "Ready");
            if ready.map(|c| c["status"] != "True").unwrap_or(true) {
                (Tone::Danger, "Not ready".into(), ready.map(msg).unwrap_or_default().into_iter().chain(bad).collect())
            } else if !bad.is_empty() {
                (Tone::Warning, "Ready, but under pressure".into(), bad)
            } else if spec["unschedulable"] == true {
                (Tone::Warning, "Ready, scheduling disabled".into(), vec!["Cordoned: running pods stay, new pods go elsewhere.".into()])
            } else {
                (Tone::Success, "Ready".into(), vec![])
            }
        }
        Kind::HorizontalPodAutoscalers => {
            let (cur, max, min) = (n(&st["currentReplicas"]), n(&spec["maxReplicas"]), spec["minReplicas"].as_i64().unwrap_or(1));
            if let Some(c) = cond(o, "ScalingActive").filter(|c| c["status"] == "False") {
                if c["reason"] == "ScalingDisabled" {
                    return (Tone::Muted, "Scaling disabled: target at 0 replicas".into(), vec![]);
                }
                return (Tone::Danger, "Can't read its metrics".into(), msg(c));
            }
            if let Some(c) = cond(o, "AbleToScale").filter(|c| c["status"] == "False") {
                return (Tone::Warning, "Not able to scale".into(), msg(c));
            }
            if max > 0 && cur >= max && max > min && cond(o, "ScalingLimited").map(|c| c["status"] == "True").unwrap_or(false) {
                return (Tone::Warning, format!("At max replicas ({max})"), vec!["The metrics ask for more replicas than the maximum.".into()]);
            }
            (Tone::Success, many(cur, "replica"), vec![])
        }
        Kind::PodDisruptionBudgets => {
            let (ok, want, all, may) = (n(&st["currentHealthy"]), n(&st["desiredHealthy"]), n(&st["expectedPods"]), n(&st["disruptionsAllowed"]));
            if all == 0 {
                (Tone::Muted, "Selects no pods".into(), vec![])
            } else if ok < want {
                (Tone::Danger, format!("Too few healthy pods: {ok} of {want} required"), vec![])
            } else if may == 0 {
                (Tone::Warning, "No disruptions allowed".into(), vec!["A node drain that hits one of its pods waits until this changes.".into()])
            } else {
                (Tone::Success, format!("{} allowed", many(may, "disruption")), vec![])
            }
        }
        Kind::ResourceQuotas => {
            let l = quota(o);
            let full: Vec<&str> = l.iter().filter(|x| x.2 > 0.0 && x.1 >= x.2).map(|x| x.0.as_str()).collect();
            let near: Vec<&str> = l.iter().filter(|x| x.2 > 0.0 && x.1 < x.2 && x.1 / x.2 >= 0.85).map(|x| x.0.as_str()).collect();
            if l.is_empty() {
                (Tone::Muted, "No hard limits".into(), vec![])
            } else if l.iter().all(|x| x.2 == 0.0) {
                (Tone::Muted, "All limits are 0: nothing may be created".into(), vec![])
            } else if !full.is_empty() {
                (Tone::Danger, format!("Quota reached: {}", full.join(", ")), vec![])
            } else if !near.is_empty() {
                (Tone::Warning, format!("Near quota: {}", near.join(", ")), vec![])
            } else {
                (Tone::Success, "Within quota".into(), vec![])
            }
        }
        Kind::CustomResourceDefinitions => {
            if cond(o, "Established").map(|c| c["status"] == "True").unwrap_or(false) {
                (Tone::Success, "Established".into(), vec![])
            } else {
                (Tone::Danger, "Not established".into(), st["conditions"].as_array().into_iter().flatten().filter(|c| c["status"] == "False").flat_map(msg).collect())
            }
        }
        Kind::CertificateSigningRequests => {
            let has = |t: &str| cond(o, t).is_some();
            if has("Denied") {
                (Tone::Danger, "Denied".into(), cond(o, "Denied").map(msg).unwrap_or_default())
            } else if has("Failed") {
                (Tone::Danger, "Failed".into(), cond(o, "Failed").map(msg).unwrap_or_default())
            } else if has("Approved") {
                (Tone::Success, if st["certificate"].is_string() { "Approved, issued".into() } else { "Approved, not issued yet".into() }, vec![])
            } else {
                (Tone::Warning, "Pending approval".into(), vec![])
            }
        }
        Kind::VolumeAttachments => {
            let err = |k: &str| st[k]["message"].as_str().map(|m| vec![truncate(m, 300)]);
            if let Some(m) = err("attachError") {
                (Tone::Danger, "Attach error".into(), m)
            } else if let Some(m) = err("detachError") {
                (Tone::Danger, "Detach error".into(), m)
            } else if st["attached"] == true {
                (Tone::Success, "Attached".into(), vec![])
            } else {
                (Tone::Warning, "Not attached".into(), vec![])
            }
        }
        Kind::Leases => {
            let renewed = time_of(&spec["renewTime"]);
            let holder = s(&spec["holderIdentity"]);
            let dur = spec["leaseDurationSeconds"].as_i64().unwrap_or(15);
            match renewed {
                _ if holder.is_empty() => (Tone::Muted, "No holder".into(), vec![]),
                Some(t) if now - t > dur * 3 => (Tone::Muted, format!("Not renewed for {}", kube::human_duration(now - t)), vec!["Its holder has likely gone.".into()]),
                Some(_) => (Tone::Success, "Held".into(), vec![]),
                None => (Tone::Muted, "Held, never renewed".into(), vec![]),
            }
        }
        Kind::Events => {
            let t = o["type"].as_str().unwrap_or("");
            (if t == "Warning" { Tone::Warning } else { Tone::Info }, spaced(o["reason"].as_str().unwrap_or("Event")), o["message"].as_str().map(|m| vec![truncate(m, 600)]).unwrap_or_default())
        }
        _ => generic(o),
    }
}

/// Anything else, by its conditions or the state it gives.
pub(super) fn generic(o: &Value) -> Verdict {
    for t in ["Ready", "Available", "Healthy", "Established", "Succeeded", "Synced"] {
        if let Some(c) = cond(o, t) {
            return match c["status"].as_str() {
                Some("True") => (Tone::Success, spaced(t), vec![]),
                Some("Unknown") => (Tone::Warning, format!("{}: not known yet", spaced(t)), msg(c)),
                _ => (Tone::Warning, format!("Not {}", spaced(t).to_lowercase()), msg(c)),
            };
        }
    }
    let st = &o["status"];
    let word = [&st["health"]["status"], &st["health"], &st["phase"], &st["state"], &st["status"]].iter().find_map(|v| v.as_str()).unwrap_or("");
    let tone = match word.to_lowercase().as_str() {
        "" => Tone::Muted,
        "healthy" | "ready" | "running" | "active" | "bound" | "green" | "succeeded" | "complete" | "completed" | "available" | "ok" | "health_ok" | "deployed" => Tone::Success,
        "degraded" | "failed" | "error" | "red" | "missing" | "health_err" => Tone::Danger,
        "progressing" | "pending" | "creating" | "updating" | "reconciling" => Tone::Info,
        x if x.contains("fail") || x.contains("error") => Tone::Danger,
        x if x.contains("healthy") && !x.contains("unhealthy") => Tone::Success,
        // A state Kubedog doesn't know says nothing about how it is.
        _ => Tone::Muted,
    };
    let why = [&st["health"]["message"], &st["message"], &st["reason"]].iter().find_map(|v| v.as_str()).filter(|m| !m.is_empty() && matches!(tone, Tone::Danger | Tone::Warning)).map(|m| truncate(m, 300));
    (tone, spaced(word), why.into_iter().collect())
}

/// A quota's lines: (what, used, allowed).
pub(super) fn quota(o: &Value) -> Vec<(String, f64, f64)> {
    let hard = if o["status"]["hard"].is_object() { &o["status"]["hard"] } else { &o["spec"]["hard"] };
    hard.as_object()
        .into_iter()
        .flatten()
        .map(|(k, v)| {
            let q = |v: &Value| v.as_str().map(|t| amount(k, t)).unwrap_or(0.0);
            (k.clone(), q(&o["status"]["used"][k]), q(v))
        })
        .collect()
}

fn is_bytes(what: &str) -> bool {
    what.contains("memory") || what.contains("storage")
}

fn amount(what: &str, t: &str) -> f64 {
    if is_bytes(what) {
        resources::mem_bytes(t)
    } else if what.contains("cpu") {
        resources::cpu_milli(t)
    } else {
        t.parse().unwrap_or_else(|_| resources::cpu_milli(t) / 1000.0)
    }
}

pub(super) fn amount_words(what: &str, v: f64) -> String {
    if is_bytes(what) {
        gib(v)
    } else if what.contains("cpu") {
        hive::cores(v)
    } else {
        format!("{v:.0}")
    }
}

/// A schedule in words, or as it's written.
pub(super) fn cron_words(c: &str) -> String {
    let c = c.trim();
    let named = match c {
        "@hourly" => "every hour",
        "@daily" | "@midnight" => "every day at 00:00",
        "@weekly" => "every Sunday at 00:00",
        "@monthly" => "on day 1 of every month at 00:00",
        "@yearly" | "@annually" => "every year on 1 January at 00:00",
        _ => "",
    };
    if !named.is_empty() {
        return named.into();
    }
    let f: Vec<&str> = c.split_whitespace().collect();
    let raw = || format!("on the schedule {c}");
    if f.len() != 5 {
        return raw();
    }
    let num = |t: &str, max: u32| t.parse::<u32>().ok().filter(|n| *n <= max);
    let step = |t: &str| t.strip_prefix("*/").and_then(|n| n.parse::<u32>().ok());
    let days_any = f[2] == "*" && f[3] == "*" && f[4] == "*";
    if days_any && f[1] == "*" {
        return match (f[0], step(f[0]), num(f[0], 59)) {
            ("*", _, _) | (_, Some(1), _) => "every minute".into(),
            (_, Some(n), _) if n < 60 && 60 % n == 0 => format!("every {n} minutes"),
            (_, _, Some(m)) => format!("every hour at :{m:02}"),
            _ => raw(),
        };
    }
    let Some(m) = num(f[0], 59) else { return raw() };
    if let (true, Some(n)) = (days_any, step(f[1])) {
        return if n == 1 { format!("every hour at :{m:02}") } else if n < 24 && 24 % n == 0 { format!("every {n} hours at :{m:02}") } else { raw() };
    }
    let hours: Option<Vec<u32>> = f[1].split(',').map(|h| num(h, 23)).collect();
    let Some(hours) = hours else { return raw() };
    let at = hours.iter().map(|h| format!("{h:02}:{m:02}")).collect::<Vec<_>>().join(" and ");
    if days_any {
        return format!("every day at {at}");
    }
    const DAYS: [&str; 8] = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
    const MONTHS: [&str; 12] = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
    let day = |t: &str| num(t, 7).map(|n| DAYS[n as usize]).or_else(|| DAYS.iter().find(|d| d[..3].eq_ignore_ascii_case(t)).copied());
    if f[2] == "*" && f[3] == "*" {
        if f[4] == "1-5" || f[4].eq_ignore_ascii_case("mon-fri") {
            return format!("on weekdays at {at}");
        }
        if let Some((a, b)) = f[4].split_once('-') {
            return match (day(a), day(b)) {
                (Some(a), Some(b)) => format!("{a} to {b} at {at}"),
                _ => raw(),
            };
        }
        let d: Option<Vec<&str>> = f[4].split(',').map(day).collect();
        return d.map(|d| format!("every {} at {at}", d.join(" and "))).unwrap_or_else(raw);
    }
    match (num(f[2], 31), f[3], num(f[3], 12), f[4]) {
        (Some(d), "*", _, "*") => format!("on day {d} of every month at {at}"),
        (Some(d), _, Some(mo), "*") if mo > 0 => format!("every year on {d} {} at {at}", MONTHS[mo as usize - 1]),
        _ => raw(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn three_columns() {
        let sum = |c: [f32; 3]| c.iter().sum::<f32>();
        // Short references and labels: no wide gaps, the annotations get the room.
        assert_eq!(three(1800.0, 300.0, 250.0, 2000.0), [300.0, 250.0, 1250.0]);
        // Long labels take more when the annotations are short.
        let c = three(1800.0, 300.0, 900.0, 200.0);
        assert!(c[1] == 900.0 && sum(c) == 1800.0);
        // Everything long: each gets a share.
        let c = three(1000.0, 900.0, 900.0, 900.0);
        assert!(c[0] <= 300.0 && c[1] <= 360.0 && c[2] >= 330.0 && (sum(c) - 1000.0).abs() < 0.1);
        // Nothing in them: still columns.
        assert!(three(900.0, 0.0, 0.0, 0.0).iter().all(|w| *w >= 150.0));
    }

    #[test]
    fn workloads_well_and_unwell() {
        let v = |k: Kind, o: Value| {
            let x = verdict(k, &o, 1000);
            (x.0, x.1)
        };
        let dep = |want: i64, st: Value| json!({"metadata": {"generation": 2}, "spec": {"replicas": want}, "status": st});
        assert_eq!(v(Kind::Deployments, dep(3, json!({"observedGeneration": 2, "replicas": 3, "readyReplicas": 3, "updatedReplicas": 3}))), (Tone::Success, "3/3 pods ready".into()));
        assert_eq!(v(Kind::Deployments, dep(0, json!({"observedGeneration": 2}))).0, Tone::Muted);
        assert_eq!(v(Kind::Deployments, dep(3, json!({"observedGeneration": 2, "replicas": 4, "readyReplicas": 3, "updatedReplicas": 2}))), (Tone::Info, "Rolling out: 2/3 pods updated".into()));
        assert_eq!(v(Kind::Deployments, dep(2, json!({"observedGeneration": 2, "replicas": 2, "updatedReplicas": 2}))).0, Tone::Danger);
        assert_eq!(v(Kind::Deployments, dep(2, json!({"observedGeneration": 2, "replicas": 2, "updatedReplicas": 2, "conditions": [{"type": "Progressing", "status": "False", "message": "too long"}]}))).1, "Rollout stuck: progress deadline exceeded");
        assert_eq!(v(Kind::StatefulSets, json!({"spec": {"replicas": 3}, "status": {"readyReplicas": 2, "replicas": 3}})), (Tone::Warning, "2/3 pods ready".into()));
        assert_eq!(v(Kind::DaemonSets, json!({"spec": {}, "status": {"desiredNumberScheduled": 0}})).0, Tone::Muted);
        assert_eq!(v(Kind::ReplicaSets, json!({"metadata": {"ownerReferences": [{"kind": "Deployment"}]}, "spec": {"replicas": 0}})).1, "Old revision, kept for rollback");
        assert_eq!(v(Kind::CronJobs, json!({"spec": {"suspend": true}})).0, Tone::Muted);
        let cron = |l: &str, g: &str| json!({"spec": {}, "status": {"lastScheduleTime": l, "lastSuccessfulTime": g}});
        assert_eq!(v(Kind::CronJobs, cron("2026-01-02T00:00:00Z", "2026-01-02T00:01:00Z")).0, Tone::Success);
        assert_eq!(v(Kind::CronJobs, cron("2026-01-02T00:00:00Z", "2026-01-01T00:01:00Z")).0, Tone::Warning);
        assert_eq!(v(Kind::Jobs, json!({"status": {"conditions": [{"type": "Complete", "status": "True"}], "startTime": "2026-01-02T00:00:00Z", "completionTime": "2026-01-02T00:00:42Z"}})), (Tone::Success, "Complete in 42s".into()));
        assert_eq!(v(Kind::Deployments, json!({"metadata": {"deletionTimestamp": "2026-01-02T00:00:00Z"}})).0, Tone::Warning);
    }

    #[test]
    fn others_well_and_unwell() {
        let v = |k: Kind, o: Value| verdict(k, &o, 1000).0;
        assert_eq!(v(Kind::PersistentVolumeClaims, json!({"status": {"phase": "Pending"}})), Tone::Warning);
        assert_eq!(v(Kind::PodDisruptionBudgets, json!({"status": {"expectedPods": 2, "currentHealthy": 2, "desiredHealthy": 2, "disruptionsAllowed": 0}})), Tone::Warning);
        assert_eq!(v(Kind::PodDisruptionBudgets, json!({"status": {"expectedPods": 0}})), Tone::Muted);
        assert_eq!(v(Kind::HorizontalPodAutoscalers, json!({"spec": {"maxReplicas": 5}, "status": {"currentReplicas": 0, "conditions": [{"type": "ScalingActive", "status": "False", "reason": "ScalingDisabled"}]}})), Tone::Muted);
        assert_eq!(v(Kind::HorizontalPodAutoscalers, json!({"spec": {"maxReplicas": 5}, "status": {"currentReplicas": 5, "conditions": [{"type": "ScalingLimited", "status": "True"}]}})), Tone::Warning);
        let q = |used: &str, hard: &str| json!({"spec": {}, "status": {"hard": {"limits.memory": hard}, "used": {"limits.memory": used}}});
        assert_eq!(v(Kind::ResourceQuotas, q("1Gi", "4Gi")), Tone::Success);
        assert_eq!(v(Kind::ResourceQuotas, q("3700Mi", "4Gi")), Tone::Warning);
        assert_eq!(v(Kind::ResourceQuotas, q("4Gi", "4Gi")), Tone::Danger);
        assert_eq!(v(Kind::ResourceQuotas, q("0", "0")), Tone::Muted);
        assert_eq!(v(Kind::Nodes, json!({"status": {"conditions": [{"type": "Ready", "status": "True"}, {"type": "DiskPressure", "status": "True"}]}})), Tone::Warning);
        assert_eq!(v(Kind::Nodes, json!({"status": {"conditions": [{"type": "Ready", "status": "Unknown"}]}})), Tone::Danger);
        assert_eq!(v(Kind::CertificateSigningRequests, json!({"status": {}})), Tone::Warning);
        assert_eq!(v(Kind::ConfigMaps, json!({})), Tone::Muted);
        assert_eq!(generic(&json!({"status": {"health": {"status": "Degraded", "message": "why"}}})), (Tone::Danger, "Degraded".into(), vec!["why".into()]));
        assert_eq!(generic(&json!({"status": {"phase": "Cluster in healthy state"}})).0, Tone::Success);
    }

    #[test]
    fn schedules_and_words() {
        for (c, w) in [
            ("*/5 * * * *", "every 5 minutes"),
            ("17 6 * * 1", "every Monday at 06:17"),
            ("0 0 * * *", "every day at 00:00"),
            ("30 2,14 * * *", "every day at 02:30 and 14:30"),
            ("0 8 * * 1-5", "on weekdays at 08:00"),
            ("5 */6 * * *", "every 6 hours at :05"),
            ("0 3 1 * *", "on day 1 of every month at 03:00"),
            ("@daily", "every day at 00:00"),
            ("0 0 1-7 * 1", "on the schedule 0 0 1-7 * 1"),
            ("7-59/10 * * * *", "on the schedule 7-59/10 * * * *"),
        ] {
            assert_eq!(cron_words(c), w);
        }
        assert_eq!(spaced("ReplicaFailure"), "Replica failure");
        assert_eq!(spaced("CSIDriverReady"), "CSI driver ready");
        assert_eq!(good_when_true("MemoryPressure"), Some(false));
        assert_eq!(good_when_true("Available"), Some(true));
        assert_eq!(good_when_true("ScalingLimited"), None);
    }
}
