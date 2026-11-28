//! Which columns a list shows and in what order, and the menu that changes it: one list of rows,
//! each with a drag handle and a tick box. Hidden columns keep their place in the list.

use super::*;

/// A change to a list's columns, from a table header or the column menu.
pub(super) enum ColAction {
    /// A header started being dragged.
    DragStart(String),
    /// Put the first column next to the second (after it when true).
    Place(String, String, bool),
    /// Move a column to this place in the menu's list.
    MoveTo(String, usize),
    Hide(String),
    Show(String),
    /// "Hide empty columns" was ticked or unticked (the caller's setting already changed).
    HideEmptyChanged,
    Reset,
}

/// Columns that can be moved but not hidden.
pub(super) fn is_fixed(name: &str) -> bool {
    matches!(name, "Context" | "Namespace" | "Name")
}

/// Every column of a kind in its standard order: the fixed ones, the usual ones with the request
/// and limit columns beside the usage they belong to, the extra ones, and Age at the end.
pub(super) fn default_order(kind: Kind) -> Vec<&'static str> {
    // Pods have an order of their own: how long it runs and how often it restarted sit next to its state.
    if kind == Kind::Pods {
        return PODS.to_vec();
    }
    let mut v: Vec<&'static str> = vec!["Context"];
    if kind.namespaced() {
        v.push("Namespace");
    }
    if kind.shows_name() {
        v.push("Name");
    }
    let usual = kind.columns();
    let ends_with_age = usual.last() == Some(&"Age");
    let extras: Vec<&'static str> = kind.extra_columns().to_vec();
    let beside = |c: &str| c.ends_with("Requests") || c.ends_with("Limits");
    let body = if ends_with_age { &usual[..usual.len() - 1] } else { usual };
    for c in body {
        v.push(c);
        if *c == "Memory Usage" {
            v.extend(extras.iter().filter(|e| beside(e)));
        }
    }
    v.extend(extras.iter().filter(|e| !v.contains(e)).copied().collect::<Vec<_>>());
    if ends_with_age {
        v.push("Age");
    }
    v
}

/// The list of pods, every column in its standard order.
const PODS: [&str; 26] = [
    "Context", "Namespace", "Name", "Ready", "Status", "Age", "Restarts", "CPU Usage", "Memory Usage", "CPU Requests", "CPU Limits", "Memory Requests", "Memory Limits", "Last Restart",
    "Last Restart Reason", "Node", "Controller", "Pod IP", "Containers", "Images", "QoS Class", "Service Account", "Host IP", "Priority Class", "Labels", "Created",
];

/// The columns shown until someone chooses their own (besides the fixed ones).
pub(super) fn default_shown(kind: Kind) -> Vec<&'static str> {
    kind.columns().iter().copied().filter(|c| !(kind == Kind::Pods && *c == "Pod IP")).collect()
}

/// Whether a column that can be hidden is shown: by the saved choice; else, where only an order was saved (by a
/// version in which every usual column was the standard), all the usual ones; else the standard ones.
pub(super) fn shown_by(kind: Kind, saved: Option<&Vec<String>>, order_saved: bool, name: &str) -> bool {
    match saved {
        Some(s) if s.iter().any(|c| kind.all_columns().contains(&c.as_str())) => s.iter().any(|c| c == name),
        _ if order_saved => kind.columns().contains(&name),
        _ => default_shown(kind).contains(&name),
    }
}

/// The saved order with unknown names dropped and missing ones put where they'd normally be.
pub(super) fn full_order(kind: Kind, saved: Option<&Vec<String>>, shown: Option<&Vec<String>>) -> Vec<&'static str> {
    let base = default_order(kind);
    let mut out: Vec<&'static str> = vec![];
    let start: Vec<&String> = match (saved, shown) {
        (Some(s), _) => s.iter().collect(),
        // From before the order was kept: the fixed columns first, then the shown ones in their order.
        (None, Some(s)) => {
            out.extend(base.iter().filter(|c| is_fixed(c)));
            s.iter().collect()
        }
        _ => return base,
    };
    for n in start {
        if let Some(c) = base.iter().find(|c| *c == n) {
            if !out.contains(c) {
                out.push(c);
            }
        }
    }
    for (i, c) in base.iter().enumerate() {
        if out.contains(c) {
            continue;
        }
        // After the nearest column that normally comes before it.
        let at = base[..i].iter().rev().find_map(|p| out.iter().position(|x| x == p)).map(|p| p + 1).unwrap_or(0);
        out.insert(at, c);
    }
    out
}

/// `list` with `name` moved so that it ends up at `to` (counted in the result).
pub(super) fn moved<T: PartialEq + Copy>(list: &[T], name: T, to: usize) -> Vec<T> {
    let mut v: Vec<T> = list.iter().copied().filter(|x| *x != name).collect();
    if v.len() == list.len() {
        return v;
    }
    v.insert(to.min(v.len()), name);
    v
}

impl KubedogApp {
    /// Every column of a list in its order, hidden ones included.
    pub(super) fn column_order(&self, kind: Kind) -> Vec<&'static str> {
        let k = format!("{kind:?}");
        full_order(kind, self.prefs.column_order.get(&k), self.prefs.columns.get(&k))
    }

    /// Whether a column is shown (Context only appears with several clusters open).
    pub(super) fn column_on(&self, kind: Kind, name: &str) -> bool {
        if is_fixed(name) {
            return true;
        }
        let k = format!("{kind:?}");
        shown_by(kind, self.prefs.columns.get(&k), self.prefs.column_order.contains_key(&k), name)
    }

    /// The columns a list shows, in order.
    pub(super) fn column_layout(&self, kind: Kind) -> Vec<&'static str> {
        self.column_order(kind).into_iter().filter(|c| self.column_on(kind, c)).collect()
    }

    /// Whether the columns differ from the standard ones.
    pub(super) fn columns_changed(&self, kind: Kind) -> bool {
        let k = format!("{kind:?}");
        self.prefs.columns.contains_key(&k) || self.prefs.column_order.contains_key(&k)
    }

    pub(super) fn apply_column_action(&mut self, kind: Kind, a: ColAction) {
        let key = format!("{kind:?}");
        let mut order = self.column_order(kind);
        let mut shown: Vec<&'static str> = order.iter().copied().filter(|c| !is_fixed(c) && self.column_on(kind, c)).collect();
        match a {
            ColAction::DragStart(h) => {
                self.col_drag = Some(h);
                return;
            }
            ColAction::Place(from, to, after) => {
                self.col_drag = None;
                let (Some(f), Some(t)) = (order.iter().find(|c| **c == from).copied(), order.iter().find(|c| **c == to).copied()) else { return };
                if f == t {
                    return;
                }
                order.retain(|c| *c != f);
                let at = order.iter().position(|c| *c == t).map(|i| if after { i + 1 } else { i }).unwrap_or(order.len());
                order.insert(at, f);
            }
            ColAction::MoveTo(name, to) => {
                let Some(n) = order.iter().find(|c| **c == name).copied() else { return };
                order = moved(&order, n, to);
            }
            ColAction::Hide(h) => {
                // Keep at least one column besides the fixed ones.
                if shown.len() > 1 {
                    shown.retain(|c| *c != h);
                }
            }
            ColAction::Show(h) => {
                if let Some(c) = order.iter().find(|c| **c == h).copied() {
                    if !shown.contains(&c) {
                        shown.push(c);
                    }
                }
            }
            ColAction::HideEmptyChanged => {
                self.save();
                return;
            }
            ColAction::Reset => {
                self.prefs.columns.remove(&key);
                self.prefs.column_order.remove(&key);
                self.save();
                return;
            }
        }
        let names = |v: &[&str]| v.iter().map(|c| c.to_string()).collect::<Vec<_>>();
        if order == default_order(kind) {
            self.prefs.column_order.remove(&key);
        } else {
            self.prefs.column_order.insert(key.clone(), names(&order));
        }
        let usual = default_shown(kind);
        // Left out only when nothing at all was changed: an order kept without them means "as it was before the
        // standard columns changed" (see `shown_by`).
        if shown.len() == usual.len() && shown.iter().all(|c| usual.contains(c)) && order == default_order(kind) {
            self.prefs.columns.remove(&key);
        } else {
            let shown: Vec<&str> = order.iter().copied().filter(|c| shown.contains(c)).collect();
            self.prefs.columns.insert(key, names(&shown));
        }
        self.save();
    }
}

fn row_h() -> f32 {
    u(27.0)
}

/// What's being dragged in the menu: the column, and where in its row it was grabbed.
#[derive(Clone)]
struct MenuDrag(&'static str, f32);

/// The column menu: drag a row to move its column, click it to show or hide it.
pub(super) fn column_menu(ui: &mut Ui, order: &[&'static str], on: impl Fn(&str) -> bool, changed: bool, hide_empty: &mut bool) -> Option<ColAction> {
    let mut act = None;
    ui.set_width(u(270.0));
    let drag_id = egui::Id::new("column-menu-drag");
    let drag: Option<MenuDrag> = ui.data(|d| d.get_temp(drag_id));
    // Room for the list: what's left of the window, so a short window scrolls it.
    let max_h = (ui.ctx().content_rect().height() - 190.0).max(120.0);
    let full_h = order.len() as f32 * row_h();
    egui::ScrollArea::vertical().max_height(max_h).min_scrolled_height(max_h.min(full_h)).auto_shrink([false, true]).show(ui, |ui| {
        let (area, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), full_h), Sense::hover());
        let pointer = ui.ctx().pointer_latest_pos();
        let last_one = order.iter().filter(|c| !is_fixed(c) && on(c)).count() <= 1;
        // While dragging, the list already shows where the column would land.
        let target = drag.as_ref().zip(pointer).map(|(d, p)| {
            let top = p.y - d.1;
            (((top - area.top()) / row_h()).round().max(0.0) as usize).min(order.len() - 1)
        });
        let preview: Vec<&'static str> = match (&drag, target) {
            (Some(d), Some(t)) => moved(order, d.0, t),
            _ => order.to_vec(),
        };
        let place = |i: usize| area.top() + i as f32 * row_h();
        let mut floating: Option<(&'static str, egui::Rect)> = None;
        for (i, name) in preview.iter().copied().enumerate() {
            let held = drag.as_ref().map(|d| d.0 == name).unwrap_or(false);
            let id = egui::Id::new(("column-menu-row", name));
            // The other rows slide out of the way.
            let y = if drag.is_some() {
                ui.ctx().animate_value_with_time(id.with("y"), place(i) - area.top(), 0.12)
            } else {
                ui.ctx().animate_value_with_time(id.with("y"), place(i) - area.top(), 0.0)
            } + area.top();
            let mut rect = egui::Rect::from_min_size(egui::pos2(area.left(), y), egui::vec2(area.width(), row_h()));
            if held {
                if let (Some(d), Some(p)) = (&drag, pointer) {
                    rect = egui::Rect::from_min_size(egui::pos2(area.left(), p.y - d.1), rect.size());
                }
            }
            let resp = ui.interact(rect, id, Sense::click_and_drag());
            if resp.drag_started() {
                let at = resp.interact_pointer_pos().unwrap_or(rect.center());
                let grab = ui.input(|i| i.pointer.press_origin()).unwrap_or(at);
                ui.data_mut(|d| d.insert_temp(drag_id, MenuDrag(name, (grab.y - rect.top()).clamp(0.0, row_h()))));
            }
            if resp.clicked() && !is_fixed(name) {
                let showing = on(name);
                if !(showing && last_one) {
                    act = Some(if showing { ColAction::Hide(name.to_string()) } else { ColAction::Show(name.to_string()) });
                }
            }
            if held {
                floating = Some((name, rect));
                // The gap it would drop into.
                let gap = egui::Rect::from_min_size(egui::pos2(area.left(), place(i)), rect.size()).shrink2(egui::vec2(2.0, 2.0));
                ui.painter().rect_stroke(gap, CornerRadius::same(5), Stroke::new(1.0, PRIMARY_TEXT().gamma_multiply(0.6)), egui::StrokeKind::Inside);
            } else {
                menu_row(ui.painter(), rect, name, on(name), is_fixed(name), resp.hovered() && drag.is_none(), false);
                if resp.hovered() && drag.is_none() {
                    let over_handle = pointer.map(|p| p.x < rect.left() + 22.0).unwrap_or(false);
                    ui.ctx().set_cursor_icon(if over_handle || is_fixed(name) { egui::CursorIcon::Grab } else { egui::CursorIcon::PointingHand });
                }
            }
        }
        // The held row floats over the others.
        if let Some((name, rect)) = floating {
            menu_row(ui.painter(), rect, name, on(name), is_fixed(name), false, true);
            ui.ctx().set_cursor_icon(egui::CursorIcon::Grabbing);
            ui.ctx().request_repaint();
            // Near the edge of a scrolled list, scroll on.
            if let Some(p) = pointer {
                let clip = ui.clip_rect();
                if p.y < clip.top() + 24.0 {
                    ui.scroll_with_delta(egui::vec2(0.0, 6.0));
                } else if p.y > clip.bottom() - 24.0 {
                    ui.scroll_with_delta(egui::vec2(0.0, -6.0));
                }
            }
        }
        if let Some(d) = &drag {
            if ui.input(|i| i.pointer.any_released() || !i.pointer.any_down()) {
                ui.data_mut(|m| m.remove::<MenuDrag>(drag_id));
                if preview.as_slice() != order {
                    if let Some(t) = target {
                        act = Some(ColAction::MoveTo(d.0.to_string(), t));
                    }
                }
            }
        }
    });
    ui.add_space(2.0);
    ui.separator();
    if ui.checkbox(hide_empty, "Hide columns that are empty").on_hover_text("Leave out columns with nothing in any row").changed() {
        act = Some(ColAction::HideEmptyChanged);
    }
    if ui.add_enabled(changed, egui::Button::new(RichText::new("⟲  Reset to default").color(if changed { TEXT_DEFAULT() } else { TEXT_PLACEHOLDER() })).frame(false)).clicked() {
        act = Some(ColAction::Reset);
    }
    act
}

/// One row of the menu: six dots to grab, a tick box (not for fixed columns), the name.
fn menu_row(p: &egui::Painter, r: egui::Rect, name: &str, on: bool, fixed: bool, hover: bool, held: bool) {
    if held {
        p.rect_filled(r.expand2(egui::vec2(0.0, 1.0)), CornerRadius::same(6), BG_STRONG());
        p.rect_stroke(r.expand2(egui::vec2(0.0, 1.0)), CornerRadius::same(6), Stroke::new(1.0, PRIMARY_TEXT()), egui::StrokeKind::Inside);
    } else if hover {
        p.rect_filled(r, CornerRadius::same(5), BG_HOVER());
    }
    let dots = if hover || held { TEXT_MUTED() } else { TEXT_PLACEHOLDER() };
    for (dx, dy) in [(0.0, -4.5), (0.0, 0.0), (0.0, 4.5), (4.5, -4.5), (4.5, 0.0), (4.5, 4.5)] {
        p.circle_filled(egui::pos2(r.left() + 8.0 + dx, r.center().y + dy), 1.1, dots);
    }
    if !fixed {
        let b = egui::Rect::from_center_size(egui::pos2(r.left() + 33.0, r.center().y), egui::vec2(15.0, 15.0));
        if on {
            p.rect_filled(b, CornerRadius::same(4), PRIMARY());
            let s = Stroke::new(1.8, Color32::WHITE);
            p.line_segment([b.min + egui::vec2(3.4, 7.8), b.min + egui::vec2(6.3, 10.6)], s);
            p.line_segment([b.min + egui::vec2(6.3, 10.6), b.min + egui::vec2(11.6, 4.6)], s);
        } else {
            p.rect_stroke(b, CornerRadius::same(4), Stroke::new(1.2, TEXT_PLACEHOLDER()), egui::StrokeKind::Inside);
        }
    }
    let col = if on { TEXT_DEFAULT() } else { TEXT_SUBTLE() };
    p.text(egui::pos2(r.left() + 48.0, r.center().y), egui::Align2::LEFT_CENTER, name, FontId::proportional(z(13.5)), col);
}

// ---------------- the icons at the top right ----------------

/// A square icon button for the top bar; `on` keeps it lit.
pub(super) fn top_icon(ui: &mut Ui, on: bool, draw: impl FnOnce(&egui::Painter, egui::Pos2, Color32)) -> egui::Response {
    let (r, resp) = ui.allocate_exact_size(egui::vec2(32.0, 30.0), Sense::click());
    let hot = resp.hovered();
    let p = ui.painter();
    if on {
        p.rect_filled(r, CornerRadius::same(7), PRIMARY_TEXT().gamma_multiply(0.16));
    } else if hot {
        p.rect_filled(r, CornerRadius::same(7), BG_MUTED());
    }
    if hot {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    draw(p, r.center(), if on { PRIMARY_TEXT() } else if hot { TEXT_DEFAULT() } else { TEXT_SUBTLE() });
    resp
}

/// Sliders: three lines, each with a knob.
pub(super) fn draw_sliders(p: &egui::Painter, c: egui::Pos2, col: Color32) {
    let s = Stroke::new(1.5, col);
    for (dy, knob) in [(-6.2f32, 4.0f32), (0.0, -4.0), (6.2, 2.0)] {
        let y = c.y + dy;
        p.line_segment([egui::pos2(c.x - 9.0, y), egui::pos2(c.x + knob - 2.1, y)], s);
        p.line_segment([egui::pos2(c.x + knob + 2.1, y), egui::pos2(c.x + 9.0, y)], s);
        p.circle_stroke(egui::pos2(c.x + knob, y), 2.0, s);
    }
}

/// Refresh: an open circle ending in an arrowhead.
pub(super) fn draw_refresh(p: &egui::Painter, c: egui::Pos2, col: Color32) {
    let r = 7.2;
    let (from, to) = (-0.30f32, 5.05f32);
    let at = |a: f32| c + egui::vec2(a.cos(), a.sin()) * r;
    p.add(egui::Shape::line((0..=40).map(|i| at(from + (to - from) * i as f32 / 40.0)).collect(), Stroke::new(1.6, col)));
    // The arrowhead points on along the circle.
    let along = egui::vec2(-to.sin(), to.cos());
    let out = egui::vec2(to.cos(), to.sin());
    let e = at(to);
    p.add(egui::Shape::convex_polygon(vec![e + along * 4.6, e + out * 3.4 - along * 0.6, e - out * 3.4 - along * 0.6], col, Stroke::NONE));
}

/// Settings: a gear with eight rounded teeth.
pub(super) fn draw_gear(p: &egui::Painter, c: egui::Pos2, col: Color32) {
    let s = Stroke::new(1.5, col);
    let n = 8;
    let mut pts = vec![];
    for i in 0..n {
        let a = std::f32::consts::TAU * i as f32 / n as f32;
        for (da, r) in [(-0.30f32, 6.0f32), (-0.19, 8.2), (0.19, 8.2), (0.30, 6.0)] {
            pts.push(c + egui::vec2((a + da).cos(), (a + da).sin()) * r);
        }
    }
    p.add(egui::Shape::closed_line(pts, s));
    p.circle_stroke(c, 2.6, s);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders() {
        let d = default_order(Kind::Pods);
        assert_eq!(&d[..7], &["Context", "Namespace", "Name", "Ready", "Status", "Age", "Restarts"]);
        // What a list of pods shows until someone chooses: no Pod IP, the rest as they come.
        let shown: Vec<&str> = d.iter().copied().filter(|c| default_shown(Kind::Pods).contains(c)).collect();
        assert_eq!(shown, ["Ready", "Status", "Age", "Restarts", "CPU Usage", "Memory Usage", "Last Restart", "Last Restart Reason", "Node", "Controller"]);
        assert_eq!(default_order(Kind::Deployments).last(), Some(&"Age"));
        // Nothing saved: no Pod IP. Only an order saved (by a version that showed it): it stays. A saved choice wins.
        assert!(!shown_by(Kind::Pods, None, false, "Pod IP") && shown_by(Kind::Pods, None, false, "Age"));
        assert!(shown_by(Kind::Pods, None, true, "Pod IP") && !shown_by(Kind::Pods, None, true, "Images"));
        let own: Vec<String> = vec!["Status".into(), "Images".into()];
        assert!(shown_by(Kind::Pods, Some(&own), true, "Images") && !shown_by(Kind::Pods, Some(&own), true, "Pod IP") && !shown_by(Kind::Pods, Some(&own), false, "Age"));
        assert_eq!(default_shown(Kind::Deployments), Kind::Deployments.columns());
        let mem = d.iter().position(|c| *c == "Memory Usage").unwrap();
        assert_eq!(&d[mem + 1..mem + 5], &["CPU Requests", "CPU Limits", "Memory Requests", "Memory Limits"]);
        // Every column once, for every kind.
        for k in GROUPS.iter().flat_map(|g| g.1.iter().copied()) {
            let d = default_order(k);
            let mut u = d.clone();
            u.sort();
            u.dedup();
            assert_eq!(u.len(), d.len(), "{k:?}");
            for c in k.all_columns() {
                assert!(d.contains(&c), "{k:?} {c}");
            }
        }
        // A saved order keeps its places; unknown names go, missing ones return to their usual spot.
        let saved: Vec<String> = ["Name", "Age", "Gone", "Status", "Name"].iter().map(|s| s.to_string()).collect();
        let o = full_order(Kind::Pods, Some(&saved), None);
        assert_eq!(o.len(), d.len());
        assert!(o.iter().position(|c| *c == "Age") < o.iter().position(|c| *c == "Status"));
        // Shown columns saved before the order was kept.
        let shown: Vec<String> = ["Status", "Images", "Age"].iter().map(|s| s.to_string()).collect();
        let o = full_order(Kind::Pods, None, Some(&shown));
        let pos = |n: &str| o.iter().position(|c| *c == n).unwrap();
        assert!(pos("Name") < pos("Status") && pos("Status") < pos("Images") && pos("Images") < pos("Age"));
        assert_eq!(o.len(), d.len());
        assert_eq!(moved(&[1, 2, 3, 4], 1, 2), vec![2, 3, 1, 4]);
        assert_eq!(moved(&[1, 2, 3, 4], 4, 0), vec![4, 1, 2, 3]);
        assert_eq!(moved(&[1, 2, 3], 2, 99), vec![1, 3, 2]);
    }

    /// Drag and click rows of the real menu with made-up mouse events.
    #[test]
    fn menu_drag_and_click() {
        let order: Vec<&'static str> = vec!["Name", "Ready", "Status", "Node", "Age"];
        let run = |events: Vec<Vec<egui::Event>>| -> Vec<ColAction> {
            let ctx = egui::Context::default();
            let mut out = vec![];
            let mut t = 0.0;
            for ev in std::iter::once(vec![]).chain(std::iter::once(vec![])).chain(events) {
                t += 0.05;
                let input = egui::RawInput { screen_rect: Some(egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(400.0, 600.0))), time: Some(t), events: ev, ..Default::default() };
                let mut full = ctx.run_ui(input, |ui| {
                    egui::Area::new(egui::Id::new("t")).fixed_pos(egui::pos2(10.0, 10.0)).show(ui.ctx(), |ui| {
                        let mut he = false;
                        if let Some(a) = column_menu(ui, &order, |n| n != "Node", false, &mut he) {
                            out.push(a);
                        }
                    });
                });
                full.textures_delta.clear();
            }
            out
        };
        let at = |i: usize| egui::pos2(60.0, 10.0 + i as f32 * row_h() + row_h() / 2.0);
        let button = |pos, pressed| egui::Event::PointerButton { pos, button: egui::PointerButton::Primary, pressed, modifiers: Default::default() };
        let drag = |from: usize, to: usize| {
            let (a, b) = (at(from), at(to));
            let mid = a + (b - a) * 0.5;
            vec![
                vec![egui::Event::PointerMoved(a)],
                vec![button(a, true)],
                vec![egui::Event::PointerMoved(mid)],
                vec![egui::Event::PointerMoved(b)],
                vec![egui::Event::PointerMoved(b)],
                vec![button(b, false)],
                vec![],
            ]
        };
        let click = |i: usize| vec![vec![egui::Event::PointerMoved(at(i))], vec![button(at(i), true)], vec![button(at(i), false)], vec![]];
        // Node (hidden) dragged up to second place; Ready dragged to the end.
        let r = run(drag(3, 1));
        assert!(matches!(r.as_slice(), [ColAction::MoveTo(n, 1)] if n == "Node"), "{}", r.len());
        let r = run(drag(1, 4));
        assert!(matches!(r.as_slice(), [ColAction::MoveTo(n, 4)] if n == "Ready"), "{}", r.len());
        // Dropped where it was: nothing.
        assert!(run(drag(2, 2)).is_empty() || matches!(run(drag(2, 2)).as_slice(), [ColAction::Hide(n)] if n == "Status"));
        // Clicks show and hide; the name can't be hidden.
        assert!(matches!(run(click(2)).as_slice(), [ColAction::Hide(n)] if n == "Status"));
        assert!(matches!(run(click(3)).as_slice(), [ColAction::Show(n)] if n == "Node"));
        assert!(run(click(0)).is_empty());
    }
}
