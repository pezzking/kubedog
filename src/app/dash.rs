//! Dashboard sections for the Cluster and Workloads overview pages,
//! drawn under the health bars.

use super::pg::label_at;
use super::*;

/// Sweep of a ring chart: (fraction, colour) segments around a circle.
fn ring(ui: &mut Ui, size: f32, thickness: f32, segments: &[(f32, Color32)], center_text: &str, sub: &str) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), Sense::hover());
    let c = rect.center();
    let r = size / 2.0 - thickness / 2.0 - 1.0;
    let p = ui.painter();
    p.circle_stroke(c, r, Stroke::new(thickness, BG_MUTED()));
    let mut start = -std::f32::consts::FRAC_PI_2;
    for (frac, col) in segments {
        if *frac <= 0.0 {
            continue;
        }
        let sweep = frac.min(1.0) * std::f32::consts::TAU;
        let steps = ((sweep / 0.05).ceil() as usize).max(2);
        let pts: Vec<egui::Pos2> = (0..=steps)
            .map(|i| {
                let a = start + sweep * i as f32 / steps as f32;
                c + egui::vec2(a.cos(), a.sin()) * r
            })
            .collect();
        p.add(egui::Shape::line(pts, Stroke::new(thickness, *col)));
        start += sweep;
    }
    p.text(c - egui::vec2(0.0, 6.0), egui::Align2::CENTER_CENTER, center_text, FontId::proportional(size * 0.2), TEXT_DEFAULT());
    p.text(c + egui::vec2(0.0, size * 0.14), egui::Align2::CENTER_CENTER, sub, FontId::proportional(z(11.0)), TEXT_SUBTLE());
}

/// How many columns of at least `min` fit, for `n` boxes, keeping the rows as even as they get.
fn columns_for(avail: f32, min: f32, gap: f32, n: usize) -> usize {
    let n = n.max(1);
    let fit = (((avail + gap) / (min + gap)).floor() as usize).clamp(1, n);
    n.div_ceil(n.div_ceil(fit))
}

/// Boxes of the same size that fill the width.
pub(super) fn grid(ui: &mut Ui, n: usize, min: f32, h: f32, gap: f32, mut draw: impl FnMut(&mut Ui, usize, egui::Rect)) {
    if n == 0 {
        return;
    }
    let avail = ui.available_width();
    let cols = columns_for(avail, min, gap, n);
    let rows = n.div_ceil(cols);
    let w = (avail - gap * (cols - 1) as f32) / cols as f32;
    let (area, _) = ui.allocate_exact_size(egui::vec2(avail, rows as f32 * (h + gap) - gap), Sense::hover());
    for i in 0..n {
        let at = area.min + egui::vec2((i % cols) as f32 * (w + gap), (i / cols) as f32 * (h + gap));
        draw(ui, i, egui::Rect::from_min_size(at, egui::vec2(w, h)));
    }
}

/// A dashboard tile: a label, a big number and a hint line.
pub(super) fn tile(ui: &Ui, r: egui::Rect, label: &str, value: &str, hint: &str, accent: Color32) {
    let p = ui.painter();
    p.rect_filled(r, CornerRadius::same(8), BG_CARD());
    p.rect_stroke(r, CornerRadius::same(8), Stroke::new(1.0, BORDER_SUBTLE()), egui::StrokeKind::Inside);
    p.rect_filled(egui::Rect::from_min_size(r.min, egui::vec2(3.0, r.height())), CornerRadius { nw: 8, sw: 8, ne: 0, se: 0 }, accent);
    let x = r.left() + 15.0;
    let max = r.width() - 24.0;
    label_at(ui, p, egui::pos2(x, r.top() + r.height() * 0.2), label, 12.0, TEXT_SUBTLE(), max);
    label_at(ui, p, egui::pos2(x, r.top() + r.height() * 0.5), value, 26.0, TEXT_DEFAULT(), max);
    label_at(ui, p, egui::pos2(x, r.top() + r.height() * 0.81), hint, 11.5, accent, max);
}

/// A line of a list: full width, its own height, lit when it can be clicked.
pub(super) fn line(ui: &mut Ui, h: f32, click: bool) -> (egui::Rect, egui::Response) {
    let (r, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), h), if click { Sense::click() } else { Sense::hover() });
    if click && resp.hovered() {
        ui.painter().rect_filled(r.expand2(egui::vec2(6.0, 0.0)), CornerRadius::same(5), BG_HOVER());
    }
    let resp = if click { resp.on_hover_cursor(egui::CursorIcon::PointingHand) } else { resp };
    (r, resp)
}

/// Text from `x` (a share of the line) that's at most `w` wide.
pub(super) fn at(ui: &Ui, r: egui::Rect, x: f32, w: f32, text: &str, size: f32, col: Color32) {
    label_at(ui, ui.painter(), egui::pos2(r.left() + r.width() * x, r.center().y), text, size, col, (r.width() * w - 10.0).max(8.0));
}

/// Text ending at `x` (a share of the line).
pub(super) fn at_end(ui: &Ui, r: egui::Rect, x: f32, text: &str, size: f32, col: Color32) {
    ui.painter().text(egui::pos2(r.left() + r.width() * x, r.center().y), egui::Align2::RIGHT_CENTER, text, FontId::proportional(z(size)), col);
}

/// A bar from `x`, `w` wide (shares of the line).
pub(super) fn bar(ui: &Ui, r: egui::Rect, x: f32, w: f32, frac: f64, col: Color32) {
    let b = egui::Rect::from_min_size(egui::pos2(r.left() + r.width() * x, r.center().y - 3.5), egui::vec2(r.width() * w, 7.0));
    ui.painter().rect_filled(b, CornerRadius::same(3), BG_MUTED());
    ui.painter().rect_filled(egui::Rect::from_min_size(b.min, egui::vec2((b.width() * frac.clamp(0.0, 1.0) as f32).max(2.0), b.height())), CornerRadius::same(3), col);
}

/// Two titled cards side by side with the same height, or under each other when it's narrow.
/// Heights are what each needs; the lists say how high they are.
pub(super) fn pair<T>(ui: &mut Ui, state: &mut T, (ta, ha): (&str, f32), (tb, hb): (&str, f32), a: impl FnOnce(&mut Ui, &mut T), b: impl FnOnce(&mut Ui, &mut T)) {
    let gap = 16.0;
    let avail = ui.available_width();
    let side = avail >= u(820.0);
    let w = if side { (avail - gap) / 2.0 } else { avail };
    let h = if side { ha.max(hb) } else { 0.0 };
    let col = |ui: &mut Ui, title: &str, f: &mut dyn FnMut(&mut Ui)| {
        ui.allocate_ui_with_layout(egui::vec2(w, 0.0), Layout::top_down(Align::Min), |ui| {
            ui.set_width(w);
            ui.spacing_mut().item_spacing = egui::vec2(8.0, 5.0);
            ui.label(RichText::new(title).size(z(17.0)).color(TEXT_DEFAULT()));
            ui.add_space(3.0);
            card(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                ui.set_min_height(h);
                f(ui);
            });
        });
    };
    let (mut a, mut b) = (Some(a), Some(b));
    ui.add_space(26.0);
    if side {
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            col(ui, ta, &mut |ui| if let Some(f) = a.take() { f(ui, state) });
            col(ui, tb, &mut |ui| if let Some(f) = b.take() { f(ui, state) });
        });
    } else {
        col(ui, ta, &mut |ui| if let Some(f) = a.take() { f(ui, state) });
        ui.add_space(22.0);
        col(ui, tb, &mut |ui| if let Some(f) = b.take() { f(ui, state) });
    }
}

/// "Nothing to show" in the middle of a card.
pub(super) fn nothing(ui: &mut Ui, h: f32, text: &str, col: Color32) {
    let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), ui.available_height().max(h)), Sense::hover());
    let g = ui.painter().layout(text.to_string(), FontId::proportional(z(14.0)), col, r.width());
    ui.painter().galley(r.center() - g.size() / 2.0, g, col);
}

/// "quay.io/a/b@sha256:0123..." → ("quay.io/a/b", "sha256:0123456789ab").
fn image_parts(img: &str) -> (String, String) {
    if let Some((repo, d)) = img.split_once('@') {
        let repo = repo.rsplit_once(':').filter(|x| !x.1.contains('/')).map(|x| x.0).unwrap_or(repo);
        let (alg, hex) = d.split_once(':').unwrap_or(("", d));
        return (repo.to_string(), format!("{alg}:{}", hex.chars().take(12).collect::<String>()));
    }
    match img.rsplit_once(':').filter(|(_, t)| !t.contains('/')) {
        Some((r, t)) => (r.to_string(), t.to_string()),
        None => (img.to_string(), "latest".to_string()),
    }
}

pub(super) fn load_color(frac: f64) -> Color32 {
    if frac >= 0.9 {
        DANGER()
    } else if frac >= 0.75 {
        WARNING()
    } else {
        SUCCESS()
    }
}

/// A tiny bar chart of counts (oldest left).
pub(super) fn sparkline(ui: &Ui, r: egui::Rect, counts: &[f64], color: Color32) {
    let max = counts.iter().cloned().fold(0.0, f64::max).max(1.0);
    let w = r.width() / counts.len().max(1) as f32;
    for (i, c) in counts.iter().enumerate() {
        let h = (r.height() * (*c / max) as f32).max(if *c > 0.0 { 2.0 } else { 1.0 });
        let bar = egui::Rect::from_min_max(egui::pos2(r.left() + i as f32 * w + 1.0, r.bottom() - h), egui::pos2(r.left() + (i + 1) as f32 * w - 1.0, r.bottom()));
        ui.painter().rect_filled(bar, CornerRadius::same(1), if *c > 0.0 { color } else { BG_MUTED() });
    }
}

pub(super) fn section(ui: &mut Ui, title: &str, hint: &str) {
    ui.add_space(26.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new(title).size(z(17.0)).color(TEXT_DEFAULT()));
        if !hint.is_empty() {
            ui.label(RichText::new(hint).size(z(12.0)).color(TEXT_PLACEHOLDER()));
        }
    });
    ui.add_space(8.0);
}

impl KubedogApp {
    fn rows_all(&self, k: Kind) -> Option<Vec<(String, Row)>> {
        let mut out = vec![];
        let mut any = false;
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            if let Some(l) = self.lists.get(&Self::list_key(c, k)) {
                if l.fetched.is_some() {
                    any = true;
                    out.extend(l.rows.iter().cloned().map(|r| (c.clone(), r)));
                }
            }
        }
        any.then_some(out)
    }

    fn items_all(&self, k: Kind) -> Vec<(String, Value)> {
        let mut out = vec![];
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            if let Some(l) = self.lists.get(&Self::list_key(c, k)) {
                out.extend(l.items.iter().cloned().map(|o| (c.clone(), o)));
            }
        }
        out
    }

    /// Headline tiles, pod health ring, per-node load, failing events and top consumers.
    pub(super) fn cluster_dashboard(&self, ui: &mut Ui, open_node: &mut Option<String>) -> Option<Selected> {
        let mut open: Option<Selected> = None;
        let nodes = self.rows_all(Kind::Nodes).unwrap_or_default();
        let pods = self.rows_all(Kind::Pods).unwrap_or_default();
        let events = self.rows_all(Kind::Events).unwrap_or_default();
        let deps = self.rows_all(Kind::Deployments).unwrap_or_default();
        let status = |r: &Row| r.cells.get(1).map(|c| c.text.clone()).unwrap_or_default();
        let running = pods.iter().filter(|(_, r)| status(r) == "Running").count();
        let completed = pods.iter().filter(|(_, r)| status(r) == "Completed").count();
        let pending = pods.iter().filter(|(_, r)| matches!(status(r).as_str(), "Pending" | "ContainerCreating" | "PodInitializing") || status(r).starts_with("Init:")).count();
        let failing = pods.len().saturating_sub(running + completed + pending);
        let ready_nodes = nodes.iter().filter(|(_, r)| r.cells.first().map(|c| c.text == "Ready").unwrap_or(false)).count();
        // Scaled to zero (grey) is how it was asked to be, so it counts as healthy.
        let healthy_deps = deps.iter().filter(|(_, r)| r.cells.first().map(|c| c.tone != Tone::Danger).unwrap_or(false)).count();
        let hour = 3600.0;
        let warn_hour: Vec<&(String, Row)> = events
            .iter()
            .filter(|(_, r)| r.cells.get(3).map(|c| c.text == "Warning").unwrap_or(false) && matches!(r.cells.get(5).map(|c| &c.sort), Some(SortKey::Num(x)) if *x < hour))
            .collect();
        // Cluster CPU and memory from node metrics vs allocatable.
        let mut used = (0.0f64, 0.0f64);
        let mut alloc = (0.0f64, 0.0f64);
        let mut have_metrics = false;
        for (c, r) in &nodes {
            alloc.0 += r.req[1];
            alloc.1 += r.req[3];
            if let Some(u) = self.metrics.get(c).and_then(|m| m.nodes.get(&r.name)) {
                used.0 += u.0;
                used.1 += u.1;
                have_metrics = true;
            }
        }

        section(ui, "At a glance", "");
        let cpu_frac = if alloc.0 > 0.0 { used.0 / alloc.0 } else { 0.0 };
        let mem_frac = if alloc.1 > 0.0 { used.1 / alloc.1 } else { 0.0 };
        let share = |f: f64| if have_metrics { format!("{:.0}%", f * 100.0) } else { "–".into() };
        let of = |t: String| if have_metrics { t } else { "no metrics".into() };
        let good = |ok: bool, bad: Color32| if ok { SUCCESS() } else { bad };
        let refused = self.nodes_refused();
        let mut tiles: Vec<(&str, String, String, Color32)> = vec![
            ("Nodes ready", format!("{ready_nodes}/{}", nodes.len()), if ready_nodes == nodes.len() { "all healthy".into() } else { format!("{} not ready", nodes.len() - ready_nodes) }, good(ready_nodes == nodes.len(), DANGER())),
            ("Pods running", running.to_string(), format!("{failing} failing · {pending} pending"), if failing > 0 { DANGER() } else if pending > 0 { WARNING() } else { SUCCESS() }),
            ("Deployments healthy", format!("{healthy_deps}/{}", deps.len()), if healthy_deps == deps.len() { "all available".into() } else { format!("{} degraded", deps.len() - healthy_deps) }, good(healthy_deps == deps.len(), WARNING())),
            ("CPU in use", share(cpu_frac), of(format!("{:.1} of {:.0} cores", used.0 / 1000.0, alloc.0 / 1000.0)), load_color(cpu_frac)),
            ("Memory in use", share(mem_frac), of(format!("{} of {}", gib(used.1), gib(alloc.1))), load_color(mem_frac)),
            ("Warnings, last hour", warn_hour.len().to_string(), if warn_hour.is_empty() { "quiet".into() } else { "see below".into() }, good(warn_hour.is_empty(), WARNING())),
        ];
        if refused {
            let (n, cu, mu, ca, ma) = self.pods_summary();
            let of = |a: f64, b: f64| if b > 0.0 { format!("{:.0}% of what they ask for", a / b * 100.0) } else { "from pod usage".into() };
            tiles[0] = ("Nodes under your pods", n.to_string(), "no access to nodes themselves".into(), TEXT_SUBTLE());
            tiles[3] = ("CPU of your pods", format!("{:.1} cores", cu / 1000.0), of(cu, ca), PRIMARY_TEXT());
            tiles[4] = ("Memory of your pods", gib(mu), of(mu, ma), PRIMARY_TEXT());
            let seen: Vec<&grafana::Node> = self.active.iter().filter(|c| self.ctx_shown(c)).flat_map(|c| self.grafana_nodes(c)).collect();
            if !seen.is_empty() {
                let (cores, used) = seen.iter().fold((0.0, 0.0), |a, n| (a.0 + n.cores, a.1 + n.cpu.unwrap_or(0.0) * n.cores));
                let (mt, ma) = seen.iter().fold((0.0, 0.0), |a, n| (a.0 + n.mem_total, a.1 + n.mem_avail));
                let down = seen.iter().filter(|n| n.ready == Some(false)).count();
                tiles[0] = ("Nodes, from Grafana", seen.len().to_string(), if down > 0 { format!("{down} not ready") } else { format!("{n} under your pods") }, if down > 0 { DANGER() } else { SUCCESS() });
                if cores > 0.0 {
                    tiles[3] = ("CPU in use, whole nodes", format!("{:.0}%", used / cores * 100.0), format!("{used:.1} of {cores:.0} cores"), load_color(used / cores));
                }
                if mt > 0.0 {
                    tiles[4] = ("Memory in use, whole nodes", format!("{:.0}%", (mt - ma) / mt * 100.0), format!("{} of {}", gib(mt - ma), gib(mt)), load_color((mt - ma) / mt));
                }
            }
        } else if nodes.is_empty() {
            tiles[0] = ("Nodes ready", "–".into(), "reading…".into(), TEXT_SUBTLE());
        }
        grid(ui, tiles.len(), u(170.0), u(112.0), 14.0, |ui, i, r| {
            let t = &tiles[i];
            tile(ui, r, t.0, &t.1, &t.2, t.3);
        });

        section(ui, "Pods and nodes", "");
        let mut sorted = nodes.clone();
        sorted.sort_by(|a, b| a.1.name.cmp(&b.1.name));
        let (gap, node_h, ring_w) = (12.0, u(96.0), u(330.0));
        let side = ui.available_width() > ring_w + u(380.0);
        let room = ui.available_width() - if side { ring_w + gap } else { 0.0 };
        let gone: Vec<String> = self.active.iter().filter(|c| self.ctx_shown(c) && self.refused(c, Kind::Nodes)).cloned().collect();
        let n_nodes = if refused { self.pod_nodes(&gone).len().min(24) } else { sorted.len() };
        let rows = n_nodes.div_ceil(columns_for(room, u(190.0), gap, n_nodes)).max(1);
        let h = (rows as f32 * (node_h + gap) - gap).max(u(152.0));
        let mut draw_ring = |ui: &mut Ui| {
            let (r, _) = ui.allocate_exact_size(egui::vec2(if side { ring_w } else { ui.available_width() }, if side { h } else { u(152.0) }), Sense::hover());
            ui.painter().rect_filled(r, CornerRadius::same(8), BG_CARD());
            ui.painter().rect_stroke(r, CornerRadius::same(8), Stroke::new(1.0, BORDER_SUBTLE()), egui::StrokeKind::Inside);
            let size = u(124.0);
            let total = pods.len().max(1) as f32;
            let spot = egui::Rect::from_min_size(egui::pos2(r.left() + 14.0, r.center().y - size / 2.0), egui::vec2(size, size));
            ring(&mut ui.new_child(egui::UiBuilder::new().max_rect(spot)), size, u(14.0), &[(running as f32 / total, SUCCESS()), (completed as f32 / total, TEXT_PLACEHOLDER()), (pending as f32 / total, WARNING()), (failing as f32 / total, DANGER())], &pods.len().to_string(), "pods");
            for (i, (label, n, col)) in [("Running", running, SUCCESS()), ("Completed", completed, TEXT_SUBTLE()), ("Pending", pending, WARNING()), ("Failing", failing, DANGER())].iter().enumerate() {
                let pos = egui::pos2(spot.right() + u(24.0), r.center().y + u(26.0) * (i as f32 - 1.5));
                ui.painter().circle_filled(pos, u(4.0), *col);
                label_at(ui, ui.painter(), pos + egui::vec2(u(14.0), 0.0), &format!("{n}  {label}"), 14.0, TEXT_MUTED(), u(150.0));
            }
        };
        // Per-node load: a card per node, coloured by the busier of CPU and memory.
        let mut draw_nodes = |ui: &mut Ui| {
            let node_h = if side { (h + gap) / rows as f32 - gap } else { node_h };
            if refused {
                let w = ui.available_width();
                ui.allocate_ui_with_layout(egui::vec2(w, h), Layout::top_down(Align::Min), |ui| {
                    if let Some(n) = self.nodes_from_pods(ui, &gone, node_h) {
                        *open_node = Some(n);
                    }
                });
                return;
            }
            grid(ui, sorted.len(), u(190.0), node_h, gap, |ui, i, r| {
                let (c, n) = &sorted[i];
                let use_ = self.metrics.get(c).and_then(|m| m.nodes.get(&n.name)).copied();
                let cf = use_.map(|x| x.0 / n.req[1].max(1.0)).unwrap_or(0.0);
                let mf = use_.map(|x| x.1 / n.req[3].max(1.0)).unwrap_or(0.0);
                let hot = load_color(cf.max(mf));
                let resp = ui.interact(r, egui::Id::new(("dash-node", i)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                ui.painter().rect_filled(r, CornerRadius::same(8), if resp.hovered() { BG_HOVER() } else { BG_CARD() });
                ui.painter().rect_stroke(r, CornerRadius::same(8), Stroke::new(1.0, if use_.is_some() { hot.gamma_multiply(0.6) } else { BORDER_SUBTLE() }), egui::StrokeKind::Inside);
                let inner = r.shrink2(egui::vec2(12.0, 0.0));
                let part = |f: f32| egui::Rect::from_center_size(egui::pos2(inner.center().x, r.top() + r.height() * f), egui::vec2(inner.width(), u(18.0)));
                let ready = n.cells.first().map(|x| x.text == "Ready").unwrap_or(false);
                let top = part(0.22);
                ui.painter().circle_filled(egui::pos2(top.left() + u(4.0), top.center().y), u(4.0), if ready { SUCCESS() } else { DANGER() });
                label_at(ui, ui.painter(), egui::pos2(top.left() + u(15.0), top.center().y), &n.name, 12.5, TEXT_DEFAULT(), top.width() - u(16.0));
                for (f, label, x, col) in [(0.52, "CPU", cf, CPU_BAR()), (0.8, "Mem", mf, MEM_BAR())] {
                    let l = part(f);
                    at(ui, l, 0.0, 0.24, label, 11.0, TEXT_SUBTLE());
                    bar(ui, l, 0.22, 0.52, x, col);
                    at_end(ui, l, 1.0, &if use_.is_some() { format!("{:.0}%", x * 100.0) } else { "–".into() }, 11.0, TEXT_MUTED());
                }
                if resp.on_hover_text(format!("Open {}", n.name)).clicked() {
                    open = Some(Selected { ctx: c.clone(), kind: Kind::Nodes, ns: String::new(), name: n.name.clone() });
                }
            });
        };
        if side {
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = gap;
                draw_ring(ui);
                draw_nodes(ui);
            });
        } else {
            draw_ring(ui);
            ui.add_space(gap);
            draw_nodes(ui);
        }

        // Failing events grouped by reason, with a one-hour timeline.
        section(ui, "Failing events", "warnings grouped by reason · bars show the last hour in 5-minute steps");
        let mut groups: Vec<(String, f64, Vec<f64>, HashSet<String>, String, f64)> = vec![];
        for (_, r) in events.iter().filter(|(_, r)| r.cells.get(3).map(|c| c.text == "Warning").unwrap_or(false)) {
            let reason = r.cells.get(1).map(|c| c.text.clone()).unwrap_or_default();
            let count = match r.cells.get(4).map(|c| &c.sort) {
                Some(SortKey::Num(n)) => *n,
                _ => 1.0,
            };
            let age = match r.cells.get(5).map(|c| &c.sort) {
                Some(SortKey::Num(n)) => *n,
                _ => f64::MAX,
            };
            let g = match groups.iter_mut().position(|g| g.0 == reason) {
                Some(i) => &mut groups[i],
                None => {
                    groups.push((reason.clone(), 0.0, vec![0.0; 12], HashSet::new(), String::new(), f64::MAX));
                    groups.last_mut().unwrap()
                }
            };
            g.1 += count;
            if age < hour {
                let bucket = 11 - ((age / 300.0).floor() as usize).min(11);
                g.2[bucket] += 1.0;
            }
            g.3.insert(r.cells.first().map(|c| c.text.clone()).unwrap_or_default());
            if age < g.5 {
                g.5 = age;
                g.4 = r.cells.get(2).map(|c| c.text.clone()).unwrap_or_default();
            }
        }
        groups.sort_by(|a, b| a.5.partial_cmp(&b.5).unwrap_or(std::cmp::Ordering::Equal));
        if groups.is_empty() {
            empty_box(ui, 90.0, |ui| {
                ui.label(RichText::new(if events.is_empty() { "Loading events…" } else { "No warning events. All quiet." }).size(z(14.5)).color(TEXT_SUBTLE()));
            });
        } else {
            card(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                let wide = ui.available_width() >= u(760.0);
                let (x1, x2, x3, x4) = if wide { (0.19, 0.25, 0.31, 0.42) } else { (0.34, 0.46, 0.58, 0.78) };
                let (r, _) = line(ui, u(24.0), false);
                for (x, h) in [(0.0, "Reason"), (x1, "Times"), (x2, "Objects"), (x3, "Last hour"), (x4, "Latest message")] {
                    at(ui, r, x, 0.2, h, 12.0, TEXT_SUBTLE());
                }
                for (reason, count, timeline, objs, msg, age) in groups.iter().take(12) {
                    let (r, resp) = line(ui, u(28.0), false);
                    at(ui, r, 0.0, x1, reason, 13.5, WARNING());
                    at(ui, r, x1, x2 - x1, &format!("{count:.0}"), 13.5, TEXT_DEFAULT());
                    at(ui, r, x2, x3 - x2, &objs.len().to_string(), 13.5, TEXT_MUTED());
                    let w = (r.width() * (x4 - x3) - 16.0).min(u(110.0));
                    let spot = egui::Rect::from_center_size(egui::pos2(r.left() + r.width() * x3 + w / 2.0, r.center().y), egui::vec2(w, u(18.0)));
                    sparkline(ui, spot, timeline, WARNING());
                    at(ui, r, x4, 1.0 - x4, &format!("{} ago  ·  {msg}", kube::human_duration(*age as i64)), 12.5, TEXT_MUTED());
                    let mut names: Vec<&String> = objs.iter().collect();
                    names.sort();
                    let some = names.iter().take(12).map(|x| x.as_str()).collect::<Vec<_>>().join("\n");
                    resp.on_hover_text(format!("{msg}\n\n{some}"));
                }
            });
        }

        // Top consumers.
        section(ui, "Top consumers", "pods using the most CPU and memory right now");
        let usage: Vec<(String, Row, (f64, f64))> = pods
            .iter()
            .filter_map(|(c, r)| self.metrics.get(c).and_then(|m| m.pods.get(&(r.ns.clone(), r.name.clone()))).map(|u| (c.clone(), r.clone(), *u)))
            .collect();
        if usage.is_empty() {
            empty_box(ui, 70.0, |ui| {
                ui.label(RichText::new("No pod metrics yet (the cluster needs the metrics API).").size(z(14.0)).color(TEXT_SUBTLE()));
            });
        } else {
            let top = |cpu: bool| {
                let v = |x: &(f64, f64)| if cpu { x.0 } else { x.1 };
                let mut l: Vec<&(String, Row, (f64, f64))> = usage.iter().collect();
                l.sort_by(|a, b| v(&b.2).partial_cmp(&v(&a.2)).unwrap_or(std::cmp::Ordering::Equal));
                l.truncate(8);
                l
            };
            let show = |ui: &mut Ui, cpu: bool, open: &mut Option<Selected>| {
                let list = top(cpu);
                let v = |x: &(f64, f64)| if cpu { x.0 } else { x.1 };
                let max = list.first().map(|x| v(&x.2)).unwrap_or(1.0).max(1.0);
                for (c, row, x) in list {
                    let (r, resp) = line(ui, u(27.0), true);
                    at(ui, r, 0.0, 0.56, &format!("{}/{}", row.ns, row.name), 12.5, PRIMARY_TEXT());
                    bar(ui, r, 0.57, 0.29, v(x) / max, if cpu { CPU_BAR() } else { MEM_BAR() });
                    let (n, unit) = if cpu { resources::fmt_cpu(x.0) } else { resources::fmt_mem(x.1) };
                    at_end(ui, r, 1.0, &format!("{n}{unit}"), 12.0, TEXT_MUTED());
                    if resp.on_hover_text(format!("{}/{}", row.ns, row.name)).clicked() {
                        *open = Some(Selected { ctx: c.clone(), kind: Kind::Pods, ns: row.ns.clone(), name: row.name.clone() });
                    }
                }
            };
            let h = u(27.0) * usage.len().min(8) as f32;
            ui.add_space(-26.0);
            pair(ui, &mut open, ("CPU", h), ("Memory", h), |ui, o| show(ui, true, o), |ui, o| show(ui, false, o));
        }
        open
    }

    /// Rollouts in progress, restart leaderboard, images in use, usage by namespace.
    pub(super) fn workloads_dashboard(&self, ui: &mut Ui, ns: &Option<String>) -> Option<Selected> {
        let mut open: Option<Selected> = None;
        let _ = ns;
        let keep = |r: &Row| self.ns_ok(&r.ns);
        let pods: Vec<(String, Row)> = self.rows_all(Kind::Pods).unwrap_or_default().into_iter().filter(|(_, r)| keep(r)).collect();

        // Deployments and StatefulSets not yet at their desired state, if any.
        let mut rolling: Vec<(String, Kind, Value)> = vec![];
        for kind in [Kind::Deployments, Kind::StatefulSets] {
            for (c, o) in self.items_all(kind) {
                if self.ns_ok(o["metadata"]["namespace"].as_str().unwrap_or("")) {
                    let want = o["spec"]["replicas"].as_i64().unwrap_or(1);
                    let st = &o["status"];
                    let ready = st["readyReplicas"].as_i64().unwrap_or(0);
                    let updated = st["updatedReplicas"].as_i64().unwrap_or(0);
                    if want > 0 && (ready < want || updated < want) {
                        rolling.push((c, kind, o));
                    }
                }
            }
        }
        if !rolling.is_empty() {
            section(ui, "Rollouts in progress", "workloads whose pods are still being replaced or aren't all ready");
            card(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                for (c, kind, o) in rolling.iter().take(15) {
                    let want = o["spec"]["replicas"].as_i64().unwrap_or(1).max(1);
                    let ready = o["status"]["readyReplicas"].as_i64().unwrap_or(0);
                    let updated = o["status"]["updatedReplicas"].as_i64().unwrap_or(0);
                    let name = o["metadata"]["name"].as_str().unwrap_or("").to_string();
                    let nsn = o["metadata"]["namespace"].as_str().unwrap_or("").to_string();
                    let (r, resp) = line(ui, u(28.0), true);
                    at(ui, r, 0.0, 0.34, &format!("{nsn}/{name}"), 13.0, PRIMARY_TEXT());
                    at(ui, r, 0.35, 0.12, kind.label(), 11.5, TEXT_PLACEHOLDER());
                    at(ui, r, 0.47, 0.08, "updated", 11.5, TEXT_SUBTLE());
                    bar(ui, r, 0.55, 0.14, updated as f64 / want as f64, INFO());
                    at(ui, r, 0.72, 0.07, "ready", 11.5, TEXT_SUBTLE());
                    bar(ui, r, 0.79, 0.14, ready as f64 / want as f64, if ready >= want { SUCCESS() } else { WARNING() });
                    at_end(ui, r, 1.0, &format!("{ready}/{want}"), 13.0, TEXT_MUTED());
                    if resp.on_hover_text(format!("{nsn}/{name}")).clicked() {
                        open = Some(Selected { ctx: c.clone(), kind: *kind, ns: nsn, name });
                    }
                }
                if rolling.len() > 15 {
                    let (r, _) = line(ui, u(24.0), false);
                    at(ui, r, 0.0, 1.0, &format!("and {} more", rolling.len() - 15), 12.0, TEXT_SUBTLE());
                }
            });
        }

        let mut restarts: Vec<&(String, Row)> = pods.iter().filter(|(_, r)| matches!(r.cells.get(4).map(|c| &c.sort), Some(SortKey::Num(n)) if *n > 0.0)).collect();
        restarts.sort_by(|a, b| b.1.cells[4].sort.partial_cmp(&a.1.cells[4].sort).unwrap_or(std::cmp::Ordering::Equal));
        let mut images: HashMap<String, usize> = HashMap::new();
        for (_, o) in self.items_all(Kind::Pods) {
            if self.ns_ok(o["metadata"]["namespace"].as_str().unwrap_or("")) {
                for c in o["spec"]["containers"].as_array().into_iter().flatten() {
                    if let Some(i) = c["image"].as_str() {
                        *images.entry(i.to_string()).or_default() += 1;
                    }
                }
            }
        }
        let mut images: Vec<(String, usize)> = images.into_iter().collect();
        images.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let lh = u(27.0);
        let title = format!("Images in use ({})", images.len());
        pair(
            ui,
            &mut open,
            ("Most restarts", lh * restarts.len().clamp(1, 10) as f32),
            (&title, lh * images.len().min(10) as f32),
            |ui, open| {
                if restarts.is_empty() {
                    nothing(ui, lh, "No restarts.", SUCCESS());
                }
                for (c, row) in restarts.iter().take(10) {
                    let (r, resp) = line(ui, lh, true);
                    let num = egui::Rect::from_min_size(r.min, egui::vec2(u(40.0), r.height()));
                    at_end(ui, num, 1.0, &row.cells[4].text, 13.5, tone_color(row.cells[4].tone));
                    let rest = egui::Rect::from_min_max(egui::pos2(num.right() + 14.0, r.top()), r.max);
                    let why = if row.cells[6].text == "-" { "" } else { &row.cells[6].text };
                    at(ui, rest, 0.0, if why.is_empty() { 1.0 } else { 0.68 }, &format!("{}/{}", row.ns, row.name), 12.5, PRIMARY_TEXT());
                    at_end(ui, rest, 1.0, &fit(ui, why, rest.width() * 0.31, z(11.5)), 11.5, WARNING());
                    if resp.on_hover_text(format!("{}/{}\n{why}", row.ns, row.name)).clicked() {
                        *open = Some(Selected { ctx: c.clone(), kind: Kind::Pods, ns: row.ns.clone(), name: row.name.clone() });
                    }
                }
            },
            |ui, _| {
                if images.is_empty() {
                    nothing(ui, lh, "No images yet.", TEXT_SUBTLE());
                }
                for (img, n) in images.iter().take(10) {
                    let (r, resp) = line(ui, lh, false);
                    let num = egui::Rect::from_min_size(r.min, egui::vec2(u(40.0), r.height()));
                    at_end(ui, num, 1.0, &format!("×{n}"), 13.5, TEXT_MUTED());
                    let rest = egui::Rect::from_min_max(egui::pos2(num.right() + 14.0, r.top()), r.max);
                    let (repo, tag) = image_parts(img);
                    let latest = tag == "latest";
                    at(ui, rest, 0.0, 0.6, &repo, 12.5, TEXT_DEFAULT());
                    at_end(ui, rest, 1.0, &fit(ui, &tag, rest.width() * 0.38, z(11.5)), 11.5, if latest { WARNING() } else { TEXT_SUBTLE() });
                    resp.on_hover_text(if latest { format!("{img}\nThe “latest” tag can change under you; pin a version.") } else { img.clone() });
                }
            },
        );

        // Usage by namespace.
        section(ui, "Usage by namespace", "from live pod metrics");
        let mut by_ns: HashMap<String, (f64, f64, usize)> = HashMap::new();
        for (c, r) in &pods {
            if let Some(u) = self.metrics.get(c).and_then(|m| m.pods.get(&(r.ns.clone(), r.name.clone()))) {
                let e = by_ns.entry(r.ns.clone()).or_default();
                e.0 += u.0;
                e.1 += u.1;
                e.2 += 1;
            }
        }
        let mut by_ns: Vec<(String, (f64, f64, usize))> = by_ns.into_iter().collect();
        by_ns.sort_by(|a, b| b.1 .1.partial_cmp(&a.1 .1).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.0.cmp(&b.0)));
        if by_ns.is_empty() {
            empty_box(ui, 70.0, |ui| {
                ui.label(RichText::new("No pod metrics yet.").size(z(14.0)).color(TEXT_SUBTLE()));
            });
        } else {
            let top_cpu = by_ns.iter().map(|x| x.1 .0).fold(1.0, f64::max);
            let top_mem = by_ns.iter().map(|x| x.1 .1).fold(1.0, f64::max);
            card(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                let (r, _) = line(ui, u(24.0), false);
                for (x, h) in [(0.0, "Namespace"), (0.28, "Pods"), (0.36, "CPU"), (0.69, "Memory")] {
                    at(ui, r, x, 0.2, h, 12.0, TEXT_SUBTLE());
                }
                for (n, (cpu, mem, count)) in by_ns.iter().take(12) {
                    let (r, resp) = line(ui, u(27.0), false);
                    let name = if self.is_starred(n) { format!("★ {n}") } else { n.clone() };
                    at(ui, r, 0.0, 0.27, &name, 13.5, TEXT_DEFAULT());
                    at(ui, r, 0.28, 0.08, &count.to_string(), 13.5, TEXT_MUTED());
                    let (v, unit) = resources::fmt_cpu(*cpu);
                    bar(ui, r, 0.36, 0.21, cpu / top_cpu, CPU_BAR());
                    at_end(ui, r, 0.655, &format!("{v}{unit}"), 12.0, TEXT_MUTED());
                    bar(ui, r, 0.69, 0.21, mem / top_mem, MEM_BAR());
                    at_end(ui, r, 1.0, &gib(*mem), 12.0, TEXT_MUTED());
                    resp.on_hover_text(n);
                }
                if by_ns.len() > 12 {
                    let (r, _) = line(ui, u(24.0), false);
                    at(ui, r, 0.0, 1.0, &format!("and {} more namespaces", by_ns.len() - 12), 12.0, TEXT_SUBTLE());
                }
            });
        }
        open
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_helpers() {
        assert_eq!(columns_for(1500.0, 170.0, 14.0, 6), 6);
        assert_eq!(columns_for(1300.0, 150.0, 12.0, 9), 5);
        assert_eq!(columns_for(100.0, 170.0, 14.0, 6), 1);
        assert_eq!(columns_for(1000.0, 170.0, 14.0, 0), 1);
        assert_eq!(image_parts("q.io/a/b@sha256:0123456789abcdef"), ("q.io/a/b".into(), "sha256:0123456789ab".into()));
        assert_eq!(image_parts("r:5000/a:v1"), ("r:5000/a".into(), "v1".into()));
        assert_eq!(image_parts("r:5000/a"), ("r:5000/a".into(), "latest".into()));
    }
}
