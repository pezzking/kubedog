//! A node's page: gauges for CPU, memory and pods, a usage history chart, how much is
//! requested and limited against what the node can give, the busiest pods, pods per
//! namespace, conditions and taints (Kubedog addition).

use super::*;
use std::f32::consts::PI;

/// How many CPU/memory readings each node keeps for its history chart (one per metrics refresh).
pub(super) const NODE_HISTORY: usize = 120;

/// What the node page needs, gathered once per frame.
struct NodeFacts {
    cpu_alloc: f64,
    cpu_cap: f64,
    mem_alloc: f64,
    mem_cap: f64,
    pods_cap: f64,
    usage: Option<(f64, f64)>,
    /// Sum of requests and limits of the pods still running here: [cpu req, cpu lim, mem req, mem lim].
    req: [f64; 4],
    pods: Vec<(String, String, Option<(f64, f64)>)>,
    pods_loaded: bool,
}

impl KubedogApp {
    fn node_facts(&self, sel: &Selected, o: &Value) -> NodeFacts {
        let st = &o["status"];
        let q = |k: &str, v: &str| st[k][v].as_str().unwrap_or("0").to_string();
        let metrics = self.metrics.get(&sel.ctx);
        let mut req = [0.0; 4];
        let mut pods = vec![];
        let list = self.lists.get(&Self::list_key(&sel.ctx, Kind::Pods));
        for p in list.map(|l| l.items.as_slice()).unwrap_or(&[]) {
            if p["spec"]["nodeName"].as_str() != Some(&sel.name) {
                continue;
            }
            // Finished pods no longer hold their requests.
            if matches!(p["status"]["phase"].as_str(), Some("Succeeded" | "Failed")) {
                continue;
            }
            let r = resources::requests(Kind::Pods, p);
            for i in 0..4 {
                req[i] += r[i];
            }
            let ns = p["metadata"]["namespace"].as_str().unwrap_or("").to_string();
            let name = p["metadata"]["name"].as_str().unwrap_or("").to_string();
            let u = metrics.and_then(|m| m.pods.get(&(ns.clone(), name.clone())).copied());
            pods.push((ns, name, u));
        }
        NodeFacts {
            cpu_alloc: resources::cpu_milli(&q("allocatable", "cpu")),
            cpu_cap: resources::cpu_milli(&q("capacity", "cpu")),
            mem_alloc: resources::mem_bytes(&q("allocatable", "memory")),
            mem_cap: resources::mem_bytes(&q("capacity", "memory")),
            pods_cap: q("allocatable", "pods").parse().unwrap_or(0.0),
            usage: metrics.and_then(|m| m.nodes.get(&sel.name).copied()),
            req,
            pods,
            pods_loaded: list.map(|l| l.fetched.is_some()).unwrap_or(false),
        }
    }

    /// The graphics at the top of a node's Overview. Returns a pod to open, if one was clicked.
    pub(super) fn node_visuals(&self, ui: &mut Ui, sel: &Selected, o: &Value) -> Option<Selected> {
        let f = self.node_facts(sel, o);
        let mut open: Option<Selected> = None;

        // ----- gauges and history -----
        let cpu_used = f.usage.map(|u| u.0);
        let mem_used = f.usage.map(|u| u.1);
        let running = f.pods.len() as f64;
        ui.horizontal_top(|ui| {
            card_fixed(ui, u(640.0).max(640.0), u(230.0).max(230.0), |ui| {
                ui.horizontal_top(|ui| {
                    gauge(ui, "CPU", cpu_used, f.req[0], f.req[1], f.cpu_alloc, CPU_BAR(), cores);
                    gauge(ui, "Memory", mem_used, f.req[2], f.req[3], f.mem_alloc, MEM_BAR(), |v| {
                        let (a, b) = resources::fmt_mem(v);
                        format!("{a}{b}")
                    });
                    gauge(ui, "Pods", Some(running), 0.0, 0.0, f.pods_cap, INFO(), |v| format!("{v:.0}"));
                });
            });
            ui.add_space(12.0);
            card_fixed(ui, (ui.available_width() - 2.0).max(320.0), u(230.0).max(230.0), |ui| {
                ui.label(RichText::new("Usage history").size(z(14.0)).color(TEXT_DEFAULT()));
                let hist = self.metrics.get(&sel.ctx).and_then(|m| m.node_hist.get(&sel.name)).cloned().unwrap_or_default();
                let every = self.prefs.metrics_secs;
                if hist.len() < 2 {
                    ui.add_space(30.0);
                    ui.label(RichText::new("Collecting readings… (one every {every} s)".replace("{every}", &every.to_string())).color(TEXT_SUBTLE()));
                } else {
                    let mins = (hist.len() as u64 * every) / 60;
                    ui.label(RichText::new(format!("last {} · share of what the node can give", if mins >= 1 { format!("{mins} min") } else { format!("{} s", hist.len() as u64 * every) })).size(z(11.5)).color(TEXT_PLACEHOLDER()));
                    ui.add_space(4.0);
                    let cpu: Vec<f64> = hist.iter().map(|h| h.0 / f.cpu_alloc.max(1.0)).collect();
                    let mem: Vec<f64> = hist.iter().map(|h| h.1 / f.mem_alloc.max(1.0)).collect();
                    history_chart(ui, &[(&cpu, CPU_BAR(), "CPU"), (&mem, MEM_BAR(), "Memory")]);
                }
            });
        });

        // ----- allocation -----
        ui.add_space(12.0);
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Allocation").size(z(14.0)).color(TEXT_DEFAULT()));
                ui.label(RichText::new("what pods asked for (requests), may burst to (limits) and use, against what the node can give").size(z(11.5)).color(TEXT_PLACEHOLDER()));
            });
            ui.add_space(6.0);
            alloc_bar(ui, "CPU", cpu_used, f.req[0], f.req[1], f.cpu_alloc, f.cpu_cap, CPU_BAR(), &cores);
            ui.add_space(6.0);
            alloc_bar(ui, "Memory", mem_used, f.req[2], f.req[3], f.mem_alloc, f.mem_cap, MEM_BAR(), &|v| {
                let (a, b) = resources::fmt_mem(v);
                format!("{a}{b}")
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                legend(ui, CPU_BAR(), "used");
                legend(ui, CPU_BAR().gamma_multiply(0.35), "requested");
                legend(ui, TEXT_SUBTLE(), "│ limits");
                legend(ui, BORDER_DEFAULT(), "allocatable = 100%");
            });
        });

        // ----- busiest pods and pods per namespace -----
        ui.add_space(12.0);
        if !f.pods_loaded {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Loading the pods on this node…").color(TEXT_SUBTLE()));
            });
        } else {
            ui.horizontal_top(|ui| {
                let w = ((ui.available_width() - 24.0) / 3.0).max(260.0);
                for (title, idx, total, color) in [("Busiest by CPU", 0usize, f.cpu_alloc, CPU_BAR()), ("Busiest by memory", 1, f.mem_alloc, MEM_BAR())] {
                    card_fixed(ui, w, u(300.0), |ui| {
                        ui.label(RichText::new(title).size(z(14.0)).color(TEXT_DEFAULT()));
                        ui.add_space(6.0);
                        let mut top: Vec<&(String, String, Option<(f64, f64)>)> = f.pods.iter().filter(|p| p.2.is_some()).collect();
                        top.sort_by(|a, b| {
                            let g = |p: &(String, String, Option<(f64, f64)>)| p.2.map(|u| if idx == 0 { u.0 } else { u.1 }).unwrap_or(0.0);
                            g(b).partial_cmp(&g(a)).unwrap_or(std::cmp::Ordering::Equal)
                        });
                        if top.is_empty() {
                            ui.label(RichText::new("No usage readings yet.").color(TEXT_SUBTLE()));
                        }
                        let max = top.first().and_then(|p| p.2).map(|u| if idx == 0 { u.0 } else { u.1 }).unwrap_or(1.0).max(1.0);
                        for (ns, name, u) in top.into_iter().take(9) {
                            let v = u.map(|u| if idx == 0 { u.0 } else { u.1 }).unwrap_or(0.0);
                            let text = if idx == 0 { resources::fmt_cpu(v) } else { resources::fmt_mem(v) };
                            if pod_bar(ui, name, ns, v / max, v / total.max(1.0), &format!("{}{}", text.0, text.1), color).clicked() {
                                open = Some(Selected { ctx: sel.ctx.clone(), kind: Kind::Pods, ns: ns.clone(), name: name.clone() });
                            }
                        }
                    });
                    ui.add_space(12.0);
                }
                card_fixed(ui, (ui.available_width() - 2.0).max(240.0), u(300.0), |ui| {
                    ui.label(RichText::new(format!("{} pods by namespace", f.pods.len())).size(z(14.0)).color(TEXT_DEFAULT()));
                    ui.add_space(6.0);
                    let mut by: Vec<(String, usize)> = vec![];
                    for (ns, _, _) in &f.pods {
                        match by.iter_mut().find(|x| &x.0 == ns) {
                            Some(x) => x.1 += 1,
                            None => by.push((ns.clone(), 1)),
                        }
                    }
                    by.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                    if by.len() > 7 {
                        let rest: usize = by[6..].iter().map(|x| x.1).sum();
                        by.truncate(6);
                        by.push(("other namespaces".into(), rest));
                    }
                    let total = f.pods.len().max(1) as f32;
                    let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 16.0), Sense::hover());
                    let mut x = r.left();
                    for (i, (_, n)) in by.iter().enumerate() {
                        let w = r.width() * *n as f32 / total;
                        let seg = egui::Rect::from_min_max(egui::pos2(x, r.top()), egui::pos2(x + w, r.bottom()));
                        ui.painter().rect_filled(seg.shrink2(egui::vec2(0.5, 0.0)), CornerRadius::same(3), CTX_PALETTE[i % CTX_PALETTE.len()]);
                        x += w;
                    }
                    ui.add_space(8.0);
                    for (i, (ns, n)) in by.iter().enumerate() {
                        ui.horizontal(|ui| {
                            let (d, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), Sense::hover());
                            ui.painter().rect_filled(d, CornerRadius::same(2), CTX_PALETTE[i % CTX_PALETTE.len()]);
                            ui.add(egui::Label::new(RichText::new(ns).size(z(13.0)).color(TEXT_MUTED())).truncate());
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(RichText::new(n.to_string()).size(z(13.0)).color(TEXT_DEFAULT()));
                            });
                        });
                    }
                });
            });
        }

        // ----- taints (conditions are at the top of the page) -----
        ui.add_space(12.0);
        card(ui, |ui| {
            let taints = o["spec"]["taints"].as_array().cloned().unwrap_or_default();
            ui.label(RichText::new(format!("Taints ({})", taints.len())).size(z(14.0)).color(TEXT_DEFAULT()));
            ui.add_space(4.0);
            if taints.is_empty() {
                ui.label(RichText::new("None: any pod may be scheduled here.").size(z(12.5)).color(TEXT_SUBTLE()));
            }
            ui.horizontal_wrapped(|ui| {
                for t in taints {
                    let k = t["key"].as_str().unwrap_or("");
                    let v = t["value"].as_str().map(|v| format!("={v}")).unwrap_or_default();
                    let e = t["effect"].as_str().unwrap_or("");
                    let col = if e == "NoExecute" { DANGER() } else if e == "NoSchedule" { WARNING() } else { TEXT_SUBTLE() };
                    chip(ui, &format!("{k}{v} : {e}"), col);
                }
            });
        });
        ui.add_space(12.0);
        open
    }
}

/// A small rounded label in a colour.
fn chip(ui: &mut Ui, text: &str, col: Color32) -> egui::Response {
    Frame::new()
        .fill(col.gamma_multiply(0.14))
        .stroke(Stroke::new(1.0, col.gamma_multiply(0.5)))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(9, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(z(12.5)).color(col));
        })
        .response
}

fn card_fixed(ui: &mut Ui, w: f32, h: f32, add: impl FnOnce(&mut Ui)) {
    ui.allocate_ui_with_layout(egui::vec2(w, h), Layout::top_down(Align::Min), |ui| {
        Frame::new()
            .fill(BG_CARD())
            .stroke(Stroke::new(1.0, BORDER_SUBTLE()))
            .corner_radius(CornerRadius::same(10))
            .inner_margin(Margin::same(14))
            .show(ui, |ui| {
                ui.set_width(w - 28.0);
                ui.set_min_height(h - 28.0);
                add(ui)
            });
    });
}

fn arc(p: &egui::Painter, c: egui::Pos2, r: f32, from: f32, to: f32, stroke: Stroke) {
    if to <= from {
        return;
    }
    let steps = (((to - from) / 0.04).ceil() as usize).max(2);
    let pts: Vec<egui::Pos2> = (0..=steps).map(|i| {
        let a = from + (to - from) * i as f32 / steps as f32;
        c + egui::vec2(a.cos(), a.sin()) * r
    }).collect();
    p.add(egui::Shape::line(pts, stroke));
}

/// A 270° gauge: the used part solid (coloured by how full it is), requests as a pale band
/// inside, limits as a tick, all against what the node can give.
#[allow(clippy::too_many_arguments)]
fn gauge(ui: &mut Ui, title: &str, used: Option<f64>, req: f64, lim: f64, alloc: f64, color: Color32, fmt: impl Fn(f64) -> String) {
    let size = u(190.0).max(190.0);
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(size + 14.0, size), Sense::hover());
    let c = rect.center() + egui::vec2(0.0, 6.0);
    let r = size / 2.0 - 16.0;
    let p = ui.painter();
    let start = 0.75 * PI;
    let sweep = 1.5 * PI;
    let at = |f: f64| start + sweep * (f.clamp(0.0, 1.0) as f32);
    arc(p, c, r, start, start + sweep, Stroke::new(12.0, BG_MUTED()));
    if req > 0.0 {
        arc(p, c, r - 13.0, start, at(req / alloc.max(1.0)), Stroke::new(5.0, color.gamma_multiply(0.45)));
    }
    let frac = used.map(|u| u / alloc.max(1.0));
    if let Some(fr) = frac {
        let col = if title == "Pods" { color } else if fr >= 0.9 { DANGER() } else if fr >= 0.75 { WARNING() } else { color };
        arc(p, c, r, start, at(fr).max(start + 0.03), Stroke::new(12.0, col));
    }
    if lim > 0.0 {
        let a = at(lim / alloc.max(1.0));
        let d = egui::vec2(a.cos(), a.sin());
        p.line_segment([c + d * (r - 9.0), c + d * (r + 9.0)], Stroke::new(2.5, if lim > alloc { WARNING() } else { TEXT_DEFAULT() }));
    }
    p.text(c - egui::vec2(0.0, u(12.0)), egui::Align2::CENTER_CENTER, frac.map(|f| format!("{:.0}%", f * 100.0)).unwrap_or_else(|| "–".into()), FontId::proportional(z(30.0)), TEXT_DEFAULT());
    let used_text = used.map(&fmt).unwrap_or_else(|| "?".into());
    p.text(c + egui::vec2(0.0, u(18.0)), egui::Align2::CENTER_CENTER, format!("{} of {}", used_text.trim_end_matches(" cores"), fmt(alloc)), FontId::proportional(z(12.0)), TEXT_SUBTLE());
    p.text(egui::pos2(c.x, rect.bottom() - 10.0), egui::Align2::CENTER_CENTER, title, FontId::proportional(z(14.0)), TEXT_MUTED());
    let mut tip = format!("{title}: {} used of {} the node can give", used.map(&fmt).unwrap_or_else(|| "?".into()), fmt(alloc));
    if req > 0.0 {
        tip += &format!("\nrequested {} ({:.0}%)", fmt(req), req / alloc.max(1.0) * 100.0);
    }
    if lim > 0.0 {
        tip += &format!("\nlimits {} ({:.0}%){}", fmt(lim), lim / alloc.max(1.0) * 100.0, if lim > alloc { " — overcommitted" } else { "" });
    }
    resp.on_hover_text(tip);
}

/// Lines with a soft fill underneath, 0–100 % (higher values are clipped to the top).
fn history_chart(ui: &mut Ui, series: &[(&Vec<f64>, Color32, &str)]) {
    let (r, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), (ui.available_height() - 24.0).max(100.0)), Sense::hover());
    let p = ui.painter();
    for g in [0.25f32, 0.5, 0.75, 1.0] {
        let y = r.bottom() - r.height() * g;
        p.hline(r.x_range(), y, Stroke::new(1.0, BORDER_SUBTLE()));
        p.text(egui::pos2(r.right() - 2.0, y - 1.0), egui::Align2::RIGHT_BOTTOM, format!("{:.0}%", g * 100.0), FontId::proportional(z(10.0)), TEXT_PLACEHOLDER());
    }
    for (vals, col, _) in series {
        let n = vals.len();
        if n < 2 {
            continue;
        }
        let pt = |i: usize| egui::pos2(r.left() + r.width() * i as f32 / (n - 1) as f32, r.bottom() - r.height() * (vals[i].clamp(0.0, 1.0) as f32));
        let mut mesh = egui::Mesh::default();
        let fill = col.gamma_multiply(0.16);
        for i in 0..n - 1 {
            let (a, b) = (pt(i), pt(i + 1));
            let base = mesh.vertices.len() as u32;
            mesh.colored_vertex(a, fill);
            mesh.colored_vertex(b, fill);
            mesh.colored_vertex(egui::pos2(b.x, r.bottom()), Color32::TRANSPARENT);
            mesh.colored_vertex(egui::pos2(a.x, r.bottom()), Color32::TRANSPARENT);
            mesh.add_triangle(base, base + 1, base + 2);
            mesh.add_triangle(base, base + 2, base + 3);
        }
        p.add(egui::Shape::mesh(mesh));
        p.add(egui::Shape::line((0..n).map(pt).collect(), Stroke::new(2.0, *col)));
        p.circle_filled(pt(n - 1), 3.5, *col);
    }
    if let Some(pos) = resp.hover_pos() {
        let n = series.iter().map(|s| s.0.len()).max().unwrap_or(0);
        if n >= 2 {
            let i = (((pos.x - r.left()) / r.width()) * (n - 1) as f32).round().clamp(0.0, (n - 1) as f32) as usize;
            let x = r.left() + r.width() * i as f32 / (n - 1) as f32;
            p.vline(x, r.y_range(), Stroke::new(1.0, TEXT_PLACEHOLDER()));
            let text: Vec<String> = series.iter().filter_map(|(v, _, name)| v.get(i).map(|x| format!("{name} {:.0}%", x * 100.0))).collect();
            resp.on_hover_text(text.join("\n"));
        }
    }
    ui.horizontal(|ui| {
        for (_, col, name) in series {
            legend(ui, *col, name);
        }
    });
}

/// One resource's allocation: used solid, requested pale, limits as a tick, allocatable = full width.
#[allow(clippy::too_many_arguments)]
fn alloc_bar(ui: &mut Ui, title: &str, used: Option<f64>, req: f64, lim: f64, alloc: f64, cap: f64, color: Color32, fmt: &dyn Fn(f64) -> String) {
    ui.horizontal(|ui| {
        left_cell(ui, [z(70.0), z(20.0)], egui::Label::new(RichText::new(title).color(TEXT_MUTED())));
        let w = (ui.available_width() - u(345.0)).max(160.0);
        let (r, resp) = ui.allocate_exact_size(egui::vec2(w, 16.0), Sense::hover());
        let p = ui.painter();
        // Scale: the larger of allocatable and limits, so overcommit shows past the end line.
        let top = alloc.max(lim).max(1.0);
        let x = |v: f64| r.left() + r.width() * (v / top).clamp(0.0, 1.0) as f32;
        p.rect_filled(r, CornerRadius::same(4), BG_MUTED());
        p.rect_filled(egui::Rect::from_min_max(r.min, egui::pos2(x(req), r.bottom())), CornerRadius::same(4), color.gamma_multiply(0.35));
        if let Some(u) = used {
            p.rect_filled(egui::Rect::from_min_max(r.min + egui::vec2(0.0, 4.0), egui::pos2(x(u).max(r.left() + 2.0), r.bottom() - 4.0)), CornerRadius::same(2), color);
        }
        if lim > 0.0 {
            p.vline(x(lim), r.y_range().expand(3.0), Stroke::new(2.0, if lim > alloc { WARNING() } else { TEXT_SUBTLE() }));
        }
        p.vline(x(alloc), r.y_range().expand(5.0), Stroke::new(1.5, BORDER_DEFAULT()));
        resp.on_hover_text(format!(
            "used {}\nrequested {}\nlimits {}\nallocatable {} (capacity {})",
            used.map(fmt).unwrap_or_else(|| "?".into()),
            fmt(req),
            fmt(lim),
            fmt(alloc),
            fmt(cap)
        ));
        let pct = |v: f64| format!("{:.0}%", v / alloc.max(1.0) * 100.0);
        ui.label(RichText::new(format!("used {}", used.map(|u| pct(u)).unwrap_or_else(|| "?".into()))).size(z(12.5)).color(color));
        ui.label(RichText::new(format!("req {}", pct(req))).size(z(12.5)).color(TEXT_MUTED()));
        ui.label(RichText::new(format!("lim {}", pct(lim))).size(z(12.5)).color(if lim > alloc { WARNING() } else { TEXT_MUTED() }));
        ui.label(RichText::new(format!("of {}", fmt(alloc))).size(z(12.5)).color(TEXT_SUBTLE()));
    });
}

/// A pod's row in a "busiest" list: name, a bar (relative to the busiest), and the value.
fn pod_bar(ui: &mut Ui, name: &str, ns: &str, rel: f64, of_node: f64, value: &str, color: Color32) -> egui::Response {
    let (r, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(26.0)), Sense::click());
    let p = ui.painter();
    if resp.hovered() {
        p.rect_filled(r, CornerRadius::same(4), BG_HOVER());
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    let val_w = u(64.0);
    let bar_w = (r.width() * 0.34).min(140.0);
    let name_w = r.width() - val_w - bar_w - 16.0;
    let g = p.layout_no_wrap(fit(ui, name, name_w, z(13.0)), FontId::proportional(z(13.0)), PRIMARY_TEXT());
    p.galley(egui::pos2(r.left() + 4.0, r.center().y - g.size().y / 2.0), g, PRIMARY_TEXT());
    let br = egui::Rect::from_min_size(egui::pos2(r.left() + name_w + 8.0, r.center().y - 4.0), egui::vec2(bar_w, 8.0));
    p.rect_filled(br, CornerRadius::same(3), BG_MUTED());
    p.rect_filled(egui::Rect::from_min_size(br.min, egui::vec2((br.width() * rel.clamp(0.0, 1.0) as f32).max(2.0), br.height())), CornerRadius::same(3), color);
    p.text(egui::pos2(r.right() - 4.0, r.center().y), egui::Align2::RIGHT_CENTER, value, FontId::proportional(z(13.0)), TEXT_DEFAULT());
    resp.on_hover_text(format!("{ns}/{name}\n{value} · {:.1}% of the node\nClick to open", of_node * 100.0))
}

/// CPU in cores ("5.9 cores"), from millicores.
fn cores(m: f64) -> String {
    format!("{:.1} cores", m / 1000.0)
}

fn legend(ui: &mut Ui, col: Color32, text: &str) {
    let (d, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), Sense::hover());
    ui.painter().rect_filled(d, CornerRadius::same(2), col);
    ui.label(RichText::new(text).size(z(11.5)).color(TEXT_SUBTLE()));
    ui.add_space(8.0);
}
