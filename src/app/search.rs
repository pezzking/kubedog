//! Search (⌘K): pages and every object Kubedog has read, across the open clusters.

use super::*;

enum Hit {
    Page(View, String),
    Object(Selected),
    Custom(crds::CustomSel, String),
}

impl KubedogApp {
    /// Open the search box, and read the common kinds so there's something to find.
    pub(super) fn open_search(&mut self) {
        self.palette = Some((String::new(), 0));
        if self.screenshot.is_some() && std::env::var("KUBEDOG_SHOT_SEARCH").is_err() {
            return;
        }
        for c in self.active.clone() {
            for k in [Kind::Pods, Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::Services, Kind::Ingresses, Kind::ConfigMaps, Kind::Secrets, Kind::CronJobs, Kind::Jobs, Kind::Nodes, Kind::Namespaces] {
                if !self.lists.contains_key(&Self::list_key(&c, k)) {
                    self.fetch_list(&c, k);
                }
            }
        }
    }

    fn search_hits(&self, q: &str) -> Vec<(Hit, String, String)> {
        let q = q.trim().to_lowercase();
        let mut out: Vec<(i32, Hit, String, String)> = vec![];
        if q.is_empty() {
            return vec![];
        }
        let score = |name: &str| -> Option<i32> {
            let n = name.to_lowercase();
            if n == q {
                Some(0)
            } else if n.starts_with(&q) {
                Some(1)
            } else if n.contains(&q) {
                Some(2)
            } else {
                None
            }
        };
        // Pages.
        let mut pages: Vec<(View, String)> = vec![
            (View::ClusterOverview, "Cluster Overview".into()),
            (View::WorkloadsOverview, "Workloads Overview".into()),
            (View::Helm, "Helm Releases".into()),
            (View::ServiceMap, "Service Map".into()),
            (View::StorageUsage, "Storage Usage".into()),
            (View::Settings, "Settings".into()),
        ];
        pages.extend(self.power_pages().into_iter().map(|(v, l)| (v, l.to_string())));
        pages.extend(GROUPS.iter().flat_map(|g| g.1.iter().map(|k| (View::Resource(*k), k.label().to_string()))));
        pages.extend(self.crds.iter().enumerate().map(|(i, k)| (View::Custom(i as u32), format!("{} ({})", k.kind, k.group))));
        for (v, label) in pages {
            if let Some(s) = score(&label) {
                out.push((s, Hit::Page(v, label.clone()), label, "page".into()));
            }
        }
        // Objects.
        for c in &self.active {
            for (key, l) in &self.lists {
                let mut parts = key.splitn(3, '|');
                let (_, ctx, what) = (parts.next(), parts.next().unwrap_or(""), parts.next().unwrap_or(""));
                if ctx != c {
                    continue;
                }
                if let Some(ck) = what.strip_prefix("crd:") {
                    let Some(i) = self.crd_index(ck) else { continue };
                    let kind = self.crds[i as usize].kind.clone();
                    for o in &l.items {
                        let name = o["metadata"]["name"].as_str().unwrap_or("");
                        if let Some(s) = score(name) {
                            let ns = o["metadata"]["namespace"].as_str().unwrap_or("").to_string();
                            let sub = format!("{kind}{}", if ns.is_empty() { String::new() } else { format!(" · {ns}") });
                            out.push((s + 3, Hit::Custom(crds::CustomSel { ctx: c.clone(), idx: i, ns, name: name.to_string() }, kind.clone()), name.to_string(), sub));
                        }
                    }
                } else if let Some(kind) = kind_from_key(key).filter(|k| *k != Kind::Events) {
                    for r in &l.rows {
                        if let Some(s) = score(&r.name) {
                            let sub = format!("{}{}", kind.singular(), if r.ns.is_empty() { String::new() } else { format!(" · {}", r.ns) });
                            out.push((s + 3, Hit::Object(Selected { ctx: c.clone(), kind, ns: r.ns.clone(), name: r.name.clone() }), r.name.clone(), sub));
                        }
                    }
                }
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0).then(a.2.len().cmp(&b.2.len())).then(a.2.cmp(&b.2)));
        out.truncate(60);
        let multi = self.active.len() > 1;
        out.into_iter()
            .map(|(_, h, name, sub)| {
                let sub = match (&h, multi) {
                    (Hit::Object(s), true) => format!("{sub} · {}", ctx_label(&s.ctx)),
                    (Hit::Custom(s, _), true) => format!("{sub} · {}", ctx_label(&s.ctx)),
                    _ => sub,
                };
                (h, name, sub)
            })
            .collect()
    }

    /// The search box, over the window.
    pub(super) fn search_ui(&mut self, ctx: &egui::Context) {
        let Some((mut q, mut idx)) = self.palette.take() else { return };
        let hits = self.search_hits(&q);
        let (up, down, enter, esc) = ctx.input(|i| (i.key_pressed(Key::ArrowUp), i.key_pressed(Key::ArrowDown), i.key_pressed(Key::Enter), i.key_pressed(Key::Escape)));
        if down {
            idx = (idx + 1).min(hits.len().saturating_sub(1));
        }
        if up {
            idx = idx.saturating_sub(1);
        }
        let mut chosen: Option<usize> = if enter && !hits.is_empty() { Some(idx.min(hits.len() - 1)) } else { None };
        let mut keep = !esc;
        let modal = egui::Modal::new(egui::Id::new("search"))
            .frame(Frame::new().fill(BG_DEFAULT()).stroke(Stroke::new(1.0, BORDER_DEFAULT())).corner_radius(CornerRadius::same(10)).inner_margin(Margin::same(14)))
            .show(ctx, |ui| {
                ui.set_width(620.0);
                let w = ui.available_width() - 8.0;
                let r = filter_styled(ui, &mut q, "Search pages and objects…", w, 4, Some(z(16.0)));
                r.request_focus();
                if r.changed() {
                    idx = 0;
                }
                ui.add_space(6.0);
                if q.trim().is_empty() {
                    ui.label(RichText::new("Type part of a name: a pod, a deployment, a config map, a page… ↑↓ to move, Enter to open, Esc to close.").size(z(12.5)).color(TEXT_SUBTLE()));
                } else if hits.is_empty() {
                    ui.label(RichText::new("Nothing found in what Kubedog has read so far.").size(z(12.5)).color(TEXT_SUBTLE()));
                }
                let h = (hits.len() as f32 * (u(30.0) + 5.0) + 4.0).min(420.0);
                egui::ScrollArea::vertical().max_height(h).min_scrolled_height(h).show(ui, |ui| {
                    for (i, (_, name, sub)) in hits.iter().enumerate() {
                        let on = i == idx;
                        let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(30.0)), Sense::click());
                        if on || resp.hovered() {
                            ui.painter().rect_filled(rect, CornerRadius::same(6), if on { BG_SELECTED() } else { BG_HOVER() });
                        }
                        let p = ui.painter();
                        let g = p.layout_no_wrap(fit(ui, name, rect.width() * 0.6, z(14.0)), FontId::proportional(z(14.0)), PRIMARY_TEXT());
                        p.galley(egui::pos2(rect.left() + 10.0, rect.center().y - g.size().y / 2.0), g, PRIMARY_TEXT());
                        p.text(rect.right_center() - egui::vec2(10.0, 0.0), egui::Align2::RIGHT_CENTER, sub, FontId::proportional(z(12.0)), TEXT_SUBTLE());
                        if on && (up || down) {
                            resp.scroll_to_me(None);
                        }
                        if resp.clicked() {
                            chosen = Some(i);
                        }
                    }
                });
            });
        if modal.should_close() {
            keep = false;
        }
        if let Some(i) = chosen {
            keep = false;
            match hits.into_iter().nth(i).map(|h| h.0) {
                Some(Hit::Page(View::Custom(c), _)) => self.open_custom(c),
                Some(Hit::Page(v, _)) => self.navigate(v, None),
                Some(Hit::Object(s)) => self.navigate(View::Resource(s.kind), Some(s)),
                Some(Hit::Custom(s, _)) => {
                    let i = s.idx;
                    self.open_custom(i);
                    self.custom_tab = 0;
                    self.custom_sel = Some(s);
                    self.refresh_custom(i, true);
                }
                None => {}
            }
        }
        if keep {
            self.palette = Some((q, idx));
        }
    }
}
