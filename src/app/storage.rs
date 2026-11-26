//! Storage usage per volume claim (a Kubedog addition). Each node's kubelet reports
//! the volumes its pods mount: `kubectl get --raw /api/v1/nodes/NODE/proxy/stats/summary`
//! gives used, capacity and available bytes per claim (`pods[].volume[].pvcRef`).
//! Only claims mounted by a running pod are reported; the rest show "not mounted".

use super::*;

/// How often claim usage is read again (estimated).
const STORAGE_EVERY: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Default)]
pub(super) struct ClaimUsage {
    pub used: f64,
    pub capacity: f64,
    pub available: f64,
    pub inodes_used: f64,
    pub inodes: f64,
    pub pod: String,
    pub node: String,
}

#[derive(Default)]
pub(super) struct ClaimStats {
    loading: bool,
    fetched: Option<Instant>,
    error: Option<String>,
    /// (namespace, claim) -> usage
    usage: HashMap<(String, String), ClaimUsage>,
}

impl KubedogApp {
    pub(super) fn wants_storage(&self) -> bool {
        matches!(self.view, View::StorageUsage | View::Resource(Kind::PersistentVolumeClaims))
            || self.selected.as_ref().map(|s| s.kind == Kind::PersistentVolumeClaims).unwrap_or(false)
            || (self.tab == Tab::Storage && self.selected.as_ref().map(|s| s.kind == Kind::Pods).unwrap_or(false))
            || self.pg_wants_storage()
            || self.view == View::Incident
            || matches!(self.view, View::Op(i) if powers::op_index("ceph") == Some(i))
    }

    pub(super) fn refresh_storage(&mut self, force: bool) {
        if self.demo || !self.wants_storage() {
            return;
        }
        for c in self.active.clone() {
            let st = self.claim_stats.entry(c.clone()).or_default();
            let stale = st.fetched.map(|t| t.elapsed() >= STORAGE_EVERY).unwrap_or(true);
            if st.loading || !(stale || force) {
                continue;
            }
            st.loading = true;
            let ctx = c.clone();
            self.spawn(move |k| {
                let nodes = k.run(&["--context".into(), ctx.clone(), "get".into(), "nodes".into(), "-o".into(), "name".into(), format!("--request-timeout={}", kube::REQUEST_TIMEOUT)]);
                let mut out = vec![];
                let mut errors = vec![];
                match nodes {
                    Err(e) => errors.push(e),
                    Ok(list) => {
                        for n in list.lines().filter_map(|l| l.strip_prefix("node/")) {
                            let r = k.run(&[
                                "--context".into(),
                                ctx.clone(),
                                "get".into(),
                                "--raw".into(),
                                format!("/api/v1/nodes/{n}/proxy/stats/summary"),
                                format!("--request-timeout={}", kube::REQUEST_TIMEOUT),
                            ]);
                            match r.and_then(|j| serde_json::from_str::<Value>(&j).map_err(|e| e.to_string())) {
                                Ok(v) => {
                                    for p in v["pods"].as_array().cloned().unwrap_or_default() {
                                        for vol in p["volume"].as_array().cloned().unwrap_or_default() {
                                            if let Some(pvc) = vol["pvcRef"].as_object() {
                                                out.push(serde_json::json!({
                                                    "ns": pvc.get("namespace"), "name": pvc.get("name"),
                                                    "used": vol["usedBytes"], "capacity": vol["capacityBytes"], "available": vol["availableBytes"],
                                                    "inodesUsed": vol["inodesUsed"], "inodes": vol["inodes"],
                                                    "pod": p["podRef"]["name"], "node": n,
                                                }));
                                            }
                                        }
                                    }
                                }
                                Err(e) => errors.push(e),
                            }
                        }
                    }
                }
                let text = serde_json::json!({ "claims": out, "error": if out.is_empty() { errors.first().cloned() } else { None } });
                Msg::Text { key: format!("pvcstats|{ctx}"), result: Ok(text.to_string()) }
            });
        }
    }

    pub(super) fn on_claim_stats(&mut self, ctx: &str, result: Result<String, String>) {
        let st = self.claim_stats.entry(ctx.to_string()).or_default();
        st.loading = false;
        st.fetched = Some(Instant::now());
        let v: Value = result.ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        st.error = v["error"].as_str().map(|e| if is_refusal(e) { "not available: no permission to read node stats".to_string() } else { e.to_string() });
        st.usage.clear();
        for c in v["claims"].as_array().cloned().unwrap_or_default() {
            let f = |k: &str| c[k].as_f64().unwrap_or(0.0);
            st.usage.insert(
                (c["ns"].as_str().unwrap_or("").to_string(), c["name"].as_str().unwrap_or("").to_string()),
                ClaimUsage {
                    used: f("used"),
                    capacity: f("capacity"),
                    available: f("available"),
                    inodes_used: f("inodesUsed"),
                    inodes: f("inodes"),
                    pod: c["pod"].as_str().unwrap_or("").to_string(),
                    node: c["node"].as_str().unwrap_or("").to_string(),
                },
            );
        }
    }

    pub(super) fn claim_usage(&self, ctx: &str, ns: &str, name: &str) -> Option<&ClaimUsage> {
        self.claim_stats.get(ctx)?.usage.get(&(ns.to_string(), name.to_string()))
    }

    pub(super) fn claim_stats_state(&self, ctx: &str) -> (bool, Option<String>) {
        match self.claim_stats.get(ctx) {
            Some(s) => (s.fetched.is_some(), s.error.clone()),
            None => (false, None),
        }
    }

    /// The storage usage page.
    pub(super) fn storage_usage(&mut self, ui: &mut Ui) {
        let claims = self.items_of(Kind::PersistentVolumeClaims);
        let filtered: Vec<(String, Value)> = claims
            .into_iter()
            .filter(|(_, o)| self.ns_ok(o["metadata"]["namespace"].as_str().unwrap_or("")))
            .filter(|(_, o)| self.search.is_empty() || o.to_string().to_lowercase().contains(&self.search.to_lowercase()))
            .collect();
        self.header(ui, true, Some(format!("{} Persistent Volume Claims", filtered.len())), true);
        let mut rows: Vec<(String, Value, Option<ClaimUsage>)> = filtered
            .into_iter()
            .map(|(c, o)| {
                let u = self.claim_usage(&c, o["metadata"]["namespace"].as_str().unwrap_or(""), o["metadata"]["name"].as_str().unwrap_or("")).cloned();
                (c, o, u)
            })
            .collect();
        rows.sort_by(|a, b| {
            let fa = a.2.as_ref().map(|u| u.used / u.capacity.max(1.0)).unwrap_or(-1.0);
            let fb = b.2.as_ref().map(|u| u.used / u.capacity.max(1.0)).unwrap_or(-1.0);
            fb.partial_cmp(&fa).unwrap_or(std::cmp::Ordering::Equal)
        });
        let mounted: Vec<&ClaimUsage> = rows.iter().filter_map(|r| r.2.as_ref()).collect();
        let used: f64 = mounted.iter().map(|u| u.used).sum();
        let cap: f64 = mounted.iter().map(|u| u.capacity).sum();
        let requested: f64 = rows.iter().map(|r| resources::mem_bytes(r.1["status"]["capacity"]["storage"].as_str().unwrap_or(""))).sum();
        let full = mounted.iter().filter(|u| u.used / u.capacity.max(1.0) >= 0.9).count();
        let errors: Vec<String> = self.active.iter().filter_map(|c| self.claim_stats_state(c).1).collect();
        let loaded = self.active.iter().all(|c| self.claim_stats_state(c).0);
        let mut open: Option<Selected> = None;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.add_space(4.0);
            ui.with_layout(Layout::left_to_right(Align::Min).with_main_wrap(true), |ui| {
                ui.spacing_mut().item_spacing = egui::vec2(14.0, 14.0);
                let tile = |ui: &mut Ui, label: &str, value: String, hint: String, accent: Color32| {
                    Frame::new().fill(BG_CARD()).stroke(Stroke::new(1.0, BORDER_SUBTLE())).corner_radius(CornerRadius::same(8)).inner_margin(Margin::same(12)).show(ui, |ui| {
                        ui.set_width(180.0);
                        ui.vertical(|ui| {
                            ui.label(RichText::new(label).size(z(12.0)).color(TEXT_SUBTLE()));
                            ui.label(RichText::new(value).size(z(24.0)).strong().color(TEXT_DEFAULT()));
                            ui.label(RichText::new(hint).size(z(11.5)).color(accent));
                        });
                    });
                };
                tile(ui, "Claims", rows.len().to_string(), if !errors.is_empty() && mounted.is_empty() { String::new() } else { format!("{} mounted right now", mounted.len()) }, TEXT_SUBTLE());
                tile(ui, "Requested", gib(requested), "total size of all claims".into(), TEXT_SUBTLE());
                if !errors.is_empty() && mounted.is_empty() {
                    tile(ui, "Used (mounted)", "–".into(), "your account can't read it".into(), TEXT_SUBTLE());
                    return;
                }
                tile(ui, "Used (mounted)", gib(used), if cap > 0.0 { format!("{:.0}% of {}", used / cap * 100.0, gib(cap)) } else { "–".into() }, if cap > 0.0 { usage_color(used / cap) } else { TEXT_SUBTLE() });
                tile(ui, "Nearly full", full.to_string(), "90% or more used".into(), if full > 0 { DANGER() } else { SUCCESS() });
            });
            for e in &errors {
                ui.add_space(6.0);
                ui.label(RichText::new(format!("Usage {e}")).color(WARNING()));
            }
            if !loaded {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(RichText::new("Reading volume usage from each node…").color(TEXT_SUBTLE()));
                });
            }
            ui.add_space(12.0);
            for (c, o, u) in &rows {
                let ns = o["metadata"]["namespace"].as_str().unwrap_or("").to_string();
                let name = o["metadata"]["name"].as_str().unwrap_or("").to_string();
                let size = o["status"]["capacity"]["storage"].as_str().unwrap_or("").to_string();
                let class = o["spec"]["storageClassName"].as_str().unwrap_or("").to_string();
                let phase = o["status"]["phase"].as_str().unwrap_or("").to_string();
                let r = Frame::new().fill(BG_CARD()).stroke(Stroke::new(1.0, BORDER_SUBTLE())).corner_radius(CornerRadius::same(8)).inner_margin(Margin::symmetric(12, 8)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.set_width(300.0);
                            ui.add(egui::Label::new(RichText::new(format!("{ns}/{name}")).color(PRIMARY_TEXT())).truncate());
                            ui.label(RichText::new(format!("{size} · {class} · {phase}")).size(z(11.5)).color(TEXT_SUBTLE()));
                        });
                        match u {
                            Some(u) => {
                                let frac = u.used / u.capacity.max(1.0);
                                claim_bar(ui, 380.0, frac);
                                ui.label(RichText::new(format!("{:.0}%", frac * 100.0)).strong().color(usage_color(frac)));
                                ui.label(RichText::new(format!("{} used of {} · {} free", gib(u.used), gib(u.capacity), gib(u.available))).size(z(12.0)).color(TEXT_MUTED()));
                                if u.inodes > 0.0 && u.inodes_used / u.inodes > 0.8 {
                                    ui.label(RichText::new(format!("files {:.0}% used", u.inodes_used / u.inodes * 100.0)).size(z(11.5)).color(WARNING()));
                                }
                                ui.label(RichText::new(format!("mounted by {}", u.pod)).size(z(11.5)).color(TEXT_PLACEHOLDER()));
                            }
                            None => {
                                ui.label(RichText::new(if !errors.is_empty() && mounted.is_empty() { "usage isn't available" } else if loaded { "not mounted by a running pod, so no usage is reported" } else { "…" }).size(z(12.0)).color(TEXT_PLACEHOLDER()));
                            }
                        }
                    });
                }).response.interact(Sense::click());
                if r.on_hover_text("Open this claim").clicked() {
                    open = Some(Selected { ctx: c.clone(), kind: Kind::PersistentVolumeClaims, ns, name });
                }
                ui.add_space(6.0);
            }
        });
        if let Some(s) = open {
            self.navigate(View::Resource(Kind::PersistentVolumeClaims), Some(s));
        }
    }

    /// The usage part of a claim's Overview tab.
    pub(super) fn claim_detail(&self, ui: &mut Ui, sel: &Selected) {
        ui.add_space(8.0);
        ui.label(RichText::new("Usage").color(TEXT_SUBTLE()).strong());
        card(ui, |ui| match self.claim_usage(&sel.ctx, &sel.ns, &sel.name) {
            Some(u) => {
                let frac = u.used / u.capacity.max(1.0);
                ui.horizontal(|ui| {
                    claim_bar(ui, 320.0, frac);
                    ui.label(RichText::new(format!("{:.1}%", frac * 100.0)).strong().color(usage_color(frac)));
                });
                kv(ui, "Used", gib(u.used));
                kv(ui, "Free", gib(u.available));
                kv(ui, "Capacity", gib(u.capacity));
                if u.inodes > 0.0 {
                    kv(ui, "Files (inodes)", format!("{:.0} of {:.0} ({:.0}%)", u.inodes_used, u.inodes, u.inodes_used / u.inodes * 100.0));
                }
                kv(ui, "Mounted by", format!("{} on {}", u.pod, u.node));
            }
            None => {
                let (loaded, err) = self.claim_stats_state(&sel.ctx);
                ui.label(RichText::new(match (loaded, err) {
                    (_, Some(e)) => format!("Usage {e}"),
                    (true, None) => "Not mounted by a running pod, so no usage is reported.".to_string(),
                    _ => "Reading usage…".to_string(),
                }).color(TEXT_SUBTLE()));
            }
        });
    }
}

pub(super) fn usage_color(frac: f64) -> Color32 {
    if frac >= 0.9 {
        DANGER()
    } else if frac >= 0.75 {
        WARNING()
    } else {
        SUCCESS()
    }
}

/// A storage bar with 75% and 90% marks.
pub(super) fn claim_bar(ui: &mut Ui, width: f32, frac: f64) {
    let (r, _) = ui.allocate_exact_size(egui::vec2(width, 10.0), Sense::hover());
    ui.painter().rect_filled(r, CornerRadius::same(5), BG_MUTED());
    let f = egui::Rect::from_min_size(r.min, egui::vec2((r.width() * frac.clamp(0.0, 1.0) as f32).max(3.0), r.height()));
    ui.painter().rect_filled(f, CornerRadius::same(5), usage_color(frac));
    for m in [0.75f32, 0.9] {
        let x = r.left() + r.width() * m;
        ui.painter().vline(x, r.y_range(), Stroke::new(1.0, BG_DEFAULT()));
    }
}
