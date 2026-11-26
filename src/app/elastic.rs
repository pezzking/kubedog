//! Elasticsearch run by the ECK operator: health, nodes, where the space goes, activity.

use super::pg::{big, bytes, check_panel, label_at, panel, pill, spark, two, Check, PgId};
use super::*;

pub(super) const CRD: &str = "elasticsearches.elasticsearch.k8s.elastic.co";

/// Everything asked of Elasticsearch, all of it reads.
const PATHS: [(&str, &str); 6] = [
    ("health", "/_cluster/health"),
    ("nodes", "/_cat/nodes?format=json&bytes=b&h=name,node.role,master,heap.percent,ram.percent,cpu,disk.used_percent,disk.used,disk.total,version"),
    ("indices", "/_cat/indices?format=json&bytes=b&h=index,health,status,pri,rep,docs.count,store.size&expand_wildcards=all"),
    ("shards", "/_cat/shards?format=json&h=index,shard,prirep,state,node,unassigned.reason"),
    ("stats", "/_nodes/stats/indices,thread_pool?filter_path=nodes.*.name,nodes.*.indices.search.query_total,nodes.*.indices.search.query_time_in_millis,nodes.*.indices.indexing.index_total,nodes.*.thread_pool.search.rejected,nodes.*.thread_pool.write.rejected"),
    ("license", "/_license"),
];

fn fetch(k: &Kubectl, id: &PgId, tls: bool) -> Result<String, String> {
    // The monitoring login is for watching only; the superuser is only a fallback.
    let name = &id.name;
    let (auth, who) = match login::secret_value(k, &id.ctx, &id.ns, &format!("{name}-es-internal-users"), "elastic-internal-monitoring") {
        Ok(p) => (login::Auth::User("elastic-internal-monitoring".into(), p), "elastic-internal-monitoring"),
        Err(_) => (login::Auth::User("elastic".into(), login::secret_value(k, &id.ctx, &id.ns, &format!("{name}-es-elastic-user"), "elastic")?), "elastic"),
    };
    let ca = if tls {
        let s = format!("{name}-es-http-certs-public");
        Some(login::secret_value(k, &id.ctx, &id.ns, &s, "ca.crt").or_else(|_| login::secret_value(k, &id.ctx, &id.ns, &s, "tls.crt"))?)
    } else {
        None
    };
    let t = login::tunnel(k, &id.ctx, &id.ns, &format!("svc/{name}-es-http"), 9200)?;
    let base = format!("{}://{name}-es-http.{}.svc:9200", if tls { "https" } else { "http" }, id.ns);
    let paths: Vec<String> = PATHS.iter().map(|p| p.1.to_string()).collect();
    let got = login::get(&auth, &base, &t, &paths, ca.as_deref())?;
    let mut out = serde_json::json!({ "who": who });
    for ((key, _), (code, body)) in PATHS.iter().zip(got) {
        if code == 200 {
            out[*key] = serde_json::from_str(&body).map_err(|e| format!("couldn't read its answer: {e}"))?;
        } else if *key == "health" {
            return Err(match code {
                401 => format!("the login {who} was refused"),
                403 => format!("the login {who} isn't allowed to look"),
                c => format!("it answered {c}"),
            });
        }
    }
    Ok(out.to_string())
}

fn num(v: &Value) -> f64 {
    v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())).unwrap_or(0.0)
}

fn sum_stats(v: &Value, path: &[&str]) -> f64 {
    v["stats"]["nodes"].as_object().into_iter().flatten().map(|(_, n)| num(path.iter().fold(n, |a, k| &a[*k]))).fold(0.0, |a, b| a + b)
}

/// Counters for the charts: searches and writes since the nodes started.
pub(super) fn reading(v: &Value) -> (f64, f64) {
    (sum_stats(v, &["indices", "search", "query_total"]), sum_stats(v, &["indices", "indexing", "index_total"]))
}

/// The data stream or the index a backing index belongs to
/// (".ds-logs-app-2026.11.17-000031" → "logs-app").
fn family(index: &str) -> String {
    let Some(rest) = index.strip_prefix(".ds-") else { return index.to_string() };
    let parts: Vec<&str> = rest.rsplitn(3, '-').collect();
    if parts.len() == 3 && parts[0].len() == 6 && parts[0].bytes().all(|b| b.is_ascii_digit()) && parts[1].len() == 10 {
        return parts[2].to_string();
    }
    rest.to_string()
}

#[derive(Debug, PartialEq, Clone)]
struct Family {
    name: String,
    size: f64,
    docs: f64,
    indices: usize,
    worst: u8,
    system: bool,
}

/// Indices by family, biggest first.
fn families(v: &Value) -> Vec<Family> {
    let mut m: HashMap<String, Family> = HashMap::new();
    for i in v["indices"].as_array().into_iter().flatten() {
        let name = family(i["index"].as_str().unwrap_or(""));
        let f = m.entry(name.clone()).or_insert(Family { system: name.starts_with('.'), name, size: 0.0, docs: 0.0, indices: 0, worst: 0 });
        f.size += num(&i["store.size"]);
        f.docs += num(&i["docs.count"]);
        f.indices += 1;
        f.worst = f.worst.max(match i["health"].as_str() { Some("red") => 2, Some("yellow") => 1, _ => 0 });
    }
    let mut out: Vec<Family> = m.into_values().collect();
    out.sort_by(|a, b| b.size.partial_cmp(&a.size).unwrap_or(std::cmp::Ordering::Equal).then(a.name.cmp(&b.name)));
    out
}

/// Look it over, worst first.
fn checks(v: &Value, now: i64) -> Vec<Check> {
    let mut out: Vec<Check> = vec![];
    let mut add = |tone: Tone, title: &str, detail: String| out.push(Check { tone, title: title.into(), detail });
    let h = &v["health"];
    match h["status"].as_str() {
        Some("green") => add(Tone::Success, "Green", format!("{} shards, all copies in place", num(&h["active_shards"]))),
        Some("yellow") => add(Tone::Warning, "Yellow", format!("{} copies have no place: nothing is lost, but a failure now would hurt", num(&h["unassigned_shards"]))),
        _ => add(Tone::Danger, "Red", format!("{} main shards are missing: some data can't be read", num(&h["unassigned_primary_shards"]))),
    }
    let nodes = v["nodes"].as_array().cloned().unwrap_or_default();
    let worst = |k: &str| nodes.iter().map(|n| (num(&n[k]), n["name"].as_str().unwrap_or("").to_string())).fold((0.0, String::new()), |a, b| if b.0 > a.0 { b } else { a });
    let mut level = |k: &str, warn: f64, bad: f64, good: &str, high: &str| {
        let (x, n) = worst(k);
        let t = if x >= bad { Tone::Danger } else if x >= warn { Tone::Warning } else { Tone::Success };
        out.push(Check { tone: t, title: (if t == Tone::Success { good } else { high }).into(), detail: format!("at most {x:.0}% ({n})") });
    };
    // Elasticsearch stops placing copies at 85% and moves shards away at 90%.
    level("disk.used_percent", 80.0, 90.0, "Room on disk", "Disk filling up");
    level("heap.percent", 85.0, 95.0, "Heap is fine", "Heap is high");
    level("cpu", 85.0, 97.0, "CPU is fine", "CPU is high");
    let mut add = |tone: Tone, title: &str, detail: String| out.push(Check { tone, title: title.into(), detail });
    let masters = nodes.iter().filter(|n| n["node.role"].as_str().unwrap_or("").contains('m')).count();
    if masters < 3 {
        add(Tone::Warning, "Fewer than three masters", format!("{masters}: it may stop when one node fails"));
    } else {
        add(Tone::Success, "Masters can fail over", format!("{masters} nodes can lead"));
    }
    let data = num(&h["number_of_data_nodes"]).max(1.0);
    let per = num(&h["active_shards"]) / data;
    if per > 800.0 {
        add(Tone::Warning, "Many shards per node", format!("{per:.0} (the usual limit is 1000)"));
    }
    let bare: Vec<&str> = v["indices"].as_array().into_iter().flatten().filter(|i| num(&i["rep"]) == 0.0 && num(&i["docs.count"]) > 0.0 && i["status"].as_str() != Some("close")).filter_map(|i| i["index"].as_str()).filter(|n| !n.starts_with('.')).collect();
    if !bare.is_empty() && data > 1.0 {
        add(Tone::Warning, "Indices without a copy", format!("{}: {}", bare.len(), truncate(&bare.join(", "), 160)));
    }
    let (rs, rw) = (sum_stats(v, &["thread_pool", "search", "rejected"]), sum_stats(v, &["thread_pool", "write", "rejected"]));
    if rs + rw > 0.0 {
        add(Tone::Warning, "Work was turned away", format!("{rs:.0} searches and {rw:.0} writes since the nodes started"));
    }
    if num(&h["number_of_pending_tasks"]) > 50.0 {
        add(Tone::Warning, "Master is behind", format!("{} waiting tasks", num(&h["number_of_pending_tasks"])));
    }
    let l = &v["license"]["license"];
    if let Some(t) = l["expiry_date_in_millis"].as_f64().map(|m| (m / 1000.0) as i64) {
        let (kind, days) = (l["type"].as_str().unwrap_or(""), (t - now).div_euclid(86400));
        if t < now {
            add(Tone::Danger, "Licence expired", format!("{kind}, on {}", netmap::iso_date(t)));
        } else if days <= 7 {
            add(Tone::Danger, "Licence about to expire", format!("{kind}, on {} (in {days}d)", netmap::iso_date(t)));
        } else if days <= 30 {
            add(Tone::Warning, "Licence expires soon", format!("{kind}, on {} (in {days}d)", netmap::iso_date(t)));
        } else {
            add(Tone::Success, "Licence valid", format!("{kind}, {days} days left"));
        }
    }
    let rank = |t: Tone| match t { Tone::Danger => 0, Tone::Warning => 1, _ => 2 };
    out.sort_by_key(|c| rank(c.tone));
    out
}

/// Rectangles in proportion to sizes (largest first), as square as they get.
fn treemap(area: egui::Rect, sizes: &[f32]) -> Vec<egui::Rect> {
    let total: f32 = sizes.iter().sum();
    let mut out = vec![];
    if total <= 0.0 || area.area() <= 0.0 {
        return vec![egui::Rect::from_min_size(area.min, egui::Vec2::ZERO); sizes.len()];
    }
    let areas: Vec<f32> = sizes.iter().map(|s| s / total * area.area()).collect();
    let mut rest = area;
    let mut i = 0;
    while i < areas.len() {
        let side = rest.width().min(rest.height()).max(1e-3);
        let ratio = |row: &[f32]| -> f32 {
            let s: f32 = row.iter().sum();
            let (hi, lo) = row.iter().fold((0.0f32, f32::MAX), |a, x| (a.0.max(*x), a.1.min(*x)));
            (side * side * hi / (s * s)).max(s * s / (side * side * lo.max(1e-6)))
        };
        let mut n = 1;
        while i + n < areas.len() && ratio(&areas[i..i + n + 1]) <= ratio(&areas[i..i + n]) {
            n += 1;
        }
        let row = &areas[i..i + n];
        let sum: f32 = row.iter().sum();
        let thick = sum / side;
        let tall = rest.width() >= rest.height();
        let mut at = 0.0;
        for a in row {
            let len = a / thick.max(1e-6);
            out.push(if tall {
                egui::Rect::from_min_size(rest.min + egui::vec2(0.0, at), egui::vec2(thick, len))
            } else {
                egui::Rect::from_min_size(rest.min + egui::vec2(at, 0.0), egui::vec2(len, thick))
            });
            at += len;
        }
        if tall {
            rest.min.x += thick;
        } else {
            rest.min.y += thick;
        }
        i += n;
    }
    out
}

impl KubedogApp {
    pub(super) fn es_items(&self, ctx: &str) -> &[Value] {
        let Some(k) = self.crd_index(CRD).and_then(|i| self.crds.get(i as usize)) else { return &[] };
        self.lists.get(&Self::custom_list_key(ctx, k)).map(|l| l.items.as_slice()).unwrap_or(&[])
    }

    pub(super) fn has_elastic(&self) -> bool {
        self.active.iter().any(|c| !self.es_items(c).is_empty())
    }

    fn es_key(id: &PgId) -> String {
        format!("es|{}|{}|{}", id.ctx, id.ns, id.name)
    }

    fn es_object(&self, id: &PgId) -> Option<&Value> {
        self.es_items(&id.ctx).iter().find(|o| o["metadata"]["name"].as_str() == Some(&id.name) && o["metadata"]["namespace"].as_str() == Some(&id.ns))
    }

    pub(super) fn refresh_elastic(&mut self, force: bool) {
        if self.power_off("elastic") {
            return;
        }
        if self.view != View::Elastic {
            return;
        }
        if let Some(i) = self.crd_index(CRD) {
            self.refresh_custom(i, force);
        }
        let Some(id) = self.es_sel.clone() else { return };
        let tls = self.es_object(&id).map(|o| o["spec"]["http"]["tls"]["selfSignedCertificate"]["disabled"].as_bool() != Some(true)).unwrap_or(true);
        let key = Self::es_key(&id);
        self.serve(&key, force, move |k| fetch(k, &id, tls));
    }

    pub(super) fn elastic_ready(&self) -> bool {
        self.has_elastic() && self.es_sel.as_ref().map(|id| !self.login_allowed(&Self::es_key(id)) || self.served.get(&Self::es_key(id)).map(|s| s.fetched.is_some()).unwrap_or(false)).unwrap_or(true)
    }

    pub(super) fn elastic_view(&mut self, ui: &mut Ui) {
        if let Some(id) = self.es_sel.clone() {
            self.elastic_page(ui, &id);
            return;
        }
        let search = self.search.to_lowercase();
        let mut cards = vec![];
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            for o in self.es_items(c) {
                let (ns, name) = (o["metadata"]["namespace"].as_str().unwrap_or(""), o["metadata"]["name"].as_str().unwrap_or(""));
                if !self.ns_ok(ns) || !(search.is_empty() || name.contains(&search) || ns.contains(&search)) {
                    continue;
                }
                let st = &o["status"];
                let health = st["health"].as_str().unwrap_or("unknown");
                let tone = match health { "green" => SUCCESS(), "yellow" => WARNING(), "red" => DANGER(), _ => TEXT_SUBTLE() };
                let want: i64 = o["spec"]["nodeSets"].as_array().into_iter().flatten().map(|n| n["count"].as_i64().unwrap_or(0)).sum();
                let lines = vec![
                    (format!("{health} · {}", st["phase"].as_str().unwrap_or("")), tone),
                    (format!("{} of {want} nodes  ·  Elasticsearch {}", st["availableNodes"].as_i64().unwrap_or(0), st["version"].as_str().unwrap_or("")), TEXT_MUTED()),
                ];
                cards.push((PgId { ctx: c.clone(), ns: ns.into(), name: name.into() }, tone, lines));
            }
        }
        cards.sort_by(|a, b| (&a.0.ns, &a.0.name).cmp(&(&b.0.ns, &b.0.name)));
        self.header(ui, true, Some(format!("{} Elasticsearch", cards.len())), true);
        ui.add_space(8.0);
        if cards.is_empty() {
            ui.label(RichText::new("None here.").color(TEXT_SUBTLE()));
        }
        let mut open = None;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| open = self.super_cards(ui, &cards));
        if open.is_some() {
            self.es_sel = open;
            self.refresh_current(false);
        }
    }

    fn elastic_page(&mut self, ui: &mut Ui, id: &PgId) {
        if self.super_back(ui, id, "Elasticsearch") {
            self.es_sel = None;
            return;
        }
        let key = Self::es_key(id);
        let obj = self.es_object(id).cloned().unwrap_or(Value::Null);
        let (data, error, hist) = match self.served.get(&key) {
            Some(s) => (s.data.clone(), s.error.clone(), s.hist.iter().copied().collect::<Vec<_>>()),
            None => (None, None, vec![]),
        };
        let allowed = self.login_allowed(&key);
        let mut forget = false;
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{} /", id.ns)).size(z(20.0)).color(TEXT_SUBTLE()));
            ui.label(RichText::new(&id.name).size(z(20.0)).color(TEXT_DEFAULT()));
            pill(ui, &format!("Elasticsearch {}", obj["status"]["version"].as_str().unwrap_or("")), INFO());
            let h = obj["status"]["health"].as_str().unwrap_or("unknown");
            pill(ui, h, match h { "green" => SUCCESS(), "yellow" => WARNING(), "red" => DANGER(), _ => TEXT_SUBTLE() });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if allowed {
                    forget = button(ui, "Log out", false, false);
                    if let Some(w) = data.as_ref().and_then(|d| d["who"].as_str()) {
                        ui.label(RichText::new(format!("reading as {w}")).size(z(12.0)).color(if w == "elastic" { WARNING() } else { TEXT_SUBTLE() }));
                    }
                }
            });
        });
        ui.add_space(6.0);
        if forget {
            self.allow_login(&key, false);
            return;
        }
        let mut area = egui::ScrollArea::vertical().id_salt("es-page").auto_shrink([false, false]);
        if self.screenshot.is_some() {
            if let Some(y) = std::env::var("KUBEDOG_SHOT_SCROLL").ok().and_then(|v| v.parse::<f32>().ok()) {
                area = area.vertical_scroll_offset(y);
            }
        }
        area.show(ui, |ui| {
            if !allowed {
                let how = format!("It uses the monitoring login of this cluster (secret {0}-es-internal-users), which is meant for watching only. If that's missing, it uses the administrator login in {0}-es-elastic-user.", id.name);
                self.login_card(ui, &key, &id.name, &how, true);
            }
            if let Some(e) = &error {
                Frame::new().fill(WARN_BG()).corner_radius(CornerRadius::same(6)).inner_margin(Margin::same(8)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(format!("Couldn't look inside: {e}")).size(z(12.5)).color(WARNING()));
                });
                ui.add_space(8.0);
            }
            let Some(v) = &data else {
                if allowed && error.is_none() {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(RichText::new("Logging in…").color(TEXT_SUBTLE()));
                    });
                }
                return;
            };
            self.es_nodes(ui, v);
            ui.add_space(12.0);
            let list = checks(v, kube::now_secs());
            two(ui, |ui| check_panel(ui, &list), |ui| es_activity(ui, v, &hist));
            ui.add_space(12.0);
            card(ui, |ui| es_space(ui, v));
            ui.add_space(12.0);
            card(ui, |ui| es_table(ui, v));
            ui.add_space(16.0);
        });
    }

    /// The nodes: rings for heap, CPU and disk, and how many shards each holds.
    fn es_nodes(&self, ui: &mut Ui, v: &Value) {
        let nodes = v["nodes"].as_array().cloned().unwrap_or_default();
        let shards = v["shards"].as_array().cloned().unwrap_or_default();
        let most = nodes.iter().map(|n| shards.iter().filter(|s| s["node"].as_str() == n["name"].as_str()).count()).max().unwrap_or(1).max(1);
        let gap = 12.0;
        let avail = ui.available_width();
        let cols = ((avail + gap) / (u(330.0) + gap)).floor().clamp(1.0, nodes.len().max(1) as f32);
        let w = (avail + gap) / cols - gap - 0.5;
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = egui::vec2(gap, gap);
            for n in &nodes {
                let name = n["name"].as_str().unwrap_or("");
                let (r, _) = ui.allocate_exact_size(egui::vec2(w, u(176.0)), Sense::hover());
                let p = ui.painter();
                let lead = n["master"].as_str() == Some("*");
                p.rect_filled(r, CornerRadius::same(10), BG_CARD());
                p.rect_stroke(r, CornerRadius::same(10), Stroke::new(if lead { 2.0 } else { 1.0 }, if lead { SUCCESS() } else { BORDER_SUBTLE() }), egui::StrokeKind::Inside);
                label_at(ui, p, r.left_top() + egui::vec2(14.0, u(20.0)), name, 13.5, TEXT_DEFAULT(), r.width() - u(110.0));
                if lead {
                    p.text(r.right_top() + egui::vec2(-14.0, u(20.0)), egui::Align2::RIGHT_CENTER, "leading", FontId::proportional(z(12.0)), SUCCESS());
                }
                for (i, (label, k)) in [("Heap", "heap.percent"), ("CPU", "cpu"), ("Disk", "disk.used_percent")].iter().enumerate() {
                    let x = num(&n[*k]);
                    let c = egui::pos2(r.left() + r.width() * (0.18 + 0.32 * i as f32), r.top() + u(78.0));
                    let col = if x >= 90.0 { DANGER() } else if x >= 80.0 { WARNING() } else { [CPU_BAR(), INFO(), SUCCESS()][i] };
                    let rad = u(30.0);
                    p.circle_stroke(c, rad, Stroke::new(u(7.0), BG_MUTED()));
                    let sweep = (x / 100.0).clamp(0.0, 1.0) as f32 * std::f32::consts::TAU;
                    let pts: Vec<egui::Pos2> = (0..=48).map(|s| {
                        let a = -std::f32::consts::FRAC_PI_2 + sweep * s as f32 / 48.0;
                        c + egui::vec2(a.cos(), a.sin()) * rad
                    }).collect();
                    p.add(egui::Shape::line(pts, Stroke::new(u(7.0), col)));
                    p.text(c, egui::Align2::CENTER_CENTER, format!("{x:.0}%"), FontId::proportional(z(14.0)), TEXT_DEFAULT());
                    p.text(c + egui::vec2(0.0, rad + u(16.0)), egui::Align2::CENTER_CENTER, *label, FontId::proportional(z(11.5)), TEXT_SUBTLE());
                }
                let mine = shards.iter().filter(|s| s["node"].as_str() == Some(name)).count();
                let bar = egui::Rect::from_min_size(egui::pos2(r.left() + 14.0, r.bottom() - u(12.0)), egui::vec2(r.width() - 28.0, 4.0));
                p.rect_filled(bar, CornerRadius::same(2), BG_MUTED());
                p.rect_filled(egui::Rect::from_min_size(bar.min, egui::vec2(bar.width() * mine as f32 / most as f32, 4.0)), CornerRadius::same(2), PRIMARY_TEXT());
                label_at(ui, p, egui::pos2(r.left() + 14.0, r.bottom() - u(24.0)), &format!("{mine} shards  ·  {} of {} used", bytes(num(&n["disk.used"])), bytes(num(&n["disk.total"]))), 11.5, TEXT_SUBTLE(), r.width() - 28.0);
            }
        });
    }
}

fn es_activity(ui: &mut Ui, v: &Value, hist: &[(i64, f64, f64)]) {
    panel(ui, "Activity", "counted per shard, so one request can count several times");
    let rate = |f: fn(&(i64, f64, f64)) -> f64| -> Vec<f64> { hist.windows(2).map(|w| ((f(&w[1]) - f(&w[0])) / (w[1].0 - w[0].0).max(1) as f64).max(0.0)).collect() };
    let (s, w) = (rate(|h| h.1), rate(|h| h.2));
    if s.is_empty() {
        ui.add_space(14.0);
        ui.label(RichText::new("Collecting readings… (one every 15 seconds while this page is open)").size(z(12.5)).color(TEXT_SUBTLE()));
    } else {
        let per = |x: f64| format!("{x:.1}/s");
        ui.horizontal(|ui| {
            big(ui, &per(s[s.len() - 1]), "searches", PRIMARY_TEXT());
            ui.add_space(18.0);
            big(ui, &per(w[w.len() - 1]), "writes, copies included", SUCCESS());
        });
        ui.add_space(6.0);
        spark(ui, &s, u(48.0), PRIMARY_TEXT(), per);
        ui.add_space(4.0);
        spark(ui, &w, u(48.0), SUCCESS(), per);
    }
    let (q, ms) = (sum_stats(v, &["indices", "search", "query_total"]), sum_stats(v, &["indices", "search", "query_time_in_millis"]));
    if q > 0.0 {
        ui.add_space(4.0);
        ui.label(RichText::new(format!("a search takes {:.1} ms per shard on average since the nodes started", ms / q)).size(z(12.0)).color(TEXT_SUBTLE()));
    }
}

/// Where the space goes.
fn es_space(ui: &mut Ui, v: &Value) {
    let fam = families(v);
    let total: f64 = fam.iter().map(|f| f.size).sum();
    panel(ui, "Where the space goes", &format!("{} in {} indices, copies included; a data stream is one block", bytes(total), v["indices"].as_array().map(|a| a.len()).unwrap_or(0)));
    let (area, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(250.0)), Sense::hover());
    let mut top: Vec<Family> = fam.iter().take(40).cloned().collect();
    let rest: f64 = fam.iter().skip(40).map(|f| f.size).sum();
    if rest > 0.0 {
        top.push(Family { name: format!("{} more", fam.len() - 40), size: rest, docs: 0.0, indices: 0, worst: 0, system: true });
        top.sort_by(|a, b| b.size.partial_cmp(&a.size).unwrap_or(std::cmp::Ordering::Equal));
    }
    let sizes: Vec<f32> = top.iter().map(|f| f.size as f32).collect();
    for (i, (f, r)) in top.iter().zip(treemap(area, &sizes)).enumerate() {
        let r = r.shrink(1.5);
        if r.width() < 2.0 || r.height() < 2.0 {
            continue;
        }
        let resp = ui.interact(r, egui::Id::new(("es-map", i)), Sense::hover());
        let base = match f.worst { 2 => DANGER(), 1 => WARNING(), _ if f.system => TEXT_SUBTLE(), _ => CTX_PALETTE[i % CTX_PALETTE.len()] };
        let p = ui.painter();
        p.rect_filled(r, CornerRadius::same(5), base.gamma_multiply(if resp.hovered() { 0.42 } else { 0.26 }));
        p.rect_stroke(r, CornerRadius::same(5), Stroke::new(1.0, base.gamma_multiply(0.7)), egui::StrokeKind::Inside);
        if r.width() > u(70.0) && r.height() > u(38.0) {
            label_at(ui, p, r.left_top() + egui::vec2(8.0, u(14.0)), &f.name, 12.0, TEXT_DEFAULT(), r.width() - 16.0);
            label_at(ui, p, r.left_top() + egui::vec2(8.0, u(30.0)), &bytes(f.size), 11.0, TEXT_MUTED(), r.width() - 16.0);
        }
        resp.on_hover_text(format!("{}\n{} ({:.1}%)\n{} documents in {} indices", f.name, bytes(f.size), f.size / total.max(1.0) * 100.0, f.docs as i64, f.indices));
    }
}

fn es_table(ui: &mut Ui, v: &Value) {
    let bad: Vec<&Value> = v["shards"].as_array().into_iter().flatten().filter(|s| s["state"].as_str() != Some("STARTED")).collect();
    if !bad.is_empty() {
        panel(ui, "Shards on the move or without a place", "");
        for s in bad.iter().take(12) {
            ui.label(RichText::new(format!("{} #{} {} {} {}", s["index"].as_str().unwrap_or(""), s["shard"].as_str().unwrap_or(""), if s["prirep"] == "p" { "main" } else { "copy" }, s["state"].as_str().unwrap_or("").to_lowercase(), s["unassigned.reason"].as_str().unwrap_or(""))).size(z(12.5)).color(WARNING()));
        }
        ui.add_space(8.0);
    }
    panel(ui, "Biggest", "");
    for f in families(v).iter().take(12) {
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(24.0)), Sense::hover());
            let p = ui.painter();
            let w = r.width();
            label_at(ui, p, r.left_center(), &f.name, 13.0, match f.worst { 2 => DANGER(), 1 => WARNING(), _ => TEXT_DEFAULT() }, w * 0.5);
            label_at(ui, p, egui::pos2(r.left() + w * 0.55, r.center().y), &bytes(f.size), 13.0, TEXT_MUTED(), w * 0.12);
            label_at(ui, p, egui::pos2(r.left() + w * 0.68, r.center().y), &format!("{} documents", pulsar::count(f.docs)), 13.0, TEXT_MUTED(), w * 0.17);
            label_at(ui, p, egui::pos2(r.left() + w * 0.86, r.center().y), &format!("{} {}", f.indices, if f.indices == 1 { "index" } else { "indices" }), 13.0, TEXT_SUBTLE(), w * 0.13);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(status: &str, disk: &str, expiry: f64) -> Value {
        serde_json::json!({
            "health": {"status": status, "active_shards": 10, "unassigned_shards": 2, "unassigned_primary_shards": 1, "number_of_data_nodes": 3, "number_of_pending_tasks": 0},
            "nodes": (0..3).map(|i| serde_json::json!({"name": format!("n{i}"), "node.role": "dim", "heap.percent": "40", "cpu": "10", "disk.used_percent": disk})).collect::<Vec<_>>(),
            "indices": [{"index": ".ds-logs-app-2026.11.17-000031", "health": "green", "rep": "1", "docs.count": "5", "store.size": "100"}, {"index": ".ds-logs-app-2026.11.18-000032", "health": "yellow", "rep": "1", "docs.count": "5", "store.size": "50"}, {"index": "shop", "health": "green", "rep": "1", "docs.count": "1", "store.size": "20"}],
            "stats": {"nodes": {"a": {"indices": {"search": {"query_total": 4}, "indexing": {"index_total": 7}}}, "b": {"indices": {"search": {"query_total": 6}, "indexing": {"index_total": 1}}}}},
            "license": {"license": {"type": "enterprise", "expiry_date_in_millis": expiry}}
        })
    }

    #[test]
    fn reads() {
        let now = 1_000_000_000;
        let far = (now as f64 + 100.0 * 86400.0) * 1000.0;
        let ok = data("green", "30", far);
        assert!(checks(&ok, now).iter().all(|c| c.tone == Tone::Success), "{:?}", checks(&ok, now));
        assert_eq!(reading(&ok), (10.0, 8.0));
        let f = families(&ok);
        assert_eq!((f[0].name.as_str(), f[0].size, f[0].indices, f[0].worst), ("logs-app", 150.0, 2, 1));
        assert_eq!(family(".ds-x-y"), "x-y");
        let mut bad = data("red", "92", (now as f64 + 5.0 * 86400.0) * 1000.0);
        bad["indices"][2]["rep"] = "0".into();
        let r = checks(&bad, now);
        for t in ["Red", "Disk filling up", "Licence about to expire"] {
            assert!(r.iter().any(|c| c.title == t && c.tone == Tone::Danger), "{t} {r:?}");
        }
        assert!(r.iter().any(|c| c.title == "Indices without a copy"));
        assert!(!checks(&Value::Null, now).is_empty());
    }

    #[test]
    fn map_fills_the_area() {
        let a = egui::Rect::from_min_size(egui::pos2(5.0, 7.0), egui::vec2(300.0, 120.0));
        let sizes = [50.0, 30.0, 20.0, 5.0, 1.0, 0.0];
        let r = treemap(a, &sizes);
        assert_eq!(r.len(), sizes.len());
        let sum: f32 = r.iter().map(|x| x.area()).sum();
        assert!((sum - a.area()).abs() < 5.0, "{sum}");
        assert!(r.iter().all(|x| a.expand(0.5).contains_rect(*x)), "{r:?}");
        assert!((r[0].area() / a.area() - 50.0 / 106.0).abs() < 0.01);
        assert_eq!(treemap(a, &[]).len(), 0);
    }
}
