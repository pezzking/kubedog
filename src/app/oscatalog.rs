//! OpenShift's software catalog: operators that can be installed, templates, images and Helm
//! repositories. Browsing only; what to install is given as text.

use super::face::many;
use super::incident::chip_button;
use super::ops::{ns_of, text};
use super::pg::{label_at, panel, pill};
use super::podxray::Go;
use super::work::{name_of, said};
use super::*;

const KINDS: [&str; 4] = ["Operators", "Templates", "Images", "Helm repositories"];
/// The step in which cards are shown.
const STEP: usize = 60;

#[derive(Default)]
pub(super) struct Catalog {
    kind: usize,
    category: String,
    source: String,
    installed: bool,
    shown: usize,
    /// (cluster, catalog, package).
    pub pick: Option<(String, String, String)>,
    channel: String,
    manual: bool,
    started: bool,
}

/// What's kept of an offered operator.
pub(super) fn slim(items: &[Value]) -> Value {
    Value::Array(items.iter().map(|o| {
        let st = &o["status"];
        let def = text(&st["defaultChannel"]);
        let chans = st["channels"].as_array().cloned().unwrap_or_default();
        let c = chans.iter().find(|c| c["name"] == def.as_str()).or(chans.first()).cloned().unwrap_or_default();
        let d = &c["currentCSVDesc"];
        let a = &d["annotations"];
        let list = |v: &Value| -> Vec<String> { v.as_str().unwrap_or("").split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect() };
        serde_json::json!({
            "name": text(&st["packageName"]),
            "catalog": text(&st["catalogSource"]),
            "catalogNs": text(&st["catalogSourceNamespace"]),
            "from": text(&st["catalogSourceDisplayName"]),
            "provider": text(&st["provider"]["name"]),
            "display": d["displayName"].as_str().filter(|s| !s.is_empty()).unwrap_or(st["packageName"].as_str().unwrap_or("")),
            "short": truncate(&a["description"].as_str().filter(|s| !s.trim().is_empty()).or(d["description"].as_str().and_then(|t| t.lines().map(|l| l.trim().trim_start_matches(['#', ' '])).find(|l| l.len() > 30 && !l.starts_with(['!', '[', '<'])))).unwrap_or("").split_whitespace().collect::<Vec<_>>().join(" "), 240),
            "long": truncate(d["description"].as_str().unwrap_or(""), 2400),
            "cats": list(&a["categories"]),
            "level": text(&a["capabilities"]),
            "created": text(&a["createdAt"]),
            "suggested": text(&a["operatorframework.io/suggested-namespace"]),
            "modes": d["installModes"].as_array().into_iter().flatten().filter(|m| m["supported"] == true).map(|m| text(&m["type"])).collect::<Vec<_>>(),
            "version": text(&d["version"]),
            "default": def,
            "channels": chans.iter().map(|c| serde_json::json!({"name": c["name"], "version": c["currentCSVDesc"]["version"], "csv": c["currentCSV"], "old": c["deprecation"]["message"]})).collect::<Vec<_>>(),
            "old": st["deprecation"]["message"],
            "kinds": d["customresourcedefinitions"]["owned"].as_array().into_iter().flatten().map(|k| text(&k["kind"])).collect::<Vec<_>>(),
            "needs": d["customresourcedefinitions"]["required"].as_array().into_iter().flatten().map(|k| text(&k["kind"])).collect::<Vec<_>>(),
            "kube": text(&d["minKubeVersion"]),
        })
    }).collect())
}

/// Templates, images and Helm repositories: names and words only. (A template's objects aren't kept.)
pub(super) fn slim_more(templates: &[Value], images: &[Value], helm: &[Value]) -> Value {
    let a = |o: &Value, k: &str| text(&o["metadata"]["annotations"][k]);
    serde_json::json!({
        "templates": templates.iter().map(|o| serde_json::json!({"name": name_of(o), "display": a(o, "openshift.io/display-name"), "text": truncate(&a(o, "description"), 400), "tags": a(o, "tags"), "by": a(o, "openshift.io/provider-display-name")})).collect::<Vec<_>>(),
        "images": images.iter().map(|o| {
            let tags: Vec<&Value> = o["spec"]["tags"].as_array().into_iter().flatten().collect();
            let builder = tags.iter().any(|t| t["annotations"]["tags"].as_str().unwrap_or("").contains("builder"));
            let bad = o["status"]["tags"].as_array().into_iter().flatten().filter(|t| t["conditions"].as_array().into_iter().flatten().any(|c| c["type"] == "ImportSuccess" && c["status"] == "False")).map(|t| text(&t["tag"])).collect::<Vec<_>>();
            serde_json::json!({"name": name_of(o), "display": a(o, "openshift.io/display-name"), "tags": tags.iter().map(|t| text(&t["name"])).collect::<Vec<_>>(), "builder": builder, "bad": bad})
        }).collect::<Vec<_>>(),
        "helm": helm.iter().map(|o| serde_json::json!({"name": name_of(o), "display": text(&o["spec"]["name"]), "url": text(&o["spec"]["connectionConfig"]["url"]), "off": o["spec"]["disabled"]})).collect::<Vec<_>>(),
    })
}

/// Its catalog or its maker says not to use it any more.
fn deprecated(p: &Value) -> bool {
    p["old"].as_str().map(|s| !s.is_empty()).unwrap_or(false) || ["display", "short"].iter().any(|k| p[*k].as_str().unwrap_or("").to_lowercase().starts_with("[deprecated"))
}

/// Something to know before choosing this one.
fn warnings(p: &Value, all: &[Value], now: i64) -> Vec<(Tone, String)> {
    let mut v = vec![];
    if let Some(m) = p["old"].as_str().filter(|m| !m.is_empty()) {
        v.push((Tone::Danger, format!("Deprecated: {m}")));
    } else if deprecated(p) {
        v.push((Tone::Danger, "Its maker calls it deprecated".into()));
    }
    if let Some(t) = pod::time_of(&p["created"]).filter(|t| now - t > 2 * 365 * 86400) {
        v.push((Tone::Warning, format!("Its newest version is {} years old", (now - t) / (365 * 86400))));
    }
    let other: Vec<String> = all.iter().filter(|x| x["name"] == p["name"] && x["catalog"] != p["catalog"]).map(|x| format!("{} ({})", text(&x["catalog"]), text(&x["version"]))).collect();
    if !other.is_empty() {
        v.push((Tone::Info, format!("Also in {}: so a subscription has to name its catalog", other.join(", "))));
    }
    let modes: Vec<&str> = p["modes"].as_array().into_iter().flatten().filter_map(|m| m.as_str()).collect();
    if modes == ["AllNamespaces"] {
        v.push((Tone::Info, "It always watches every namespace".into()));
    }
    if p["level"] == "Basic Install" {
        v.push((Tone::Info, "Its own words: basic install only. Updates of what it runs are up to you".into()));
    }
    let needs: Vec<&str> = p["needs"].as_array().into_iter().flatten().filter_map(|m| m.as_str()).collect();
    if !needs.is_empty() {
        v.push((Tone::Info, format!("It needs another operator that brings {}", needs.join(", "))));
    }
    v
}

/// The numbers of a version, to compare them.
fn numbers(v: &str) -> Vec<u64> {
    v.split(|c: char| !c.is_ascii_digit()).filter(|x| !x.is_empty()).take(4).filter_map(|x| x.parse().ok()).collect()
}

fn yaml_word(s: &str) -> String {
    let plain = !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_')) && s.as_bytes()[0].is_ascii_alphabetic() && !matches!(s.to_lowercase().as_str(), "true" | "false" | "yes" | "no" | "on" | "off" | "null" | "y" | "n");
    if plain { s.to_string() } else { format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace(['\n', '\r'], " ")) }
}

/// What to apply to install it: a namespace, an operator group where one is needed, and the subscription.
fn install(p: &Value, channel: &str, manual: bool) -> String {
    let w = |k: &str| yaml_word(p[k].as_str().unwrap_or(""));
    let modes: Vec<&str> = p["modes"].as_array().into_iter().flatten().filter_map(|m| m.as_str()).collect();
    let all = modes.contains(&"AllNamespaces");
    let suggested = p["suggested"].as_str().unwrap_or("");
    // The shared namespace has a group that watches everything; its own is clearer.
    let ns = yaml_word(if !suggested.is_empty() { suggested } else if all { "openshift-operators" } else { p["name"].as_str().unwrap_or("") });
    let mut t = String::new();
    if ns != "openshift-operators" {
        let target = if all { "spec: {}\n".to_string() } else { format!("spec:\n  targetNamespaces:\n    - {ns}\n") };
        t.push_str(&format!("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {ns}\n---\napiVersion: operators.coreos.com/v1\nkind: OperatorGroup\nmetadata:\n  name: {ns}\n  namespace: {ns}\n{target}---\n"));
    }
    t.push_str(&format!("apiVersion: operators.coreos.com/v1alpha1\nkind: Subscription\nmetadata:\n  name: {}\n  namespace: {ns}\nspec:\n  name: {}\n  channel: {}\n  source: {}\n  sourceNamespace: {}\n  installPlanApproval: {}\n", w("name"), w("name"), yaml_word(channel), w("catalog"), w("catalogNs"), if manual { "Manual" } else { "Automatic" }));
    t
}

impl KubedogApp {
    /// Read when the tab is opened: it's a lot.
    pub(super) fn ask_catalog(&mut self, c: &str, force: bool) {
        let get = |what: &str, more: &[&str]| -> Vec<String> { ["--context", c, "get", what, "-o", "json", "--request-timeout=60s"].iter().map(|s| s.to_string()).chain(more.iter().map(|s| s.to_string())).collect() };
        // (Every namespace has the same ones; one is enough.)
        let a = get("packagemanifests.packages.operators.coreos.com", &["-n", "openshift-marketplace"]);
        self.ask(&format!("oscat|{c}"), 1800, force, move |k| Ok(slim(&kube::parse_items(&k.run(&a)?)?).to_string()));
        let (t, i, h) = (get("templates.template.openshift.io", &["-n", "openshift"]), get("imagestreams.image.openshift.io", &["-n", "openshift"]), get("helmchartrepositories.helm.openshift.io", &[]));
        self.ask(&format!("oscat2|{c}"), 1800, force, move |k| {
            let l = |a: &[String]| k.run(a).and_then(|j| kube::parse_items(&j)).unwrap_or_default();
            Ok(slim_more(&l(&t), &l(&i), &l(&h)).to_string())
        });
    }

    /// The subscriptions of a cluster to this package: (from this catalog, the subscription).
    fn subscribed(&self, ctx: &str, p: &Value) -> Vec<(bool, &Value)> {
        self.op_all(ctx, openshift::SUBS).iter().filter(|s| s["spec"]["name"] == p["name"]).map(|s| (s["spec"]["source"] == p["catalog"], s)).collect()
    }

    pub(super) fn os_catalog(&mut self, ui: &mut Ui, ctxs: &[String]) -> Option<Go> {
        let mut go = None;
        if !self.catalog.started {
            self.catalog.started = true;
            self.catalog.manual = true;
            self.catalog.shown = STEP;
        }
        for c in ctxs {
            self.ask_catalog(c, false);
        }
        if self.screenshot.is_some() && self.catalog.pick.is_none() {
            if let (Ok(n), Some(c)) = (std::env::var("KUBEDOG_SHOT_OBJ"), ctxs.first()) {
                if let Some(p) = self.answer(&format!("oscat|{c}")).and_then(|r| r.as_ref().ok()).and_then(|v| v.as_array()).into_iter().flatten().find(|p| p["name"] == n.as_str()) {
                    self.catalog.pick = Some((c.clone(), text(&p["catalog"]), n));
                }
            }
        }
        if let Some(p) = self.catalog.pick.clone() {
            return self.os_offer(ui, &p);
        }
        ui.horizontal_wrapped(|ui| {
            for (i, t) in KINDS.iter().enumerate() {
                if chip_button(ui, t, self.catalog.kind == i) {
                    self.catalog.kind = i;
                    self.catalog.shown = STEP;
                }
            }
        });
        ui.add_space(6.0);
        if self.catalog.kind > 0 {
            for c in ctxs {
                self.os_more(ui, c, ctxs.len() > 1);
            }
            return None;
        }
        let q = self.search.to_lowercase();
        for c in ctxs {
            let list = match self.answer(&format!("oscat|{c}")) {
                Some(Ok(Value::Array(l))) => l,
                Some(Err(e)) => {
                    said(ui, &format!("The catalog of {} couldn't be read: {}", ctx_label(c), truncate(e, 240)), WARNING());
                    continue;
                }
                _ => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        said(ui, "Reading the catalog; it's big, so this takes a moment…", TEXT_SUBTLE());
                    });
                    continue;
                }
            };
            let mut cats: HashMap<String, usize> = HashMap::new();
            let mut sources: HashMap<String, usize> = HashMap::new();
            for p in list {
                for x in p["cats"].as_array().into_iter().flatten().filter_map(|x| x.as_str()) {
                    *cats.entry(x.to_string()).or_default() += 1;
                }
                *sources.entry(text(&p["catalog"])).or_default() += 1;
            }
            let mut cats: Vec<(String, usize)> = cats.into_iter().collect();
            cats.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            let mut sources: Vec<(String, usize)> = sources.into_iter().collect();
            sources.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            let installed = |p: &Value| self.subscribed(c, p).iter().any(|s| s.0);
            let hit = |p: &Value| {
                (self.catalog.category.is_empty() || p["cats"].as_array().into_iter().flatten().any(|x| x == self.catalog.category.as_str()))
                    && (self.catalog.source.is_empty() || p["catalog"] == self.catalog.source.as_str())
                    && (q.is_empty() || ["display", "name", "provider", "short"].iter().any(|k| p[*k].as_str().unwrap_or("").to_lowercase().contains(&q)) || p["kinds"].as_array().into_iter().flatten().any(|k| k.as_str().unwrap_or("").to_lowercase().contains(&q)))
                    && (!self.catalog.installed || installed(p))
            };
            let mut found: Vec<&Value> = list.iter().filter(|p| hit(p)).collect();
            // What's installed first, then what has the searched word in its name.
            found.sort_by_cached_key(|p| (!installed(p), deprecated(p), !q.is_empty() && !p["display"].as_str().unwrap_or("").to_lowercase().contains(&q), p["display"].as_str().unwrap_or("").to_lowercase(), text(&p["catalog"])));
            // Only what's shown is copied.
            let count = found.len();
            let found: Vec<Value> = found.into_iter().take(self.catalog.shown).cloned().collect();
            let mine: Vec<Option<String>> = found.iter().map(|p| self.subscribed(c, p).into_iter().find(|s| s.0).map(|s| text(&s.1["status"]["installedCSV"]))).collect();
            let total = list.len();
            let (mut cat, mut src, mut only) = (self.catalog.category.clone(), self.catalog.source.clone(), self.catalog.installed);
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut only, "Only installed");
                ui.add_space(8.0);
                for (s, n) in &sources {
                    if chip_button(ui, &format!("{s} ({n})"), src == *s) {
                        src = if src == *s { String::new() } else { s.clone() };
                    }
                }
            });
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                for (s, n) in cats.iter().take(22) {
                    if chip_button(ui, &format!("{s} ({n})"), cat == *s) {
                        cat = if cat == *s { String::new() } else { s.clone() };
                    }
                }
            });
            if cat != self.catalog.category || src != self.catalog.source || only != self.catalog.installed {
                self.catalog.category = cat;
                self.catalog.source = src;
                self.catalog.installed = only;
                self.catalog.shown = STEP;
            }
            ui.add_space(8.0);
            said(ui, &format!("{}{}. Search with the filter above, also by the kinds they bring.", if ctxs.len() > 1 { format!("{}: ", ctx_label(c)) } else { String::new() }, if count == total { many(total as i64, "operator") } else { format!("{} of {}", count, many(total as i64, "operator")) }), TEXT_SUBTLE());
            ui.add_space(8.0);
            let n = found.len();
            let mut pick = None;
            dash::grid(ui, n, u(320.0), u(150.0), 12.0, |ui, i, r| {
                let p = &found[i];
                let resp = ui.interact(r, ui.id().with(("offer", c, &p["catalog"], &p["name"])), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                let here = mine[i].is_some();
                let pt = ui.painter();
                pt.rect(r, CornerRadius::same(10), if resp.hovered() { BG_HOVER() } else { BG_CARD() }, Stroke::new(1.0, if resp.hovered() { PRIMARY_TEXT() } else if here { SUCCESS().gamma_multiply(0.6) } else { BORDER_SUBTLE() }), egui::StrokeKind::Inside);
                let (x, w) = (r.left() + u(14.0), r.width() - u(28.0));
                label_at(ui, pt, egui::pos2(x, r.top() + u(22.0)), p["display"].as_str().unwrap_or(""), 14.5, PRIMARY_TEXT(), w - if here { u(76.0) } else { 0.0 });
                if here {
                    pt.text(egui::pos2(r.right() - u(14.0), r.top() + u(22.0)), egui::Align2::RIGHT_CENTER, "installed", FontId::proportional(z(12.0)), SUCCESS());
                }
                label_at(ui, pt, egui::pos2(x, r.top() + u(42.0)), &format!("{}{}", text(&p["provider"]), if deprecated(p) { "  ·  deprecated" } else { "" }), 12.0, TEXT_SUBTLE(), w);
                let mut job = egui::text::LayoutJob::simple(text(&p["short"]), FontId::proportional(z(12.5)), TEXT_MUTED(), w);
                job.wrap.max_rows = 3;
                let g = pt.layout_job(job);
                pt.galley(egui::pos2(x, r.top() + u(56.0)), g, TEXT_MUTED());
                label_at(ui, pt, egui::pos2(x, r.bottom() - u(16.0)), &format!("{}  ·  {}  ·  {}", text(&p["version"]), text(&p["catalog"]), text(&p["level"])), 11.5, TEXT_PLACEHOLDER(), w);
                if resp.clicked() {
                    pick = Some((c.clone(), text(&p["catalog"]), text(&p["name"])));
                }
            });
            ui.add_space(8.0);
            if count > n && button(ui, &format!("Show more ({} left)", count - n), false, false) {
                self.catalog.shown += STEP * 2;
            }
            ui.add_space(14.0);
            if pick.is_some() {
                self.catalog.channel.clear();
                self.catalog.pick = pick;
            }
        }
        go.take()
    }

    /// One offered operator.
    fn os_offer(&mut self, ui: &mut Ui, (ctx, cat, name): &(String, String, String)) -> Option<Go> {
        let mut go = None;
        let mut close = ui.input(|i| i.key_pressed(Key::Escape)) && self.dialog.is_none() && self.palette.is_none();
        ui.horizontal(|ui| {
            close |= back_button(ui).on_hover_text("The catalog (Esc)").clicked();
            ui.label(RichText::new(format!("{} · Catalog", ctx_label(ctx))).size(z(12.0)).color(TEXT_SUBTLE()));
        });
        let all: &[Value] = self.answer(&format!("oscat|{ctx}")).and_then(|r| r.as_ref().ok()).and_then(|v| v.as_array()).map(|v| v.as_slice()).unwrap_or(&[]);
        let found = all.iter().find(|p| p["name"] == name.as_str() && p["catalog"] == cat.as_str()).map(|p| (p.clone(), warnings(p, all, kube::now_secs())));
        let Some((p, known)) = found else {
            said(ui, "It isn't in the catalog any more.", TEXT_SUBTLE());
            if close {
                self.catalog.pick = None;
            }
            return None;
        };
        if close {
            self.catalog.pick = None;
            return None;
        }
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(text(&p["display"])).size(z(20.0)).strong().color(TEXT_DEFAULT()));
            ui.label(RichText::new(format!("by {}", text(&p["provider"]))).size(z(13.0)).color(TEXT_SUBTLE()));
            pill(ui, &text(&p["from"]), TEXT_SUBTLE());
            if !text(&p["level"]).is_empty() {
                pill(ui, &text(&p["level"]), INFO());
            }
        });
        said(ui, &text(&p["short"]), TEXT_MUTED());
        ui.add_space(8.0);
        let subs: Vec<(bool, Value)> = self.subscribed(ctx, &p).into_iter().map(|s| (s.0, s.1.clone())).collect();
        for (same, s) in &subs {
            card(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.painter().circle_filled(ui.cursor().min + egui::vec2(6.0, 11.0), u(4.5), if *same { SUCCESS() } else { WARNING() });
                    ui.add_space(18.0);
                    ui.label(RichText::new(format!("Installed in {}{}: {}", ns_of(s), if *same { String::new() } else { format!(", from {}", text(&s["spec"]["source"])) }, text(&s["status"]["installedCSV"]))).size(z(14.0)).color(TEXT_DEFAULT()));
                    let ch = text(&s["spec"]["channel"]);
                    ui.label(RichText::new(format!("channel {ch}, updates {}", text(&s["spec"]["installPlanApproval"]).to_lowercase())).size(z(12.5)).color(TEXT_SUBTLE()));
                    if button(ui, "Open the subscription", false, false) {
                        go = self.custom_go(ctx, openshift::SUBS, s);
                    }
                });
                let ch = text(&s["spec"]["channel"]);
                if *same && !ch.is_empty() && p["default"] != ch.as_str() {
                    said(ui, &format!("It follows channel {ch}; the one that's advised is {}.", text(&p["default"])), WARNING());
                }
            });
            ui.add_space(6.0);
        }
        for (t, w) in known {
            said(ui, &w, match t { Tone::Danger => DANGER(), Tone::Warning => WARNING(), _ => INFO() });
        }
        ui.add_space(8.0);
        // The advised one first, then the newest.
        let mut sorted: Vec<&Value> = p["channels"].as_array().into_iter().flatten().collect();
        sorted.sort_by_key(|c| (c["name"] != p["default"], std::cmp::Reverse(numbers(c["version"].as_str().unwrap_or("")))));
        let many_chans = sorted.len();
        let mut chans: Vec<ops::Item> = sorted.into_iter().map(|c| {
            let old = text(&c["old"]);
            ops::Item::new(if !old.is_empty() { Tone::Warning } else if c["name"] == p["default"] { Tone::Success } else { Tone::Muted }, vec![text(&c["name"]), text(&c["version"]), if c["name"] == p["default"] { "advised".into() } else { String::new() }, old])
        }).collect();
        chans.truncate(8);
        ops::table(ui, &format!("Channels ({many_chans})"), if many_chans > 8 { "a subscription follows one of them; the newest are here" } else { "a subscription follows one of them" }, &[("Channel", 0.3), ("Newest version", 0.25), ("", 0.15), ("", 0.3)], &chans, 8, "None.");
        let kinds: Vec<String> = p["kinds"].as_array().into_iter().flatten().map(text).collect();
        card(ui, |ui| {
            panel(ui, "What it brings", "");
            said(ui, &if kinds.is_empty() { "No kinds of its own.".to_string() } else { format!("Kinds: {}.", kinds.join(", ")) }, TEXT_MUTED());
            let m: Vec<String> = p["modes"].as_array().into_iter().flatten().map(|m| match m.as_str().unwrap_or("") { "OwnNamespace" => "its own namespace", "SingleNamespace" => "one other namespace", "MultiNamespace" => "several namespaces", _ => "every namespace" }.to_string()).collect();
            said(ui, &format!("It can watch {}.{}{}", m.join(", "), if text(&p["suggested"]).is_empty() { String::new() } else { format!(" It likes to be in namespace {}.", text(&p["suggested"])) }, if text(&p["kube"]).is_empty() { String::new() } else { format!(" Needs Kubernetes {} or newer.", text(&p["kube"])) }), TEXT_MUTED());
        });
        ui.add_space(10.0);
        if !subs.is_empty() {
            if !subs.iter().any(|s| s.0) {
                said(ui, "It's installed from another catalog already: two of them would get in each other's way.", WARNING());
                ui.add_space(8.0);
            }
        } else {
            card(ui, |ui| {
                panel(ui, "To install it", "Kubedog doesn't install: copy this into Git, or look it through and apply it yourself");
                if self.catalog.channel.is_empty() || !p["channels"].as_array().into_iter().flatten().any(|c| c["name"] == self.catalog.channel.as_str()) {
                    self.catalog.channel = text(&p["default"]);
                }
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Channel").size(z(13.0)).color(TEXT_MUTED()));
                    egui::ComboBox::from_id_salt("offer-channel").selected_text(self.catalog.channel.clone()).show_ui(ui, |ui| {
                        for c in p["channels"].as_array().into_iter().flatten() {
                            ui.selectable_value(&mut self.catalog.channel, text(&c["name"]), text(&c["name"]));
                        }
                    });
                    ui.checkbox(&mut self.catalog.manual, "Updates wait for approval");
                });
                let t = install(&p, &self.catalog.channel, self.catalog.manual);
                let grouped = t.contains("OperatorGroup");
                Frame::new().fill(LOG_BG()).corner_radius(CornerRadius::same(6)).inner_margin(Margin::same(10)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.add(egui::Label::new(RichText::new(t.trim_end()).font(FontId::monospace(z(12.5))).color(TEXT_DEFAULT())).selectable(true));
                });
                ui.add_space(4.0);
                if button(ui, "Copy", false, false) {
                    ui.ctx().copy_text(t);
                    self.toast("Copied".into(), false);
                }
                said(ui, &format!("An operator gets the rights its maker asks for, often over the whole cluster.{}", if grouped { " If the namespace already has an operator group, leave out the one above." } else { "" }), WARNING());
            });
            ui.add_space(10.0);
        }
        let long = text(&p["long"]);
        if !long.is_empty() {
            card(ui, |ui| {
                panel(ui, "In its maker's words", "");
                // As plain text: no links, no pictures.
                let t = long.lines().filter(|l| !l.trim_start().starts_with("![") && !l.trim_start().starts_with("[![")).map(|l| l.trim_start_matches('#').trim_end()).collect::<Vec<_>>().join("\n");
                said(ui, t.trim(), TEXT_MUTED());
            });
        }
        go
    }

    fn os_more(&self, ui: &mut Ui, c: &str, name: bool) {
        let Some(Ok(v)) = self.answer(&format!("oscat2|{c}")) else {
            said(ui, "Reading…", TEXT_SUBTLE());
            return;
        };
        let q = self.search.to_lowercase();
        let head = |t: &str, n: usize| if name { format!("{t} of {} ({n})", ctx_label(c)) } else { format!("{t} ({n})") };
        let hit = |i: &ops::Item| q.is_empty() || i.cells.iter().any(|x| x.to_lowercase().contains(&q));
        let rows = |k: &str| v[k].as_array().cloned().unwrap_or_default();
        match self.catalog.kind {
            1 => {
                let l: Vec<ops::Item> = rows("templates").iter().map(|o| ops::Item::new(Tone::Normal, vec![text(&o["name"]), text(&o["display"]), text(&o["text"]), text(&o["tags"]), text(&o["by"])])).filter(hit).collect();
                ops::table(ui, &head("Templates", l.len()), "ready sets of objects, in namespace openshift", &[("Template", 0.2), ("Name", 0.2), ("What it is", 0.34), ("Tags", 0.16), ("By", 0.1)], &l, 200, "None, or your account can't see them.");
            }
            2 => {
                let mut l: Vec<ops::Item> = rows("images").iter().map(|o| {
                    let bad: Vec<String> = o["bad"].as_array().into_iter().flatten().map(text).collect();
                    let tags: Vec<String> = o["tags"].as_array().into_iter().flatten().map(text).collect();
                    ops::Item::new(if bad.is_empty() { Tone::Success } else { Tone::Warning }, vec![text(&o["name"]), if bad.is_empty() { "fine".into() } else { format!("can't be imported: {}", some_names(&bad)) }, if o["builder"] == true { "builds apps".into() } else { String::new() }, tags.join(", ")])
                }).filter(hit).collect();
                ops::worst_first(&mut l);
                ops::table(ui, &head("Images", l.len()), "image streams in namespace openshift", &[("Image", 0.25), ("State", 0.25), ("", 0.12), ("Tags", 0.38)], &l, 200, "None, or your account can't see them.");
            }
            _ => {
                let l: Vec<ops::Item> = rows("helm").iter().map(|o| ops::Item::new(if o["off"] == true { Tone::Muted } else { Tone::Success }, vec![text(&o["name"]), if o["off"] == true { "off".into() } else { "on".into() }, text(&o["display"]), text(&o["url"])])).filter(hit).collect();
                ops::table(ui, &head("Helm repositories", l.len()), "their charts aren't listed: Kubedog doesn't go out to them", &[("Repository", 0.25), ("State", 0.1), ("Name", 0.25), ("Address", 0.4)], &l, 100, "None, or your account can't see them.");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pkg() -> Value {
        slim(&[json!({"metadata": {"name": "a"}, "status": {"packageName": "a", "catalogSource": "cat", "catalogSourceNamespace": "openshift-marketplace", "catalogSourceDisplayName": "Cat", "provider": {"name": "P"}, "defaultChannel": "stable", "channels": [
            {"name": "old", "currentCSV": "a.v1", "currentCSVDesc": {"version": "1.0.0"}},
            {"name": "stable", "currentCSV": "a.v2", "currentCSVDesc": {"version": "2.0.0", "displayName": "App", "description": "# Long", "installModes": [{"type": "OwnNamespace", "supported": true}, {"type": "AllNamespaces", "supported": false}], "customresourcedefinitions": {"owned": [{"kind": "Thing"}], "required": [{"kind": "Other"}]}, "annotations": {"description": "Short", "categories": "Database, Storage", "capabilities": "Basic Install", "createdAt": "2020-01-01T00:00:00Z", "alm-examples": "big"}}}
        ]}})])[0].clone()
    }

    #[test]
    fn what_is_kept() {
        let p = pkg();
        assert_eq!((p["display"].as_str(), p["version"].as_str(), p["default"].as_str()), (Some("App"), Some("2.0.0"), Some("stable")));
        assert_eq!((p["cats"].clone(), p["modes"].clone(), p["kinds"].clone()), (json!(["Database", "Storage"]), json!(["OwnNamespace"]), json!(["Thing"])));
        assert!(!p.to_string().contains("big") && p["channels"].as_array().unwrap().len() == 2);
        let m = slim_more(&[json!({"metadata": {"name": "t", "annotations": {"description": "d"}}, "objects": [{"data": "made-up"}], "parameters": [{"value": "made-up"}]})], &[json!({"metadata": {"name": "i"}, "spec": {"tags": [{"name": "1", "annotations": {"tags": "builder,x"}}]}, "status": {"tags": [{"tag": "1", "conditions": [{"type": "ImportSuccess", "status": "False"}]}]}})], &[]);
        assert!(!m.to_string().contains("made-up") && m["images"][0]["builder"] == true && m["images"][0]["bad"][0] == "1");
    }

    #[test]
    fn to_know() {
        let p = pkg();
        let mut other = p.clone();
        other["catalog"] = json!("second");
        let now = kube::parse_time("2026-01-01T00:00:00Z").unwrap();
        let t = warnings(&p, &[p.clone(), other], now).into_iter().map(|w| w.1).collect::<Vec<_>>().join("\n");
        assert!(deprecated(&json!({"display": "[DEPRECATED] X"})) && !deprecated(&p));
        for w in ["6 years old", "Also in second", "basic install", "brings Other"] {
            assert!(t.contains(w), "{w}\n{t}");
        }
    }

    #[test]
    fn text_to_install() {
        let mut p = pkg();
        let t = install(&p, "stable", true);
        assert!(t.contains("kind: OperatorGroup") && t.contains("targetNamespaces:\n    - a") && t.contains("installPlanApproval: Manual") && t.contains("sourceNamespace: openshift-marketplace") && t.contains("channel: stable"));
        // Everything: the shared namespace, which has its group.
        p["modes"] = json!(["AllNamespaces"]);
        let t = install(&p, "4.10", false);
        assert!(!t.contains("OperatorGroup") && t.contains("namespace: openshift-operators") && t.contains("channel: \"4.10\"") && t.contains("Automatic"));
        p["suggested"] = json!("own");
        assert!(install(&p, "x", true).contains("namespace: own\nspec: {}"));
        // A catalog's text can't add lines of its own.
        p["name"] = json!("a\nkind: Secret");
        assert!(!install(&p, "x\n---", true).contains("\nkind: Secret") && !install(&p, "x\n---\n", true).contains("\"x\n"));
        assert!(numbers("0.51.0") > numbers("0.9.2"));
        assert_eq!((yaml_word("yes"), yaml_word("stable-4.2")), ("\"yes\"".into(), "stable-4.2".into()));
    }
}
