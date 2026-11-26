//! A pod's Network and Environment sections (Kubedog additions): the services that send it
//! traffic (and the ingresses in front of them), the network policies that apply to it, and every
//! environment variable of its containers with where its value comes from.
//! A secret's value is blurred, and only read when it's clicked; it's forgotten with the page.

use super::*;

/// Whether labels match a label selector (`matchLabels` + `matchExpressions`, or a plain map).
pub(super) fn selector_matches(sel: &Value, labels: &Value) -> bool {
    let label = |k: &str| labels[k].as_str();
    let plain = sel.as_object().map(|m| m.contains_key("matchLabels") || m.contains_key("matchExpressions")).unwrap_or(false);
    let ml = if plain { &sel["matchLabels"] } else { sel };
    if let Some(m) = ml.as_object() {
        if !m.iter().all(|(k, v)| label(k) == v.as_str()) {
            return false;
        }
    }
    for e in sel["matchExpressions"].as_array().into_iter().flatten() {
        let k = e["key"].as_str().unwrap_or("");
        let vals: Vec<&str> = e["values"].as_array().map(|a| a.iter().filter_map(|v| v.as_str()).collect()).unwrap_or_default();
        let ok = match e["operator"].as_str().unwrap_or("") {
            "In" => label(k).map(|v| vals.contains(&v)).unwrap_or(false),
            "NotIn" => label(k).map(|v| !vals.contains(&v)).unwrap_or(true),
            "Exists" => label(k).is_some(),
            "DoesNotExist" => label(k).is_none(),
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

/// A service port's target as the pod's container port ("http" → 8080).
fn target_port(port: &Value, pod: &Value) -> String {
    let t = &port["targetPort"];
    if let Some(n) = t.as_u64() {
        return n.to_string();
    }
    if let Some(name) = t.as_str() {
        for c in pod["spec"]["containers"].as_array().into_iter().flatten() {
            for p in c["ports"].as_array().into_iter().flatten() {
                if p["name"].as_str() == Some(name) {
                    return format!("{} ({name})", p["containerPort"]);
                }
            }
        }
        return name.to_string();
    }
    port["port"].to_string()
}

impl KubedogApp {
    pub(super) fn items_in(&self, ctx: &str, kind: Kind, ns: &str) -> Option<Vec<Value>> {
        let l = self.lists.get(&Self::list_key(ctx, kind))?;
        l.fetched?;
        Some(l.items.iter().filter(|o| o["metadata"]["namespace"].as_str() == Some(ns)).cloned().collect())
    }

    /// The same without copying them; None also when the account may not read them.
    pub(super) fn refs(&self, ctx: &str, kind: Kind, ns: &str) -> Option<Vec<&Value>> {
        let l = self.lists.get(&Self::list_key(ctx, kind))?;
        l.fetched?;
        // A list that was refused isn't an empty one.
        if l.items.is_empty() && self.refused(ctx, kind) {
            return None;
        }
        Some(l.items.iter().filter(|o| ns.is_empty() || o["metadata"]["namespace"].as_str() == Some(ns)).collect())
    }

    /// The Network section of a pod. Returns an object to open when one is clicked.
    pub(super) fn pod_network(&self, ui: &mut Ui, sel: &Selected, pod: &Value) -> Option<Selected> {
        let mut open = None;
        let labels = &pod["metadata"]["labels"];
        let st = &pod["status"];
        let link = |ui: &mut Ui, text: &str| ui.add(egui::Label::new(RichText::new(text).color(PRIMARY_TEXT())).sense(Sense::click())).on_hover_cursor(egui::CursorIcon::PointingHand);
        ui.add_space(8.0);
        ui.label(RichText::new("Network").color(TEXT_SUBTLE()).strong());
        card(ui, |ui| {
            let ips: Vec<String> = st["podIPs"].as_array().map(|a| a.iter().filter_map(|x| x["ip"].as_str().map(String::from)).collect()).unwrap_or_default();
            kv(ui, "Pod IP", if ips.is_empty() { st["podIP"].as_str().unwrap_or("-").to_string() } else { ips.join(", ") });
            kv(ui, "Host IP", st["hostIP"].as_str().unwrap_or("-"));
            if pod["spec"]["hostNetwork"].as_bool() == Some(true) {
                kv(ui, "Host network", "yes: the pod uses the node's network directly");
            }
            if let Some(h) = pod["spec"]["hostname"].as_str() {
                let sub = pod["spec"]["subdomain"].as_str().map(|s| format!(".{s}.{}.svc", sel.ns)).unwrap_or_default();
                kv(ui, "Hostname", format!("{h}{sub}"));
            }

            // Services whose selector picks this pod, with the ports they send here.
            ui.add_space(8.0);
            ui.label(RichText::new("Services").size(z(13.5)).strong().color(TEXT_DEFAULT()));
            let Some(services) = self.items_in(&sel.ctx, Kind::Services, &sel.ns) else {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(RichText::new("Reading services…").color(TEXT_SUBTLE()));
                });
                return;
            };
            let mine: Vec<&Value> = services
                .iter()
                .filter(|s| s["spec"]["selector"].as_object().map(|m| !m.is_empty()).unwrap_or(false) && selector_matches(&s["spec"]["selector"], labels))
                .collect();
            if mine.is_empty() {
                ui.label(RichText::new("No service sends traffic to this pod (no service's selector matches its labels).").size(z(12.5)).color(TEXT_SUBTLE()));
            }
            for s in &mine {
                let name = s["metadata"]["name"].as_str().unwrap_or("");
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("⇄").color(TEXT_SUBTLE()));
                    if link(ui, name).on_hover_text("Open this service").clicked() {
                        open = Some(Selected { ctx: sel.ctx.clone(), kind: Kind::Services, ns: sel.ns.clone(), name: name.to_string() });
                    }
                    let ty = s["spec"]["type"].as_str().unwrap_or("ClusterIP");
                    ui.label(RichText::new(ty).size(z(12.0)).color(INFO()));
                    if let Some(ip) = s["spec"]["clusterIP"].as_str().filter(|ip| *ip != "None") {
                        ui.label(RichText::new(ip).size(z(12.0)).color(TEXT_MUTED()));
                    } else {
                        ui.label(RichText::new("headless").size(z(12.0)).color(TEXT_MUTED()));
                    }
                    for lb in s["status"]["loadBalancer"]["ingress"].as_array().into_iter().flatten() {
                        if let Some(a) = lb["ip"].as_str().or(lb["hostname"].as_str()) {
                            ui.label(RichText::new(format!("external {a}")).size(z(12.0)).color(SUCCESS()));
                        }
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    ui.add_space(22.0);
                    let dns = format!("{name}.{}.svc.cluster.local", sel.ns);
                    if ui.add(egui::Label::new(RichText::new(&dns).monospace().size(z(12.0)).color(TEXT_MUTED())).sense(Sense::click())).on_hover_text("Click to copy").clicked() {
                        ui.ctx().copy_text(dns.clone());
                    }
                });
                for p in s["spec"]["ports"].as_array().into_iter().flatten() {
                    ui.horizontal(|ui| {
                        ui.add_space(22.0);
                        let pname = p["name"].as_str().map(|n| format!("{n}  ")).unwrap_or_default();
                        let node = p["nodePort"].as_u64().map(|n| format!("   (node port {n})")).unwrap_or_default();
                        ui.label(RichText::new(format!("{pname}{}/{} → pod {}{node}", p["port"], p["protocol"].as_str().unwrap_or("TCP"), target_port(p, pod))).size(z(12.5)).color(TEXT_DEFAULT()));
                    });
                }
                // Ways in from outside.
                for e in self.entries_to(&sel.ctx, &sel.ns, name) {
                    let url = if e.plain { e.url() } else { e.address() };
                    ui.horizontal_wrapped(|ui| {
                        ui.add_space(22.0);
                        ui.label(RichText::new("🌐").size(z(12.0)));
                        if e.way == podxray::Way::Ingress {
                            if link(ui, &url).on_hover_text(format!("Ingress {}: click to open it", e.name)).clicked() {
                                open = Some(Selected { ctx: sel.ctx.clone(), kind: Kind::Ingresses, ns: sel.ns.clone(), name: e.name.clone() });
                            }
                        } else {
                            if link(ui, &url).on_hover_text(format!("Route {}: click to copy", e.name)).clicked() {
                                ui.ctx().copy_text(url.clone());
                            }
                            ui.label(RichText::new(format!("route {}", e.name)).size(z(12.0)).color(TEXT_SUBTLE()));
                        }
                        if !e.taken {
                            ui.label(RichText::new("not taken on yet").size(z(12.0)).color(WARNING()));
                        }
                    });
                }
            }

            // Network policies that apply to this pod.
            ui.add_space(8.0);
            ui.label(RichText::new("Network policies").size(z(13.5)).strong().color(TEXT_DEFAULT()));
            match self.items_in(&sel.ctx, Kind::NetworkPolicies, &sel.ns) {
                None => {
                    ui.label(RichText::new("Not read (no permission, or still loading).").size(z(12.5)).color(TEXT_SUBTLE()));
                }
                Some(pols) => {
                    let mine: Vec<&Value> = pols.iter().filter(|p| selector_matches(&p["spec"]["podSelector"], labels)).collect();
                    if mine.is_empty() {
                        ui.label(RichText::new("None: all traffic to and from this pod is allowed.").size(z(12.5)).color(TEXT_SUBTLE()));
                    }
                    for p in mine {
                        let name = p["metadata"]["name"].as_str().unwrap_or("");
                        let types: Vec<&str> = p["spec"]["policyTypes"].as_array().map(|a| a.iter().filter_map(|t| t.as_str()).collect()).unwrap_or_else(|| vec!["Ingress"]);
                        let rules = |k: &str| p["spec"][k].as_array().map(|a| a.len()).unwrap_or(0);
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new("🛡").size(z(12.0)));
                            if link(ui, name).clicked() {
                                open = Some(Selected { ctx: sel.ctx.clone(), kind: Kind::NetworkPolicies, ns: sel.ns.clone(), name: name.to_string() });
                            }
                            for t in &types {
                                let n = rules(&t.to_lowercase());
                                let text = if n == 0 { format!("{t}: all denied") } else { format!("{t}: {n} rule{}", if n == 1 { "" } else { "s" }) };
                                ui.label(RichText::new(text).size(z(12.0)).color(if n == 0 { WARNING() } else { TEXT_MUTED() }));
                            }
                        });
                    }
                }
            }
        });
        open
    }

    /// The Environment tab of a pod: every variable of every container, as name, value and source.
    pub(super) fn pod_env(&mut self, ui: &mut Ui, sel: &Selected, pod: &Value) -> Option<Selected> {
        let mut open = None;
        // The names in secrets taken in whole (never their values).
        for s in whole_secrets(pod) {
            if !self.pod.keys.contains_key(&s) {
                self.pod_secret_keys(sel, &s);
            }
        }
        let configmaps = self.items_in(&sel.ctx, Kind::ConfigMaps, &sel.ns);
        let cm_refused = self.refused(&sel.ctx, Kind::ConfigMaps);
        let cm = |name: &str| -> Whole {
            match &configmaps {
                Some(l) => match l.iter().find(|c| c["metadata"]["name"].as_str() == Some(name)) {
                    Some(c) => Whole::Got(c["data"].as_object().into_iter().flatten().map(|(k, v)| (k.clone(), v.as_str().map(String::from))).collect()),
                    None if cm_refused => Whole::Not("your account can't read it".into()),
                    None => Whole::Not("it doesn't exist".into()),
                },
                None if cm_refused => Whole::Not("your account can't read it".into()),
                None => Whole::Reading,
            }
        };
        let keys = |name: &str| -> Whole {
            match self.pod.keys.get(name) {
                Some(Some(Ok(l))) => Whole::Got(l.iter().map(|k| (k.clone(), None)).collect()),
                Some(Some(Err(e))) => Whole::Not(if is_refusal(e) { "your account can't read it".into() } else if e.contains("not found") { "it doesn't exist".into() } else { truncate(e, 120) }),
                _ => Whole::Reading,
            }
        };
        let mut all: Vec<(String, bool, Vec<Var>)> = vec![];
        for (list, init) in [("containers", false), ("initContainers", true)] {
            for c in pod["spec"][list].as_array().into_iter().flatten() {
                let vars = env_vars(c, pod, &cm, &keys);
                if !vars.is_empty() {
                    all.push((c["name"].as_str().unwrap_or("").to_string(), init, vars));
                }
            }
        }
        let total: usize = all.iter().map(|a| a.2.len()).sum();
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{total} variable{}", if total == 1 { "" } else { "s" })).size(z(14.0)).color(TEXT_SUBTLE()));
            if total > 6 {
                filter_box(ui, &mut self.env_filter, "Filter by name, value or source", u(260.0));
            }
        });
        ui.add_space(4.0);
        if total == 0 {
            card(ui, |ui| {
                ui.label(RichText::new("No environment variables set.").size(z(12.5)).color(TEXT_SUBTLE()));
            });
            return None;
        }
        let q = self.env_filter.to_lowercase();
        for a in &mut all {
            a.2.retain(|v| q.is_empty() || v.name.to_lowercase().contains(&q) || matches!(&v.value, Val::Text(t) if t.to_lowercase().contains(&q)) || v.from().to_lowercase().contains(&q));
            if self.pod.env_by_source {
                a.2.sort_by(|x, y| x.from().cmp(&y.from()).then(x.name.cmp(&y.name)));
            } else {
                a.2.sort_by(|x, y| x.name.cmp(&y.name));
            }
        }
        // The same columns for every container: as wide as what's in them, within reason.
        let mono = |size: f32| FontId::monospace(z(size));
        let width = |t: &str, f: FontId| ui.painter().layout_no_wrap(t.to_string(), f, Color32::WHITE).size().x;
        let vars = || all.iter().flat_map(|a| a.2.iter());
        let room = ui.available_width() - 26.0;
        let gap = 22.0;
        let widest = |it: &mut dyn Iterator<Item = f32>| it.fold(0.0f32, f32::max).ceil() + 6.0;
        let src = widest(&mut vars().map(|v| width(&v.from(), FontId::proportional(z(12.5))) + u(16.0))).clamp(u(110.0), (room * 0.36).max(u(110.0)));
        let name = widest(&mut vars().map(|v| width(&v.name, mono(12.5)))).clamp(u(110.0), (room * 0.34).max(u(110.0)));
        let left = (room - name - src - 2.0 * gap).max(u(120.0));
        let value = widest(&mut vars().map(|v| match &v.value {
            Val::Text(t) => width(&truncate(&t.split_whitespace().collect::<Vec<_>>().join(" "), 100), mono(12.5)),
            Val::Secret => u(200.0),
            _ => u(170.0),
        }))
        .clamp(u(200.0).min(left), left);
        let cols = [name, value, src];
        let mut act: Option<Do> = None;
        for (cname, init, vars) in &all {
            if vars.is_empty() {
                continue;
            }
            card(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                ui.horizontal(|ui| {
                    ui.label(RichText::new(cname).size(z(15.0)).color(TEXT_DEFAULT()));
                    if *init {
                        ui.label(RichText::new("runs before the start").size(z(11.5)).color(TEXT_SUBTLE()));
                    }
                    ui.label(RichText::new(format!("{}", vars.len())).size(z(12.0)).color(TEXT_PLACEHOLDER()));
                });
                ui.add_space(6.0);
                // Headers; a click sorts.
                let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(24.0)), Sense::hover());
                let mut x = r.left();
                for (i, (t, w)) in ["Name", "Value", "From"].iter().zip(cols).enumerate() {
                    let hr = egui::Rect::from_min_size(egui::pos2(x, r.top()), egui::vec2(w, r.height()));
                    let on = (i == 0 && !self.pod.env_by_source) || (i == 2 && self.pod.env_by_source);
                    let resp = ui.interact(hr, ui.id().with(("env-head", cname, i)), if i == 1 { Sense::hover() } else { Sense::click() });
                    ui.painter().text(hr.left_center(), egui::Align2::LEFT_CENTER, format!("{t}{}", if on { " ↑" } else { "" }), FontId::proportional(z(12.0)), if resp.hovered() && i != 1 { TEXT_DEFAULT() } else { TEXT_SUBTLE() });
                    if resp.clicked() {
                        act = Some(Do::Sort(i == 2));
                    }
                    x += w + gap;
                }
                for (i, v) in vars.iter().enumerate() {
                    let y = ui.cursor().top();
                    ui.painter().hline(r.x_range(), y, Stroke::new(1.0, BORDER_SUBTLE()));
                    ui.add_space(3.0);
                    ui.push_id(("env", cname, i), |ui| {
                        ui.horizontal_top(|ui| {
                            ui.spacing_mut().item_spacing.x = gap;
                            let cell = |ui: &mut Ui, w: f32, add: &mut dyn FnMut(&mut Ui)| {
                                ui.allocate_ui_with_layout(egui::vec2(w, u(22.0)), Layout::top_down(Align::Min), |ui| {
                                    ui.set_width(w);
                                    ui.set_min_height(u(22.0));
                                    ui.spacing_mut().item_spacing = egui::vec2(6.0, 1.0);
                                    add(ui);
                                });
                            };
                            let faded = |c: Color32| if v.over { c.gamma_multiply(0.45) } else { c };
                            cell(ui, name, &mut |ui| {
                                ui.add_space(u(3.0));
                                let mut t = RichText::new(&v.name).monospace().size(z(12.5)).color(faded(PRIMARY_TEXT()));
                                if v.over {
                                    t = t.strikethrough();
                                }
                                let l = ui.add(egui::Label::new(t).truncate().sense(Sense::click()));
                                if l.on_hover_text(if v.over { "Overridden: another variable with this name wins. Click to copy the name" } else { "Click to copy the name" }).clicked() {
                                    act = Some(Do::Copy(v.name.clone()));
                                }
                            });
                            cell(ui, value, &mut |ui| {
                                if let Some(a) = self.env_value(ui, sel, cname, v, faded(TEXT_DEFAULT())) {
                                    act = Some(a);
                                }
                            });
                            cell(ui, src, &mut |ui| {
                                let (kind, col) = match &v.source {
                                    Source::ConfigMap(..) => (Some(Kind::ConfigMaps), INFO()),
                                    Source::Secret(..) => (Some(Kind::Secrets), WARNING()),
                                    _ => (None, TEXT_PLACEHOLDER()),
                                };
                                let (r, resp) = ui.allocate_exact_size(egui::vec2(src, u(22.0)), if kind.is_some() { Sense::click() } else { Sense::hover() });
                                ui.painter().circle_filled(egui::pos2(r.left() + u(4.0), r.center().y), u(3.5), faded(col));
                                let tc = if kind.is_some() && resp.hovered() { PRIMARY_TEXT() } else { TEXT_MUTED() };
                                let words = v.from();
                                pg::label_at(ui, ui.painter(), egui::pos2(r.left() + u(14.0), r.center().y), &words, 12.5, faded(tc), src - u(14.0));
                                if let (Some(k), Some(n)) = (kind, v.source.object()) {
                                    if resp.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text(format!("{words}\nClick to open")).clicked() {
                                        open = Some(Selected { ctx: sel.ctx.clone(), kind: k, ns: sel.ns.clone(), name: n.to_string() });
                                    }
                                }
                            });
                        });
                    });
                    ui.add_space(3.0);
                }
            });
            ui.add_space(8.0);
        }
        match act {
            Some(Do::Copy(t)) => {
                ui.ctx().copy_text(t);
                self.toast("Copied".into(), false);
            }
            Some(Do::Reveal(s, k)) => self.pod_reveal(sel, &s, &k),
            Some(Do::Hide(s, k)) => {
                self.pod.shown.remove(&(s, k));
            }
            Some(Do::Fold(k)) => {
                if !self.env_open.remove(&k) {
                    self.env_open.insert(k);
                }
            }
            Some(Do::Sort(by)) => self.pod.env_by_source = by,
            None => {}
        }
        open
    }

    /// The value cell of a variable.
    fn env_value(&self, ui: &mut Ui, sel: &Selected, cname: &str, v: &Var, col: Color32) -> Option<Do> {
        let mut act = None;
        // Lines up with the blurred ones.
        if !matches!(v.value, Val::Secret) {
            ui.add_space(u(3.0));
        }
        match &v.value {
            Val::Text(t) if t.is_empty() => {
                ui.label(RichText::new("(empty)").size(z(12.5)).color(TEXT_PLACEHOLDER()));
            }
            Val::Text(t) => {
                // One line; long ones open with a click on "more".
                let key = format!("{}|{cname}|{}", sel.key(), v.name);
                let opened = self.env_open.contains(&key);
                let lines = t.lines().count();
                let one = if lines > 1 { truncate(&t.split_whitespace().collect::<Vec<_>>().join(" "), 160) } else { truncate(t, 160) };
                let wide = ui.painter().layout_no_wrap(one.clone(), FontId::monospace(z(12.5)), col).size().x > ui.available_width();
                let long = lines > 1 || t.chars().count() > 160 || wide;
                let shown = if opened { truncate(t, 20_000) } else { one };
                let l = egui::Label::new(RichText::new(shown).monospace().size(z(12.5)).color(col)).sense(Sense::click());
                let l = if opened { l.wrap() } else { l.truncate() };
                if ui.add(l).on_hover_text("Click to copy").clicked() {
                    act = Some(Do::Copy(t.clone()));
                }
                if long {
                    let words = if opened { "less".to_string() } else if lines > 1 { format!("all {lines} lines") } else { "all of it".to_string() };
                    if ui.link(RichText::new(words).size(z(11.5))).clicked() {
                        act = Some(Do::Fold(key));
                    }
                }
            }
            Val::Secret => {
                let Source::Secret(s, k) = &v.source else { return None };
                match self.pod.shown.get(&(s.clone(), k.clone())) {
                    Some(None) => {
                        ui.spinner();
                    }
                    Some(Some(Err(e))) => {
                        ui.label(RichText::new(if is_refusal(e) { "your account can't read it".to_string() } else { truncate(e, 120) }).size(z(12.5)).color(WARNING()));
                    }
                    Some(Some(Ok(t))) => {
                        if ui.add(egui::Label::new(RichText::new(truncate(t, 20_000)).monospace().size(z(12.5)).color(col)).wrap().sense(Sense::click())).on_hover_text("Click to copy").clicked() {
                            act = Some(Do::Copy(t.clone()));
                        }
                        if ui.link(RichText::new("hide").size(z(11.5))).clicked() {
                            act = Some(Do::Hide(s.clone(), k.clone()));
                        }
                    }
                    None => {
                        if blurred(ui).on_hover_text("Click to read it from the secret").clicked() {
                            act = Some(Do::Reveal(s.clone(), k.clone()));
                        }
                    }
                }
            }
            Val::Later => {
                ui.label(RichText::new("worked out when the pod starts").size(z(12.5)).color(TEXT_PLACEHOLDER()));
            }
            Val::Reading => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(RichText::new("reading…").size(z(12.5)).color(TEXT_PLACEHOLDER()));
                });
            }
            Val::Not(e) => {
                ui.add(egui::Label::new(RichText::new(e).size(z(12.5)).color(WARNING())).truncate()).on_hover_text(e);
            }
        }
        act
    }
}

/// What a click in the Environment tab does.
enum Do {
    Copy(String),
    Reveal(String, String),
    Hide(String, String),
    Fold(String),
    Sort(bool),
}

/// What's in a config map or secret that's taken in whole.
enum Whole {
    Got(Vec<(String, Option<String>)>),
    Reading,
    Not(String),
}

#[derive(Debug, PartialEq, Clone)]
enum Val {
    Text(String),
    /// Blurred until it's asked for.
    Secret,
    Later,
    Reading,
    Not(String),
}

#[derive(Debug, PartialEq, Clone)]
enum Source {
    Here,
    /// The object, and its key when that isn't the variable's name.
    ConfigMap(String, String),
    /// The object and its key.
    Secret(String, String),
    Other(String),
}

impl Source {
    fn object(&self) -> Option<&str> {
        match self {
            Source::ConfigMap(n, _) | Source::Secret(n, _) => Some(n),
            _ => None,
        }
    }
    fn words(&self) -> String {
        match self {
            Source::Here => "set in the pod".into(),
            Source::ConfigMap(n, k) if k.is_empty() => format!("config map {n}"),
            Source::ConfigMap(n, k) => format!("config map {n}, {k}"),
            Source::Secret(n, k) if k.is_empty() => format!("secret {n}"),
            Source::Secret(n, k) => format!("secret {n}, {k}"),
            Source::Other(t) => t.clone(),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
struct Var {
    name: String,
    value: Val,
    source: Source,
    /// Another variable of the same name wins.
    over: bool,
}

impl Var {
    /// Where it comes from; a secret's key only when it isn't the variable's name.
    fn from(&self) -> String {
        match &self.source {
            Source::Secret(n, k) if *k == self.name => format!("secret {n}"),
            s => s.words(),
        }
    }
}

/// Secrets whose every key becomes a variable.
fn whole_secrets(pod: &Value) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for l in ["containers", "initContainers"] {
        for f in pod["spec"][l].as_array().into_iter().flatten().flat_map(|c| c["envFrom"].as_array().into_iter().flatten()) {
            if let Some(n) = f["secretRef"]["name"].as_str() {
                if !out.iter().any(|x| x == n) {
                    out.push(n.to_string());
                }
            }
        }
    }
    out
}

/// A container's variables. Those taken in whole come first, so single ones win over them, and
/// later ones over earlier ones, as in Kubernetes.
fn env_vars(c: &Value, pod: &Value, cm: &dyn Fn(&str) -> Whole, keys: &dyn Fn(&str) -> Whole) -> Vec<Var> {
    let mut out: Vec<Var> = vec![];
    let mut add = |name: String, value: Val, source: Source| out.push(Var { name, value, source, over: false });
    for f in c["envFrom"].as_array().into_iter().flatten() {
        let prefix = f["prefix"].as_str().unwrap_or("");
        for (part, secret) in [("configMapRef", false), ("secretRef", true)] {
            let Some(n) = f[part]["name"].as_str() else { continue };
            // The key is said when it isn't the variable's own name.
            let source = |k: &str| if secret { Source::Secret(n.to_string(), k.to_string()) } else { Source::ConfigMap(n.to_string(), if prefix.is_empty() { String::new() } else { k.to_string() }) };
            match if secret { keys(n) } else { cm(n) } {
                Whole::Got(list) if list.is_empty() => add(n.to_string(), Val::Not("it's empty".into()), if secret { Source::Secret(n.into(), String::new()) } else { Source::ConfigMap(n.into(), String::new()) }),
                Whole::Got(list) => {
                    for (k, v) in list {
                        add(format!("{prefix}{k}"), if secret { Val::Secret } else { v.map(Val::Text).unwrap_or(Val::Later) }, source(&k));
                    }
                }
                Whole::Reading => add(n.to_string(), Val::Reading, if secret { Source::Secret(n.into(), String::new()) } else { Source::ConfigMap(n.into(), String::new()) }),
                Whole::Not(e) => add(n.to_string(), Val::Not(if f[part]["optional"] == true { format!("{e} (optional)") } else { e }), if secret { Source::Secret(n.into(), String::new()) } else { Source::ConfigMap(n.into(), String::new()) }),
            }
        }
    }
    for e in c["env"].as_array().into_iter().flatten() {
        let name = e["name"].as_str().unwrap_or("").to_string();
        let vf = &e["valueFrom"];
        let pair = |k: &str| (vf[k]["name"].as_str().unwrap_or("").to_string(), vf[k]["key"].as_str().unwrap_or("").to_string());
        if vf["configMapKeyRef"].is_object() {
            let (n, k) = pair("configMapKeyRef");
            let value = match cm(&n) {
                Whole::Got(l) => l.into_iter().find(|x| x.0 == k).and_then(|x| x.1).map(Val::Text).unwrap_or_else(|| Val::Not(format!("no {k} in it"))),
                Whole::Reading => Val::Reading,
                Whole::Not(e) => Val::Not(e),
            };
            let k = if k == name { String::new() } else { k };
            add(name, value, Source::ConfigMap(n, k));
        } else if vf["secretKeyRef"].is_object() {
            let (n, k) = pair("secretKeyRef");
            add(name, Val::Secret, Source::Secret(n, k));
        } else if let Some(p) = vf["fieldRef"]["fieldPath"].as_str() {
            let v = match p {
                "metadata.name" => &pod["metadata"]["name"],
                "metadata.namespace" => &pod["metadata"]["namespace"],
                "metadata.uid" => &pod["metadata"]["uid"],
                "spec.nodeName" => &pod["spec"]["nodeName"],
                "spec.serviceAccountName" => &pod["spec"]["serviceAccountName"],
                "status.podIP" => &pod["status"]["podIP"],
                "status.hostIP" => &pod["status"]["hostIP"],
                _ => &Value::Null,
            };
            add(name, v.as_str().map(|s| Val::Text(s.to_string())).unwrap_or(Val::Later), Source::Other(format!("the pod's {p}")));
        } else if let Some(r) = vf["resourceFieldRef"]["resource"].as_str() {
            add(name, Val::Later, Source::Other(format!("the container's {r}")));
        } else if vf.is_object() {
            add(name, Val::Later, Source::Other("set elsewhere".into()));
        } else {
            // A variable without a value is empty.
            add(name, Val::Text(e["value"].as_str().unwrap_or("").to_string()), Source::Here);
        }
    }
    let mut last: HashMap<String, usize> = HashMap::new();
    for i in 0..out.len() {
        // A line that stands for a whole object isn't a variable.
        if matches!(out[i].value, Val::Reading | Val::Not(_)) && out[i].source.object() == Some(out[i].name.as_str()) {
            continue;
        }
        if let Some(j) = last.insert(out[i].name.clone(), i) {
            out[j].over = true;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variables() {
        let pod = serde_json::json!({"metadata": {"name": "p"}, "spec": {"containers": [{
            "envFrom": [{"configMapRef": {"name": "conf"}}, {"prefix": "DB_", "secretRef": {"name": "creds"}}, {"secretRef": {"name": "slow"}}, {"configMapRef": {"name": "gone", "optional": true}}],
            "env": [{"name": "A", "value": "own"}, {"name": "E"}, {"name": "S", "valueFrom": {"secretKeyRef": {"name": "creds", "key": "pass"}}},
                {"name": "C", "valueFrom": {"configMapKeyRef": {"name": "conf", "key": "b"}}}, {"name": "M", "valueFrom": {"configMapKeyRef": {"name": "conf", "key": "nope"}}},
                {"name": "N", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}}, {"name": "R", "valueFrom": {"resourceFieldRef": {"resource": "limits.cpu"}}}]
        }]}});
        assert_eq!(whole_secrets(&pod), vec!["creds", "slow"]);
        let cm = |n: &str| if n == "conf" { Whole::Got(vec![("A".into(), Some("1".into())), ("b".into(), Some("2".into()))]) } else { Whole::Not("it doesn't exist".into()) };
        let keys = |n: &str| if n == "creds" { Whole::Got(vec![("pass".into(), None)]) } else { Whole::Reading };
        let v = env_vars(&pod["spec"]["containers"][0], &pod, &cm, &keys);
        let get = |n: &str, own: bool| v.iter().find(|x| x.name == n && (x.source == Source::Here) == own).cloned().unwrap();
        // Its own value wins over the one from the config map.
        assert!(get("A", false).over && !get("A", true).over);
        assert_eq!(get("E", true).value, Val::Text(String::new()));
        let db = get("DB_pass", false);
        assert_eq!((db.value.clone(), db.from().as_str()), (Val::Secret, "secret creds, pass"));
        assert_eq!(Var { name: "pass".into(), ..db }.from(), "secret creds");
        assert_eq!((get("C", false).value, get("C", false).source.words().as_str()), (Val::Text("2".into()), "config map conf, b"));
        assert_eq!(get("b", false).source.words(), "config map conf");
        assert_eq!(get("M", false).value, Val::Not("no nope in it".into()));
        assert_eq!(get("slow", false).value, Val::Reading);
        assert_eq!(get("gone", false).value, Val::Not("it doesn't exist (optional)".into()));
        assert_eq!(get("N", false).value, Val::Text("p".into()));
        assert_eq!(get("R", false).source.words(), "the container's limits.cpu");
        // No value of a secret is ever in here.
        assert!(v.iter().filter(|x| matches!(x.source, Source::Secret(..))).all(|x| !matches!(x.value, Val::Text(_))));
    }
}
