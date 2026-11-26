//! Networking: the Service Map, and the TLS
//! certificate behind each ingress.

use super::*;

impl KubedogApp {
    pub(super) fn fetch_cert(&mut self, ctx: &str, ns: &str, secret: &str) {
        let key = format!("cert|{ctx}|{ns}|{secret}");
        if self.certs.contains_key(&key) || self.demo {
            return;
        }
        self.certs.insert(key.clone(), (true, Err(String::new())));
        // Only the certificate is read, never the private key.
        let args = vec![
            "--context".into(),
            ctx.to_string(),
            "-n".into(),
            ns.to_string(),
            "get".into(),
            "secret".into(),
            secret.to_string(),
            "-o".into(),
            "jsonpath={.data.tls\\.crt}".into(),
            format!("--request-timeout={}", kube::REQUEST_TIMEOUT),
        ];
        self.spawn(move |k| Msg::Text { key, result: k.run(&args) });
    }

    pub(super) fn on_cert(&mut self, key: String, result: Result<String, String>) {
        let r = match result {
            Ok(s) if s.trim().is_empty() => Err("the secret has no tls.crt".to_string()),
            Ok(s) => certs::cert_from_secret_b64(&s),
            Err(e) if e.contains("NotFound") || e.contains("not found") => Err("secret not found".to_string()),
            Err(e) => Err(e),
        };
        self.certs.insert(key, (false, r));
    }

    /// The TLS part of an ingress's Overview tab.
    pub(super) fn ingress_tls(&mut self, ui: &mut Ui, sel: &Selected, o: &Value) {
        let tls = o["spec"]["tls"].as_array().cloned().unwrap_or_default();
        ui.add_space(8.0);
        ui.label(RichText::new("TLS").color(TEXT_SUBTLE()).strong());
        if tls.is_empty() {
            ui.label(RichText::new("No TLS: this ingress serves plain HTTP.").color(TEXT_MUTED()));
            return;
        }
        for t in tls {
            let hosts = t["hosts"].as_array().map(|a| a.iter().filter_map(|h| h.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
            card(ui, |ui| {
                kv(ui, "Hosts", if hosts.is_empty() { "(all)".to_string() } else { hosts.clone() });
                match t["secretName"].as_str() {
                    None => {
                        kv(ui, "Secret", "none: the ingress controller's default certificate");
                    }
                    Some(secret) => {
                        let key = format!("cert|{}|{}|{}", sel.ctx, sel.ns, secret);
                        if !self.certs.contains_key(&key) {
                            self.fetch_cert(&sel.ctx, &sel.ns, secret);
                        }
                        ui.horizontal(|ui| {
                            left_cell(ui, [z(130.0), z(18.0)], egui::Label::new(RichText::new("Secret").color(TEXT_SUBTLE())));
                            let l = ui.add(egui::Label::new(RichText::new(secret).color(PRIMARY_TEXT())).sense(Sense::click()));
                            if l.on_hover_text("Open this secret").clicked() {
                                self.pending_open = Some(Selected { ctx: sel.ctx.clone(), kind: Kind::Secrets, ns: sel.ns.clone(), name: secret.to_string() });
                            }
                        });
                        match self.certs.get(&key) {
                            Some((true, _)) | None => {
                                ui.spinner();
                            }
                            Some((false, Err(e))) => {
                                kv(ui, "Certificate", "");
                                ui.label(RichText::new(e).color(WARNING()));
                            }
                            Some((false, Ok(c))) => {
                                kv(ui, "Issued to", c.subject.clone());
                                kv(ui, "Issued by", c.issuer.clone());
                                if let Some(na) = c.not_after {
                                    let days = (na - kube::now_secs()) / 86400;
                                    let (txt, col) = if days < 0 {
                                        (format!("expired {} days ago", -days), DANGER())
                                    } else if days < 14 {
                                        (format!("expires in {days} days"), WARNING())
                                    } else {
                                        (format!("valid for {days} more days"), SUCCESS())
                                    };
                                    ui.horizontal(|ui| {
                                        left_cell(ui, [z(130.0), z(18.0)], egui::Label::new(RichText::new("Expires").color(TEXT_SUBTLE())));
                                        ui.label(RichText::new(iso_date(na)).color(TEXT_DEFAULT()));
                                        ui.label(RichText::new(txt).strong().color(col));
                                    });
                                }
                            }
                        }
                    }
                }
            });
            ui.add_space(4.0);
        }
    }

    /// Service Map: ingress → service → endpoints → pods, one chain per service.
    pub(super) fn service_map(&mut self, ui: &mut Ui) {
        let services = self.items_of(Kind::Services);
        let ingresses = self.items_of(Kind::Ingresses);
        let slices = self.items_of(Kind::EndpointSlices);
        let pods = self.items_of(Kind::Pods);
        let total = services.iter().filter(|(_, o)| self.ns_ok(o["metadata"]["namespace"].as_str().unwrap_or(""))).count();
        self.header(ui, true, Some(format!("{total} Services")), true);
        let search = self.search.to_lowercase();
        let loaded = self.view_kinds().iter().all(|k| self.active.iter().all(|c| self.lists.get(&Self::list_key(c, *k)).map(|l| l.fetched.is_some()).unwrap_or(false)));
        if !loaded && services.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                ui.spinner();
                ui.label(RichText::new("Loading services, ingresses, endpoints and pods…").color(TEXT_SUBTLE()));
            });
            return;
        }
        ui.label(RichText::new("Each row follows a service from the ingress that routes to it, through its endpoints, to the pods behind it. Red marks a broken link.").size(z(12.5)).color(TEXT_SUBTLE()));
        ui.add_space(8.0);

        struct Chain {
            ctx: String,
            ns: String,
            name: String,
            svc: Option<Value>,
            ingresses: Vec<(String, String)>, // (ingress name, host/path)
            ready: usize,
            not_ready: usize,
            pods: Vec<(String, bool)>,
            selector: bool,
        }
        let mut chains: Vec<Chain> = vec![];
        for (c, s) in &services {
            let ns = s["metadata"]["namespace"].as_str().unwrap_or("").to_string();
            let name = s["metadata"]["name"].as_str().unwrap_or("").to_string();
            let sel = s["spec"]["selector"].as_object().cloned().unwrap_or_default();
            let mut ready = 0;
            let mut not_ready = 0;
            for (sc, es) in &slices {
                if sc == c && es["metadata"]["namespace"].as_str() == Some(&ns) && es["metadata"]["labels"]["kubernetes.io/service-name"].as_str() == Some(&name) {
                    for e in es["endpoints"].as_array().cloned().unwrap_or_default() {
                        if e["conditions"]["ready"].as_bool() == Some(false) {
                            not_ready += 1;
                        } else {
                            ready += 1;
                        }
                    }
                }
            }
            let mut ps = vec![];
            if !sel.is_empty() {
                for (pc, p) in &pods {
                    if pc != c || p["metadata"]["namespace"].as_str() != Some(&ns) {
                        continue;
                    }
                    let labels = &p["metadata"]["labels"];
                    if sel.iter().all(|(k, v)| labels[k] == *v) {
                        let ok = p["status"]["conditions"].as_array().map(|a| a.iter().any(|x| x["type"] == "Ready" && x["status"] == "True")).unwrap_or(false);
                        ps.push((p["metadata"]["name"].as_str().unwrap_or("").to_string(), ok));
                    }
                }
            }
            chains.push(Chain { ctx: c.clone(), ns, name, svc: Some(s.clone()), ingresses: vec![], ready, not_ready, pods: ps, selector: !sel.is_empty() });
        }
        // Ingress backends, including ones that point at a missing service.
        for (c, i) in &ingresses {
            let ns = i["metadata"]["namespace"].as_str().unwrap_or("").to_string();
            let iname = i["metadata"]["name"].as_str().unwrap_or("").to_string();
            let mut add = |svc: &str, route: String| {
                match chains.iter_mut().find(|ch| &ch.ctx == c && ch.ns == ns && ch.name == svc) {
                    Some(ch) => ch.ingresses.push((iname.clone(), route)),
                    None => chains.push(Chain { ctx: c.clone(), ns: ns.clone(), name: svc.to_string(), svc: None, ingresses: vec![(iname.clone(), route)], ready: 0, not_ready: 0, pods: vec![], selector: false }),
                }
            };
            if let Some(svc) = i["spec"]["defaultBackend"]["service"]["name"].as_str() {
                add(svc, "(default backend)".into());
            }
            for rule in i["spec"]["rules"].as_array().cloned().unwrap_or_default() {
                let host = rule["host"].as_str().unwrap_or("*").to_string();
                for p in rule["http"]["paths"].as_array().cloned().unwrap_or_default() {
                    if let Some(svc) = p["backend"]["service"]["name"].as_str() {
                        add(svc, format!("{host}{}", p["path"].as_str().unwrap_or("/")));
                    }
                }
            }
        }
        chains.retain(|ch| self.ns_ok(&ch.ns));
        if !search.is_empty() {
            chains.retain(|ch| {
                ch.name.to_lowercase().contains(&search)
                    || ch.ns.to_lowercase().contains(&search)
                    || ch.ingresses.iter().any(|(n, r)| n.to_lowercase().contains(&search) || r.to_lowercase().contains(&search))
            });
        }
        // Broken links first, then services with ingresses, then by name.
        let broken = |ch: &Chain| ch.svc.is_none() || (ch.selector && ch.ready == 0);
        chains.sort_by(|a, b| broken(b).cmp(&broken(a)).then(b.ingresses.is_empty().cmp(&a.ingresses.is_empty()).reverse()).then(a.ns.cmp(&b.ns)).then(a.name.cmp(&b.name)));
        let broken_n = chains.iter().filter(|c| broken(c)).count();
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{} chains", chains.len())).color(TEXT_MUTED()));
            if broken_n > 0 {
                ui.label(RichText::new(format!("· {broken_n} broken")).strong().color(DANGER()));
            }
            if !self.ns_any() && chains.len() > 80 {
                ui.label(RichText::new("· showing the first 80; pick a namespace to see all").color(TEXT_PLACEHOLDER()));
            }
        });
        ui.add_space(6.0);
        let mut open: Option<Selected> = None;
        let multi = self.active.len() > 1;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for ch in chains.iter().take(if self.ns_any() { 400 } else { 80 }) {
                let is_broken = broken(ch);
                Frame::new()
                    .fill(BG_CARD())
                    .stroke(Stroke::new(1.0, if is_broken { DANGER().gamma_multiply(0.5) } else { BORDER_SUBTLE() }))
                    .corner_radius(CornerRadius::same(8))
                    .inner_margin(Margin::symmetric(10, 8))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            let node = |ui: &mut Ui, w: f32, title: &str, sub: &str, color: Color32, fill: Color32| -> egui::Response {
                                Frame::new()
                                    .fill(fill)
                                    .stroke(Stroke::new(1.0, color.gamma_multiply(0.7)))
                                    .corner_radius(CornerRadius::same(6))
                                    .inner_margin(Margin::symmetric(8, 4))
                                    .show(ui, |ui| {
                                        ui.vertical(|ui| {
                                            ui.set_width(z(w));
                                            ui.add(egui::Label::new(RichText::new(title).size(z(12.5)).color(TEXT_DEFAULT())).truncate());
                                            ui.add(egui::Label::new(RichText::new(sub).size(z(11.0)).color(color)).truncate());
                                        });
                                    })
                                    .response
                                    .interact(Sense::click())
                            };
                            let arrow = |ui: &mut Ui, ok: bool| {
                                let (r, _) = ui.allocate_exact_size(egui::vec2(28.0, 30.0), Sense::hover());
                                let col = if ok { TEXT_PLACEHOLDER() } else { DANGER() };
                                let y = r.center().y;
                                ui.painter().line_segment([egui::pos2(r.left() + 2.0, y), egui::pos2(r.right() - 4.0, y)], Stroke::new(1.5, col));
                                ui.painter().line_segment([egui::pos2(r.right() - 9.0, y - 4.0), egui::pos2(r.right() - 4.0, y)], Stroke::new(1.5, col));
                                ui.painter().line_segment([egui::pos2(r.right() - 9.0, y + 4.0), egui::pos2(r.right() - 4.0, y)], Stroke::new(1.5, col));
                            };
                            // 1. ingresses
                            ui.vertical(|ui| {
                                if ch.ingresses.is_empty() {
                                    node(ui, 200.0, "no ingress", "reachable inside the cluster", TEXT_PLACEHOLDER(), Color32::TRANSPARENT);
                                }
                                for (iname, route) in ch.ingresses.iter().take(3) {
                                    if node(ui, 200.0, route, &format!("ingress {iname}"), INFO(), BG_DEFAULT()).on_hover_text("Open this ingress").clicked() {
                                        open = Some(Selected { ctx: ch.ctx.clone(), kind: Kind::Ingresses, ns: ch.ns.clone(), name: iname.clone() });
                                    }
                                }
                                if ch.ingresses.len() > 3 {
                                    ui.label(RichText::new(format!("+{} more routes", ch.ingresses.len() - 3)).size(z(11.0)).color(TEXT_PLACEHOLDER()));
                                }
                            });
                            arrow(ui, ch.svc.is_some() || ch.ingresses.is_empty());
                            // 2. service
                            match &ch.svc {
                                Some(svc) => {
                                    let ports = svc["spec"]["ports"].as_array().map(|a| a.iter().map(|p| p["port"].to_string()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
                                    let ty = svc["spec"]["type"].as_str().unwrap_or("ClusterIP");
                                    let title = if multi { format!("{} · {}/{}", ch.ctx, ch.ns, ch.name) } else { format!("{}/{}", ch.ns, ch.name) };
                                    if node(ui, 230.0, &title, &format!("{ty} · port {ports}"), PRIMARY_TEXT(), BG_DEFAULT()).on_hover_text("Open this service").clicked() {
                                        open = Some(Selected { ctx: ch.ctx.clone(), kind: Kind::Services, ns: ch.ns.clone(), name: ch.name.clone() });
                                    }
                                }
                                None => {
                                    node(ui, 230.0, &format!("{}/{}", ch.ns, ch.name), "service is missing", DANGER(), Color32::TRANSPARENT);
                                }
                            }
                            if ch.svc.is_some() {
                                let ep_ok = ch.ready > 0 || !ch.selector;
                                arrow(ui, ep_ok);
                                // 3. endpoints
                                let (sub, col) = if !ch.selector && ch.ready + ch.not_ready == 0 {
                                    ("no selector (external or manual)".to_string(), TEXT_PLACEHOLDER())
                                } else if ch.ready == 0 {
                                    ("no ready endpoints".to_string(), DANGER())
                                } else if ch.not_ready > 0 {
                                    (format!("{} not ready", ch.not_ready), WARNING())
                                } else {
                                    ("all ready".to_string(), SUCCESS())
                                };
                                node(ui, 150.0, &format!("{} endpoints", ch.ready + ch.not_ready), &sub, col, BG_DEFAULT());
                                if ch.selector {
                                    arrow(ui, !ch.pods.is_empty());
                                    // 4. pods
                                    ui.vertical(|ui| {
                                        if ch.pods.is_empty() {
                                            ui.label(RichText::new("no pods match the selector").color(DANGER()));
                                        }
                                        ui.horizontal_wrapped(|ui| {
                                            ui.spacing_mut().item_spacing = egui::vec2(4.0, 4.0);
                                            for (p, ok) in ch.pods.iter().take(12) {
                                                let r = Frame::new()
                                                    .fill(if *ok { SUCCESS().gamma_multiply(0.18) } else { DANGER().gamma_multiply(0.18) })
                                                    .stroke(Stroke::new(1.0, if *ok { SUCCESS().gamma_multiply(0.6) } else { DANGER().gamma_multiply(0.6) }))
                                                    .corner_radius(CornerRadius::same(4))
                                                    .inner_margin(Margin::symmetric(6, 2))
                                                    .show(ui, |ui| {
                                                        ui.label(RichText::new(truncate(p, 34)).size(z(11.5)).color(TEXT_DEFAULT()));
                                                    })
                                                    .response
                                                    .interact(Sense::click());
                                                if r.on_hover_text(if *ok { "Ready · open this pod" } else { "Not ready · open this pod" }).clicked() {
                                                    open = Some(Selected { ctx: ch.ctx.clone(), kind: Kind::Pods, ns: ch.ns.clone(), name: p.clone() });
                                                }
                                            }
                                            if ch.pods.len() > 12 {
                                                ui.label(RichText::new(format!("+{}", ch.pods.len() - 12)).size(z(11.5)).color(TEXT_SUBTLE()));
                                            }
                                        });
                                    });
                                }
                            }
                        });
                    });
                ui.add_space(6.0);
            }
        });
        if let Some(s) = open {
            self.navigate(View::Resource(s.kind), Some(s));
        }
    }

    pub(super) fn items_of(&self, k: Kind) -> Vec<(String, Value)> {
        let mut out = vec![];
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            if let Some(l) = self.lists.get(&Self::list_key(c, k)) {
                out.extend(l.items.iter().cloned().map(|o| (c.clone(), o)));
            }
        }
        out
    }
}

/// A Unix time as YYYY-MM-DD.
pub(super) fn iso_date(t: i64) -> String {
    let days = t.div_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    /// Set KUBEDOG_TEST_CERT_B64 to a file holding a secret's base64 tls.crt to check
    /// the reader against `openssl x509 -enddate`.
    #[test]
    fn reads_certificate() {
        let Ok(p) = std::env::var("KUBEDOG_TEST_CERT_B64") else { return };
        let b64 = std::fs::read_to_string(p).unwrap();
        let c = super::certs::cert_from_secret_b64(&b64).unwrap();
        println!("subject={} issuer={} not_after={}", c.subject, c.issuer, c.not_after.map(super::iso_date).unwrap_or_default());
    }
}
