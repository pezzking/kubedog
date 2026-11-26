//! The pages of everything that isn't a pod or a workload: the facts at the top, and for each kind
//! what it means in words or as a picture.

use super::dash::{at, at_end, line};
use super::face::{amount_words, many, Face, Fact, Side};
use super::pg::{label_at, panel};
use super::podxray::{Go, Look};
use super::work::{cells_size, draw_cells, meter, name_of, said};
use super::*;

/// What an object's page loads.
pub(super) fn needs(k: Kind) -> Vec<Kind> {
    let mut v = vec![k];
    let users = [Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::CronJobs, Kind::Jobs, Kind::Pods];
    match k {
        Kind::Services => v.extend([Kind::Ingresses, Kind::Pods, Kind::EndpointSlices]),
        Kind::Ingresses => v.extend([Kind::Services, Kind::Pods]),
        Kind::NetworkPolicies | Kind::PodDisruptionBudgets | Kind::Nodes | Kind::PriorityClasses | Kind::RuntimeClasses => v.push(Kind::Pods),
        Kind::ConfigMaps => v.extend(users),
        Kind::Secrets => {
            v.push(Kind::Ingresses);
            v.extend(users);
        }
        Kind::ServiceAccounts => {
            v.extend(users);
            v.extend([Kind::RoleBindings, Kind::ClusterRoleBindings]);
        }
        Kind::PersistentVolumeClaims => v.extend(users),
        Kind::StorageClasses => v.extend([Kind::PersistentVolumeClaims, Kind::PersistentVolumes]),
        Kind::Namespaces => v.extend([Kind::Pods, Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::CronJobs, Kind::ResourceQuotas, Kind::LimitRanges, Kind::PersistentVolumeClaims, Kind::Services]),
        Kind::Roles => v.push(Kind::RoleBindings),
        Kind::ClusterRoles => v.extend([Kind::RoleBindings, Kind::ClusterRoleBindings]),
        Kind::IngressClasses => v.push(Kind::Ingresses),
        _ => {}
    }
    v
}

// ---------- in words ----------

/// A selector: "a=b, c in (d, e)".
pub(super) fn selector_words(s: &Value) -> String {
    let mut out: Vec<String> = s["matchLabels"].as_object().into_iter().flatten().map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or(""))).collect();
    for e in s["matchExpressions"].as_array().into_iter().flatten() {
        let vals = e["values"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
        out.push(match e["operator"].as_str().unwrap_or("") {
            "In" => format!("{} in ({vals})", e["key"].as_str().unwrap_or("")),
            "NotIn" => format!("{} not in ({vals})", e["key"].as_str().unwrap_or("")),
            "Exists" => format!("{} set", e["key"].as_str().unwrap_or("")),
            _ => format!("{} not set", e["key"].as_str().unwrap_or("")),
        });
    }
    out.join(", ")
}

/// One side of a network policy rule.
fn peer_words(p: &Value) -> String {
    if let Some(c) = p["ipBlock"]["cidr"].as_str() {
        let except: Vec<&str> = p["ipBlock"]["except"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).collect();
        return format!("addresses {c}{}", if except.is_empty() { String::new() } else { format!(" except {}", except.join(", ")) });
    }
    let ns = &p["namespaceSelector"];
    let pods = &p["podSelector"];
    let who = match selector_words(pods) {
        w if w.is_empty() => "any pod".to_string(),
        w => format!("pods with {w}"),
    };
    let where_ = if ns.is_null() {
        "in this namespace".to_string()
    } else {
        let m = ns["matchLabels"].as_object();
        match (m.map(|m| m.len()), ns["matchLabels"]["kubernetes.io/metadata.name"].as_str(), selector_words(ns)) {
            (Some(1), Some(n), _) if ns["matchExpressions"].is_null() => format!("in namespace {n}"),
            (_, _, w) if w.is_empty() => "in any namespace".into(),
            (_, _, w) => format!("in namespaces with {w}"),
        }
    };
    format!("{who} {where_}")
}

fn rule_ports(r: &Value) -> String {
    let l: Vec<String> = r["ports"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| {
            let n = p["port"].as_str().map(String::from).or_else(|| p["port"].as_i64().map(|n| n.to_string())).unwrap_or("any".into());
            let end = p["endPort"].as_i64().map(|e| format!("–{e}")).unwrap_or_default();
            let proto = p["protocol"].as_str().filter(|p| *p != "TCP").map(|p| format!("/{p}")).unwrap_or_default();
            format!("{n}{end}{proto}")
        })
        .collect();
    match l.len() {
        0 => "any port".into(),
        1 => format!("port {}", l[0]),
        _ => format!("ports {}", l.join(", ")),
    }
}

/// What a policy lets through: lines (who, ports); None: it says nothing about that way.
pub(super) fn policy_words(o: &Value, inward: bool) -> Option<Vec<(String, String)>> {
    let spec = &o["spec"];
    let (key, side, ty) = if inward { ("ingress", "from", "Ingress") } else { ("egress", "to", "Egress") };
    let on = match spec["policyTypes"].as_array() {
        Some(t) => t.iter().any(|x| x == ty),
        None => inward || spec[key].is_array(),
    };
    if !on {
        return None;
    }
    let mut out = vec![];
    for r in spec[key].as_array().into_iter().flatten() {
        let ports = rule_ports(r);
        match r[side].as_array().filter(|a| !a.is_empty()) {
            None => out.push((if inward { "anyone, from anywhere" } else { "anything, anywhere" }.to_string(), ports)),
            Some(l) => out.extend(l.iter().map(|p| (peer_words(p), ports.clone()))),
        }
    }
    Some(out)
}

/// A role's rule: (verbs, resources, how much to mind).
pub(super) fn rule_words(r: &Value) -> (String, String, Tone) {
    let list = |k: &str| -> Vec<&str> { r[k].as_array().into_iter().flatten().filter_map(|x| x.as_str()).collect() };
    let (verbs, res, groups, names, urls) = (list("verbs"), list("resources"), list("apiGroups"), list("resourceNames"), list("nonResourceURLs"));
    let has = |v: &str| verbs.contains(&v);
    let all = has("*");
    let mut what = if !urls.is_empty() {
        urls.join(", ")
    } else {
        let g: Vec<&str> = groups.iter().map(|g| if g.is_empty() { "core" } else { g }).collect();
        format!("{}{}", res.join(", "), if g.is_empty() { String::new() } else { format!("  ({})", g.join(", ")) })
    };
    if !names.is_empty() {
        what.push_str(&format!(", only {}", names.join(", ")));
    }
    let change = all || verbs.iter().any(|v| matches!(*v, "create" | "update" | "patch" | "delete" | "deletecollection"));
    let broad = res.contains(&"*");
    let risky = verbs.iter().any(|v| matches!(*v, "escalate" | "bind" | "impersonate")) || (broad && all) || (change && res.iter().any(|x| matches!(*x, "pods/exec" | "pods/attach" | "rolebindings" | "clusterrolebindings" | "clusterroles" | "roles" | "mutatingwebhookconfigurations")));
    let secrets = (broad || res.contains(&"secrets")) && (all || has("get") || has("list") || has("watch")) && names.is_empty() && (groups.contains(&"") || groups.contains(&"*"));
    let tone = if risky { Tone::Danger } else if secrets || (change && broad) { Tone::Warning } else { Tone::Normal };
    (verbs.join(", "), what, tone)
}

fn subject(s: &Value, ns: &str) -> String {
    let n = s["name"].as_str().unwrap_or("");
    match s["kind"].as_str().unwrap_or("") {
        "ServiceAccount" => format!("service account {}", match s["namespace"].as_str() { Some(x) if x != ns => format!("{x}/{n}"), _ => n.to_string() }),
        "Group" => format!("group {n}"),
        "User" => format!("user {n}"),
        x => format!("{x} {n}"),
    }
}

/// A metric that an autoscaler goes by: (name, now, aim, in words).
pub(super) fn hpa_metrics(o: &Value) -> Vec<(String, Option<f64>, Option<f64>, String)> {
    let q = |v: &Value| v.as_i64().map(|n| n as f64).or_else(|| v.as_str().map(number));
    let part = |m: &Value| -> (String, Value, Value) {
        let key = match m["type"].as_str().unwrap_or("") { "Resource" => "resource", "ContainerResource" => "containerResource", "Pods" => "pods", "Object" => "object", _ => "external" };
        let name = m[key]["name"].as_str().or(m[key]["metric"]["name"].as_str()).unwrap_or("").to_string();
        (format!("{key}|{name}|{}", m[key]["container"].as_str().unwrap_or("")), m[key]["target"].clone(), m[key]["current"].clone())
    };
    let now: Vec<(String, Value, Value)> = o["status"]["currentMetrics"].as_array().into_iter().flatten().map(part).collect();
    o["spec"]["metrics"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| {
            let (id, target, _) = part(m);
            let cur = now.iter().find(|x| x.0 == id).map(|x| x.2.clone()).unwrap_or_default();
            let bytes = id.contains("|memory|");
            let cpu = id.starts_with("resource|cpu|") || id.starts_with("containerResource|cpu|");
            let name = id.split('|').nth(1).unwrap_or("").to_string();
            let words = |v: f64| if bytes { gib(v) } else if cpu { hive::cores(v * 1000.0) } else { tidy(v) };
            let (n, t, w) = if !target["averageUtilization"].is_null() {
                let (n, t) = (q(&cur["averageUtilization"]), q(&target["averageUtilization"]));
                (n, t, format!("{} / {}% of request", n.map(|n| format!("{n:.0}%")).unwrap_or("unknown".into()), t.map(tidy).unwrap_or_default()))
            } else {
                let k = if target["averageValue"].is_null() { "value" } else { "averageValue" };
                let (n, t) = (q(&cur[k]), q(&target[k]));
                (n, t, format!("{} / {}{}", n.map(words).unwrap_or("unknown".into()), t.map(words).unwrap_or_default(), if k == "averageValue" { " per pod" } else { "" }))
            };
            (name, n, t, w)
        })
        .collect()
}

fn tidy(v: f64) -> String {
    if v.fract().abs() < 0.005 { format!("{v:.0}") } else { format!("{v:.2}") }
}

/// "500m" → 0.5, "2k" → 2000, "1Gi" → bytes.
fn number(t: &str) -> f64 {
    if let Ok(v) = t.parse() {
        return v;
    }
    if t.ends_with('i') {
        return resources::mem_bytes(t);
    }
    let (n, s) = t.split_at(t.len().saturating_sub(1));
    let f = match s { "m" => 1e-3, "u" => 1e-6, "n" => 1e-9, "k" => 1e3, "M" => 1e6, "G" => 1e9, "T" => 1e12, _ => return 0.0 };
    n.parse::<f64>().unwrap_or(0.0) * f
}

fn access_words(v: &Value) -> String {
    v.as_array().into_iter().flatten().filter_map(|m| m.as_str()).map(|m| match m { "ReadWriteOnce" => "RWO", "ReadOnlyMany" => "ROX", "ReadWriteMany" => "RWX", "ReadWriteOncePod" => "RWOP", x => x }).collect::<Vec<_>>().join(", ")
}

// ---------- drawing ----------

struct Row_ {
    col: Color32,
    name: String,
    mid: String,
    end: String,
    tip: String,
    to: Option<Selected>,
}

impl Row_ {
    fn new(name: impl Into<String>, col: Color32) -> Row_ {
        Row_ { col, name: name.into(), mid: String::new(), end: String::new(), tip: String::new(), to: None }
    }
    fn mid(mut self, t: impl Into<String>) -> Row_ {
        self.mid = t.into();
        self
    }
    fn end(mut self, t: impl Into<String>) -> Row_ {
        self.end = t.into();
        self
    }
    fn tip(mut self, t: impl Into<String>) -> Row_ {
        self.tip = t.into();
        self
    }
    fn to(mut self, t: Selected) -> Row_ {
        self.to = Some(t);
        self
    }
}

/// A card of lines, each with a dot; those that lead somewhere can be clicked.
fn rows(ui: &mut Ui, title: &str, hint: &str, list: &[Row_], none: &str, max: usize, open: &mut Option<Selected>) {
    card(ui, |ui| {
        panel(ui, title, hint);
        ui.spacing_mut().item_spacing.y = 0.0;
        if list.is_empty() {
            said(ui, none, TEXT_SUBTLE());
        }
        // The second column starts at the same place on every line.
        let widest = list.iter().take(max).map(|x| ui.painter().layout_no_wrap(x.name.clone(), FontId::proportional(z(13.0)), TEXT_DEFAULT()).size().x).fold(0.0f32, f32::max);
        let nw_all = (widest + 24.0).clamp(ui.available_width() * 0.22, ui.available_width() * 0.46);
        for x in list.iter().take(max) {
            let (r, resp) = line(ui, u(27.0), x.to.is_some());
            ui.painter().circle_filled(egui::pos2(r.left() + u(5.0), r.center().y), u(4.0), x.col);
            let end = ui.painter().layout_no_wrap(fit(ui, &x.end, r.width() * 0.4, z(12.0)), FontId::proportional(z(12.0)), if matches!(x.col, c if c == DANGER() || c == WARNING()) { x.col } else { TEXT_SUBTLE() });
            let ew = end.size().x;
            let c = if matches!(x.col, c if c == DANGER() || c == WARNING()) { x.col } else { TEXT_SUBTLE() };
            ui.painter().galley(egui::pos2(r.right() - ew, r.center().y - end.size().y / 2.0), end, c);
            let left = r.left() + u(18.0);
            let room = r.right() - ew - 14.0 - left;
            let nw = if x.mid.is_empty() { room } else { nw_all.min(room * 0.7) };
            label_at(ui, ui.painter(), egui::pos2(left, r.center().y), &x.name, 13.0, if x.to.is_some() { PRIMARY_TEXT() } else { TEXT_DEFAULT() }, (nw - 8.0).max(10.0));
            if !x.mid.is_empty() {
                label_at(ui, ui.painter(), egui::pos2(left + nw + 14.0, r.center().y), &x.mid, 12.5, TEXT_MUTED(), (room - nw - 14.0).max(10.0));
            }
            let tip = if x.tip.is_empty() { format!("{}\n{} {}", x.name, x.mid, x.end) } else { x.tip.clone() };
            if resp.on_hover_text(tip.trim().to_string()).clicked() {
                *open = x.to.clone();
            }
        }
        if list.len() > max {
            let (r, _) = line(ui, u(24.0), false);
            at(ui, r, 0.0, 1.0, &format!("and {} more", list.len() - max), 12.0, TEXT_PLACEHOLDER());
        }
    });
    ui.add_space(10.0);
}

/// Lines of words, long ones wrap.
fn paragraph(ui: &mut Ui, title: &str, hint: &str, list: &[(String, Color32)]) {
    card(ui, |ui| {
        panel(ui, title, hint);
        for (t, c) in list {
            ui.horizontal_top(|ui| {
                let (r, _) = ui.allocate_exact_size(egui::vec2(u(10.0), u(18.0)), Sense::hover());
                ui.painter().circle_filled(r.center(), u(3.0), c.gamma_multiply(0.8));
                said(ui, t, *c);
            });
        }
    });
    ui.add_space(10.0);
}

impl KubedogApp {
    fn pods_like<'a>(&'a self, sel: &Selected, selector: &Value) -> Vec<&'a Value> {
        self.refs(&sel.ctx, Kind::Pods, &sel.ns).unwrap_or_default().into_iter().filter(|p| podnet::selector_matches(selector, &p["metadata"]["labels"])).collect()
    }

    /// A service's pods: (ready, all). None while that's not known.
    pub(super) fn service_ready(&self, ctx: &str, ns: &str, name: &str) -> Option<(usize, usize)> {
        if let Some(l) = self.refs(ctx, Kind::EndpointSlices, ns) {
            let mut seen: HashMap<String, bool> = HashMap::new();
            for e in l.into_iter().filter(|s| s["metadata"]["labels"]["kubernetes.io/service-name"].as_str() == Some(name)).flat_map(|s| s["endpoints"].as_array().into_iter().flatten()) {
                let id = e["targetRef"]["name"].as_str().or(e["addresses"][0].as_str()).unwrap_or("").to_string();
                *seen.entry(id).or_default() |= e["conditions"]["ready"] != false;
            }
            return Some((seen.values().filter(|r| **r).count(), seen.len()));
        }
        let s = self.refs(ctx, Kind::Services, ns)?.into_iter().find(|s| name_of(s) == name)?;
        let sel = &s["spec"]["selector"];
        sel.as_object().filter(|m| !m.is_empty())?;
        let pods: Vec<&Value> = self.refs(ctx, Kind::Pods, ns)?.into_iter().filter(|p| podnet::selector_matches(sel, &p["metadata"]["labels"]) && !matches!(p["status"]["phase"].as_str(), Some("Succeeded" | "Failed"))).collect();
        Some((pods.iter().filter(|p| pod::cond(p, "Ready").map(|c| c["status"] == "True").unwrap_or(false)).count(), pods.len()))
    }

    /// What uses a config map, secret, service account or claim: (kind, name, how).
    pub(super) fn users_of(&self, sel: &Selected) -> Vec<(Kind, String, String)> {
        let mut v = vec![];
        if sel.kind == Kind::Secrets {
            for ing in self.refs(&sel.ctx, Kind::Ingresses, &sel.ns).unwrap_or_default() {
                if ing["spec"]["tls"].as_array().into_iter().flatten().any(|t| t["secretName"].as_str() == Some(&sel.name)) {
                    v.push((Kind::Ingresses, name_of(ing).to_string(), "its certificate".to_string()));
                }
            }
        }
        let what = match sel.kind { Kind::ConfigMaps => "configmap", Kind::Secrets => "secret", _ => "" };
        for k in [Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::CronJobs, Kind::Jobs, Kind::Pods] {
            for w in self.refs(&sel.ctx, k, &sel.ns).unwrap_or_default() {
                // Pods and jobs made by a controller are counted through it; a claim from a template
                // is only in the pods.
                let made = w["metadata"]["ownerReferences"].as_array().map(|a| !a.is_empty()).unwrap_or(false);
                if matches!(k, Kind::Pods | Kind::Jobs) && made && !(k == Kind::Pods && sel.kind == Kind::PersistentVolumeClaims) {
                    continue;
                }
                if !workload::uses_of(workload::pod_spec(k, w)).iter().any(|(uk, un)| *uk == sel.kind && un == &sel.name) {
                    continue;
                }
                let how = if what.is_empty() {
                    String::new()
                } else {
                    let pod = if k == Kind::Pods { (*w).clone() } else { work::sample(k, w) };
                    let l: Vec<&str> = podplace::config_uses(&pod)
                        .into_iter()
                        .filter(|u| u.0 == what && u.1 == sel.name)
                        .map(|u| match u.2 { podplace::How::Variable => "as variables", podplace::How::Files => "as files", podplace::How::Fixed => "as a fixed file" })
                        .collect();
                    if l.is_empty() { "to fetch images".into() } else { l.join(", ") }
                };
                v.push((k, name_of(w).to_string(), how));
            }
        }
        v
    }

    fn users_reading(&self, ctx: &str) -> bool {
        [Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::CronJobs, Kind::Jobs, Kind::Pods].iter().any(|k| !self.refused(ctx, *k) && self.missing(ctx, *k).is_some())
    }

    /// The top of an object's page.
    pub(super) fn object_face(&self, sel: &Selected, o: &Value, now: i64) -> (Face, Side) {
        let (mut tone, mut head, mut notes) = face::verdict(sel.kind, o, now);
        let (spec, st, md) = (&o["spec"], &o["status"], &o["metadata"]);
        let created = md["creationTimestamp"].as_str().unwrap_or("");
        let s = |v: &Value| v.as_str().unwrap_or("").to_string();
        let lk = |kind: Kind, name: &str| Selected { ctx: sel.ctx.clone(), kind, ns: if kind.namespaced() { sel.ns.clone() } else { String::new() }, name: name.to_string() };
        let mut f: Vec<Fact> = vec![];
        let mut pills = face::pills(o, now);
        let mut side = Side::None;
        let mut sub = format!("created {} ago", kube::age(created));
        match sel.kind {
            Kind::Services => {
                let ty = spec["type"].as_str().unwrap_or("ClusterIP");
                if ty == "ExternalName" {
                    (tone, head) = (Tone::Info, format!("External name: {}", s(&spec["externalName"])));
                } else {
                    let sel_any = spec["selector"].as_object().map(|m| !m.is_empty()).unwrap_or(false);
                    (tone, head) = match self.service_ready(&sel.ctx, &sel.ns, &sel.name) {
                        None => (Tone::Muted, self.missing(&sel.ctx, Kind::Pods).map(|w| format!("Can't tell yet: {w}")).unwrap_or("Can't tell where it leads".into())),
                        Some((0, 0)) => (if sel_any { Tone::Warning } else { Tone::Muted }, if sel_any { "No endpoints".into() } else { "No selector, no endpoints".into() }),
                        Some((0, n)) => (Tone::Danger, format!("0/{n} endpoints ready")),
                        Some((r, n)) if r < n => (Tone::Warning, format!("{r}/{n} endpoints ready")),
                        Some((r, n)) => (Tone::Success, format!("{r}/{n} endpoints ready")),
                    };
                    if sel_any && head == "No endpoints" {
                        notes.push("No pod in the namespace matches the selector, or they're scaled to 0.".into());
                    }
                }
                f.push(Fact::new("Type", ty));
                f.push(Fact::new("Cluster IP", if spec["clusterIP"] == "None" { "None (headless)".into() } else { s(&spec["clusterIP"]) }));
                f.push(Fact::new("DNS name", format!("{}.{}.svc", sel.name, sel.ns)));
                let ext: Vec<String> = st["loadBalancer"]["ingress"].as_array().into_iter().flatten().map(|i| i["ip"].as_str().or(i["hostname"].as_str()).unwrap_or("").to_string()).chain(spec["externalIPs"].as_array().into_iter().flatten().map(&s)).collect();
                if ty == "LoadBalancer" || !ext.is_empty() {
                    f.push(Fact::new("External address", if ext.is_empty() { "pending".into() } else { ext.join(", ") }).col(if ext.is_empty() { WARNING() } else { TEXT_DEFAULT() }));
                    if ext.is_empty() && ty == "LoadBalancer" {
                        tone = if tone == Tone::Success { Tone::Warning } else { tone };
                        notes.push("No load balancer address assigned yet.".into());
                    }
                }
                f.push(Fact::new("Selector", resources::selector(&spec["selector"])));
                f.push(Fact::new("Session affinity", spec["sessionAffinity"].as_str().unwrap_or("None")));
                if spec["externalTrafficPolicy"] == "Local" {
                    f.push(Fact::new("External traffic policy", "Local"));
                }
            }
            Kind::Ingresses => {
                let e = podxray::pick_ingress(o);
                let mut bad = vec![];
                let mut unknown = 0;
                let mut names: Vec<&str> = vec![];
                for x in &e {
                    if !names.contains(&x.service.as_str()) && !x.service.is_empty() {
                        names.push(&x.service);
                    }
                }
                for n in &names {
                    match self.service_ready(&sel.ctx, &sel.ns, n) {
                        Some((0, _)) => bad.push(format!("Service {n} has no ready endpoints.")),
                        Some(_) => {}
                        None => match self.refs(&sel.ctx, Kind::Services, &sel.ns) {
                            Some(l) if !l.iter().any(|s| name_of(s) == *n) => bad.push(format!("Service {n} doesn't exist.")),
                            _ => unknown += 1,
                        },
                    }
                }
                (tone, head) = if names.is_empty() {
                    (Tone::Warning, "No backends".into())
                } else if bad.len() == names.len() {
                    (Tone::Danger, "No backend is ready".into())
                } else if !bad.is_empty() {
                    (Tone::Warning, format!("{}/{} backends ready", names.len() - bad.len(), names.len()))
                } else if unknown > 0 {
                    (Tone::Muted, many(names.len() as i64, "backend"))
                } else {
                    (Tone::Success, format!("{0}/{0} backends ready", names.len()))
                };
                notes.extend(bad);
                let hosts: HashSet<&str> = e.iter().map(|x| x.host.as_str()).collect();
                f.push(Fact::new("Hosts", hosts.len().to_string()));
                let class = spec["ingressClassName"].as_str().or(md["annotations"]["kubernetes.io/ingress.class"].as_str()).unwrap_or("");
                f.push(if class.is_empty() { Fact::new("Ingress class", "cluster default") } else { Fact::new("Ingress class", class).to(lk(Kind::IngressClasses, class)) });
                let addr: Vec<String> = st["loadBalancer"]["ingress"].as_array().into_iter().flatten().map(|i| i["ip"].as_str().or(i["hostname"].as_str()).unwrap_or("").to_string()).collect();
                f.push(Fact::new("Load balancer", addr.join(", ")));
                f.push(Fact::new("TLS", if spec["tls"].as_array().map(|a| !a.is_empty()).unwrap_or(false) { "yes" } else { "no, plain HTTP" }));
            }
            Kind::EndpointSlices => {
                let e = o["endpoints"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
                let ready = e.iter().filter(|x| x["conditions"]["ready"] != false).count();
                (tone, head) = match (ready, e.len()) {
                    (0, 0) => (Tone::Muted, "No endpoints".into()),
                    (0, n) => (Tone::Danger, format!("0/{n} endpoints ready")),
                    (r, n) if r < n => (Tone::Warning, format!("{r}/{n} endpoints ready")),
                    (n, _) => (Tone::Success, format!("{n}/{n} endpoints ready")),
                };
                let svc = s(&md["labels"]["kubernetes.io/service-name"]);
                if !svc.is_empty() {
                    f.push(Fact::new("Service", svc.clone()).to(lk(Kind::Services, &svc)));
                }
                f.push(Fact::new("Address type", s(&o["addressType"])));
                f.push(Fact::new("Ports", o["ports"].as_array().into_iter().flatten().map(|p| format!("{}{}", p["name"].as_str().filter(|n| !n.is_empty()).map(|n| format!("{n} ")).unwrap_or_default(), p["port"])).collect::<Vec<_>>().join(", ")));
            }
            Kind::NetworkPolicies => {
                let pods = self.pods_like(sel, &spec["podSelector"]).len();
                let whole = selector_words(&spec["podSelector"]).is_empty();
                let (i, e) = (policy_words(o, true), policy_words(o, false));
                (tone, head) = match self.missing(&sel.ctx, Kind::Pods) {
                    Some(_) => (Tone::Info, if whole { "Applies to all pods in the namespace".into() } else { "Applies to the pods it selects".to_string() }),
                    None if pods == 0 => (Tone::Muted, "Selects no pods".into()),
                    None => (Tone::Info, if whole { format!("Applies to all {pods} pods in the namespace") } else { format!("Applies to {}", many(pods as i64, "pod")) }),
                };
                let way = |w: &Option<Vec<(String, String)>>| match w { None => "not restricted".to_string(), Some(l) if l.is_empty() => "all denied".into(), Some(l) => many(l.len() as i64, "allow rule") };
                f.push(Fact::new("Ingress", way(&i)));
                f.push(Fact::new("Egress", way(&e)));
                f.push(Fact::new("Pod selector", if whole { "(all pods)".into() } else { selector_words(&spec["podSelector"]) }));
            }
            Kind::ConfigMaps | Kind::Secrets => {
                let users = self.users_of(sel);
                let n = o["data"].as_object().map(|m| m.len()).unwrap_or(0) + o["binaryData"].as_object().map(|m| m.len()).unwrap_or(0);
                let size: usize = [&o["data"], &o["binaryData"]].iter().flat_map(|d| d.as_object().into_iter().flatten()).map(|(_, v)| v.as_str().map(|t| if sel.kind == Kind::Secrets { t.len() * 3 / 4 } else { t.len() }).unwrap_or(0)).sum();
                (tone, head) = if !users.is_empty() {
                    (Tone::Success, format!("Used by {}", many(users.len() as i64, "workload")))
                } else if self.users_reading(&sel.ctx) {
                    (Tone::Muted, "Looking for what uses it…".into())
                } else {
                    (Tone::Muted, "Not referenced by a workload in this namespace".into())
                };
                if users.iter().all(|u| u.0 == Kind::Ingresses) && !users.is_empty() {
                    head = format!("Used by {}", many(users.len() as i64, "ingress").replace("ingresss", "ingresses"));
                }
                f.push(Fact::new("Keys", n.to_string()));
                f.push(Fact::new("Size", if size < 1024 { format!("{size} bytes") } else { format!("{:.1} KB of at most 1 MB", size as f64 / 1024.0) }));
                if sel.kind == Kind::Secrets {
                    f.push(Fact::new("Type", o["type"].as_str().unwrap_or("Opaque")));
                }
                f.push(Fact::new("Immutable", if o["immutable"] == true { "yes" } else { "no" }));
                // When a manager last wrote it.
                let last = md["managedFields"].as_array().into_iter().flatten().filter_map(|m| pod::time_of(&m["time"])).max();
                if let Some(t) = last {
                    f.push(Fact::new("Last updated", format!("{} ago", kube::human_duration((now - t).max(0)))));
                }
            }
            Kind::PersistentVolumeClaims => {
                let usage = self.claim_usage(&sel.ctx, &sel.ns, &sel.name);
                if let Some(x) = &usage {
                    let share = x.used / x.capacity.max(1.0);
                    side = Side::Ring(share, format!("{:.0}% full", share * 100.0), format!("{} of {}", gib(x.used), gib(x.capacity)));
                    if share >= 0.9 {
                        (tone, head) = (Tone::Danger, "Nearly full".into());
                    } else if share >= 0.75 && tone == Tone::Success {
                        (tone, head) = (Tone::Warning, "Filling up".into());
                    }
                }
                f.push(Fact::new("Capacity", s(&st["capacity"]["storage"])));
                let want = s(&spec["resources"]["requests"]["storage"]);
                if resources::mem_bytes(&want) > resources::mem_bytes(&s(&st["capacity"]["storage"])) && st["phase"] == "Bound" {
                    notes.push(format!("Requested {want}; the resize isn't done yet."));
                    f.push(Fact::new("Requested", want).col(WARNING()));
                }
                let class = s(&spec["storageClassName"]);
                f.push(if class.is_empty() { Fact::new("Storage class", "-") } else { Fact::new("Storage class", class.clone()).to(lk(Kind::StorageClasses, &class)) });
                let vol = s(&spec["volumeName"]);
                if !vol.is_empty() {
                    f.push(Fact::new("Volume", vol.clone()).to(lk(Kind::PersistentVolumes, &vol)));
                }
                f.push(Fact::new("Access modes", access_words(&spec["accessModes"])));
                f.push(Fact::new("Volume mode", spec["volumeMode"].as_str().unwrap_or("Filesystem")));
            }
            Kind::PersistentVolumes => {
                f.push(Fact::new("Capacity", s(&spec["capacity"]["storage"])));
                let (cn, cns) = (s(&spec["claimRef"]["name"]), s(&spec["claimRef"]["namespace"]));
                if !cn.is_empty() {
                    f.push(Fact::new("Claim", format!("{cns}/{cn}")).to(Selected { ctx: sel.ctx.clone(), kind: Kind::PersistentVolumeClaims, ns: cns.clone(), name: cn.clone() }));
                    if let Some(x) = self.claim_usage(&sel.ctx, &cns, &cn) {
                        let share = x.used / x.capacity.max(1.0);
                        side = Side::Ring(share, format!("{:.0}% full", share * 100.0), format!("{} of {}", gib(x.used), gib(x.capacity)));
                    }
                }
                let class = s(&spec["storageClassName"]);
                f.push(if class.is_empty() { Fact::new("Storage class", "-") } else { Fact::new("Storage class", class.clone()).to(lk(Kind::StorageClasses, &class)) });
                f.push(Fact::new("Access modes", access_words(&spec["accessModes"])));
                f.push(Fact::new("Reclaim policy", spec["persistentVolumeReclaimPolicy"].as_str().unwrap_or("Delete")));
                let from = spec["csi"]["driver"].as_str().map(String::from).or_else(|| ["nfs", "local", "hostPath", "iscsi", "fc", "cephfs", "rbd"].iter().find(|k| spec[**k].is_object()).map(|k| k.to_string())).unwrap_or_default();
                f.push(Fact::new("Driver", from));
                f.push(Fact::new("Volume mode", spec["volumeMode"].as_str().unwrap_or("Filesystem")));
            }
            Kind::StorageClasses => {
                let default = md["annotations"]["storageclass.kubernetes.io/is-default-class"] == "true";
                let n = self.refs(&sel.ctx, Kind::PersistentVolumeClaims, "").unwrap_or_default().into_iter().filter(|c| c["spec"]["storageClassName"].as_str() == Some(&sel.name)).count();
                (tone, head) = (Tone::Info, if default { "Default storage class".into() } else { "Storage class".into() });
                f.push(Fact::new("Claims", match self.missing(&sel.ctx, Kind::PersistentVolumeClaims) { Some(_) => "-".into(), None => n.to_string() }));
                f.push(Fact::new("Provisioner", s(&o["provisioner"])));
                f.push(Fact::new("Reclaim policy", o["reclaimPolicy"].as_str().unwrap_or("Delete")));
                f.push(Fact::new("Binding mode", o["volumeBindingMode"].as_str().unwrap_or("Immediate")));
                f.push(Fact::new("Volume expansion", if o["allowVolumeExpansion"] == true { "yes" } else { "no" }));
            }
            Kind::Nodes => {
                let ni = &st["nodeInfo"];
                if let Some(x) = self.metrics.get(&sel.ctx).and_then(|m| m.nodes.get(&sel.name)) {
                    for (what, used, of) in [("CPU", x.0, resources::cpu_milli(&s(&st["allocatable"]["cpu"]))), ("memory", x.1, resources::mem_bytes(&s(&st["allocatable"]["memory"])))] {
                        if of > 0.0 && used / of >= 0.9 {
                            notes.push(format!("{:.0}% of allocatable {what} in use.", used / of * 100.0));
                            if tone == Tone::Success {
                                (tone, head) = (Tone::Warning, format!("Ready, high {what} usage"));
                            }
                        }
                    }
                }
                for (l, k) in [("Zone", "topology.kubernetes.io/zone"), ("Instance type", "node.kubernetes.io/instance-type")] {
                    if let Some(v) = md["labels"][k].as_str() {
                        f.push(Fact::new(l, v));
                    }
                }
                let roles: Vec<&str> = md["labels"].as_object().map(|m| m.keys().filter_map(|k| k.strip_prefix("node-role.kubernetes.io/")).collect()).unwrap_or_default();
                f.push(Fact::new("Roles", roles.join(", ")));
                f.push(Fact::new("Schedulable", if spec["unschedulable"] == true { "no (cordoned)" } else { "yes" }).col(if spec["unschedulable"] == true { WARNING() } else { TEXT_DEFAULT() }));
                f.push(Fact::new("CPU allocatable", format!("{} of {}", s(&st["allocatable"]["cpu"]), s(&st["capacity"]["cpu"]))));
                f.push(Fact::new("Memory allocatable", format!("{} of {}", gib(resources::mem_bytes(&s(&st["allocatable"]["memory"]))), gib(resources::mem_bytes(&s(&st["capacity"]["memory"]))))));
                for t in ["InternalIP", "ExternalIP"] {
                    if let Some(a) = st["addresses"].as_array().into_iter().flatten().find(|a| a["type"] == t) {
                        f.push(Fact::new(if t == "InternalIP" { "Internal IP" } else { "External IP" }, s(&a["address"])));
                    }
                }
                f.push(Fact::new("OS image", s(&ni["osImage"])));
                f.push(Fact::new("Kernel", s(&ni["kernelVersion"])));
                f.push(Fact::new("Kubelet", s(&ni["kubeletVersion"])));
                f.push(Fact::new("Container runtime", s(&ni["containerRuntimeVersion"])));
                f.push(Fact::new("Architecture", s(&ni["architecture"])));
                for t in spec["taints"].as_array().into_iter().flatten() {
                    f.push(Fact::new("Taint", format!("{}{}: {}", s(&t["key"]), t["value"].as_str().map(|v| format!("={v}")).unwrap_or_default(), s(&t["effect"]))).col(WARNING()));
                }
                sub = format!("joined {} ago", kube::age(created));
            }
            Kind::Namespaces => {
                let pods = self.refs(&sel.ctx, Kind::Pods, &sel.name).unwrap_or_default();
                let mut bad = 0;
                for p in &pods {
                    if matches!(pod::verdict(p, now).0, Tone::Danger | Tone::Warning) {
                        bad += 1;
                    }
                }
                if st["phase"] != "Terminating" {
                    (tone, head) = match (self.missing(&sel.ctx, Kind::Pods), pods.len(), bad) {
                        (Some(w), _, _) => (Tone::Muted, format!("Active; {w}")),
                        (_, 0, _) => (Tone::Muted, "No pods".into()),
                        (_, n, 0) => (Tone::Success, format!("{0}/{0} pods healthy", n)),
                        (_, n, b) => (Tone::Warning, format!("{}/{n} pods healthy", n - b)),
                    };
                }
                let m = self.metrics.get(&sel.ctx);
                let (c, mem) = pods.iter().filter_map(|p| m?.pods.get(&(sel.name.clone(), name_of(p).to_string()))).fold((0.0, 0.0), |a, x| (a.0 + x.0, a.1 + x.1));
                let count = |k: Kind| match self.missing(&sel.ctx, k) { Some(_) => "-".to_string(), None => self.refs(&sel.ctx, k, &sel.name).map(|l| l.len().to_string()).unwrap_or("-".into()) };
                f.push(Fact::new("Pods", count(Kind::Pods)));
                f.push(Fact::new("Usage", if c + mem > 0.0 { format!("{} CPU, {}", hive::cores(c), gib(mem)) } else { "-".into() }));
                for (l, k) in [("Deployments", Kind::Deployments), ("StatefulSets", Kind::StatefulSets), ("DaemonSets", Kind::DaemonSets), ("Services", Kind::Services), ("Volume claims", Kind::PersistentVolumeClaims)] {
                    f.push(Fact::new(l, count(k)));
                }
                for (l, k) in [("Requester", "openshift.io/requester"), ("Description", "openshift.io/description")] {
                    if let Some(v) = md["annotations"][k].as_str().filter(|v| !v.is_empty()) {
                        f.push(Fact::new(l, v));
                    }
                }
            }
            Kind::Events => {
                let i = &o["involvedObject"];
                let name = s(&i["name"]);
                f.push(match event_kind(i["kind"].as_str().unwrap_or("")) {
                    Some(k) => Fact::new("Object", format!("{} {name}", s(&i["kind"]))).to(Selected { ctx: sel.ctx.clone(), kind: k, ns: if k.namespaced() { s(&i["namespace"]) } else { String::new() }, name }),
                    None => Fact::new("Object", format!("{} {name}", s(&i["kind"]))),
                });
                let n = o["count"].as_i64().or(o["series"]["count"].as_i64()).unwrap_or(1);
                f.push(Fact::new("Count", n.to_string()));
                let last = pod::time_of(&o["lastTimestamp"]).or_else(|| pod::time_of(&o["series"]["lastObservedTime"])).or_else(|| pod::time_of(&o["eventTime"]));
                let first = pod::time_of(&o["firstTimestamp"]).or_else(|| pod::time_of(&o["eventTime"]));
                let ago = |t: Option<i64>| t.map(|t| format!("{} ago", kube::human_duration((now - t).max(0)))).unwrap_or("-".into());
                f.push(Fact::new("First seen", ago(first)));
                f.push(Fact::new("Last seen", ago(last)));
                f.push(Fact::new("Source", o["source"]["component"].as_str().or(o["reportingComponent"].as_str()).unwrap_or("")));
                sub = format!("last seen {}", ago(last));
            }
            Kind::HorizontalPodAutoscalers => {
                let t = &spec["scaleTargetRef"];
                let (cur, want, min, max) = (st["currentReplicas"].as_i64().unwrap_or(0), st["desiredReplicas"].as_i64().unwrap_or(0), spec["minReplicas"].as_i64().unwrap_or(1), spec["maxReplicas"].as_i64().unwrap_or(0));
                let name = s(&t["name"]);
                f.push(match workload::kind_named(t["kind"].as_str().unwrap_or("")) {
                    Some(k) => Fact::new("Target", format!("{} {name}", s(&t["kind"]))).to(lk(k, &name)),
                    None => Fact::new("Target", format!("{} {name}", s(&t["kind"]))),
                });
                f.push(Fact::new("Current replicas", cur.to_string()));
                f.push(Fact::new("Desired replicas", want.to_string()).col(if want != cur { INFO() } else { TEXT_DEFAULT() }));
                f.push(Fact::new("Min / max", format!("{min} / {max}")));
                f.push(Fact::new("Last scaled", pod::time_of(&st["lastScaleTime"]).map(|t| format!("{} ago", kube::human_duration((now - t).max(0)))).unwrap_or("never".into())));
                if let Some(h) = md["labels"]["scaledobject.keda.sh/name"].as_str() {
                    f.push(Fact::new("Scaled object (KEDA)", h));
                }
            }
            Kind::PodDisruptionBudgets => {
                let n = |k: &str| st[k].as_i64().unwrap_or(0);
                let q = |v: &Value| v.as_str().map(String::from).or_else(|| v.as_i64().map(|x| x.to_string()));
                f.push(match (q(&spec["minAvailable"]), q(&spec["maxUnavailable"])) { (Some(x), _) => Fact::new("Min available", x), (_, Some(x)) => Fact::new("Max unavailable", x), _ => Fact::new("Rule", "-") });
                f.push(Fact::new("Healthy", format!("{} of {}", n("currentHealthy"), n("expectedPods"))));
                f.push(Fact::new("Disruptions allowed", n("disruptionsAllowed").to_string()));
                f.push(Fact::new("Selector", selector_words(&spec["selector"])));
                if let Some(x) = spec["unhealthyPodEvictionPolicy"].as_str() {
                    f.push(Fact::new("Unhealthy pod eviction", x));
                }
            }
            Kind::ResourceQuotas => {
                let l = face::quota(o);
                if let Some(x) = l.iter().filter(|x| x.2 > 0.0).max_by(|a, b| (a.1 / a.2).partial_cmp(&(b.1 / b.2)).unwrap_or(std::cmp::Ordering::Equal)) {
                    side = Side::Ring(x.1 / x.2, format!("{:.0}%", x.1 / x.2 * 100.0), format!("of {}", x.0));
                }
                f.push(Fact::new("Hard limits", l.len().to_string()));
                let scopes: Vec<String> = spec["scopes"].as_array().into_iter().flatten().map(&s).collect();
                f.push(Fact::new("Scopes", if scopes.is_empty() { "whole namespace".into() } else { scopes.join(", ") }));
            }
            Kind::LimitRanges => {
                (tone, head) = (Tone::Info, "Default and allowed requests and limits".into());
                f.push(Fact::new("Rules", spec["limits"].as_array().map(|a| a.len()).unwrap_or(0).to_string()));
            }
            Kind::ServiceAccounts => {
                let users = self.users_of(sel);
                (tone, head) = if !users.is_empty() { (Tone::Success, format!("Used by {}", many(users.len() as i64, "workload"))) } else if self.users_reading(&sel.ctx) { (Tone::Muted, "Looking for what uses it…".into()) } else { (Tone::Muted, "Not used by a workload in this namespace".into()) };
                f.push(Fact::new("Token automount", if o["automountServiceAccountToken"] == false { "no" } else { "yes" }));
                f.push(Fact::new("Image pull secrets", o["imagePullSecrets"].as_array().map(|a| a.iter().filter_map(|x| x["name"].as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default()));
            }
            Kind::Roles | Kind::ClusterRoles => {
                let rules = o["rules"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
                let worst = rules.iter().map(|r| rule_words(r).2).max_by_key(|t| match t { Tone::Danger => 2, Tone::Warning => 1, _ => 0 }).unwrap_or(Tone::Normal);
                (tone, head) = match worst {
                    Tone::Danger => (Tone::Warning, "Privileged: can escalate or control everything".into()),
                    Tone::Warning => (Tone::Warning, "Broad: reads secrets or writes all resources".into()),
                    _ if rules.is_empty() => (Tone::Muted, if o["aggregationRule"].is_object() { "Aggregated from other roles".into() } else { "No rules".into() }),
                    _ => (Tone::Info, many(rules.len() as i64, "rule")),
                };
                f.push(Fact::new("Rules", rules.len().to_string()));
                f.push(Fact::new("Scope", if sel.kind == Kind::Roles { sel.ns.clone() } else { "cluster, or where it's bound".into() }));
                let n = self.bindings_of(sel).len();
                f.push(Fact::new("Bound by", match self.missing(&sel.ctx, Kind::RoleBindings) { Some(_) => "-".into(), None => many(n as i64, "binding") }));
            }
            Kind::RoleBindings | Kind::ClusterRoleBindings => {
                let subs = o["subjects"].as_array().map(|a| a.len()).unwrap_or(0);
                let r = &o["roleRef"];
                (tone, head) = if subs == 0 { (Tone::Muted, "No subjects".into()) } else { (Tone::Info, format!("Binds {} to {}", s(&r["name"]), if subs == 1 { subject(&o["subjects"][0], &sel.ns) } else { format!("{subs} subjects") })) };
                let k = if r["kind"] == "Role" { Kind::Roles } else { Kind::ClusterRoles };
                f.push(Fact::new("Role", s(&r["name"])).to(lk(k, &s(&r["name"]))));
                f.push(Fact::new("Scope", if sel.kind == Kind::RoleBindings { sel.ns.clone() } else { "cluster".into() }));
                f.push(Fact::new("Subjects", subs.to_string()));
                if matches!(r["name"].as_str(), Some("cluster-admin")) && sel.kind == Kind::ClusterRoleBindings {
                    tone = Tone::Warning;
                    notes.push("cluster-admin is full control of the cluster.".into());
                }
            }
            Kind::CustomResourceDefinitions => {
                f.push(Fact::new("Kind", s(&spec["names"]["kind"])));
                f.push(Fact::new("Group", s(&spec["group"])));
                f.push(Fact::new("Scope", spec["scope"].as_str().unwrap_or("")));
                let v: Vec<String> = spec["versions"].as_array().into_iter().flatten().filter(|v| v["served"] == true).map(|v| format!("{}{}", s(&v["name"]), if v["storage"] == true { " (stored)" } else { "" })).collect();
                f.push(Fact::new("Versions", v.join(", ")));
                let short: Vec<&str> = spec["names"]["shortNames"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).collect();
                if !short.is_empty() {
                    f.push(Fact::new("Short names", short.join(", ")));
                }
                if spec["conversion"]["strategy"] == "Webhook" {
                    f.push(Fact::new("Conversion webhook", s(&spec["conversion"]["webhook"]["clientConfig"]["service"]["name"])));
                }
            }
            Kind::Leases => {
                f.push(Fact::new("Holder", s(&spec["holderIdentity"])));
                let ago = |v: &Value| pod::time_of(v).map(|t| format!("{} ago", kube::human_duration((now - t).max(0)))).unwrap_or("never".into());
                f.push(Fact::new("Renewed", ago(&spec["renewTime"])));
                f.push(Fact::new("Acquired", ago(&spec["acquireTime"])));
                f.push(Fact::new("Duration", spec["leaseDurationSeconds"].as_i64().map(|n| format!("{n} seconds")).unwrap_or_default()));
                f.push(Fact::new("Transitions", spec["leaseTransitions"].as_i64().unwrap_or(0).to_string()));
            }
            Kind::IngressClasses => {
                let default = md["annotations"]["ingressclass.kubernetes.io/is-default-class"] == "true";
                let n = self.ingresses_of(sel).len();
                (tone, head) = match self.missing(&sel.ctx, Kind::Ingresses) {
                    Some(_) => (Tone::Info, "Ingress class".into()),
                    None => (if n > 0 { Tone::Success } else { Tone::Muted }, format!("Used by {}", many(n as i64, "ingress").replace("ingresss", "ingresses"))),
                };
                f.push(Fact::new("Controller", s(&spec["controller"])));
                f.push(Fact::new("Default", if default { "yes" } else { "no" }));
            }
            Kind::VolumeAttachments => {
                let pv = s(&spec["source"]["persistentVolumeName"]);
                let node = s(&spec["nodeName"]);
                f.push(if pv.is_empty() { Fact::new("Volume", "-") } else { Fact::new("Volume", pv.clone()).to(lk(Kind::PersistentVolumes, &pv)) });
                f.push(Fact::new("Node", node.clone()).to(lk(Kind::Nodes, &node)));
                f.push(Fact::new("Attacher", s(&spec["attacher"])));
            }
            Kind::CSINodes => {
                let n = spec["drivers"].as_array().map(|a| a.len()).unwrap_or(0);
                (tone, head) = if n == 0 { (Tone::Muted, "No CSI drivers on this node".into()) } else { (Tone::Info, format!("{} on this node", many(n as i64, "CSI driver"))) };
                f.push(Fact::new("Node", sel.name.clone()).to(lk(Kind::Nodes, &sel.name)));
            }
            Kind::CSIDrivers => {
                (tone, head) = (Tone::Info, "CSI driver".into());
                f.push(Fact::new("Attach required", if spec["attachRequired"] == false { "no" } else { "yes" }));
                f.push(Fact::new("Pod info on mount", if spec["podInfoOnMount"] == true { "yes" } else { "no" }));
                f.push(Fact::new("Storage capacity", if spec["storageCapacity"] == true { "yes" } else { "no" }));
                f.push(Fact::new("Lifecycle modes", spec["volumeLifecycleModes"].as_array().into_iter().flatten().map(&s).collect::<Vec<_>>().join(", ")));
            }
            Kind::PriorityClasses => {
                let n = self.refs(&sel.ctx, Kind::Pods, "").unwrap_or_default().iter().filter(|p| p["spec"]["priorityClassName"].as_str() == Some(&sel.name)).count();
                (tone, head) = match self.missing(&sel.ctx, Kind::Pods) { Some(_) => (Tone::Info, "Priority class".into()), None => (if n > 0 { Tone::Info } else { Tone::Muted }, format!("Used by {}", many(n as i64, "pod"))) };
                f.push(Fact::new("Value", o["value"].to_string()));
                f.push(Fact::new("Global default", if o["globalDefault"] == true { "yes" } else { "no" }));
                f.push(Fact::new("Preemption", o["preemptionPolicy"].as_str().unwrap_or("PreemptLowerPriority")));
                if let Some(d) = o["description"].as_str() {
                    notes.push(truncate(d, 300));
                }
            }
            Kind::RuntimeClasses => {
                let n = self.refs(&sel.ctx, Kind::Pods, "").unwrap_or_default().iter().filter(|p| p["spec"]["runtimeClassName"].as_str() == Some(&sel.name)).count();
                (tone, head) = (Tone::Info, "Runtime class".into());
                f.push(Fact::new("Handler", s(&o["handler"])));
                f.push(Fact::new("Pods", match self.missing(&sel.ctx, Kind::Pods) { Some(_) => "-".into(), None => n.to_string() }));
            }
            Kind::MutatingWebhooks | Kind::ValidatingWebhooks => {
                let l = o["webhooks"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
                let strict = l.iter().filter(|w| w["failurePolicy"] != "Ignore").count();
                (tone, head) = (Tone::Info, many(l.len() as i64, if sel.kind == Kind::MutatingWebhooks { "mutating webhook" } else { "validating webhook" }));
                f.push(Fact::new("Failure policy", match (strict, l.len()) { (0, _) => "Ignore".to_string(), (a, b) if a == b => "Fail".into(), (a, b) => format!("Fail for {a} of {b}") }));
                let svcs: std::collections::BTreeSet<String> = l.iter().filter_map(|w| w["clientConfig"]["service"]["name"].as_str()).map(String::from).collect();
                f.push(Fact::new("Service", svcs.into_iter().collect::<Vec<_>>().join(", ")));
            }
            Kind::CertificateSigningRequests => {
                f.push(Fact::new("Requestor", s(&spec["username"])));
                f.push(Fact::new("Signer", s(&spec["signerName"])));
                f.push(Fact::new("Usages", spec["usages"].as_array().into_iter().flatten().map(&s).collect::<Vec<_>>().join(", ")));
                if let Some(n) = spec["expirationSeconds"].as_i64() {
                    f.push(Fact::new("Expiration", kube::human_duration(n)));
                }
            }
            _ => {}
        }
        if sel.kind == Kind::Leases {
            pills.clear();
        }
        if head.is_empty() {
            head = sel.kind.singular().to_string();
        }
        if md["ownerReferences"][0]["name"].is_string() {
            f.push(self.owner_fact(sel, o));
        }
        if let Some(h) = md["labels"]["app.kubernetes.io/managed-by"].as_str() {
            f.push(Fact::new("Managed by", h));
        }
        if sel.kind != Kind::Events {
            f.push(Fact::new("Created", format!("{} ago", kube::age(created))));
        }
        (Face { tone, head, sub, notes, pills, facts: f }, side)
    }

    fn bindings_of(&self, sel: &Selected) -> Vec<(Kind, &Value)> {
        let k = if sel.kind == Kind::Roles { "Role" } else { "ClusterRole" };
        let mut v = vec![];
        for kind in [Kind::RoleBindings, Kind::ClusterRoleBindings] {
            for b in self.refs(&sel.ctx, kind, if sel.kind == Kind::Roles { &sel.ns } else { "" }).unwrap_or_default() {
                if b["roleRef"]["kind"] == k && b["roleRef"]["name"].as_str() == Some(&sel.name) {
                    v.push((kind, b));
                }
            }
        }
        v
    }

    fn ingresses_of(&self, sel: &Selected) -> Vec<&Value> {
        self.refs(&sel.ctx, Kind::Ingresses, "").unwrap_or_default().into_iter().filter(|i| i["spec"]["ingressClassName"].as_str() == Some(&sel.name) || i["metadata"]["annotations"]["kubernetes.io/ingress.class"].as_str() == Some(&sel.name)).collect()
    }

    /// What's particular to a kind. Returns an object to open.
    pub(super) fn object_body(&self, ui: &mut Ui, sel: &Selected, o: &Value, f: &Face, go: &mut Option<Go>) -> Option<Selected> {
        let mut open: Option<Selected> = None;
        let (spec, st) = (&o["spec"], &o["status"]);
        let now = kube::now_secs();
        let s = |v: &Value| v.as_str().unwrap_or("").to_string();
        let lk = |kind: Kind, name: &str| Selected { ctx: sel.ctx.clone(), kind, ns: if kind.namespaced() { sel.ns.clone() } else { String::new() }, name: name.to_string() };
        let any = |v: &Value| v.as_str().map(String::from).or_else(|| v.as_i64().map(|n| n.to_string())).unwrap_or_default();
        match sel.kind {
            Kind::Services if spec["type"] != "ExternalName" => {
                if spec["selector"].as_object().map(|m| !m.is_empty()).unwrap_or(false) {
                    let pods: Vec<&Value> = self.pods_like(sel, &spec["selector"]).into_iter().filter(|p| !matches!(p["status"]["phase"].as_str(), Some("Succeeded" | "Failed"))).collect();
                    let cells = self.cells(&sel.ctx, "", &pods, &|_| false);
                    let (want, least, tall) = cells_size(cells.len());
                    let pod = serde_json::json!({"metadata": {"labels": spec["selector"]}, "spec": {}});
                    let look = Look {
                        title: "Map",
                        note: if cells.is_empty() { String::new() } else { "the pods behind it; click a pod to open it".into() },
                        pod: &pod,
                        only: Some(&sel.name),
                        claims: vec![],
                        tone: f.tone,
                        running: !cells.is_empty(),
                        ready: cells.iter().any(|c| pod::cond(c.pod, "Ready").map(|c| c["status"] == "True").unwrap_or(false)),
                        want: want.max(u(220.0)),
                        least,
                        tall,
                        storage: false,
                        doors: true,
                    };
                    let none = self.missing(&sel.ctx, Kind::Pods).unwrap_or("no pods".into());
                    if let Some(g) = self.xray(ui, sel, &look, |ui, p, body, time| draw_cells(ui, sel, p, body, time, &cells, &none)) {
                        *go = Some(g);
                    }
                    ui.add_space(10.0);
                    let l: Vec<Row_> = self.entries_to(&sel.ctx, &sel.ns, &sel.name).into_iter().map(|e| {
                        let r = Row_::new(e.address(), if e.taken { INFO() } else { WARNING() }).mid(format!("{} {}", if e.way == podxray::Way::Ingress { "ingress" } else { "route" }, e.name)).end(if e.tls { "TLS" } else { "plain HTTP" });
                        if e.way == podxray::Way::Ingress { r.to(lk(Kind::Ingresses, &e.name)) } else { r }
                    }).collect();
                    if !l.is_empty() {
                        rows(ui, "Exposed by", "", &l, "", 12, &mut open);
                    }
                }
                let l: Vec<Row_> = spec["ports"].as_array().into_iter().flatten().map(|p| {
                    let proto = p["protocol"].as_str().unwrap_or("TCP");
                    Row_::new(format!("{}{}", p["name"].as_str().map(|n| format!("{n}  ")).unwrap_or_default(), p["port"]), INFO()).mid(format!("→ target port {}", any(&p["targetPort"]))).end(format!("{proto}{}", p["nodePort"].as_i64().map(|n| format!(", node port {n}")).unwrap_or_default()))
                }).collect();
                rows(ui, "Ports", "", &l, "None.", 20, &mut open);
            }
            Kind::Ingresses => {
                let e = podxray::pick_ingress(o);
                let l: Vec<Row_> = e.iter().map(|x| {
                    let port = spec["rules"].as_array().into_iter().flatten().flat_map(|r| r["http"]["paths"].as_array().into_iter().flatten()).find(|p| p["backend"]["service"]["name"].as_str() == Some(&x.service)).map(|p| any(if p["backend"]["service"]["port"]["number"].is_null() { &p["backend"]["service"]["port"]["name"] } else { &p["backend"]["service"]["port"]["number"] })).unwrap_or_default();
                    let exists = self.refs(&sel.ctx, Kind::Services, &sel.ns).map(|l| l.iter().any(|s| name_of(s) == x.service));
                    let (col, end) = match (exists, self.service_ready(&sel.ctx, &sel.ns, &x.service)) {
                        (Some(false), _) => (DANGER(), "that service doesn't exist".to_string()),
                        (_, Some((0, 0))) => (WARNING(), "no pods".into()),
                        (_, Some((0, n))) => (DANGER(), format!("0 of {n} pods ready")),
                        (_, Some((r, n))) => (if r < n { WARNING() } else { SUCCESS() }, format!("{r} of {} ready", many(n as i64, "pod"))),
                        _ => (TEXT_SUBTLE(), String::new()),
                    };
                    Row_::new(x.address(), col).mid(format!("→ service {}{}", x.service, if port.is_empty() { String::new() } else { format!(", port {port}") })).end(end).to(lk(Kind::Services, &x.service))
                }).collect();
                rows(ui, "Rules", "host and path to service; click for the service", &l, "No rules.", 30, &mut open);
                let mut hosts: Vec<&podxray::Entry> = vec![];
                for x in e.iter().filter(|x| x.plain) {
                    if !hosts.iter().any(|h| h.host == x.host) {
                        hosts.push(x);
                    }
                }
                if !hosts.is_empty() {
                    ui.horizontal_wrapped(|ui| {
                        for h in hosts.iter().take(6) {
                            if button(ui, &format!("Open {}", h.host), false, false) {
                                ui.ctx().open_url(egui::OpenUrl::new_tab(h.url()));
                            }
                        }
                    });
                }
            }
            Kind::EndpointSlices => {
                let l: Vec<Row_> = o["endpoints"].as_array().into_iter().flatten().map(|e| {
                    let ok = e["conditions"]["ready"] != false;
                    let addr = e["addresses"].as_array().into_iter().flatten().map(&s).collect::<Vec<_>>().join(", ");
                    let t = &e["targetRef"];
                    let r = Row_::new(addr, if ok { SUCCESS() } else if e["conditions"]["terminating"] == true { TEXT_SUBTLE() } else { WARNING() }).mid(format!("{} {}", s(&t["kind"]).to_lowercase(), s(&t["name"]))).end(if ok { s(&e["nodeName"]) } else if e["conditions"]["terminating"] == true { "stopping".into() } else { "not ready".into() });
                    if t["kind"] == "Pod" { r.to(lk(Kind::Pods, &s(&t["name"]))) } else { r }
                }).collect();
                rows(ui, "Endpoints", "", &l, "None.", 100, &mut open);
            }
            Kind::NetworkPolicies => {
                for (inward, title) in [(true, "Ingress rules"), (false, "Egress rules")] {
                    let l: Vec<(String, Color32)> = match policy_words(o, inward) {
                        None => vec![("Not restricted by this policy.".into(), TEXT_SUBTLE())],
                        Some(l) if l.is_empty() => vec![(if inward { "All ingress denied, except what another policy allows." } else { "All egress denied, except what another policy allows." }.into(), WARNING())],
                        Some(l) => l.into_iter().map(|(who, ports)| (format!("{} {who}, {ports}", if inward { "from" } else { "to" }), TEXT_MUTED())).collect(),
                    };
                    paragraph(ui, title, if inward { "traffic allowed to the selected pods" } else { "traffic allowed from the selected pods" }, &l);
                }
                let pods = self.pods_like(sel, &spec["podSelector"]);
                let l: Vec<Row_> = pods.iter().map(|p| { let v = pod::verdict(p, now); Row_::new(name_of(p), tone_color(v.0)).mid(v.1).to(lk(Kind::Pods, name_of(p))) }).collect();
                rows(ui, &format!("Selected pods ({})", l.len()), "", &l, &self.missing(&sel.ctx, Kind::Pods).unwrap_or("No pod matches the selector.".into()), 20, &mut open);
            }
            Kind::PodDisruptionBudgets => {
                card(ui, |ui| {
                    let n = |k: &str| st[k].as_i64().unwrap_or(0) as f64;
                    panel(ui, "Healthy pods", "");
                    meter(ui, "Healthy", n("currentHealthy"), n("expectedPods"), &format!("{:.0} of {:.0}", n("currentHealthy"), n("expectedPods")), if n("currentHealthy") >= n("desiredHealthy") { SUCCESS() } else { DANGER() });
                    meter(ui, "Required", n("desiredHealthy"), n("expectedPods"), &format!("{:.0}", n("desiredHealthy")), INFO());
                });
                ui.add_space(10.0);
                let pods = self.pods_like(sel, &spec["selector"]);
                let l: Vec<Row_> = pods.iter().map(|p| { let v = pod::verdict(p, now); Row_::new(name_of(p), tone_color(v.0)).mid(v.1).end(s(&p["spec"]["nodeName"])).to(lk(Kind::Pods, name_of(p))) }).collect();
                rows(ui, &format!("Selected pods ({})", l.len()), "", &l, &self.missing(&sel.ctx, Kind::Pods).unwrap_or("No pod matches the selector.".into()), 30, &mut open);
            }
            Kind::HorizontalPodAutoscalers => self.hpa_body(ui, o),
            Kind::ResourceQuotas => {
                card(ui, |ui| {
                    panel(ui, "Used of hard limits", "");
                    quota_meters(ui, o);
                });
                ui.add_space(10.0);
            }
            Kind::LimitRanges => limit_table(ui, o),
            Kind::ConfigMaps | Kind::Secrets | Kind::ServiceAccounts | Kind::PersistentVolumeClaims => {
                let l: Vec<Row_> = self.users_of(sel).into_iter().map(|(k, n, how)| {
                    let v = self.object_of(&lk(k, &n)).map(|w| if k == Kind::Pods { pod::verdict(&w, now) } else { face::verdict(k, &w, now) });
                    let col = v.as_ref().map(|v| tone_color(v.0)).unwrap_or(TEXT_SUBTLE());
                    Row_::new(n.clone(), if k == Kind::Ingresses { INFO() } else { col }).mid(format!("{}{}", k.singular(), if how.is_empty() { String::new() } else { format!(", {how}") })).end(v.map(|v| v.1).unwrap_or_default()).to(lk(k, &n))
                }).collect();
                let none = if self.users_reading(&sel.ctx) { "Reading the workloads…" } else { "Nothing in this namespace references it. Programs that read it through the API aren't seen here." };
                rows(ui, "Used by", "", &l, none, 20, &mut open);
                if sel.kind == Kind::ServiceAccounts {
                    let mut l: Vec<Row_> = vec![];
                    for (kind, ns) in [(Kind::RoleBindings, sel.ns.as_str()), (Kind::ClusterRoleBindings, "")] {
                        for b in self.refs(&sel.ctx, kind, ns).unwrap_or_default() {
                            let hit = b["subjects"].as_array().into_iter().flatten().any(|x| x["kind"] == "ServiceAccount" && x["name"].as_str() == Some(&sel.name) && x["namespace"].as_str().unwrap_or(&sel.ns) == sel.ns);
                            if hit {
                                let r = s(&b["roleRef"]["name"]);
                                let power = r == "cluster-admin" || r == "admin";
                                l.push(Row_::new(r.clone(), if power { WARNING() } else { INFO() }).mid(if kind == Kind::RoleBindings { format!("in {}", sel.ns) } else { "cluster-wide".into() }).end(format!("via {}", name_of(b))).to(lk(kind, name_of(b))));
                            }
                        }
                    }
                    let gone: Vec<String> = [Kind::RoleBindings, Kind::ClusterRoleBindings].iter().filter_map(|k| self.missing(&sel.ctx, *k)).collect();
                    let none = if gone.is_empty() { "No role is bound to it by name.".to_string() } else { gone.join("; ") };
                    rows(ui, "Roles", "bound to it by name; its groups may add more", &l, &none, 30, &mut open);
                }
            }
            Kind::Roles | Kind::ClusterRoles => {
                let l: Vec<Row_> = o["rules"].as_array().into_iter().flatten().map(|r| {
                    let (does, what, tone) = rule_words(r);
                    let col = match tone { Tone::Danger => DANGER(), Tone::Warning => WARNING(), _ => INFO() };
                    Row_::new(does, col).mid(what.clone()).end(match tone { Tone::Danger => "privileged", Tone::Warning => "broad", _ => "" }).tip(format!("{}\n{}", r["verbs"].as_array().into_iter().flatten().map(&s).collect::<Vec<_>>().join(", "), what))
                }).collect();
                rows(ui, "Rules", "verbs and resources", &l, "No rules.", 200, &mut open);
                let l: Vec<Row_> = self.bindings_of(sel).into_iter().map(|(k, b)| {
                    let subs: Vec<String> = b["subjects"].as_array().into_iter().flatten().map(|x| subject(x, &sel.ns)).collect();
                    let ns = s(&b["metadata"]["namespace"]);
                    Row_::new(name_of(b), INFO()).mid(subs.join(", ")).end(if ns.is_empty() { "cluster-wide".to_string() } else { format!("in {ns}") }).to(Selected { ctx: sel.ctx.clone(), kind: k, ns, name: name_of(b).into() })
                }).collect();
                rows(ui, "Bound to", "", &l, &self.missing(&sel.ctx, Kind::RoleBindings).unwrap_or("None.".into()), 40, &mut open);
            }
            Kind::RoleBindings | Kind::ClusterRoleBindings => {
                let l: Vec<Row_> = o["subjects"].as_array().into_iter().flatten().map(|x| {
                    let r = Row_::new(subject(x, &sel.ns), INFO());
                    if x["kind"] == "ServiceAccount" { r.to(Selected { ctx: sel.ctx.clone(), kind: Kind::ServiceAccounts, ns: x["namespace"].as_str().unwrap_or(&sel.ns).into(), name: s(&x["name"]) }) } else { r }
                }).collect();
                rows(ui, "Subjects", "", &l, "None.", 100, &mut open);
            }
            Kind::StorageClasses => {
                let l: Vec<Row_> = self.refs(&sel.ctx, Kind::PersistentVolumeClaims, "").unwrap_or_default().into_iter().filter(|c| c["spec"]["storageClassName"].as_str() == Some(&sel.name)).map(|c| {
                    let ns = s(&c["metadata"]["namespace"]);
                    let v = face::verdict(Kind::PersistentVolumeClaims, c, now);
                    let use_ = self.claim_usage(&sel.ctx, &ns, name_of(c)).map(|x| format!(", {:.0}% full", x.used / x.capacity.max(1.0) * 100.0)).unwrap_or_default();
                    Row_::new(format!("{ns}/{}", name_of(c)), tone_color(v.0)).mid(format!("{}{use_}", s(&c["status"]["capacity"]["storage"]))).end(v.1).to(Selected { ctx: sel.ctx.clone(), kind: Kind::PersistentVolumeClaims, ns, name: name_of(c).into() })
                }).collect();
                let total: f64 = self.refs(&sel.ctx, Kind::PersistentVolumeClaims, "").unwrap_or_default().into_iter().filter(|c| c["spec"]["storageClassName"].as_str() == Some(&sel.name)).map(|c| resources::mem_bytes(c["status"]["capacity"]["storage"].as_str().unwrap_or(""))).sum();
                rows(ui, &format!("Claims ({})", l.len()), &if total > 0.0 { format!("{} provisioned", gib(total)) } else { String::new() }, &l, &self.missing(&sel.ctx, Kind::PersistentVolumeClaims).unwrap_or("None.".into()), 40, &mut open);
                let p: Vec<(String, Color32)> = o["parameters"].as_object().into_iter().flatten().map(|(k, v)| (format!("{k} = {}", s(v)), TEXT_MUTED())).collect();
                if !p.is_empty() {
                    paragraph(ui, "Parameters", "", &p);
                }
            }
            Kind::IngressClasses => {
                let l: Vec<Row_> = self.ingresses_of(sel).into_iter().map(|i| { let ns = s(&i["metadata"]["namespace"]); Row_::new(format!("{ns}/{}", name_of(i)), INFO()).mid(podxray::pick_ingress(i).iter().map(|e| e.address()).collect::<Vec<_>>().join(", ")).to(Selected { ctx: sel.ctx.clone(), kind: Kind::Ingresses, ns, name: name_of(i).into() }) }).collect();
                rows(ui, &format!("Ingresses ({})", l.len()), "", &l, &self.missing(&sel.ctx, Kind::Ingresses).unwrap_or("None.".into()), 40, &mut open);
            }
            Kind::Namespaces => {
                let tiles = self.work_tiles(Some((&sel.ctx, &sel.name)));
                if !tiles.is_empty() {
                    card(ui, |ui| {
                        panel(ui, "Workloads", "coloured by health; D deployment, S stateful set, N daemon set, C cron job; click one to open it");
                        open = open.take().or(draw_tiles(ui, &tiles));
                    });
                    ui.add_space(10.0);
                }
                let trouble: Vec<Row_> = tiles.iter().filter(|t| matches!(t.tone, Tone::Danger | Tone::Warning)).map(|t| Row_::new(t.to.name.clone(), tone_color(t.tone)).mid(t.to.kind.singular()).end(t.head.clone()).to(t.to.clone())).collect();
                if !trouble.is_empty() {
                    rows(ui, "Needs attention", "", &trouble, "", 12, &mut open);
                }
                let sick: Vec<Row_> = self.refs(&sel.ctx, Kind::Pods, &sel.name).unwrap_or_default().into_iter().filter_map(|p| {
                    let v = pod::verdict(p, now);
                    matches!(v.0, Tone::Danger | Tone::Warning).then(|| Row_::new(name_of(p), tone_color(v.0)).mid(v.1).end(v.2.first().cloned().unwrap_or_default()).to(Selected { ctx: sel.ctx.clone(), kind: Kind::Pods, ns: sel.name.clone(), name: name_of(p).into() }))
                }).collect();
                if !sick.is_empty() {
                    rows(ui, "Pods that need attention", "", &sick, "", 12, &mut open);
                }
                for q in self.refs(&sel.ctx, Kind::ResourceQuotas, &sel.name).unwrap_or_default() {
                    card(ui, |ui| {
                        panel(ui, &format!("Quota {}", name_of(q)), "");
                        quota_meters(ui, q);
                    });
                    ui.add_space(10.0);
                }
                for l in self.refs(&sel.ctx, Kind::LimitRanges, &sel.name).unwrap_or_default() {
                    limit_table(ui, l);
                }
                let m = self.metrics.get(&sel.ctx);
                let mut top: Vec<(&Value, (f64, f64))> = self.refs(&sel.ctx, Kind::Pods, &sel.name).unwrap_or_default().into_iter().filter_map(|p| Some((p, *m?.pods.get(&(sel.name.clone(), name_of(p).to_string()))?))).collect();
                top.sort_by(|a, b| b.1 .1.partial_cmp(&a.1 .1).unwrap_or(std::cmp::Ordering::Equal));
                let l: Vec<Row_> = top.iter().map(|(p, x)| Row_::new(name_of(p), tone_color(pod::verdict(p, now).0)).mid(format!("{} CPU", hive::cores(x.0))).end(gib(x.1)).to(Selected { ctx: sel.ctx.clone(), kind: Kind::Pods, ns: sel.name.clone(), name: name_of(p).into() })).collect();
                if !l.is_empty() {
                    rows(ui, "Top pods", "by memory", &l, "", 10, &mut open);
                }
            }
            Kind::CSINodes => {
                let l: Vec<Row_> = spec["drivers"].as_array().into_iter().flatten().map(|d| Row_::new(s(&d["name"]), INFO()).end(d["allocatable"]["count"].as_i64().map(|n| format!("at most {}", many(n, "volume"))).unwrap_or_default()).to(lk(Kind::CSIDrivers, &s(&d["name"])))).collect();
                rows(ui, "Drivers", "", &l, "None.", 40, &mut open);
            }
            Kind::MutatingWebhooks | Kind::ValidatingWebhooks => {
                for w in o["webhooks"].as_array().into_iter().flatten() {
                    let strict = w["failurePolicy"] != "Ignore";
                    card(ui, |ui| {
                        panel(ui, &s(&w["name"]), &format!("failure policy {}, timeout {} s", if strict { "Fail" } else { "Ignore" }, w["timeoutSeconds"].as_i64().unwrap_or(10)));
                        for r in w["rules"].as_array().into_iter().flatten() {
                            let l = |k: &str| r[k].as_array().into_iter().flatten().map(&s).collect::<Vec<_>>().join(", ");
                            said(ui, &format!("{} on {}", l("operations"), l("resources")), TEXT_MUTED());
                        }
                        for (k, t) in [("namespaceSelector", "Namespace selector:"), ("objectSelector", "Object selector:")] {
                            let t2 = selector_words(&w[k]);
                            if !t2.is_empty() {
                                said(ui, &format!("{t} {t2}"), TEXT_SUBTLE());
                            }
                        }
                        let sv = &w["clientConfig"]["service"];
                        if let (Some(n), Some(ns)) = (sv["name"].as_str(), sv["namespace"].as_str()) {
                            self.link_line(ui, &format!("{ns}/{n}"), "service", INFO(), Selected { ctx: sel.ctx.clone(), kind: Kind::Services, ns: ns.into(), name: n.into() }, &mut open);
                        } else if let Some(url) = w["clientConfig"]["url"].as_str() {
                            said(ui, &format!("URL {url}"), TEXT_SUBTLE());
                        }
                    });
                    ui.add_space(8.0);
                }
            }
            Kind::CustomResourceDefinitions => {
                let l: Vec<Row_> = spec["versions"].as_array().into_iter().flatten().map(|v| Row_::new(s(&v["name"]), if v["served"] == true { SUCCESS() } else { TEXT_SUBTLE() }).mid(if v["served"] == true { "served" } else { "not served" }).end(format!("{}{}", if v["storage"] == true { "storage version" } else { "" }, if v["deprecated"] == true { " deprecated" } else { "" }))).collect();
                rows(ui, "Versions", "", &l, "None.", 20, &mut open);
            }
            _ => {}
        }
        open
    }

    /// An autoscaler's slider and what it goes by.
    fn hpa_body(&self, ui: &mut Ui, o: &Value) {
        let (spec, st) = (&o["spec"], &o["status"]);
        let (cur, want, min, max) = (st["currentReplicas"].as_i64().unwrap_or(0), st["desiredReplicas"].as_i64().unwrap_or(0), spec["minReplicas"].as_i64().unwrap_or(1), spec["maxReplicas"].as_i64().unwrap_or(1).max(1));
        card(ui, |ui| {
            panel(ui, "Replicas", "the shaded part is the allowed range");
            let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(62.0)), Sense::hover());
            let p = ui.painter();
            let track = egui::Rect::from_min_max(egui::pos2(r.left() + u(14.0), r.center().y - 5.0), egui::pos2(r.right() - u(14.0), r.center().y + 5.0));
            let x = |n: i64| track.left() + track.width() * (n as f32 / max as f32).clamp(0.0, 1.0);
            p.rect_filled(track, CornerRadius::same(5), BG_MUTED());
            p.rect_filled(egui::Rect::from_min_max(egui::pos2(x(min), track.top()), track.max), CornerRadius::same(5), INFO().gamma_multiply(0.35));
            let ticks = max.min(24);
            for i in 0..=ticks {
                let n = i * max / ticks;
                p.vline(x(n), track.bottom()..=(track.bottom() + 4.0), Stroke::new(1.0, BORDER_DEFAULT()));
            }
            for (n, t) in [(min, "min"), (max, "max")] {
                p.text(egui::pos2(x(n).clamp(r.left() + u(24.0), r.right() - u(24.0)), r.bottom()), egui::Align2::CENTER_BOTTOM, format!("{t} {n}"), FontId::proportional(z(11.0)), TEXT_SUBTLE());
            }
            if want != cur {
                p.circle_stroke(egui::pos2(x(want), track.center().y), u(9.0), Stroke::new(2.0, INFO()));
            }
            let col = if cur >= max { WARNING() } else { SUCCESS() };
            p.circle_filled(egui::pos2(x(cur), track.center().y), u(8.0), col);
            p.text(egui::pos2(x(cur).clamp(r.left() + u(34.0), r.right() - u(34.0)), r.top()), egui::Align2::CENTER_TOP, if want != cur { format!("current {cur}, desired {want}") } else { format!("current {cur}") }, FontId::proportional(z(12.0)), TEXT_DEFAULT());
        });
        ui.add_space(10.0);
        card(ui, |ui| {
            panel(ui, "Metrics", "current against target; above target it adds replicas");
            let l = hpa_metrics(o);
            if l.is_empty() {
                said(ui, "None.", TEXT_SUBTLE());
            }
            for (name, now, aim, words) in l {
                let (r, resp) = line(ui, u(28.0), false);
                let share = match (now, aim) { (Some(n), Some(a)) if a > 0.0 => n / a, _ => 0.0 };
                at(ui, r, 0.0, 0.42, &name, 12.5, TEXT_DEFAULT());
                dash::bar(ui, r, 0.43, 0.22, share, if share >= 1.0 { WARNING() } else { SUCCESS() });
                at_end(ui, r, 1.0, &words, 12.0, TEXT_MUTED());
                resp.on_hover_text(format!("{name}\n{words}"));
            }
        });
        ui.add_space(10.0);
    }
}

fn quota_meters(ui: &mut Ui, o: &Value) {
    for (what, used, hard) in face::quota(o) {
        let share = if hard > 0.0 { used / hard } else { 0.0 };
        let col = if share >= 1.0 { DANGER() } else if share >= 0.85 { WARNING() } else { SUCCESS() };
        meter(ui, &what, used, hard, &if hard == 0.0 { "0 allowed".to_string() } else { format!("{} of {}", amount_words(&what, used), amount_words(&what, hard)) }, col);
    }
}

fn limit_table(ui: &mut Ui, o: &Value) {
    card(ui, |ui| {
        panel(ui, &format!("Limit range {}", name_of(o)), "");
        let (r, _) = line(ui, u(22.0), false);
        let cols = [("Type", "", 0.0), ("Resource", "", 0.16), ("Min", "min", 0.32), ("Default request", "defaultRequest", 0.46), ("Default limit", "default", 0.66), ("Max", "max", 0.86)];
        for (t, _, x) in cols {
            at(ui, r, x, 0.22, t, 11.5, TEXT_SUBTLE());
        }
        for l in o["spec"]["limits"].as_array().into_iter().flatten() {
            let mut res: Vec<&String> = ["min", "max", "default", "defaultRequest"].iter().flat_map(|k| l[*k].as_object().into_iter().flatten().map(|x| x.0)).collect();
            res.sort();
            res.dedup();
            for k in res {
                let (r, _) = line(ui, u(26.0), false);
                at(ui, r, 0.0, 0.16, l["type"].as_str().unwrap_or(""), 12.5, TEXT_MUTED());
                at(ui, r, 0.16, 0.15, k, 12.5, TEXT_DEFAULT());
                for (_, key, x) in cols.iter().skip(2) {
                    at(ui, r, *x, 0.15, l[*key][k].as_str().unwrap_or("–"), 12.5, TEXT_DEFAULT());
                }
            }
        }
    });
    ui.add_space(10.0);
}

// ---------- every workload, as boxes ----------

pub(super) struct Tile {
    pub to: Selected,
    pub tone: Tone,
    pub head: String,
    pub pods: i64,
}

/// Boxes that fill the width, a letter for their kind; bigger ones run more pods. Returns the one clicked.
pub(super) fn draw_tiles(ui: &mut Ui, tiles: &[Tile]) -> Option<Selected> {
    let mut open = None;
    let gap = 5.0;
    let size = u(22.0);
    let avail = ui.available_width();
    let cols = ((avail + gap) / (size + gap)).floor().max(1.0) as usize;
    let n = tiles.len().min(600);
    let (area, _) = ui.allocate_exact_size(egui::vec2(avail, n.div_ceil(cols) as f32 * (size + gap)), Sense::hover());
    for (i, t) in tiles.iter().take(n).enumerate() {
        let r = egui::Rect::from_min_size(area.min + egui::vec2((i % cols) as f32 * (size + gap), (i / cols) as f32 * (size + gap)), egui::vec2(size, size));
        if tile(ui, r, t) {
            open = Some(t.to.clone());
        }
    }
    open
}

pub(super) fn letter(k: Kind) -> &'static str {
    match k { Kind::Deployments => "D", Kind::StatefulSets => "S", Kind::DaemonSets => "N", Kind::CronJobs => "C", Kind::Jobs => "J", _ => "" }
}

pub(super) fn tile(ui: &mut Ui, r: egui::Rect, t: &Tile) -> bool {
    let resp = ui.interact(r, ui.id().with(("tile", t.to.key())), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
    let col = match t.tone { Tone::Muted | Tone::Normal => TEXT_PLACEHOLDER(), x => tone_color(x) };
    let p = ui.painter();
    let quiet = matches!(t.tone, Tone::Muted | Tone::Normal);
    let strong = matches!(t.tone, Tone::Danger | Tone::Warning);
    p.rect_filled(r, CornerRadius::same(5), col.gamma_multiply(if quiet { 0.12 } else if strong { 0.75 } else if resp.hovered() { 0.45 } else { 0.28 }));
    p.rect_stroke(r, CornerRadius::same(5), Stroke::new(if resp.hovered() { 2.0 } else { 1.0 }, col.gamma_multiply(if quiet { 0.5 } else { 0.9 })), egui::StrokeKind::Inside);
    p.text(r.center(), egui::Align2::CENTER_CENTER, letter(t.to.kind), FontId::proportional(z(11.0)), if strong { BG_DEFAULT() } else { col });
    resp.on_hover_text(format!("{}/{}\n{}: {}{}", t.to.ns, t.to.name, t.to.kind.singular(), t.head, if t.pods > 0 { format!("\n{}", many(t.pods, "pod")) } else { String::new() })).clicked()
}

impl KubedogApp {
    /// Every workload shown (or of one namespace), with how it is.
    pub(super) fn work_tiles(&self, only: Option<(&str, &str)>) -> Vec<Tile> {
        let now = kube::now_secs();
        let mut out = vec![];
        let ctxs: Vec<&String> = self.active.iter().filter(|c| only.map(|o| o.0 == c.as_str()).unwrap_or_else(|| self.ctx_shown(c))).collect();
        for c in ctxs {
            for k in [Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::CronJobs] {
                for o in self.refs(c, k, only.map(|o| o.1).unwrap_or("")).unwrap_or_default() {
                    let ns = o["metadata"]["namespace"].as_str().unwrap_or("");
                    if only.is_none() && !self.ns_ok(ns) {
                        continue;
                    }
                    let v = face::verdict(k, o, now);
                    let pods = o["status"]["replicas"].as_i64().or(o["status"]["desiredNumberScheduled"].as_i64()).unwrap_or(0);
                    out.push(Tile { to: Selected { ctx: c.to_string(), kind: k, ns: ns.into(), name: name_of(o).into() }, tone: v.0, head: v.1, pods });
                }
            }
        }
        out
    }

    /// The Workloads overview's summary: how many are well, and who needs a look.
    pub(super) fn work_summary(&self, ui: &mut Ui) -> Option<Selected> {
        let mut open = None;
        let tiles = self.work_tiles(None);
        let ctxs: Vec<&String> = self.active.iter().filter(|c| self.ctx_shown(c)).collect();
        let kinds = [Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::CronJobs];
        let wait: Vec<String> = ctxs.iter().flat_map(|c| kinds.iter().filter_map(|k| self.missing(c, *k))).collect();
        if tiles.is_empty() && !wait.is_empty() {
            return None;
        }
        let count = |f: &dyn Fn(Tone) -> bool| tiles.iter().filter(|t| f(t.tone)).count();
        let bad = count(&|t| t == Tone::Danger);
        let warn = count(&|t| t == Tone::Warning);
        let moving = count(&|t| t == Tone::Info);
        let idle = count(&|t| matches!(t, Tone::Muted | Tone::Normal));
        let well = tiles.len() - bad - warn - moving - idle;
        let (tone, head) = if tiles.is_empty() {
            (Tone::Muted, "No workloads here".to_string())
        } else if bad > 0 {
            (Tone::Danger, format!("{} failing", many(bad as i64, "workload")))
        } else if warn > 0 {
            (Tone::Warning, format!("{} degraded", many(warn as i64, "workload")))
        } else {
            (Tone::Success, "All workloads healthy".into())
        };
        let mut f = Face { tone, head, sub: format!("{} in {}", many(tiles.len() as i64, "workload"), many(tiles.iter().map(|t| (&t.to.ctx, &t.to.ns)).collect::<HashSet<_>>().len() as i64, "namespace")), notes: vec![], pills: vec![], facts: vec![] };
        for (n, t, c) in [(well, "healthy", SUCCESS()), (moving, "rolling out or running", INFO()), (warn, "degraded", WARNING()), (bad, "failing", DANGER()), (idle, "scaled to 0 or suspended", TEXT_SUBTLE())] {
            if n > 0 {
                f.pills.push((format!("● {n} {t}"), c, String::new()));
            }
        }
        let mut gone: Vec<String> = wait;
        gone.dedup();
        if !gone.is_empty() {
            f.pills.push((gone.join("; "), TEXT_PLACEHOLDER(), String::new()));
        }
        let share = if tiles.len() > idle { well as f64 / (tiles.len() - idle) as f64 } else { 1.0 };
        face::show(ui, &f, Side::Ring(share, format!("{:.0}%", share * 100.0), "of active workloads healthy".into()));
        if tiles.is_empty() {
            return None;
        }
        ui.add_space(12.0);
        let mut trouble: Vec<&Tile> = tiles.iter().filter(|t| matches!(t.tone, Tone::Danger | Tone::Warning)).collect();
        trouble.sort_by_key(|t| (t.tone != Tone::Danger, t.to.ns.clone(), t.to.name.clone()));
        if !trouble.is_empty() {
            let now = kube::now_secs();
            let l: Vec<Row_> = trouble
                .iter()
                .map(|t| {
                    // The first thing its pods say, when there's something.
                    let why = if trouble.len() <= 40 { self.object_of(&t.to).and_then(|o| { let p = self.pods_of(&t.to, &o)?; p.iter().map(|p| pod::verdict(p, now)).find(|v| matches!(v.0, Tone::Danger | Tone::Warning)).map(|v| v.1) }) } else { None };
                    Row_::new(format!("{}/{}", t.to.ns, t.to.name), tone_color(t.tone)).mid(format!("{}{}", t.to.kind.singular(), why.map(|w| format!(": {w}")).unwrap_or_default())).end(t.head.clone()).to(t.to.clone())
                })
                .collect();
            rows(ui, "Needs attention", "", &l, "", 8, &mut open);
        }
        open
    }

    /// Every workload as a box, by namespace.
    pub(super) fn work_map(&self, ui: &mut Ui) -> Option<Selected> {
        let mut open = None;
        let tiles = self.work_tiles(None);
        if tiles.is_empty() {
            return None;
        }
        let many_ctx = self.active.iter().filter(|c| self.ctx_shown(c)).count() > 1;
        ui.add_space(26.0);
        let mut by: Vec<(String, Vec<&Tile>)> = vec![];
        let mut at_: HashMap<(String, String), usize> = HashMap::new();
        for t in &tiles {
            let key = (t.to.ctx.clone(), t.to.ns.clone());
            let i = *at_.entry(key).or_insert_with(|| {
                by.push((if many_ctx { format!("{} · {}", ctx_label(&t.to.ctx), t.to.ns) } else { t.to.ns.clone() }, vec![]));
                by.len() - 1
            });
            by[i].1.push(t);
        }
        let worst = |l: &[&Tile]| l.iter().filter(|t| matches!(t.tone, Tone::Danger | Tone::Warning)).count();
        by.sort_by(|a, b| worst(&b.1).cmp(&worst(&a.1)).then(b.1.len().cmp(&a.1.len())).then(a.0.cmp(&b.0)));
        let left = by.len().saturating_sub(200);
        by.truncate(200);
        card(ui, |ui| {
            panel(ui, "All workloads", "by namespace: D deployment, S stateful set, N daemon set, C cron job; click one to open it");
            let (size, gap, pad, head) = (u(20.0), 4.0, 9.0, u(22.0));
            let avail = ui.available_width();
            // Place the namespaces next to each other, as they fit.
            let mut place: Vec<(f32, f32, f32, f32, usize)> = vec![];
            let (mut x, mut y, mut tall) = (0.0f32, 0.0f32, 0.0f32);
            for (name, l) in &by {
                let shown = l.len().min(240);
                let title = ui.painter().layout_no_wrap(name.clone(), FontId::proportional(z(12.0)), TEXT_DEFAULT()).size().x.min(u(190.0));
                let most = (((avail - 2.0 * pad + gap) / (size + gap)).floor() as usize).max(1);
                let cols = ((shown as f32 * 3.0).sqrt().ceil() as usize).max(((title + gap) / (size + gap)).ceil() as usize).clamp(1, most);
                let w = cols as f32 * (size + gap) - gap + 2.0 * pad;
                let h = head + shown.div_ceil(cols) as f32 * (size + gap) - gap + pad * 1.5;
                if x > 0.0 && x + w > avail {
                    x = 0.0;
                    y += tall + 10.0;
                    tall = 0.0;
                }
                place.push((x, y, w, h, cols));
                x += w + 10.0;
                tall = tall.max(h);
            }
            let (area, _) = ui.allocate_exact_size(egui::vec2(avail, y + tall), Sense::hover());
            for ((name, l), (x, y, w, h, cols)) in by.iter().zip(&place) {
                let r = egui::Rect::from_min_size(area.min + egui::vec2(*x, *y), egui::vec2(*w, *h));
                let bad = worst(l);
                ui.painter().rect_filled(r, CornerRadius::same(8), BG_SUBTLE());
                ui.painter().rect_stroke(r, CornerRadius::same(8), Stroke::new(1.0, if bad > 0 { WARNING().gamma_multiply(0.6) } else { BORDER_SUBTLE() }), egui::StrokeKind::Inside);
                label_at(ui, ui.painter(), egui::pos2(r.left() + pad, r.top() + head * 0.55), name, 12.0, TEXT_MUTED(), w - 2.0 * pad);
                for (i, t) in l.iter().take(240).enumerate() {
                    let tr = egui::Rect::from_min_size(egui::pos2(r.left() + pad + (i % cols) as f32 * (size + gap), r.top() + head + (i / cols) as f32 * (size + gap)), egui::vec2(size, size));
                    if tile(ui, tr, t) {
                        open = Some(t.to.clone());
                    }
                }
            }
            if left > 0 {
                said(ui, &format!("and {left} more namespaces"), TEXT_PLACEHOLDER());
            }
        });
        open
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn policies() {
        let o = json!({"spec": {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "shop"}}, "podSelector": {"matchLabels": {"app": "web"}}}, {"ipBlock": {"cidr": "10.0.0.0/8", "except": ["10.1.0.0/16"]}}, {"podSelector": {}}, {"namespaceSelector": {}}], "ports": [{"port": 8000, "protocol": "TCP"}, {"port": 53, "protocol": "UDP"}]}, {}]}});
        let l = policy_words(&o, true).unwrap();
        assert_eq!(l[0], ("pods with app=web in namespace shop".to_string(), "ports 8000, 53/UDP".to_string()));
        assert_eq!(l[1].0, "addresses 10.0.0.0/8 except 10.1.0.0/16");
        assert_eq!(l[2].0, "any pod in this namespace");
        assert_eq!(l[3].0, "any pod in any namespace");
        assert_eq!(l[4], ("anyone, from anywhere".to_string(), "any port".to_string()));
        assert!(policy_words(&o, false).is_none());
        assert_eq!(policy_words(&json!({"spec": {"policyTypes": ["Egress"]}}), false), Some(vec![]));
    }

    #[test]
    fn roles() {
        let r = |v: Value| rule_words(&v);
        assert_eq!(r(json!({"verbs": ["get", "list", "watch"], "resources": ["pods"], "apiGroups": [""]})), ("get, list, watch".into(), "pods  (core)".into(), Tone::Normal));
        assert_eq!(r(json!({"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]})), ("*".into(), "*  (*)".into(), Tone::Danger));
        assert_eq!(r(json!({"verbs": ["get"], "resources": ["secrets"], "apiGroups": [""]})).2, Tone::Warning);
        assert_eq!(r(json!({"verbs": ["get"], "resources": ["secrets"], "apiGroups": [""], "resourceNames": ["one"]})).2, Tone::Normal);
        assert_eq!(r(json!({"verbs": ["create"], "resources": ["pods/exec"], "apiGroups": [""]})).2, Tone::Danger);
        assert_eq!(r(json!({"verbs": ["get"], "nonResourceURLs": ["/metrics"]})).1, "/metrics");
        assert_eq!(r(json!({"verbs": ["create", "patch", "approve"], "resources": ["things"], "apiGroups": ["a.b"]})).0, "create, patch, approve");
    }

    #[test]
    fn autoscalers() {
        let o = json!({"spec": {"metrics": [
            {"type": "Resource", "resource": {"name": "cpu", "target": {"type": "Utilization", "averageUtilization": 80}}},
            {"type": "External", "external": {"metric": {"name": "queue"}, "target": {"type": "AverageValue", "averageValue": "500"}}},
            {"type": "Resource", "resource": {"name": "memory", "target": {"type": "AverageValue", "averageValue": "1Gi"}}}
        ]}, "status": {"currentMetrics": [
            {"type": "External", "external": {"metric": {"name": "queue"}, "current": {"averageValue": "250m"}}},
            {"type": "Resource", "resource": {"name": "cpu", "current": {"averageUtilization": 40, "averageValue": "20m"}}}
        ]}});
        let m = hpa_metrics(&o);
        assert_eq!((m[0].1, m[0].2), (Some(40.0), Some(80.0)));
        assert_eq!((m[1].0.as_str(), m[1].1, m[1].2), ("queue", Some(0.25), Some(500.0)));
        assert_eq!(m[2].3, "unknown / 1.0Gi per pod");
    }
}
