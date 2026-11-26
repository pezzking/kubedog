//! Gateways (every way in: conflicts and dead backends), monitoring (alerts, monitors that match
//! nothing) and backups (what's covered and how old).

use super::face::{many, Side};
use super::ops::{ago, ns_of, obj, summary, table, text, worst_first, Item};
use super::pg::panel;
use super::podxray::Go;
use super::work::{name_of, said};
use super::*;

/// A way in from outside.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Door {
    pub ctx: String,
    pub ns: String,
    pub kind: &'static str,
    pub name: String,
    pub host: String,
    pub path: String,
    pub service: String,
    pub tls: bool,
    pub taken: bool,
}

/// Two ways in for the same address in one cluster: indexes of those that clash.
pub(super) fn clashes(l: &[Door]) -> HashSet<usize> {
    let mut m: HashMap<(&str, &str, &str), Vec<usize>> = HashMap::new();
    for (i, d) in l.iter().enumerate().filter(|(_, d)| !d.host.is_empty() && d.host != "*") {
        m.entry((&d.ctx, &d.host, &d.path)).or_default().push(i);
    }
    m.into_values().filter(|v| v.iter().map(|i| (&l[*i].kind, &l[*i].ns, &l[*i].name)).collect::<HashSet<_>>().len() > 1).flatten().collect()
}

/// What a Route is, without its certificate and key.
fn slim_route(o: &Value) -> Value {
    let made = o["metadata"]["ownerReferences"].as_array().into_iter().flatten().any(|r| r["kind"] == "Ingress");
    let taken = o["status"]["ingress"].as_array().into_iter().flatten().any(|i| i["conditions"].as_array().into_iter().flatten().any(|c| c["type"] == "Admitted" && c["status"] == "True"));
    serde_json::json!({"ns": o["metadata"]["namespace"], "name": o["metadata"]["name"], "host": o["spec"]["host"], "path": o["spec"]["path"], "service": o["spec"]["to"]["name"], "tls": o["spec"]["tls"]["termination"], "taken": taken, "made": made})
}

/// Does a monitor's selector find anything? (how many, ports that exist)
fn monitored<'a>(o: &Value, ns: &str, all: &[&'a Value], labels: impl Fn(&Value) -> Value) -> Vec<&'a Value> {
    let sel = &o["spec"]["namespaceSelector"];
    let names: Vec<&str> = sel["matchNames"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).collect();
    all.iter().filter(|s| if sel["any"] == true { true } else if names.is_empty() { ns_of(s) == ns } else { names.contains(&ns_of(s)) }).filter(|s| podnet::selector_matches(&o["spec"]["selector"], &labels(s))).copied().collect()
}

/// A Kasten RunAction for a policy.
pub(super) fn kasten_run(ns: &str, policy: &str) -> String {
    serde_json::json!({"apiVersion": "actions.kio.kasten.io/v1alpha1", "kind": "RunAction", "metadata": {"generateName": format!("run-{policy}-"), "namespace": ns}, "spec": {"subject": {"apiVersion": "config.kio.kasten.io/v1alpha1", "kind": "Policy", "name": policy, "namespace": ns}}}).to_string()
}

/// The newest good backup of a namespace: (when, by what).
pub(super) fn newest<'a>(ns: &str, velero: impl Iterator<Item = &'a Value>, kasten: &[Value]) -> Option<(i64, String)> {
    let mut best: Option<(i64, String)> = None;
    let mut add = |t: Option<i64>, by: String| {
        if let Some(t) = t {
            if best.as_ref().map(|b| b.0 < t).unwrap_or(true) {
                best = Some((t, by));
            }
        }
    };
    for b in velero.filter(|b| b["status"]["phase"] == "Completed") {
        let list = |k: &str| -> Vec<&str> { b["spec"][k].as_array().into_iter().flatten().filter_map(|x| x.as_str()).collect() };
        let (inc, exc) = (list("includedNamespaces"), list("excludedNamespaces"));
        if (inc.is_empty() || inc.contains(&"*") || inc.contains(&ns)) && !exc.contains(&ns) {
            add(pod::time_of(&b["status"]["completionTimestamp"]), format!("Velero {}", name_of(b)));
        }
    }
    for p in kasten.iter().filter(|p| p["ns"].as_str() == Some(ns)) {
        add(pod::time_of(&p["at"]), format!("Kasten {}", text(&p["name"])));
    }
    best
}

impl KubedogApp {
    // ---------- gateways ----------

    pub(super) fn ask_routes(&mut self, force: bool) {
        for c in self.active.clone() {
            let ctx = c.clone();
            self.ask(&format!("routes|{c}"), 30, force, move |k| {
                let a: Vec<String> = ["--context", &ctx, "get", "routes.route.openshift.io", "--all-namespaces", "-o", "json", &format!("--request-timeout={}", kube::REQUEST_TIMEOUT)].iter().map(|s| s.to_string()).collect();
                let items = match k.run(&a) {
                    Ok(j) => kube::parse_items(&j)?,
                    Err(e) if e.contains("doesn't have a resource type") => vec![],
                    Err(e) => return Err(e),
                };
                // Keys in routes are dropped before anything is kept.
                Ok(Value::Array(items.iter().map(slim_route).collect()).to_string())
            });
        }
    }

    pub(super) fn doors(&self) -> Vec<Door> {
        let mut out = vec![];
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            let mut add = |ns: &str, kind, e: podxray::Entry| out.push(Door { ctx: c.clone(), ns: ns.into(), kind, name: e.name, host: e.host, path: if e.path.is_empty() { "/".into() } else { e.path }, service: e.service, tls: e.tls, taken: e.taken });
            for i in self.refs(c, Kind::Ingresses, "").unwrap_or_default() {
                for e in podxray::pick_ingress(i) {
                    add(ns_of(i), "Ingress", e);
                }
            }
            for h in self.op_all(c, "httproutes.gateway.networking.k8s.io") {
                for e in podxray::pick_http(h) {
                    add(ns_of(h), "HTTPRoute", e);
                }
            }
            if let Some(Ok(Value::Array(l))) = self.answer(&format!("routes|{c}")) {
                for r in l.iter().filter(|r| r["made"] != true) {
                    out.push(Door { ctx: c.clone(), ns: text(&r["ns"]), kind: "Route", name: text(&r["name"]), host: text(&r["host"]), path: r["path"].as_str().filter(|p| !p.is_empty()).unwrap_or("/").into(), service: text(&r["service"]), tls: r["tls"].is_string(), taken: r["taken"] == true });
                }
            }
        }
        out
    }

    pub(super) fn gateways_page(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        let doors: Vec<Door> = self.doors().into_iter().filter(|d| self.ns_ok(&d.ns)).collect();
        let clash = clashes(&doors);
        let many_ctx = self.active.len() > 1;
        // Services once each: there are many doors.
        let mut ready: HashMap<(String, String, String), (Option<bool>, Option<(usize, usize)>)> = HashMap::new();
        for d in &doors {
            ready.entry((d.ctx.clone(), d.ns.clone(), d.service.clone())).or_insert_with(|| {
                let exists = self.refs(&d.ctx, Kind::Services, &d.ns).map(|l| l.iter().any(|s| name_of(s) == d.service));
                (exists, self.service_ready(&d.ctx, &d.ns, &d.service))
            });
        }
        let items: Vec<Item> = doors
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let (exists, r) = ready.get(&(d.ctx.clone(), d.ns.clone(), d.service.clone())).copied().unwrap_or((None, None));
                let (t, w) = match (exists, r) {
                    (Some(false), _) => (Tone::Danger, "its service doesn't exist".to_string()),
                    (_, Some((0, 0))) => (Tone::Warning, "no endpoints".into()),
                    (_, Some((0, n))) => (Tone::Danger, format!("0/{n} endpoints ready")),
                    _ if !d.taken => (Tone::Warning, "not admitted".into()),
                    _ if clash.contains(&i) => (Tone::Warning, "the same address twice".into()),
                    (_, Some((r, n))) if r < n => (Tone::Warning, format!("{r}/{n} endpoints ready")),
                    (_, Some((r, n))) => (Tone::Success, format!("{r}/{n} endpoints ready")),
                    _ => (Tone::Muted, "backend not known".into()),
                };
                let g = match d.kind { "Ingress" => Some(obj(&d.ctx, Kind::Ingresses, &d.ns, &d.name)), "HTTPRoute" => self.crd_index("httproutes.gateway.networking.k8s.io").map(|idx| Go::Custom(crds::CustomSel { ctx: d.ctx.clone(), idx, ns: d.ns.clone(), name: d.name.clone() })), _ => Some(obj(&d.ctx, Kind::Services, &d.ns, &d.service)) };
                let twin = if clash.contains(&i) { format!("\nalso served by: {}", doors.iter().enumerate().filter(|(j, x)| *j != i && x.ctx == d.ctx && x.host == d.host && x.path == d.path).map(|(_, x)| format!("{} {}/{}", x.kind, x.ns, x.name)).collect::<Vec<_>>().join(", ")) } else { String::new() };
                Item::new(t, vec![format!("{}{}", if d.host.is_empty() { "(no host)" } else { &d.host }, if d.path == "/" { "" } else { &d.path }), w.clone(), format!("{} {}", d.kind, d.name), format!("{}{}", if many_ctx { format!("{} · ", ctx_label(&d.ctx)) } else { String::new() }, d.ns), d.service.clone(), if d.tls { "TLS".into() } else { "plain HTTP".into() }]).tip(format!("{}{}\n{w}{twin}", d.host, d.path)).go(g)
            })
            .collect();
        let mut f = summary(&items, "address");
        f.head = f.head.replace("addresss", "addresses");
        f.sub = f.sub.replace("addresss", "addresses");
        let plain = doors.iter().filter(|d| !d.tls).count();
        if !clash.is_empty() {
            f.notes.push(format!("{} answered by more than one: which one wins depends on the controller.", clash.len()));
        }
        if plain > 0 {
            f.notes.push(format!("{plain} without TLS."));
        }
        face::show(ui, &f, Side::None);
        ui.add_space(10.0);
        self.bad_switch(ui);
        for c in &self.active {
            if let Some(Err(e)) = self.answer(&format!("routes|{c}")) {
                said(ui, &format!("{}: routes couldn't be read: {}", ctx_label(c), truncate(e, 160)), WARNING());
            }
        }
        let mut items = self.op_filter(items);
        worst_first(&mut items);
        let none = self.active.iter().find_map(|c| self.missing(c, Kind::Ingresses)).unwrap_or("None.".into());
        go = table(ui, &format!("Ways in ({})", items.len()), "from ingresses, OpenShift routes and HTTP routes", &[("Address", 0.32), ("State", 0.16), ("From", 0.2), ("Namespace", 0.13), ("Service", 0.13), ("", 0.06)], &items, 300, &none).or(go);
        for k in ["gateways.gateway.networking.k8s.io", "virtualservices.networking.istio.io", "ingressroutes.traefik.io", "apisixroutes.apisix.apache.org"] {
            go = self.kind_table(ui, k).or(go);
        }
        go
    }

    // ---------- monitoring ----------

    /// Alerts are read again once they've been asked for.
    pub(super) fn ask_alerts(&mut self, force: bool) {
        let keys: Vec<String> = self.powers.answers.keys().filter(|k| k.starts_with("alerts|")).cloned().collect();
        for k in keys {
            let p: Vec<&str> = k.split('|').collect();
            if let [_, ctx, ns] = p.as_slice() {
                let (ctx, ns) = (ctx.to_string(), ns.to_string());
                self.read_alerts(&ctx, &ns, force);
            }
        }
    }

    fn read_alerts(&mut self, ctx: &str, ns: &str, force: bool) {
        let path = format!("/api/v1/namespaces/{ns}/services/alertmanager-operated:9093/proxy/api/v2/alerts?active=true&silenced=false&inhibited=false");
        let args = powers::raw_args(ctx, &path);
        self.ask(&format!("alerts|{ctx}|{ns}"), 30, force, move |k| {
            let v: Value = serde_json::from_str(&k.run(&args)?).map_err(|_| "it didn't answer with alerts".to_string())?;
            let l: Vec<Value> = v.as_array().into_iter().flatten().take(500).map(|a| serde_json::json!({"labels": a["labels"], "at": a["startsAt"], "text": a["annotations"]["summary"].as_str().or(a["annotations"]["message"].as_str()).or(a["annotations"]["description"].as_str()).unwrap_or("")})).collect();
            Ok(Value::Array(l).to_string())
        });
    }

    pub(super) fn prom_page(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        let now = kube::now_secs();
        let managers: Vec<(String, String)> = self.op_items("alertmanagers.monitoring.coreos.com").into_iter().map(|(c, o)| (c.to_string(), ns_of(o).to_string())).collect();
        // Monitors that find nothing.
        let mut monitors: Vec<Item> = vec![];
        for c in self.active.clone().iter().filter(|c| self.ctx_shown(c)) {
            let (svcs, pods) = (self.refs(c, Kind::Services, ""), self.refs(c, Kind::Pods, ""));
            for (key, list, what) in [("servicemonitors.monitoring.coreos.com", &svcs, "service"), ("podmonitors.monitoring.coreos.com", &pods, "pod")] {
                for (cx, o) in self.op_items(key).into_iter().filter(|x| x.0 == c.as_str()) {
                    let (t, w, n) = match list {
                        None => (Tone::Muted, format!("{what}s not known"), 0),
                        Some(all) => {
                            let hit = monitored(o, ns_of(o), all, |s| s["metadata"]["labels"].clone());
                            let ports: Vec<&str> = o["spec"][if what == "pod" { "podMetricsEndpoints" } else { "endpoints" }].as_array().into_iter().flatten().filter_map(|e| e["port"].as_str()).collect();
                            let have: HashSet<&str> = hit.iter().flat_map(|s| if what == "pod" { s["spec"]["containers"].as_array().into_iter().flatten().flat_map(|c| c["ports"].as_array().into_iter().flatten()).filter_map(|p| p["name"].as_str()).collect::<Vec<_>>() } else { s["spec"]["ports"].as_array().into_iter().flatten().filter_map(|p| p["name"].as_str()).collect() }).collect();
                            let gone: Vec<&str> = ports.iter().filter(|p| !have.contains(**p)).copied().collect();
                            if hit.is_empty() {
                                (Tone::Warning, format!("selects no {what}"), 0)
                            } else if !gone.is_empty() && gone.len() == ports.len() {
                                (Tone::Warning, format!("no port named {}", gone.join(", ")), hit.len())
                            } else {
                                (Tone::Success, "selects".into(), hit.len())
                            }
                        }
                    };
                    monitors.push(Item::new(t, vec![self.full_name(cx, o), w, many(n as i64, what), o["spec"]["selector"]["matchLabels"].as_object().map(|m| m.iter().map(|(k, v)| format!("{k}={}", text(v))).collect::<Vec<_>>().join(", ")).unwrap_or_default()]).go(self.custom_go(cx, key, o)));
                }
            }
        }
        let mut servers: Vec<Item> = vec![];
        for key in ["prometheuses.monitoring.coreos.com", "alertmanagers.monitoring.coreos.com"] {
            for (c, o) in self.op_items(key) {
                let v = face::generic(o);
                servers.push(Item::new(v.0, vec![self.full_name(c, o), v.1, key.split('.').next().unwrap_or("").into(), format!("{}/{} available", o["status"]["availableReplicas"].as_i64().unwrap_or(0), o["status"]["replicas"].as_i64().unwrap_or(0))]).go(self.custom_go(c, key, o)));
            }
        }
        let all: Vec<Item> = monitors.iter().chain(&servers).map(|i| Item::new(i.tone, i.cells.clone())).collect();
        face::show(ui, &summary(&all, "part"), Side::None);
        ui.add_space(10.0);
        // Alerts.
        let mut read: Option<(String, String)> = None;
        for (c, ns) in &managers {
            let key = format!("alerts|{c}|{ns}");
            match self.powers.answers.get(&key) {
                None => card(ui, |ui| {
                    panel(ui, "Firing alerts", "");
                    said(ui, &format!("Kubedog can ask the Alertmanager in {ns} which alerts fire, through the cluster's API with your own account. Nothing is changed by it."), TEXT_MUTED());
                    ui.add_space(4.0);
                    if button(ui, "Ask it", true, false) {
                        read = Some((c.clone(), ns.clone()));
                    }
                }),
                Some(None) => said(ui, "Reading alerts…", TEXT_SUBTLE()),
                Some(Some(Err(e))) => card(ui, |ui| {
                    panel(ui, "Firing alerts", "");
                    said(ui, &format!("The Alertmanager in {ns} didn't answer: {}. Some, such as OpenShift's own, only answer with a login of their own.", truncate(e, 200)), WARNING());
                    if button(ui, "Ask again", false, false) {
                        read = Some((c.clone(), ns.clone()));
                    }
                }),
                Some(Some(Ok(v))) => {
                    let mut l: Vec<Item> = v.as_array().into_iter().flatten().map(|a| {
                        let lb = &a["labels"];
                        let t = match lb["severity"].as_str() { Some("critical") => Tone::Danger, Some("warning") => Tone::Warning, _ => Tone::Info };
                        let (n, p) = (text(&lb["namespace"]), text(&lb["pod"]));
                        Item::new(t, vec![text(&lb["alertname"]), text(&lb["severity"]), truncate(a["text"].as_str().unwrap_or(""), 240), n.clone(), p.clone(), ago(now, pod::time_of(&a["at"]))]).go(if p.is_empty() { None } else { Some(obj(c, Kind::Pods, &n, &p)) })
                    }).collect();
                    l = self.op_filter(l);
                    worst_first(&mut l);
                    go = table(ui, &format!("Firing alerts ({})", l.len()), ns, &[("Alert", 0.22), ("Severity", 0.08), ("What", 0.36), ("Namespace", 0.14), ("Pod", 0.14), ("Since", 0.06)], &l, 100, "Nothing fires.").or(go);
                }
            }
            ui.add_space(10.0);
        }
        if let Some((c, ns)) = read {
            self.read_alerts(&c, &ns, true);
        }
        self.bad_switch(ui);
        worst_first(&mut servers);
        go = table(ui, "Servers", "", &[("Name", 0.4), ("State", 0.2), ("Kind", 0.2), ("Copies", 0.2)], &self.op_filter(servers), 40, &self.op_missing("prometheuses.monitoring.coreos.com").unwrap_or("None.".into())).or(go);
        worst_first(&mut monitors);
        go = table(ui, &format!("Monitors ({})", monitors.len()), "what Prometheus is told to scrape; those that find nothing first", &[("Monitor", 0.34), ("State", 0.18), ("Finds", 0.1), ("Selector", 0.38)], &self.op_filter(monitors), 120, &self.op_missing("servicemonitors.monitoring.coreos.com").unwrap_or("None.".into())).or(go);
        let mut rules: Vec<Item> = self.op_items("prometheusrules.monitoring.coreos.com").into_iter().map(|(c, o)| {
            let r: Vec<&Value> = o["spec"]["groups"].as_array().into_iter().flatten().flat_map(|g| g["rules"].as_array().into_iter().flatten()).collect();
            let a: Vec<String> = r.iter().filter_map(|r| r["alert"].as_str().map(String::from)).collect();
            Item::new(Tone::Muted, vec![self.full_name(c, o), many(a.len() as i64, "alert"), many((r.len() - a.len()) as i64, "recording"), some_names(&a)]).tip(a.join("\n")).go(self.custom_go(c, "prometheusrules.monitoring.coreos.com", o))
        }).collect();
        rules = self.op_filter(rules);
        go = table(ui, &format!("Rules ({})", rules.len()), "", &[("Rule", 0.34), ("Alerts", 0.1), ("Recordings", 0.1), ("", 0.46)], &rules, 80, "None.").or(go);
        go
    }

    // ---------- backups ----------

    pub(super) fn ask_kasten(&mut self, force: bool) {
        if self.crd_index("policies.config.kio.kasten.io").is_none() {
            return;
        }
        for c in self.active.clone() {
            let ctx = c.clone();
            self.ask(&format!("kasten|{c}"), 60, force, move |k| {
                let a: Vec<String> = ["--context", &ctx, "get", "restorepoints.apps.kio.kasten.io", "--all-namespaces", "-o", "json", &format!("--request-timeout={}", kube::REQUEST_TIMEOUT)].iter().map(|s| s.to_string()).collect();
                let l: Vec<Value> = kube::parse_items(&k.run(&a)?)?.iter().map(|o| serde_json::json!({"ns": o["metadata"]["namespace"], "name": o["metadata"]["name"], "at": o["metadata"]["creationTimestamp"]})).collect();
                Ok(Value::Array(l).to_string())
            });
        }
    }

    pub(super) fn backups_page(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        let now = kube::now_secs();
        let mut items: Vec<Item> = vec![];
        let mut notes = vec![];
        for c in self.active.clone().iter().filter(|c| self.ctx_shown(c)) {
            let velero = self.op_all(c, "backups.velero.io");
            let kasten: Vec<Value> = match self.answer(&format!("kasten|{c}")) {
                Some(Ok(Value::Array(l))) => l.clone(),
                Some(Err(e)) => {
                    notes.push(format!("{}: Kasten's restore points couldn't be read: {}", ctx_label(c), truncate(e, 160)));
                    vec![]
                }
                _ => vec![],
            };
            let mut by: HashMap<&str, (usize, f64)> = HashMap::new();
            for p in self.refs(c, Kind::PersistentVolumeClaims, "").unwrap_or_default() {
                let e = by.entry(ns_of(p)).or_default();
                e.0 += 1;
                e.1 += resources::mem_bytes(p["status"]["capacity"]["storage"].as_str().unwrap_or(""));
            }
            for (ns, (n, size)) in by.into_iter().filter(|x| self.ns_ok(x.0)) {
                let last = newest(ns, velero.iter(), &kasten);
                let (t, w) = match &last {
                    None => (Tone::Danger, "no backup".to_string()),
                    Some((t, _)) if now - t > 2 * 86400 => (Tone::Warning, format!("{} old", kube::human_duration(now - t))),
                    Some((t, _)) => (Tone::Success, format!("{} old", kube::human_duration((now - t).max(0)))),
                };
                let name = if self.active.len() > 1 { format!("{} · {ns}", ctx_label(c)) } else { ns.to_string() };
                items.push(Item::new(t, vec![name, w, last.map(|l| l.1).unwrap_or_default(), many(n as i64, "claim"), gib(size)]).go(Some(obj(c, Kind::Namespaces, "", ns))));
            }
        }
        let none = ["backups.velero.io", "policies.config.kio.kasten.io"].iter().all(|k| self.crd_index(k).is_none());
        let mut f = summary(&items, "namespace");
        if none {
            f.tone = Tone::Muted;
            f.head = "Neither Velero nor Kasten is here".into();
            f.pills.clear();
        }
        f.notes = notes;
        face::show(ui, &f, Side::None);
        ui.add_space(10.0);
        self.bad_switch(ui);
        if !none {
            let mut items = self.op_filter(items);
            worst_first(&mut items);
            go = table(ui, "What's covered", "namespaces with disks and their newest good backup", &[("Namespace", 0.3), ("Newest", 0.16), ("By", 0.3), ("Claims", 0.12), ("Size", 0.12)], &items, 100, &self.active.iter().find_map(|c| self.missing(c, Kind::PersistentVolumeClaims)).unwrap_or("None have disks.".into())).or(go);
        }
        for k in ["schedules.velero.io", "backups.velero.io", "backupstoragelocations.velero.io", "restores.velero.io", "policies.config.kio.kasten.io", "profiles.config.kio.kasten.io"] {
            go = self.kind_table(ui, k).or(go);
        }
        go
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn same_address() {
        let d = |kind, name: &str, host: &str, path: &str| Door { ctx: "c".into(), ns: "n".into(), kind, name: name.into(), host: host.into(), path: path.into(), service: "s".into(), tls: true, taken: true };
        let l = vec![d("Ingress", "a", "x.example", "/"), d("Route", "b", "x.example", "/"), d("Ingress", "a", "x.example", "/api"), d("Ingress", "a", "x.example", "/api"), d("Ingress", "e", "*", "/"), d("Ingress", "f", "*", "/")];
        let mut c: Vec<usize> = clashes(&l).into_iter().collect();
        c.sort();
        assert_eq!(c, vec![0, 1]);
        let r = slim_route(&json!({"metadata": {"name": "r", "namespace": "n", "ownerReferences": [{"kind": "Ingress"}]}, "spec": {"host": "h", "to": {"name": "s"}, "tls": {"termination": "edge", "key": "SECRET", "certificate": "C"}}, "status": {"ingress": [{"conditions": [{"type": "Admitted", "status": "True"}]}]}}));
        assert!(!r.to_string().contains("SECRET") && r["tls"] == "edge" && r["made"] == true && r["taken"] == true);
    }

    #[test]
    fn covered() {
        let v = [json!({"metadata": {"name": "all"}, "spec": {"excludedNamespaces": ["c"]}, "status": {"phase": "Completed", "completionTimestamp": "2026-01-02T00:00:00Z"}}), json!({"metadata": {"name": "bad"}, "status": {"phase": "Failed", "completionTimestamp": "2026-01-03T00:00:00Z"}})];
        assert_eq!(newest("a", v.iter(), &[]).unwrap().1, "Velero all");
        assert!(newest("c", v.iter(), &[]).is_none());
        assert_eq!(newest("c", v.iter(), &[json!({"ns": "c", "name": "rp", "at": "2026-01-01T00:00:00Z"})]).unwrap().1, "Kasten rp");
        let m: Value = serde_json::from_str(&kasten_run("kasten-io", "daily")).unwrap();
        assert_eq!((m["kind"].as_str(), m["spec"]["subject"]["name"].as_str()), (Some("RunAction"), Some("daily")));
    }

    #[test]
    fn monitors() {
        let s = json!({"metadata": {"namespace": "n", "labels": {"app": "web"}}});
        let all = [&s];
        let m = |sel: Value| monitored(&json!({"spec": {"selector": {"matchLabels": {"app": "web"}}, "namespaceSelector": sel}}), "other", &all, |s| s["metadata"]["labels"].clone()).len();
        assert_eq!((m(json!({})), m(json!({"any": true})), m(json!({"matchNames": ["n"]}))), (0, 1, 1));
    }
}
