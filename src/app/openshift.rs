//! OpenShift: its version and updates, operators, machines, and security context constraints: what
//! runs with more rights than it asks for. Reading only.

use super::face::{many, Face, Side};
use super::incident::tab_strip;
use super::ops::{ago, ns_of, table, text, worst_first, Item};
use super::pod::cond;
use super::podxray::Go;
use super::work::{name_of, said};
use super::*;

pub(super) const VERSIONS: &str = "clusterversions.config.openshift.io";
const OPERATORS: &str = "clusteroperators.config.openshift.io";
const POOLS: &str = "machineconfigpools.machineconfiguration.openshift.io";
const MACHINES: &str = "machines.machine.openshift.io";
const CHECKS: &str = "machinehealthchecks.machine.openshift.io";
pub(super) const SUBS: &str = "subscriptions.operators.coreos.com";
const PLANS: &str = "installplans.operators.coreos.com";
const CATALOGS: &str = "catalogsources.operators.coreos.com";
const SCC: &str = "securitycontextconstraints.security.openshift.io";
const ROUTERS: &str = "ingresscontrollers.operator.openshift.io";

pub(super) const MORE: &[&str] = &[OPERATORS, POOLS, MACHINES, CHECKS, SUBS, PLANS, CATALOGS, SCC, ROUTERS];

const TABS: [&str; 6] = ["Overview", "Operators", "Updates", "Machines", "Security", "Catalog"];

fn is(o: &Value, t: &str, s: &str) -> bool {
    cond(o, t).map(|c| c["status"] == s).unwrap_or(false)
}

fn why(o: &Value, t: &str) -> String {
    cond(o, t).map(|c| format!("{} {}", text(&c["reason"]), truncate(c["message"].as_str().unwrap_or(""), 400)).trim().to_string()).unwrap_or_default()
}

/// A cluster operator: how it is, and why.
fn operator_state(o: &Value) -> (Tone, &'static str, String) {
    if is(o, "Degraded", "True") {
        return (Tone::Danger, "Degraded", why(o, "Degraded"));
    }
    if !is(o, "Available", "True") {
        return (Tone::Danger, "Not available", why(o, "Available"));
    }
    if is(o, "Progressing", "True") {
        return (Tone::Info, "Progressing", why(o, "Progressing"));
    }
    if is(o, "Upgradeable", "False") {
        return (Tone::Warning, "Blocks updates", why(o, "Upgradeable"));
    }
    (Tone::Success, "Fine", String::new())
}

/// A pool of machines with one configuration.
fn pool_state(o: &Value) -> (Tone, &'static str, String) {
    if is(o, "Degraded", "True") || is(o, "NodeDegraded", "True") || is(o, "RenderDegraded", "True") {
        let w = ["NodeDegraded", "RenderDegraded", "Degraded"].iter().find(|t| is(o, t, "True")).map(|t| why(o, t)).unwrap_or_default();
        return (Tone::Danger, "Degraded", w);
    }
    if o["spec"]["paused"] == true {
        return (Tone::Warning, "Paused", "it gets no new configuration, and that includes renewed certificates".into());
    }
    if is(o, "Updating", "True") {
        return (Tone::Info, "Updating", String::new());
    }
    (Tone::Success, "Up to date", String::new())
}

/// An installed operator's subscription.
fn sub_state(o: &Value) -> (Tone, &'static str, String) {
    let st = &o["status"];
    if is(o, "ResolutionFailed", "True") {
        return (Tone::Danger, "Can't be resolved", why(o, "ResolutionFailed"));
    }
    if is(o, "CatalogSourcesUnhealthy", "True") {
        return (Tone::Warning, "Its catalog has a problem", why(o, "CatalogSourcesUnhealthy"));
    }
    match st["state"].as_str() {
        Some("UpgradePending") if o["spec"]["installPlanApproval"] == "Manual" => (Tone::Warning, "Waits for approval", format!("{} to {}", text(&st["installedCSV"]), text(&st["currentCSV"]))),
        Some("UpgradePending") => (Tone::Info, "Updating", format!("{} to {}", text(&st["installedCSV"]), text(&st["currentCSV"]))),
        Some("UpgradeAvailable") => (Tone::Info, "Update available", text(&st["currentCSV"])),
        Some("AtLatestKnown") => (Tone::Success, "Up to date", String::new()),
        _ if st["installedCSV"].as_str().unwrap_or("").is_empty() => (Tone::Warning, "Not installed", String::new()),
        _ => (Tone::Normal, "Installed", String::new()),
    }
}

/// How wide a security context constraint is: 0 narrow, 1 any user, 2 parts of the host, 3 privileged.
fn width(o: &Value) -> (u8, String) {
    let on = |k: &str| o[k] == true;
    if on("allowPrivilegedContainer") {
        return (3, "privileged containers".into());
    }
    let mut host = vec![];
    for (k, w) in [("allowHostNetwork", "the host's network"), ("allowHostPID", "the host's processes"), ("allowHostIPC", "the host's IPC"), ("allowHostDirVolumePlugin", "folders of the host")] {
        if on(k) {
            host.push(w);
        }
    }
    if !host.is_empty() {
        return (2, host.join(", "));
    }
    let root = o["runAsUser"]["type"] == "RunAsAny";
    let caps: Vec<&str> = o["allowedCapabilities"].as_array().into_iter().flatten().filter_map(|c| c.as_str()).filter(|c| *c != "NET_BIND_SERVICE").collect();
    match (root, caps.is_empty()) {
        (true, true) => (1, "any user, root too".into()),
        (true, false) => (1, format!("any user, root too, and {}", caps.join(", "))),
        (false, false) => (1, format!("extra rights: {}", caps.join(", "))),
        _ => (0, String::new()),
    }
}

/// What a pod asks for that a narrow one wouldn't give. `given`: rights its constraint adds by itself, which
/// are in the pod's settings too, without the app having asked.
fn asks_for(p: &Value, given: &[String]) -> Vec<&'static str> {
    let s = &p["spec"];
    let mut v = vec![];
    for (k, w) in [("hostNetwork", "host network"), ("hostPID", "host processes"), ("hostIPC", "host IPC")] {
        if s[k] == true {
            v.push(w);
        }
    }
    if s["volumes"].as_array().into_iter().flatten().any(|x| x["hostPath"].is_object()) {
        v.push("folders of the host");
    }
    let mut root = s["securityContext"]["runAsUser"].as_i64() == Some(0);
    let mut some_user = s["securityContext"]["runAsUser"].as_i64().is_some() || s["securityContext"]["fsGroup"].as_i64().is_some();
    for c in s["containers"].as_array().into_iter().flatten().chain(s["initContainers"].as_array().into_iter().flatten()) {
        let x = &c["securityContext"];
        if x["privileged"] == true && !v.contains(&"privileged") {
            v.push("privileged");
        }
        if c["ports"].as_array().into_iter().flatten().any(|p| p["hostPort"].as_i64().unwrap_or(0) > 0) && !v.contains(&"host ports") {
            v.push("host ports");
        }
        if x["capabilities"]["add"].as_array().into_iter().flatten().filter_map(|k| k.as_str()).any(|k| k != "NET_BIND_SERVICE" && !given.iter().any(|g| g == k)) && !v.contains(&"extra rights") {
            v.push("extra rights");
        }
        root |= x["runAsUser"].as_i64() == Some(0);
        some_user |= x["runAsUser"].as_i64().is_some();
    }
    if root {
        v.push("root");
    } else if some_user {
        v.push("a fixed user or group");
    }
    v
}

struct Used {
    scc: String,
    width: u8,
    allows: String,
    sel: Selected,
    pods: usize,
    asks: Vec<&'static str>,
}

/// Every app under a wide one, the widest that asks for nothing first. Without asking for a kind of user, a
/// container may still need root because of its image: that can't be seen from here.
fn narrower(width: u8, asks: &[&str]) -> bool {
    match width {
        3 => !asks.iter().any(|a| matches!(*a, "privileged")),
        2 => !asks.iter().any(|a| matches!(*a, "host network" | "host processes" | "host IPC" | "folders of the host" | "host ports")),
        1 => asks.is_empty(),
        _ => false,
    }
}

fn newer(v: &Value) -> Vec<String> {
    v["status"]["availableUpdates"].as_array().into_iter().flatten().filter_map(|u| u["version"].as_str().map(String::from)).collect()
}

/// Findings about one cluster: (tone, what, more).
#[allow(clippy::too_many_arguments)]
fn findings(version: Option<&Value>, operators: &[&Value], pools: &[&Value], subs: &[&Value], catalogs: &[&Value], machines: &[&Value], csrs: usize, old: &Value, now: i64) -> Vec<(Tone, String, String)> {
    let mut f: Vec<(Tone, String, String)> = vec![];
    if let Some(v) = version {
        if is(v, "Failing", "True") {
            f.push((Tone::Danger, "The cluster's update is failing".into(), why(v, "Failing")));
        }
        if is(v, "Progressing", "True") {
            f.push((Tone::Info, "The cluster is being updated".into(), why(v, "Progressing")));
        }
        if is(v, "Upgradeable", "False") {
            f.push((Tone::Warning, "The next minor update is blocked".into(), why(v, "Upgradeable")));
        }
        if is(v, "RetrievedUpdates", "False") {
            f.push((Tone::Warning, "It can't ask which updates there are".into(), why(v, "RetrievedUpdates")));
        }
        let n = newer(v);
        if !n.is_empty() {
            f.push((Tone::Info, format!("{} available", many(n.len() as i64, "update")), some_names(&n)));
        }
        if v["spec"]["desiredUpdate"]["force"] == true {
            f.push((Tone::Warning, "The last update was forced".into(), "its checks were skipped: signature and blocking conditions".into()));
        }
        if let Some(t) = v["status"]["history"].as_array().into_iter().flatten().find(|h| h["state"] == "Completed").and_then(|h| pod::time_of(&h["completionTime"])).filter(|t| now - t > 200 * 86400) {
            f.push((Tone::Warning, format!("Not updated for {} days", (now - t) / 86400), "security fixes come with the updates".into()));
        }
    }
    for o in operators {
        let (t, w, y) = operator_state(o);
        if matches!(t, Tone::Danger | Tone::Warning) {
            f.push((t, format!("Cluster operator {}: {}", name_of(o), w.to_lowercase()), y));
        }
    }
    for o in pools {
        let (t, w, y) = pool_state(o);
        if matches!(t, Tone::Danger | Tone::Warning) {
            f.push((t, format!("Machine pool {}: {}", name_of(o), w.to_lowercase()), y));
        }
    }
    for o in subs {
        let (t, w, y) = sub_state(o);
        if matches!(t, Tone::Danger | Tone::Warning) {
            f.push((t, format!("Operator {}: {}", name_of(o), w.to_lowercase()), y));
        }
    }
    for o in catalogs {
        let s = text(&o["status"]["connectionState"]["lastObservedState"]);
        if !s.is_empty() && s != "READY" {
            f.push((Tone::Warning, format!("Catalog {} isn't ready", name_of(o)), s));
        }
    }
    for o in machines {
        let p = text(&o["status"]["phase"]);
        if matches!(p.as_str(), "Failed" | "Deleting") || p == "Provisioned" || p == "Provisioning" {
            f.push((if p == "Failed" { Tone::Danger } else { Tone::Info }, format!("Machine {} is {}", name_of(o), p.to_lowercase()), truncate(o["status"]["errorMessage"].as_str().unwrap_or(""), 300)));
        }
    }
    if csrs > 0 {
        f.push((Tone::Warning, format!("{} waiting for approval", many(csrs as i64, "certificate request")), "a node may not be able to join, or lose its certificate".into()));
    }
    for a in old.as_array().into_iter().flatten().filter(|a| a["count"].as_i64().unwrap_or(0) > 0) {
        f.push((Tone::Warning, format!("{} is still used, and is gone from Kubernetes {} on", text(&a["name"]), text(&a["gone"])), a["who"].as_array().into_iter().flatten().filter_map(|w| w.as_str()).take(4).collect::<Vec<_>>().join(", ")));
    }
    f.sort_by_key(|x| match x.0 {
        Tone::Danger => 0,
        Tone::Warning => 1,
        _ => 2,
    });
    f
}

/// Old kinds that are going, how often they were asked for in a day, and by whom.
fn slim_old(items: &[Value]) -> Value {
    Value::Array(items.iter().filter(|o| !o["status"]["removedInRelease"].as_str().unwrap_or("").is_empty()).map(|o| {
        let mut who: HashMap<String, i64> = HashMap::new();
        for h in std::iter::once(&o["status"]["currentHour"]).chain(o["status"]["last24h"].as_array().into_iter().flatten()) {
            for n in h["byNode"].as_array().into_iter().flatten() {
                for x in n["byUser"].as_array().into_iter().flatten() {
                    *who.entry(format!("{} ({})", text(&x["username"]), text(&x["userAgent"]).split('/').next().unwrap_or(""))).or_default() += x["requestCount"].as_i64().unwrap_or(0);
                }
            }
        }
        let mut w: Vec<(String, i64)> = who.into_iter().collect();
        w.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        serde_json::json!({"name": name_of(o), "gone": o["status"]["removedInRelease"], "count": o["status"]["requestCount"], "who": w.into_iter().take(8).map(|x| format!("{} {}×", x.0, x.1)).collect::<Vec<_>>()})
    }).collect())
}

fn slim_csv(items: &[Value]) -> Value {
    Value::Array(items.iter().map(|o| {
        let max = o["metadata"]["annotations"]["olm.properties"].as_str().and_then(|t| serde_json::from_str::<Value>(t).ok()).and_then(|v| v.as_array()?.iter().find(|p| p["type"] == "olm.maxOpenShiftVersion").map(|p| p["value"].as_str().map(String::from).unwrap_or(p["value"].to_string()))).unwrap_or_default();
        serde_json::json!({"ns": ns_of(o), "name": name_of(o), "display": o["spec"]["displayName"], "version": o["spec"]["version"], "phase": o["status"]["phase"], "reason": o["status"]["reason"], "message": truncate(o["status"]["message"].as_str().unwrap_or(""), 300), "max": max})
    }).collect())
}

/// Whether an operator says it doesn't go along to the next minor version.
fn stays_behind(max: &str, version: &str) -> bool {
    let two = |s: &str| -> Option<(u32, u32)> {
        let mut p = s.trim_matches('"').trim_start_matches('v').split('.');
        Some((p.next()?.parse().ok()?, p.next()?.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()?))
    };
    match (two(max), two(version)) {
        (Some(m), Some(v)) => m <= v,
        _ => false,
    }
}

impl KubedogApp {
    /// What isn't a plain list of custom objects.
    pub(super) fn ask_openshift(&mut self, force: bool) {
        for c in self.active.clone() {
            if self.op_all(&c, VERSIONS).is_empty() {
                continue;
            }
            let get = |what: &str, more: &[&str]| -> Vec<String> { ["--context", &c, "get", what, "-o", "json", &format!("--request-timeout={}", kube::REQUEST_TIMEOUT)].iter().map(|s| s.to_string()).chain(more.iter().map(|s| s.to_string())).collect() };
            let a = get("clusterserviceversions.operators.coreos.com", &["--all-namespaces", "-l", "!olm.copiedFrom"]);
            self.ask(&format!("oscsv|{c}"), 90, force, move |k| Ok(slim_csv(&kube::parse_items(&k.run(&a)?)?).to_string()));
            let a = get("apirequestcounts.apiserver.openshift.io", &[]);
            self.ask(&format!("osold|{c}"), 900, force, move |k| Ok(slim_old(&kube::parse_items(&k.run(&a)?)?).to_string()));
            let a = get("infrastructures.config.openshift.io", &["--field-selector=metadata.name=cluster"]);
            self.ask(&format!("osinfra|{c}"), 3600, force, move |k| {
                let v = kube::parse_items(&k.run(&a)?)?;
                let s = v.first().map(|o| o["status"].clone()).unwrap_or_default();
                Ok(serde_json::json!({"platform": s["platformStatus"]["type"], "control": s["controlPlaneTopology"]}).to_string())
            });
        }
    }

    fn os_old(&self, ctx: &str) -> Value {
        self.answer(&format!("osold|{ctx}")).and_then(|r| r.as_ref().ok().cloned()).unwrap_or_default()
    }

    fn os_waiting(&self, ctx: &str) -> usize {
        self.refs(ctx, Kind::CertificateSigningRequests, "").unwrap_or_default().into_iter().filter(|o| o["status"]["conditions"].as_array().map(|c| c.is_empty()).unwrap_or(true)).count()
    }

    pub(super) fn openshift_page(&mut self, ui: &mut Ui) -> Option<Go> {
        if self.screenshot.is_some() {
            if let Some(t) = std::env::var("KUBEDOG_SHOT_TAB").ok().and_then(|t| t.parse::<usize>().ok()) {
                self.powers.os_tab = t.min(TABS.len() - 1);
            }
        }
        let ctxs: Vec<String> = self.active.iter().filter(|c| self.ctx_shown(c) && !self.op_all(c, VERSIONS).is_empty()).cloned().collect();
        if ctxs.is_empty() {
            let t = self.op_missing(VERSIONS).unwrap_or("None of the open clusters is an OpenShift.".into());
            said(ui, &t, TEXT_SUBTLE());
            return None;
        }
        let mut tab = self.powers.os_tab;
        ui.horizontal(|ui| tab_strip(ui, &TABS, &mut tab));
        self.powers.os_tab = tab;
        ui.add_space(6.0);
        if tab < 5 {
            self.bad_switch(ui);
        }
        match tab {
            0 => self.os_overview(ui, &ctxs),
            1 => self.os_operators(ui),
            2 => self.os_updates(ui, &ctxs),
            3 => self.os_machines(ui, &ctxs),
            4 => self.os_security(ui, &ctxs),
            _ => self.os_catalog(ui, &ctxs),
        }
    }

    fn os_overview(&mut self, ui: &mut Ui, ctxs: &[String]) -> Option<Go> {
        let now = kube::now_secs();
        for c in ctxs {
            let all = |k: &str| -> Vec<&Value> { self.op_all(c, k).iter().collect() };
            let v = self.op_all(c, VERSIONS).first();
            let used = self.os_used(c, false);
            let mut f = findings(v, &all(OPERATORS), &all(POOLS), &all(SUBS), &all(CATALOGS), &all(MACHINES), self.os_waiting(c), &self.os_old(c), now);
            let top = used.iter().filter(|x| x.width == 3 && narrower(3, &x.asks)).count();
            if top > 0 {
                f.push((Tone::Warning, format!("{} could start a privileged container without asking for it", many(top as i64, "app")), "see Security: their constraint is wider than they need".into()));
                f.sort_by_key(|x| match x.0 {
                    Tone::Danger => 0,
                    Tone::Warning => 1,
                    _ => 2,
                });
            }
            let bad = f.iter().filter(|x| x.0 == Tone::Danger).count();
            let warn = f.iter().filter(|x| x.0 == Tone::Warning).count();
            let infra = self.answer(&format!("osinfra|{c}")).and_then(|r| r.as_ref().ok().cloned()).unwrap_or_default();
            let st = v.map(|v| v["status"].clone()).unwrap_or_default();
            let ok = all(OPERATORS).iter().filter(|o| operator_state(o).0 == Tone::Success).count();
            let since = st["history"].as_array().into_iter().flatten().find(|h| h["state"] == "Completed").and_then(|h| pod::time_of(&h["completionTime"]));
            let wide = used.iter().filter(|x| x.width > 0 && narrower(x.width, &x.asks)).count();
            let face = Face {
                tone: if bad > 0 { Tone::Danger } else if warn > 0 { Tone::Warning } else { Tone::Success },
                head: if bad + warn == 0 { "All is well".into() } else { format!("{} to look at", many((bad + warn) as i64, "thing")) },
                sub: format!("{}OpenShift {}", if ctxs.len() > 1 { format!("{}, ", ctx_label(c)) } else { String::new() }, text(&st["desired"]["version"])),
                notes: vec![],
                pills: vec![],
                facts: vec![
                    face::Fact::new("Channel", v.map(|v| text(&v["spec"]["channel"])).filter(|t| !t.is_empty()).unwrap_or("none".into())),
                    face::Fact::new("Last update", ago(now, since)),
                    face::Fact::new("Cluster operators", format!("{ok} of {} fine", all(OPERATORS).len())),
                    face::Fact::new("Installed operators", all(SUBS).len().to_string()),
                    face::Fact::new("Runs on", infra["platform"].as_str().unwrap_or("not known").to_string()),
                    face::Fact::new("Apps with more rights than they ask for", wide.to_string()),
                ],
            };
            face::show(ui, &face, Side::None);
            ui.add_space(10.0);
            let items = self.op_filter(f.into_iter().map(|x| Item::new(x.0, vec![x.1, x.2])).collect());
            table(ui, "To look at", "", &[("What", 0.4), ("More", 0.6)], &items, 80, "Nothing.");
            let gone: Vec<String> = [OPERATORS, POOLS, MACHINES, SUBS, CATALOGS, SCC].iter().filter(|k| self.op_all(c, k).is_empty()).filter_map(|k| self.op_missing(k)).collect();
            if !gone.is_empty() {
                said(ui, &format!("Not read: {}.", gone.join("; ")), TEXT_PLACEHOLDER());
            }
            ui.add_space(8.0);
        }
        None
    }

    fn os_operators(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        let now = kube::now_secs();
        let mut l: Vec<Item> = self.op_items(OPERATORS).into_iter().map(|(c, o)| {
            let (t, w, y) = operator_state(o);
            let ver = o["status"]["versions"].as_array().into_iter().flatten().find(|x| x["name"] == "operator").map(|x| text(&x["version"])).unwrap_or_default();
            let since = o["status"]["conditions"].as_array().into_iter().flatten().filter_map(|x| pod::time_of(&x["lastTransitionTime"])).max();
            Item::new(t, vec![self.full_name(c, o), w.into(), y, ver, ago(now, since)]).go(self.custom_go(c, OPERATORS, o))
        }).collect();
        worst_first(&mut l);
        let l = self.op_filter(l);
        let none = self.op_missing(OPERATORS).unwrap_or("None with this filter.".into());
        go = table(ui, &format!("Cluster operators ({})", l.len()), "the parts OpenShift itself is made of", &[("Operator", 0.22), ("State", 0.12), ("Why", 0.36), ("Version", 0.18), ("Changed", 0.12)], &l, 80, &none).or(go);
        let mut s: Vec<Item> = self.op_items(SUBS).into_iter().map(|(c, o)| {
            let (t, w, y) = sub_state(o);
            Item::new(t, vec![self.full_name(c, o), w.into(), y, text(&o["status"]["installedCSV"]), text(&o["spec"]["channel"]), text(&o["spec"]["installPlanApproval"]).to_lowercase(), text(&o["spec"]["source"])]).go(self.custom_go(c, SUBS, o))
        }).collect();
        worst_first(&mut s);
        let s = self.op_filter(s);
        let none = self.op_missing(SUBS).unwrap_or("None.".into());
        go = table(ui, &format!("Installed operators ({})", s.len()), "what was subscribed to", &[("Subscription", 0.2), ("State", 0.12), ("Why", 0.2), ("Version", 0.2), ("Channel", 0.09), ("Updates", 0.08), ("Catalog", 0.11)], &s, 80, &none).or(go);
        let mut v: Vec<Item> = vec![];
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            for o in self.answer(&format!("oscsv|{c}")).and_then(|r| r.as_ref().ok()).and_then(|v| v.as_array()).into_iter().flatten() {
                if !self.ns_ok(o["ns"].as_str().unwrap_or("")) {
                    continue;
                }
                let p = text(&o["phase"]);
                let t = match p.as_str() { "Succeeded" => Tone::Success, "Failed" => Tone::Danger, "" => Tone::Muted, _ => Tone::Warning };
                v.push(Item::new(t, vec![format!("{}/{}", text(&o["ns"]), text(&o["display"])), if p.is_empty() { "not known".into() } else { p.clone() }, if p == "Succeeded" { String::new() } else { text(&o["message"]) }, text(&o["version"]), text(&o["max"]).trim_matches('"').to_string()]));
            }
        }
        worst_first(&mut v);
        let v = self.op_filter(v);
        table(ui, &format!("Operator versions ({})", v.len()), "", &[("Operator", 0.34), ("State", 0.13), ("Why", 0.28), ("Version", 0.12), ("Goes up to", 0.13)], &v, 80, "None, or not read yet.");
        let plans: Vec<Item> = self.op_items(PLANS).into_iter().filter(|(_, o)| o["spec"]["approved"] != true || !matches!(o["status"]["phase"].as_str(), Some("Complete"))).map(|(c, o)| {
            let waits = o["spec"]["approved"] != true;
            let p = text(&o["status"]["phase"]);
            let t = if p == "Failed" { Tone::Danger } else if waits { Tone::Warning } else { Tone::Info };
            Item::new(t, vec![self.full_name(c, o), if waits { "Waits for approval".into() } else { p }, o["spec"]["clusterServiceVersionNames"].as_array().into_iter().flatten().map(text).collect::<Vec<_>>().join(", ")]).go(self.custom_go(c, PLANS, o))
        }).collect();
        go = table(ui, &format!("Install plans that aren't done ({})", plans.len()), "", &[("Plan", 0.34), ("State", 0.2), ("Installs", 0.46)], &plans, 40, "None: all are done.").or(go);
        let cats: Vec<Item> = self.op_items(CATALOGS).into_iter().map(|(c, o)| {
            let st = text(&o["status"]["connectionState"]["lastObservedState"]);
            Item::new(if st == "READY" { Tone::Success } else { Tone::Warning }, vec![self.full_name(c, o), if st.is_empty() { "not known".into() } else { st.to_lowercase().replace('_', " ") }, text(&o["spec"]["displayName"]), text(&o["spec"]["image"])]).go(self.custom_go(c, CATALOGS, o))
        }).collect();
        table(ui, &format!("Catalogs ({})", cats.len()), "where operators come from", &[("Catalog", 0.3), ("State", 0.14), ("Name", 0.2), ("Image", 0.36)], &cats, 40, "None.").or(go)
    }

    fn os_updates(&mut self, ui: &mut Ui, ctxs: &[String]) -> Option<Go> {
        let mut go = None;
        let now = kube::now_secs();
        for c in ctxs {
            let Some(v) = self.op_all(c, VERSIONS).first().cloned() else { continue };
            let here = text(&v["status"]["desired"]["version"]);
            if ctxs.len() > 1 {
                ui.label(RichText::new(ctx_label(c)).size(z(16.0)).color(TEXT_DEFAULT()));
            }
            // What stands in the way.
            let mut way: Vec<Item> = vec![];
            if is(&v, "Upgradeable", "False") {
                way.push(Item::new(Tone::Danger, vec!["The cluster says no to the next minor version".into(), why(&v, "Upgradeable")]));
            }
            for o in self.op_all(c, OPERATORS) {
                let (t, w, y) = operator_state(o);
                if matches!(t, Tone::Danger | Tone::Warning) {
                    way.push(Item::new(t, vec![format!("Cluster operator {}: {}", name_of(o), w.to_lowercase()), y]).go(self.custom_go(c, OPERATORS, o)));
                }
            }
            for o in self.op_all(c, POOLS) {
                let (t, w, y) = pool_state(o);
                if matches!(t, Tone::Danger | Tone::Warning) {
                    way.push(Item::new(t, vec![format!("Machine pool {}: {}", name_of(o), w.to_lowercase()), y]).go(self.custom_go(c, POOLS, o)));
                }
            }
            for o in self.answer(&format!("oscsv|{c}")).and_then(|r| r.as_ref().ok()).and_then(|v| v.as_array()).into_iter().flatten() {
                let max = text(&o["max"]);
                if stays_behind(&max, &here) {
                    way.push(Item::new(Tone::Warning, vec![format!("{} doesn't go along to the next minor version", text(&o["display"])), format!("it goes up to {}", max.trim_matches('"'))]));
                }
            }
            for a in self.os_old(c).as_array().into_iter().flatten() {
                let n = a["count"].as_i64().unwrap_or(0);
                let who = a["who"].as_array().into_iter().flatten().filter_map(|w| w.as_str()).collect::<Vec<_>>().join(", ");
                way.push(Item::new(if n > 0 { Tone::Warning } else { Tone::Muted }, vec![format!("{} is gone from Kubernetes {} on", text(&a["name"]), text(&a["gone"])), if n > 0 { format!("asked for {n}× in a day, by {who}") } else { "not asked for in the last day".into() }]));
            }
            worst_first(&mut way);
            let blocks = way.iter().filter(|i| i.bad()).count();
            let n = newer(&v);
            let face = Face {
                tone: if blocks > 0 { Tone::Warning } else { Tone::Success },
                head: if n.is_empty() { "No update is offered".into() } else { format!("{} available", many(n.len() as i64, "update")) },
                sub: format!("now {here}, channel {}; {}", v["spec"]["channel"].as_str().unwrap_or("none"), if blocks == 0 { "nothing in the way that OpenShift reports".into() } else { format!("{} in the way", many(blocks as i64, "thing")) }),
                notes: vec!["Budgets that stop a drain, and a rehearsal per node, are in Readiness.".into()],
                pills: vec![],
                facts: vec![],
            };
            face::show(ui, &face, Side::None);
            ui.add_space(10.0);
            go = table(ui, "In the way, or good to know", "", &[("What", 0.42), ("More", 0.58)], &self.op_filter(way), 60, "Nothing.").or(go);
            let mut ups: Vec<Item> = v["status"]["availableUpdates"].as_array().into_iter().flatten().map(|x| Item::new(Tone::Success, vec![text(&x["version"]), "recommended".into(), text(&x["url"])])).collect();
            for x in v["status"]["conditionalUpdates"].as_array().into_iter().flatten() {
                let rec = x["conditions"].as_array().into_iter().flatten().find(|c| c["type"] == "Recommended");
                let ok = rec.map(|r| r["status"] == "True").unwrap_or(false);
                let risks = x["risks"].as_array().into_iter().flatten().map(|r| format!("{}: {}", text(&r["name"]), truncate(r["message"].as_str().unwrap_or(""), 200))).collect::<Vec<_>>().join("; ");
                ups.push(Item::new(if ok { Tone::Success } else { Tone::Warning }, vec![text(&x["release"]["version"]), if ok { "recommended here".into() } else { "with known risks".into() }, risks]));
            }
            table(ui, &format!("Updates ({})", ups.len()), "", &[("Version", 0.25), ("State", 0.15), ("More", 0.6)], &ups, 30, "None in this channel.");
            let hist: Vec<Item> = v["status"]["history"].as_array().into_iter().flatten().map(|h| {
                let done = h["state"] == "Completed";
                let (a, b) = (pod::time_of(&h["startedTime"]), pod::time_of(&h["completionTime"]));
                let took = a.zip(b).map(|(a, b)| kube::human_duration((b - a).max(0))).unwrap_or_default();
                Item::new(if done { Tone::Success } else { Tone::Warning }, vec![text(&h["version"]), if done { "completed".into() } else { "not completed".into() }, ago(now, b.or(a)), took, if h["verified"] == true { "verified".into() } else { "signature not verified".into() }])
            }).collect();
            table(ui, "Earlier updates", "", &[("Version", 0.3), ("State", 0.18), ("When", 0.16), ("Took", 0.14), ("Signature", 0.22)], &hist, 20, "None.");
        }
        go
    }

    fn os_machines(&mut self, ui: &mut Ui, ctxs: &[String]) -> Option<Go> {
        let mut go = None;
        let num = |v: &Value| v.as_i64().unwrap_or(0);
        let mut p: Vec<Item> = self.op_items(POOLS).into_iter().map(|(c, o)| {
            let (t, w, y) = pool_state(o);
            let st = &o["status"];
            Item::new(t, vec![self.full_name(c, o), w.into(), y, format!("{} of {}", num(&st["updatedMachineCount"]), num(&st["machineCount"])), num(&st["unavailableMachineCount"]).to_string(), text(&o["spec"]["maxUnavailable"]).to_string()]).go(self.custom_go(c, POOLS, o))
        }).collect();
        worst_first(&mut p);
        let none = self.op_missing(POOLS).unwrap_or("None.".into());
        go = table(ui, &format!("Machine pools ({})", p.len()), "nodes that share a configuration", &[("Pool", 0.22), ("State", 0.13), ("Why", 0.3), ("Up to date", 0.12), ("Unavailable", 0.12), ("At most at once", 0.11)], &p, 40, &none).or(go);
        // Nodes between two configurations.
        let mut wait: Vec<Item> = vec![];
        for c in ctxs {
            for n in self.refs(c, Kind::Nodes, "").unwrap_or_default() {
                let a = &n["metadata"]["annotations"];
                let get = |k: &str| text(&a[format!("machineconfiguration.openshift.io/{k}").as_str()]);
                let (state, cur, want) = (get("state"), get("currentConfig"), get("desiredConfig"));
                if state.is_empty() || (state == "Done" && cur == want) {
                    continue;
                }
                let t = if matches!(state.as_str(), "Degraded" | "Unreconcilable") { Tone::Danger } else { Tone::Info };
                wait.push(Item::new(t, vec![name_of(n).to_string(), state, get("reason"), format!("{cur} to {want}")]).go(Some(ops::obj(c, Kind::Nodes, "", name_of(n)))));
            }
        }
        go = table(ui, &format!("Nodes that wait for a configuration ({})", wait.len()), "", &[("Node", 0.22), ("State", 0.13), ("Why", 0.3), ("From and to", 0.35)], &wait, 60, if ctxs.iter().all(|c| self.refs(c, Kind::Nodes, "").is_some()) { "None: every node has the configuration it should have." } else { "Not known: the nodes can't be read, or aren't read yet." }).or(go);
        let mut m: Vec<Item> = self.op_items(MACHINES).into_iter().map(|(c, o)| {
            let ph = text(&o["status"]["phase"]);
            let t = match ph.as_str() { "Running" => Tone::Success, "Failed" => Tone::Danger, "" => Tone::Muted, _ => Tone::Warning };
            let l = &o["metadata"]["labels"];
            Item::new(t, vec![self.full_name(c, o), if ph.is_empty() { "not known".into() } else { ph }, text(&o["status"]["nodeRef"]["name"]), text(&l["machine.openshift.io/cluster-api-machine-role"]), text(&l["machine.openshift.io/instance-type"]), truncate(o["status"]["errorMessage"].as_str().unwrap_or(""), 300)]).go(self.custom_go(c, MACHINES, o))
        }).collect();
        worst_first(&mut m);
        let m = self.op_filter(m);
        let none = self.op_missing(MACHINES).unwrap_or("None: the machines aren't managed by OpenShift.".into());
        go = table(ui, &format!("Machines ({})", m.len()), "", &[("Machine", 0.32), ("State", 0.1), ("Node", 0.2), ("Role", 0.1), ("Type", 0.1), ("Trouble", 0.18)], &m, 100, &none).or(go);
        let h: Vec<Item> = self.op_items(CHECKS).into_iter().map(|(c, o)| {
            let (now, all) = (num(&o["status"]["currentHealthy"]), num(&o["status"]["expectedMachines"]));
            Item::new(if now < all { Tone::Warning } else { Tone::Success }, vec![self.full_name(c, o), format!("{now} of {all} healthy"), text(&o["spec"]["maxUnhealthy"])]).go(self.custom_go(c, CHECKS, o))
        }).collect();
        go = table(ui, &format!("Health checks ({})", h.len()), "they replace machines that stay unhealthy", &[("Check", 0.5), ("State", 0.3), ("Stops above", 0.2)], &h, 40, "None.").or(go);
        let mut q: Vec<Item> = vec![];
        for c in ctxs {
            for o in self.refs(c, Kind::CertificateSigningRequests, "").unwrap_or_default().into_iter().filter(|o| o["status"]["conditions"].as_array().map(|x| x.is_empty()).unwrap_or(true)) {
                q.push(Item::new(Tone::Warning, vec![name_of(o).to_string(), text(&o["spec"]["username"]), text(&o["spec"]["signerName"]), kube::age(o["metadata"]["creationTimestamp"].as_str().unwrap_or(""))]).go(Some(ops::obj(c, Kind::CertificateSigningRequests, "", name_of(o)))));
            }
        }
        go = table(ui, &format!("Certificate requests that wait ({})", q.len()), "a node that joins or renews asks for one", &[("Request", 0.24), ("By", 0.36), ("Signer", 0.28), ("Age", 0.12)], &q, 40, "None.").or(go);
        let routers: Vec<Item> = self.op_items(ROUTERS).into_iter().map(|(c, o)| {
            let bad = is(o, "Degraded", "True") || !is(o, "Available", "True");
            Item::new(if bad { Tone::Danger } else { Tone::Success }, vec![self.full_name(c, o), if bad { "has a problem".into() } else { "fine".into() }, format!("{} of {}", num(&o["status"]["availableReplicas"]), o["spec"]["replicas"].as_i64().unwrap_or(2)), text(&o["status"]["domain"]), if bad { why(o, "Degraded") } else { String::new() }]).go(self.custom_go(c, ROUTERS, o))
        }).collect();
        table(ui, &format!("Routers ({})", routers.len()), "where traffic comes in", &[("Router", 0.26), ("State", 0.14), ("Ready", 0.1), ("Domain", 0.3), ("Why", 0.2)], &routers, 20, "None.").or(go)
    }

    /// Apps and the constraint their pods run under.
    fn os_used(&self, ctx: &str, system: bool) -> Vec<Used> {
        let sccs: HashMap<String, (u8, String, Vec<String>)> = self.op_all(ctx, SCC).iter().map(|o| {
            let (w, a) = width(o);
            (name_of(o).to_string(), (w, a, o["defaultAddCapabilities"].as_array().into_iter().flatten().map(text).collect()))
        }).collect();
        let Some(l) = self.lists.get(&Self::list_key(ctx, Kind::Pods)) else { return vec![] };
        let mut by: HashMap<(Kind, String, String, String), Used> = HashMap::new();
        for (p, r) in l.items.iter().zip(&l.rows) {
            let scc = text(&p["metadata"]["annotations"]["openshift.io/scc"]);
            let sys = r.ns.starts_with("openshift") || r.ns.starts_with("kube-");
            if scc.is_empty() || (sys && !system) || !self.ns_ok(&r.ns) || matches!(p["status"]["phase"].as_str(), Some("Succeeded" | "Failed")) {
                continue;
            }
            let (kind, name) = r.workload.clone().unwrap_or((Kind::Pods, r.name.clone()));
            let (w, a, given) = sccs.get(&scc).cloned().unwrap_or_default();
            let e = by.entry((kind, r.ns.clone(), name.clone(), scc.clone())).or_insert_with(|| Used { scc, width: w, allows: a, sel: Selected { ctx: ctx.into(), kind, ns: r.ns.clone(), name }, pods: 0, asks: vec![] });
            e.pods += 1;
            for x in asks_for(p, &given) {
                if !e.asks.contains(&x) {
                    e.asks.push(x);
                }
            }
        }
        by.into_values().collect()
    }

    fn os_security(&mut self, ui: &mut Ui, ctxs: &[String]) -> Option<Go> {
        let mut go = None;
        let mut system = self.powers.os_system;
        ui.checkbox(&mut system, "Namespaces of the platform too (openshift-*, kube-*)");
        self.powers.os_system = system;
        ui.add_space(6.0);
        let mut used: Vec<Used> = ctxs.iter().flat_map(|c| self.os_used(c, system)).filter(|x| x.width > 0).collect();
        let free = |x: &Used| narrower(x.width, &x.asks);
        used.sort_by(|a, b| (!free(a), std::cmp::Reverse(a.width), &a.sel.ns, &a.sel.name, a.sel.kind.singular(), &a.scc, &a.sel.ctx).cmp(&(!free(b), std::cmp::Reverse(b.width), &b.sel.ns, &b.sel.name, b.sel.kind.singular(), &b.scc, &b.sel.ctx)));
        let n = used.iter().filter(|x| free(x)).count();
        let top = used.iter().filter(|x| free(x) && x.width == 3).count();
        let face = Face {
            tone: if top > 0 { Tone::Warning } else if n > 0 { Tone::Info } else { Tone::Success },
            head: if n == 0 { "No app has clearly more rights than it asks for".into() } else { format!("{} with more rights than they ask for", many(n as i64, "app")) },
            sub: format!("{top} of them could start a privileged container; {} run under a wide constraint in all", used.len()),
            notes: vec!["A constraint (SCC) says what a pod may do. An image can still need root without its settings saying so, so try a narrower one before you rely on it.".into()],
            pills: vec![],
            facts: vec![],
        };
        face::show(ui, &face, Side::None);
        ui.add_space(10.0);
        let word = |w: u8| match w { 3 => "privileged", 2 => "the host", _ => "any user" };
        let items: Vec<Item> = used.iter().map(|x| {
            let t = match (free(x), x.width) { (true, 3) => Tone::Warning, (true, _) => Tone::Info, _ => Tone::Muted };
            Item::new(t, vec![format!("{}/{}", x.sel.ns, x.sel.name), x.scc.clone(), word(x.width).into(), x.allows.clone(), if x.asks.is_empty() { "nothing special".into() } else { x.asks.join(", ") }, if free(x) { "more than it asks for".into() } else { "asks for it".into() }, x.pods.to_string()]).go(Some(Go::Object(x.sel.clone())))
        }).collect();
        let items = self.op_filter(items);
        go = table(ui, &format!("Apps under a wide constraint ({})", items.len()), "what they may do, next to what they ask for", &[("App", 0.25), ("Constraint", 0.14), ("Width", 0.08), ("Allows", 0.18), ("Asks for", 0.17), ("", 0.13), ("Pods", 0.05)], &items, 150, "None.").or(go);
        let mut c: Vec<(u8, Item)> = self.op_items(SCC).into_iter().map(|(ctx, o)| {
            let (w, a) = width(o);
            let groups: Vec<String> = o["groups"].as_array().into_iter().flatten().map(text).collect();
            let users = o["users"].as_array().map(|x| x.len()).unwrap_or(0);
            let open = groups.iter().any(|g| matches!(g.as_str(), "system:authenticated" | "system:serviceaccounts" | "system:unauthenticated"));
            let t = if open && w > 0 { Tone::Danger } else { match w { 3 => Tone::Warning, 0 => Tone::Success, _ => Tone::Info } };
            let pods = self.lists.get(&Self::list_key(ctx, Kind::Pods)).map(|l| l.items.iter().filter(|p| p["metadata"]["annotations"]["openshift.io/scc"].as_str() == Some(name_of(o))).count()).unwrap_or(0);
            (w, Item::new(t, vec![name_of(o).to_string(), match w { 0 => "narrow", x => word(x) }.to_string(), a, if open { "everyone".into() } else { format!("{}, {}", many(users as i64, "account"), many(groups.len() as i64, "group")) }, pods.to_string()]).go(self.custom_go(ctx, SCC, o)))
        }).collect();
        c.sort_by_key(|x| (x.1.tone != Tone::Danger, std::cmp::Reverse(x.0)));
        let c: Vec<Item> = self.op_filter(c.into_iter().map(|x| x.1).collect());
        let none = self.op_missing(SCC).unwrap_or("None.".into());
        table(ui, &format!("Constraints ({})", c.len()), "who is named in them; roles can give them to more accounts", &[("Constraint", 0.3), ("Width", 0.12), ("Allows", 0.28), ("Named in it", 0.2), ("Pods", 0.1)], &c, 80, &none).or(go)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn with(conds: &[(&str, &str)]) -> Value {
        json!({"metadata": {"name": "x"}, "spec": {}, "status": {"conditions": conds.iter().map(|c| json!({"type": c.0, "status": c.1, "reason": "R", "message": "m"})).collect::<Vec<_>>()}})
    }

    #[test]
    fn states() {
        assert_eq!(operator_state(&with(&[("Available", "True"), ("Degraded", "False")])).1, "Fine");
        assert_eq!(operator_state(&with(&[("Available", "True"), ("Degraded", "True")])).0, Tone::Danger);
        assert_eq!(operator_state(&with(&[("Available", "False")])).1, "Not available");
        assert_eq!(operator_state(&with(&[("Available", "True"), ("Upgradeable", "False")])).1, "Blocks updates");
        let mut p = with(&[("Updated", "True")]);
        assert_eq!(pool_state(&p).1, "Up to date");
        p["spec"]["paused"] = json!(true);
        assert_eq!(pool_state(&p).1, "Paused");
        assert_eq!(pool_state(&with(&[("NodeDegraded", "True")])).0, Tone::Danger);
        let mut s = with(&[]);
        s["status"]["state"] = json!("UpgradePending");
        s["spec"]["installPlanApproval"] = json!("Manual");
        assert_eq!(sub_state(&s).1, "Waits for approval");
        assert_eq!(sub_state(&with(&[("ResolutionFailed", "True")])).0, Tone::Danger);
    }

    #[test]
    fn rights() {
        assert_eq!(width(&json!({"allowPrivilegedContainer": true})).0, 3);
        assert_eq!(width(&json!({"allowHostNetwork": true, "runAsUser": {"type": "RunAsAny"}})).0, 2);
        assert_eq!(width(&json!({"runAsUser": {"type": "RunAsAny"}})).0, 1);
        assert_eq!(width(&json!({"runAsUser": {"type": "MustRunAsRange"}, "allowedCapabilities": ["NET_BIND_SERVICE"]})).0, 0);
        assert_eq!(width(&json!({"runAsUser": {"type": "MustRunAsRange"}, "allowedCapabilities": ["SYS_ADMIN"]})).0, 1);
        let plain = json!({"spec": {"containers": [{"name": "a"}]}});
        assert!(asks_for(&plain, &[]).is_empty() && narrower(3, &asks_for(&plain, &[])) && narrower(1, &asks_for(&plain, &[])));
        let root = json!({"spec": {"securityContext": {"runAsUser": 0}, "containers": [{"name": "a"}]}});
        assert!(asks_for(&root, &[]) == vec!["root"] && narrower(3, &asks_for(&root, &[])) && !narrower(1, &asks_for(&root, &[])));
        let host = json!({"spec": {"hostNetwork": true, "volumes": [{"hostPath": {"path": "/x"}}], "containers": [{"securityContext": {"privileged": true, "capabilities": {"add": ["NET_ADMIN"]}}, "ports": [{"hostPort": 80}]}]}});
        assert!(!narrower(3, &asks_for(&host, &[])) && !narrower(2, &asks_for(&host, &[])) && asks_for(&host, &[]).len() == 5);
        assert!(!narrower(0, &[]));
        let added = json!({"spec": {"containers": [{"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}}}]}});
        assert!(asks_for(&added, &["NET_ADMIN".into()]).is_empty() && asks_for(&added, &[]) == vec!["extra rights"]);
    }

    #[test]
    fn what_to_look_at() {
        let mut v = with(&[("Failing", "True"), ("Upgradeable", "False")]);
        v["spec"]["desiredUpdate"]["force"] = json!(true);
        v["status"]["availableUpdates"] = json!([{"version": "4.2"}]);
        v["status"]["history"] = json!([{"state": "Completed", "completionTime": "2026-01-01T00:00:00Z"}]);
        let now = kube::parse_time("2026-11-01T00:00:00Z").unwrap();
        let op = with(&[("Available", "True"), ("Degraded", "True")]);
        let cat = json!({"metadata": {"name": "cat"}, "status": {"connectionState": {"lastObservedState": "TRANSIENT_FAILURE"}}});
        let m = json!({"metadata": {"name": "m"}, "status": {"phase": "Failed", "errorMessage": "no"}});
        let old = slim_old(&[json!({"metadata": {"name": "old.v1"}, "status": {"removedInRelease": "1.32", "requestCount": 5, "last24h": [{"byNode": [{"byUser": [{"username": "u", "userAgent": "tool/1 x", "requestCount": 5}]}]}]}}), json!({"metadata": {"name": "fine"}, "status": {"requestCount": 5}})]);
        assert_eq!(old[0]["who"][0], "u (tool) 5×");
        let f = findings(Some(&v), &[&op], &[], &[], &[&cat], &[&m], 2, &old, now);
        let t = f.iter().map(|x| format!("{} / {}", x.1, x.2)).collect::<Vec<_>>().join("\n");
        for w in ["update is failing", "minor update is blocked", "1 update available", "was forced", "Not updated for", "operator x: degraded", "Catalog cat", "Machine m is failed", "2 certificate requests", "old.v1 is still used"] {
            assert!(t.contains(w), "{w}\n{t}");
        }
        assert!(f[0].0 == Tone::Danger);
        assert!(findings(None, &[], &[], &[], &[], &[], 0, &Value::Null, now).is_empty());
    }

    #[test]
    fn versions() {
        assert!(stays_behind("\"4.21\"", "4.21.0-x") && stays_behind("4.20", "4.21.3") && !stays_behind("4.22", "4.21.3") && !stays_behind("", "4.21"));
        let c = slim_csv(&[json!({"metadata": {"name": "a", "namespace": "n", "annotations": {"olm.properties": "[{\"type\":\"olm.maxOpenShiftVersion\",\"value\":\"4.21\"}]"}}, "spec": {"displayName": "A"}, "status": {"phase": "Succeeded"}})]);
        assert_eq!((c[0]["max"].as_str(), c[0]["display"].as_str()), (Some("4.21"), Some("A")));
    }
}
