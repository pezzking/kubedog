//! Readiness: before an upgrade, before a drain, what expires, who may do what, what's wasted, and
//! what's unsafe. Everything is read; what can be changed from here goes through the lock.

use super::face::{many, Face, Fact, Side};
use super::incident::{chip_button, tab_strip};
use super::ops::{ns_of, obj, table, text, worst_first, Item};
use super::pg::panel;
use super::podxray::Go;
use super::work::{name_of, said};
use super::*;

const TABS: [&str; 6] = ["Upgrade", "Drain", "Expiry", "Access", "Waste", "Security"];

#[derive(Default)]
pub(super) struct Ready {
    tab: usize,
    /// Nodes to rehearse a drain of, and what came out.
    nodes: HashSet<(String, String)>,
    plan: Option<Plan>,
    /// What's asked about access: (verb, group, resource).
    ask: usize,
    who: String,
}

// ---------- drain ----------

#[derive(Clone, Default, Debug)]
pub(super) struct Plan {
    /// (pod's namespace, name, where it goes or why it has no place)
    pub moves: Vec<(String, String, Result<String, String>)>,
    pub stay: usize,
    pub lost: Vec<String>,
    pub scratch: Vec<String>,
    pub waits: Vec<String>,
    pub down: Vec<String>,
}

fn owner(p: &Value) -> (String, String) {
    let r = &p["metadata"]["ownerReferences"][0];
    (text(&r["kind"]), text(&r["name"]))
}

/// Where everything would go when these nodes are drained.
pub(super) fn rehearse(away: &HashSet<String>, nodes: &[&Value], pods: &[&Value], budgets: &[&Value]) -> Plan {
    let mut plan = Plan::default();
    let live: Vec<&Value> = pods.iter().filter(|p| !matches!(p["status"]["phase"].as_str(), Some("Succeeded" | "Failed"))).copied().collect();
    let mut on: HashMap<String, Vec<&Value>> = HashMap::new();
    for p in &live {
        if let Some(n) = p["spec"]["nodeName"].as_str().filter(|n| !away.contains(*n)) {
            on.entry(n.to_string()).or_default().push(p);
        }
    }
    let targets: Vec<&Value> = nodes.iter().filter(|n| !away.contains(name_of(n))).copied().collect();
    let mut go: Vec<&Value> = vec![];
    for p in live.iter().filter(|p| p["spec"]["nodeName"].as_str().map(|n| away.contains(n)).unwrap_or(false)) {
        let mirror = !p["metadata"]["annotations"]["kubernetes.io/config.mirror"].is_null();
        let (kind, _) = owner(p);
        if mirror || kind == "DaemonSet" || kind == "Node" {
            plan.stay += 1;
            continue;
        }
        let full = format!("{}/{}", ns_of(p), name_of(p));
        if kind.is_empty() {
            plan.lost.push(full.clone());
        }
        if p["spec"]["volumes"].as_array().into_iter().flatten().any(|v| v["emptyDir"].is_object()) {
            plan.scratch.push(full);
        }
        go.push(p);
    }
    // Budgets that don't allow so many to go.
    for b in budgets {
        if !b["spec"]["selector"].is_object() {
            continue;
        }
        let hit = go.iter().filter(|p| ns_of(p) == ns_of(b) && podnet::selector_matches(&b["spec"]["selector"], &p["metadata"]["labels"])).count() as i64;
        let may = b["status"]["disruptionsAllowed"].as_i64().unwrap_or(0);
        if hit > 0 && may == 0 && b["metadata"]["ownerReferences"][0]["apiVersion"].as_str().unwrap_or("").starts_with("postgresql.cnpg.io") {
            plan.waits.push(format!("{}/{}: waits until CloudNativePG has moved the primary", ns_of(b), name_of(b)));
        } else if hit > 0 && may == 0 {
            plan.waits.push(format!("{}/{}: allows none to go, {} would have to", ns_of(b), name_of(b), many(hit, "pod")));
        } else if hit > may {
            plan.waits.push(format!("{}/{}: lets {may} go at a time, so {} go one after another", ns_of(b), name_of(b), many(hit, "pod")));
        }
    }
    // Apps that have all their ready pods here.
    let mut by: HashMap<(String, String, String), (usize, usize)> = HashMap::new();
    for p in &live {
        let (k, n) = owner(p);
        if k.is_empty() || k == "DaemonSet" || k == "Job" || k == "Node" {
            continue;
        }
        let e = by.entry((ns_of(p).to_string(), k, n)).or_default();
        e.0 += 1;
        if p["spec"]["nodeName"].as_str().map(|n| away.contains(n)).unwrap_or(false) {
            e.1 += 1;
        }
    }
    plan.down = by.into_iter().filter(|(_, (all, here))| all == here && *here > 0).map(|((ns, k, n), (all, _))| format!("{ns}/{}{}", if k == "ReplicaSet" { n.rsplit_once('-').map(|x| x.0.to_string()).unwrap_or(n) } else { n }, if all > 1 { format!(" (all {all} pods)") } else { String::new() })).collect();
    plan.down.sort();
    // The biggest first, each where it fits.
    let mem = |p: &Value| resources::requests(Kind::Pods, p)[2];
    go.sort_by(|a, b| mem(b).partial_cmp(&mem(a)).unwrap_or(std::cmp::Ordering::Equal));
    let none = vec![];
    for p in go {
        let mut best: Option<(&str, usize)> = None;
        let mut why: HashMap<String, usize> = HashMap::new();
        for n in &targets {
            let here = on.get(name_of(n)).unwrap_or(&none);
            let no = podplace::against(p, n, here);
            if no.is_empty() {
                if best.map(|b| here.len() < b.1).unwrap_or(true) {
                    best = Some((name_of(n), here.len()));
                }
            } else {
                for w in no {
                    *why.entry(w).or_default() += 1;
                }
            }
        }
        let r = match best {
            Some((n, _)) => {
                on.entry(n.to_string()).or_default().push(p);
                Ok(n.to_string())
            }
            None => {
                let mut w: Vec<(String, usize)> = why.into_iter().collect();
                w.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                Err(w.into_iter().take(3).map(|(w, n)| format!("{w} ({n})")).collect::<Vec<_>>().join(", "))
            }
        };
        plan.moves.push((ns_of(p).into(), name_of(p).into(), r));
    }
    plan.moves.sort_by(|a, b| a.2.is_ok().cmp(&b.2.is_ok()).then(a.0.cmp(&b.0)).then(a.1.cmp(&b.1)));
    plan
}

// ---------- access ----------

/// What can be asked: (label, verb, group, resource).
const ASKS: &[(&str, &str, &str, &str)] = &[
    ("read secrets", "get", "", "secrets"),
    ("run commands in pods", "create", "", "pods/exec"),
    ("make pods", "create", "", "pods"),
    ("delete deployments", "delete", "apps", "deployments"),
    ("change config maps", "update", "", "configmaps"),
    ("give out roles", "create", "rbac.authorization.k8s.io", "rolebindings"),
    ("raise roles", "escalate", "rbac.authorization.k8s.io", "clusterroles"),
    ("act as others", "impersonate", "", "users"),
    ("drain nodes", "create", "", "pods/eviction"),
    ("do anything", "*", "*", "*"),
];

/// Does a role's rule let this? Some(names) when only for certain objects.
pub(super) fn lets(r: &Value, verb: &str, group: &str, res: &str) -> Option<Vec<String>> {
    let has = |k: &str, x: &str| r[k].as_array().into_iter().flatten().any(|v| v.as_str() == Some(x) || v.as_str() == Some("*"));
    let resource = has("resources", res) || res.split_once('/').map(|(_, s)| r["resources"].as_array().into_iter().flatten().any(|v| v.as_str() == Some(&format!("*/{s}")))).unwrap_or(false);
    if !(has("verbs", verb) && has("apiGroups", group) && resource) {
        return None;
    }
    Some(r["resourceNames"].as_array().into_iter().flatten().map(text).collect())
}

/// Who a binding names: "ServiceAccount ns/name", "Group x"...
fn subjects(b: &Value) -> Vec<String> {
    b["subjects"].as_array().into_iter().flatten().map(|s| match s["kind"].as_str() { Some("ServiceAccount") => format!("service account {}/{}", s["namespace"].as_str().unwrap_or(ns_of(b)), text(&s["name"])), Some(k) => format!("{} {}", k.to_lowercase(), text(&s["name"])), None => text(&s["name"]) }).collect()
}

/// Accounts of the cluster itself say little.
fn own(s: &str) -> bool {
    s.contains(" system:") || s.contains(" kube-system/") || s.contains(" openshift-") || s.contains(" kube-")
}

// ---------- security ----------

/// What's unsafe about a pod, with weights.
pub(super) fn unsafe_bits(p: &Value) -> Vec<(u32, String)> {
    let mut v: Vec<(u32, String)> = vec![];
    let spec = &p["spec"];
    for (k, w, t) in [("hostNetwork", 6, "uses the node's network"), ("hostPID", 8, "sees the node's processes"), ("hostIPC", 6, "shares the node's memory segments")] {
        if spec[k] == true {
            v.push((w, t.into()));
        }
    }
    for x in spec["volumes"].as_array().into_iter().flatten() {
        if let Some(h) = x["hostPath"]["path"].as_str() {
            v.push((if h == "/" || h.contains("docker.sock") || h.contains("crio.sock") || h.contains("containerd.sock") { 9 } else { 3 }, format!("mounts {h} of the node")));
        }
    }
    let psc = &spec["securityContext"];
    for c in pod::containers(p) {
        let n = text(&c["name"]);
        let sc = &c["securityContext"];
        let get = |k: &str| if sc[k].is_null() { &psc[k] } else { &sc[k] };
        if sc["privileged"] == true {
            v.push((10, format!("{n} is privileged")));
        } else {
            let user = get("runAsUser").as_i64();
            if user == Some(0) {
                v.push((6, format!("{n} runs as root")));
            } else if user.is_none() && get("runAsNonRoot") != &Value::Bool(true) {
                v.push((3, format!("{n} may run as root")));
            }
            if sc["allowPrivilegeEscalation"] != false {
                v.push((1, format!("{n} may gain more rights")));
            }
        }
        for a in sc["capabilities"]["add"].as_array().into_iter().flatten().filter_map(|x| x.as_str()) {
            let w = if matches!(a, "SYS_ADMIN" | "ALL" | "NET_ADMIN" | "SYS_PTRACE" | "SYS_MODULE") { 7 } else { 2 };
            v.push((w, format!("{n} has {a}")));
        }
        let img = c["image"].as_str().unwrap_or("");
        let last = img.rsplit('/').next().unwrap_or(img);
        if !img.contains('@') && (last.ends_with(":latest") || !last.contains(':')) {
            v.push((2, format!("{n} uses “latest”")));
        }
        if c["resources"]["limits"]["memory"].is_null() {
            v.push((1, format!("{n} has no memory limit")));
        }
        let s = c["env"].as_array().into_iter().flatten().filter(|e| e["valueFrom"]["secretKeyRef"].is_object()).count() + c["envFrom"].as_array().into_iter().flatten().filter(|e| e["secretRef"].is_object()).count();
        if s > 0 {
            v.push((1, format!("{n} takes secrets as variables")));
        }
    }
    v
}

/// A round figure with half as much again on top: (cpu m, memory Mi).
pub(super) fn suggest(cpu: f64, mem: f64) -> (i64, i64) {
    let c = ((cpu * 1.5 / 10.0).ceil() * 10.0).max(10.0) as i64;
    let m = ((mem * 1.5 / 1048576.0 / 16.0).ceil() * 16.0).max(32.0) as i64;
    (c, m)
}

impl KubedogApp {
    pub(super) fn ready_kinds(&self) -> Vec<Kind> {
        match self.ready.tab {
            0 => vec![Kind::Nodes, Kind::PodDisruptionBudgets, Kind::Deployments, Kind::StatefulSets, Kind::Pods, Kind::MutatingWebhooks, Kind::ValidatingWebhooks, Kind::Services, Kind::EndpointSlices],
            1 => vec![Kind::Nodes, Kind::Pods, Kind::PodDisruptionBudgets],
            2 => vec![Kind::Ingresses, Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets],
            3 => vec![Kind::Roles, Kind::ClusterRoles, Kind::RoleBindings, Kind::ClusterRoleBindings],
            4 => vec![Kind::Pods, Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::CronJobs, Kind::Jobs, Kind::ReplicaSets, Kind::PersistentVolumeClaims, Kind::PersistentVolumes, Kind::ConfigMaps, Kind::Services, Kind::EndpointSlices, Kind::Ingresses, Kind::ServiceAccounts],
            _ => vec![Kind::Pods, Kind::NetworkPolicies],
        }
    }

    pub(super) fn refresh_readiness(&mut self, force: bool) {
        if self.view != View::Readiness || self.power_off("readiness") {
            return;
        }
        for c in self.active.clone() {
            match self.ready.tab {
                0 => {
                    let a = ["--context", &c, "version", "-o", "json", &format!("--request-timeout={}", kube::REQUEST_TIMEOUT)].iter().map(|s| s.to_string()).collect::<Vec<_>>();
                    self.ask(&format!("version|{c}"), 600, force, move |k| k.run(&a));
                }
                2 => {
                    let ctx = c.clone();
                    self.read_custom("certificates.cert-manager.io", 120, force);
                    self.ask(&format!("tls|{c}"), 600, force, move |k| {
                        // Only certificates are asked for, never keys.
                        let a: Vec<String> = ["--context", &ctx, "get", "secrets", "--all-namespaces", "--field-selector", "type=kubernetes.io/tls", "-o", "go-template={{range .items}}{{.metadata.namespace}}{{\"\\t\"}}{{.metadata.name}}{{\"\\t\"}}{{index .data \"tls.crt\"}}{{\"\\n\"}}{{end}}", &format!("--request-timeout={}", kube::REQUEST_TIMEOUT)].iter().map(|s| s.to_string()).collect();
                        let t = k.run(&a)?;
                        let l: Vec<Value> = t.lines().filter_map(|l| { let f: Vec<&str> = l.split('\t').collect(); let c = certs::cert_from_secret_b64(f.get(2)?).ok()?; Some(serde_json::json!({"ns": f[0], "name": f[1], "end": c.not_after, "start": c.not_before, "issuer": c.issuer, "subject": c.subject})) }).collect();
                        Ok(Value::Array(l).to_string())
                    });
                }
                4 => {
                    let ctx = c.clone();
                    self.ask(&format!("secretnames|{c}"), 300, force, move |k| {
                        // Names and types only.
                        let a: Vec<String> = ["--context", &ctx, "get", "secrets", "--all-namespaces", "-o", "go-template={{range .items}}{{.metadata.namespace}}{{\"\\t\"}}{{.metadata.name}}{{\"\\t\"}}{{.type}}{{\"\\t\"}}{{if .metadata.ownerReferences}}owned{{end}}{{\"\\n\"}}{{end}}", &format!("--request-timeout={}", kube::REQUEST_TIMEOUT)].iter().map(|s| s.to_string()).collect();
                        let l: Vec<Value> = k.run(&a)?.lines().filter_map(|l| { let f: Vec<&str> = l.split('\t').collect(); (f.len() >= 3).then(|| serde_json::json!({"ns": f[0], "name": f[1], "type": f[2], "owned": f.get(3) == Some(&"owned")})) }).collect();
                        Ok(Value::Array(l).to_string())
                    });
                }
                _ => {}
            }
        }
    }

    pub(super) fn readiness_view(&mut self, ui: &mut Ui) {
        if self.power_off("readiness") {
            self.header(ui, false, None, false);
            said(ui, "Readiness is switched off in Settings > Superpowers.", TEXT_SUBTLE());
            return;
        }
        if self.screenshot.is_some() {
            if let Some(t) = std::env::var("KUBEDOG_SHOT_TAB").ok().and_then(|t| t.parse().ok()).filter(|t| *t < TABS.len()) {
                if self.ready.tab != t {
                    self.ready.tab = t;
                    self.refresh_current(false);
                }
            }
        }
        self.header(ui, true, Some("Readiness".into()), true);
        let mut tab = self.ready.tab;
        ui.horizontal(|ui| tab_strip(ui, &TABS, &mut tab));
        if tab != self.ready.tab {
            self.ready.tab = tab;
            self.refresh_current(false);
        }
        ui.add_space(8.0);
        let mut go: Option<Go> = None;
        self.page_scroll().id_salt(("ready", tab)).show(ui, |ui| {
            go = match tab {
                0 => self.upgrade(ui),
                1 => self.drain_rehearsal(ui),
                2 => self.expiry(ui),
                3 => self.access(ui),
                4 => self.waste(ui),
                _ => self.security(ui),
            };
            ui.add_space(20.0);
        });
        if let Some(g) = go {
            self.go_to(g);
        }
    }

    fn not_read(&self, kinds: &[Kind]) -> Vec<String> {
        let mut v: Vec<String> = self.active.iter().filter(|c| self.ctx_shown(c)).flat_map(|c| kinds.iter().filter_map(|k| self.missing(c, *k))).collect();
        v.sort();
        v.dedup();
        v
    }

    fn upgrade(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        let mut items: Vec<Item> = vec![];
        let mut versions: Vec<String> = vec![];
        let mut ask_apis: Option<String> = None;
        for c in self.active.clone().iter().filter(|c| self.ctx_shown(c)) {
            let pre = if self.active.len() > 1 { format!("{} · ", ctx_label(c)) } else { String::new() };
            let ver = match self.answer(&format!("version|{c}")) { Some(Ok(v)) => text(&v["serverVersion"]["gitVersion"]), _ => String::new() };
            let minor = |v: &str| v.trim_start_matches('v').split('.').nth(1).and_then(|m| m.parse::<i64>().ok());
            if !ver.is_empty() {
                versions.push(format!("{pre}{ver}"));
            }
            // Nodes behind the server.
            let mut kubelets: Vec<String> = vec![];
            for n in self.refs(c, Kind::Nodes, "").unwrap_or_default() {
                let k = text(&n["status"]["nodeInfo"]["kubeletVersion"]);
                let behind = minor(&ver).zip(minor(&k)).map(|(a, b)| a - b).unwrap_or(0);
                if behind >= 1 {
                    items.push(Item::new(if behind >= 3 { Tone::Danger } else { Tone::Warning }, vec!["Node behind".into(), format!("{pre}{}", name_of(n)), format!("kubelet {k}, the server has {ver}")]).go(Some(obj(c, Kind::Nodes, "", name_of(n)))));
                }
                if n["spec"]["unschedulable"] == true {
                    items.push(Item::new(Tone::Warning, vec!["Node cordoned".into(), format!("{pre}{}", name_of(n)), "its room isn't there for a rolling upgrade".into()]).go(Some(obj(c, Kind::Nodes, "", name_of(n)))));
                }
                if !kubelets.contains(&k) {
                    kubelets.push(k);
                }
            }
            // Budgets that stop a drain.
            for b in self.refs(c, Kind::PodDisruptionBudgets, "").unwrap_or_default().into_iter().filter(|b| self.ns_ok(ns_of(b))) {
                if b["status"]["expectedPods"].as_i64().unwrap_or(0) > 0 && b["status"]["disruptionsAllowed"].as_i64().unwrap_or(0) == 0 {
                    let cnpg = b["metadata"]["ownerReferences"][0]["apiVersion"].as_str().unwrap_or("").starts_with("postgresql.cnpg.io");
                    items.push(Item::new(if cnpg { Tone::Info } else { Tone::Danger }, vec![if cnpg { "Postgres primary" } else { "Blocks draining" }.into(), format!("{pre}{}/{}", ns_of(b), name_of(b)), format!("its budget allows no pod to go: {} of {} healthy{}", b["status"]["currentHealthy"], b["status"]["desiredHealthy"], if cnpg { "; CloudNativePG moves the primary away first" } else { "" })]).go(Some(obj(c, Kind::PodDisruptionBudgets, ns_of(b), name_of(b)))));
                }
            }
            // Apps that stop when their one pod moves.
            for k in [Kind::Deployments, Kind::StatefulSets] {
                for o in self.refs(c, k, "").unwrap_or_default().into_iter().filter(|o| self.ns_ok(ns_of(o)) && o["spec"]["replicas"].as_i64().unwrap_or(1) == 1) {
                    items.push(Item::new(Tone::Info, vec!["Single replica".into(), format!("{pre}{}/{}", ns_of(o), name_of(o)), "down while its pod moves to another node".into()]).go(Some(obj(c, k, ns_of(o), name_of(o)))));
                }
            }
            // Webhooks that may refuse everything.
            for k in [Kind::MutatingWebhooks, Kind::ValidatingWebhooks] {
                for o in self.refs(c, k, "").unwrap_or_default() {
                    for w in o["webhooks"].as_array().into_iter().flatten().filter(|w| w["failurePolicy"] != "Ignore") {
                        let s = &w["clientConfig"]["service"];
                        let (Some(n), Some(ns)) = (s["name"].as_str(), s["namespace"].as_str()) else { continue };
                        let exists = self.refs(c, Kind::Services, ns).map(|l| l.iter().any(|x| name_of(x) == n));
                        let ready = self.service_ready(c, ns, n);
                        if exists == Some(false) || matches!(ready, Some((0, _))) {
                            items.push(Item::new(Tone::Danger, vec!["Webhook without an answer".into(), format!("{pre}{}", name_of(o)), format!("{}: service {ns}/{n} {}, so what it's asked about is refused", text(&w["name"]), if exists == Some(false) { "doesn't exist" } else { "has no ready endpoints" })]).go(Some(obj(c, k, "", name_of(o)))));
                        } else if matches!(ready, Some((1, 1))) && w["rules"].as_array().into_iter().flatten().any(|r| r["apiGroups"].as_array().into_iter().flatten().any(|g| matches!(g.as_str(), Some("" | "*"))) && r["resources"].as_array().into_iter().flatten().any(|x| matches!(x.as_str(), Some("pods" | "*" | "*/*")))) {
                            items.push(Item::new(Tone::Warning, vec!["Webhook on one pod".into(), format!("{pre}{}", name_of(o)), format!("{}: while {ns}/{n} moves, new pods are refused", text(&w["name"]))]).go(Some(obj(c, k, "", name_of(o)))));
                        }
                    }
                }
            }
            // Kinds that are stored in, or only served as, an old version.
            let crds = self.lists.get(&Self::list_key(c, Kind::CustomResourceDefinitions)).map(|l| l.items.as_slice()).unwrap_or(&[]);
            for d in crds {
                let old: Vec<String> = d["spec"]["versions"].as_array().into_iter().flatten().filter(|v| v["deprecated"] == true && v["storage"] == true).map(|v| text(&v["name"])).collect();
                if !old.is_empty() {
                    items.push(Item::new(Tone::Warning, vec!["Old custom kind".into(), format!("{pre}{}", name_of(d)), format!("stored as {}, which is deprecated", old.join(", "))]).go(Some(obj(c, Kind::CustomResourceDefinitions, "", name_of(d)))));
                }
            }
            // APIs in use that will go: the server counts them itself.
            let key = format!("apis|{c}");
            match self.powers.answers.get(&key) {
                None => ask_apis = Some(c.clone()),
                Some(Some(Ok(v))) => {
                    for a in v.as_array().into_iter().flatten() {
                        let gone = text(&a["removed"]);
                        items.push(Item::new(if gone.is_empty() { Tone::Info } else { Tone::Danger }, vec!["Old API in use".into(), format!("{pre}{} {}", text(&a["resource"]), text(&a["version"])), if gone.is_empty() { "deprecated; when it goes isn't known".into() } else { format!("gone in Kubernetes {gone}") }]));
                    }
                }
                Some(Some(Err(e))) => items.push(Item::new(Tone::Muted, vec!["Old APIs".into(), format!("{pre}not known"), truncate(e, 200)])),
                _ => {}
            }
        }
        let bad = items.iter().filter(|i| i.tone == Tone::Danger).count();
        let warn = items.iter().filter(|i| i.tone == Tone::Warning).count();
        let gone = self.not_read(&[Kind::Nodes, Kind::PodDisruptionBudgets, Kind::MutatingWebhooks, Kind::ValidatingWebhooks, Kind::Deployments]);
        face::show(ui, &Face { tone: if bad > 0 { Tone::Danger } else if warn > 0 { Tone::Warning } else { Tone::Success }, head: if bad > 0 { format!("{} in the way of an upgrade", many(bad as i64, "thing")) } else if warn > 0 { format!("{} to look at first", many(warn as i64, "thing")) } else { "Nothing in the way that Kubedog can see".into() }, sub: if versions.is_empty() { "reading the version…".into() } else { versions.join(", ") }, notes: if gone.is_empty() { vec![] } else { vec![format!("Not looked at: {}.", gone.join("; "))] }, pills: vec![], facts: vec![] }, Side::None);
        ui.add_space(8.0);
        if let Some(c) = ask_apis {
            ui.horizontal(|ui| {
                if button(ui, "Check for old APIs in use", true, false) {
                    let args = powers::raw_args(&c, "/metrics");
                    self.ask(&format!("apis|{c}"), 0, true, move |k| Ok(Value::Array(old_apis(&k.run(&args)?)).to_string()));
                }
                said(ui, "reads the API server's own counters; needs wide rights and takes a moment", TEXT_PLACEHOLDER());
            });
        }
        self.bad_switch(ui);
        let mut items = self.op_filter(items);
        worst_first(&mut items);
        go = table(ui, &format!("What to know ({})", items.len()), "", &[("What", 0.18), ("Where", 0.36), ("Why", 0.46)], &items, 200, "Nothing.").or(go);
        go
    }

    fn drain_rehearsal(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        let mut all: Vec<(String, String, String)> = vec![];
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            for n in self.refs(c, Kind::Nodes, "").unwrap_or_default() {
                all.push((c.clone(), name_of(n).into(), text(&n["metadata"]["labels"]["topology.kubernetes.io/zone"])));
            }
        }
        if self.screenshot.is_some() && self.ready.nodes.is_empty() {
            if let Some(n) = std::env::var("KUBEDOG_SHOT_OBJ").ok().and_then(|o| all.iter().find(|a| a.1 == o).cloned()) {
                self.ready.nodes.insert((n.0, n.1));
                self.ready.plan = None;
            }
        }
        let mut changed = false;
        card(ui, |ui| {
            panel(ui, "Nodes to drain", "nothing is drained: it's worked out from what's running now");
            ui.horizontal_wrapped(|ui| {
                for (c, n, _) in &all {
                    let key = (c.clone(), n.clone());
                    let on = self.ready.nodes.contains(&key);
                    if chip_button(ui, n, on) {
                        changed = true;
                        if !self.ready.nodes.remove(&key) {
                            self.ready.nodes.insert(key);
                        }
                    }
                }
            });
            let mut zones: Vec<&str> = all.iter().map(|a| a.2.as_str()).filter(|z| !z.is_empty()).collect();
            zones.sort();
            zones.dedup();
            if zones.len() > 1 {
                ui.horizontal_wrapped(|ui| {
                    said(ui, "a whole zone:", TEXT_SUBTLE());
                    for z in zones {
                        if chip_button(ui, z, false) {
                            changed = true;
                            self.ready.nodes = all.iter().filter(|a| a.2 == z).map(|a| (a.0.clone(), a.1.clone())).collect();
                        }
                    }
                });
            }
            if all.is_empty() {
                said(ui, &self.not_read(&[Kind::Nodes]).join("; "), TEXT_SUBTLE());
            }
        });
        if changed {
            self.ready.plan = None;
        }
        ui.add_space(10.0);
        let Some((ctx, _)) = self.ready.nodes.iter().next().cloned() else {
            said(ui, "Pick one or more nodes.", TEXT_SUBTLE());
            return None;
        };
        if self.prefs.ctx_namespaces.contains_key(&ctx) || self.refused(&ctx, Kind::Namespaces) {
            said(ui, "Kubedog only sees the pods of some namespaces here, so it can't tell how full the nodes are.", WARNING());
            return None;
        }
        if let Some(w) = [Kind::Nodes, Kind::Pods, Kind::PodDisruptionBudgets].iter().find_map(|k| self.missing(&ctx, *k)) {
            said(ui, &w, TEXT_SUBTLE());
            return None;
        }
        if self.ready.plan.is_none() {
            let away: HashSet<String> = self.ready.nodes.iter().filter(|n| n.0 == ctx).map(|n| n.1.clone()).collect();
            let get = |k: Kind| self.refs(&ctx, k, "").unwrap_or_default();
            let p = rehearse(&away, &get(Kind::Nodes), &get(Kind::Pods), &get(Kind::PodDisruptionBudgets));
            self.ready.plan = Some(p);
        }
        let plan = self.ready.plan.clone().unwrap_or_default();
        let stuck = plan.moves.iter().filter(|m| m.2.is_err()).count();
        let blocked = plan.waits.iter().filter(|w| w.contains("allows none")).count();
        let mut notes = vec![];
        if blocked > 0 {
            notes.push(format!("{} would stop it.", many(blocked as i64, "budget")));
        }
        if stuck > 0 {
            notes.push(format!("{} would have no place to go.", many(stuck as i64, "pod")));
        }
        if !plan.lost.is_empty() {
            notes.push(format!("{} not made again by anything: {}.", many(plan.lost.len() as i64, "pod"), some_names(&plan.lost)));
        }
        face::show(ui, &Face { tone: if stuck + blocked > 0 { Tone::Danger } else if !plan.down.is_empty() || !plan.lost.is_empty() { Tone::Warning } else { Tone::Success }, head: if stuck + blocked > 0 { "This drain would get stuck".into() } else if !plan.down.is_empty() { format!("It would work, with {} down for a moment", many(plan.down.len() as i64, "app")) } else { "It would work".into() }, sub: "a guess at what the scheduler would do, not a promise".into(), notes, pills: vec![], facts: vec![Fact::new("Pods to move", plan.moves.len().to_string()), Fact::new("Stay (daemon sets)", plan.stay.to_string()), Fact::new("Without a place", stuck.to_string()), Fact::new("Lose scratch data", plan.scratch.len().to_string()), Fact::new("Apps down", plan.down.len().to_string())] }, Side::None);
        ui.add_space(8.0);
        if button(ui, "Work it out again", false, false) {
            self.ready.plan = None;
        }
        ui.add_space(8.0);
        let waits: Vec<Item> = plan.waits.iter().map(|w| Item::new(if w.contains("allows none") { Tone::Danger } else { Tone::Info }, vec![w.clone()])).collect();
        if !waits.is_empty() {
            go = table(ui, "Budgets", "", &[("", 1.0)], &waits, 40, "").or(go);
        }
        let down: Vec<Item> = plan.down.iter().map(|d| Item::new(Tone::Warning, vec![d.clone()])).collect();
        if !down.is_empty() {
            go = table(ui, &format!("Down for a moment ({})", down.len()), "all their pods are on these nodes", &[("App", 1.0)], &self.op_filter(down), 60, "").or(go);
        }
        let moves: Vec<Item> = plan.moves.iter().map(|(ns, n, r)| Item::new(if r.is_ok() { Tone::Success } else { Tone::Danger }, vec![format!("{ns}/{n}"), match r { Ok(to) => format!("to {to}"), Err(w) => format!("nowhere: {w}") }]).go(Some(obj(&ctx, Kind::Pods, ns, n)))).collect();
        go = table(ui, &format!("Where pods would go ({})", moves.len()), "", &[("Pod", 0.5), ("Where", 0.5)], &self.op_filter(moves), 200, "None to move.").or(go);
        said(ui, "Not looked at: pods it must be near or away from, even spreading, and where disks can be attached.", TEXT_PLACEHOLDER());
        go
    }

    fn expiry(&mut self, ui: &mut Ui) -> Option<Go> {
        let now = kube::now_secs();
        let mut items: Vec<(i64, Item)> = vec![];
        let mut wait = None;
        for c in self.active.clone().iter().filter(|c| self.ctx_shown(c)) {
            let pre = if self.active.len() > 1 { format!("{} · ", ctx_label(c)) } else { String::new() };
            // What uses each.
            let mut users: HashMap<(String, String), Vec<String>> = HashMap::new();
            for i in self.refs(c, Kind::Ingresses, "").unwrap_or_default() {
                for t in i["spec"]["tls"].as_array().into_iter().flatten().filter_map(|t| t["secretName"].as_str()) {
                    users.entry((ns_of(i).into(), t.into())).or_default().push(format!("ingress {}", name_of(i)));
                }
            }
            for k in [Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets] {
                for w in self.refs(c, k, "").unwrap_or_default() {
                    for (uk, n) in workload::uses_of(workload::pod_spec(k, w)) {
                        if uk == Kind::Secrets {
                            users.entry((ns_of(w).into(), n)).or_default().push(name_of(w).into());
                        }
                    }
                }
            }
            let managed: HashSet<(String, String)> = self.op_all(c, "certificates.cert-manager.io").iter().map(|o| (ns_of(o).to_string(), text(&o["spec"]["secretName"]))).collect();
            match self.powers.answers.get(&format!("tls|{c}")) {
                Some(Some(Ok(v))) => {
                    for s in v.as_array().into_iter().flatten() {
                        let (ns, n) = (text(&s["ns"]), text(&s["name"]));
                        if !self.ns_ok(&ns) {
                            continue;
                        }
                        let end = s["end"].as_i64().unwrap_or(i64::MAX);
                        let system = ns.starts_with("openshift") || ns.starts_with("kube-");
                        let auto = system || managed.contains(&(ns.clone(), n.clone()));
                        let used = users.get(&(ns.clone(), n.clone())).cloned().unwrap_or_default();
                        let days = (end - now) / 86400;
                        let t = if end < now { if used.is_empty() { Tone::Warning } else { Tone::Danger } } else if days < 7 { Tone::Danger } else if days < 30 && !auto { Tone::Warning } else { Tone::Success };
                        items.push((end, Item::new(t, vec![format!("{pre}{ns}/{n}"), if end < now { format!("expired {} days ago", -days) } else { format!("{} left", many(days, "day")) }, text(&s["subject"]), text(&s["issuer"]), if system { "the platform".into() } else if auto { "cert-manager".into() } else { "by hand or another".into() }, if used.is_empty() { "-".into() } else { some_names(&used) }]).tip(format!("{ns}/{n}\nused by: {}", if used.is_empty() { "nothing found".into() } else { used.join(", ") })).go(Some(obj(c, Kind::Secrets, &ns, &n)))));
                    }
                }
                Some(Some(Err(e))) => wait = Some(format!("{pre}certificates couldn't be read: {}", truncate(e, 160))),
                _ => wait = Some("Reading certificates…".into()),
            }
        }
        items.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cells.cmp(&b.1.cells)));
        let soon = items.iter().filter(|i| i.1.bad()).count();
        face::show(ui, &Face { tone: if items.iter().any(|i| i.1.tone == Tone::Danger) { Tone::Danger } else if soon > 0 { Tone::Warning } else { Tone::Success }, head: if soon > 0 { format!("{} to look at", many(soon as i64, "certificate")) } else { "Nothing expires soon".into() }, sub: format!("{} in TLS secrets", many(items.len() as i64, "certificate")), notes: wait.into_iter().collect(), pills: vec![], facts: vec![] }, Side::None);
        ui.add_space(10.0);
        // The months ahead.
        card(ui, |ui| {
            panel(ui, "The year ahead", "how many expire in each month; those renewed by themselves are lighter");
            let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(110.0)), Sense::hover());
            let w = r.width() / 12.0;
            let mut n = [[0usize; 2]; 12];
            for (end, i) in &items {
                let m = (end - now) / (30 * 86400);
                if *end > now && (0..12).contains(&m) {
                    n[m as usize][matches!(i.cells[4].as_str(), "cert-manager" | "the platform") as usize] += 1;
                }
            }
            let max = n.iter().map(|x| x[0] + x[1]).max().unwrap_or(1).max(1) as f32;
            for (i, x) in n.iter().enumerate() {
                let b = egui::Rect::from_min_max(egui::pos2(r.left() + i as f32 * w + 6.0, r.top() + u(16.0)), egui::pos2(r.left() + (i + 1) as f32 * w - 6.0, r.bottom() - u(20.0)));
                let mut y = b.bottom();
                for (k, col) in [(0, WARNING()), (1, SUCCESS().gamma_multiply(0.45))] {
                    let h = b.height() * x[k] as f32 / max;
                    ui.painter().rect_filled(egui::Rect::from_min_max(egui::pos2(b.left(), y - h), egui::pos2(b.right(), y)), CornerRadius::same(3), col);
                    y -= h;
                }
                if x[0] + x[1] > 0 {
                    ui.painter().text(egui::pos2(b.center().x, y - 2.0), egui::Align2::CENTER_BOTTOM, (x[0] + x[1]).to_string(), FontId::proportional(z(11.0)), TEXT_MUTED());
                }
                ui.painter().text(egui::pos2(b.center().x, r.bottom()), egui::Align2::CENTER_BOTTOM, if i == 0 { "this month".to_string() } else { format!("+{i}") }, FontId::proportional(z(10.5)), TEXT_PLACEHOLDER());
            }
        });
        ui.add_space(10.0);
        self.bad_switch(ui);
        let l = self.op_filter(items.into_iter().map(|i| i.1).collect());
        let go = table(ui, &format!("Certificates ({})", l.len()), "soonest first; only certificates are read, never keys. Tokens and logins for images aren't read.", &[("Secret", 0.26), ("Left", 0.13), ("For", 0.18), ("From", 0.15), ("Renewed by", 0.11), ("Used by", 0.17)], &l, 200, "None.");
        go
    }

    /// (who, how, where, only these objects, strength)
    fn who_can(&self, c: &str, verb: &str, group: &str, res: &str) -> Vec<(String, String, String, Vec<String>, Selected)> {
        let mut out = vec![];
        for (kind, ns_scope) in [(Kind::ClusterRoleBindings, false), (Kind::RoleBindings, true)] {
            for b in self.refs(c, kind, "").unwrap_or_default() {
                let ns = ns_of(b).to_string();
                if ns_scope && !self.ns_ok(&ns) {
                    continue;
                }
                let rr = &b["roleRef"];
                let role = if rr["kind"] == "Role" { self.refs(c, Kind::Roles, &ns) } else { self.refs(c, Kind::ClusterRoles, "") }.unwrap_or_default().into_iter().find(|r| r["metadata"]["name"] == rr["name"]);
                let Some(role) = role else { continue };
                let Some(names) = role["rules"].as_array().into_iter().flatten().find_map(|r| lets(r, verb, group, res)) else { continue };
                for s in subjects(b) {
                    out.push((s, format!("{} via {}", text(&rr["name"]), name_of(b)), if ns_scope { format!("in {ns}") } else { "everywhere".into() }, names.clone(), Selected { ctx: c.to_string(), kind, ns: ns.clone(), name: name_of(b).into() }));
                }
            }
        }
        out
    }

    fn access(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        card(ui, |ui| {
            panel(ui, "Who can…", "");
            ui.horizontal_wrapped(|ui| {
                for (i, a) in ASKS.iter().enumerate() {
                    if chip_button(ui, a.0, self.ready.ask == i) {
                        self.ready.ask = i;
                    }
                }
            });
        });
        ui.add_space(10.0);
        let (label, verb, group, res) = ASKS[self.ready.ask.min(ASKS.len() - 1)];
        let gone = self.not_read(&[Kind::Roles, Kind::ClusterRoles, Kind::RoleBindings, Kind::ClusterRoleBindings]);
        let mut items: Vec<Item> = vec![];
        for c in self.active.clone().iter().filter(|c| self.ctx_shown(c)) {
            for (who, how, where_, names, sel) in self.who_can(c, verb, group, res) {
                let mine = own(&who);
                let t = if mine { Tone::Muted } else if where_ == "everywhere" && names.is_empty() { Tone::Danger } else if names.is_empty() { Tone::Warning } else { Tone::Info };
                items.push(Item::new(t, vec![who, where_, how, if names.is_empty() { "all of them".into() } else { some_names(&names) }]).go(Some(Go::Object(sel))));
            }
        }
        items.sort_by(|a, b| a.cells.cmp(&b.cells));
        items.dedup_by(|a, b| a.cells == b.cells);
        let people = items.iter().filter(|i| i.tone != Tone::Muted).count();
        face::show(ui, &Face { tone: if gone.is_empty() { Tone::Info } else { Tone::Muted }, head: format!("{} can {label}", many(people as i64, "account or group").replace("account or groups", "accounts or groups")), sub: format!("besides {} of the cluster itself", items.len() - people), notes: if gone.is_empty() { vec![] } else { vec![format!("Not all of it can be read: {}.", gone.join("; "))] }, pills: vec![], facts: vec![] }, Side::None);
        ui.add_space(10.0);
        let mut l = self.op_filter(items);
        worst_first(&mut l);
        go = table(ui, &format!("Who can {label} ({})", l.len()), "through roles and bindings; groups are named as they are", &[("Who", 0.36), ("Where", 0.16), ("How", 0.34), ("Which", 0.14)], &l, 200, "No one.").or(go);
        // The other way round.
        card(ui, |ui| {
            panel(ui, "What can this one do?", "part of an account's, user's or group's name");
            filter_box(ui, &mut self.ready.who, "name", u(320.0));
        });
        let q = self.ready.who.trim().to_lowercase();
        if q.len() >= 2 {
            ui.add_space(8.0);
            let mut rules: Vec<Item> = vec![];
            for c in self.active.clone().iter().filter(|c| self.ctx_shown(c)) {
                for (kind, scoped) in [(Kind::ClusterRoleBindings, false), (Kind::RoleBindings, true)] {
                    for b in self.refs(c, kind, "").unwrap_or_default() {
                        for s in subjects(b).into_iter().filter(|s| s.to_lowercase().contains(&q)) {
                            let rr = &b["roleRef"];
                            let role = if rr["kind"] == "Role" { self.refs(c, Kind::Roles, ns_of(b)) } else { self.refs(c, Kind::ClusterRoles, "") }.unwrap_or_default().into_iter().find(|r| r["metadata"]["name"] == rr["name"]);
                            for r in role.map(|r| r["rules"].as_array().cloned().unwrap_or_default()).unwrap_or_default() {
                                let (verbs, what, t) = objects::rule_words(&r);
                                rules.push(Item::new(if t == Tone::Normal { Tone::Muted } else { t }, vec![s.clone(), verbs, what, if scoped { format!("in {}", ns_of(b)) } else { "everywhere".into() }, text(&rr["name"])]).go(Some(Go::Object(Selected { ctx: c.clone(), kind, ns: ns_of(b).into(), name: name_of(b).into() }))));
                            }
                        }
                    }
                }
            }
            worst_first(&mut rules);
            go = table(ui, &format!("May do ({})", rules.len()), "risky rules first", &[("Who", 0.24), ("Verbs", 0.2), ("On", 0.28), ("Where", 0.12), ("Role", 0.16)], &rules, 200, "No binding names it.").or(go);
        }
        go
    }

    fn waste(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        let now = kube::now_secs();
        let mut sizes: Vec<(f64, Item, Option<(Selected, Vec<String>)>)> = vec![];
        let mut idle: Vec<Item> = vec![];
        let (mut free_cpu, mut free_mem, mut free_disk) = (0.0, 0.0, 0.0);
        for c in self.active.clone().iter().filter(|c| self.ctx_shown(c)) {
            let pre = if self.active.len() > 1 { format!("{} · ", ctx_label(c)) } else { String::new() };
            let m = self.metrics.get(c);
            for k in [Kind::Deployments, Kind::StatefulSets] {
                for o in self.refs(c, k, "").unwrap_or_default().into_iter().filter(|o| self.ns_ok(ns_of(o))) {
                    let s = Selected { ctx: c.clone(), kind: k, ns: ns_of(o).into(), name: name_of(o).into() };
                    let cs = workload::pod_spec(k, o)["containers"].as_array().cloned().unwrap_or_default();
                    let req = cs.iter().map(pod::asks).fold((0.0, 0.0), |a, x| (a.0 + x.0, a.1 + x.2));
                    if req.0 <= 0.0 && req.1 <= 0.0 {
                        continue;
                    }
                    // Its busiest pod, over what Kubedog has seen.
                    let pods = self.pods_of(&s, o).unwrap_or_default();
                    let mut peak = (0.0f64, 0.0f64);
                    let mut reads = 0;
                    for p in &pods {
                        let key = (ns_of(p).to_string(), name_of(p).to_string());
                        if let Some(h) = m.and_then(|m| m.pod_hist.get(&key)) {
                            reads = reads.max(h.len());
                            for (_, a, b) in h {
                                peak = (peak.0.max(*a as f64), peak.1.max(*b as f64));
                            }
                        }
                        if let Some(x) = m.and_then(|m| m.pods.get(&key)) {
                            peak = (peak.0.max(x.0), peak.1.max(x.1));
                        }
                    }
                    if peak.1 <= 0.0 {
                        continue;
                    }
                    let (sc, sm) = suggest(peak.0, peak.1);
                    let save = (((req.0 - sc as f64).max(0.0)) * pods.len() as f64, (req.1 - sm as f64 * 1048576.0).max(0.0) * pods.len() as f64);
                    if save.0 < 100.0 && save.1 < 268435456.0 {
                        continue;
                    }
                    free_cpu += save.0;
                    free_mem += save.1;
                    let one = cs.len() == 1;
                    // A few readings say too little to act on.
                    let args = (one && reads >= 40).then(|| {
                        let ask_c = if req.0 > sc as f64 { format!("cpu={sc}m") } else { format!("cpu={}m", req.0 as i64) };
                        let ask_m = if req.1 > sm as f64 * 1048576.0 { format!("memory={sm}Mi") } else { format!("memory={}Mi", (req.1 / 1048576.0) as i64) };
                        let a: Vec<String> = ["--context", c, "-n", ns_of(o), "set", "resources", &format!("{}/{}", k.resource(), name_of(o)), "-c", cs[0]["name"].as_str().unwrap_or(""), &format!("--requests={ask_c},{ask_m}")].iter().map(|x| x.to_string()).collect();
                        (s.clone(), a)
                    });
                    sizes.push((save.1 + save.0 * 1_000_000.0, Item::new(Tone::Warning, vec![format!("{pre}{}/{}", ns_of(o), name_of(o)), format!("{} CPU, {}", hive::cores(save.0), gib(save.1)), format!("{} CPU, {}", hive::cores(req.0), gib(req.1)), format!("{} CPU, {}", hive::cores(peak.0), gib(peak.1)), if !one { "several containers".into() } else if reads < 40 { "watch longer".into() } else { format!("{sc}m, {sm}Mi") }, many(reads as i64, "reading")]).go(Some(Go::Object(s))), args));
                }
            }
            // Disks nothing mounts.
            let mut used: HashSet<(String, String)> = HashSet::new();
            for k in [Kind::Pods, Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::CronJobs, Kind::Jobs] {
                for w in self.refs(c, k, "").unwrap_or_default() {
                    for (uk, n) in workload::uses_of(workload::pod_spec(k, w)) {
                        used.insert((format!("{uk:?}|{}", ns_of(w)), n));
                    }
                    for t in w["spec"]["volumeClaimTemplates"].as_array().into_iter().flatten() {
                        // Claims made for a stateful set that's scaled down belong to it.
                        used.insert((format!("tpl|{}", ns_of(w)), format!("{}-{}-", text(&t["metadata"]["name"]), name_of(w))));
                    }
                }
            }
            let has = |k: Kind, ns: &str, n: &str| used.contains(&(format!("{k:?}|{ns}"), n.to_string()));
            let full = self.missing(c, Kind::Pods).is_none() && self.missing(c, Kind::Deployments).is_none() && self.missing(c, Kind::StatefulSets).is_none() && self.missing(c, Kind::DaemonSets).is_none() && self.missing(c, Kind::CronJobs).is_none();
            let old = |o: &Value| now - pod::time_of(&o["metadata"]["creationTimestamp"]).unwrap_or(now) > 86400;
            if full {
                for p in self.refs(c, Kind::PersistentVolumeClaims, "").unwrap_or_default().into_iter().filter(|p| self.ns_ok(ns_of(p)) && old(p)) {
                    let (ns, n) = (ns_of(p), name_of(p));
                    let tpl = used.iter().any(|u| u.0 == format!("tpl|{ns}") && n.starts_with(&u.1));
                    if !has(Kind::PersistentVolumeClaims, ns, n) && !tpl {
                        free_disk += resources::mem_bytes(p["status"]["capacity"]["storage"].as_str().unwrap_or(""));
                        idle.push(Item::new(Tone::Warning, vec![format!("{pre}{ns}/{n}"), "nothing mounts it".into(), "volume claim".into(), text(&p["status"]["capacity"]["storage"]), kube::age(p["metadata"]["creationTimestamp"].as_str().unwrap_or(""))]).go(Some(obj(c, Kind::PersistentVolumeClaims, ns, n))));
                    }
                }
                for o in self.refs(c, Kind::ConfigMaps, "").unwrap_or_default().into_iter().filter(|o| self.ns_ok(ns_of(o)) && old(o) && o["metadata"]["ownerReferences"].is_null()) {
                    let (ns, n) = (ns_of(o), name_of(o));
                    // Those the cluster and its operators keep for themselves are read by programs.
                    let system = ns.starts_with("openshift") || ns.starts_with("kube-") || matches!(n, "kube-root-ca.crt" | "openshift-service-ca.crt") || n.ends_with("-lock") || n.contains("leader") || o["metadata"]["labels"].as_object().map(|m| m.keys().any(|k| k.starts_with("grafana_") || k.contains("operator") || k.contains("argocd"))).unwrap_or(false);
                    if !system && !has(Kind::ConfigMaps, ns, n) {
                        idle.push(Item::new(Tone::Info, vec![format!("{pre}{ns}/{n}"), "no workload points at it".into(), "config map".into(), String::new(), kube::age(o["metadata"]["creationTimestamp"].as_str().unwrap_or(""))]).go(Some(obj(c, Kind::ConfigMaps, ns, n))));
                    }
                }
                // Secrets, by name only.
                let mut also: HashSet<(String, String)> = HashSet::new();
                for i in self.refs(c, Kind::Ingresses, "").unwrap_or_default() {
                    for t in i["spec"]["tls"].as_array().into_iter().flatten().filter_map(|t| t["secretName"].as_str()) {
                        also.insert((ns_of(i).into(), t.into()));
                    }
                }
                for s in self.refs(c, Kind::ServiceAccounts, "").unwrap_or_default() {
                    for k in ["secrets", "imagePullSecrets"] {
                        for x in s[k].as_array().into_iter().flatten().filter_map(|x| x["name"].as_str()) {
                            also.insert((ns_of(s).into(), x.into()));
                        }
                    }
                }
                if let Some(Ok(Value::Array(l))) = self.answer(&format!("secretnames|{c}")) {
                    for s in l.iter().filter(|s| s["owned"] != true && s["type"] == "Opaque") {
                        let (ns, n) = (text(&s["ns"]), text(&s["name"]));
                        if !self.ns_ok(&ns) || ns.starts_with("openshift") || ns.starts_with("kube-") || has(Kind::Secrets, &ns, &n) || also.contains(&(ns.clone(), n.clone())) {
                            continue;
                        }
                        idle.push(Item::new(Tone::Info, vec![format!("{pre}{ns}/{n}"), "no workload points at it".into(), "secret".into(), String::new(), String::new()]).go(Some(obj(c, Kind::Secrets, &ns, &n))));
                    }
                }
            }
            for v in self.refs(c, Kind::PersistentVolumes, "").unwrap_or_default().into_iter().filter(|v| v["status"]["phase"] == "Released") {
                free_disk += resources::mem_bytes(v["spec"]["capacity"]["storage"].as_str().unwrap_or(""));
                idle.push(Item::new(Tone::Warning, vec![format!("{pre}{}", name_of(v)), "its claim is gone, the data is kept".into(), "volume".into(), text(&v["spec"]["capacity"]["storage"]), kube::age(v["metadata"]["creationTimestamp"].as_str().unwrap_or(""))]).go(Some(obj(c, Kind::PersistentVolumes, "", name_of(v)))));
            }
            for s in self.refs(c, Kind::Services, "").unwrap_or_default().into_iter().filter(|s| self.ns_ok(ns_of(s)) && s["spec"]["type"] != "ExternalName" && s["spec"]["selector"].as_object().map(|m| !m.is_empty()).unwrap_or(false)) {
                if self.service_ready(c, ns_of(s), name_of(s)) == Some((0, 0)) {
                    idle.push(Item::new(Tone::Info, vec![format!("{pre}{}/{}", ns_of(s), name_of(s)), "no endpoints".into(), "service".into(), String::new(), kube::age(s["metadata"]["creationTimestamp"].as_str().unwrap_or(""))]).go(Some(obj(c, Kind::Services, ns_of(s), name_of(s)))));
                }
            }
            let dead = self.refs(c, Kind::ReplicaSets, "").unwrap_or_default().into_iter().filter(|r| self.ns_ok(ns_of(r)) && r["spec"]["replicas"].as_i64() == Some(0)).count();
            if dead > 200 {
                idle.push(Item::new(Tone::Info, vec![format!("{pre}{dead} old replica sets"), "kept for rolling back".into(), "replica set".into(), String::new(), String::new()]).go(Some(obj(c, Kind::ReplicaSets, "", ""))));
            }
            for j in self.refs(c, Kind::Jobs, "").unwrap_or_default().into_iter().filter(|j| self.ns_ok(ns_of(j)) && j["metadata"]["ownerReferences"].is_null() && j["spec"]["ttlSecondsAfterFinished"].is_null()) {
                if pod::time_of(&j["status"]["completionTime"]).map(|t| now - t > 7 * 86400).unwrap_or(false) {
                    idle.push(Item::new(Tone::Info, vec![format!("{pre}{}/{}", ns_of(j), name_of(j)), "done for over a week".into(), "job".into(), String::new(), kube::age(j["metadata"]["creationTimestamp"].as_str().unwrap_or(""))]).go(Some(obj(c, Kind::Jobs, ns_of(j), name_of(j)))));
                }
            }
        }
        sizes.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.1.cells.cmp(&b.1.cells)));
        let gone = self.not_read(&[Kind::Pods, Kind::Deployments, Kind::PersistentVolumeClaims, Kind::ConfigMaps]);
        face::show(ui, &Face { tone: if sizes.is_empty() && idle.is_empty() { Tone::Success } else { Tone::Info }, head: format!("{} CPU, {} memory and {} disk could be freed", hive::cores(free_cpu), gib(free_mem), gib(free_disk)), sub: "requests from the highest use Kubedog has seen, with half as much again on top: the longer it's open, the better".into(), notes: if gone.is_empty() { vec![] } else { vec![format!("Not looked at: {}.", gone.join("; "))] }, pills: vec![], facts: vec![Fact::new("Ask for too much", sizes.len().to_string()), Fact::new("Seem unused", idle.len().to_string())] }, Side::None);
        ui.add_space(10.0);
        // Requests, with a button each.
        let q = self.search.to_lowercase();
        let mut act: Option<(Selected, Vec<String>, String)> = None;
        card(ui, |ui| {
            panel(ui, &format!("Ask for more than they use ({})", sizes.len()), "after 40 readings (about 10 minutes) new requests can be applied, with a confirmation; pods are replaced one by one, and Git may put the old ones back");
            ui.spacing_mut().item_spacing.y = 0.0;
            if sizes.is_empty() {
                said(ui, "None, or no usage read yet.", TEXT_SUBTLE());
            }
            for (_, it, args) in sizes.iter().filter(|s| q.is_empty() || s.1.cells[0].to_lowercase().contains(&q)).take(60) {
                let (r, resp) = dash::line(ui, u(32.0), true);
                let w = r.width() - u(190.0);
                for (i, (x, wd)) in [(0.0, 0.32), (0.33, 0.2), (0.54, 0.17), (0.72, 0.15), (0.88, 0.12)].iter().enumerate() {
                    let pre = ["", "frees ", "asks ", "peak ", ""][i];
                    pg::label_at(ui, ui.painter(), egui::pos2(r.left() + w * x, r.center().y), &format!("{pre}{}", it.cells[i]), if i == 0 { 13.0 } else { 12.0 }, if i == 0 { PRIMARY_TEXT() } else { TEXT_MUTED() }, w * wd - 8.0);
                }
                if resp.on_hover_text(format!("{}\nfrom {}", it.cells[0], it.cells[5])).clicked() {
                    go = it.go.clone();
                }
                if let Some((s, a)) = args {
                    let b = egui::Rect::from_min_size(egui::pos2(r.right() - u(184.0), r.top() + 3.0), egui::vec2(u(184.0), u(26.0)));
                    let mut ui2 = ui.new_child(egui::UiBuilder::new().max_rect(b).layout(Layout::right_to_left(Align::Center)));
                    if button(&mut ui2, "Apply", false, false) {
                        act = Some((s.clone(), a.clone(), it.cells[4].clone()));
                    }
                    if button(&mut ui2, "Copy", false, false) {
                        ui2.ctx().copy_text(format!("kubectl {}", a.iter().map(|x| if x.contains(' ') { sh_quote(x) } else { x.clone() }).collect::<Vec<_>>().join(" ")));
                    }
                }
            }
        });
        if let Some((s, a, w)) = act {
            let body = format!("Set the requests of {} “{}” to {w}? Its pods are replaced.", s.kind.singular(), s.name);
            self.request(Action::Run { sel: s.clone(), args: a, what: format!("New requests for {}", s.name) }, "New requests".into(), body, "Apply", false);
        }
        ui.add_space(12.0);
        let mut idle = self.op_filter(idle);
        worst_first(&mut idle);
        go = table(ui, &format!("Seem unused ({})", idle.len()), "look before you delete: programs may read them through the API", &[("What", 0.42), ("Why", 0.26), ("Kind", 0.14), ("Size", 0.09), ("Age", 0.09)], &idle, 200, "None.").or(go);
        go
    }

    fn security(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        let mut by: HashMap<(String, String, String), (Vec<(u32, String)>, usize, Selected)> = HashMap::new();
        let mut open_ns: Vec<Item> = vec![];
        for c in self.active.clone().iter().filter(|c| self.ctx_shown(c)) {
            let pre = if self.active.len() > 1 { format!("{} · ", ctx_label(c)) } else { String::new() };
            let mut ns_pods: HashMap<&str, usize> = HashMap::new();
            for p in self.refs(c, Kind::Pods, "").unwrap_or_default().into_iter().filter(|p| self.ns_ok(ns_of(p)) && p["status"]["phase"] == "Running") {
                *ns_pods.entry(ns_of(p)).or_default() += 1;
                let (k, n) = owner(p);
                let (kind, n) = match k.as_str() { "ReplicaSet" => (Kind::Deployments, n.rsplit_once('-').map(|x| x.0.to_string()).unwrap_or(n)), _ => match workload::kind_named(&k) { Some(k) => (k, n), None => (Kind::Pods, name_of(p).to_string()) } };
                let e = by.entry((c.clone(), ns_of(p).to_string(), format!("{kind:?}|{n}"))).or_insert_with(|| (unsafe_bits(p), 0, Selected { ctx: c.clone(), kind, ns: ns_of(p).into(), name: n }));
                e.1 += 1;
            }
            if let Some(l) = self.refs(c, Kind::NetworkPolicies, "") {
                let with: HashSet<&str> = l.iter().map(|p| ns_of(p)).collect();
                for (ns, n) in ns_pods {
                    if !with.contains(ns) && !ns.starts_with("openshift") && !ns.starts_with("kube-") {
                        open_ns.push(Item::new(Tone::Warning, vec![format!("{pre}{ns}"), "no network policy: every pod may reach its pods".into(), many(n as i64, "pod")]).go(Some(obj(c, Kind::Namespaces, "", ns))));
                    }
                }
            }
        }
        let many_ctx = self.active.len() > 1;
        let mut list: Vec<(u32, Item)> = by
            .into_iter()
            .filter(|(_, v)| !v.0.is_empty())
            .map(|((c, ns, _), (bits, n, s))| {
                let score: u32 = bits.iter().map(|b| b.0).sum();
                let top = bits.iter().map(|b| b.0).max().unwrap_or(0);
                let system = ns.starts_with("openshift") || ns.starts_with("kube-");
                let t = if system { Tone::Muted } else if top >= 7 { Tone::Danger } else if top >= 3 { Tone::Warning } else { Tone::Info };
                let mut words = bits;
                words.sort_by(|a, b| b.0.cmp(&a.0));
                let w: Vec<String> = words.iter().map(|b| b.1.clone()).collect();
                (score, Item::new(t, vec![format!("{}{ns}/{}", if many_ctx { format!("{} · ", ctx_label(&c)) } else { String::new() }, s.name), format!("{score}"), w.iter().take(3).cloned().collect::<Vec<_>>().join(", "), s.kind.singular().into(), many(n as i64, "pod")]).tip(w.join("\n")).go(Some(Go::Object(s))))
            })
            .collect();
        by_points(&mut list);
        let risky = list.iter().filter(|l| l.1.tone == Tone::Danger).count();
        let warn = list.iter().filter(|l| l.1.tone == Tone::Warning).count();
        let gone = self.not_read(&[Kind::Pods, Kind::NetworkPolicies]);
        face::show(ui, &Face { tone: if risky > 0 { Tone::Danger } else if warn + open_ns.len() > 0 { Tone::Warning } else { Tone::Success }, head: if risky > 0 { format!("{} with strong rights on their node", many(risky as i64, "workload")) } else if warn > 0 { format!("{} to look at", many(warn as i64, "workload")) } else { "Nothing that stands out".into() }, sub: "the cluster's own workloads are listed last".into(), notes: if gone.is_empty() { vec![] } else { vec![format!("Not looked at: {}.", gone.join("; "))] }, pills: vec![], facts: vec![Fact::new("Namespaces without a policy", open_ns.len().to_string())] }, Side::None);
        ui.add_space(10.0);
        self.bad_switch(ui);
        let mut l = self.op_filter(list.into_iter().map(|x| x.1).collect());
        // Stable: within a colour the highest score stays first.
        l.sort_by_key(|i| match i.tone { Tone::Danger => 0, Tone::Warning => 1, Tone::Info => 2, _ => 3 });
        go = table(ui, &format!("Workloads ({})", l.len()), "by what could go wrong; hover for all of it", &[("Workload", 0.32), ("Points", 0.07), ("Why", 0.41), ("Kind", 0.1), ("", 0.1)], &l, 200, "None.").or(go);
        let mut o = self.op_filter(open_ns);
        o.sort_by(|a, b| a.cells.cmp(&b.cells));
        go = table(ui, &format!("Open namespaces ({})", o.len()), "", &[("Namespace", 0.3), ("", 0.5), ("", 0.2)], &o, 100, "None.").or(go);
        go
    }
}

/// The most points first, and those with as many by name: gathered from a map, they would otherwise be in
/// another order each time the page is drawn.
fn by_points(l: &mut [(u32, Item)]) {
    l.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cells.cmp(&b.1.cells)));
}

/// The API server's own counters of old APIs that were asked for since it started.
pub(super) fn old_apis(metrics: &str) -> Vec<Value> {
    metrics
        .lines()
        .filter(|l| l.starts_with("apiserver_requested_deprecated_apis{"))
        .filter_map(|l| {
            let get = |k: &str| l.split(&format!("{k}=\"")).nth(1).and_then(|x| x.split('"').next()).unwrap_or("").to_string();
            let g = get("group");
            Some(serde_json::json!({"resource": get("resource"), "version": if g.is_empty() { get("version") } else { format!("{g}/{}", get("version")) }, "removed": get("removed_release")}))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node(n: &str, mem: &str) -> Value {
        json!({"metadata": {"name": n, "labels": {}}, "spec": {}, "status": {"allocatable": {"cpu": "4", "memory": mem, "pods": "110"}, "conditions": [{"type": "Ready", "status": "True"}]}})
    }
    fn pod_on(n: &str, name: &str, owner: &str, mem: &str) -> Value {
        json!({"metadata": {"name": name, "namespace": "shop", "uid": name, "labels": {"app": owner}, "ownerReferences": if owner.is_empty() { json!(null) } else { json!([{"kind": if owner == "ds" { "DaemonSet" } else { "ReplicaSet" }, "name": format!("{owner}-abc")}]) }}, "spec": {"nodeName": n, "containers": [{"name": "c", "resources": {"requests": {"memory": mem}}}]}, "status": {"phase": "Running"}})
    }

    #[test]
    fn rehearsals() {
        let (a, b) = (node("a", "8Gi"), node("b", "4Gi"));
        let pods = [pod_on("a", "web-1", "web", "1Gi"), pod_on("a", "big-1", "big", "6Gi"), pod_on("a", "ds-1", "ds", "1Gi"), pod_on("a", "bare", "", "1Gi"), pod_on("b", "web-2", "web", "1Gi")];
        let p: Vec<&Value> = pods.iter().collect();
        let pdb = json!({"metadata": {"name": "web", "namespace": "shop"}, "spec": {"selector": {"matchLabels": {"app": "web"}}}, "status": {"disruptionsAllowed": 0}});
        let plan = rehearse(&HashSet::from(["a".to_string()]), &[&a, &b], &p, &[&pdb]);
        assert_eq!(plan.stay, 1);
        assert_eq!(plan.lost, vec!["shop/bare"]);
        assert_eq!(plan.down, vec!["shop/big"]);
        assert!(plan.waits[0].contains("allows none"));
        let of = |n: &str| plan.moves.iter().find(|m| m.1 == n).unwrap().2.clone();
        assert!(of("big-1").is_err());
        assert_eq!(of("web-1"), Ok("b".to_string()));
    }

    #[test]
    fn rights() {
        let r = |v: Value| lets(&v, "get", "", "secrets");
        assert_eq!(r(json!({"verbs": ["get"], "apiGroups": [""], "resources": ["secrets"]})), Some(vec![]));
        assert_eq!(r(json!({"verbs": ["*"], "apiGroups": ["*"], "resources": ["*"]})), Some(vec![]));
        assert_eq!(r(json!({"verbs": ["get"], "apiGroups": [""], "resources": ["secrets"], "resourceNames": ["one"]})), Some(vec!["one".into()]));
        assert_eq!(r(json!({"verbs": ["list"], "apiGroups": [""], "resources": ["secrets"]})), None);
        assert_eq!(r(json!({"verbs": ["get"], "apiGroups": ["apps"], "resources": ["*"]})), None);
        assert_eq!(subjects(&json!({"metadata": {"namespace": "n"}, "subjects": [{"kind": "ServiceAccount", "name": "a"}, {"kind": "Group", "name": "g"}]})), vec!["service account n/a", "group g"]);
        assert!(own("group system:masters") && !own("user ann"));
    }

    #[test]
    fn workloads_keep_their_place() {
        // From a map like on the page, many times: always the same order.
        let order = || {
            let m: HashMap<String, u32> = (0..60).map(|i| (format!("shop/app-{i:02}"), i % 3)).collect();
            let mut l: Vec<(u32, Item)> = m.into_iter().map(|(n, p)| (p, Item::new(Tone::Warning, vec![n, p.to_string()]))).collect();
            by_points(&mut l);
            l.into_iter().map(|x| x.1.cells[0].clone()).collect::<Vec<_>>()
        };
        let first = order();
        assert_eq!(&first[..2], &["shop/app-02".to_string(), "shop/app-05".into()]);
        assert!((0..20).all(|_| order() == first));
    }

    #[test]
    fn unsafe_and_sizes() {
        let bits = unsafe_bits(&json!({"spec": {"hostPID": true, "volumes": [{"hostPath": {"path": "/"}}], "containers": [{"name": "c", "image": "web", "securityContext": {"privileged": true, "capabilities": {"add": ["SYS_ADMIN"]}}}]}}));
        assert!(bits.iter().map(|b| b.0).sum::<u32>() >= 34 && bits.iter().any(|b| b.1 == "c is privileged") && bits.iter().any(|b| b.1.contains("latest")));
        let good = unsafe_bits(&json!({"spec": {"containers": [{"name": "c", "image": "web:1", "resources": {"limits": {"memory": "1Gi"}}, "securityContext": {"runAsNonRoot": true, "allowPrivilegeEscalation": false}}]}}));
        assert!(good.is_empty(), "{good:?}");
        assert_eq!(suggest(33.0, 100.0 * 1048576.0), (50, 160));
        assert_eq!(suggest(0.5, 1.0), (10, 32));
        let m = old_apis("x 1\napiserver_requested_deprecated_apis{group=\"policy\",removed_release=\"1.25\",resource=\"podsecuritypolicies\",subresource=\"\",version=\"v1beta1\"} 1\n");
        assert_eq!((m[0]["removed"].as_str(), m[0]["version"].as_str()), (Some("1.25"), Some("policy/v1beta1")));
    }
}
