//! Network Lab: the path as it should be, from what the cluster's objects say. Every step says yes, no,
//! maybe or not known. What can't be read or isn't understood never counts as a yes.

use super::netlab::{self, ANP, BANP, CALICO, CALICO_ALL, CILIUM, CILIUM_ALL, CUDN, EGRESS_FW, EGRESS_IP, EGRESS_SVC, ISTIO, NETS, UDN};
use super::ops::{ns_of, obj, text};
use super::podnet::selector_matches;
use super::podxray::Go;
use super::work::name_of;
use super::*;
use std::net::IpAddr;

/// What a step says.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(super) enum Say {
    Yes,
    No,
    Maybe,
    Unknown,
    /// Only to know.
    Info,
}

impl Say {
    pub fn word(self) -> &'static str {
        match self {
            Say::Yes => "yes",
            Say::No => "no",
            Say::Maybe => "maybe",
            Say::Unknown => "not known",
            Say::Info => "",
        }
    }
    pub fn tone(self) -> Tone {
        match self {
            Say::Yes => Tone::Success,
            Say::No => Tone::Danger,
            Say::Maybe => Tone::Warning,
            _ => Tone::Muted,
        }
    }
}

#[derive(Clone)]
pub(super) struct PathStep {
    pub say: Say,
    pub text: String,
    pub go: Option<Go>,
}

/// What the steps add up to.
pub(super) fn sum(l: &[PathStep]) -> Say {
    [Say::No, Say::Maybe, Say::Unknown].into_iter().find(|s| l.iter().any(|x| x.say == *s)).unwrap_or(Say::Yes)
}

/// One end of a path.
#[derive(Clone, PartialEq, Debug)]
pub(super) enum End {
    /// From or to somewhere outside, not told where.
    Outside,
    Object(Selected),
    /// A name or an address outside the cluster.
    Address(String),
}

/// "5432", "53/udp".
pub(super) fn read_port(t: &str) -> Option<(i64, &'static str)> {
    let (n, p) = t.trim().split_once('/').unwrap_or((t.trim(), "tcp"));
    let proto = match p.to_lowercase().as_str() {
        "tcp" => "TCP",
        "udp" => "UDP",
        "sctp" => "SCTP",
        _ => return None,
    };
    n.parse::<i64>().ok().filter(|n| (1..=65535).contains(n)).map(|n| (n, proto))
}

/// The other side of a connection, as policies see it.
#[derive(Clone, Default)]
pub(super) struct Other {
    pub ns: String,
    pub ns_labels: Value,
    pub labels: Value,
    pub ip: Option<IpAddr>,
    /// A pod on the pod network: policies know it by its labels.
    pub pod: bool,
    /// On the node's own network: the labels of the node.
    pub node: Option<Value>,
}

pub(super) struct Port<'a> {
    pub n: i64,
    pub proto: &'a str,
    /// The names of the pod's ports.
    pub names: &'a [(String, i64)],
}

fn any(sel: &Value) -> bool {
    sel.as_object().map(|m| m.is_empty()).unwrap_or(false)
}

pub(super) fn meets(sel: &Value, labels: &Value) -> bool {
    any(sel) || (sel.is_object() && selector_matches(sel, labels))
}

/// Is an address in a range?
pub(super) fn in_range(cidr: &str, ip: IpAddr) -> Option<bool> {
    let (net, bits) = cidr.split_once('/')?;
    let bits: u32 = bits.parse().ok()?;
    match (net.parse::<IpAddr>().ok()?, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) if bits <= 32 => Some(bits == 0 || (u32::from(n) ^ u32::from(i)) >> (32 - bits) == 0),
        (IpAddr::V6(n), IpAddr::V6(i)) if bits <= 128 => Some(bits == 0 || (u128::from(n) ^ u128::from(i)) >> (128 - bits) == 0),
        (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => Some(false),
        _ => None,
    }
}

// ---------- network policies ----------

/// One side of a network policy's rule against who's there. None: can't be told.
fn peer(p: &Value, policy_ns: &str, o: &Other) -> Option<bool> {
    if p["ipBlock"].is_object() {
        let b = &p["ipBlock"];
        let everyone = b["cidr"] == "0.0.0.0/0" && !b["except"].is_array() && !o.pod && o.node.is_none();
        let Some(ip) = o.ip else { return everyone.then_some(true) };
        let cut = b["except"].as_array().into_iter().flatten().any(|x| in_range(x.as_str().unwrap_or(""), ip) == Some(true));
        let inside = in_range(b["cidr"].as_str().unwrap_or(""), ip)? && !cut;
        // Whether ranges also count for pods (and nodes) differs between networks.
        return if inside && (o.pod || o.node.is_some()) { None } else { Some(inside) };
    }
    if o.node.is_some() && !o.pod {
        // Pods on the node's own network: some networks can tell them, most can't.
        return None;
    }
    if !o.pod {
        return Some(false);
    }
    let ns_ok = if p["namespaceSelector"].is_null() { o.ns == policy_ns } else { meets(&p["namespaceSelector"], &o.ns_labels) };
    let pod_ok = p["podSelector"].is_null() || meets(&p["podSelector"], &o.labels);
    Some(ns_ok && pod_ok)
}

/// Does a rule's port list let a port through?
fn port_ok(r: &Value, port: &Port) -> bool {
    match r["ports"].as_array().filter(|a| !a.is_empty()) {
        None => true,
        Some(l) => l.iter().any(|p| {
            if p["protocol"].as_str().unwrap_or("TCP") != port.proto {
                return false;
            }
            match (&p["port"], p["endPort"].as_i64()) {
                (Value::Null, _) => true,
                (Value::Number(n), Some(e)) => n.as_i64().map(|n| n <= port.n && port.n <= e).unwrap_or(false),
                (Value::Number(n), None) => n.as_i64() == Some(port.n),
                (Value::String(s), _) => port.names.iter().any(|(n, p)| n == s && *p == port.n),
                _ => false,
            }
        }),
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(super) enum Gate {
    /// No policy is about this pod in this direction.
    Open,
    /// Let through, by these.
    Allowed(Vec<String>),
    /// Stopped: these are about it and none lets it through.
    Blocked(Vec<String>),
    /// Depends on addresses.
    Unsure(Vec<String>),
}

/// What the network policies of a pod's namespace say about one way.
pub(super) fn gate(policies: &[&Value], inward: bool, labels: &Value, o: &Other, port: &Port) -> Gate {
    let (key, side, ty) = if inward { ("ingress", "from", "Ingress") } else { ("egress", "to", "Egress") };
    let mut about = vec![];
    let mut yes = vec![];
    let mut maybe = vec![];
    for p in policies {
        let spec = &p["spec"];
        let on = match spec["policyTypes"].as_array() {
            Some(t) => t.iter().any(|x| x == ty),
            None => inward || spec[key].is_array(),
        };
        let all = spec["podSelector"].as_object().map(|m| m.is_empty()).unwrap_or(true);
        if !on || !(all || meets(&spec["podSelector"], labels)) {
            continue;
        }
        let name = name_of(p).to_string();
        about.push(name.clone());
        for r in spec[key].as_array().into_iter().flatten().filter(|r| port_ok(r, port)) {
            match r[side].as_array().filter(|a| !a.is_empty()) {
                None => yes.push(name.clone()),
                Some(l) => {
                    let m: Vec<Option<bool>> = l.iter().map(|x| peer(x, ns_of(p), o)).collect();
                    if m.contains(&Some(true)) {
                        yes.push(name.clone());
                    } else if m.contains(&None) {
                        maybe.push(name.clone());
                    }
                }
            }
        }
    }
    yes.dedup();
    maybe.dedup();
    if about.is_empty() {
        Gate::Open
    } else if !yes.is_empty() {
        Gate::Allowed(yes)
    } else if !maybe.is_empty() {
        Gate::Unsure(maybe)
    } else {
        Gate::Blocked(about)
    }
}

// ---------- admin network policies ----------

#[derive(Debug, PartialEq, Clone)]
pub(super) enum Admin {
    /// None is about it.
    Nothing,
    Allow(String),
    Deny(String),
    /// Left to network policies.
    Pass(String),
    /// It depends on something that can't be told from here.
    Unsure(String),
}

/// One side of an admin policy's rule. None: can't be told.
fn admin_peer(p: &Value, o: &Other) -> Option<bool> {
    if p["namespaces"].is_object() {
        return Some(o.pod && meets(&p["namespaces"], &o.ns_labels));
    }
    if p["pods"].is_object() {
        return Some(o.pod && meets(&p["pods"]["namespaceSelector"], &o.ns_labels) && meets(&p["pods"]["podSelector"], &o.labels));
    }
    if p["nodes"].is_object() {
        return match &o.node {
            Some(l) => Some(meets(&p["nodes"], l)),
            None if o.pod => Some(false),
            // An address outside could still be a node's.
            None => o.ip.map(|_| false),
        };
    }
    if let Some(l) = p["networks"].as_array() {
        let Some(ip) = o.ip else { return (!o.pod && o.node.is_none() && l.iter().any(|n| n == "0.0.0.0/0")).then_some(true) };
        return Some(l.iter().any(|n| in_range(n.as_str().unwrap_or(""), ip) == Some(true)));
    }
    if p["domainNames"].is_array() {
        return if o.pod { Some(false) } else { None };
    }
    // Something newer than this.
    None
}

fn admin_port(r: &Value, port: &Port) -> bool {
    match r["ports"].as_array().filter(|a| !a.is_empty()) {
        None => true,
        Some(l) => l.iter().any(|p| {
            let n = &p["portNumber"];
            let g = &p["portRange"];
            if n.is_object() {
                n["port"].as_i64() == Some(port.n) && n["protocol"].as_str().unwrap_or("TCP") == port.proto
            } else if g.is_object() {
                g["start"].as_i64().unwrap_or(0) <= port.n && port.n <= g["end"].as_i64().unwrap_or(0) && g["protocol"].as_str().unwrap_or("TCP") == port.proto
            } else {
                p["namedPort"].as_str().map(|s| port.names.iter().any(|x| x.0 == s && x.1 == port.n)).unwrap_or(false)
            }
        }),
    }
}

/// What admin policies (or the baseline one) say: by priority, the first rule that's about it decides.
pub(super) fn admin(list: &[Value], inward: bool, ns_labels: &Value, labels: &Value, o: &Other, port: &Port) -> Admin {
    let (key, side) = if inward { ("ingress", "from") } else { ("egress", "to") };
    let mut l: Vec<&Value> = list.iter().collect();
    l.sort_by_key(|p| (p["spec"]["priority"].as_i64().unwrap_or(0), name_of(p).to_string()));
    // Rules before it that might have been about it: (action, whose).
    let mut maybe: Vec<(String, String)> = vec![];
    for p in l {
        let s = &p["spec"]["subject"];
        let mine = if s["pods"].is_object() { meets(&s["pods"]["namespaceSelector"], ns_labels) && meets(&s["pods"]["podSelector"], labels) } else { s["namespaces"].is_object() && meets(&s["namespaces"], ns_labels) };
        if !mine {
            continue;
        }
        for r in p["spec"][key].as_array().into_iter().flatten().filter(|r| admin_port(r, port)) {
            let who = match r["name"].as_str().filter(|n| !n.is_empty()) {
                Some(n) => format!("{} (rule {n})", name_of(p)),
                None => name_of(p).to_string(),
            };
            let m: Vec<Option<bool>> = r[side].as_array().into_iter().flatten().map(|x| admin_peer(x, o)).collect();
            let act = text(&r["action"]);
            if m.contains(&Some(true)) {
                if let Some(x) = maybe.iter().find(|x| x.0 != act) {
                    return Admin::Unsure(x.1.clone());
                }
                return match act.as_str() {
                    "Allow" => Admin::Allow(who),
                    "Deny" => Admin::Deny(who),
                    "Pass" => Admin::Pass(who),
                    _ => Admin::Unsure(who),
                };
            } else if m.contains(&None) {
                maybe.push((act, who));
            }
        }
    }
    match maybe.into_iter().find(|x| x.0 != "Pass") {
        Some(x) => Admin::Unsure(x.1),
        None => Admin::Nothing,
    }
}

/// Admin policies, then network policies, then the baseline: what's said, why, and by what (kind, name).
/// The lists are `None` when they couldn't be read (with why).
pub(super) fn tiers(adm: Result<&[Value], String>, nps: Option<&[&Value]>, base: Result<&[Value], String>, inward: bool, me: (&Value, &Value), o: &Other, port: &Port) -> (Say, String, Option<(&'static str, String)>) {
    let who = if inward { "come in" } else { "leave" };
    let (ns_labels, labels) = me;
    let first = match &adm {
        Ok(l) => admin(l, inward, ns_labels, labels, o, port),
        Err(_) => Admin::Nothing,
    };
    let at = |n: &str| n.split(' ').next().unwrap_or(n).to_string();
    match &first {
        Admin::Allow(n) => return (Say::Yes, format!("May {who}: let through by admin policy {n}; network policies aren't asked"), Some(("anp", at(n)))),
        Admin::Deny(n) => return (Say::No, format!("May not {who}: admin policy {n} forbids it, whatever network policies say"), Some(("anp", at(n)))),
        Admin::Unsure(n) => return (Say::Maybe, format!("Whether it may {who} depends on admin policy {n}, on something that can't be told from here"), Some(("anp", at(n)))),
        _ => {}
    }
    let passed = if let Admin::Pass(n) = &first { format!(" (admin policy {n} leaves it to these)") } else { String::new() };
    let Some(nps) = nps else {
        return (Say::Unknown, format!("Whether it may {who} isn't known: the network policies can't be read"), None);
    };
    let g = gate(nps, inward, labels, o, port);
    // An admin policy that can't be seen goes before all of it.
    let hidden = adm.as_ref().err().map(|e| format!("; admin policies go before this and {e}"));
    let (say, t, by) = match g {
        Gate::Allowed(v) => (Say::Yes, format!("May {who}: let through by {}{passed}", v.join(", ")), v.first().map(|n| ("np", n.clone()))),
        Gate::Blocked(v) => (Say::No, format!("May not {who}: {} and none lets it through{passed}", if v.len() == 1 { format!("policy {} is about it", v[0]) } else { format!("policies {} are about it", v.join(", ")) }), v.first().map(|n| ("np", n.clone()))),
        Gate::Unsure(v) => (Say::Maybe, format!("Whether it may {who} depends on {}: on addresses, or on how this network sees what comes from a node{passed}", v.join(", ")), v.first().map(|n| ("np", n.clone()))),
        Gate::Open => match &base {
            Err(e) => (Say::Unknown, format!("No network policy limits what may {who}, but the baseline admin policy decides then, and {e}"), None),
            Ok(l) => match admin(l, inward, ns_labels, labels, o, port) {
                Admin::Deny(n) => (Say::No, format!("May not {who}: no network policy is about it, and the baseline admin policy {n} forbids it"), Some(("banp", at(&n)))),
                Admin::Allow(n) => (Say::Yes, format!("May {who}: let through by the baseline admin policy {n}"), Some(("banp", at(&n)))),
                Admin::Unsure(n) => (Say::Maybe, format!("Whether it may {who} depends on the baseline admin policy {n}, on something that can't be told from here"), Some(("banp", at(&n)))),
                _ => (Say::Yes, format!("No policy limits what may {who}"), None),
            },
        },
    };
    match hidden {
        Some(h) if say == Say::Yes => (Say::Unknown, format!("{t}{h}"), by),
        Some(h) if say == Say::No => (Say::Maybe, format!("{t}{h}"), by),
        _ => (say, t, by),
    }
}

// ---------- out of the cluster ----------

/// What an egress firewall says about an address: the first rule about it decides; none: it's let through.
/// (what it says, why)
pub(super) fn egress_firewall(fw: &Value, host: &str, port: i64, proto: &str, nodes: &[&Value]) -> (Say, String) {
    let ip = host.parse::<IpAddr>().ok();
    let mut maybe: Vec<(String, String)> = vec![];
    for (i, r) in fw["spec"]["egress"].as_array().into_iter().flatten().enumerate() {
        let ports = r["ports"].as_array().filter(|a| !a.is_empty());
        if !ports.map(|l| l.iter().any(|p| p["port"].as_i64() == Some(port) && p["protocol"].as_str().unwrap_or("TCP") == proto)).unwrap_or(true) {
            continue;
        }
        let to = &r["to"];
        let (m, what): (Option<bool>, String) = if let Some(c) = to["cidrSelector"].as_str() {
            (if c == "0.0.0.0/0" && ip.is_none() { Some(true) } else { ip.and_then(|i| in_range(c, i)) }, c.to_string())
        } else if let Some(d) = to["dnsName"].as_str() {
            let (d, h) = (d.trim_end_matches('.').to_lowercase(), host.trim_end_matches('.').to_lowercase());
            let hit = match d.strip_prefix("*.") {
                Some(rest) => h.split_once('.').map(|x| x.1 == rest).unwrap_or(false),
                None => d == h,
            };
            // Another name can have the same address.
            (if ip.is_some() { None } else if hit { Some(true) } else { None }, d)
        } else if to["nodeSelector"].is_object() {
            let hit = nodes.iter().any(|n| meets(&to["nodeSelector"], &n["metadata"]["labels"]) && n["status"]["addresses"].as_array().into_iter().flatten().any(|a| a["address"].as_str() == Some(host)));
            (if ip.is_some() { Some(hit) } else { None }, "some nodes".into())
        } else {
            (None, "a rule that isn't known here".into())
        };
        let act = text(&r["type"]);
        match m {
            Some(true) => {
                if let Some(x) = maybe.iter().find(|x| x.0 != act) {
                    return (Say::Maybe, format!("depends on whether {host} falls under rule {}", x.1));
                }
                return if act == "Deny" { (Say::No, format!("rule {} ({what}) forbids it", i + 1)) } else { (Say::Yes, format!("rule {} ({what}) lets it through", i + 1)) };
            }
            None => maybe.push((act, format!("{} ({what})", i + 1))),
            Some(false) => {}
        }
    }
    match maybe.iter().find(|x| x.0 == "Deny") {
        Some(x) => (Say::Maybe, format!("depends on whether {host} falls under rule {}", x.1)),
        None => (Say::Yes, "no rule is about it".into()),
    }
}

// ---------- user-defined networks ----------

/// The network of its own that a namespace's pods have first, if any.
pub(super) fn own_network(udn: &[Value], cudn: &[Value], ns: &str, ns_labels: &Value) -> Option<String> {
    let first = |s: &Value| ["layer2", "layer3"].iter().any(|l| s[*l]["role"] == "Primary");
    if let Some(u) = udn.iter().find(|u| ns_of(u) == ns && first(&u["spec"])) {
        return Some(format!("{ns}/{}", name_of(u)));
    }
    cudn.iter().find(|u| first(&u["spec"]["network"]) && meets(&u["spec"]["namespaceSelector"], ns_labels)).map(|u| name_of(u).to_string())
}

/// The second network cards a pod asks for.
fn extra_cards(p: &Value) -> Option<String> {
    let t = p["metadata"]["annotations"]["k8s.v1.cni.cncf.io/networks"].as_str().filter(|t| !t.trim().is_empty())?;
    let v: Option<Vec<String>> = serde_json::from_str::<Value>(t).ok().and_then(|v| v.as_array().map(|a| a.iter().map(|x| text(&x["name"])).collect()));
    Some(truncate(&v.map(|v| v.join(", ")).unwrap_or(t.to_string()), 80))
}

fn ports_of(p: &Value) -> Vec<(String, i64)> {
    p["spec"]["containers"].as_array().into_iter().flatten().flat_map(|c| c["ports"].as_array().into_iter().flatten()).filter_map(|p| Some((p["name"].as_str()?.to_string(), p["containerPort"].as_i64()?))).collect()
}

/// How pods see what comes in over a node: as the node itself, unless the client's address is kept.
fn via_node(svc: &Value) -> Other {
    if svc["spec"]["externalTrafficPolicy"] == "Local" { Other::default() } else { Other { node: Some(Value::Null), ..Default::default() } }
}

fn ready(p: &Value) -> bool {
    pod::cond(p, "Ready").map(|c| c["status"] == "True").unwrap_or(false)
}

/// A path, step by step, and the pods at its ends.
#[derive(Clone, Default)]
pub(super) struct Path {
    pub steps: Vec<PathStep>,
    pub from_pod: Option<Value>,
    /// What to connect to from the pod: host and port.
    pub host: String,
    /// The port of the pod at the other end.
    pub target: i64,
}

impl Path {
    fn add(&mut self, say: Say, text: impl Into<String>, go: Option<Go>) {
        self.steps.push(PathStep { say, text: text.into(), go });
    }
}

impl KubedogApp {
    /// What else is read for a path.
    pub(super) fn refresh_path(&mut self, force: bool) {
        self.sync_crds();
        self.read_custom(NETS, 60, force);
        for d in netlab::DECIDERS {
            self.read_custom(d.0, 60, force);
        }
        self.ask_routes(force);
    }

    pub(super) fn path_kinds() -> Vec<Kind> {
        vec![Kind::Pods, Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::ReplicaSets, Kind::Services, Kind::EndpointSlices, Kind::NetworkPolicies, Kind::Namespaces, Kind::Nodes, Kind::Ingresses]
    }

    fn ns_labels(&self, ctx: &str, ns: &str) -> Value {
        self.refs(ctx, Kind::Namespaces, "").unwrap_or_default().into_iter().find(|o| name_of(o) == ns).map(|o| o["metadata"]["labels"].clone()).unwrap_or_else(|| serde_json::json!({"kubernetes.io/metadata.name": ns}))
    }

    fn as_other(&self, ctx: &str, p: &Value) -> Other {
        let host = p["spec"]["hostNetwork"] == true;
        let node = p["spec"]["nodeName"].as_str().unwrap_or("");
        let node_labels = || self.refs(ctx, Kind::Nodes, "").unwrap_or_default().into_iter().find(|n| name_of(n) == node).map(|n| n["metadata"]["labels"].clone()).unwrap_or_default();
        Other { ns: ns_of(p).into(), ns_labels: self.ns_labels(ctx, ns_of(p)), labels: p["metadata"]["labels"].clone(), ip: p["status"]["podIP"].as_str().and_then(|i| i.parse().ok()), pod: !host, node: host.then(node_labels) }
    }

    /// What the policies say about one pod and one way, as steps.
    fn policy_steps(&self, out: &mut Path, ctx: &str, inward: bool, pod: &Value, o: &Other, port: &Port, net: Option<&str>) {
        let ns = ns_of(pod).to_string();
        if pod["spec"]["hostNetwork"] == true {
            out.add(Say::Info, format!("{} uses its node's own network: policies aren't about it", name_of(pod)), None);
            return;
        }
        let labels = pod["metadata"]["labels"].clone();
        let nl = self.ns_labels(ctx, &ns);
        let nps = self.refs(ctx, Kind::NetworkPolicies, &ns);
        let (say, t, by) = tiers(self.kind_known(ctx, ANP), nps.as_deref(), self.kind_known(ctx, BANP), inward, (&nl, &labels), o, port);
        let go = by.and_then(|(k, n)| match k {
            "np" => Some(obj(ctx, Kind::NetworkPolicies, &ns, &n)),
            k => {
                let key = if k == "anp" { ANP } else { BANP };
                self.kind_known(ctx, key).unwrap_or_default().iter().find(|x| name_of(x) == n).and_then(|x| self.custom_go(ctx, key, x))
            }
        });
        // A network that doesn't keep to policies lets everything through.
        match netlab::keeps_policies(net) {
            Some(false) if say != Say::Yes => out.add(Say::Yes, format!("In {ns}: {t}. But {} doesn't keep to policies, so it isn't stopped", net.unwrap_or("this network")), go),
            None if say == Say::No => out.add(Say::Maybe, format!("In {ns}: {t}. Whether this cluster's network keeps to policies isn't known"), go),
            _ => out.add(say, format!("In {ns}: {t}"), go),
        }
        // Policies of the network or the mesh that aren't understood here.
        for (key, what, all) in [(CILIUM, "Cilium policies", false), (CILIUM_ALL, "Cilium cluster policies", true), (CALICO, "Calico policies", false), (CALICO_ALL, "Calico global policies", true), (ISTIO, "Istio authorization policies", false)] {
            match self.kind_known(ctx, key) {
                Ok(l) => {
                    let n = l.iter().filter(|x| all || ns_of(x) == ns || (key == ISTIO && ns_of(x) == "istio-system")).count();
                    if n > 0 {
                        out.add(Say::Unknown, format!("{n} {what} may be about it; they aren't looked at here"), None);
                    }
                }
                Err(e) if e.contains("which kinds") => {}
                Err(e) => out.add(Say::Unknown, format!("{what}: {e}"), None),
            }
        }
    }

    /// The network a cluster's pods are on, by its name.
    pub(super) fn net_name(&self, ctx: &str) -> Option<String> {
        let conf = self.kind_known(ctx, NETS).ok().and_then(|l| l.iter().find(|x| name_of(x) == "cluster"));
        match conf.and_then(|c| c["status"]["networkType"].as_str()) {
            Some("OVNKubernetes") => Some("OVN-Kubernetes".into()),
            Some(t) => Some(t.into()),
            None => {
                let l = self.refs(ctx, Kind::DaemonSets, "")?;
                netlab::cni(&l.iter().map(|d| name_of(d)).collect::<Vec<_>>()).map(String::from)
            }
        }
    }

    /// Is an address one of the cluster's own (pods, services)?
    fn own_address(&self, ctx: &str, ip: IpAddr) -> Option<&'static str> {
        let c = self.kind_known(ctx, NETS).ok()?.iter().find(|x| name_of(x) == "cluster")?;
        let has = |v: &Value| v.as_array().into_iter().flatten().filter_map(|x| x.as_str().or(x["cidr"].as_str())).any(|r| in_range(r, ip) == Some(true));
        if has(&c["status"]["serviceNetwork"]) { Some("a service") } else if has(&c["status"]["clusterNetwork"]) { Some("a pod") } else { None }
    }

    /// The whole path. (cluster, from, to, port, protocol)
    pub(super) fn net_path(&self, ctx: &str, a: &End, b: &End, port: i64, proto: &str) -> Path {
        let mut out = Path { target: port, ..Default::default() };
        let net = self.net_name(ctx);
        let node_bad = |n: &str| -> Option<String> { self.refs(ctx, Kind::Nodes, "").unwrap_or_default().into_iter().find(|x| name_of(x) == n).and_then(|x| pod::cond(x, "Ready").filter(|c| c["status"] != "True").map(|_| n.to_string())) };
        // Where it starts.
        let mut pa: Option<Value> = None;
        if let End::Object(s) = a {
            pa = match s.kind {
                // A helper that isn't there yet: a pod with our label only, or on a node's network.
                Kind::Namespaces => Some(serde_json::json!({"metadata": {"name": "a-new-pod", "namespace": s.name, "labels": {"kubedog-helper": "netlab"}}, "spec": {"containers": []}, "status": {"phase": "Running"}})),
                Kind::Nodes => Some(serde_json::json!({"metadata": {"name": format!("on-{}", s.name), "namespace": self.helper_home()}, "spec": {"containers": [], "hostNetwork": true, "nodeName": s.name}, "status": {"phase": "Running"}})),
                _ => self.pod_at(s).cloned(),
            };
            match &pa {
                Some(_) if matches!(s.kind, Kind::Namespaces | Kind::Nodes) => {
                    out.add(Say::Yes, if s.kind == Kind::Nodes { format!("From node {}", s.name) } else { format!("From a new pod in {}, which has only Kubedog's own label", s.name) }, None);
                    out.from_pod = pa.clone();
                }
                Some(p) if p["status"]["phase"] == "Running" => {
                    out.add(Say::Yes, format!("From pod {}{}", name_of(p), p["spec"]["nodeName"].as_str().map(|n| format!(", on {n}")).unwrap_or_default()), Some(obj(ctx, Kind::Pods, &s.ns, name_of(p))));
                    if let Some(x) = extra_cards(p) {
                        out.add(Say::Info, format!("It has another network card ({x}): what goes over that isn't looked at"), None);
                    }
                    out.from_pod = pa.clone();
                }
                _ => out.add(Say::Maybe, format!("{} has no running pod to start from", s.name), None),
            }
        }
        match b {
            End::Address(host) => self.path_out(&mut out, ctx, pa.as_ref(), host, port, proto, net.as_deref()),
            End::Outside => out.add(Say::Unknown, "Where it goes isn't told", None),
            End::Object(b) => {
                // The way in from outside.
                let outside = matches!(a, End::Outside | End::Address(_));
                let svc = (b.kind == Kind::Services).then(|| self.object_of(b)).flatten();
                let pb = self.pod_at(b).cloned();
                let mut froms: Vec<(String, Other)> = vec![];
                if outside {
                    froms = self.path_in(&mut out, ctx, b, svc.as_ref(), port);
                    if let End::Address(h) = a {
                        let ip = h.parse::<IpAddr>().ok();
                        for f in &mut froms {
                            if !f.1.pod && f.1.node.is_none() {
                                f.1.ip = ip;
                            }
                        }
                    }
                }
                let mut target = port;
                if let Some(svc) = &svc {
                    target = self.path_service(&mut out, ctx, b, svc, pa.as_ref(), pb.as_ref(), port, proto, outside);
                } else if b.kind == Kind::Services {
                    out.add(Say::No, format!("Service {} isn't there", b.name), None);
                }
                out.target = target;
                match &pb {
                    None => {
                        let empty = svc.as_ref().map(|s| !s["spec"]["selector"].as_object().map(|m| !m.is_empty()).unwrap_or(false)).unwrap_or(false);
                        if empty {
                            out.add(Say::Unknown, format!("{} has no selector: where it sends isn't a pod that's known here", b.name), None);
                        } else {
                            out.add(Say::No, format!("{} has no pod to reach", b.name), None);
                        }
                    }
                    Some(p) => {
                        let ok = p["status"]["phase"] == "Running";
                        out.add(if ok && ready(p) { Say::Yes } else if ok { Say::Maybe } else { Say::No }, format!("To pod {}{}{}", name_of(p), p["spec"]["nodeName"].as_str().map(|n| format!(", on {n}")).unwrap_or_default(), if !ok { ", which doesn't run" } else if !ready(p) { ", which isn't ready" } else { "" }), Some(obj(ctx, Kind::Pods, &b.ns, name_of(p))));
                        let listed: Vec<i64> = p["spec"]["containers"].as_array().into_iter().flatten().flat_map(|c| c["ports"].as_array().into_iter().flatten()).filter_map(|x| x["containerPort"].as_i64()).collect();
                        if !listed.is_empty() && !listed.contains(&target) {
                            out.add(Say::Maybe, format!("Port {target} isn't listed by its containers ({}); it may still listen", listed.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")), None);
                        }
                        if let Some(x) = extra_cards(p) {
                            out.add(Say::Info, format!("It has another network card ({x}): what goes over that isn't looked at"), None);
                        }
                        for n in [pa.as_ref(), Some(p)].into_iter().flatten().filter_map(|x| x["spec"]["nodeName"].as_str()).filter_map(node_bad) {
                            out.add(Say::Maybe, format!("Node {n} isn't ready"), Some(obj(ctx, Kind::Nodes, "", &n)));
                        }
                        let names = ports_of(p);
                        let pt = Port { n: target, proto, names: &names };
                        if let Some(x) = &pa {
                            self.path_networks(&mut out, ctx, x, p);
                            let same = name_of(x) == name_of(p) && ns_of(x) == ns_of(p);
                            if same {
                                out.add(Say::Info, "It's the same pod: through its service, some networks have trouble with that (hairpin); policies don't count for it", None);
                            } else {
                                let (ox, oy) = (self.as_other(ctx, x), self.as_other(ctx, p));
                                self.policy_steps(&mut out, ctx, false, x, &oy, &pt, net.as_deref());
                                self.policy_steps(&mut out, ctx, true, p, &ox, &pt, net.as_deref());
                            }
                        }
                        for (what, o) in &froms {
                            let mut sub = Path::default();
                            self.policy_steps(&mut sub, ctx, true, p, o, &pt, net.as_deref());
                            for mut s in sub.steps {
                                if froms.len() > 1 {
                                    s.text = format!("{what}: {}", s.text);
                                }
                                if !out.steps.iter().any(|x| x.text == s.text) {
                                    out.steps.push(s);
                                }
                            }
                        }
                    }
                }
                out.host = if b.kind == Kind::Services { format!("{}.{}.svc", b.name, b.ns) } else { pb.as_ref().map(|y| text(&y["status"]["podIP"])).unwrap_or_default() };
            }
        }
        out
    }

    /// Two pods on networks of their own?
    fn path_networks(&self, out: &mut Path, ctx: &str, x: &Value, y: &Value) {
        let (u, c) = (self.kind_known(ctx, UDN), self.kind_known(ctx, CUDN));
        let (Ok(u), Ok(c)) = (&u, &c) else {
            if let Some(e) = u.err().or(c.err()).filter(|e| !e.contains("which kinds")) {
                out.add(Say::Unknown, format!("Whether they're on the same pod network: {e}"), None);
            }
            return;
        };
        let of = |p: &Value| own_network(u, c, ns_of(p), &self.ns_labels(ctx, ns_of(p)));
        let (n, m) = (of(x), of(y));
        if n != m {
            let w = |n: &Option<String>| n.clone().map(|n| format!("network {n}")).unwrap_or("the cluster's network".into());
            out.add(Say::Maybe, format!("They're on different networks ({} and {}), which are kept apart unless something joins them", w(&n), w(&m)), None);
        } else if let Some(n) = n {
            out.add(Say::Info, format!("Both are on network {n}"), None);
        }
    }

    /// A service: its port, its endpoints, its traps. Returns the port of the pods.
    #[allow(clippy::too_many_arguments)]
    fn path_service(&self, out: &mut Path, ctx: &str, b: &Selected, svc: &Value, pa: Option<&Value>, pb: Option<&Value>, port: i64, proto: &str, outside: bool) -> i64 {
        let go = || Some(Go::Object(b.clone()));
        let spec = &svc["spec"];
        if spec["type"] == "ExternalName" {
            out.add(Say::Info, format!("Service {} only points to the name {}", b.name, text(&spec["externalName"])), go());
        }
        let list: Vec<&Value> = spec["ports"].as_array().into_iter().flatten().collect();
        let mut target = port;
        let found = list.iter().find(|p| p["port"].as_i64() == Some(port) && p["protocol"].as_str().unwrap_or("TCP") == proto);
        match found {
            None => {
                let other = list.iter().find(|p| p["port"].as_i64() == Some(port));
                let words = list.iter().map(|p| format!("{}{}", p["port"], match p["protocol"].as_str() { Some("TCP") | None => String::new(), Some(x) => format!("/{}", x.to_lowercase()) })).collect::<Vec<_>>().join(", ");
                out.add(Say::No, match other {
                    Some(o) => format!("Service {} has port {port} for {}, not for {proto}", b.name, o["protocol"].as_str().unwrap_or("TCP")),
                    None => format!("Service {} has no port {port}: it has {words}", b.name),
                }, go());
            }
            Some(p) => {
                let t = &p["targetPort"];
                let n = t.as_i64().or_else(|| pb.and_then(|pod| ports_of(pod).into_iter().find(|x| Some(x.0.as_str()) == t.as_str()).map(|x| x.1))).or(if t.is_null() { Some(port) } else { None });
                match n {
                    Some(n) => {
                        target = n;
                        if spec["clusterIP"] == "None" {
                            out.add(if n == port { Say::Yes } else { Say::Maybe }, format!("Service {} is headless: its name gives the pods' own addresses, so the port to use is {n}", b.name), go());
                            target = if n == port { n } else { port };
                        } else {
                            out.add(Say::Yes, format!("Service {} sends port {port} to port {n} of its pods", b.name), go());
                        }
                    }
                    None if pb.is_some() => out.add(Say::No, format!("Service {} sends to port “{}”, which no container has", b.name, text(t)), go()),
                    None => out.add(Say::Unknown, format!("Service {} sends to port “{}” of its pods", b.name, text(t)), go()),
                }
            }
        }
        match self.service_ready(ctx, &b.ns, &b.name) {
            Some((0, n)) => out.add(Say::No, format!("None of its endpoints is ready (0/{n})"), None),
            Some((r, n)) if r < n => out.add(Say::Info, format!("{r}/{n} endpoints ready"), None),
            Some((r, n)) => out.add(Say::Yes, format!("{r}/{n} endpoints ready"), None),
            None => out.add(Say::Unknown, "Its endpoints aren't known", None),
        }
        // Only to endpoints on the same node?
        let on: Option<HashSet<String>> = self.refs(ctx, Kind::EndpointSlices, &b.ns).map(|l| l.into_iter().filter(|s| s["metadata"]["labels"]["kubernetes.io/service-name"].as_str() == Some(&b.name)).flat_map(|s| s["endpoints"].as_array().into_iter().flatten()).filter(|e| e["conditions"]["ready"] != false).filter_map(|e| e["nodeName"].as_str().map(String::from)).collect());
        if spec["internalTrafficPolicy"] == "Local" {
            if let (Some(on), Some(n)) = (&on, pa.and_then(|p| p["spec"]["nodeName"].as_str())) {
                if on.contains(n) {
                    out.add(Say::Yes, format!("It only sends to pods on the same node, and {n} has one"), None);
                } else {
                    out.add(Say::No, format!("It only sends to pods on the same node (internalTrafficPolicy: Local), and {n} has none that's ready"), go());
                }
            }
        }
        if outside && spec["externalTrafficPolicy"] == "Local" && matches!(spec["type"].as_str(), Some("LoadBalancer" | "NodePort")) {
            if let (Some(on), Some(all)) = (&on, self.refs(ctx, Kind::Nodes, "").map(|n| n.len())) {
                out.add(Say::Info, format!("From outside, only nodes with a pod of it answer (externalTrafficPolicy: Local): {} of {all} now. A load balancer has to know", on.len()), go());
            }
        }
        target
    }

    /// From outside: what leads to it, and who its pods then see. (what, who)
    fn path_in(&self, out: &mut Path, ctx: &str, b: &Selected, svc: Option<&Value>, port: i64) -> Vec<(String, Other)> {
        let mut v: Vec<(String, Other)> = vec![];
        let Some(svc) = svc else {
            out.add(Say::Unknown, "From outside, pick a service: that's what ways in lead to", None);
            return v;
        };
        let doors: Vec<opnet::Door> = self.doors().into_iter().filter(|d| d.ctx == ctx && d.ns == b.ns && d.service == b.name).collect();
        let mut led = false;
        for d in doors.iter().take(6) {
            led = true;
            let go = (d.kind == "Ingress").then(|| obj(ctx, Kind::Ingresses, &d.ns, &d.name));
            out.add(if d.taken { Say::Yes } else { Say::Maybe }, format!("{} {} leads to it: {}{}{}", d.kind, d.name, if d.host.is_empty() { "any name" } else { &d.host }, if d.path == "/" { "" } else { &d.path }, if d.taken { "" } else { ", but nothing has taken it" }), go);
        }
        if led {
            // The pods that let it in.
            let routers: Vec<&Value> = self
                .refs(ctx, Kind::Pods, "")
                .unwrap_or_default()
                .into_iter()
                .filter(|p| {
                    let n = name_of(p);
                    p["status"]["phase"] == "Running" && if doors.iter().any(|d| d.kind == "Route") && !doors.iter().any(|d| d.kind != "Route") { ns_of(p) == "openshift-ingress" && n.starts_with("router-") } else { (ns_of(p) == "openshift-ingress" && n.starts_with("router-")) || (n.contains("ingress-nginx") && n.contains("controller")) || n.starts_with("traefik-") || n.contains("istio-ingressgateway") }
                })
                .collect();
            let mut seen: HashSet<String> = HashSet::new();
            for p in &routers {
                let owner = name_of(p).rsplitn(3, '-').last().unwrap_or(name_of(p)).to_string();
                if seen.insert(format!("{}/{owner}", ns_of(p))) {
                    v.push((format!("through {owner}"), self.as_other(ctx, p)));
                }
            }
            if !v.is_empty() {
                out.add(Say::Info, v.iter().map(|x| x.0.clone()).collect::<Vec<_>>().join(", "), routers.first().map(|p| obj(ctx, Kind::Pods, ns_of(p), name_of(p))));
            }
            if v.is_empty() {
                out.add(Say::Unknown, "The pods that let it in aren't known here, so whether policies let them through isn't either", None);
            }
        }
        match svc["spec"]["type"].as_str() {
            Some("LoadBalancer") => {
                led = true;
                let ips: Vec<String> = svc["status"]["loadBalancer"]["ingress"].as_array().into_iter().flatten().filter_map(|a| a["ip"].as_str().or(a["hostname"].as_str()).map(String::from)).collect();
                if ips.is_empty() {
                    out.add(Say::No, "Its load balancer has no address yet", Some(Go::Object(b.clone())));
                } else {
                    out.add(Say::Yes, format!("Its load balancer is at {}", ips.join(", ")), Some(Go::Object(b.clone())));
                }
                v.push(("through the load balancer".into(), via_node(svc)));
            }
            Some("NodePort") => {
                led = true;
                let np = svc["spec"]["ports"].as_array().into_iter().flatten().find(|p| p["port"].as_i64() == Some(port)).and_then(|p| p["nodePort"].as_i64());
                out.add(Say::Info, format!("Reached on every node{}", np.map(|n| format!(", port {n}")).unwrap_or_default()), Some(Go::Object(b.clone())));
                v.push(("through a node".into(), via_node(svc)));
            }
            _ => {}
        }
        if !led {
            let routes = self.answer(&format!("routes|{ctx}")).map(|r| r.is_ok()).unwrap_or(false);
            let known = self.refs(ctx, Kind::Ingresses, &b.ns).is_some() && routes;
            out.add(if known { Say::No } else { Say::Unknown }, if known { "Nothing leads to it from outside: no route, ingress, node port or load balancer" } else { "No way in that can be seen; not all of them could be read" }, None);
        }
        v
    }

    /// Out of the cluster.
    #[allow(clippy::too_many_arguments)]
    fn path_out(&self, out: &mut Path, ctx: &str, pa: Option<&Value>, host: &str, port: i64, proto: &str, net: Option<&str>) {
        let ip = host.parse::<IpAddr>().ok();
        out.host = host.to_string();
        if let Some(w) = ip.and_then(|i| self.own_address(ctx, i)) {
            out.add(Say::Unknown, format!("{host} is an address of {w} in this cluster: pick that as the other end"), None);
            return;
        }
        if ip.is_none() {
            out.add(Say::Info, format!("{host} isn't looked up here; rules with addresses can't be told for a name"), None);
        }
        let Some(p) = pa else { return };
        let o = Other { ip, ..Default::default() };
        self.policy_steps(out, ctx, false, p, &o, &Port { n: port, proto, names: &[] }, net);
        if p["spec"]["hostNetwork"] == true {
            return;
        }
        let nodes = self.refs(ctx, Kind::Nodes, "").unwrap_or_default();
        match self.kind_known(ctx, EGRESS_FW) {
            Ok(l) => {
                for f in l.iter().filter(|f| ns_of(f) == ns_of(p)) {
                    let (s, w) = egress_firewall(f, host, port, proto, &nodes);
                    out.add(s, format!("Egress firewall of {}: {w}", ns_of(p)), self.custom_go(ctx, EGRESS_FW, f));
                }
            }
            Err(e) if e.contains("which kinds") => out.add(Say::Unknown, format!("Egress firewalls: {e}"), None),
            Err(e) => out.add(Say::Unknown, format!("Egress firewalls: {e}"), None),
        }
        let nl = self.ns_labels(ctx, ns_of(p));
        match self.kind_known(ctx, EGRESS_IP) {
            Ok(l) => {
                for e in l.iter().filter(|e| meets(&e["spec"]["namespaceSelector"], &nl) && (e["spec"]["podSelector"].is_null() || meets(&e["spec"]["podSelector"], &p["metadata"]["labels"]))) {
                    let on: Vec<String> = e["status"]["items"].as_array().into_iter().flatten().map(|i| format!("{} (on {})", text(&i["egressIP"]), text(&i["node"]))).collect();
                    if on.is_empty() {
                        out.add(Say::No, format!("It should leave from egress IP {}, but no node has it: such traffic is dropped", name_of(e)), self.custom_go(ctx, EGRESS_IP, e));
                    } else {
                        out.add(Say::Info, format!("It leaves from {}", on.join(", ")), self.custom_go(ctx, EGRESS_IP, e));
                    }
                }
            }
            Err(e) if e.contains("which kinds") => {}
            Err(e) => out.add(Say::Unknown, format!("Egress IPs: {e}"), None),
        }
        if let Ok(l) = self.kind_known(ctx, EGRESS_SVC) {
            for e in l.iter().filter(|e| ns_of(e) == ns_of(p)) {
                let svc = self.refs(ctx, Kind::Services, ns_of(p)).unwrap_or_default().into_iter().find(|s| name_of(s) == name_of(e));
                if svc.map(|s| s["spec"]["selector"].as_object().map(|m| !m.is_empty()).unwrap_or(false) && selector_matches(&s["spec"]["selector"], &p["metadata"]["labels"])).unwrap_or(false) {
                    out.add(Say::Info, format!("It leaves from the load balancer address of service {} (egress service)", name_of(e)), self.custom_go(ctx, EGRESS_SVC, e));
                }
            }
        }
        out.add(Say::Unknown, "Outside the cluster: routers, firewalls and the other side aren't known here", None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pod(ns: &str, labels: Value) -> Other {
        Other { ns: ns.into(), ns_labels: json!({"kubernetes.io/metadata.name": ns}), labels, ip: "10.128.0.5".parse().ok(), pod: true, node: None }
    }
    fn at(ip: &str) -> Other {
        Other { ip: ip.parse().ok(), ..Default::default() }
    }
    const P: Port = Port { n: 5432, proto: "TCP", names: &[] };

    #[test]
    fn gates() {
        let shop = pod("shop", json!({"app": "web"}));
        let pol = |ingress: Value| json!({"metadata": {"name": "p", "namespace": "db"}, "spec": {"podSelector": {"matchLabels": {"app": "db"}}, "policyTypes": ["Ingress"], "ingress": ingress}});
        let db = json!({"app": "db"});
        let names = vec![("sql".to_string(), 5432)];
        let g = |p: &Value, n| gate(&[p], true, &db, &shop, &Port { n, proto: "TCP", names: &names });
        assert_eq!(g(&pol(json!([])), 5432), Gate::Blocked(vec!["p".into()]));
        assert_eq!(g(&pol(json!([{}])), 5432), Gate::Allowed(vec!["p".into()]));
        // Without a namespace selector only its own namespace.
        assert_eq!(g(&pol(json!([{"from": [{"podSelector": {"matchLabels": {"app": "web"}}}]}])), 5432), Gate::Blocked(vec!["p".into()]));
        let both = json!([{"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "shop"}}, "podSelector": {"matchLabels": {"app": "web"}}}], "ports": [{"port": "sql"}]}]);
        assert_eq!(g(&pol(both.clone()), 5432), Gate::Allowed(vec!["p".into()]));
        assert_eq!(g(&pol(both), 80), Gate::Blocked(vec!["p".into()]));
        // A range that has a pod's address: networks differ in that. One that doesn't: no.
        assert_eq!(g(&pol(json!([{"from": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}])), 5432), Gate::Unsure(vec!["p".into()]));
        assert_eq!(g(&pol(json!([{"from": [{"ipBlock": {"cidr": "192.0.2.0/24"}}]}])), 5432), Gate::Blocked(vec!["p".into()]));
        assert_eq!(g(&pol(json!([{"ports": [{"port": 5000, "endPort": 6000}]}])), 5432), Gate::Allowed(vec!["p".into()]));
        assert_eq!(g(&pol(json!([{"ports": [{"port": 5432, "protocol": "UDP"}]}])), 5432), Gate::Blocked(vec!["p".into()]));
        assert_eq!(gate(&[&pol(json!([]))], true, &json!({"app": "web"}), &shop, &P), Gate::Open);
        assert_eq!(gate(&[&pol(json!([]))], false, &db, &shop, &P), Gate::Open);
        // From outside: by address only.
        let r = pol(json!([{"from": [{"ipBlock": {"cidr": "192.0.2.0/24", "except": ["192.0.2.9/32"]}}]}]));
        let o = |x: &Other| gate(&[&r], true, &db, x, &P);
        assert_eq!(o(&at("192.0.2.8")), Gate::Allowed(vec!["p".into()]));
        assert_eq!(o(&at("192.0.2.9")), Gate::Blocked(vec!["p".into()]));
        assert_eq!(o(&Other::default()), Gate::Unsure(vec!["p".into()]));
        // A pod on its node's network isn't known by its labels.
        let host = Other { pod: false, node: Some(json!({})), ..shop.clone() };
        assert_eq!(gate(&[&pol(json!([{"from": [{"namespaceSelector": {}}]}]))], true, &db, &host, &P), Gate::Unsure(vec!["p".into()]));
        assert_eq!(gate(&[&pol(json!([{"from": [{"namespaceSelector": {}}]}]))], true, &db, &at("192.0.2.1"), &P), Gate::Blocked(vec!["p".into()]));
    }

    fn anp(name: &str, prio: i64, rules: Value) -> Value {
        json!({"metadata": {"name": name}, "spec": {"priority": prio, "subject": {"namespaces": {"matchLabels": {"kubernetes.io/metadata.name": "db"}}}, "ingress": rules}})
    }
    fn from_shop(action: &str) -> Value {
        json!({"action": action, "from": [{"namespaces": {"matchLabels": {"kubernetes.io/metadata.name": "shop"}}}]})
    }
    fn db() -> (Value, Value) {
        (json!({"kubernetes.io/metadata.name": "db"}), json!({"app": "db"}))
    }

    #[test]
    fn admin_policies() {
        let (nl, l) = db();
        let shop = pod("shop", json!({"app": "web"}));
        let f = |list: &[Value], o: &Other| admin(list, true, &nl, &l, o, &P);
        // The lowest number goes first, whatever the order of the list.
        let two = [anp("late", 50, json!([from_shop("Allow")])), anp("early", 5, json!([from_shop("Deny")]))];
        assert_eq!(f(&two, &shop), Admin::Deny("early".into()));
        assert_eq!(f(&two, &pod("other", json!({}))), Admin::Nothing);
        // In one policy the first rule; its name is said.
        let mut r = from_shop("Pass");
        r["name"] = json!("let-teams-say");
        assert_eq!(f(&[anp("a", 1, json!([r, from_shop("Deny")]))], &shop), Admin::Pass("a (rule let-teams-say)".into()));
        // Ports.
        let mut r = from_shop("Deny");
        r["ports"] = json!([{"portNumber": {"port": 80, "protocol": "TCP"}}, {"portRange": {"start": 5000, "end": 5400}}]);
        assert_eq!(f(&[anp("a", 1, json!([r.clone()]))], &shop), Admin::Nothing);
        r["ports"] = json!([{"portRange": {"start": 5000, "end": 5500}}]);
        assert_eq!(f(&[anp("a", 1, json!([r]))], &shop), Admin::Deny("a".into()));
        // A pod on its node's network isn't one of its namespace's pods here.
        let host = Other { pod: false, node: Some(json!({})), ..shop.clone() };
        assert_eq!(f(&two, &host), Admin::Nothing);
        // Not for another namespace.
        assert_eq!(admin(&two, true, &json!({"kubernetes.io/metadata.name": "x"}), &l, &shop, &P), Admin::Nothing);
        // By address: to a name it can't be told, unless what follows says the same.
        let e = |rules: Value| json!({"metadata": {"name": "e"}, "spec": {"priority": 1, "subject": {"namespaces": {}}, "egress": rules}});
        let deny = json!({"action": "Deny", "to": [{"networks": ["203.0.113.0/24"]}]});
        let all = |a: &str| json!({"action": a, "to": [{"networks": ["0.0.0.0/0"]}]});
        let g = |l2: &[Value], o: &Other| admin(l2, false, &nl, &l, o, &P);
        assert_eq!(g(&[e(json!([deny, all("Allow")]))], &at("203.0.113.7")), Admin::Deny("e".into()));
        assert_eq!(g(&[e(json!([deny, all("Allow")]))], &at("198.51.100.7")), Admin::Allow("e".into()));
        assert_eq!(g(&[e(json!([deny]))], &Other::default()), Admin::Unsure("e".into()));
        // A kind of rule from later than this.
        assert_eq!(g(&[e(json!([{"action": "Deny", "to": [{"moons": ["x"]}]}]))], &at("198.51.100.7")), Admin::Unsure("e".into()));
    }

    #[test]
    fn who_goes_first() {
        let (nl, l) = db();
        let shop = pod("shop", json!({"app": "web"}));
        let block = json!({"metadata": {"name": "closed", "namespace": "db"}, "spec": {"podSelector": {}, "policyTypes": ["Ingress"]}});
        let t = |a: Result<&[Value], String>, n: Option<&[&Value]>, b: Result<&[Value], String>| tiers(a, n, b, true, (&nl, &l), &shop, &P).0;
        let (allow, deny, pass) = ([anp("a", 1, json!([from_shop("Allow")]))], [anp("a", 1, json!([from_shop("Deny")]))], [anp("a", 1, json!([from_shop("Pass")]))]);
        // Admin Allow goes over a closed network policy; Deny over none.
        assert_eq!(t(Ok(&allow), Some(&[&block]), Ok(&[])), Say::Yes);
        assert_eq!(t(Ok(&deny), Some(&[]), Ok(&[])), Say::No);
        assert_eq!(t(Ok(&pass), Some(&[&block]), Ok(&[])), Say::No);
        assert_eq!(t(Ok(&[]), Some(&[]), Ok(&[])), Say::Yes);
        // The baseline only when no network policy is about the pod.
        assert_eq!(t(Ok(&[]), Some(&[]), Ok(&deny)), Say::No);
        assert_eq!(t(Ok(&pass), Some(&[]), Ok(&deny)), Say::No);
        let open = json!({"metadata": {"name": "open", "namespace": "db"}, "spec": {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": [{}]}});
        assert_eq!(t(Ok(&[]), Some(&[&open]), Ok(&deny)), Say::Yes);
        // What can't be read is never a yes, nor a sure no.
        let e = || Err("your account can't see adminnetworkpolicies".to_string());
        assert_eq!(t(e(), Some(&[&open]), Ok(&[])), Say::Unknown);
        assert_eq!(t(e(), Some(&[]), Ok(&[])), Say::Unknown);
        assert_eq!(t(e(), Some(&[&block]), Ok(&[])), Say::Maybe);
        assert_eq!(t(Ok(&[]), Some(&[]), e()), Say::Unknown);
        assert_eq!(t(Ok(&[]), Some(&[&open]), e()), Say::Yes);
        assert_eq!(t(Ok(&[]), None, Ok(&[])), Say::Unknown);
        assert_eq!(t(Ok(&allow), None, Ok(&[])), Say::Yes);
    }

    #[test]
    fn firewalls_out() {
        let fw = |r: Value| json!({"spec": {"egress": r}});
        let rule = |t: &str, to: Value| json!({"type": t, "to": to});
        let f = |r: Value, h: &str| egress_firewall(&fw(r), h, 443, "TCP", &[]).0;
        let closed = json!([rule("Allow", json!({"dnsName": "*.example.com"})), rule("Allow", json!({"cidrSelector": "192.0.2.0/24"})), rule("Deny", json!({"cidrSelector": "0.0.0.0/0"}))]);
        assert_eq!(f(closed.clone(), "web.example.com"), Say::Yes);
        assert_eq!(f(closed.clone(), "192.0.2.4"), Say::Yes); // whichever rule it falls under
        assert_eq!(f(closed.clone(), "198.51.100.1"), Say::Maybe);
        assert_eq!(f(json!([rule("Allow", json!({"cidrSelector": "192.0.2.0/24"})), rule("Deny", json!({"cidrSelector": "0.0.0.0/0"}))]), "198.51.100.1"), Say::No);
        assert_eq!(f(json!([rule("Deny", json!({"cidrSelector": "192.0.2.0/24"}))]), "198.51.100.1"), Say::Yes);
        assert_eq!(f(json!([]), "198.51.100.1"), Say::Yes);
        // A name against addresses: not known.
        assert_eq!(f(json!([rule("Deny", json!({"cidrSelector": "192.0.2.0/24"}))]), "web.example.org"), Say::Maybe);
        // Ports.
        let mut r = rule("Deny", json!({"cidrSelector": "0.0.0.0/0"}));
        r["ports"] = json!([{"port": 25, "protocol": "TCP"}]);
        assert_eq!(f(json!([r.clone()]), "198.51.100.1"), Say::Yes);
        r["ports"] = json!([{"port": 443, "protocol": "TCP"}]);
        assert_eq!(f(json!([r]), "198.51.100.1"), Say::No);
    }

    #[test]
    fn networks() {
        let u = [json!({"metadata": {"name": "red", "namespace": "shop"}, "spec": {"layer2": {"role": "Primary"}}}), json!({"metadata": {"name": "extra", "namespace": "db"}, "spec": {"layer2": {"role": "Secondary"}}})];
        let c = [json!({"metadata": {"name": "wide"}, "spec": {"namespaceSelector": {"matchLabels": {"team": "a"}}, "network": {"layer3": {"role": "Primary"}}}})];
        assert_eq!(own_network(&u, &c, "shop", &json!({})), Some("shop/red".into()));
        assert_eq!(own_network(&u, &c, "db", &json!({})), None);
        assert_eq!(own_network(&u, &c, "x", &json!({"team": "a"})), Some("wide".into()));
        assert_eq!(in_range("10.128.0.0/14", "10.131.255.255".parse().unwrap()), Some(true));
        assert_eq!(in_range("10.128.0.0/14", "10.132.0.0".parse().unwrap()), Some(false));
        assert_eq!(in_range("2001:db8::/32", "2001:db8:1::1".parse().unwrap()), Some(true));
        assert_eq!(in_range("0.0.0.0/0", "2001:db8::1".parse().unwrap()), Some(false));
        assert_eq!(in_range("nonsense", "192.0.2.1".parse().unwrap()), None);
        assert_eq!(read_port("53/udp"), Some((53, "UDP")));
        assert_eq!(read_port(" 443 "), Some((443, "TCP")));
        assert_eq!((read_port("0"), read_port("1/icmp"), read_port("x")), (None, None, None));
    }

    #[test]
    fn adding_up() {
        let s = |l: &[Say]| sum(&l.iter().map(|x| PathStep { say: *x, text: String::new(), go: None }).collect::<Vec<_>>());
        assert_eq!(s(&[Say::Yes, Say::Info]), Say::Yes);
        assert_eq!(s(&[Say::Yes, Say::Unknown]), Say::Unknown);
        assert_eq!(s(&[Say::Unknown, Say::Maybe]), Say::Maybe);
        assert_eq!(s(&[Say::Maybe, Say::No, Say::Yes]), Say::No);
    }
}
