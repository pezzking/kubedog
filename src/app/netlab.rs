//! Network Lab: is the network well (from what the cluster itself says, reading only), and tests from this
//! computer. What's tested is chosen by a person; nothing is tried by itself.

use super::dash::line;
use super::face::{many, Face, Fact, Side};
use super::incident::tab_strip;
use super::nettest::{self, Done, Mode, Step, Target};
use super::ops::{ago, ns_of, obj, table, text, worst_first, Item};
use super::pg::{label_at, panel, pill};
use super::podxray::Go;
use super::work::{name_of, said};
use super::*;
use std::collections::VecDeque;

pub(super) const NETS: &str = "networks.config.openshift.io";
const CHECKS: &str = "podnetworkconnectivitychecks.controlplane.operator.openshift.io";
const OPERATORS: &str = "clusteroperators.config.openshift.io";
const POOLS: &str = "ipaddresspools.metallb.io";
pub(super) const ANP: &str = "adminnetworkpolicies.policy.networking.k8s.io";
pub(super) const BANP: &str = "baselineadminnetworkpolicies.policy.networking.k8s.io";
pub(super) const EGRESS_FW: &str = "egressfirewalls.k8s.ovn.org";
pub(super) const EGRESS_IP: &str = "egressips.k8s.ovn.org";
pub(super) const EGRESS_SVC: &str = "egressservices.k8s.ovn.org";
pub(super) const UDN: &str = "userdefinednetworks.k8s.ovn.org";
pub(super) const CUDN: &str = "clusteruserdefinednetworks.k8s.ovn.org";
pub(super) const NAD: &str = "network-attachment-definitions.k8s.cni.cncf.io";
pub(super) const ISTIO: &str = "authorizationpolicies.security.istio.io";
pub(super) const CILIUM: &str = "ciliumnetworkpolicies.cilium.io";
pub(super) const CILIUM_ALL: &str = "ciliumclusterwidenetworkpolicies.cilium.io";
pub(super) const CALICO: &str = "networkpolicies.crd.projectcalico.org";
pub(super) const CALICO_ALL: &str = "globalnetworkpolicies.crd.projectcalico.org";

/// What else decides about traffic, with what it does.
pub(super) const DECIDERS: &[(&str, &str, &str)] = &[
    (ANP, "Admin network policies", "go before network policies, for the whole cluster"),
    (BANP, "Baseline admin policy", "for pods that no network policy is about"),
    (EGRESS_FW, "Egress firewalls", "what a namespace may reach outside the cluster"),
    (EGRESS_IP, "Egress IPs", "the address that traffic out of a namespace comes from"),
    (EGRESS_SVC, "Egress services", "the same, for the pods of a service"),
    (UDN, "User-defined networks", "a namespace with a pod network of its own"),
    (CUDN, "Cluster user-defined networks", "the same, for several namespaces"),
    (NAD, "Extra networks (Multus)", "second network cards for pods"),
    (ISTIO, "Istio authorization policies", "what the mesh lets through"),
    (CILIUM, "Cilium policies", "policies of the network itself"),
    (CILIUM_ALL, "Cilium cluster policies", "the same, for the whole cluster"),
    (CALICO, "Calico policies", "policies of the network itself"),
    (CALICO_ALL, "Calico global policies", "the same, for the whole cluster"),
];

/// What isn't known only because it's on its way.
pub(super) const READING: &str = "it's still being read";

const TABS: [&str; 5] = ["Overview", "From this computer", "Can A reach B", "From a pod", "Packets"];

#[derive(Default)]
pub(super) struct NetLab {
    pub tab: usize,
    typed: String,
    error: String,
    queue: VecDeque<Target>,
    running: usize,
    /// How many there were in the last go.
    total: usize,
    pub done: Vec<Done>,
    /// The result that's open.
    pub open: Option<usize>,
    pub tries: nettry::Tries,
    pub traces: ovntrace::Traces,
    pub packets: packets::Packets,
    /// Its settings are open.
    pub setup: bool,
    /// What the overview was made of, kept a moment: it goes over every service.
    over: HashMap<String, (Instant, Over)>,
}

// ---------- what the cluster says ----------

/// The pod network, by the daemon set that makes it.
pub(super) fn cni(sets: &[&str]) -> Option<&'static str> {
    const KNOWN: [(&str, &str); 12] = [("ovnkube-node", "OVN-Kubernetes"), ("sdn", "OpenShift SDN"), ("cilium", "Cilium"), ("calico-node", "Calico"), ("canal", "Canal (Calico and Flannel)"), ("kube-flannel", "Flannel"), ("weave-net", "Weave"), ("kindnet", "kindnet"), ("aws-node", "Amazon VPC"), ("azure-cni", "Azure CNI"), ("antrea-agent", "Antrea"), ("kube-router", "kube-router")];
    KNOWN.iter().find(|(p, _)| sets.iter().any(|s| s == p || s.strip_prefix(p).map(|r| r.starts_with('-')).unwrap_or(false))).map(|k| k.1)
}

/// Does the pod network keep to network policies? None: not known.
pub(super) fn keeps_policies(cni: Option<&str>) -> Option<bool> {
    match cni? {
        "Flannel" => Some(false),
        "Amazon VPC" | "Azure CNI" | "kindnet" => None,
        _ => Some(true),
    }
}

/// What a part of the network does, by the name of what runs it.
fn role(ns: &str, name: &str) -> Option<&'static str> {
    let has = |l: &[&str]| l.iter().any(|x| name.contains(x));
    if name.starts_with("sdn") && ns != "openshift-sdn" {
        return None;
    }
    if cni(&[name]).is_some() || matches!(name, "ovnkube-control-plane" | "calico-kube-controllers" | "calico-typha" | "cilium-operator" | "antrea-controller") {
        return Some("Pod network");
    }
    if name.starts_with("kube-proxy") {
        return Some("Services");
    }
    if has(&["coredns", "kube-dns", "dns-default", "nodelocaldns", "node-local-dns"]) || (ns == "openshift-dns" && name == "node-resolver") {
        return Some("DNS");
    }
    if (ns == "openshift-ingress" && name.starts_with("router-")) || (name.contains("ingress-nginx") && name.contains("controller")) || name == "traefik" || name.contains("istio-ingressgateway") || name.contains("haproxy-ingress") || (name.contains("envoy") && ns.contains("gateway")) {
        return Some("Ways in");
    }
    if (ns.contains("metallb") && has(&["speaker", "controller"])) || name.starts_with("kube-vip") {
        return Some("Load balancer addresses");
    }
    if name.starts_with("multus") {
        return Some("Extra networks");
    }
    if name.starts_with("istiod") || name.starts_with("linkerd-destination") {
        return Some("Service mesh");
    }
    None
}

/// One of OpenShift's own connection checks: (tone, word, why).
fn check_state(o: &Value, now: i64) -> (Tone, String, String) {
    let st = &o["status"];
    let c = st["conditions"].as_array().into_iter().flatten().find(|c| c["type"] == "Reachable");
    let out: Vec<(i64, Option<i64>)> = st["outages"].as_array().into_iter().flatten().filter_map(|x| Some((pod::time_of(&x["start"])?, pod::time_of(&x["end"])))).collect();
    let day = out.iter().filter(|x| now - x.1.unwrap_or(now) < 86400).count();
    let last = out.iter().map(|x| x.0).max();
    let past = last.map(|t| format!("last outage {}, {} on record", ago(now, Some(t)), out.len())).unwrap_or_default();
    match c.and_then(|c| c["status"].as_str()) {
        Some("False") => (Tone::Danger, "not reachable".into(), text(&c.unwrap()["message"])),
        Some("True") if day > 0 => (Tone::Warning, format!("{} in the last day", many(day as i64, "outage")), past),
        Some("True") => (Tone::Success, "reachable".into(), past),
        _ => (Tone::Muted, "not known".into(), past),
    }
}

/// How many addresses a MetalLB pool has (only IPv4; None when it can't be told).
fn pool_size(o: &Value) -> Option<u64> {
    let v4 = |t: &str| t.trim().parse::<std::net::Ipv4Addr>().ok().map(u32::from);
    let mut n = 0u64;
    for a in o["spec"]["addresses"].as_array()? {
        let a = a.as_str()?;
        n += match (a.split_once('/'), a.split_once('-')) {
            (Some((ip, bits)), _) => {
                v4(ip)?;
                1u64 << 32u32.checked_sub(bits.trim().parse().ok()?)?
            }
            (_, Some((x, y))) => (v4(y)?.checked_sub(v4(x)?)? as u64) + 1,
            _ => return None,
        };
    }
    Some(n)
}

/// Is an address in a pool?
fn in_pool(o: &Value, ip: &str) -> bool {
    let v4 = |t: &str| t.trim().parse::<std::net::Ipv4Addr>().ok().map(u32::from);
    let Some(i) = v4(ip) else { return false };
    o["spec"]["addresses"].as_array().into_iter().flatten().filter_map(|a| a.as_str()).any(|a| match (a.split_once('/'), a.split_once('-')) {
        (Some((net, bits)), _) => match (v4(net), bits.trim().parse::<u32>()) {
            (Some(n), Ok(b)) if b <= 32 => b == 0 || (n ^ i) >> (32 - b) == 0,
            _ => false,
        },
        (_, Some((x, y))) => matches!((v4(x), v4(y)), (Some(x), Some(y)) if x <= i && i <= y),
        _ => false,
    })
}

/// Ready and all endpoints of every service, from the endpoint slices: ((namespace, service), (ready, all)).
fn endpoints(slices: &[&Value]) -> HashMap<(String, String), (usize, usize)> {
    let mut seen: HashMap<(String, String), HashMap<String, bool>> = HashMap::new();
    for s in slices {
        let Some(svc) = s["metadata"]["labels"]["kubernetes.io/service-name"].as_str() else { continue };
        let m = seen.entry((ns_of(s).to_string(), svc.to_string())).or_default();
        for e in s["endpoints"].as_array().into_iter().flatten() {
            let id = e["targetRef"]["name"].as_str().or(e["addresses"][0].as_str()).unwrap_or("").to_string();
            *m.entry(id).or_default() |= e["conditions"]["ready"] != false;
        }
    }
    seen.into_iter().map(|(k, m)| (k, (m.values().filter(|r| **r).count(), m.len()))).collect()
}

/// A part of the network: what runs it.
#[derive(Clone)]
struct Part {
    role: &'static str,
    kind: Kind,
    ns: String,
    name: String,
    ready: i64,
    want: i64,
    restarts: i64,
}

/// The overview of a cluster.
#[derive(Clone, Default)]
struct Over {
    network: String,
    facts: Vec<(String, String)>,
    finds: Vec<(Tone, String, String, Option<Go>)>,
    parts: Vec<Part>,
    /// (namespace, name, ready, all)
    empty: Vec<(String, String, usize, usize)>,
    unread: Vec<String>,
    /// Still being read for the first time.
    reading: Vec<String>,
}

// ---------- tests from this computer: what the cluster publishes ----------

/// What to test of a way in.
fn door_target(d: &opnet::Door, expect: Vec<String>) -> Option<Target> {
    let h = d.host.trim().to_lowercase();
    if h.is_empty() || h.contains('*') {
        return None;
    }
    let t = nettest::read_target(&format!("{}://{h}", if d.tls { "https" } else { "http" })).ok()?;
    Some(Target { path: nettest::good_path(&d.path), of: format!("{} {}/{}", d.kind, d.ns, d.name), expect, ..t })
}

/// What to test of a load balancer service: a connection to each of its TCP ports.
fn lb_targets(s: &Value) -> Vec<Target> {
    let mut v = vec![];
    for a in s["status"]["loadBalancer"]["ingress"].as_array().into_iter().flatten() {
        let Some(host) = a["ip"].as_str().or(a["hostname"].as_str()) else { continue };
        for p in s["spec"]["ports"].as_array().into_iter().flatten().filter(|p| p["protocol"].as_str().unwrap_or("TCP") == "TCP").take(20) {
            if let Some(port) = p["port"].as_u64().and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0) {
                if let Ok(t) = nettest::read_target(&if host.contains(':') { format!("tcp://[{host}]:{port}") } else { format!("tcp://{host}:{port}") }) {
                    v.push(Target { mode: Mode::Tcp, of: format!("Service {}/{}", ns_of(s), name_of(s)), ..t });
                }
            }
        }
    }
    v
}

/// The same address once.
fn once(v: Vec<Target>) -> Vec<Target> {
    let mut seen = HashSet::new();
    v.into_iter().filter(|t| seen.insert((t.label(), t.mode.word()))).collect()
}

impl KubedogApp {
    /// A custom kind in a cluster: its objects (none when the cluster doesn't have the kind), or why that
    /// isn't known.
    pub(super) fn kind_known(&self, ctx: &str, key: &str) -> Result<&[Value], String> {
        match self.lists.get(&Self::list_key(ctx, Kind::CustomResourceDefinitions)) {
            Some(l) if l.fetched.is_some() && !self.refused(ctx, Kind::CustomResourceDefinitions) => {
                if !l.items.iter().any(|o| o["metadata"]["name"].as_str() == Some(key)) {
                    return Ok(&[]);
                }
            }
            Some(l) if l.error.is_some() || self.refused(ctx, Kind::CustomResourceDefinitions) => return Err("your account can't see which kinds the cluster has".into()),
            _ => return Err(READING.into()),
        }
        let Some(k) = self.crd_index(key).and_then(|i| self.crds.get(i as usize)) else { return Err(READING.into()) };
        match self.lists.get(&Self::custom_list_key(ctx, k)) {
            Some(l) if l.error.as_deref().map(is_refusal).unwrap_or(false) => Err(format!("your account can't see {}", k.plural)),
            Some(l) if l.fetched.is_some() => Ok(&l.items),
            Some(l) if l.error.is_some() => Err(format!("{} couldn't be read", k.plural)),
            _ => Err(READING.into()),
        }
    }

    pub(super) fn refresh_netlab(&mut self, force: bool) {
        if self.view != View::NetLab || self.power_off("netlab") || self.demo {
            return;
        }
        self.sync_crds();
        for k in [CHECKS, OPERATORS, POOLS] {
            self.read_custom(k, 30, force);
        }
        self.refresh_path(force);
        self.ask_tools();
        if force {
            self.netlab.over.clear();
        }
    }

    pub(super) fn netlab_kinds(&self) -> Vec<Kind> {
        if self.netlab.tab < 2 {
            return vec![Kind::Pods, Kind::Nodes, Kind::DaemonSets, Kind::Deployments, Kind::Services, Kind::EndpointSlices, Kind::Ingresses, Kind::NetworkPolicies, Kind::Namespaces];
        }
        Self::path_kinds()
    }

    /// The result that's open, for the way back.
    pub(super) fn netlab_sub(&self) -> Option<String> {
        match self.netlab.tab {
            1 => self.netlab.open,
            3 => self.netlab.tries.open,
            4 => self.packets_sub(),
            _ => None,
        }
        .map(|i| format!("test {i}"))
    }

    pub(super) fn netlab_close(&mut self) {
        self.netlab.open = None;
        self.netlab.tries.open = None;
        self.packets_close();
    }

    fn net_over(&self, ctx: &str) -> Over {
        let now = kube::now_secs();
        let mut o = Over::default();
        let sets = self.refs(ctx, Kind::DaemonSets, "");
        let names: Vec<&str> = sets.iter().flatten().map(|d| name_of(d)).collect();
        let conf = self.kind_known(ctx, NETS).ok().and_then(|l| l.iter().find(|x| name_of(x) == "cluster"));
        o.network = match conf.and_then(|c| c["status"]["networkType"].as_str()) {
            Some("OVNKubernetes") => "OVN-Kubernetes".into(),
            Some(t) => t.into(),
            None => cni(&names).map(|t| t.to_string()).unwrap_or("not known".into()),
        };
        o.facts.push(("Pod network".into(), o.network.clone()));
        if let Some(c) = conf {
            let st = &c["status"];
            let list = |v: &Value| v.as_array().into_iter().flatten().filter_map(|x| x.as_str().or(x["cidr"].as_str())).collect::<Vec<_>>().join(", ");
            o.facts.push(("Pod addresses".into(), list(&st["clusterNetwork"])));
            o.facts.push(("Service addresses".into(), list(&st["serviceNetwork"])));
            if let Some(m) = st["clusterNetworkMTU"].as_i64() {
                o.facts.push(("MTU in pods".into(), m.to_string()));
            }
        }
        // What makes the network.
        let pods = self.refs(ctx, Kind::Pods, "");
        for (kind, l) in [(Kind::DaemonSets, &sets), (Kind::Deployments, &self.refs(ctx, Kind::Deployments, ""))] {
            for d in l.iter().flatten() {
                let Some(role) = role(ns_of(d), name_of(d)) else { continue };
                let (ready, want) = if kind == Kind::DaemonSets { (d["status"]["numberReady"].as_i64().unwrap_or(0), d["status"]["desiredNumberScheduled"].as_i64().unwrap_or(0)) } else { (d["status"]["readyReplicas"].as_i64().unwrap_or(0), d["spec"]["replicas"].as_i64().unwrap_or(1)) };
                let mine = |p: &&&Value| {
                    let r = &p["metadata"]["ownerReferences"][0];
                    ns_of(p) == ns_of(d) && if kind == Kind::DaemonSets { r["name"].as_str() == Some(name_of(d)) } else { r["kind"] == "ReplicaSet" && r["name"].as_str().and_then(|n| n.rsplit_once('-')).map(|x| x.0 == name_of(d)).unwrap_or(false) }
                };
                let restarts = pods.iter().flatten().filter(mine).flat_map(|p| p["status"]["containerStatuses"].as_array().into_iter().flatten()).filter(|c| pod::time_of(&c["lastState"]["terminated"]["finishedAt"]).map(|t| now - t < 86400).unwrap_or(false)).count() as i64;
                o.parts.push(Part { role, kind, ns: ns_of(d).into(), name: name_of(d).into(), ready, want, restarts });
            }
        }
        for p in o.parts.iter().filter(|p| p.want > 0) {
            let go = Some(obj(ctx, p.kind, &p.ns, &p.name));
            if p.ready < p.want {
                o.finds.push((if p.ready == 0 { Tone::Danger } else { Tone::Warning }, format!("{}: {}/{} of {} ready", p.role, p.ready, p.want, p.name), format!("in {}", p.ns), go));
            } else if p.restarts > 0 {
                o.finds.push((Tone::Warning, format!("{}: {} of {} in the last day", p.role, many(p.restarts, "restart"), p.name), format!("in {}", p.ns), go));
            }
        }
        if let Some(n) = self.refs(ctx, Kind::Nodes, "") {
            for x in n {
                let go = Some(obj(ctx, Kind::Nodes, "", name_of(x)));
                if let Some(c) = pod::cond(x, "NetworkUnavailable").filter(|c| c["status"] == "True") {
                    o.finds.push((Tone::Danger, format!("Node {} has no working network", name_of(x)), text(&c["message"]), go));
                } else if let Some(c) = pod::cond(x, "Ready").filter(|c| c["status"] != "True") {
                    o.finds.push((Tone::Warning, format!("Node {} isn't ready", name_of(x)), text(&c["message"]), go));
                }
            }
        }
        // What OpenShift says about its own parts.
        for x in self.kind_known(ctx, OPERATORS).unwrap_or_default().iter().filter(|x| matches!(name_of(x), "network" | "dns" | "ingress")) {
            let is = |t: &str, s: &str| pod::cond(x, t).filter(|c| c["status"] == s);
            if let Some(c) = is("Available", "False").or(is("Degraded", "True")) {
                o.finds.push((Tone::Danger, format!("OpenShift's {} operator isn't well", name_of(x)), text(&c["message"]), self.custom_go(ctx, OPERATORS, x)));
            }
        }
        for x in self.kind_known(ctx, CHECKS).unwrap_or_default() {
            let (t, w, y) = check_state(x, now);
            if matches!(t, Tone::Danger | Tone::Warning) {
                let to = name_of(x).split_once("-to-").map(|p| p.1).unwrap_or(name_of(x)).to_string();
                o.finds.push((t, format!("Connection check to {to}: {w}"), y, self.custom_go(ctx, CHECKS, x)));
            }
        }
        // Services.
        let services = self.refs(ctx, Kind::Services, "");
        let slices = self.refs(ctx, Kind::EndpointSlices, "");
        if let (Some(sv), Some(sl)) = (&services, &slices) {
            let ends = endpoints(sl);
            for s in sv.iter().filter(|s| self.ns_ok(ns_of(s))) {
                if s["spec"]["type"] == "ExternalName" || !s["spec"]["selector"].as_object().map(|m| !m.is_empty()).unwrap_or(false) {
                    continue;
                }
                let (r, n) = ends.get(&(ns_of(s).to_string(), name_of(s).to_string())).copied().unwrap_or((0, 0));
                if r == 0 {
                    o.empty.push((ns_of(s).into(), name_of(s).into(), r, n));
                }
            }
            let down = o.empty.iter().filter(|e| e.3 > 0).count();
            if down > 0 {
                o.finds.push((Tone::Danger, format!("{} with no endpoint that's ready", many(down as i64, "service")), "see the list below".into(), None));
            }
        }
        let mut used: Vec<String> = vec![];
        for s in services.iter().flatten().filter(|s| s["spec"]["type"] == "LoadBalancer") {
            let ips: Vec<String> = s["status"]["loadBalancer"]["ingress"].as_array().into_iter().flatten().filter_map(|a| a["ip"].as_str().or(a["hostname"].as_str()).map(String::from)).collect();
            if ips.is_empty() && self.ns_ok(ns_of(s)) {
                o.finds.push((Tone::Danger, format!("Service {}/{} has no load balancer address yet", ns_of(s), name_of(s)), "nothing gave it one: no controller for it, or its addresses are used up".into(), Some(obj(ctx, Kind::Services, ns_of(s), name_of(s)))));
            }
            used.extend(ips);
        }
        used.sort();
        used.dedup();
        for p in self.kind_known(ctx, POOLS).unwrap_or_default() {
            if let Some(n) = pool_size(p) {
                let u = used.iter().filter(|i| in_pool(p, i)).count() as u64;
                o.facts.push((format!("Pool {}", name_of(p)), format!("{u} of {n} addresses in use")));
                // (A pool of a few is made for just those.)
                if n > 3 && u * 10 >= n * 9 {
                    o.finds.push((Tone::Warning, format!("Address pool {} is {}used up", name_of(p), if u < n { "nearly " } else { "" }), format!("{u} of {n} addresses"), self.custom_go(ctx, POOLS, p)));
                }
            }
        }
        // From Grafana, when it's set up.
        for n in self.grafana_nodes(ctx) {
            let name = n.kube.clone().unwrap_or(n.uname.clone());
            if let Some(c) = n.conntrack.filter(|c| *c > 0.8) {
                o.finds.push((if c > 0.95 { Tone::Danger } else { Tone::Warning }, format!("Node {name}: its table of connections is {:.0}% full", c * 100.0), "when it's full, new connections are dropped".into(), Some(obj(ctx, Kind::Nodes, "", &name))));
            }
            if let Some(d) = n.drops.filter(|d| *d > 10.0) {
                o.finds.push((Tone::Warning, format!("Node {name} drops {d:.0} packets a second"), "on its network cards; a few are normal".into(), Some(obj(ctx, Kind::Nodes, "", &name))));
            }
        }
        for k in self.netlab_kinds() {
            match self.missing(ctx, k) {
                Some(w) if w.starts_with("reading") => o.reading.push(k.label().to_string()),
                Some(w) => o.unread.push(w),
                None => {}
            }
        }
        for k in [CHECKS, OPERATORS] {
            if let Err(e) = self.kind_known(ctx, k) {
                if e == READING {
                    o.reading.push(k.split('.').next().unwrap_or(k).to_string());
                } else if !o.unread.contains(&e) {
                    o.unread.push(e);
                }
            }
        }
        o.finds.sort_by_key(|f| matches!(f.0, Tone::Warning));
        o
    }

    pub(super) fn netlab_loading(&self) -> bool {
        let wait = |c: &String| self.netlab_kinds().into_iter().any(|k| self.missing(c, k).map(|w| w.starts_with("reading")).unwrap_or(false)) || [CHECKS, OPERATORS, NETS].iter().any(|k| self.kind_known(c, k).err().as_deref() == Some(READING));
        self.view == View::NetLab && !self.demo && !self.power_off("netlab") && self.active.iter().any(wait)
    }

    fn net_over_kept(&mut self, ctx: &str) -> Over {
        if let Some((t, o)) = self.netlab.over.get(ctx) {
            if t.elapsed() < Duration::from_secs(if o.reading.is_empty() { 3 } else { 0 }) {
                return o.clone();
            }
        }
        let o = self.net_over(ctx);
        self.netlab.over.insert(ctx.to_string(), (Instant::now(), o.clone()));
        o
    }

    pub(super) fn netlab_view(&mut self, ui: &mut Ui) {
        if self.power_off("netlab") {
            self.header(ui, false, None, false);
            said(ui, "Network Lab is switched off in Settings > Superpowers.", TEXT_SUBTLE());
            return;
        }
        if self.screenshot.is_some() {
            if let Some(t) = std::env::var("KUBEDOG_SHOT_TAB").ok().and_then(|t| t.parse::<usize>().ok()) {
                self.netlab.tab = t.min(TABS.len() - 1);
            }
            // For pictures: made-up results from a file, nothing is tested.
            if self.netlab.done.is_empty() {
                if let Some(v) = std::env::var("KUBEDOG_SHOT_NETTEST").ok().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|t| serde_json::from_str::<Value>(&t).ok()) {
                    self.netlab.done = v.as_array().into_iter().flatten().filter_map(nettest::from_json).collect();
                    self.netlab.total = self.netlab.done.len();
                    self.netlab.open = std::env::var("KUBEDOG_SHOT_OBJ").ok().and_then(|t| t.parse().ok()).filter(|i| *i < self.netlab.done.len());
                }
            }
        }
        self.header(ui, true, Some("Network Lab".into()), true);
        let mut tab = self.netlab.tab;
        ui.horizontal(|ui| tab_strip(ui, &TABS, &mut tab));
        if tab != self.netlab.tab {
            self.netlab.tab = tab;
            self.refresh_current(false);
        }
        ui.add_space(8.0);
        // What packets say stays here: none of it is noted for AI.
        if tab == 4 {
            aipage::begin(false);
        }
        let mut go = None;
        self.page_scroll().id_salt(("netlab", tab)).show(ui, |ui| {
            go = match tab {
                0 => self.net_overview(ui),
                1 => self.net_computer(ui),
                2 => self.connection(ui),
                3 => self.net_from_pod(ui),
                _ => self.net_packets(ui),
            };
            ui.add_space(20.0);
        });
        if let Some(g) = go {
            self.go_to(g);
        }
    }

    fn net_overview(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        let ctxs: Vec<String> = self.active.iter().filter(|c| self.ctx_shown(c)).cloned().collect();
        let multi = ctxs.len() > 1;
        for c in &ctxs {
            let o = self.net_over_kept(c);
            let bad = o.finds.iter().filter(|f| f.0 == Tone::Danger).count();
            let warn = o.finds.len() - bad;
            let parts = o.parts.iter().filter(|p| p.want > 0).count();
            let nothing = o.parts.is_empty() && o.finds.is_empty() && !o.unread.is_empty();
            let f = Face {
                tone: if nothing || (!o.reading.is_empty() && o.finds.is_empty()) { Tone::Muted } else if bad > 0 { Tone::Danger } else if warn > 0 { Tone::Warning } else { Tone::Success },
                head: if !o.reading.is_empty() && o.finds.is_empty() { "Reading…".into() } else if nothing { "Not known".into() } else if bad > 0 { format!("{} wrong", many(bad as i64, "thing")) } else if warn > 0 { format!("{} to look at", many(warn as i64, "thing")) } else { "Nothing wrong that the cluster knows of".into() },
                sub: if multi { ctx_label(c) } else { "from what the cluster says itself; nothing is tried".into() },
                notes: o.finds.iter().take(2).map(|f| f.1.clone()).collect(),
                pills: vec![],
                facts: o.facts.iter().map(|(a, b)| Fact::new(a, b)).collect(),
            };
            face::show(ui, &f, Side::None);
            ui.add_space(10.0);
            let items: Vec<Item> = o.finds.iter().map(|f| Item::new(f.0, vec![f.1.clone(), f.2.clone()]).go(f.3.clone())).collect();
            let items = self.op_filter(items);
            go = table(ui, "To look at", "", &[("What", 0.5), ("More", 0.5)], &items, 40, if o.unread.is_empty() && o.reading.is_empty() { "Nothing." } else { "Nothing in what could be read." }).or(go);
            if !o.reading.is_empty() {
                said(ui, &format!("Still reading: {}.", o.reading.join(", ")), TEXT_PLACEHOLDER());
                ui.add_space(6.0);
            }
            if !o.unread.is_empty() {
                said(ui, &format!("Not read: {}.", o.unread.join("; ")), TEXT_PLACEHOLDER());
                ui.add_space(6.0);
            }
            let mut p: Vec<Item> = o
                .parts
                .iter()
                .map(|p| {
                    let t = if p.want == 0 { Tone::Muted } else if p.ready == 0 { Tone::Danger } else if p.ready < p.want || p.restarts > 0 { Tone::Warning } else { Tone::Success };
                    Item::new(t, vec![p.role.into(), format!("{}/{} ready", p.ready, p.want), p.name.clone(), p.ns.clone(), if p.restarts > 0 { format!("{} in the last day", many(p.restarts, "restart")) } else { String::new() }]).go(Some(obj(c, p.kind, &p.ns, &p.name)))
                })
                .collect();
            worst_first(&mut p);
            let p = self.op_filter(p);
            go = table(ui, &format!("What makes the network ({parts})"), "", &[("Part", 0.2), ("State", 0.16), ("What runs it", 0.26), ("Namespace", 0.22), ("Restarts", 0.16)], &p, 40, "Nothing that's known by its name, or your account can't see it.").or(go);
            let checks = self.kind_known(c, CHECKS).unwrap_or_default();
            if !checks.is_empty() {
                let now = kube::now_secs();
                let mut l: Vec<Item> = checks
                    .iter()
                    .map(|x| {
                        let (t, w, y) = check_state(x, now);
                        let to = name_of(x).split_once("-to-").map(|p| p.1).unwrap_or(name_of(x)).to_string();
                        Item::new(t, vec![to, w, text(&x["spec"]["targetEndpoint"]), y]).go(self.custom_go(c, CHECKS, x))
                    })
                    .collect();
                worst_first(&mut l);
                let l = self.op_filter(l);
                go = table(ui, &format!("OpenShift's own connection checks ({})", checks.len()), "a pod of OpenShift tries these all the time", &[("To", 0.34), ("State", 0.2), ("Address", 0.2), ("Outages", 0.26)], &l, 40, "None with this filter.").or(go);
            }
            let mut e: Vec<Item> = o.empty.iter().map(|(ns, n, r, all)| Item::new(if *all > 0 { Tone::Danger } else { Tone::Muted }, vec![format!("{ns}/{n}"), if *all > 0 { format!("{r}/{all} ready") } else { "no pod matches, or none is started".into() }]).go(Some(obj(c, Kind::Services, ns, n)))).collect();
            worst_first(&mut e);
            let e = self.op_filter(e);
            go = table(ui, &format!("Services with nothing behind them ({})", o.empty.len()), "grey: none is expected, when its app is scaled to zero", &[("Service", 0.5), ("Endpoints", 0.5)], &e, 30, "None.").or(go);
            // What else decides.
            let mut d: Vec<Item> = vec![Item::new(Tone::Muted, vec!["Network policies".into(), match self.refs(c, Kind::NetworkPolicies, "") { Some(l) => l.len().to_string(), None => self.missing(c, Kind::NetworkPolicies).unwrap_or("not known".into()) }, "what pods of a namespace may send and get".into()])];
            for (k, label, does) in DECIDERS {
                match self.kind_known(c, k) {
                    Ok([]) => {}
                    Ok(l) => d.push(Item::new(Tone::Muted, vec![label.to_string(), l.len().to_string(), does.to_string()]).go(if l.len() == 1 { self.custom_go(c, k, &l[0]) } else { None })),
                    Err(w) if w.contains("can't see") && !w.contains("which kinds") => d.push(Item::new(Tone::Muted, vec![label.to_string(), w, does.to_string()])),
                    Err(_) => {}
                }
            }
            go = table(ui, "What decides about traffic here", "only what there is", &[("Kind", 0.3), ("How many", 0.25), ("What they do", 0.45)], &d, 20, "").or(go);
        }
        ui.horizontal(|ui| {
            let i = powers::op_index("gateways");
            if i.is_some() && self.power_shown("gateways") && button(ui, "Every way in", false, false) {
                self.set_view(View::Op(i.unwrap()));
            }
            if button(ui, "Service map", false, false) {
                self.set_view(View::ServiceMap);
            }
        });
        go
    }

    // ---------- tests from this computer ----------

    /// Puts tests in line. Only from a click.
    fn net_test(&mut self, l: Vec<Target>) {
        if self.screenshot.is_some() || self.demo || l.is_empty() {
            return;
        }
        if self.netlab.queue.is_empty() && self.netlab.running == 0 {
            self.netlab.total = 0;
        }
        for t in l.into_iter().take(nettest::MOST.saturating_sub(self.netlab.queue.len())) {
            if !self.netlab.queue.contains(&t) {
                self.netlab.total += 1;
                self.netlab.queue.push_back(t);
            }
        }
        self.net_pump();
    }

    fn net_pump(&mut self) {
        while self.netlab.running < nettest::AT_ONCE {
            let Some(t) = self.netlab.queue.pop_front() else { return };
            self.netlab.running += 1;
            self.spawn(move |_| {
                // A test that breaks off still has to make room for the next.
                let r = std::panic::catch_unwind(|| nettest::to_json(&nettest::run(&t)).to_string());
                Msg::Text { key: "nettest|".into(), result: r.map_err(|_| "the test broke off".to_string()) }
            });
        }
    }

    pub(super) fn on_nettest(&mut self, key: &str, result: &Result<String, String>) -> bool {
        if key != "nettest|" {
            return false;
        }
        self.netlab.running = self.netlab.running.saturating_sub(1);
        if let Some(d) = result.as_ref().ok().and_then(|t| serde_json::from_str::<Value>(t).ok()).and_then(|v| nettest::from_json(&v)) {
            // The newest of an address takes the place of the old one.
            match self.netlab.done.iter_mut().find(|x| x.target.label() == d.target.label() && x.target.mode == d.target.mode) {
                Some(x) => *x = d,
                None => self.netlab.done.push(d),
            }
        }
        self.net_pump();
        true
    }

    /// What the open clusters publish, in the shown namespaces.
    fn net_published(&self) -> Vec<Target> {
        let mut v = vec![];
        for d in self.doors().into_iter().filter(|d| self.ns_ok(&d.ns)) {
            let expect = if d.kind == "Ingress" {
                self.refs(&d.ctx, Kind::Ingresses, &d.ns).unwrap_or_default().into_iter().find(|i| name_of(i) == d.name).map(|i| i["status"]["loadBalancer"]["ingress"].as_array().into_iter().flatten().filter_map(|a| a["ip"].as_str().map(String::from)).collect()).unwrap_or_default()
            } else {
                vec![]
            };
            v.extend(door_target(&d, expect));
        }
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            for s in self.refs(c, Kind::Services, "").unwrap_or_default().into_iter().filter(|s| s["spec"]["type"] == "LoadBalancer" && self.ns_ok(ns_of(s))) {
                v.extend(lb_targets(s));
            }
        }
        once(v)
    }

    fn net_computer(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut start: Vec<Target> = vec![];
        if let Some(d) = self.netlab.open.and_then(|i| self.netlab.done.get(i)).cloned() {
            let mut close = false;
            ui.horizontal(|ui| {
                close = button(ui, "← All tests", false, false);
                if button(ui, "Test again", false, false) {
                    start.push(d.target.clone());
                }
            });
            ui.add_space(8.0);
            result_page(ui, &d);
            if close {
                self.netlab.open = None;
            }
            self.net_test(start);
            return None;
        }
        card(ui, |ui| {
            panel(ui, "Test an address", "a name, host:port, or https://host/path");
            ui.horizontal(|ui| {
                let r = filter_box(ui, &mut self.netlab.typed, "web.example.com", u(380.0));
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                if button(ui, "Test", true, false) || enter {
                    match nettest::read_target(&self.netlab.typed) {
                        Ok(t) => {
                            self.netlab.error.clear();
                            start.push(t);
                        }
                        Err(e) => self.netlab.error = e,
                    }
                }
            });
            if !self.netlab.error.is_empty() {
                said(ui, &self.netlab.error, DANGER());
            }
            said(ui, "It goes out from this computer, with its DNS and VPN and straight, without a web proxy: others can see something else. Only what you click is tested. Certificates are always checked, and nothing is sent over one that isn't good. The page itself isn't read.", TEXT_PLACEHOLDER());
        });
        ui.add_space(10.0);
        // Results, the worst first.
        let busy = self.netlab.running + self.netlab.queue.len();
        if !self.netlab.done.is_empty() || busy > 0 {
            let mut clear = false;
            let mut again = false;
            let mut stop = false;
            card(ui, |ui| {
                let (bad, warn) = (self.netlab.done.iter().filter(|d| d.tone() == Tone::Danger).count(), self.netlab.done.iter().filter(|d| d.tone() == Tone::Warning).count());
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Results").size(z(14.5)).strong().color(TEXT_DEFAULT()));
                    for (n, w, c) in [(bad, "failed", DANGER()), (warn, "to look at", WARNING()), (self.netlab.done.len() - bad - warn, "fine", SUCCESS())] {
                        if n > 0 {
                            pill(ui, &format!("{n} {w}"), c);
                        }
                    }
                    if busy > 0 {
                        ui.spinner();
                        ui.label(RichText::new(format!("{busy} of {} to go", self.netlab.total)).size(z(12.5)).color(TEXT_MUTED()));
                        stop = button(ui, "Stop", false, false);
                    } else {
                        again = button(ui, "Test these again", false, false);
                        clear = button(ui, "Clear", false, false);
                    }
                });
                ui.add_space(6.0);
                ui.spacing_mut().item_spacing.y = 0.0;
                let mut order: Vec<usize> = (0..self.netlab.done.len()).collect();
                order.sort_by_key(|i| {
                    let d = &self.netlab.done[*i];
                    (match d.tone() { Tone::Danger => 0, Tone::Warning => 1, _ => 2 }, d.target.label())
                });
                for i in order {
                    let d = &self.netlab.done[i];
                    let (r, resp) = line(ui, u(30.0), true);
                    ui.painter().circle_filled(egui::pos2(r.left() + u(5.0), r.center().y), u(4.5), tone_color(d.tone()));
                    let w = r.width() - u(18.0);
                    let x = r.left() + u(18.0);
                    label_at(ui, ui.painter(), egui::pos2(x, r.center().y), &d.target.label(), 13.0, PRIMARY_TEXT(), w * 0.36);
                    let h = d.head().map(|s| format!("{}: {}", s.what, s.said)).unwrap_or_default();
                    label_at(ui, ui.painter(), egui::pos2(x + w * 0.37, r.center().y), &h, 12.5, if d.tone() == Tone::Success { TEXT_MUTED() } else { tone_color(d.tone()) }, w * 0.38);
                    label_at(ui, ui.painter(), egui::pos2(x + w * 0.76, r.center().y), &d.target.of, 12.0, TEXT_SUBTLE(), w * 0.16);
                    dash::at_end(ui, r, 1.0, &format!("{} ms", d.ms()), 12.0, TEXT_SUBTLE());
                    let tip = d.steps.iter().map(|s| format!("{}: {}", s.what, s.said)).collect::<Vec<_>>().join("\n");
                    if resp.on_hover_text(format!("{}\n{tip}", d.target.label())).clicked() {
                        self.netlab.open = Some(i);
                    }
                }
            });
            if again {
                start.extend(self.netlab.done.iter().map(|d| d.target.clone()));
            }
            if clear {
                self.netlab.done.clear();
            }
            if stop {
                self.netlab.queue.clear();
            }
            ui.add_space(10.0);
        }
        // What the cluster publishes.
        let all = self.net_published();
        let q = self.search.to_lowercase();
        let l: Vec<&Target> = all.iter().filter(|t| q.is_empty() || t.label().to_lowercase().contains(&q) || t.of.to_lowercase().contains(&q)).collect();
        card(ui, |ui| {
            let n = l.len().min(nettest::MOST);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(format!("What the cluster publishes ({})", l.len())).size(z(14.5)).strong().color(TEXT_DEFAULT()));
                ui.label(RichText::new("routes, ingresses, HTTP routes and load balancers; click one to test it").size(z(11.5)).color(TEXT_PLACEHOLDER()));
                if n > 0 && busy == 0 && button(ui, &if n == 1 { "Test it".to_string() } else { format!("Test all {n}") }, false, false) {
                    start.extend(l.iter().take(n).map(|t| (*t).clone()));
                }
            });
            ui.add_space(4.0);
            ui.spacing_mut().item_spacing.y = 0.0;
            if l.is_empty() {
                said(ui, if all.is_empty() { "Nothing, in the namespaces that are shown." } else { "None with this filter." }, TEXT_SUBTLE());
            }
            for t in l.iter().take(150) {
                let (r, resp) = line(ui, u(27.0), true);
                label_at(ui, ui.painter(), egui::pos2(r.left(), r.center().y), &t.label(), 13.0, PRIMARY_TEXT(), r.width() * 0.5);
                label_at(ui, ui.painter(), egui::pos2(r.left() + r.width() * 0.51, r.center().y), t.mode.word(), 12.0, TEXT_SUBTLE(), r.width() * 0.1);
                label_at(ui, ui.painter(), egui::pos2(r.left() + r.width() * 0.62, r.center().y), &t.of, 12.5, TEXT_MUTED(), r.width() * 0.38);
                if resp.on_hover_text(format!("Test {}", t.label())).clicked() {
                    start.push((*t).clone());
                }
            }
            if l.len() > 150 {
                said(ui, &format!("and {} more: filter to see them", l.len() - 150), TEXT_PLACEHOLDER());
            }
        });
        self.net_test(start);
        None
    }
}

/// One test in full: its steps after each other, and the certificates that were shown.
fn result_page(ui: &mut Ui, d: &Done) {
    let now = kube::now_secs();
    let h = d.head().cloned();
    let f = Face {
        tone: d.tone(),
        head: match (&h, d.tone()) {
            (Some(s), Tone::Danger) => format!("It stops at the {}", if s.what == "TLS" { s.what.to_string() } else { s.what.to_lowercase() }),
            (_, Tone::Warning) => "It works, with something to look at".into(),
            _ => "It works".into(),
        },
        sub: format!("{}, {}", d.target.label(), ago(now, Some(d.at))),
        notes: h.filter(|_| d.tone() != Tone::Success).map(|s| vec![s.said]).unwrap_or_default(),
        pills: vec![],
        facts: vec![Fact::new("Tested", d.target.mode.word()), Fact::new("Of", d.target.of.clone()), Fact::new("Time", format!("{} ms", d.ms()))],
    };
    face::show(ui, &f, Side::None);
    ui.add_space(10.0);
    card(ui, |ui| {
        panel(ui, "Step by step", "");
        steps(ui, d);
    });
    ui.add_space(10.0);
    if !d.chain.is_empty() {
        card(ui, |ui| {
            panel(ui, "Certificates the server showed", "its own first");
            for (i, c) in d.chain.iter().enumerate() {
                let (w, t) = certs::verdict(c, now);
                ui.horizontal_wrapped(|ui| {
                    ui.add_space(u(16.0) * i as f32);
                    ui.label(RichText::new(if c.subject.is_empty() { &c.subject_full } else { &c.subject }).size(z(13.5)).color(TEXT_DEFAULT()));
                    pill(ui, w, tone_color(t));
                });
                let names: Vec<&str> = c.alt_names.iter().filter(|n| matches!(n.0, "DNS" | "IP")).map(|n| n.1.as_str()).collect();
                let mut l = vec![format!("signed by {}", if c.issuer_full == c.subject_full { "itself".to_string() } else if c.issuer.is_empty() { c.issuer_full.clone() } else { c.issuer.clone() })];
                if let Some(t) = c.not_after {
                    l.push(format!("until {} ({})", netmap::iso_date(t), ago(now, Some(t))));
                }
                if !c.key.is_empty() {
                    l.push(c.key.clone());
                }
                if !names.is_empty() {
                    l.push(format!("for {}", names.iter().take(8).copied().collect::<Vec<_>>().join(", ") + if names.len() > 8 { "…" } else { "" }));
                }
                ui.horizontal_wrapped(|ui| {
                    ui.add_space(u(16.0) * i as f32);
                    ui.label(RichText::new(l.join("   ·   ")).size(z(12.0)).color(TEXT_SUBTLE())).on_hover_text(c.subject_full.clone());
                });
                ui.add_space(6.0);
            }
        });
    }
}

/// The steps as a stair: when each began and how long it took.
fn steps(ui: &mut Ui, d: &Done) {
    let total = d.ms().max(1) as f32;
    let mut begin = 0.0;
    let all: &[(&str, Mode)] = &[("Name", Mode::Tcp), ("Connection", Mode::Tcp), ("TLS", Mode::Tls), ("Answer", Mode::Http)];
    let wanted = |w: &str| match w {
        "Name" => d.steps.iter().any(|s| s.what == "Name"),
        "TLS" => matches!(d.target.mode, Mode::Tls | Mode::Https),
        "Answer" => matches!(d.target.mode, Mode::Http | Mode::Https),
        _ => true,
    };
    for (what, _) in all.iter().filter(|x| wanted(x.0)) {
        let s: Option<&Step> = d.steps.iter().find(|s| s.what == *what);
        let (r, _) = line(ui, u(30.0), false);
        let col = s.map(|s| tone_color(s.tone)).unwrap_or(TEXT_PLACEHOLDER());
        ui.painter().circle_filled(egui::pos2(r.left() + u(6.0), r.center().y), u(5.0), if s.is_some() { col } else { BG_MUTED() });
        label_at(ui, ui.painter(), egui::pos2(r.left() + u(20.0), r.center().y), what, 13.0, if s.is_some() { TEXT_DEFAULT() } else { TEXT_PLACEHOLDER() }, u(90.0));
        let words = s.map(|s| s.said.clone()).unwrap_or("not reached".into());
        let left = r.left() + u(112.0);
        let w = r.right() - left;
        label_at(ui, ui.painter(), egui::pos2(left, r.center().y), &words, 13.0, s.filter(|s| s.tone != Tone::Success).map(|s| tone_color(s.tone)).unwrap_or(TEXT_MUTED()), w * 0.66);
        if let Some(ms) = s.and_then(|s| s.ms) {
            let track = egui::Rect::from_min_max(egui::pos2(left + w * 0.69, r.center().y - u(4.0)), egui::pos2(r.right() - u(64.0), r.center().y + u(4.0)));
            ui.painter().rect_filled(track, CornerRadius::same(4), BG_MUTED());
            let x0 = track.left() + track.width() * begin / total;
            let x1 = (track.left() + track.width() * (begin + ms as f32) / total).max(x0 + 3.0).min(track.right().max(x0 + 3.0));
            ui.painter().rect_filled(egui::Rect::from_min_max(egui::pos2(x0, track.top()), egui::pos2(x1, track.bottom())), CornerRadius::same(4), col);
            dash::at_end(ui, r, 1.0, &format!("{ms} ms"), 12.0, TEXT_SUBTLE());
            begin += ms as f32;
        }
        for m in s.iter().flat_map(|s| &s.more) {
            ui.horizontal_wrapped(|ui| {
                ui.add_space(u(112.0));
                ui.label(RichText::new(m).size(z(12.0)).color(TEXT_SUBTLE()));
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn networks_and_parts() {
        assert_eq!(cni(&["node-exporter", "ovnkube-node"]), Some("OVN-Kubernetes"));
        assert_eq!(cni(&["kube-flannel-ds"]), Some("Flannel"));
        assert_eq!(cni(&["cilium"]), Some("Cilium"));
        assert_eq!(cni(&["web", "ciliumish"]), None);
        assert_eq!(keeps_policies(Some("Flannel")), Some(false));
        assert_eq!(keeps_policies(None), None);
        assert_eq!(role("kube-system", "coredns"), Some("DNS"));
        assert_eq!(role("openshift-ingress", "router-default"), Some("Ways in"));
        assert_eq!(role("shop", "router-default"), None);
        assert_eq!(role("metallb-system", "metallb-speaker"), Some("Load balancer addresses"));
        assert_eq!(role("shop", "speaker"), None);
        assert_eq!(role("shop", "sdn"), None);
        assert_eq!(role("kube-system", "kube-proxy"), Some("Services"));
    }

    #[test]
    fn own_checks() {
        let now = kube::parse_time("2026-11-24T12:00:00Z").unwrap();
        let c = |s: &str, out: Value| json!({"status": {"conditions": [{"type": "Reachable", "status": s, "message": "no answer"}], "outages": out}});
        assert_eq!(check_state(&c("True", json!(null)), now), (Tone::Success, "reachable".into(), String::new()));
        assert_eq!(check_state(&c("False", json!([])), now), (Tone::Danger, "not reachable".into(), "no answer".into()));
        let r = check_state(&c("True", json!([{"start": "2026-11-24T10:00:00Z", "end": "2026-11-24T10:01:00Z"}, {"start": "2026-11-01T10:00:00Z", "end": "2026-11-01T10:01:00Z"}])), now);
        assert_eq!((r.0, r.1.as_str()), (Tone::Warning, "1 outage in the last day"));
        assert!(r.2.ends_with("2 on record"));
        // An old one only: fine, and it's said.
        let r = check_state(&c("True", json!([{"start": "2026-11-01T10:00:00Z", "end": "2026-11-01T10:01:00Z"}])), now);
        assert_eq!(r.0, Tone::Success);
        assert_eq!(check_state(&json!({}), now).0, Tone::Muted);
    }

    #[test]
    fn pools() {
        let p = |l: Value| json!({"spec": {"addresses": l}});
        assert_eq!(pool_size(&p(json!(["192.0.2.0/28", "198.51.100.10-198.51.100.19"]))), Some(26));
        assert_eq!(pool_size(&p(json!(["2001:db8::/64"]))), None);
        assert_eq!(pool_size(&p(json!(["192.0.2.9-192.0.2.1"]))), None);
        assert_eq!(pool_size(&p(json!(["192.0.2.0/99"]))), None);
        let x = p(json!(["192.0.2.0/28", "198.51.100.10-198.51.100.19"]));
        assert!(in_pool(&x, "192.0.2.15") && in_pool(&x, "198.51.100.19"));
        assert!(!in_pool(&x, "192.0.2.16") && !in_pool(&x, "198.51.100.20") && !in_pool(&x, "lb.example.com"));
    }

    #[test]
    fn endpoint_counts() {
        let s = |svc: &str, e: Value| json!({"metadata": {"namespace": "shop", "labels": {"kubernetes.io/service-name": svc}}, "endpoints": e});
        let a = s("web", json!([{"targetRef": {"name": "web-1"}, "conditions": {"ready": true}}, {"targetRef": {"name": "web-2"}, "conditions": {"ready": false}}]));
        // The same pods again, for IPv6.
        let b = s("web", json!([{"targetRef": {"name": "web-1"}, "conditions": {"ready": true}}]));
        let m = endpoints(&[&a, &b]);
        assert_eq!(m[&("shop".to_string(), "web".to_string())], (1, 2));
        assert!(!m.contains_key(&("shop".to_string(), "db".to_string())));
    }

    #[test]
    fn what_to_test() {
        let d = |host: &str, path: &str, tls| opnet::Door { ctx: "c".into(), ns: "shop".into(), kind: "Route", name: "web".into(), host: host.into(), path: path.into(), service: "web".into(), tls, taken: true };
        assert_eq!(door_target(&d("Web.example.com", "/", true), vec![]).unwrap().label(), "https://web.example.com/");
        assert_eq!(door_target(&d("web.example.com", "/api(/|$)(.*)", false), vec![]).unwrap().label(), "http://web.example.com/");
        assert!(door_target(&d("*.example.com", "/", true), vec![]).is_none());
        assert!(door_target(&d("", "/", true), vec![]).is_none());
        let s = json!({"metadata": {"name": "lb", "namespace": "shop"}, "spec": {"ports": [{"port": 5432}, {"port": 53, "protocol": "UDP"}]}, "status": {"loadBalancer": {"ingress": [{"ip": "192.0.2.7"}, {"ip": "2001:db8::7"}]}}});
        assert_eq!(lb_targets(&s).iter().map(|t| t.label()).collect::<Vec<_>>(), vec!["192.0.2.7:5432", "[2001:db8::7]:5432"]);
        assert!(lb_targets(&s).iter().all(|t| t.mode == Mode::Tcp));
        assert_eq!(once(lb_targets(&s).into_iter().chain(lb_targets(&s)).collect()).len(), 2);
    }
}
