//! Network Lab: the path as OVN-Kubernetes itself computes it. `ovn-trace` runs in the OVN pod of the
//! sender's node (kubectl exec, behind the lock and a confirmation), for a made-up packet: nothing is
//! sent. The answer is read loosely, and its whole text is always there to look at.

use super::dash::line;
use super::incident::chip_button;
use super::netpath::{self, End};
use super::nettry::Ran;
use super::ops::{ago, text};
use super::pg::{label_at, panel, pill};
use super::work::{name_of, said};
use super::*;
use std::net::IpAddr;

/// Where OVN-Kubernetes lives.
const HOMES: [&str; 2] = ["openshift-ovn-kubernetes", "ovn-kubernetes"];

/// What runs in the OVN pod: the trace, then, for the rules it met, whose they are. The switch, the packet
/// and the backend are arguments. A connection is tracked several times on its way: each time it's new.
const SCRIPT: &str = r#"s=$1; f=$2; l=$3
n="--ct new"; set -- $n $n $n $n $n $n $n $n
if [ "$l" != "-" ]; then set -- "$@" "--lb-dst=$l"; fi
o=$(timeout 20 ovn-trace --no-leader-only "$@" "$s" "$f" 2>&1); e=$?
printf '%s\n' "$o"
echo "KD end $e"
for u in $(printf '%s\n' "$o" | sed -n 's/.*_acl_eval .*uuid \([0-9a-f]*\).*/\1/p' | sort -u | head -n 20); do
h=$(timeout 5 ovn-sbctl --no-leader-only --bare --columns=external_ids list logical_flow "$u" 2>/dev/null | sed -n 's/.*stage-hint=\([0-9a-f]*\).*/\1/p')
if [ -n "$h" ]; then echo "KD acl $u"; timeout 5 ovn-nbctl --no-leader-only --format=json --columns=name,external_ids,priority,action,match list ACL "$h" 2>/dev/null; fi
done
echo "KD done"
"#;

/// A trace to run.
#[derive(Clone, PartialEq, Debug)]
pub(super) struct Ask {
    pub ctx: String,
    pub home: String,
    pub ovn_pod: String,
    pub container: String,
    pub switch: String,
    pub packet: String,
    pub lb: Option<String>,
    /// In words, for the page and the list.
    pub what: String,
    pub key: String,
}

impl Ask {
    fn args(&self) -> Vec<String> {
        ["--context", &self.ctx, "-n", &self.home, "exec", &self.ovn_pod, "-c", &self.container, "--", "sh", "-c", SCRIPT, "trace", &self.switch, &self.packet, self.lb.as_deref().unwrap_or("-")].iter().map(|s| s.to_string()).collect()
    }
}

/// The address of a network card that OVN-Kubernetes gives an IPv4 address.
fn mac_of(ip: &str) -> Option<String> {
    let a: std::net::Ipv4Addr = ip.parse().ok()?;
    let o = a.octets();
    Some(format!("0a:58:{:02x}:{:02x}:{:02x}:{:02x}", o[0], o[1], o[2], o[3]))
}

fn good_mac(m: &str) -> bool {
    m.len() == 17 && m.split(':').count() == 6 && m.split(':').all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A name that can stand in a packet's description.
fn good_name(n: &str) -> bool {
    !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
}

/// What's known of a pod's network card: (its MAC, its address, its gateway).
fn card_of(p: &Value) -> Result<(String, String, String), String> {
    let a: Value = p["metadata"]["annotations"]["k8s.ovn.org/pod-networks"].as_str().and_then(|t| serde_json::from_str(t).ok()).ok_or("OVN didn't note the pod's address")?;
    if a.as_object().map(|m| m.iter().any(|(k, v)| k != "default" && v["role"] == "primary")).unwrap_or(false) {
        return Err("the pod is on a network of its own; that can't be traced here yet".into());
    }
    let d = &a["default"];
    let ip = text(&d["ip_address"]);
    let ip = ip.split('/').next().unwrap_or("").to_string();
    let (mac, gw) = (text(&d["mac_address"]), text(&d["gateway_ip"]));
    if !good_mac(&mac) || ip.parse::<std::net::Ipv4Addr>().is_err() || gw.parse::<std::net::Ipv4Addr>().is_err() {
        return Err("only IPv4 can be traced here".into());
    }
    Ok((mac, ip, gw))
}

/// The packet, as ovn-trace takes it.
pub(super) fn packet(from: &Value, to_ip: &str, to_mac: Option<&str>, port: i64, proto: &str) -> Result<String, String> {
    let (mac, ip, gw) = card_of(from)?;
    let (ns, name) = (from["metadata"]["namespace"].as_str().unwrap_or(""), name_of(from));
    if !good_name(ns) || !good_name(name) {
        return Err("that pod's name can't be used".into());
    }
    match to_ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => {}
        Ok(_) => return Err("only IPv4 can be traced here".into()),
        Err(_) => return Err("give an address: names aren't looked up here".into()),
    }
    let dst = match to_mac.filter(|m| good_mac(m)) {
        Some(m) => m.to_string(),
        None => mac_of(&gw).ok_or("the pod's gateway isn't known")?,
    };
    let p = match proto {
        "TCP" => "tcp",
        "UDP" => "udp",
        _ => return Err("only TCP and UDP can be traced here".into()),
    };
    Ok(format!("inport==\"{ns}_{name}\" && eth.src=={mac} && eth.dst=={dst} && ip4.src=={ip} && ip4.dst=={to_ip} && ip.ttl==64 && {p} && {p}.src==52888 && {p}.dst=={port}"))
}

// ---------- reading what came back ----------

/// A rule that the packet met.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Rule {
    pub action: String,
    /// Whose it is, in words.
    pub of: String,
    pub priority: i64,
    pub matches: String,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Ending {
    /// To a pod's port.
    Delivered(String),
    /// To another node, or out.
    Leaves(String, String),
    Dropped(String),
    Refused,
    Unknown(String),
}

#[derive(Clone, Debug)]
pub(super) struct Traced {
    /// Switches and routers it passed: (name, from, to).
    pub hops: Vec<(String, String, String)>,
    pub rules: Vec<Rule>,
    pub end: Ending,
    pub raw: String,
}

fn quoted(l: &str, key: &str) -> String {
    l.split(&format!("{key}=\"")).nth(1).and_then(|r| r.split('"').next()).unwrap_or("").to_string()
}

/// Whose rule it is, from what OVN-Kubernetes notes with it.
fn owner(name: &str, ids: &HashMap<String, String>) -> String {
    let n = ids.get("k8s.ovn.org/name").cloned().unwrap_or_default();
    let kind = ids.get("k8s.ovn.org/owner-type").map(|s| s.as_str()).unwrap_or("");
    let way = ids.get("direction").map(|d| format!(", {}", d.to_lowercase())).unwrap_or_default();
    let what = match kind {
        "NetworkPolicy" => format!("network policy {}", n.replacen(':', "/", 1)),
        "NetpolNamespace" => format!("the closed door that network policies in {n} make"),
        "AdminNetworkPolicy" => format!("admin network policy {n}"),
        "BaselineAdminNetworkPolicy" => "the baseline admin network policy".to_string(),
        "EgressFirewall" => format!("the egress firewall of {n}"),
        "NetpolNode" => "what nodes may always do".to_string(),
        "" if !name.is_empty() => format!("rule {name}"),
        "" => "a rule without a name".to_string(),
        k => format!("{k} {n}"),
    };
    format!("{what}{way}")
}

/// An answer of `ovn-nbctl --format=json list ACL`.
fn read_rule(t: &str) -> Option<Rule> {
    let v: Value = serde_json::from_str(t.trim()).ok()?;
    let heads: Vec<&str> = v["headings"].as_array()?.iter().filter_map(|h| h.as_str()).collect();
    let row = v["data"].as_array()?.first()?;
    let at = |k: &str| heads.iter().position(|h| *h == k).map(|i| &row[i]).unwrap_or(&Value::Null);
    let ids: HashMap<String, String> = at("external_ids")[1].as_array().into_iter().flatten().filter_map(|p| Some((p[0].as_str()?.to_string(), p[1].as_str()?.to_string()))).collect();
    Some(Rule { action: text(at("action")), of: owner(at("name").as_str().unwrap_or(""), &ids), priority: at("priority").as_i64().unwrap_or(0), matches: text(at("match")) })
}

pub(super) fn read(out: &str) -> Traced {
    let (body, tail) = out.split_once("KD end ").unwrap_or((out, ""));
    let body = body.trim_end().to_string();
    // Whose the rules are, by the flow they were met as.
    let mut known: HashMap<String, Rule> = HashMap::new();
    let mut id = String::new();
    for l in tail.lines() {
        if let Some(u) = l.strip_prefix("KD acl ") {
            id = u.trim().to_string();
        } else if let Some(r) = read_rule(l) {
            known.insert(id.clone(), r);
        }
    }
    let mut t = Traced { hops: vec![], rules: vec![], end: Ending::Unknown(String::new()), raw: body.clone() };
    let mut end: Option<Ending> = None;
    let mut stage = String::new();
    for l in body.lines() {
        let s = l.trim();
        if l.starts_with("ingress(dp=") {
            // What comes after a refusal is the refusal on its way back.
            if end == Some(Ending::Refused) {
                break;
            }
            t.hops.push((quoted(l, "dp"), quoted(l, "inport"), String::new()));
            end = None;
        } else if l.starts_with("egress(dp=") {
            if end == Some(Ending::Refused) {
                break;
            }
            if let Some(h) = t.hops.last_mut() {
                h.2 = quoted(l, "outport");
            }
            end = None;
        } else if s.contains(" (northd.c") || s.contains("priority ") && s.contains(", uuid ") {
            stage = s.split_whitespace().nth(1).unwrap_or("").to_string();
            if stage.ends_with("_acl_eval") {
                if let Some(r) = s.split("uuid ").nth(1).and_then(|u| known.get(u.split_whitespace().next().unwrap_or(""))) {
                    t.rules.push(r.clone());
                }
            }
        } else if s.starts_with("reject {") || s.starts_with("tcp_reset") {
            end = Some(Ending::Refused);
        } else if s == "drop;" {
            end = Some(Ending::Dropped(stage.clone()));
        } else if let Some(r) = s.strip_prefix("/* output to \"") {
            let port = r.split('"').next().unwrap_or("").to_string();
            let kind = quoted(&s.replace("type \"", "type=\""), "type");
            end = Some(match kind.as_str() {
                "" | "virtual" => Ending::Delivered(port),
                "patch" | "router" | "l3gateway" => Ending::Dropped(String::new()),
                k => Ending::Leaves(port, k.to_string()),
            });
        }
    }
    t.end = match end {
        _ if t.hops.is_empty() => Ending::Unknown(truncate(body.lines().find(|l| !l.trim().is_empty() && !l.starts_with('#')).unwrap_or("nothing came back"), 200)),
        Some(Ending::Dropped(s)) if s.is_empty() => Ending::Unknown("it ends between two parts of the network".into()),
        Some(e) => e,
        // It stops without going anywhere.
        None => Ending::Dropped(stage),
    };
    t
}

/// The rule that stopped it, if it's one of those it met.
fn culprit(t: &Traced) -> Option<&Rule> {
    if !matches!(t.end, Ending::Dropped(_) | Ending::Refused) {
        return None;
    }
    t.rules.last().filter(|r| matches!(r.action.as_str(), "drop" | "reject"))
}

/// In a sentence.
pub(super) fn sentence(t: &Traced) -> (Tone, String) {
    match (&t.end, culprit(t)) {
        (Ending::Dropped(_), Some(r)) => (Tone::Danger, format!("OVN drops it: {}", r.of)),
        (Ending::Refused, Some(r)) => (Tone::Danger, format!("OVN refuses it: {}", r.of)),
        (Ending::Refused, None) => (Tone::Danger, "OVN refuses it".into()),
        (Ending::Dropped(s), None) if s.contains("ip_routing") => (Tone::Danger, "OVN drops it: no route for that address".into()),
        (Ending::Dropped(s), None) if s.contains("port_sec") => (Tone::Danger, "OVN drops it: not the address this pod should have".into()),
        (Ending::Dropped(s), None) => (Tone::Danger, format!("OVN drops it{}", if s.is_empty() { String::new() } else { format!(" (in {s})") })),
        (Ending::Delivered(p), _) => (Tone::Success, format!("OVN delivers it to {}", p.replacen('_', "/", 1))),
        // Every node has its own copy of the rules: the receiver's aren't in this one.
        (Ending::Leaves(p, k), _) if k == "remote" => (Tone::Muted, format!("Nothing stops it on this node; OVN passes it to {}, and what the rules there say isn't known", p.strip_prefix("tstor-").unwrap_or(p))),
        (Ending::Leaves(p, k), _) => (Tone::Success, match k.as_str() {
            "localnet" => "OVN sends it out of the node".into(),
            k => format!("OVN passes it on through {p} ({k})"),
        }),
        (Ending::Unknown(w), _) => (Tone::Muted, if w.is_empty() { "Not known".into() } else { format!("Not known: {w}") }),
    }
}

#[derive(Default)]
pub(super) struct Traces {
    running: HashMap<String, Ask>,
    done: HashMap<String, (i64, Result<Traced, String>)>,
    raw: bool,
}

impl KubedogApp {
    /// The OVN pod of a node.
    fn ovn_pod(&self, ctx: &str, node: &str) -> Option<&Value> {
        HOMES.iter().find_map(|h| self.refs(ctx, Kind::Pods, h)?.into_iter().find(|p| p["metadata"]["labels"]["app"] == "ovnkube-node" && p["spec"]["nodeName"].as_str() == Some(node) && p["status"]["phase"] == "Running"))
    }

    /// What to ask OVN about a path; why not, if it can't.
    fn make_trace(&self, ctx: &str, a: &End, b: &End, port: i64, proto: &str) -> Result<Ask, String> {
        if self.net_name(ctx).as_deref() != Some("OVN-Kubernetes") {
            return Err(String::new());
        }
        let End::Object(from) = a else { return Err("only from a pod".into()) };
        let path = self.net_path(ctx, a, b, port, proto);
        let Some(p) = &path.from_pod else { return Err("there's no running pod to start from".into()) };
        if p["spec"]["hostNetwork"] == true {
            return Err("the pod uses its node's own network, which OVN doesn't make".into());
        }
        let node = text(&p["spec"]["nodeName"]);
        let Some(o) = self.ovn_pod(ctx, &node) else { return Err("the OVN pod of its node can't be seen with this account".into()) };
        let mut lb = None;
        let (ip, mac) = match b {
            End::Address(h) => (h.clone(), None),
            End::Outside => return Err("give an address".into()),
            End::Object(s) => {
                let pb = self.pod_at(s);
                let svc = (s.kind == Kind::Services).then(|| self.object_of(s)).flatten();
                match (&svc, pb) {
                    (Some(v), _) if v["spec"]["clusterIP"].as_str().map(|c| c != "None").unwrap_or(false) => {
                        // The backend that the service's balancing picks.
                        if let Some(i) = pb.and_then(|p| p["status"]["podIP"].as_str()) {
                            lb = Some(format!("{i}:{}", path.target));
                        }
                        (text(&v["spec"]["clusterIP"]), None)
                    }
                    (_, Some(p)) if p["spec"]["hostNetwork"] != true => {
                        let i = text(&p["status"]["podIP"]);
                        // On the same node it goes straight to the pod.
                        let near = p["spec"]["nodeName"].as_str() == Some(&node);
                        let m = near.then(|| mac_of(&i)).flatten();
                        (i, m)
                    }
                    (_, Some(p)) => (text(&p["status"]["podIP"]), None),
                    _ => return Err("the other end has no pod".into()),
                }
            }
        };
        if let Some(l) = &lb {
            if l.parse::<std::net::SocketAddrV4>().is_err() {
                return Err("only IPv4 can be traced here".into());
            }
        }
        let packet = packet(p, &ip, mac.as_deref(), port, proto)?;
        if !good_name(&node) {
            return Err("that node's name can't be used".into());
        }
        let cs: Vec<&str> = o["spec"]["containers"].as_array().into_iter().flatten().filter_map(|c| c["name"].as_str()).collect();
        let container = ["sbdb", "ovn-controller", "ovnkube-controller"].into_iter().find(|c| cs.contains(c)).or(cs.first().copied()).unwrap_or("").to_string();
        let to = match b {
            End::Object(s) => format!("{}/{}", s.ns, s.name),
            End::Address(h) => h.clone(),
            End::Outside => String::new(),
        };
        let what = format!("from {}/{} to {to}, port {port}", from.ns, name_of(p));
        Ok(Ask { ctx: ctx.into(), home: text(&o["metadata"]["namespace"]), ovn_pod: name_of(o).into(), container, switch: node, packet, lb, key: format!("{ctx}|{what}|{proto}"), what })
    }

    /// Only after a confirmation.
    pub(super) fn start_trace(&mut self, a: Ask) {
        self.netlab.tries.ran.push(Ran { at: kube::now_secs(), ctx: a.ctx.clone(), what: format!("OVN trace {}", a.what), place: format!("pod {}/{}, container {}", a.home, a.ovn_pod, a.container) });
        let (key, args) = (a.key.clone(), a.args());
        self.netlab.traces.running.insert(key.clone(), a);
        self.spawn(move |k| Msg::Text { key: format!("ovntrace|{key}"), result: k.run_for(&args, Duration::from_secs(150)) });
    }

    pub(super) fn on_trace(&mut self, key: &str, r: &Result<String, String>) -> bool {
        let Some(k) = key.strip_prefix("ovntrace|") else { return false };
        self.netlab.traces.running.remove(k);
        let v = match r {
            Ok(o) => Ok(read(o)),
            Err(e) if is_refusal(e) => Err("your account may not run commands in OVN's pods".into()),
            Err(e) => Err(truncate(e, 200)),
        };
        self.netlab.traces.done.insert(k.to_string(), (kube::now_secs(), v));
        true
    }

    /// The button and what came of it, under a path.
    pub(super) fn trace_part(&mut self, ui: &mut Ui, ctx: &str, a: &End, b: &End, port: i64, proto: &str) {
        let ask = match self.make_trace(ctx, a, b, port, proto) {
            Ok(x) => x,
            Err(e) => {
                if !e.is_empty() {
                    said(ui, &format!("OVN can't be asked: {e}."), TEXT_PLACEHOLDER());
                }
                return;
            }
        };
        // For pictures: an answer from a file.
        if self.screenshot.is_some() && self.netlab.traces.done.is_empty() {
            if let Some(t) = std::env::var("KUBEDOG_SHOT_TRACE").ok().and_then(|p| std::fs::read_to_string(p).ok()) {
                self.netlab.traces.done.insert(ask.key.clone(), (kube::now_secs(), Ok(read(&t))));
            }
        }
        let busy = self.netlab.traces.running.contains_key(&ask.key);
        ui.horizontal(|ui| {
            if busy {
                ui.spinner();
                said(ui, "OVN is computing the path…", TEXT_MUTED());
            } else if button(ui, "Ask OVN", false, false) && self.screenshot.is_none() {
                let body = format!("Let OVN compute the path {}? It runs ovn-trace and reads OVN's rules in pod “{}” (container “{}”) in namespace “{}”, with kubectl exec. It computes for a made-up packet: nothing is sent and nothing changes.", ask.what, ask.ovn_pod, ask.container, ask.home);
                self.request(Action::OvnTrace { ask: Box::new(ask.clone()) }, "Ask OVN".into(), body, "Run", false);
            }
            if !busy {
                said(ui, "computes the path of a made-up packet and names the rule that drops it; sends nothing, after you confirm", TEXT_PLACEHOLDER());
            }
        });
        let Some((at, r)) = self.netlab.traces.done.get(&ask.key).cloned() else { return };
        ui.add_space(8.0);
        let expected = netpath::sum(&self.net_path(ctx, a, b, port, proto).steps);
        let mut raw = self.netlab.traces.raw;
        card(ui, |ui| {
            panel(ui, "As OVN computes it", &format!("{}; computed, not seen", ago(kube::now_secs(), Some(at))));
            let t = match &r {
                Ok(t) => t,
                Err(e) => {
                    said(ui, e, DANGER());
                    return;
                }
            };
            let (tone, words) = sentence(t);
            ui.horizontal_wrapped(|ui| pill(ui, &words, if tone == Tone::Muted { TEXT_SUBTLE() } else { tone_color(tone) }));
            if matches!((tone, expected), (Tone::Success, netpath::Say::No) | (Tone::Danger, netpath::Say::Yes)) {
                said(ui, "That's not what the objects say (above): OVN may not have taken something over yet, or something isn't understood here.", WARNING());
            }
            ui.add_space(4.0);
            for (dp, i, o) in &t.hops {
                let (r, _) = line(ui, u(24.0), false);
                ui.painter().circle_filled(egui::pos2(r.left() + u(6.0), r.center().y), u(4.0), INFO());
                label_at(ui, ui.painter(), egui::pos2(r.left() + u(20.0), r.center().y), dp, 13.0, TEXT_DEFAULT(), u(240.0));
                label_at(ui, ui.painter(), egui::pos2(r.left() + u(270.0), r.center().y), &if o.is_empty() { format!("in at {i}") } else { format!("in at {i}, out at {o}") }, 12.5, TEXT_MUTED(), r.width() - u(280.0));
            }
            if !t.rules.is_empty() {
                ui.add_space(4.0);
                said(ui, "Rules it met:", TEXT_SUBTLE());
            }
            for x in &t.rules {
                let col = match x.action.as_str() {
                    "drop" | "reject" => DANGER(),
                    "pass" => TEXT_SUBTLE(),
                    _ => SUCCESS(),
                };
                let (r, resp) = line(ui, u(24.0), false);
                ui.painter().circle_filled(egui::pos2(r.left() + u(6.0), r.center().y), u(4.0), col);
                label_at(ui, ui.painter(), egui::pos2(r.left() + u(20.0), r.center().y), &x.action, 12.5, col, u(110.0));
                label_at(ui, ui.painter(), egui::pos2(r.left() + u(136.0), r.center().y), &x.of, 13.0, TEXT_DEFAULT(), r.width() - u(140.0));
                resp.on_hover_text(format!("{}\npriority {}\n{}", x.of, x.priority, x.matches));
            }
            ui.add_space(4.0);
            if chip_button(ui, if raw { "Hide the whole answer" } else { "Show the whole answer" }, raw) {
                raw = !raw;
            }
            if raw {
                egui::ScrollArea::vertical().id_salt("trace").max_height(u(420.0)).show(ui, |ui| {
                    for l in t.raw.lines() {
                        let s = l.trim();
                        let col = if s == "drop;" || s.starts_with("reject") || s.contains("verdict=drop") || s.contains("verdict=reject") { DANGER() } else if s.starts_with("/* output to") { SUCCESS() } else if l.starts_with("ingress(") || l.starts_with("egress(") { TEXT_DEFAULT() } else if s.contains("_acl_eval") { WARNING() } else { TEXT_SUBTLE() };
                        ui.label(RichText::new(l).monospace().size(z(11.5)).color(col));
                    }
                });
            }
        });
        self.netlab.traces.raw = raw;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Cut from what OVN 25.03 answered for a made-up network.
    const DROP: &str = r#"# tcp,reg14=0x2,nw_src=10.128.2.5,nw_dst=10.128.2.6,tp_dst=80

ingress(dp="worker-1", inport="shop_web-1")
-------------------------------------------
 0. ls_in_check_port_sec (northd.c:9399): 1, priority 50, uuid db1bea99
    reg0[15] = check_in_port_sec();
    next;
 8. ls_in_acl_eval (northd.c:7480): ip && !ct.est, priority 1, uuid 02a364de
    next;
28. ls_in_l2_lkup (northd.c:10292): eth.dst == 0a:58:0a:80:02:06, priority 50, uuid 713fbf18
    outport = "db_db-1";
    output;

egress(dp="worker-1", inport="shop_web-1", outport="db_db-1")
-------------------------------------------------------------
 2. ls_out_pre_acl (northd.c:6057): ip, priority 100, uuid ec43a7a3
    reg0[0] = 1;
    next;
 6. ls_out_acl_eval (northd.c:7110): reg0[9] == 1 && (outport == @a_db && ip), priority 2000, uuid a5ef1b64
    log(name="NP:db:closed:Ingress", verdict=drop, severity=info);
    reg8[17] = 1;
    next;
 8. ls_out_acl_action (northd.c:7281): reg8[17] == 1, priority 1000, uuid ad679ab9
    reg8[16] = 0;
"#;
    const RULE: &str = r#"KD end 0
KD acl a5ef1b64
{"data":[["NP:db:closed:Ingress",["map",[["direction","Ingress"],["k8s.ovn.org/name","db"],["k8s.ovn.org/owner-type","NetpolNamespace"]]],1000,"drop","outport == @a_db && ip"]],"headings":["name","external_ids","priority","action","match"]}
KD done
"#;

    #[test]
    fn drops_are_named() {
        let t = read(&format!("{DROP}{RULE}"));
        assert_eq!(t.hops, vec![("worker-1".to_string(), "shop_web-1".into(), "db_db-1".into())]);
        assert_eq!(t.end, Ending::Dropped("ls_out_acl_action".into()));
        assert_eq!(sentence(&t), (Tone::Danger, "OVN drops it: the closed door that network policies in db make, ingress".into()));
        // Without the rule it still says that it's dropped.
        assert_eq!(sentence(&read(DROP)).0, Tone::Danger);
    }

    #[test]
    fn goes_through() {
        let ok = format!("{}\n 6. ls_out_acl_eval (northd.c:7065): reg0[7] == 1, priority 2001, uuid aec05731\n    reg8[16] = 1;\n    next;\n12. ls_out_apply_port_sec (northd.c:5874): 1, priority 0, uuid 960cb2c7\n    output;\n    /* output to \"db_db-1\", type \"\" */\nKD end 0\nKD acl aec05731\n{}\nKD done", DROP.split(" 6. ls_out").next().unwrap(), r#"{"data":[[["set",[]],["map",[["k8s.ovn.org/name","db:web-to-db"],["k8s.ovn.org/owner-type","NetworkPolicy"]]],1001,"allow-related","x"]],"headings":["name","external_ids","priority","action","match"]}"#);
        let t = read(&ok);
        assert_eq!((t.end.clone(), t.rules[0].of.as_str()), (Ending::Delivered("db_db-1".into()), "network policy db/web-to-db"));
        assert_eq!(sentence(&t).1, "OVN delivers it to db/db-1");
        // Over a router: what's handed on between parts isn't the end.
        let far = "ingress(dp=\"worker-1\", inport=\"shop_web-1\")\n 0. a (northd.c:1): 1, priority 1, uuid 1\n    /* output to \"stor-worker-1\", type \"patch\" */\n\ningress(dp=\"ovn_cluster_router\", inport=\"rtos-worker-1\")\n15. lr_in_ip_routing (northd.c:13782): 1, priority 0, uuid f4c99155\n    drop;\n";
        assert_eq!(sentence(&read(far)).1, "OVN drops it: no route for that address");
        let remote = far.replace("    drop;", "    /* output to \"tstor-worker-2\", type \"remote\" */");
        assert_eq!(sentence(&read(&remote)), (Tone::Muted, "Nothing stops it on this node; OVN passes it to worker-2, and what the rules there say isn't known".into()));
        // Cut off where one part hands on to the next.
        assert!(matches!(read(far.split("\ningress(dp=\"ovn").next().unwrap()).end, Ending::Unknown(_)));
    }

    #[test]
    fn refusals_and_errors() {
        let r = DROP.replace("    reg8[16] = 0;\n", "    reject { outport <-> inport; next(pipeline=ingress, table=28); };\n\ntcp_reset\n---------\n    next(pipeline=ingress, table=28);\n\ningress(dp=\"worker-1\", inport=\"db_db-1\")\n28. ls_in_l2_lkup (northd.c:10292): x, priority 50, uuid 0637a04f\n    output;\n    /* output to \"shop_web-1\", type \"\" */\n");
        let t = read(&format!("{r}{}", RULE.replace("\"drop\"", "\"reject\"")));
        assert_eq!(sentence(&t).1, "OVN refuses it: the closed door that network policies in db make, ingress");
        assert_eq!(t.hops.len(), 1);
        for e in ["unknown datapath \"worker-9\"\nKD end 1\n", "error parsing flow: Constraints are ambiguous\nKD end 1", "", "sh: ovn-trace: not found\nKD end 127"] {
            let t = read(e);
            assert_eq!(sentence(&t).0, Tone::Muted, "{e}");
        }
    }

    #[test]
    fn packets() {
        assert_eq!(mac_of("10.128.2.45").as_deref(), Some("0a:58:0a:80:02:2d"));
        let pod = |a: Value| json!({"metadata": {"namespace": "shop", "name": "web-1", "annotations": {"k8s.ovn.org/pod-networks": a.to_string()}}});
        let a = json!({"default": {"ip_address": "10.128.2.5/23", "mac_address": "0a:58:0a:80:02:05", "gateway_ip": "10.128.2.1", "role": "primary"}});
        let p = pod(a.clone());
        assert_eq!(packet(&p, "172.30.0.9", None, 5432, "TCP").unwrap(), "inport==\"shop_web-1\" && eth.src==0a:58:0a:80:02:05 && eth.dst==0a:58:0a:80:02:01 && ip4.src==10.128.2.5 && ip4.dst==172.30.0.9 && ip.ttl==64 && tcp && tcp.src==52888 && tcp.dst==5432");
        assert!(packet(&p, "10.128.2.6", mac_of("10.128.2.6").as_deref(), 53, "UDP").unwrap().contains("eth.dst==0a:58:0a:80:02:06 && ip4.src"));
        for (x, host, proto) in [(p.clone(), "web.example.com", "TCP"), (p.clone(), "2001:db8::1", "TCP"), (p.clone(), "192.0.2.1", "SCTP"), (json!({}), "192.0.2.1", "TCP"), (p.clone(), "192.0.2.1\" || 1 == \"1", "TCP")] {
            assert!(packet(&x, host, None, 1, proto).is_err(), "{host}");
        }
        // On a network of its own.
        let mut own = a;
        own["shop/red"] = json!({"role": "primary"});
        own["default"]["role"] = json!("infrastructure-locked");
        assert!(packet(&pod(own), "192.0.2.1", None, 1, "TCP").unwrap_err().contains("network of its own"));
        let k = Ask { ctx: "c".into(), home: "ovn".into(), ovn_pod: "o".into(), container: "sbdb".into(), switch: "worker-1".into(), packet: "p; rm -rf /".into(), lb: None, what: String::new(), key: String::new() };
        let a = k.args();
        let i = a.iter().position(|x| x == SCRIPT).unwrap();
        assert_eq!(&a[i + 1..], &["trace".to_string(), "worker-1".into(), "p; rm -rf /".into(), "-".into()]);
    }
}
