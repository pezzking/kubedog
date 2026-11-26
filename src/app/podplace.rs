//! Where a pod may run (Scheduling), and what would happen to it (What if): worked out from its
//! definition, its neighbours and the nodes, without trying anything.

use super::dash::{at, at_end, line};
use super::pg::pill;
use super::*;

// ---------- scheduling ----------

pub(super) fn tolerates(pod: &Value, taint: &Value) -> bool {
    pod["spec"]["tolerations"].as_array().into_iter().flatten().any(|t| {
        let effect = t["effect"].as_str().unwrap_or("");
        if !effect.is_empty() && Some(effect) != taint["effect"].as_str() {
            return false;
        }
        let key = t["key"].as_str().unwrap_or("");
        match t["operator"].as_str().unwrap_or("Equal") {
            "Exists" => key.is_empty() || Some(key) == taint["key"].as_str(),
            _ => Some(key) == taint["key"].as_str() && t["value"].as_str().unwrap_or("") == taint["value"].as_str().unwrap_or(""),
        }
    })
}

/// A node selector term's expression against a node.
fn expr(e: &Value, labels: &Value, name: &str, fields: bool) -> bool {
    let k = e["key"].as_str().unwrap_or("");
    let have = if fields { (k == "metadata.name").then_some(name) } else { labels[k].as_str() };
    let vals: Vec<&str> = e["values"].as_array().into_iter().flatten().filter_map(|v| v.as_str()).collect();
    let num = |s: Option<&str>| s.and_then(|s| s.parse::<i64>().ok());
    match e["operator"].as_str().unwrap_or("") {
        "In" => have.map(|h| vals.contains(&h)).unwrap_or(false),
        "NotIn" => have.map(|h| !vals.contains(&h)).unwrap_or(true),
        "Exists" => have.is_some(),
        "DoesNotExist" => have.is_none(),
        "Gt" => num(have).zip(num(vals.first().copied())).map(|(a, b)| a > b).unwrap_or(false),
        "Lt" => num(have).zip(num(vals.first().copied())).map(|(a, b)| a < b).unwrap_or(false),
        _ => false,
    }
}

/// What a pod asks for, by resource (CPU in m, the rest as numbers). Init containers count when
/// one alone needs more; sidecars are added.
fn wants(o: &Value) -> HashMap<String, f64> {
    let of = |c: &Value| -> HashMap<String, f64> {
        let mut m: HashMap<String, f64> = HashMap::new();
        for from in ["limits", "requests"] {
            for (k, v) in c["resources"][from].as_object().into_iter().flatten() {
                let s = v.as_str().map(String::from).unwrap_or_else(|| v.to_string());
                m.insert(k.clone(), if k == "cpu" { resources::cpu_milli(&s) } else { resources::mem_bytes(&s) });
            }
        }
        m
    };
    let mut sum: HashMap<String, f64> = HashMap::new();
    let inits = o["spec"]["initContainers"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    for c in pod::containers(o).iter().chain(inits.iter().filter(|c| c["restartPolicy"] == "Always")) {
        for (k, v) in of(c) {
            *sum.entry(k).or_default() += v;
        }
    }
    for c in inits.iter().filter(|c| c["restartPolicy"] != "Always") {
        for (k, v) in of(c) {
            let e = sum.entry(k).or_default();
            *e = e.max(v);
        }
    }
    sum
}

/// Why a pod couldn't go to a node; empty when nothing speaks against it.
pub(super) fn against(pod: &Value, node: &Value, on_node: &[&Value]) -> Vec<String> {
    let mut out = vec![];
    let name = node["metadata"]["name"].as_str().unwrap_or("");
    let labels = &node["metadata"]["labels"];
    let ready = node["status"]["conditions"].as_array().into_iter().flatten().any(|c| c["type"] == "Ready" && c["status"] == "True");
    if !ready {
        out.push("the node isn't ready".into());
    }
    if node["spec"]["unschedulable"] == true && !tolerates(pod, &serde_json::json!({"key": "node.kubernetes.io/unschedulable", "effect": "NoSchedule"})) {
        out.push("cordoned".into());
    }
    for t in node["spec"]["taints"].as_array().into_iter().flatten() {
        let key = t["key"].as_str().unwrap_or("");
        if matches!(t["effect"].as_str(), Some("NoSchedule" | "NoExecute")) && key != "node.kubernetes.io/unschedulable" && !tolerates(pod, t) {
            out.push(format!("reserved ({}{})", key.rsplit('/').next().unwrap_or(key), t["value"].as_str().filter(|v| !v.is_empty()).map(|v| format!("={v}")).unwrap_or_default()));
        }
    }
    for (k, v) in pod["spec"]["nodeSelector"].as_object().into_iter().flatten() {
        if labels[k.as_str()].as_str() != v.as_str() {
            out.push(format!("lacks the label {k}={}", v.as_str().unwrap_or("")));
        }
    }
    let terms = &pod["spec"]["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"];
    if let Some(terms) = terms.as_array() {
        let ok = terms.iter().any(|t| {
            let (e, f) = (t["matchExpressions"].as_array(), t["matchFields"].as_array());
            (e.is_some() || f.is_some()) && e.into_iter().flatten().all(|x| expr(x, labels, name, false)) && f.into_iter().flatten().all(|x| expr(x, labels, name, true))
        });
        if !ok {
            out.push("not among the nodes it must run on".into());
        }
    }
    for t in pod["spec"]["affinity"]["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"].as_array().into_iter().flatten().filter(|t| t["topologyKey"] == "kubernetes.io/hostname") {
        let ns = pod["metadata"]["namespace"].as_str();
        let spaces: Vec<&str> = t["namespaces"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).collect();
        if let Some(p) = on_node.iter().find(|p| {
            let pn = p["metadata"]["namespace"].as_str();
            (if spaces.is_empty() { pn == ns } else { pn.map(|x| spaces.contains(&x)).unwrap_or(false) }) && p["metadata"]["uid"] != pod["metadata"]["uid"] && podnet::selector_matches(&t["labelSelector"], &p["metadata"]["labels"])
        }) {
            out.push(format!("won't share a node with {}", p["metadata"]["name"].as_str().unwrap_or("")));
        }
    }
    let mut used: HashMap<String, f64> = HashMap::new();
    for p in on_node.iter().filter(|p| p["metadata"]["uid"] != pod["metadata"]["uid"]) {
        for (k, v) in wants(p) {
            *used.entry(k).or_default() += v;
        }
    }
    let alloc = &node["status"]["allocatable"];
    let mut need: Vec<(String, f64)> = wants(pod).into_iter().collect();
    need.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in need.into_iter().filter(|x| x.1 > 0.0) {
        let cap = alloc[k.as_str()].as_str().map(|s| if k == "cpu" { resources::cpu_milli(s) } else { resources::mem_bytes(s) }).unwrap_or(0.0);
        let free = cap - used.get(&k).copied().unwrap_or(0.0);
        if v > free + 0.5 {
            let show = |x: f64| match k.as_str() { "cpu" => hive::cores(x.max(0.0)), "memory" | "ephemeral-storage" => gib(x.max(0.0)), _ => format!("{:.0}", x.max(0.0)) };
            out.push(format!("too little {k}: {} free, {} needed", show(free), show(v)));
        }
    }
    let max = alloc["pods"].as_str().and_then(|s| s.parse::<usize>().ok()).unwrap_or(usize::MAX);
    if on_node.iter().filter(|p| p["metadata"]["uid"] != pod["metadata"]["uid"]).count() >= max {
        out.push("full of pods".into());
    }
    out
}

/// A toleration in words.
fn toleration_words(t: &Value) -> String {
    let key = t["key"].as_str().unwrap_or("");
    let effect = match t["effect"].as_str().unwrap_or("") {
        "NoSchedule" => "may still be placed on",
        "PreferNoSchedule" => "doesn't mind",
        "NoExecute" => "stays on",
        _ => "puts up with",
    };
    let what = match key {
        "" => "any reserved node".to_string(),
        "node.kubernetes.io/not-ready" => "a node that isn't ready".into(),
        "node.kubernetes.io/unreachable" => "a node that doesn't answer".into(),
        "node.kubernetes.io/memory-pressure" => "a node short of memory".into(),
        "node.kubernetes.io/disk-pressure" => "a node short of disk".into(),
        "node.kubernetes.io/pid-pressure" => "a node short of process numbers".into(),
        "node.kubernetes.io/unschedulable" => "a cordoned node".into(),
        "node.kubernetes.io/network-unavailable" => "a node without network".into(),
        k => format!("nodes reserved with {k}{}", t["value"].as_str().filter(|v| !v.is_empty()).map(|v| format!("={v}")).unwrap_or_default()),
    };
    let time = match t["tolerationSeconds"].as_i64() {
        Some(s) => format!(", for {}", kube::human_duration(s)),
        None if t["effect"] == "NoExecute" => ", for good".into(),
        None => String::new(),
    };
    format!("{effect} {what}{time}")
}

fn affinity_words(o: &Value) -> Vec<(bool, String)> {
    let a = &o["spec"]["affinity"];
    let mut out = vec![];
    let exprs = |t: &Value| {
        let mut w: Vec<String> = vec![];
        for e in t["matchExpressions"].as_array().into_iter().flatten().chain(t["matchFields"].as_array().into_iter().flatten()) {
            let v: Vec<&str> = e["values"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).collect();
            w.push(match e["operator"].as_str().unwrap_or("") { "In" => format!("{} is {}", e["key"].as_str().unwrap_or(""), v.join(" or ")), "NotIn" => format!("{} isn't {}", e["key"].as_str().unwrap_or(""), v.join(" or ")), "Exists" => format!("has {}", e["key"].as_str().unwrap_or("")), "DoesNotExist" => format!("doesn't have {}", e["key"].as_str().unwrap_or("")), x => format!("{} {x} {}", e["key"].as_str().unwrap_or(""), v.join(",")) });
        }
        for (k, v) in t["matchLabels"].as_object().into_iter().flatten() {
            w.push(format!("{k} is {}", v.as_str().unwrap_or("")));
        }
        w.join(" and ")
    };
    for t in a["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"].as_array().into_iter().flatten() {
        out.push((true, format!("a node where {}", exprs(t))));
    }
    for t in a["nodeAffinity"]["preferredDuringSchedulingIgnoredDuringExecution"].as_array().into_iter().flatten() {
        out.push((false, format!("a node where {}", exprs(&t["preference"]))));
    }
    for (k, w) in [("podAffinity", "together with"), ("podAntiAffinity", "apart from")] {
        let by = |t: &Value| match t["topologyKey"].as_str().unwrap_or("") { "kubernetes.io/hostname" => "node".to_string(), x => x.rsplit('/').next().unwrap_or(x).to_string() };
        for t in a[k]["requiredDuringSchedulingIgnoredDuringExecution"].as_array().into_iter().flatten() {
            out.push((true, format!("a place {w} pods where {} (per {})", exprs(&t["labelSelector"]), by(t))));
        }
        for t in a[k]["preferredDuringSchedulingIgnoredDuringExecution"].as_array().into_iter().flatten() {
            out.push((false, format!("a place {w} pods where {} (per {})", exprs(&t["podAffinityTerm"]["labelSelector"]), by(&t["podAffinityTerm"]))));
        }
    }
    for t in o["spec"]["topologySpreadConstraints"].as_array().into_iter().flatten() {
        out.push((t["whenUnsatisfiable"] != "ScheduleAnyway", format!("a place that spreads its pods evenly over each {}", t["topologyKey"].as_str().unwrap_or("").rsplit('/').next().unwrap_or(""))));
    }
    out
}

/// The nodes with what speaks against each, or why that can't be told.
type Places = Result<Vec<(String, Vec<String>)>, String>;

impl KubedogApp {
    fn pod_places(&self, sel: &Selected, o: &Value) -> Places {
        if self.refused(&sel.ctx, Kind::Nodes) {
            return Err("Your account can't read nodes, so other places can't be compared.".into());
        }
        if self.prefs.ctx_namespaces.contains_key(&sel.ctx) || self.refused(&sel.ctx, Kind::Namespaces) {
            return Err("Kubedog only sees the pods of some namespaces here, so it can't tell how full the nodes are.".into());
        }
        let (Some(nodes), Some(pods)) = (self.lists.get(&Self::list_key(&sel.ctx, Kind::Nodes)).filter(|l| l.fetched.is_some()), self.lists.get(&Self::list_key(&sel.ctx, Kind::Pods))) else { return Err("Reading the nodes…".into()) };
        let mut by: HashMap<&str, Vec<&Value>> = HashMap::new();
        for p in pods.items.iter().filter(|p| !matches!(p["status"]["phase"].as_str(), Some("Succeeded" | "Failed"))) {
            if let Some(n) = p["spec"]["nodeName"].as_str() {
                by.entry(n).or_default().push(p);
            }
        }
        let none = vec![];
        let mut v: Vec<(String, Vec<String>)> = nodes.items.iter().filter_map(|n| n["metadata"]["name"].as_str().map(|name| (name.to_string(), against(o, n, by.get(name).unwrap_or(&none))))).collect();
        v.sort_by(|a, b| a.1.len().cmp(&b.1.len()).then(a.0.cmp(&b.0)));
        Ok(v)
    }

    pub(super) fn pod_scheduling(&mut self, ui: &mut Ui, sel: &Selected, o: &Value) {
        let spec = &o["spec"];
        let here = spec["nodeName"].as_str().unwrap_or("").to_string();
        let places = self.pod_places(sel, o);
        let mut open = None;
        self.page_scroll().id_salt("pod-sched").show(ui, |ui| {
            pg::two(
                ui,
                |ui| {
                    ui.label(RichText::new("Scheduling rules").size(z(15.0)).color(TEXT_DEFAULT()));
                    ui.add_space(4.0);
                    kv(ui, "Priority", match (spec["priorityClassName"].as_str(), spec["priority"].as_i64()) { (Some(n), p) => format!("{n} ({})", p.unwrap_or(0)), (None, Some(p)) if p != 0 => p.to_string(), _ => "normal".into() });
                    kv(ui, "Scheduler", spec["schedulerName"].as_str().unwrap_or("default-scheduler"));
                    let w = wants(o);
                    kv(ui, "Requests", { let mut l: Vec<String> = w.iter().filter(|x| *x.1 > 0.0).map(|(k, v)| match k.as_str() { "cpu" => format!("{} CPU", hive::cores(*v)), "memory" => format!("{} memory", gib(*v)), _ => format!("{v:.0} {k}") }).collect(); l.sort(); if l.is_empty() { "nothing: it takes what's left".to_string() } else { l.join(", ") } });
                    for (k, v) in spec["nodeSelector"].as_object().into_iter().flatten() {
                        kv(ui, "Node selector", format!("{k} = {}", v.as_str().unwrap_or("")));
                    }
                    for (must, t) in affinity_words(o) {
                        ui.add(egui::Label::new(RichText::new(format!("•  {} {t}", if must { "must go to" } else { "would like" })).size(z(13.0)).color(TEXT_MUTED())).wrap());
                    }
                    if let Some(s) = spec["terminationGracePeriodSeconds"].as_i64() {
                        kv(ui, "Grace period", format!("{s} seconds"));
                    }
                },
                |ui| {
                    let t = spec["tolerations"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
                    ui.label(RichText::new("Tolerations").size(z(15.0)).color(TEXT_DEFAULT()));
                    ui.label(RichText::new("hover for the exact toleration").size(z(11.5)).color(TEXT_PLACEHOLDER()));
                    ui.add_space(4.0);
                    if t.is_empty() {
                        ui.label(RichText::new("Nothing special.").color(TEXT_SUBTLE()));
                    }
                    for t in t {
                        let exact = format!("{} {} {} {}", t["key"].as_str().unwrap_or("(any key)"), t["operator"].as_str().unwrap_or("Equal"), t["value"].as_str().unwrap_or(""), t["effect"].as_str().unwrap_or("(any effect)"));
                        ui.add(egui::Label::new(RichText::new(format!("•  {}", toleration_words(t))).size(z(13.0)).color(TEXT_MUTED())).wrap()).on_hover_text(exact);
                    }
                },
            );
            ui.add_space(6.0);
            dash::section(ui, "Where it could run", "taints, labels, affinity, and room by what's asked for; a guess at what the scheduler would find, not a promise");
            match &places {
                Err(e) => {
                    ui.label(RichText::new(e).color(TEXT_SUBTLE()));
                }
                Ok(list) => {
                    let fit = list.iter().filter(|x| x.1.is_empty() && x.0 != here).count();
                    ui.label(RichText::new(match (fit, here.is_empty()) { (0, false) => "No other node would take it.".to_string(), (1, false) => "One other node would take it.".into(), (n, false) => format!("{n} other nodes would take it."), (0, true) => "No node would take one more of its pods.".into(), (1, true) => "One node would take one more of its pods.".into(), (n, true) => format!("{n} nodes would take one more of its pods.") }).color(if fit == 0 { WARNING() } else { SUCCESS() }));
                    ui.add_space(4.0);
                    card(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        for (name, why) in list {
                            let (r, resp) = line(ui, u(27.0), true);
                            let ok = why.is_empty();
                            ui.painter().circle_filled(egui::pos2(r.left() + u(5.0), r.center().y), u(4.5), if ok { SUCCESS() } else { TEXT_PLACEHOLDER() });
                            pg::label_at(ui, ui.painter(), egui::pos2(r.left() + u(18.0), r.center().y), name, 13.0, PRIMARY_TEXT(), r.width() * 0.26);
                            at(ui, r, 0.3, 0.56, &if ok { "fits".to_string() } else { why.join(" · ") }, 12.5, if ok { SUCCESS() } else { TEXT_MUTED() });
                            if *name == here {
                                at_end(ui, r, 1.0, "here now", 12.0, PRIMARY_TEXT());
                            }
                            if resp.on_hover_text(why.join("\n")).clicked() {
                                open = Some(Selected { ctx: sel.ctx.clone(), kind: Kind::Nodes, ns: String::new(), name: name.clone() });
                            }
                        }
                    });
                    let mut not: Vec<&str> = vec![];
                    if !spec["affinity"]["podAffinity"].is_null() { not.push("pods it must be near"); }
                    if !spec["topologySpreadConstraints"].is_null() { not.push("even spreading"); }
                    if spec["volumes"].as_array().into_iter().flatten().any(|v| v["persistentVolumeClaim"].is_object()) { not.push("where its disks can be attached"); }
                    if !not.is_empty() {
                        ui.label(RichText::new(format!("Not looked at: {}.", not.join(", "))).size(z(11.5)).color(TEXT_PLACEHOLDER()));
                    }
                }
            }
            ui.add_space(20.0);
        });
        if let Some(s) = open {
            self.navigate(View::Resource(Kind::Nodes), Some(s));
        }
    }
}

// ---------- what if ----------

pub(super) type Line = (Tone, String);

pub(super) struct Around<'a> {
    /// Ready and all other pods of the same owner, and how many of them are on the same node.
    pub ready: usize,
    pub all: usize,
    pub same_node: usize,
    /// Budget: (name, how many may be missing now).
    pub budget: Option<(String, i64)>,
    /// Seconds its own start took.
    pub start: Option<i64>,
    pub fits: Option<usize>,
    pub pod: &'a Value,
}

fn owner(o: &Value) -> &str {
    o["metadata"]["ownerReferences"].as_array().into_iter().flatten().find(|r| r["controller"] == true).and_then(|r| r["kind"].as_str()).unwrap_or("")
}

fn lost_space(o: &Value) -> Vec<&str> {
    o["spec"]["volumes"].as_array().into_iter().flatten().filter(|v| v["emptyDir"].is_object()).filter_map(|v| v["name"].as_str()).collect()
}

pub(super) fn if_deleted(a: &Around) -> Vec<Line> {
    let mut v: Vec<Line> = vec![];
    let o = a.pod;
    v.push(match owner(o) {
        "" => (Tone::Danger, "Nothing runs this pod, so it's gone for good.".into()),
        "StatefulSet" => (Tone::Success, "Its stateful set makes it again with the same name and the same disks.".into()),
        "DaemonSet" => (Tone::Success, "Its daemon set makes it again on the same node.".into()),
        "Job" => (Tone::Warning, "Its job may run it again from the start, if it has tries left.".into()),
        "ReplicaSet" => (Tone::Success, "Its deployment makes another one at once, with a new name.".into()),
        k => (Tone::Info, format!("Its {k} decides what comes next.")),
    });
    if !matches!(owner(o), "" | "Job" | "DaemonSet") {
        v.push(if a.ready == 0 {
            let back = a.start.map(|s| format!(" Its own start took {}.", kube::human_duration(s))).unwrap_or_default();
            (Tone::Danger, format!("Nobody takes over meanwhile: no other pod of it is ready.{back}"))
        } else {
            (Tone::Success, format!("{} of {} others keep working meanwhile.", a.ready, a.all))
        });
    }
    if let Some((n, left)) = &a.budget {
        v.push(if *left > 0 { (Tone::Success, format!("The budget {n} allows {left} pod{} to be missing.", if *left == 1 { "" } else { "s" })) } else { (Tone::Warning, format!("The budget {n} allows none to be missing: a drain would wait. Deleting it by hand isn't stopped by that.")) });
    }
    let lost = lost_space(o);
    if !lost.is_empty() {
        v.push((Tone::Warning, format!("Lost with it: the scratch space {}.", truncate(&lost.join(", "), 160))));
    }
    let disks = o["spec"]["volumes"].as_array().into_iter().flatten().filter(|v| v["persistentVolumeClaim"].is_object()).count();
    if disks > 0 {
        v.push((Tone::Success, if disks == 1 { "Its disk stays.".to_string() } else { format!("Its {disks} disks stay.") }));
    }
    v
}

pub(super) fn if_node_fails(a: &Around) -> Vec<Line> {
    let mut v: Vec<Line> = vec![];
    let o = a.pod;
    let wait = |key: &str| {
        let taint = serde_json::json!({"key": key, "effect": "NoExecute"});
        o["spec"]["tolerations"].as_array().into_iter().flatten().filter(|t| tolerates(&serde_json::json!({"spec": {"tolerations": [t]}}), &taint)).map(|t| t["tolerationSeconds"].as_i64()).collect::<Vec<_>>()
    };
    let w = wait("node.kubernetes.io/unreachable");
    let kind = owner(o);
    if kind == "DaemonSet" {
        v.push((Tone::Info, "It belongs to this node and waits for it to come back.".into()));
    } else if w.contains(&None) {
        v.push((Tone::Warning, "It's told to stay on a node that doesn't answer, so it isn't moved.".into()));
    } else {
        // Without a toleration it goes at once; several add up to the shortest.
        let s = w.iter().flatten().min().copied().unwrap_or(0);
        v.push((if s > 120 { Tone::Warning } else { Tone::Success }, format!("Kubernetes first has to notice, usually within a minute. Then it waits {} before it gives the pod up.", if s == 0 { "no longer".to_string() } else { kube::human_duration(s) })));
        match kind {
            "" => v.push((Tone::Danger, "Nothing makes it again elsewhere.".into())),
            "StatefulSet" => {
                v.push((Tone::Danger, "A stateful set doesn't replace it until the node is back or someone removes the pod by force: two with one name must never run.".into()));
                if a.fits == Some(0) {
                    v.push((Tone::Danger, "And no other node would take it now.".into()));
                }
            }
            _ => v.push(match a.fits {
                Some(0) => (Tone::Danger, "No other node would take it now.".into()),
                Some(n) => (Tone::Success, format!("{n} other node{} would take it.", if n == 1 { "" } else { "s" })),
                None => (Tone::Muted, "Whether another node would take it can't be told here.".into()),
            }),
        }
    }
    if a.all > 0 && kind != "DaemonSet" {
        v.push(if a.same_node == a.all {
            (Tone::Danger, if a.all == 1 { "The only other pod of it runs on the same node, so both go down together.".to_string() } else { format!("All {} others run on the same node, so everything goes down together.", a.all) })
        } else if a.same_node > 0 {
            (Tone::Warning, format!("{} of {} others run on the same node and go down with it.", a.same_node, a.all))
        } else {
            (Tone::Success, format!("{} on other nodes.", if a.all == 1 { "The other one runs".to_string() } else { format!("All {} others run", a.all) }))
        });
    }
    if o["spec"]["volumes"].as_array().into_iter().flatten().any(|x| x["persistentVolumeClaim"].is_object()) {
        v.push((Tone::Warning, "A disk for one node at a time may stay attached to the dead node for some minutes before it can move.".into()));
    }
    v
}

/// Straight line through readings: (per second, how well it fits 0..1).
pub(super) fn slope(p: &[(f64, f64)]) -> Option<(f64, f64)> {
    let n = p.len() as f64;
    if p.len() < 8 || p[p.len() - 1].0 - p[0].0 < 120.0 {
        return None;
    }
    let (mx, my) = (p.iter().map(|x| x.0).sum::<f64>() / n, p.iter().map(|x| x.1).sum::<f64>() / n);
    let (sxy, sxx, syy) = p.iter().fold((0.0, 0.0, 0.0), |a, x| (a.0 + (x.0 - mx) * (x.1 - my), a.1 + (x.0 - mx).powi(2), a.2 + (x.1 - my).powi(2)));
    if sxx <= 0.0 {
        return None;
    }
    Some((sxy / sxx, if syy > 0.0 { sxy * sxy / (sxx * syy) } else { 0.0 }))
}

/// Containers: (name, readings (seconds, bytes), asked, limit).
pub(super) fn if_memory_grows(cs: &[(String, Vec<(f64, f64)>, f64, f64)], qos: &str) -> Vec<Line> {
    let mut v: Vec<Line> = vec![];
    for (name, r, ask, lim) in cs {
        let Some(now) = r.last().map(|x| x.1) else { continue };
        let room = if *lim > 0.0 { Some((lim - now).max(0.0)) } else { None };
        let trend = slope(r).filter(|s| s.0 > 0.0 && s.1 > 0.6 && s.0 * 3600.0 > now * 0.005);
        match (room, trend) {
            (Some(left), Some((s, _))) => {
                let t = left / s;
                let span = kube::human_duration((r[r.len() - 1].0 - r[0].0) as i64);
                v.push((if t < 86_400.0 { Tone::Danger } else { Tone::Warning }, format!("{name} grew steadily over the last {span}. At that pace it hits its limit in {} and is killed.", kube::human_duration(t as i64))));
            }
            (Some(left), None) => v.push((if left < lim * 0.1 { Tone::Danger } else { Tone::Success }, format!("{name} has {} left to its limit of {}{}. Past it, it's killed and started again.", gib(left), gib(*lim), if slope(r).is_some() { " and isn't growing" } else { "" }))),
            (None, t) => v.push((Tone::Warning, format!("{name} has no limit{}: it can fill its node, and then pods are evicted.", if t.is_some() { " and is growing" } else { "" }))),
        }
        if *ask > 0.0 && now > *ask && *lim != *ask {
            v.push((Tone::Warning, format!("{name} uses {} more than it asked for, which makes it one of the first to go when the node runs short.", gib(now - ask))));
        }
    }
    if v.is_empty() {
        v.push((Tone::Muted, "No usage read yet.".into()));
    }
    v.push(match qos {
        "Guaranteed" => (Tone::Success, "When its node runs short of memory, it's among the last to be evicted.".into()),
        "BestEffort" => (Tone::Warning, "When its node runs short of memory, it's evicted first: it asked for nothing.".into()),
        _ => (Tone::Info, "When its node runs short of memory, it goes before those that use no more than they asked for.".into()),
    });
    v
}

/// What config maps and secrets a pod takes in: (kind, name, how).
#[derive(Clone, Copy, PartialEq, Debug)]
pub(super) enum How {
    /// As variables: only read at the start.
    Variable,
    /// As files that follow changes.
    Files,
    /// As files that don't (a single file mounted by subPath).
    Fixed,
}

pub(super) fn config_uses(o: &Value) -> Vec<(&'static str, String, How)> {
    let mut out: Vec<(&'static str, String, How)> = vec![];
    let mut add = |k: &'static str, n: Option<&str>, h: How| {
        if let Some(n) = n {
            if !out.iter().any(|x| x.0 == k && x.1 == n && x.2 == h) {
                out.push((k, n.to_string(), h));
            }
        }
    };
    let spec = &o["spec"];
    let all = || spec["containers"].as_array().into_iter().flatten().chain(spec["initContainers"].as_array().into_iter().flatten());
    for c in all() {
        for e in c["env"].as_array().into_iter().flatten() {
            add("configmap", e["valueFrom"]["configMapKeyRef"]["name"].as_str(), How::Variable);
            add("secret", e["valueFrom"]["secretKeyRef"]["name"].as_str(), How::Variable);
        }
        for e in c["envFrom"].as_array().into_iter().flatten() {
            add("configmap", e["configMapRef"]["name"].as_str(), How::Variable);
            add("secret", e["secretRef"]["name"].as_str(), How::Variable);
        }
    }
    for v in spec["volumes"].as_array().into_iter().flatten() {
        let mut hows: Vec<How> = vec![];
        for m in all().flat_map(|c| c["volumeMounts"].as_array().into_iter().flatten()).filter(|m| m["name"] == v["name"]) {
            let h = if m["subPath"].is_string() || m["subPathExpr"].is_string() { How::Fixed } else { How::Files };
            if !hows.contains(&h) {
                hows.push(h);
            }
        }
        for h in hows {
            add("configmap", v["configMap"]["name"].as_str(), h);
            add("secret", v["secret"]["secretName"].as_str(), h);
            for s in v["projected"]["sources"].as_array().into_iter().flatten() {
                add("configmap", s["configMap"]["name"].as_str(), h);
                add("secret", s["secret"]["name"].as_str(), h);
            }
        }
    }
    out
}

/// "configmap name time,time" lines → when each was last changed.
pub(super) fn parse_changed(t: &str) -> Vec<(String, i64)> {
    t.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 3 {
                return None;
            }
            let last = f[2].split(',').filter_map(kube::parse_time).max()?;
            Some((format!("{}/{}", f[0].to_lowercase(), f[1]), last))
        })
        .collect()
}

/// When the containers that run now were started: the first of them.
fn running_since(o: &Value) -> Option<i64> {
    o["status"]["containerStatuses"].as_array()?.iter().filter_map(|s| s["state"]["running"]["startedAt"].as_str().and_then(kube::parse_time)).min()
}

pub(super) fn if_config_changes(uses: &[(&'static str, String, How)], changed: &HashMap<String, i64>, since: Option<i64>, now: i64) -> Vec<Line> {
    let mut v: Vec<Line> = vec![];
    let label = |k: &str| if k == "secret" { "secret" } else { "config map" };
    // What it runs on already is old.
    for (k, n, h) in uses.iter().filter(|u| u.2 != How::Files) {
        if let (Some(t), Some(s)) = (changed.get(&format!("{k}/{n}")), since) {
            if *t > s {
                v.push((Tone::Danger, format!("Old values: {} {n} was changed {} ago, after this pod started, and the pod reads it {} at the start.", label(k), kube::human_duration(now - t), if *h == How::Variable { "as variables only" } else { "as a fixed file only" })));
            }
        }
    }
    let list = |h: How| uses.iter().filter(|u| u.2 == h).map(|u| format!("{} {}", label(u.0), u.1)).collect::<Vec<_>>();
    let (vars, files, fixed) = (list(How::Variable), list(How::Files), list(How::Fixed));
    let say = |l: &[String]| truncate(&l.join(", "), 220);
    if !vars.is_empty() {
        v.push((Tone::Warning, format!("Needs a restart to notice: {}.", say(&vars))));
    }
    if !fixed.is_empty() {
        v.push((Tone::Warning, format!("Single files that never follow, until a restart: {}.", say(&fixed))));
    }
    if !files.is_empty() {
        v.push((Tone::Success, format!("Files that follow by themselves within about a minute (the program still has to read them again): {}.", say(&files))));
    }
    if uses.is_empty() {
        v.push((Tone::Muted, "It takes nothing from config maps or secrets.".into()));
    }
    v
}

impl KubedogApp {
    fn ask_changed(&mut self, sel: &Selected, o: &Value, kind: &'static str) {
        if !self.pod.changed_asked.insert(kind.to_string()) {
            return;
        }
        let mut names: Vec<String> = config_uses(o).into_iter().filter(|u| u.0 == kind).map(|u| u.1).collect();
        names.sort();
        names.dedup();
        if names.is_empty() {
            return;
        }
        // Only names and times are printed, never values.
        let mut args: Vec<String> = ["--context", &sel.ctx, "-n", &sel.ns, "get", kind].iter().map(|x| x.to_string()).collect();
        args.extend(names.clone());
        args.extend(["--show-managed-fields", "--ignore-not-found", "--no-headers", "-o", "custom-columns=K:.kind,N:.metadata.name,T:.metadata.managedFields[*].time"].map(String::from));
        self.pod_ask(pod::Ask::Changed(names), move |k| k.run(&args));
    }

    pub(super) fn pod_what_if(&mut self, ui: &mut Ui, sel: &Selected, o: &Value) {
        if self.screenshot.is_none() || std::env::var("KUBEDOG_SHOT_TAB").is_ok() {
            self.ask_changed(sel, o, "configmap");
        }
        let now = kube::now_secs();
        let uid = o["metadata"]["ownerReferences"].as_array().into_iter().flatten().find(|r| r["controller"] == true).and_then(|r| r["uid"].as_str()).map(String::from);
        let here = o["spec"]["nodeName"].as_str().unwrap_or("");
        let mut a = Around { ready: 0, all: 0, same_node: 0, budget: None, start: pod::startup(o).map(|l| l.iter().map(|x| x.1).sum()), fits: None, pod: o };
        if let (Some(uid), Some(l)) = (&uid, self.lists.get(&Self::list_key(&sel.ctx, Kind::Pods))) {
            for p in l.items.iter().filter(|p| p["metadata"]["uid"] != o["metadata"]["uid"] && p["metadata"]["ownerReferences"].as_array().into_iter().flatten().any(|r| r["uid"].as_str() == Some(uid)) && !matches!(p["status"]["phase"].as_str(), Some("Succeeded" | "Failed"))) {
                a.all += 1;
                a.ready += pod::cond(p, "Ready").map(|c| c["status"] == "True").unwrap_or(false) as usize;
                a.same_node += (p["spec"]["nodeName"].as_str() == Some(here)) as usize;
            }
        }
        // Several budgets: the strictest.
        for b in self.items_in(&sel.ctx, Kind::PodDisruptionBudgets, &sel.ns).unwrap_or_default() {
            if podnet::selector_matches(&b["spec"]["selector"], &o["metadata"]["labels"]) && b["spec"]["selector"].is_object() {
                let left = b["status"]["disruptionsAllowed"].as_i64().unwrap_or(0);
                if a.budget.as_ref().map(|x| left < x.1).unwrap_or(true) {
                    a.budget = Some((b["metadata"]["name"].as_str().unwrap_or("").to_string(), left));
                }
            }
        }
        if let Ok(p) = self.pod_places(sel, o) {
            a.fits = Some(p.iter().filter(|x| x.1.is_empty() && x.0 != here).count());
        }
        let mem: Vec<(String, Vec<(f64, f64)>, f64, f64)> = pod::containers(o)
            .iter()
            .map(|c| {
                let n = c["name"].as_str().unwrap_or("").to_string();
                let (_, _, mr, ml) = pod::asks(c);
                let r = self.pod.tops.iter().filter_map(|t| t.1.get(&n).map(|x| (t.0 as f64, x.1))).collect();
                (n, r, mr, ml)
            })
            .collect();
        let uses = config_uses(o);
        let cards: Vec<(&str, &str, Vec<Line>)> = vec![
            ("…it's deleted?", "or its program crashes for good", if_deleted(&a)),
            ("…its node fails?", here, if_node_fails(&a)),
            ("…its memory keeps growing?", "from the readings while this page was open", if_memory_grows(&mem, o["status"]["qosClass"].as_str().unwrap_or(""))),
            ("…its configuration changes?", "or already has", if_config_changes(&uses, &self.pod.changed, running_since(o), now)),
        ];
        let secrets = uses.iter().any(|u| u.0 == "secret") && !self.pod.changed_asked.contains("secret");
        let mut ask = false;
        self.page_scroll().id_salt("pod-whatif").show(ui, |ui| {
            ui.label(RichText::new("What if…").size(z(20.0)).color(TEXT_DEFAULT()));
            ui.label(RichText::new("Worked out from its definition, its neighbours and the nodes. Nothing is tried.").size(z(12.5)).color(TEXT_SUBTLE()));
            ui.add_space(10.0);
            let wide = ui.available_width() >= u(900.0);
            let per = if wide { 2 } else { 1 };
            for pair in cards.chunks(per) {
                let gap = 14.0;
                let w = (ui.available_width() - gap * (per as f32 - 1.0)) / per as f32;
                ui.horizontal_top(|ui| {
                    ui.spacing_mut().item_spacing.x = gap;
                    for (title, sub, lines) in pair {
                        ui.allocate_ui_with_layout(egui::vec2(w, 0.0), Layout::top_down(Align::Min), |ui| {
                            ui.set_width(w);
                            ui.spacing_mut().item_spacing.x = 8.0;
                            let worst = lines.iter().map(|l| match l.0 { Tone::Danger => 2, Tone::Warning => 1, _ => 0 }).max().unwrap_or(0);
                            let col = [SUCCESS(), WARNING(), DANGER()][worst];
                            Frame::new().fill(BG_CARD()).stroke(Stroke::new(1.0, col.gamma_multiply(0.45))).corner_radius(CornerRadius::same(12)).inner_margin(Margin::symmetric(18, 14)).show(ui, |ui| {
                                ui.set_width(w - 38.0);
                                ui.set_min_height(u(170.0));
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(RichText::new(*title).size(z(17.0)).color(TEXT_DEFAULT()));
                                    pill(ui, ["fine", "some care", "it would hurt"][worst], col);
                                });
                                ui.label(RichText::new(*sub).size(z(12.0)).color(TEXT_PLACEHOLDER()));
                                ui.add_space(6.0);
                                for (t, text) in lines {
                                    ui.horizontal_top(|ui| {
                                        ui.label(RichText::new("●").size(z(10.0)).color(tone_color(*t)));
                                        ui.add(egui::Label::new(RichText::new(text).size(z(13.5)).color(TEXT_MUTED())).wrap());
                                    });
                                    ui.add_space(1.0);
                                }
                                if title.contains("configuration") && secrets {
                                    ui.add_space(4.0);
                                    ask = button(ui, "Check the secrets' times too", false, false);
                                }
                            });
                        });
                    }
                });
                ui.add_space(gap);
            }
        });
        if ask {
            self.ask_changed(sel, o, "secret");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GI: f64 = 1073741824.0;

    fn node(name: &str, cpu: &str, mem: &str) -> Value {
        serde_json::json!({"metadata": {"name": name, "labels": {"kubernetes.io/hostname": name, "disk": "ssd", "n": "5"}}, "spec": {}, "status": {"conditions": [{"type": "Ready", "status": "True"}], "allocatable": {"cpu": cpu, "memory": mem, "pods": "2"}}})
    }

    fn pod(uid: &str, cpu: &str, mem: &str) -> Value {
        serde_json::json!({"metadata": {"uid": uid, "name": uid, "namespace": "n", "labels": {"app": "x"}}, "spec": {"containers": [{"name": "a", "resources": {"requests": {"cpu": cpu, "memory": mem}}}]}})
    }

    #[test]
    fn places() {
        let p = pod("p", "500m", "1Gi");
        assert!(against(&p, &node("a", "2", "4Gi"), &[]).is_empty());
        let other = pod("o", "1800m", "1Gi");
        assert!(against(&p, &node("a", "2", "4Gi"), &[&other])[0].starts_with("too little cpu"));
        // Itself doesn't count.
        assert!(against(&p, &node("a", "500m", "1Gi"), &[&p]).is_empty());
        assert!(against(&p, &node("a", "8", "64Gi"), &[&pod("1", "1m", "1Mi"), &pod("2", "1m", "1Mi")]).contains(&"full of pods".to_string()));
        let mut n = node("a", "2", "4Gi");
        n["spec"] = serde_json::json!({"unschedulable": true, "taints": [{"key": "gpu", "value": "yes", "effect": "NoSchedule"}, {"key": "soft", "effect": "PreferNoSchedule"}]});
        assert_eq!(against(&p, &n, &[]), vec!["cordoned", "reserved (gpu=yes)"]);
        let mut t = p.clone();
        t["spec"]["tolerations"] = serde_json::json!([{"key": "gpu", "operator": "Equal", "value": "yes", "effect": "NoSchedule"}, {"key": "node.kubernetes.io/unschedulable", "operator": "Exists"}]);
        assert!(against(&t, &n, &[]).is_empty());
        t["spec"]["tolerations"] = serde_json::json!([{"key": "gpu", "value": "no", "effect": "NoSchedule"}]);
        assert_eq!(against(&t, &n, &[]).len(), 2);
        let mut s = p.clone();
        s["spec"]["nodeSelector"] = serde_json::json!({"disk": "hdd"});
        s["spec"]["affinity"] = serde_json::json!({"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [{"matchExpressions": [{"key": "n", "operator": "Gt", "values": ["9"]}]}, {"matchFields": [{"key": "metadata.name", "operator": "In", "values": ["b"]}]}]}}});
        assert_eq!(against(&s, &node("a", "2", "4Gi"), &[]).len(), 2);
        assert_eq!(against(&s, &node("b", "2", "4Gi"), &[]).len(), 1);
        let mut anti = p.clone();
        anti["spec"]["affinity"] = serde_json::json!({"podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [{"topologyKey": "kubernetes.io/hostname", "labelSelector": {"matchLabels": {"app": "x"}}}]}});
        assert!(against(&anti, &node("a", "2", "4Gi"), &[&pod("q", "1m", "1Mi")])[0].contains("won't share"));
        let g = serde_json::json!({"spec": {"containers": [{"resources": {"limits": {"nvidia.com/gpu": "1"}}}], "initContainers": [{"resources": {"requests": {"cpu": "3"}}}]}});
        assert!(wants(&g)["cpu"] == 3000.0 && wants(&g)["nvidia.com/gpu"] == 1.0);
        assert_eq!(against(&g, &node("a", "2", "4Gi"), &[]).len(), 2);
    }

    fn around(p: &Value) -> Around<'_> {
        Around { ready: 0, all: 0, same_node: 0, budget: None, start: Some(40), fits: Some(0), pod: p }
    }

    fn owned(kind: &str) -> Value {
        let mut p = pod("p", "1", "1Gi");
        if !kind.is_empty() {
            p["metadata"]["ownerReferences"] = serde_json::json!([{"kind": kind, "controller": true}]);
        }
        p["spec"]["tolerations"] = serde_json::json!([{"key": "node.kubernetes.io/unreachable", "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": 300}]);
        p["spec"]["volumes"] = serde_json::json!([{"name": "tmp", "emptyDir": {}}, {"name": "d", "persistentVolumeClaim": {"claimName": "x"}}]);
        p
    }

    #[test]
    fn scenarios() {
        let text = |l: &[Line]| l.iter().map(|x| x.1.clone()).collect::<Vec<_>>().join(" ");
        let bare = owned("");
        assert_eq!(if_deleted(&around(&bare))[0].0, Tone::Danger);
        let rs = owned("ReplicaSet");
        let mut a = around(&rs);
        a.budget = Some(("b".into(), 0));
        let d = text(&if_deleted(&a));
        for w in ["makes another one", "Nobody takes over", "took 40s", "a drain would wait", "scratch space tmp", "Its disk stays"] {
            assert!(d.contains(w), "{w}: {d}");
        }
        a.ready = 1;
        a.all = 2;
        a.same_node = 2;
        let n = text(&if_node_fails(&a));
        for w in ["waits 5m", "No other node would take it", "All 2 others run on the same node"] {
            assert!(n.contains(w), "{w}: {n}");
        }
        assert!(text(&if_node_fails(&around(&owned("StatefulSet")))).contains("doesn't replace it until"));
        assert!(text(&if_node_fails(&around(&owned("DaemonSet")))).contains("waits for it to come back"));
        let mut stay = owned("ReplicaSet");
        stay["spec"]["tolerations"] = serde_json::json!([{"operator": "Exists"}]);
        assert!(text(&if_node_fails(&around(&stay))).contains("told to stay"));
        // Memory.
        let grow: Vec<(f64, f64)> = (0..20).map(|i| (i as f64 * 15.0, GI * (0.5 + i as f64 * 0.01))).collect();
        let m = if_memory_grows(&[("a".into(), grow.clone(), GI * 0.6, GI)], "Burstable");
        assert!(m[0].0 == Tone::Danger && m[0].1.contains("hits its limit in"), "{m:?}");
        let flat: Vec<(f64, f64)> = (0..20).map(|i| (i as f64 * 15.0, GI * (0.5 + 0.001 * (i % 2) as f64))).collect();
        assert!(if_memory_grows(&[("a".into(), flat, GI, GI)], "Guaranteed")[0].1.contains("isn't growing"));
        assert!(if_memory_grows(&[("a".into(), grow[..3].to_vec(), 0.0, 0.0)], "BestEffort")[0].1.contains("no limit"));
        assert!(slope(&grow[..5]).is_none());
        // Config.
        let c = serde_json::json!({"spec": {"volumes": [{"name": "v", "configMap": {"name": "files"}}, {"name": "w", "secret": {"secretName": "one"}}],
            "containers": [{"env": [{"valueFrom": {"configMapKeyRef": {"name": "vars"}}}], "envFrom": [{"secretRef": {"name": "s"}}], "volumeMounts": [{"name": "v"}, {"name": "w", "subPath": "x"}]}]}});
        let u = config_uses(&c);
        assert_eq!(u, vec![("configmap", "vars".into(), How::Variable), ("secret", "s".into(), How::Variable), ("configmap", "files".into(), How::Files), ("secret", "one".into(), How::Fixed)]);
        let ch: HashMap<String, i64> = parse_changed("ConfigMap   vars   2026-01-01T00:00:00Z,2026-01-03T00:00:00Z\nConfigMap files 2026-01-05T00:00:00Z\nConfigMap bad <none>\n").into_iter().collect();
        assert_eq!(ch.len(), 2);
        let since = kube::parse_time("2026-01-02T00:00:00Z");
        let l = if_config_changes(&u, &ch, since, kube::parse_time("2026-01-06T00:00:00Z").unwrap());
        // Only what doesn't follow by itself is old.
        assert_eq!(l.iter().filter(|x| x.0 == Tone::Danger).count(), 1);
        assert!(l[0].1.contains("config map vars was changed 3d"));
        assert!(if_config_changes(&u, &ch, None, 0).iter().all(|x| x.0 != Tone::Danger));
    }

    #[test]
    fn words() {
        let t = |v: Value| toleration_words(&v);
        assert_eq!(t(serde_json::json!({"key": "node.kubernetes.io/not-ready", "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": 300})), "stays on a node that isn't ready, for 5m0s");
        assert_eq!(t(serde_json::json!({"operator": "Exists"})), "puts up with any reserved node");
        assert_eq!(t(serde_json::json!({"key": "gpu", "value": "a", "effect": "NoSchedule"})), "may still be placed on nodes reserved with gpu=a");
    }
}
