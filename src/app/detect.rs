//! The detective: follows an object's chain (ways in, services, pods, node, disks, configuration,
//! what it depends on, recent changes) and names the likely cause with its evidence.

use super::face::{many, Face, Side};
use super::ops::{ago, ns_of, obj, table, text, worst_first, Item};
use super::pg::label_at;
use super::podxray::Go;
use super::work::{name_of, said};
use super::*;

/// Something that speaks for a cause. The higher the weight, the likelier it's the cause.
#[derive(Clone)]
pub(super) struct Clue {
    pub weight: u8,
    pub tone: Tone,
    pub title: String,
    pub proof: Vec<String>,
    pub next: String,
    pub go: Option<Go>,
}

fn clue(weight: u8, tone: Tone, title: impl Into<String>, proof: Vec<String>, next: &str, go: Option<Go>) -> Clue {
    Clue { weight, tone, title: title.into(), proof, next: next.into(), go }
}

/// What a pod's own state says.
pub(super) fn pod_clues(p: &Value, go: Option<Go>) -> Vec<Clue> {
    let mut v = vec![];
    let name = name_of(p).to_string();
    if let Some(c) = pod::cond(p, "PodScheduled").filter(|c| c["status"] == "False") {
        v.push(clue(95, Tone::Danger, "It can't be placed on a node", vec![format!("{name}: {}", truncate(c["message"].as_str().unwrap_or(""), 300))], "See what it asks for in Scheduling, and free room or loosen its rules.", go.clone()));
    }
    if p["status"]["reason"] == "Evicted" {
        v.push(clue(80, Tone::Danger, if resources::rejected(p) { "Its node didn't take it" } else { "It was pushed off its node" }, vec![format!("{name}: {}", truncate(p["status"]["message"].as_str().unwrap_or(""), 300))], "The node ran short: ask for what it needs, or make room there.", go.clone()));
    }
    for list in ["initContainerStatuses", "containerStatuses"] {
        for s in p["status"][list].as_array().into_iter().flatten() {
            let c = text(&s["name"]);
            let w = &s["state"]["waiting"];
            let (reason, msg) = (text(&w["reason"]), truncate(w["message"].as_str().unwrap_or(""), 300));
            let last = if s["lastState"]["terminated"].is_object() { &s["lastState"]["terminated"] } else { &s["state"]["terminated"] };
            let (code, why) = (last["exitCode"].as_i64(), text(&last["reason"]));
            let proof = |m: String| vec![format!("{name}, container {c}: {m}")];
            match reason.as_str() {
                "ImagePullBackOff" | "ErrImagePull" | "InvalidImageName" => {
                    let lower = msg.to_lowercase();
                    let (t, n) = if lower.contains("unauthorized") || lower.contains("denied") || lower.contains("authentication") { ("Its image can't be fetched: no access", "Check its image pull secret and the registry's rights.") } else if lower.contains("not found") || lower.contains("manifest unknown") { ("Its image doesn't exist", "Check the image's name and tag.") } else { ("Its image can't be fetched", "Check the image, the registry and the network to it.") };
                    v.push(clue(97, Tone::Danger, t, proof(format!("{reason}: {msg}")), n, go.clone()));
                    continue;
                }
                "CreateContainerConfigError" | "CreateContainerError" => {
                    v.push(clue(97, Tone::Danger, "Its configuration is missing something", proof(format!("{reason}: {msg}")), "Make the secret, config map or key it names.", go.clone()));
                    continue;
                }
                _ => {}
            }
            let fine = s["state"]["running"].is_object() && s["ready"] == true;
            if why == "OOMKilled" {
                v.push(clue(if fine { 62 } else { 94 }, if fine { Tone::Warning } else { Tone::Danger }, if fine { "It ran out of memory" } else { "It runs out of memory" }, proof(format!("ended with OOMKilled{}", pod::time_of(&last["finishedAt"]).map(|t| format!(", {}", ago(kube::now_secs(), Some(t)))).unwrap_or_default())), "Raise its memory limit, or find out what grows.", go.clone()));
            } else if reason == "CrashLoopBackOff" {
                let n = match code { Some(137) => "It's killed from outside: a failing liveness probe, or memory on the node.", Some(1) | Some(2) => "It stops with an error of its own: see its last log.", Some(126) | Some(127) => "Its command can't be run: check the image and command.", Some(143) => "It's asked to stop: look for a failing liveness probe.", _ => "See its last log." };
                v.push(clue(90, Tone::Danger, "It keeps crashing", proof(format!("ended with exit code {}{}, {}", code.map(|c| c.to_string()).unwrap_or("?".into()), if why.is_empty() { String::new() } else { format!(" ({why})") }, many(s["restartCount"].as_i64().unwrap_or(0), "restart"))), n, go.clone()));
            } else if s["state"]["running"].is_object() && s["ready"] == false && list == "containerStatuses" {
                v.push(clue(70, Tone::Warning, "It runs but isn't ready", proof("its readiness probe doesn't pass".into()), "See the probe in Containers, and its log.", go.clone()));
            } else if list == "initContainerStatuses" && s["state"]["running"].is_object() && s["started"] != true {
                v.push(clue(60, Tone::Warning, "It waits for an init container", proof("the init container is still running".into()), "See that container's log.", go.clone()));
            }
        }
    }
    v
}

/// Addresses of services in a text: "name.namespace.svc", or "//name:" in its own namespace.
pub(super) fn service_names(t: &str, ns: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = vec![];
    let ok = |s: &str| !s.is_empty() && s.len() <= 63 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    for word in t.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')) {
        let p: Vec<&str> = word.split('.').collect();
        if p.len() >= 3 && p[2] == "svc" && ok(p[0]) && ok(p[1]) {
            out.push((p[1].into(), p[0].into()));
        }
    }
    for (i, _) in t.match_indices("://") {
        let rest = &t[i + 3..];
        let rest = rest.rsplit_once('@').filter(|x| !x.0.contains('/')).map(|x| x.1).unwrap_or(rest);
        let host: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.').collect();
        if ok(&host) {
            out.push((ns.into(), host));
        }
    }
    out.sort();
    out.dedup();
    out
}

impl KubedogApp {
    /// Everything that speaks for a cause, the likeliest first.
    pub(super) fn investigate(&self, sel: &Selected) -> Vec<Clue> {
        let mut v: Vec<Clue> = vec![];
        let now = kube::now_secs();
        let Some(o) = self.object_of(sel) else { return v };
        let go = |k: Kind, n: &str| Some(obj(&sel.ctx, k, &sel.ns, n));
        // From a service or an ingress to the workloads behind it.
        let mut pods: Vec<&Value> = vec![];
        let mut specs: Vec<Value> = vec![];
        let mut owners: Vec<(Kind, String)> = vec![];
        let mut services: Vec<String> = vec![];
        match sel.kind {
            Kind::Pods => {
                pods = self.refs(&sel.ctx, Kind::Pods, &sel.ns).unwrap_or_default().into_iter().filter(|p| name_of(p) == sel.name).collect();
                specs.push(o.clone());
            }
            Kind::Services => services.push(sel.name.clone()),
            Kind::Ingresses => {
                for e in podxray::pick_ingress(&o) {
                    if !services.contains(&e.service) {
                        services.push(e.service);
                    }
                }
            }
            k if work::is_work(k) => {
                pods = self.pods_of(sel, &o).unwrap_or_default();
                specs.push(work::sample(sel.kind, &o));
                let (t, head, notes) = face::verdict(sel.kind, &o, now);
                if t == Tone::Danger || t == Tone::Warning {
                    v.push(clue(20, t, head, notes, "", None));
                }
                for c in o["status"]["conditions"].as_array().into_iter().flatten().filter(|c| c["type"] == "ReplicaFailure" && c["status"] == "True") {
                    let m = truncate(c["message"].as_str().unwrap_or(""), 300);
                    let quota = m.contains("exceeded quota");
                    v.push(clue(98, Tone::Danger, if quota { "The namespace's quota is full" } else { "Its pods can't be made" }, vec![m], if quota { "Raise the quota or ask for less." } else { "The message says what refuses them." }, None));
                }
            }
            _ => {}
        }
        for n in &services {
            match self.refs(&sel.ctx, Kind::Services, &sel.ns).map(|l| l.into_iter().find(|s| name_of(s) == n)) {
                Some(None) => v.push(clue(96, Tone::Danger, format!("Service {n} doesn't exist"), vec![format!("{} points to it", sel.name)], "Make the service, or point to another.", None)),
                Some(Some(s)) => {
                    let mine: Vec<&Value> = self.refs(&sel.ctx, Kind::Pods, &sel.ns).unwrap_or_default().into_iter().filter(|p| s["spec"]["selector"].is_object() && podnet::selector_matches(&s["spec"]["selector"], &p["metadata"]["labels"])).collect();
                    if mine.is_empty() && s["spec"]["selector"].as_object().map(|m| !m.is_empty()).unwrap_or(false) {
                        v.push(clue(92, Tone::Danger, format!("No pod matches service {n}"), vec![format!("selector {}", resources::selector(&s["spec"]["selector"]))], "Compare the selector with the pods' labels, and see whether the workload is scaled to 0.", go(Kind::Services, n)));
                    }
                    pods.extend(mine);
                }
                None => {}
            }
        }
        // Who runs these pods.
        for p in &pods {
            let r = &p["metadata"]["ownerReferences"][0];
            let (k, n) = (text(&r["kind"]), text(&r["name"]));
            let (k, n) = if k == "ReplicaSet" { (Kind::Deployments, n.rsplit_once('-').map(|x| x.0.to_string()).unwrap_or(n)) } else if let Some(k) = workload::kind_named(&k) { (k, n) } else { continue };
            if !owners.contains(&(k, n.clone())) {
                owners.push((k, n));
            }
        }
        if specs.is_empty() {
            for (k, n) in &owners {
                if let Some(w) = self.object_of(&Selected { ctx: sel.ctx.clone(), kind: *k, ns: sel.ns.clone(), name: n.clone() }) {
                    specs.push(work::sample(*k, &w));
                }
            }
        }
        // The pods themselves.
        for p in &pods {
            if !matches!(p["status"]["phase"].as_str(), Some("Succeeded")) {
                v.extend(pod_clues(p, go(Kind::Pods, name_of(p))));
            }
        }
        // Their nodes.
        let mut nodes: HashSet<&str> = HashSet::new();
        for p in &pods {
            if let Some(n) = p["spec"]["nodeName"].as_str().filter(|n| nodes.insert(n)) {
                if let Some(node) = self.refs(&sel.ctx, Kind::Nodes, "").unwrap_or_default().into_iter().find(|x| name_of(x) == n) {
                    let (t, head, notes) = face::verdict(Kind::Nodes, node, now);
                    if t == Tone::Danger {
                        v.push(clue(93, t, format!("Node {n} is {}", head.to_lowercase()), notes, "Look at the node first: its pods can't be helped otherwise.", go(Kind::Nodes, n)));
                    } else if t == Tone::Warning && !head.contains("scheduling") {
                        v.push(clue(55, t, format!("Node {n}: {}", head.to_lowercase()), notes, "", go(Kind::Nodes, n)));
                    }
                }
            }
        }
        // What they need: config maps, claims.
        let mut seen: HashSet<(Kind, String)> = HashSet::new();
        for s in &specs {
            for (k, n) in workload::uses_of(&s["spec"]) {
                if !seen.insert((k, n.clone())) {
                    continue;
                }
                let Some(list) = self.refs(&sel.ctx, k, &sel.ns).filter(|_| matches!(k, Kind::ConfigMaps | Kind::PersistentVolumeClaims)) else { continue };
                match list.into_iter().find(|x| name_of(x) == n) {
                    None => {
                        // Optional ones may be missing.
                        let optional = s["spec"].to_string().contains("\"optional\":true");
                        v.push(clue(if optional { 30 } else { 91 }, if optional { Tone::Info } else { Tone::Danger }, format!("{} {n} doesn't exist", if k == Kind::ConfigMaps { "Config map" } else { "Claim" }), vec!["its pods point to it".into()], "Make it, or stop pointing to it.", None));
                    }
                    Some(c) if k == Kind::PersistentVolumeClaims => {
                        let (t, head, notes) = face::verdict(k, c, now);
                        if t != Tone::Success {
                            v.push(clue(92, t, format!("Claim {n}: {}", head.to_lowercase()), notes, "See the claim's events and its storage class.", go(k, &n)));
                        } else if let Some(x) = self.claim_usage(&sel.ctx, &sel.ns, &n) {
                            let f = x.used / x.capacity.max(1.0);
                            if f >= 0.95 {
                                v.push(clue(89, Tone::Danger, format!("Claim {n} is full"), vec![format!("{:.0}%: {} of {}", f * 100.0, gib(x.used), gib(x.capacity))], "Make room or grow it.", go(k, &n)));
                            }
                        }
                    }
                    _ => {}
                }
            }
            // What they call: services named in plain variables that have nothing behind them.
            let mut texts: Vec<String> = vec![];
            for c in s["spec"]["containers"].as_array().into_iter().flatten() {
                for e in c["env"].as_array().into_iter().flatten() {
                    if let Some(t) = e["value"].as_str() {
                        texts.push(format!("{}={t}", text(&e["name"])));
                    }
                }
                for f in c["envFrom"].as_array().into_iter().flatten() {
                    if let Some(cm) = f["configMapRef"]["name"].as_str() {
                        for x in self.refs(&sel.ctx, Kind::ConfigMaps, &sel.ns).unwrap_or_default().into_iter().filter(|x| name_of(x) == cm) {
                            texts.extend(x["data"].as_object().into_iter().flatten().map(|(k, v)| format!("{k}={}", text(v))));
                        }
                    }
                }
            }
            let mut done: HashSet<(String, String)> = HashSet::new();
            for t in texts {
                let (var, val) = t.split_once('=').unwrap_or(("", ""));
                for (ns, svc) in service_names(val, &sel.ns) {
                    if !done.insert((ns.clone(), svc.clone())) {
                        continue;
                    }
                    let Some(l) = self.refs(&sel.ctx, Kind::Services, &ns) else { continue };
                    match l.into_iter().find(|s| name_of(s) == svc) {
                        None if val.contains(&format!("{svc}.{ns}.svc")) => v.push(clue(75, Tone::Warning, format!("It's told to call {svc}.{ns}, which doesn't exist"), vec![format!("variable {var}")], "Check the address.", None)),
                        Some(s) if s["spec"]["selector"].as_object().map(|m| !m.is_empty()).unwrap_or(false) => {
                            if let Some((0, n)) = self.service_ready(&sel.ctx, &ns, &svc) {
                                v.push(clue(85, Tone::Danger, format!("Something it calls is down: {svc}.{ns}"), vec![format!("variable {var}; 0/{n} endpoints ready")], "Look at that service first.", Some(obj(&sel.ctx, Kind::Services, &ns, &svc))));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        // Services in front: named target ports that don't exist.
        if let Some(p) = pods.first() {
            for s in self.refs(&sel.ctx, Kind::Services, &sel.ns).unwrap_or_default().into_iter().filter(|s| s["spec"]["selector"].as_object().map(|m| !m.is_empty()).unwrap_or(false) && podnet::selector_matches(&s["spec"]["selector"], &p["metadata"]["labels"])) {
                for port in s["spec"]["ports"].as_array().into_iter().flatten() {
                    if let Some(t) = port["targetPort"].as_str() {
                        let has = p["spec"]["containers"].as_array().into_iter().flatten().flat_map(|c| c["ports"].as_array().into_iter().flatten()).any(|x| x["name"].as_str() == Some(t));
                        if !has {
                            v.push(clue(88, Tone::Danger, format!("Service {} sends to a port that isn't there", name_of(s)), vec![format!("target port “{t}” is named in no container")], "Name the port in the pod, or use its number.", go(Kind::Services, name_of(s))));
                        }
                    }
                }
            }
        }
        // Autoscaler at its most.
        for h in self.refs(&sel.ctx, Kind::HorizontalPodAutoscalers, &sel.ns).unwrap_or_default() {
            let t = &h["spec"]["scaleTargetRef"];
            if owners.iter().any(|(_, n)| t["name"].as_str() == Some(n)) || t["name"].as_str() == Some(&sel.name) {
                let (tone, head, notes) = face::verdict(Kind::HorizontalPodAutoscalers, h, now);
                if matches!(tone, Tone::Warning | Tone::Danger) {
                    v.push(clue(50, tone, format!("Autoscaler {}: {}", name_of(h), head.to_lowercase()), notes, "", go(Kind::HorizontalPodAutoscalers, name_of(h))));
                }
            }
        }
        // Warnings about any of these.
        let mut names: HashSet<String> = pods.iter().map(|p| name_of(p).to_string()).collect();
        names.insert(sel.name.clone());
        names.extend(owners.iter().map(|o| o.1.clone()));
        let mut ev: std::collections::BTreeMap<String, (i64, i64, String)> = Default::default();
        for e in self.refs(&sel.ctx, Kind::Events, &sel.ns).unwrap_or_default().into_iter().filter(|e| e["type"] == "Warning") {
            let n = text(&e["involvedObject"]["name"]);
            if !names.contains(&n) && !names.iter().any(|x| n.starts_with(&format!("{x}-"))) {
                continue;
            }
            let at = pod::time_of(&e["lastTimestamp"]).or_else(|| pod::time_of(&e["eventTime"])).unwrap_or(0);
            let x = ev.entry(text(&e["reason"])).or_insert((0, 0, String::new()));
            x.0 += e["count"].as_i64().unwrap_or(1);
            if at >= x.1 {
                x.1 = at;
                x.2 = format!("{n}: {}", truncate(e["message"].as_str().unwrap_or(""), 300));
            }
        }
        for (reason, (n, at, msg)) in ev.into_iter().filter(|e| now - e.1 .1 < 3 * 3600) {
            let quota = msg.contains("exceeded quota");
            let w = match reason.as_str() { "FailedCreate" if quota => 98, "FailedMount" | "FailedAttachVolume" => 86, "Unhealthy" => 65, "FailedScheduling" => 60, "BackOff" => 30, _ => 45 };
            v.push(clue(w, Tone::Warning, if quota { "The namespace's quota is full".into() } else { format!("Warning: {}", face::spaced(&reason).to_lowercase()) }, vec![format!("{msg} ({}, {})", many(n, "time"), ago(now, Some(at)))], "", None));
        }
        // What changed before it: the moment of trouble is the oldest of its pods' troubles.
        let start = pods.iter().filter_map(|p| pod::cond(p, "Ready").filter(|c| c["status"] == "False").and_then(|c| pod::time_of(&c["lastTransitionTime"]))).min().unwrap_or(now);
        if !v.is_empty() {
            let mut near: Vec<incident::Moment> = self.moments(2 * 86400).into_iter().filter(|m| m.lane == 0 && m.at <= start + 300 && start - m.at < 3 * 3600).filter(|m| m.sel.as_ref().map(|s| s.ctx == sel.ctx && (s.ns == sel.ns && (names.contains(&s.name) || seen.contains(&(s.kind, s.name.clone()))) || s.kind == Kind::Nodes && nodes.contains(s.name.as_str()))).unwrap_or(false)).collect();
            near.truncate(3);
            for m in near {
                let proof = m.diff.iter().filter(|d| !d.1.is_empty() || !d.2.is_empty()).take(4).map(|d| format!("{}: {} → {}", d.0, truncate(&d.1, 60), truncate(&d.2, 60))).collect();
                v.push(clue(87, Tone::Warning, format!("Changed {} before the trouble: {}", kube::human_duration((start - m.at).max(0)), m.title), proof, "Compare with before; a rollback may help.", m.go.clone()));
            }
        }
        v.sort_by(|a, b| b.weight.cmp(&a.weight).then(a.title.cmp(&b.title)));
        // The same from several pods is one clue.
        let mut out: Vec<Clue> = vec![];
        for c in v {
            match out.iter_mut().find(|x| x.title == c.title) {
                Some(x) => x.proof.extend(c.proof),
                None => out.push(c),
            }
        }
        out
    }

    pub(super) fn detective(&mut self, ui: &mut Ui) -> Option<Go> {
        if self.screenshot.is_some() && self.incident.sel.is_none() {
            if let (Ok(n), Some(c)) = (std::env::var("KUBEDOG_SHOT_OBJ"), self.active.first().cloned()) {
                let hit = [Kind::Deployments, Kind::StatefulSets, Kind::Services, Kind::Pods].iter().find_map(|k| self.refs(&c, *k, "").unwrap_or_default().into_iter().find(|o| name_of(o) == n).map(|o| (*k, ns_of(o).to_string())));
                if let Some((k, ns)) = hit.filter(|_| !n.is_empty()) {
                    self.incident.sel = Some(Selected { ctx: c, kind: k, ns, name: n });
                }
            }
        }
        if let Some(s) = self.incident.sel.clone() {
            return self.case(ui, &s);
        }
        let now = kube::now_secs();
        let mut pick: Option<Selected> = None;
        // Those in trouble.
        let mut items: Vec<(Item, Selected)> = self.work_tiles(None).into_iter().filter(|t| matches!(t.tone, Tone::Danger | Tone::Warning)).map(|t| (Item::new(t.tone, vec![format!("{}/{}", t.to.ns, t.to.name), t.head.clone(), t.to.kind.singular().into()]), t.to)).collect();
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            for p in self.refs(c, Kind::Pods, "").unwrap_or_default().into_iter().filter(|p| self.ns_ok(ns_of(p))) {
                let v = pod::verdict(p, now);
                if matches!(v.0, Tone::Danger | Tone::Warning) {
                    items.push((Item::new(v.0, vec![format!("{}/{}", ns_of(p), name_of(p)), v.1, "pod".into()]).tip(v.2.join("\n")), Selected { ctx: c.clone(), kind: Kind::Pods, ns: ns_of(p).into(), name: name_of(p).into() }));
                }
            }
        }
        let q = self.search.to_lowercase();
        if !q.is_empty() {
            // Anything can be looked into by name.
            for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
                for k in [Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::CronJobs, Kind::Services, Kind::Ingresses] {
                    for o in self.refs(c, k, "").unwrap_or_default().into_iter().filter(|o| self.ns_ok(ns_of(o)) && name_of(o).to_lowercase().contains(&q)).take(20) {
                        let s = Selected { ctx: c.clone(), kind: k, ns: ns_of(o).into(), name: name_of(o).into() };
                        if !items.iter().any(|i| i.1 == s) {
                            items.push((Item::new(Tone::Muted, vec![format!("{}/{}", s.ns, s.name), "-".into(), k.singular().into()]), s));
                        }
                    }
                }
            }
            items.retain(|i| i.0.cells[0].to_lowercase().contains(&q));
        }
        let sels: Vec<Selected> = items.iter().map(|i| i.1.clone()).collect();
        let mut l: Vec<Item> = items.into_iter().map(|i| i.0).collect();
        for (i, s) in l.iter_mut().zip(&sels) {
            i.go = Some(Go::Object(s.clone()));
        }
        worst_first(&mut l);
        let n = l.iter().filter(|i| i.bad()).count();
        face::show(ui, &Face { tone: if n == 0 { Tone::Success } else { Tone::Warning }, head: if n == 0 { "Nothing is in trouble".into() } else { format!("{} to look into", many(n as i64, "thing")) }, sub: "click one, or type a name in the filter to look into anything".into(), notes: vec![], pills: vec![], facts: vec![] }, Side::None);
        ui.add_space(10.0);
        if let Some(Go::Object(s)) = table(ui, "Why is it broken?", "Kubedog follows the chain and names the likely cause", &[("What", 0.5), ("State", 0.35), ("Kind", 0.15)], &l, 100, "Nothing: type a name in the filter.") {
            pick = Some(s);
        }
        if pick.is_some() {
            self.incident.sel = pick;
            self.refresh_current(false);
        }
        None
    }

    fn case(&mut self, ui: &mut Ui, s: &Selected) -> Option<Go> {
        let mut go = None;
        let id = pg::PgId { ctx: s.ctx.clone(), ns: s.ns.clone(), name: s.name.clone() };
        if self.super_back(ui, &id, "Why is it broken?") {
            self.incident.sel = None;
            return None;
        }
        let mut explain = false;
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{} /", s.ns)).size(z(19.0)).color(TEXT_SUBTLE()));
            ui.label(RichText::new(&s.name).size(z(19.0)).color(TEXT_DEFAULT()));
            ui.label(RichText::new(s.kind.singular()).size(z(12.5)).color(TEXT_PLACEHOLDER()));
            if button(ui, "Open it", false, false) {
                go = Some(Go::Object(s.clone()));
            }
            if self.ai_button(ui) {
                explain = true;
            }
        });
        if explain {
            let f = self.object_facts(s);
            self.ai_explain(f);
        }
        ui.add_space(6.0);
        let clues = self.investigate(s);
        let causes: Vec<&Clue> = clues.iter().filter(|c| c.weight >= 60 && matches!(c.tone, Tone::Danger | Tone::Warning)).collect();
        let gone: Vec<String> = [Kind::Pods, Kind::Services, Kind::Events, Kind::ConfigMaps, Kind::PersistentVolumeClaims, Kind::Nodes].iter().filter_map(|k| self.missing(&s.ctx, *k)).collect();
        let f = match causes.first() {
            Some(c) => Face { tone: c.tone, head: format!("Most likely: {}", c.title.to_lowercase()), sub: if causes.len() > 1 { format!("and {} more to look at", causes.len() - 1) } else { "nothing else stands out".into() }, notes: if c.next.is_empty() { vec![] } else { vec![c.next.clone()] }, pills: vec![], facts: vec![] },
            None => Face { tone: Tone::Success, head: "Nothing found that would break it".into(), sub: "from what Kubedog can read; its log may know more".into(), notes: vec![], pills: vec![], facts: vec![] },
        };
        face::show(ui, &f, Side::None);
        if !gone.is_empty() {
            ui.add_space(6.0);
            said(ui, &format!("Not looked at: {}.", gone.join("; ")), TEXT_PLACEHOLDER());
        }
        ui.add_space(12.0);
        for (i, c) in clues.iter().enumerate() {
            card(ui, |ui| {
                let (r, resp) = dash::line(ui, u(26.0), c.go.is_some());
                ui.painter().circle_filled(egui::pos2(r.left() + u(6.0), r.center().y), u(5.0), tone_color(c.tone));
                label_at(ui, ui.painter(), egui::pos2(r.left() + u(20.0), r.center().y), &c.title, 14.5, if c.go.is_some() { PRIMARY_TEXT() } else { TEXT_DEFAULT() }, r.width() - u(140.0));
                let word = if i == 0 && c.weight >= 60 { "most likely" } else if c.weight >= 80 { "likely" } else if c.weight >= 60 { "possible" } else { "for what it's worth" };
                ui.painter().text(r.right_center(), egui::Align2::RIGHT_CENTER, word, FontId::proportional(z(12.0)), TEXT_SUBTLE());
                if resp.clicked() {
                    go = c.go.clone();
                }
                for p in c.proof.iter().take(6) {
                    said(ui, p, TEXT_MUTED());
                }
                if c.proof.len() > 6 {
                    said(ui, &format!("and {} more like it", c.proof.len() - 6), TEXT_PLACEHOLDER());
                }
                if !c.next.is_empty() {
                    said(ui, &c.next, INFO());
                }
            });
            ui.add_space(8.0);
        }
        go
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pods_tell() {
        let p = |s: Value| pod_clues(&json!({"metadata": {"name": "web-1"}, "status": {"containerStatuses": [s]}}), None);
        assert_eq!(p(json!({"name": "c", "state": {"waiting": {"reason": "ImagePullBackOff", "message": "manifest unknown"}}}))[0].title, "Its image doesn't exist");
        assert_eq!(p(json!({"name": "c", "state": {"waiting": {"reason": "ErrImagePull", "message": "unauthorized: no"}}}))[0].title, "Its image can't be fetched: no access");
        assert_eq!(p(json!({"name": "c", "state": {"waiting": {"reason": "CrashLoopBackOff"}}, "lastState": {"terminated": {"reason": "OOMKilled", "exitCode": 137}}}))[0].title, "It runs out of memory");
        let c = p(json!({"name": "c", "restartCount": 4, "state": {"waiting": {"reason": "CrashLoopBackOff"}}, "lastState": {"terminated": {"reason": "Error", "exitCode": 1}}}));
        assert!(c[0].title == "It keeps crashing" && c[0].proof[0].contains("exit code 1 (Error), 4 restarts"));
        assert_eq!(p(json!({"name": "c", "ready": false, "state": {"running": {}}}))[0].title, "It runs but isn't ready");
        assert!(p(json!({"name": "c", "ready": true, "state": {"running": {}}})).is_empty());
        let q = pod_clues(&json!({"metadata": {"name": "w"}, "status": {"conditions": [{"type": "PodScheduled", "status": "False", "message": "0/3 nodes"}]}}), None);
        assert_eq!(q[0].title, "It can't be placed on a node");
    }

    #[test]
    fn what_it_calls() {
        assert_eq!(service_names("postgres://u:p@db.shop.svc.cluster.local:5432/x", "web"), vec![("shop".to_string(), "db".to_string())]);
        assert_eq!(service_names("http://cache:6379", "web"), vec![("web".to_string(), "cache".to_string())]);
        assert_eq!(service_names("https://example.com/a", "web"), vec![]);
        assert_eq!(service_names("plain text", "web"), vec![]);
    }
}
