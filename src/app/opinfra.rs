//! KEDA (what scales on what, and why something sleeps), Rook Ceph, and GPUs.

use super::face::{many, Face, Fact, Side};
use super::ops::{ago, ns_of, obj, summary, table, text, worst_first, Item};
use super::pg::panel;
use super::podxray::Go;
use super::work::{meter, name_of, said};
use super::*;

/// The graphics cards in a list of resources: (resource, how many).
pub(super) fn gpus(v: &Value) -> Vec<(String, f64)> {
    v.as_object()
        .into_iter()
        .flatten()
        .filter(|(k, _)| k.contains('/') && (k.ends_with("/gpu") || k.contains("/mig-") || k.ends_with("/gpu.shared") || k.starts_with("gpu.intel.com/")))
        .map(|(k, x)| (k.clone(), x.as_str().and_then(|t| t.parse().ok()).or(x.as_f64()).unwrap_or(0.0)))
        .filter(|x| x.1 > 0.0)
        .collect()
}

/// What a pod asks for.
fn pod_gpus(p: &Value) -> f64 {
    p["spec"]["containers"].as_array().into_iter().flatten().flat_map(|c| gpus(&c["resources"]["limits"])).map(|x| x.1).sum()
}

/// A scaled object's state: (tone, word, why).
fn keda_state(o: &Value) -> (Tone, String, String) {
    let on = |t: &str| pod::cond(o, t).map(|c| c["status"] == "True").unwrap_or(false);
    let paused = on("Paused") || o["metadata"]["annotations"]["autoscaling.keda.sh/paused"] == "true";
    let msg = |t: &str| pod::cond(o, t).and_then(|c| c["message"].as_str()).unwrap_or("").to_string();
    if paused {
        return (Tone::Muted, "Paused".into(), msg("Paused"));
    }
    if pod::cond(o, "Ready").map(|c| c["status"] != "True").unwrap_or(true) {
        return (Tone::Danger, "Not ready".into(), msg("Ready"));
    }
    if on("Fallback") {
        return (Tone::Warning, "On its fallback".into(), msg("Fallback"));
    }
    let act: Vec<bool> = o["status"]["triggersActivity"].as_object().into_iter().flatten().map(|(_, v)| v["isActive"] == true).collect();
    let words = if act.is_empty() { String::new() } else { format!("{} of {} active", act.iter().filter(|a| **a).count(), many(act.len() as i64, "trigger")) };
    if on("Active") {
        (Tone::Success, "Active".into(), words)
    } else {
        (Tone::Muted, "Asleep".into(), if words.is_empty() { "no trigger is active".into() } else { words })
    }
}

impl KubedogApp {
    pub(super) fn keda_page(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        let now = kube::now_secs();
        let key = "scaledobjects.keda.sh";
        let items: Vec<Item> = self
            .op_items(key)
            .into_iter()
            .map(|(c, o)| {
                let (t, w, why) = keda_state(o);
                let (spec, st) = (&o["spec"], &o["status"]);
                let hpa = self.refs(c, Kind::HorizontalPodAutoscalers, ns_of(o)).unwrap_or_default().into_iter().find(|h| st["hpaName"].as_str() == Some(name_of(h)));
                let busiest = hpa.map(objects::hpa_metrics).unwrap_or_default().into_iter().filter_map(|m| match (m.1, m.2) { (Some(n), Some(a)) if a > 0.0 => Some((n / a, m.3, m.0)), _ => None }).max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
                let cur = hpa.and_then(|h| h["status"]["currentReplicas"].as_i64());
                let max = spec["maxReplicaCount"].as_i64().unwrap_or(100);
                let mut t = t;
                let mut why = why;
                if t == Tone::Success && cur.map(|n| n >= max).unwrap_or(false) {
                    t = Tone::Warning;
                    why = format!("at its most ({max}); {why}");
                }
                let kinds: Vec<String> = { let mut v: Vec<String> = spec["triggers"].as_array().into_iter().flatten().map(|x| text(&x["type"])).collect(); v.sort(); v.dedup(); v };
                Item::new(t, vec![
                    self.full_name(c, o),
                    w,
                    why,
                    format!("{} {}", spec["scaleTargetRef"]["kind"].as_str().unwrap_or("Deployment"), text(&spec["scaleTargetRef"]["name"])),
                    format!("{} of {}–{max}", cur.map(|n| n.to_string()).unwrap_or("?".into()), spec["minReplicaCount"].as_i64().unwrap_or(0)),
                    kinds.join(", "),
                    busiest.as_ref().map(|b| b.1.clone()).unwrap_or("-".into()),
                    ago(now, pod::time_of(&st["lastActiveTime"])),
                ])
                .tip(format!("{}\n{}", self.full_name(c, o), busiest.map(|b| format!("busiest: {}\n{}", b.2, b.1)).unwrap_or_default()))
                .go(self.custom_go(c, key, o))
            })
            .collect();
        face::show(ui, &summary(&items, "scaled object"), Side::None);
        ui.add_space(10.0);
        self.bad_switch(ui);
        let mut items = self.op_filter(items);
        worst_first(&mut items);
        let none = self.op_missing(key).unwrap_or("None.".into());
        go = table(ui, &format!("Scaled objects ({})", items.len()), "busiest is the trigger closest to its target; open one to pause or resume it", &[("Scaled object", 0.22), ("State", 0.08), ("Why", 0.17), ("Scales", 0.18), ("Replicas", 0.09), ("Triggers", 0.09), ("Busiest", 0.1), ("Last active", 0.07)], &items, 200, &none).or(go);
        for k in ["scaledjobs.keda.sh", "triggerauthentications.keda.sh"] {
            go = self.kind_table(ui, k).or(go);
        }
        go
    }

    pub(super) fn ceph_page(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        let clusters: Vec<(String, Value)> = self.op_items("cephclusters.ceph.rook.io").into_iter().map(|(c, o)| (c.to_string(), o.clone())).collect();
        if clusters.is_empty() {
            said(ui, &self.op_missing("cephclusters.ceph.rook.io").unwrap_or("None here.".into()), TEXT_SUBTLE());
        }
        for (c, o) in &clusters {
            let ceph = &o["status"]["ceph"];
            let health = text(&ceph["health"]);
            let (tone, head) = match health.as_str() {
                "HEALTH_OK" => (Tone::Success, "Healthy"),
                "HEALTH_WARN" => (Tone::Warning, "Warnings"),
                "HEALTH_ERR" => (Tone::Danger, "Errors"),
                _ => (Tone::Muted, "Unknown"),
            };
            let cap = &ceph["capacity"];
            let (used, total) = (cap["bytesUsed"].as_f64().unwrap_or(0.0), cap["bytesTotal"].as_f64().unwrap_or(0.0));
            let share = if total > 0.0 { used / total } else { 0.0 };
            let at = pod::time_of(&cap["lastUpdated"]).unwrap_or(0) as f64;
            let h = self.powers.ceph.entry(format!("{c}|{}", name_of(o))).or_default();
            if h.back().map(|x| x.0 < at).unwrap_or(at > 0.0) {
                h.push_back((at, used));
                while h.len() > 500 {
                    h.pop_front();
                }
            }
            let pts: Vec<(f64, f64)> = h.iter().copied().collect();
            let span = pts.last().map(|x| x.0).unwrap_or(0.0) - pts.first().map(|x| x.0).unwrap_or(0.0);
            // A forecast needs a while of watching.
            let full = if span >= 1800.0 { podplace::slope(&pts).filter(|s| s.0 > 0.0).map(|s| (total * 0.85 - used) / s.0) } else { None };
            let ns = ns_of(o).to_string();
            let now = kube::now_secs();
            let f = Face {
                tone,
                head: format!("{head}: {}", name_of(o)),
                sub: format!("checked {}", ago(now, pod::time_of(&ceph["lastChecked"]))),
                notes: ceph["details"].as_object().into_iter().flatten().map(|(k, d)| format!("{k}: {}", truncate(d["message"].as_str().unwrap_or(""), 300))).collect(),
                pills: vec![],
                facts: vec![
                    Fact::new("Used", format!("{} of {}", gib(used), gib(total))),
                    Fact::new("Free", gib(cap["bytesAvailable"].as_f64().unwrap_or(0.0))),
                    Fact::new("Reaches 85%", match full { Some(s) if s > 0.0 => format!("in about {}", kube::human_duration(s as i64)), Some(_) => "already".into(), None if share >= 0.85 => "already".into(), None => "not known: watch for half an hour".into() }),
                    Fact::new("Version", text(&o["spec"]["cephVersion"]["image"]).rsplit(':').next().unwrap_or("").to_string()),
                    Fact::new("Namespace", ns.clone()),
                ],
            };
            face::show(ui, &f, Side::Ring(share, format!("{:.0}%", share * 100.0), "of raw space used".into()));
            ui.add_space(12.0);
            // Daemons, from their pods.
            let pods: Vec<&Value> = self.refs(c, Kind::Pods, &ns).unwrap_or_default();
            let mut osds: Vec<Item> = vec![];
            let mut parts: Vec<(&str, usize, usize)> = vec![];
            for (app, what) in [("rook-ceph-mon", "Monitors"), ("rook-ceph-mgr", "Managers"), ("rook-ceph-osd", "Disks (OSD)"), ("rook-ceph-mds", "File servers"), ("rook-ceph-rgw", "Object gateways")] {
                let mine: Vec<&&Value> = pods.iter().filter(|p| p["metadata"]["labels"]["app"].as_str() == Some(app)).collect();
                if mine.is_empty() {
                    continue;
                }
                let ok = mine.iter().filter(|p| pod::cond(p, "Ready").map(|c| c["status"] == "True").unwrap_or(false)).count();
                parts.push((what, ok, mine.len()));
                if app == "rook-ceph-osd" {
                    for p in mine {
                        let v = pod::verdict(p, now);
                        let l = &p["metadata"]["labels"];
                        osds.push(Item::new(v.0, vec![format!("osd.{}", l["ceph-osd-id"].as_str().or(l["osd"].as_str()).unwrap_or("?")), v.1, text(&p["spec"]["nodeName"]), text(&l["device-class"]), name_of(p).to_string()]).go(Some(obj(c, Kind::Pods, &ns, name_of(p)))));
                    }
                }
            }
            card(ui, |ui| {
                panel(ui, "Daemons", "");
                if parts.is_empty() {
                    said(ui, &self.missing(c, Kind::Pods).unwrap_or("None found.".into()), TEXT_SUBTLE());
                }
                for (what, ok, n) in &parts {
                    meter(ui, what, *ok as f64, *n as f64, &format!("{ok} of {n} ready"), if ok == n { SUCCESS() } else { DANGER() });
                }
            });
            ui.add_space(12.0);
            worst_first(&mut osds);
            go = table(ui, &format!("Disks ({})", osds.len()), "", &[("OSD", 0.12), ("State", 0.25), ("Node", 0.23), ("Class", 0.1), ("Pod", 0.3)], &osds, 60, "None found.").or(go);
            // What sits on it.
            let copies = self.op_all(c, "cephblockpools.ceph.rook.io").iter().chain(self.op_all(c, "cephfilesystems.ceph.rook.io").iter().flat_map(|f| f["spec"]["dataPools"].as_array().into_iter().flatten())).filter_map(|p| p["spec"]["replicated"]["size"].as_i64().or(p["replicated"]["size"].as_i64())).min();
            let classes: HashSet<&str> = self.refs(c, Kind::StorageClasses, "").unwrap_or_default().into_iter().filter(|s| s["provisioner"].as_str().unwrap_or("").contains("ceph")).map(name_of).collect();
            let claims: Vec<&Value> = self.refs(c, Kind::PersistentVolumeClaims, "").unwrap_or_default().into_iter().filter(|p| p["spec"]["storageClassName"].as_str().map(|s| classes.contains(s)).unwrap_or(false)).collect();
            let hint = match copies {
                Some(n) if n > 1 => format!("the pools keep {n} copies: one failing disk loses nothing, but these wait while it's rebuilt"),
                Some(_) => "a pool keeps one copy: a failing disk loses data".into(),
                None => String::new(),
            };
            let mut l: Vec<Item> = claims
                .iter()
                .map(|p| {
                    let use_ = self.claim_usage(c, ns_of(p), name_of(p));
                    let share = use_.as_ref().map(|x| x.used / x.capacity.max(1.0)).unwrap_or(0.0);
                    let t = if share >= 0.9 { Tone::Danger } else if share >= 0.75 { Tone::Warning } else { Tone::Success };
                    Item::new(t, vec![self.full_name(c, p), use_.map(|x| format!("{:.0}% full", x.used / x.capacity.max(1.0) * 100.0)).unwrap_or("-".into()), text(&p["status"]["capacity"]["storage"]), text(&p["spec"]["storageClassName"])]).go(Some(obj(c, Kind::PersistentVolumeClaims, ns_of(p), name_of(p))))
                })
                .collect();
            worst_first(&mut l);
            let l = self.op_filter(l);
            go = table(ui, &format!("Claims on it ({})", l.len()), &hint, &[("Claim", 0.5), ("Use", 0.15), ("Size", 0.15), ("Class", 0.2)], &l, 30, &self.missing(c, Kind::PersistentVolumeClaims).unwrap_or("None.".into())).or(go);
        }
        for k in ["cephblockpools.ceph.rook.io", "cephfilesystems.ceph.rook.io", "cephobjectstores.ceph.rook.io"] {
            go = self.kind_table(ui, k).or(go);
        }
        go
    }

    pub(super) fn gpu_page(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        let now = kube::now_secs();
        let mut nodes: Vec<Item> = vec![];
        let mut holders: Vec<Item> = vec![];
        let (mut total, mut asked) = (0.0, 0.0);
        let mut shared = false;
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            let pods = self.refs(c, Kind::Pods, "").unwrap_or_default();
            for p in pods.iter().filter(|p| !matches!(p["status"]["phase"].as_str(), Some("Succeeded" | "Failed"))) {
                let n = pod_gpus(p);
                if n > 0.0 {
                    let v = pod::verdict(p, now);
                    let use_ = self.metrics.get(c).and_then(|m| m.pods.get(&(ns_of(p).to_string(), name_of(p).to_string()))).map(|x| format!("{} CPU, {}", hive::cores(x.0), gib(x.1))).unwrap_or("-".into());
                    holders.push(Item::new(v.0, vec![self.full_name(c, p), v.1, format!("{n:.0}"), text(&p["spec"]["nodeName"]), use_]).go(Some(obj(c, Kind::Pods, ns_of(p), name_of(p)))));
                }
            }
            for n in self.refs(c, Kind::Nodes, "").unwrap_or_default() {
                let g = gpus(&n["status"]["allocatable"]);
                if g.is_empty() {
                    continue;
                }
                let have: f64 = g.iter().map(|x| x.1).sum();
                let want: f64 = pods.iter().filter(|p| p["spec"]["nodeName"].as_str() == Some(name_of(n)) && !matches!(p["status"]["phase"].as_str(), Some("Succeeded" | "Failed"))).map(|p| pod_gpus(p)).sum();
                total += have;
                asked += want;
                let l = &n["metadata"]["labels"];
                let share = text(&l["nvidia.com/gpu.sharing-strategy"]);
                let real = text(&l["nvidia.com/gpu.count"]);
                let split = !share.is_empty() && share != "none";
                shared |= split;
                let v = face::verdict(Kind::Nodes, n, now);
                nodes.push(Item::new(v.0, vec![self.full_name(c, n), v.1, text(&l["nvidia.com/gpu.product"]), g.iter().map(|x| format!("{:.0} {}", x.1, x.0)).collect::<Vec<_>>().join(", "), format!("{want:.0} of {have:.0}"), if split { format!("{} shared ({share})", if real.is_empty() { "cards".into() } else { many(real.parse().unwrap_or(1), "card") }) } else { "no".into() }, l["nvidia.com/gpu.memory"].as_str().and_then(|m| m.parse::<f64>().ok()).map(|m| gib(m * 1048576.0)).unwrap_or("-".into())]).go(Some(obj(c, Kind::Nodes, "", name_of(n)))));
            }
        }
        let pol: Vec<Item> = self.op_items("clusterpolicies.nvidia.com").into_iter().map(|(c, o)| { let st = text(&o["status"]["state"]); Item::new(if st == "ready" { Tone::Success } else { Tone::Danger }, vec![self.full_name(c, o), st]) }).collect();
        // The operator's own pods.
        let mut own: Vec<Item> = vec![];
        for (c, o) in self.op_items("clusterpolicies.nvidia.com") {
            for p in self.refs(c, Kind::Pods, o["status"]["namespace"].as_str().unwrap_or("gpu-operator")).unwrap_or_default() {
                let v = pod::verdict(p, now);
                own.push(Item::new(v.0, vec![self.full_name(c, p), v.1, text(&p["metadata"]["labels"]["app"]), text(&p["spec"]["nodeName"])]).go(Some(obj(c, Kind::Pods, ns_of(p), name_of(p)))));
            }
        }
        let ill = own.iter().filter(|i| i.bad()).count() + pol.iter().filter(|i| i.bad()).count();
        let f = Face {
            tone: if ill > 0 { Tone::Warning } else if total > 0.0 { Tone::Success } else { Tone::Muted },
            head: if total > 0.0 { format!("{asked:.0} of {total:.0} requested") } else { self.active.iter().find_map(|c| self.missing(c, Kind::Nodes)).unwrap_or("No GPUs found".into()) },
            sub: if shared { "some cards are shared, so there are more to ask for than cards".into() } else { "by what pods ask for; how busy a card is isn't known here".into() },
            notes: if ill > 0 { vec![format!("{} of the GPU operator need a look.", many(ill as i64, "part"))] } else { vec![] },
            pills: vec![],
            facts: vec![Fact::new("Not requested", format!("{:.0}", (total - asked).max(0.0))), Fact::new("Nodes", nodes.len().to_string()), Fact::new("Pods with one", holders.len().to_string()), Fact::new("Operator", pol.first().map(|p| p.cells[1].clone()).unwrap_or("-".into()))],
        };
        let share = if total > 0.0 { asked / total } else { 0.0 };
        face::show(ui, &f, Side::Ring(share, format!("{:.0}%", share * 100.0), "requested".into()));
        ui.add_space(12.0);
        self.bad_switch(ui);
        go = table(ui, "Nodes", "", &[("Node", 0.18), ("State", 0.16), ("Card", 0.22), ("Allocatable", 0.14), ("Requested", 0.1), ("Shared", 0.12), ("Memory", 0.08)], &self.op_filter(nodes), 40, "None.").or(go);
        worst_first(&mut holders);
        go = table(ui, &format!("Pods with a GPU ({})", holders.len()), "", &[("Pod", 0.4), ("State", 0.18), ("GPUs", 0.08), ("Node", 0.16), ("Uses", 0.18)], &self.op_filter(holders), 60, "No pod asks for one.").or(go);
        worst_first(&mut own);
        go = table(ui, &format!("The operator's pods ({})", own.len()), "drivers, device plugins and the like", &[("Pod", 0.4), ("State", 0.2), ("Part", 0.24), ("Node", 0.16)], &self.op_filter(own), 40, "None found.").or(go);
        go
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cards_and_scaling() {
        assert_eq!(gpus(&json!({"cpu": "4", "nvidia.com/gpu": "3", "nvidia.com/mig-1g.5gb": "2", "memory": "1Gi", "example.com/gpus-none": "1"})).iter().map(|x| x.1).sum::<f64>(), 5.0);
        assert!(gpus(&json!({"nvidia.com/gpu": "0"})).is_empty());
        assert_eq!(pod_gpus(&json!({"spec": {"containers": [{"resources": {"limits": {"nvidia.com/gpu": "1"}}}, {}]}})), 1.0);
        let k = |ready: &str, active: &str| json!({"status": {"conditions": [{"type": "Ready", "status": ready, "message": "bad"}, {"type": "Active", "status": active}], "triggersActivity": {"a": {"isActive": active == "True"}, "b": {"isActive": false}}}});
        assert_eq!(keda_state(&k("True", "True")), (Tone::Success, "Active".into(), "1 of 2 triggers active".into()));
        assert_eq!(keda_state(&k("True", "False")).1, "Asleep");
        assert_eq!(keda_state(&k("False", "False")), (Tone::Danger, "Not ready".into(), "bad".into()));
        assert_eq!(keda_state(&json!({"metadata": {"annotations": {"autoscaling.keda.sh/paused": "true"}}})).1, "Paused");
    }
}
