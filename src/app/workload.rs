//! An object's references (what it uses and what uses it) and a deployment's
//! Revisions (its rollout history, with rolling back to an earlier one).

use super::*;

/// A kind from an object's `kind` field ("ReplicaSet" → ReplicaSets).
pub(super) fn kind_named(k: &str) -> Option<Kind> {
    GROUPS.iter().flat_map(|g| g.1.iter().copied()).find(|x| x.singular().replace(' ', "").eq_ignore_ascii_case(k))
}

/// The pod template of a pod or workload.
pub(super) fn pod_spec(kind: Kind, o: &Value) -> &Value {
    match kind {
        Kind::Pods => &o["spec"],
        Kind::CronJobs => &o["spec"]["jobTemplate"]["spec"]["template"]["spec"],
        _ => &o["spec"]["template"]["spec"],
    }
}

/// Everything a pod spec points at: (kind, name), without repeats.
pub(super) fn uses_of(ps: &Value) -> Vec<(Kind, String)> {
    let mut out: Vec<(Kind, String)> = vec![];
    let mut add = |k: Kind, n: Option<&str>| {
        if let Some(n) = n.filter(|n| !n.is_empty()) {
            if !out.iter().any(|(a, b)| *a == k && b == n) {
                out.push((k, n.to_string()));
            }
        }
    };
    add(Kind::ServiceAccounts, ps["serviceAccountName"].as_str().or(ps["serviceAccount"].as_str()));
    for v in ps["volumes"].as_array().into_iter().flatten() {
        add(Kind::ConfigMaps, v["configMap"]["name"].as_str());
        add(Kind::Secrets, v["secret"]["secretName"].as_str());
        add(Kind::PersistentVolumeClaims, v["persistentVolumeClaim"]["claimName"].as_str());
        for src in v["projected"]["sources"].as_array().into_iter().flatten() {
            add(Kind::ConfigMaps, src["configMap"]["name"].as_str());
            add(Kind::Secrets, src["secret"]["name"].as_str());
        }
    }
    for s in ps["imagePullSecrets"].as_array().into_iter().flatten() {
        add(Kind::Secrets, s["name"].as_str());
    }
    let containers = ps["initContainers"].as_array().into_iter().flatten().chain(ps["containers"].as_array().into_iter().flatten());
    for c in containers {
        for e in c["env"].as_array().into_iter().flatten() {
            add(Kind::ConfigMaps, e["valueFrom"]["configMapKeyRef"]["name"].as_str());
            add(Kind::Secrets, e["valueFrom"]["secretKeyRef"]["name"].as_str());
        }
        for f in c["envFrom"].as_array().into_iter().flatten() {
            add(Kind::ConfigMaps, f["configMapRef"]["name"].as_str());
            add(Kind::Secrets, f["secretRef"]["name"].as_str());
        }
    }
    out
}

/// Kinds whose pages show what uses them.
pub(super) fn has_users(k: Kind) -> bool {
    matches!(k, Kind::ConfigMaps | Kind::Secrets | Kind::ServiceAccounts | Kind::PersistentVolumeClaims | Kind::Services)
}

impl KubedogApp {
    fn items_ns(&self, ctx: &str, kind: Kind, ns: &str) -> Vec<Value> {
        self.lists.get(&Self::list_key(ctx, kind)).map(|l| l.items.iter().filter(|o| o["metadata"]["namespace"].as_str() == Some(ns)).cloned().collect()).unwrap_or_default()
    }

    /// What an object belongs to, uses and is used by: (how, what kind, name, where to).
    pub(super) fn refs_of(&self, sel: &Selected, o: &Value) -> Vec<face::Ref> {
        let mut rows: Vec<(&'static str, Vec<(Kind, String)>)> = vec![];
        let mut out: Vec<face::Ref> = vec![];
        // What it is owned by.
        if let Some(own) = o["metadata"]["ownerReferences"].as_array().and_then(|a| a.first()) {
            if let (Some(k), Some(n)) = (own["kind"].as_str().and_then(kind_named), own["name"].as_str()) {
                rows.push(("Owner", vec![(k, n.to_string())]));
            } else if let Some(n) = own["name"].as_str() {
                // A kind Kubedog has no page for.
                out.push(("Owner", own["kind"].as_str().unwrap_or("").to_string(), n.to_string(), None));
            }
        }
        // What it uses.
        if matches!(sel.kind, Kind::Pods | Kind::Deployments | Kind::StatefulSets | Kind::DaemonSets | Kind::ReplicaSets | Kind::Jobs | Kind::CronJobs) {
            let used = uses_of(pod_spec(sel.kind, o));
            if !used.is_empty() {
                rows.push(("Uses", used));
            }
        }
        if sel.kind == Kind::Ingresses {
            let mut v: Vec<(Kind, String)> = vec![];
            for r in o["spec"]["rules"].as_array().into_iter().flatten() {
                for p in r["http"]["paths"].as_array().into_iter().flatten() {
                    if let Some(n) = p["backend"]["service"]["name"].as_str() {
                        if !v.iter().any(|x| x.1 == n) {
                            v.push((Kind::Services, n.to_string()));
                        }
                    }
                }
            }
            for t in o["spec"]["tls"].as_array().into_iter().flatten() {
                if let Some(n) = t["secretName"].as_str() {
                    v.push((Kind::Secrets, n.to_string()));
                }
            }
            if !v.is_empty() {
                rows.push(("Uses", v));
            }
        }
        // What uses it.
        if has_users(sel.kind) {
            let mut v: Vec<(Kind, String)> = vec![];
            if sel.kind == Kind::Services {
                for ing in self.items_ns(&sel.ctx, Kind::Ingresses, &sel.ns) {
                    let hit = ing["spec"]["rules"].as_array().into_iter().flatten().flat_map(|r| r["http"]["paths"].as_array().into_iter().flatten()).any(|p| p["backend"]["service"]["name"].as_str() == Some(&sel.name));
                    if hit {
                        v.push((Kind::Ingresses, ing["metadata"]["name"].as_str().unwrap_or("").to_string()));
                    }
                }
            } else {
                if sel.kind == Kind::Secrets {
                    for ing in self.items_ns(&sel.ctx, Kind::Ingresses, &sel.ns) {
                        if ing["spec"]["tls"].as_array().into_iter().flatten().any(|t| t["secretName"].as_str() == Some(&sel.name)) {
                            v.push((Kind::Ingresses, ing["metadata"]["name"].as_str().unwrap_or("").to_string()));
                        }
                    }
                }
                for k in [Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::CronJobs, Kind::Jobs, Kind::Pods] {
                    for w in self.items_ns(&sel.ctx, k, &sel.ns) {
                        // Pods and jobs made by a controller are counted through it.
                        if matches!(k, Kind::Pods | Kind::Jobs) && w["metadata"]["ownerReferences"].as_array().map(|a| !a.is_empty()).unwrap_or(false) {
                            continue;
                        }
                        if uses_of(pod_spec(k, &w)).iter().any(|(uk, un)| *uk == sel.kind && un == &sel.name) {
                            v.push((k, w["metadata"]["name"].as_str().unwrap_or("").to_string()));
                        }
                    }
                }
            }
            rows.push(("Used by", v));
        }
        // Services that send it traffic.
        if sel.kind == Kind::Pods || work::is_work(sel.kind) {
            let labels = if sel.kind == Kind::Pods { &o["metadata"]["labels"] } else { &o["spec"]["template"]["metadata"]["labels"] };
            let v: Vec<(Kind, String)> = self.refs(&sel.ctx, Kind::Services, &sel.ns).unwrap_or_default().into_iter().filter(|s| s["spec"]["selector"].as_object().map(|m| !m.is_empty()).unwrap_or(false) && podnet::selector_matches(&s["spec"]["selector"], labels)).map(|s| (Kind::Services, work::name_of(s).to_string())).collect();
            rows.push(("Selected by", v));
        }
        let spec = &o["spec"];
        let one = |k: Kind, v: &Value| v.as_str().filter(|n| !n.is_empty()).map(|n| (k, n.to_string()));
        let uses: Vec<(Kind, String)> = match sel.kind {
            Kind::PersistentVolumeClaims => [one(Kind::PersistentVolumes, &spec["volumeName"]), one(Kind::StorageClasses, &spec["storageClassName"])].into_iter().flatten().collect(),
            Kind::PersistentVolumes => one(Kind::StorageClasses, &spec["storageClassName"]).into_iter().collect(),
            Kind::Ingresses => one(Kind::IngressClasses, &spec["ingressClassName"]).into_iter().collect(),
            Kind::EndpointSlices => one(Kind::Services, &o["metadata"]["labels"]["kubernetes.io/service-name"]).into_iter().collect(),
            Kind::HorizontalPodAutoscalers => spec["scaleTargetRef"]["kind"].as_str().and_then(kind_named).and_then(|k| one(k, &spec["scaleTargetRef"]["name"])).into_iter().collect(),
            Kind::RoleBindings | Kind::ClusterRoleBindings => one(if o["roleRef"]["kind"] == "Role" { Kind::Roles } else { Kind::ClusterRoles }, &o["roleRef"]["name"]).into_iter().collect(),
            Kind::VolumeAttachments => [one(Kind::PersistentVolumes, &spec["source"]["persistentVolumeName"]), one(Kind::Nodes, &spec["nodeName"])].into_iter().flatten().collect(),
            _ => vec![],
        };
        rows.push(("Uses", uses));
        if let (Kind::PersistentVolumes, Some(n), Some(ns)) = (sel.kind, spec["claimRef"]["name"].as_str(), spec["claimRef"]["namespace"].as_str()) {
            out.push(("Claim", Kind::PersistentVolumeClaims.singular().into(), format!("{ns}/{n}"), Some(Selected { ctx: sel.ctx.clone(), kind: Kind::PersistentVolumeClaims, ns: ns.into(), name: n.into() })));
        }
        for (how, items) in rows {
            for (k, n) in items {
                let ns = if k.namespaced() { sel.ns.clone() } else { String::new() };
                out.push((how, k.singular().to_string(), n.clone(), Some(Selected { ctx: sel.ctx.clone(), kind: k, ns, name: n })));
            }
        }
        out
    }

    /// A stateful set's or daemon set's Revisions tab, from its controller revisions.
    pub(super) fn controller_revisions(&mut self, ui: &mut Ui, sel: &Selected, obj: Option<&Value>) {
        let key = format!("revs|{}", sel.key());
        let (ctx, ns) = (sel.ctx.clone(), sel.ns.clone());
        self.ask(&key, 20, false, move |k| {
            let a: Vec<String> = ["--context", &ctx, "-n", &ns, "get", "controllerrevisions.apps", "-o", "json", &format!("--request-timeout={}", kube::REQUEST_TIMEOUT)].iter().map(|s| s.to_string()).collect();
            let l: Vec<Value> = kube::parse_items(&k.run(&a)?)?
                .iter()
                .map(|o| {
                    let cs = &o["data"]["spec"]["template"]["spec"]["containers"];
                    serde_json::json!({"name": o["metadata"]["name"], "uid": o["metadata"]["ownerReferences"][0]["uid"], "rev": o["revision"], "at": o["metadata"]["creationTimestamp"], "cause": o["metadata"]["annotations"]["kubernetes.io/change-cause"], "images": cs.as_array().into_iter().flatten().map(|c| c["image"].clone()).collect::<Vec<_>>()})
                })
                .collect();
            Ok(Value::Array(l).to_string())
        });
        let uid = obj.and_then(|o| o["metadata"]["uid"].as_str()).unwrap_or("").to_string();
        let mut l: Vec<Value> = match self.answer(&key) {
            Some(Ok(v)) => v.as_array().into_iter().flatten().filter(|r| r["uid"].as_str() == Some(&uid)).cloned().collect(),
            Some(Err(e)) => {
                ui.label(RichText::new(truncate(e, 200)).color(WARNING()));
                return;
            }
            None => {
                ui.spinner();
                return;
            }
        };
        l.sort_by_key(|r| std::cmp::Reverse(r["rev"].as_i64().unwrap_or(0)));
        let cur = l.first().and_then(|r| r["rev"].as_i64()).unwrap_or(0);
        let now_images = l.first().map(|r| r["images"].clone()).unwrap_or_default();
        ui.label(RichText::new(format!("{} revisions kept (spec.revisionHistoryLimit {})", l.len(), obj.and_then(|o| o["spec"]["revisionHistoryLimit"].as_i64()).unwrap_or(10))).size(z(12.5)).color(TEXT_SUBTLE()));
        ui.add_space(6.0);
        let mut back: Option<i64> = None;
        egui::ScrollArea::vertical().id_salt("crevs").auto_shrink([false, false]).show(ui, |ui| {
            for r in &l {
                let n = r["rev"].as_i64().unwrap_or(0);
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("Revision {n}")).size(z(15.0)).strong().color(TEXT_DEFAULT()));
                        if n == cur {
                            ui.label(RichText::new("current").size(z(12.0)).color(SUCCESS()));
                        }
                        ui.label(RichText::new(format!("{} ago", kube::age(r["at"].as_str().unwrap_or("")))).size(z(12.0)).color(TEXT_SUBTLE()));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if n != cur && button(ui, "Roll back to this", false, false) {
                                back = Some(n);
                            }
                        });
                    });
                    for i in r["images"].as_array().into_iter().flatten() {
                        let changed = !now_images.as_array().map(|a| a.contains(i)).unwrap_or(false);
                        ui.label(RichText::new(i.as_str().unwrap_or("")).monospace().size(z(12.0)).color(if changed { WARNING() } else { TEXT_MUTED() }));
                    }
                    if let Some(c) = r["cause"].as_str() {
                        ui.label(RichText::new(c).size(z(12.0)).color(TEXT_SUBTLE()));
                    }
                    ui.label(RichText::new(r["name"].as_str().unwrap_or("")).size(z(11.5)).color(TEXT_PLACEHOLDER()));
                });
                ui.add_space(4.0);
            }
        });
        if let Some(r) = back {
            let body = format!("Roll {} “{}” back to revision {r}? Its pods are replaced with that revision's (kubectl rollout undo --to-revision={r}).", sel.kind.singular(), sel.name);
            self.request(Action::Rollback(sel.clone(), r), "Roll back".into(), body, "Roll back", false);
        }
    }

    /// A deployment's Revisions tab: its replica sets, newest first.
    pub(super) fn detail_revisions(&mut self, ui: &mut Ui, sel: &Selected, obj: Option<&Value>) {
        let Some(l) = self.lists.get(&Self::list_key(&sel.ctx, Kind::ReplicaSets)).filter(|l| l.fetched.is_some()) else {
            ui.spinner();
            return;
        };
        let mut sets: Vec<Value> = l
            .items
            .iter()
            .filter(|rs| rs["metadata"]["namespace"].as_str() == Some(&sel.ns))
            .filter(|rs| rs["metadata"]["ownerReferences"].as_array().into_iter().flatten().any(|r| r["kind"] == "Deployment" && r["name"].as_str() == Some(&sel.name)))
            .cloned()
            .collect();
        let rev = |rs: &Value| rs["metadata"]["annotations"]["deployment.kubernetes.io/revision"].as_str().and_then(|r| r.parse::<i64>().ok()).unwrap_or(0);
        sets.sort_by_key(|rs| std::cmp::Reverse(rev(rs)));
        let current = obj.and_then(|o| o["metadata"]["annotations"]["deployment.kubernetes.io/revision"].as_str()).and_then(|r| r.parse::<i64>().ok()).unwrap_or_else(|| sets.first().map(rev).unwrap_or(0));
        let images = |rs: &Value| -> Vec<String> { rs["spec"]["template"]["spec"]["containers"].as_array().into_iter().flatten().map(|c| c["image"].as_str().unwrap_or("").to_string()).collect() };
        let cur_images = sets.iter().find(|rs| rev(rs) == current).map(images).unwrap_or_default();
        ui.label(RichText::new(format!("{} revisions kept (spec.revisionHistoryLimit {})", sets.len(), obj.and_then(|o| o["spec"]["revisionHistoryLimit"].as_i64()).unwrap_or(10))).size(z(12.5)).color(TEXT_SUBTLE()));
        ui.add_space(6.0);
        let mut rollback: Option<i64> = None;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for rs in &sets {
                let r = rev(rs);
                let is_cur = r == current;
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("Revision {r}")).size(z(15.0)).strong().color(TEXT_DEFAULT()));
                        if is_cur {
                            ui.label(RichText::new("current").size(z(12.0)).color(SUCCESS()));
                        }
                        let ts = rs["metadata"]["creationTimestamp"].as_str().unwrap_or("");
                        ui.label(RichText::new(format!("{} ago", kube::age(ts))).size(z(12.0)).color(TEXT_SUBTLE()));
                        let (want, ready) = (rs["spec"]["replicas"].as_i64().unwrap_or(0), rs["status"]["readyReplicas"].as_i64().unwrap_or(0));
                        ui.label(RichText::new(format!("{ready}/{want} pods")).size(z(12.0)).color(if want > 0 { SUCCESS() } else { TEXT_PLACEHOLDER() }));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if !is_cur && button(ui, "Roll back to this", false, false) {
                                rollback = Some(r);
                            }
                        });
                    });
                    for img in images(rs) {
                        let changed = !cur_images.contains(&img);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("image").size(z(12.0)).color(TEXT_PLACEHOLDER()));
                            ui.label(RichText::new(img).monospace().size(z(12.0)).color(if changed && !is_cur { WARNING() } else { TEXT_MUTED() }));
                        });
                    }
                    if let Some(c) = rs["metadata"]["annotations"]["kubernetes.io/change-cause"].as_str() {
                        ui.label(RichText::new(c).size(z(12.0)).color(TEXT_SUBTLE()));
                    }
                    ui.label(RichText::new(rs["metadata"]["name"].as_str().unwrap_or("")).size(z(11.5)).color(TEXT_PLACEHOLDER()));
                });
                ui.add_space(4.0);
            }
        });
        if let Some(r) = rollback {
            let body = format!("Roll deployment “{}” back to revision {r}? Its pods are replaced with that revision's (kubectl rollout undo --to-revision={r}).", sel.name);
            self.request(Action::Rollback(sel.clone(), r), "Roll back".into(), body, "Roll back", false);
        }
    }
}
