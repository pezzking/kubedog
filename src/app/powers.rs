//! Superpowers: which there are, whether each is Auto, On or Off, and finding out by itself what the
//! open clusters have.

use super::*;

/// An operator with a page of its own. `find` are the kinds that show it's in use ("plural.group", or
/// "/group/version/plural" for what isn't a custom resource); `more` are read as well.
pub(super) struct Op {
    pub id: &'static str,
    pub label: &'static str,
    pub find: &'static [&'static str],
    pub more: &'static [&'static str],
    /// Read only when asked for.
    pub slow: &'static [&'static str],
    pub kinds: &'static [Kind],
}

const fn op(id: &'static str, label: &'static str, find: &'static [&'static str], more: &'static [&'static str], slow: &'static [&'static str], kinds: &'static [Kind]) -> Op {
    Op { id, label, find, more, slow, kinds }
}

pub(super) const OPS: &[Op] = &[
    op("openshift", "OpenShift", &[openshift::VERSIONS], openshift::MORE, &[], &[Kind::Nodes, Kind::Pods, Kind::CertificateSigningRequests]),
    op("argo", "Argo CD", &["applications.argoproj.io"], &["applicationsets.argoproj.io"], &[], &[]),
    op("secrets", "External Secrets", &["externalsecrets.external-secrets.io"], &["secretstores.external-secrets.io", "clustersecretstores.external-secrets.io", "pushsecrets.external-secrets.io"], &[], &[Kind::Pods, Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::CronJobs]),
    op("certs", "Certificates", &["certificates.cert-manager.io"], &["issuers.cert-manager.io", "clusterissuers.cert-manager.io"], &["certificaterequests.cert-manager.io", "orders.acme.cert-manager.io", "challenges.acme.cert-manager.io"], &[Kind::Ingresses]),
    op("keda", "KEDA", &["scaledobjects.keda.sh", "scaledjobs.keda.sh"], &["triggerauthentications.keda.sh"], &[], &[Kind::HorizontalPodAutoscalers]),
    op("ceph", "Ceph", &["cephclusters.ceph.rook.io"], &["cephblockpools.ceph.rook.io", "cephfilesystems.ceph.rook.io", "cephobjectstores.ceph.rook.io"], &[], &[Kind::Pods, Kind::PersistentVolumes, Kind::PersistentVolumeClaims, Kind::StorageClasses]),
    op("prom", "Monitoring", &["prometheuses.monitoring.coreos.com", "servicemonitors.monitoring.coreos.com"], &["alertmanagers.monitoring.coreos.com", "prometheusrules.monitoring.coreos.com", "podmonitors.monitoring.coreos.com"], &[], &[Kind::Services, Kind::Pods]),
    op("gateways", "Gateways", &["/networking.k8s.io/v1/ingresses", "/route.openshift.io/v1/routes", "gateways.gateway.networking.k8s.io", "virtualservices.networking.istio.io", "ingressroutes.traefik.io", "apisixroutes.apisix.apache.org"], &["httproutes.gateway.networking.k8s.io"], &[], &[Kind::Ingresses, Kind::Services, Kind::EndpointSlices]),
    op("gpu", "GPUs", &["clusterpolicies.nvidia.com"], &["nvidiadrivers.nvidia.com"], &[], &[Kind::Nodes, Kind::Pods]),
    op("backups", "Backups", &["backups.velero.io", "policies.config.kio.kasten.io"], &["schedules.velero.io", "backupstoragelocations.velero.io", "restores.velero.io", "profiles.config.kio.kasten.io"], &[], &[Kind::PersistentVolumeClaims, Kind::Namespaces]),
    op("kafka", "Kafka (Strimzi)", &["kafkas.kafka.strimzi.io"], &["kafkatopics.kafka.strimzi.io", "kafkausers.kafka.strimzi.io", "kafkaconnects.kafka.strimzi.io"], &[], &[]),
    op("redis", "Redis", &["redis.redis.redis.opstreelabs.in", "redisfailovers.databases.spotahome.com", "redisenterpriseclusters.app.redislabs.com"], &[], &[], &[]),
    op("mongodb", "MongoDB", &["mongodbcommunity.mongodbcommunity.mongodb.com", "perconaservermongodbs.psmdb.percona.com"], &[], &[], &[]),
    op("rabbitmq", "RabbitMQ", &["rabbitmqclusters.rabbitmq.com"], &["queues.rabbitmq.com", "users.rabbitmq.com"], &[], &[]),
    op("flux", "Flux", &["kustomizations.kustomize.toolkit.fluxcd.io", "helmreleases.helm.toolkit.fluxcd.io"], &["gitrepositories.source.toolkit.fluxcd.io", "helmrepositories.source.toolkit.fluxcd.io"], &[], &[]),
    op("tekton", "Tekton", &["pipelineruns.tekton.dev"], &["pipelines.tekton.dev"], &[], &[]),
    op("policies", "Policies (Kyverno, Gatekeeper)", &["clusterpolicies.kyverno.io", "constrainttemplates.templates.gatekeeper.sh"], &["policies.kyverno.io"], &[], &[]),
    op("crossplane", "Crossplane", &["providers.pkg.crossplane.io"], &["compositeresourcedefinitions.apiextensions.crossplane.io", "compositions.apiextensions.crossplane.io"], &[], &[]),
    op("longhorn", "Longhorn", &["volumes.longhorn.io"], &["nodes.longhorn.io"], &[], &[]),
    op("metallb", "MetalLB", &["ipaddresspools.metallb.io"], &["l2advertisements.metallb.io", "bgppeers.metallb.io", "bgpadvertisements.metallb.io"], &[], &[Kind::Services]),
    op("keycloak", "Keycloak", &["keycloaks.k8s.keycloak.org"], &["keycloakrealmimports.k8s.keycloak.org"], &[], &[]),
];

/// The other superpowers: (id, name, what finds it, page).
pub(super) const OWN: &[(&str, &str, &str, View)] = &[
    ("incident", "Incident Room", "always there", View::Incident),
    ("readiness", "Readiness", "always there", View::Readiness),
    ("netlab", "Network Lab", "always there", View::NetLab),
    ("shell", "Shell", "always there", View::Shells),
    ("hive", "Pod Hive", "always there", View::Hive),
    ("grafana", "Nodes (Grafana)", "a Grafana in Settings > Special monitoring", View::Observatory),
    ("proxmox", "Proxmox", "one that is set up here, or a cluster that runs on it", View::Proxmox),
    ("postgres", "Postgres Clusters", "CloudNativePG clusters", View::Postgres),
    ("elastic", "Elasticsearch", "Elasticsearch run by ECK", View::Elastic),
    ("pulsar", "Pulsar", "pods that run Pulsar", View::Pulsar),
];

#[derive(Clone, Copy, PartialEq, Debug)]
pub(super) enum Choice {
    Auto,
    On,
    Off,
}

pub(super) fn op_index(id: &str) -> Option<u8> {
    OPS.iter().position(|o| o.id == id).map(|i| i as u8)
}

/// The superpower a page belongs to.
pub(super) fn power_of(v: View) -> Option<&'static str> {
    match v {
        View::Op(i) => OPS.get(i as usize).map(|o| o.id),
        v => OWN.iter().find(|o| o.3 == v).map(|o| o.0),
    }
}

/// What was found of an operator in a cluster.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(super) enum Seen {
    Yes,
    No,
    Refused,
}

#[derive(Default)]
pub(super) struct Powers {
    /// (cluster, kind) -> whether there are any.
    seen: HashMap<(String, String), Seen>,
    pub(super) asked: HashMap<String, Instant>,
    /// Lists of operators: when each was last read is in the lists themselves.
    pub bad_only: bool,
    /// Slow kinds were asked for.
    pub slow: bool,
    pub tab: usize,
    /// OpenShift: the tab, and the platform's own namespaces too.
    pub os_tab: usize,
    pub os_system: bool,
    /// The object whose page within an operator's page is open.
    pub sel: Option<crds::CustomSel>,
    /// Answers of things that aren't lists ("routes|ctx", "alerts|ctx|ns"...).
    pub answers: HashMap<String, Option<Result<Value, String>>>,
    pub asked_at: HashMap<String, Instant>,
    /// Ceph's used bytes over time, per cluster.
    pub ceph: HashMap<String, std::collections::VecDeque<(f64, f64)>>,
}

impl KubedogApp {
    pub(super) fn power_choice(&self, id: &str) -> Choice {
        match self.prefs.powers.get(id).map(|s| s.as_str()) {
            Some("on") => Choice::On,
            Some("off") => Choice::Off,
            _ => Choice::Auto,
        }
    }

    pub(super) fn power_off(&self, id: &str) -> bool {
        self.power_choice(id) == Choice::Off
    }

    /// Whether the open clusters have it.
    pub(super) fn power_found(&self, id: &str) -> bool {
        match id {
            "incident" | "readiness" | "netlab" | "shell" | "hive" => true,
            "grafana" => self.has_grafana(),
            "proxmox" => self.has_proxmox(),
            "postgres" => self.has_pg(),
            "elastic" => self.has_elastic(),
            "pulsar" => self.has_pulsar(),
            _ => {
                let Some(i) = op_index(id) else { return false };
                let gpu = id == "gpu" && self.active.iter().any(|c| self.refs(c, Kind::Nodes, "").unwrap_or_default().iter().any(|n| !opinfra::gpus(&n["status"]["allocatable"]).is_empty()));
                gpu || OPS[i as usize].find.iter().any(|k| self.active.iter().any(|c| self.powers.seen.get(&(c.clone(), k.to_string())) == Some(&Seen::Yes)))
            }
        }
    }

    pub(super) fn power_shown(&self, id: &str) -> bool {
        match self.power_choice(id) {
            Choice::On => true,
            Choice::Off => false,
            Choice::Auto => self.power_found(id),
        }
    }

    /// The pages in the sidebar and in search, in order.
    pub(super) fn power_pages(&self) -> Vec<(View, &'static str)> {
        let mut v: Vec<(View, &'static str)> = OWN.iter().filter(|o| self.power_shown(o.0)).map(|o| (o.3, o.1)).collect();
        v.extend(OPS.iter().enumerate().filter(|(_, o)| self.power_shown(o.id)).map(|(i, o)| (View::Op(i as u8), o.label)));
        v
    }

    /// Once per cluster (and again when asked): is there at least one of each operator's kinds?
    pub(super) fn probe_powers(&mut self, force: bool) {
        if self.demo {
            return;
        }
        self.sync_crds();
        for c in self.active.clone() {
            if !force && self.powers.asked.contains_key(&c) {
                continue;
            }
            if self.lists.get(&Self::list_key(&c, Kind::CustomResourceDefinitions)).map(|l| l.fetched.is_none()).unwrap_or(true) {
                continue;
            }
            self.powers.asked.insert(c.clone(), Instant::now());
            let mut paths: Vec<(String, String, String, bool)> = vec![];
            for o in OPS.iter().filter(|o| !self.power_off(o.id)) {
                for f in o.find {
                    if let Some(rest) = f.strip_prefix('/') {
                        let mut p = rest.split('/');
                        if let (Some(g), Some(v), Some(pl)) = (p.next(), p.next(), p.next()) {
                            paths.push((f.to_string(), format!("/apis/{g}/{v}"), pl.to_string(), true));
                        }
                    } else if let Some(k) = self.crds_of(&c).into_iter().find(|k| k.key == *f) {
                        paths.push((f.to_string(), format!("/apis/{}/{}", k.group, k.version), k.plural.clone(), k.namespaced));
                    }
                }
            }
            let own = self.default_ns(&c);
            let limited = self.prefs.ctx_namespaces.get(&c).cloned();
            let known = self.namespaces.get(&c).cloned().unwrap_or_default();
            let ctx = c.clone();
            self.spawn(move |k| {
                let names = |k: &Kubectl| match &limited {
                    Some(p) => expand_namespaces(k, &ctx, p, &known).unwrap_or_default(),
                    None => visible_namespaces(k, &ctx).unwrap_or_default(),
                };
                let mut spaces: Option<Vec<String>> = None;
                let mut out = serde_json::Map::new();
                for (key, base, plural, namespaced) in paths {
                    let get = |p: String| k.run(&raw_args(&ctx, &p)).and_then(|t| serde_json::from_str::<Value>(&t).map_err(|e| e.to_string())).map(|v| v["items"].as_array().map(|a| !a.is_empty()).unwrap_or(false));
                    let mut r = if limited.is_some() && namespaced { Err("forbidden".into()) } else { get(format!("{base}/{plural}?limit=1")) };
                    if namespaced && r.as_ref().err().map(|e: &String| is_refusal(e) || e == "forbidden").unwrap_or(false) {
                        let list = spaces.get_or_insert_with(|| {
                            let v = names(k);
                            if v.is_empty() { vec![own.clone()] } else { v }
                        });
                        for n in list.iter().take(20) {
                            let x = get(format!("{base}/namespaces/{n}/{plural}?limit=1"));
                            let found = x == Ok(true);
                            if x.is_ok() || r.is_err() {
                                r = x;
                            }
                            if found {
                                break;
                            }
                        }
                    }
                    let word = match r { Ok(true) => "yes", Ok(false) => "no", Err(e) if is_refusal(&e) => "refused", Err(_) => "no" };
                    out.insert(key, Value::String(word.into()));
                }
                Msg::Text { key: format!("powers|{ctx}"), result: Ok(Value::Object(out).to_string()) }
            });
        }
    }

    /// The custom kinds one cluster has.
    fn crds_of(&self, ctx: &str) -> Vec<crds::CrdKind> {
        let Some(l) = self.lists.get(&Self::list_key(ctx, Kind::CustomResourceDefinitions)) else { return vec![] };
        let names: HashSet<&str> = l.items.iter().filter_map(|o| o["metadata"]["name"].as_str()).collect();
        self.crds.iter().filter(|k| names.contains(k.key.as_str())).cloned().collect()
    }

    pub(super) fn on_powers(&mut self, key: &str, result: &Result<String, String>) -> bool {
        if let Some(ctx) = key.strip_prefix("powers|") {
            if let Some(Value::Object(m)) = result.as_ref().ok().and_then(|t| serde_json::from_str(t).ok()) {
                for (k, v) in m {
                    let s = match v.as_str() { Some("yes") => Seen::Yes, Some("refused") => Seen::Refused, _ => Seen::No };
                    self.powers.seen.insert((ctx.to_string(), k), s);
                }
            }
            return true;
        }
        if let Some(k) = key.strip_prefix("answer|") {
            let v = result.as_ref().map_err(|e| e.clone()).and_then(|t| serde_json::from_str(t).map_err(|e| e.to_string()));
            self.powers.answers.insert(k.to_string(), Some(v));
            return true;
        }
        false
    }

    /// Ask something once (or again after `every`): the answer is JSON, kept under `key`.
    pub(super) fn ask(&mut self, key: &str, every: u64, force: bool, f: impl FnOnce(&Kubectl) -> Result<String, String> + Send + 'static) {
        if self.demo || matches!(self.powers.answers.get(key), Some(None)) {
            return;
        }
        if !force && self.powers.asked_at.get(key).map(|t| t.elapsed() < Duration::from_secs(every)).unwrap_or(false) {
            return;
        }
        self.powers.asked_at.insert(key.to_string(), Instant::now());
        // An answer that's there stays until the new one comes.
        if !self.powers.answers.contains_key(key) {
            self.powers.answers.insert(key.to_string(), None);
        }
        let key = format!("answer|{key}");
        self.spawn(move |k| Msg::Text { key, result: f(k) });
    }

    pub(super) fn answer(&self, key: &str) -> Option<&Result<Value, String>> {
        self.powers.answers.get(key).and_then(|a| a.as_ref())
    }

    /// Read the kinds of the operator whose page is open.
    pub(super) fn refresh_op(&mut self, force: bool) {
        self.probe_powers(false);
        let View::Op(i) = self.view else { return };
        let Some(o) = OPS.get(i as usize) else { return };
        if self.power_off(o.id) {
            return;
        }
        self.sync_crds();
        for k in o.find {
            self.read_custom(k, 20, force);
        }
        for k in o.more {
            self.read_custom(k, 60, force);
        }
        if self.powers.slow {
            for k in o.slow {
                self.read_custom(k, 120, force);
            }
        }
        self.refresh_op_extra(o.id, force);
    }

    /// Read a custom kind in every open cluster that has it, at most every so many seconds.
    pub(super) fn read_custom(&mut self, key: &str, every: u64, force: bool) {
        let Some(i) = self.crd_index(key) else { return };
        for c in self.active.clone() {
            let l = self.lists.get(&Self::custom_list_key(&c, &self.crds[i as usize]));
            let has = self.lists.get(&Self::list_key(&c, Kind::CustomResourceDefinitions)).map(|l| l.items.iter().any(|o| o["metadata"]["name"].as_str() == Some(key))).unwrap_or(false);
            let refused = l.and_then(|l| l.error.as_deref()).map(is_refusal).unwrap_or(false);
            let stale = l.and_then(|l| l.fetched).map(|t| t.elapsed() >= Duration::from_secs(every)).unwrap_or(true);
            if has && (force || (stale && !refused)) {
                self.fetch_custom(&c, i);
            }
        }
    }

    /// Are the lists of the operator's page still being read for the first time?
    pub(super) fn op_loading(&self) -> bool {
        let View::Op(i) = self.view else { return false };
        let Some(o) = OPS.get(i as usize) else { return false };
        let crds = |c: &String| self.lists.get(&Self::list_key(c, Kind::CustomResourceDefinitions));
        if self.active.iter().any(|c| crds(c).map(|l| l.fetched.is_none() && l.error.is_none()).unwrap_or(true)) {
            return true;
        }
        let first = |c: &String, k: &str| -> bool {
            let has = crds(c).map(|l| l.items.iter().any(|o| o["metadata"]["name"].as_str() == Some(k))).unwrap_or(false);
            has && self.crd_index(k).map(|i| self.lists.get(&Self::custom_list_key(c, &self.crds[i as usize])).map(|l| l.fetched.is_none() && l.error.is_none()).unwrap_or(true)).unwrap_or(true)
        };
        o.find.iter().chain(o.more).any(|k| self.active.iter().any(|c| first(c, k))) || self.powers.answers.values().any(|a| a.is_none())
    }

    /// Settings > Superpowers.
    pub(super) fn settings_powers(&mut self, ui: &mut Ui) {
        settings::title(ui, "Superpowers", "Auto shows one as soon as an open cluster has it. On always shows it, for accounts that can't see whether it's there. Off hides it everywhere and reads nothing for it.");
        let mut change: Option<(String, Choice)> = None;
        let mut again = false;
        // For pictures.
        if self.screenshot.is_some() && std::env::var("KUBEDOG_SHOT_SETUP").is_ok() {
            self.proxmox.setup = std::env::var("KUBEDOG_SHOT_SETUP").as_deref() != Ok("netlab");
            self.netlab.setup = !self.proxmox.setup;
        }
        ui.horizontal(|ui| {
            again = button(ui, "Look again", false, false);
            for (t, c) in [("All Auto", Choice::Auto), ("All Off", Choice::Off)] {
                if button(ui, t, false, false) {
                    change = Some((String::new(), c));
                }
            }
        });
        ui.add_space(8.0);
        let list: Vec<(&str, &str, String)> = OWN.iter().map(|o| (o.0, o.1, o.2.to_string())).chain(OPS.iter().map(|o| (o.id, o.label, o.find.iter().map(|f| f.split('/').next_back().unwrap_or(f).split('.').next().unwrap_or(f)).collect::<Vec<_>>().join(", ")))).collect();
        card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for (j, (id, label, finds)) in list.iter().enumerate() {
                let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(40.0)), Sense::hover());
                if j > 0 {
                    ui.painter().hline(r.x_range(), r.top(), Stroke::new(1.0, BORDER_SUBTLE()));
                }
                let found = self.power_found(id);
                let choice = self.power_choice(id);
                let shown = self.power_shown(id);
                ui.painter().circle_filled(egui::pos2(r.left() + u(6.0), r.center().y), u(4.5), if shown { SUCCESS() } else { BORDER_DEFAULT() });
                pg::label_at(ui, ui.painter(), egui::pos2(r.left() + u(20.0), r.center().y), label, 14.0, if choice == Choice::Off { TEXT_SUBTLE() } else { TEXT_DEFAULT() }, u(220.0));
                let words = if *finds == "always there" {
                    String::new()
                } else if found {
                    "found".to_string()
                } else if op_index(id).map(|i| OPS[i as usize].find.iter().any(|k| self.active.iter().any(|c| self.powers.seen.get(&(c.clone(), k.to_string())) == Some(&Seen::Refused)))).unwrap_or(false) {
                    format!("your account can't see {finds}")
                } else if self.active.is_empty() || !self.connected {
                    format!("looks for {finds}")
                } else {
                    if op_index(id).is_some() && !self.active.iter().all(|c| self.powers.seen.keys().any(|k| k.0 == *c)) { "looking…".into() } else { format!("not found ({finds})") }
                };
                pg::label_at(ui, ui.painter(), egui::pos2(r.left() + u(250.0), r.center().y), &words, 12.0, if found { SUCCESS() } else { TEXT_PLACEHOLDER() }, (r.width() - u(250.0) - u(if matches!(*id, "proxmox" | "grafana" | "netlab") { 330.0 } else { 230.0 })).max(10.0));
                if matches!(*id, "proxmox" | "grafana" | "netlab") {
                    let open = match *id { "proxmox" => self.proxmox.setup, "netlab" => self.netlab.setup, _ => false };
                    let b = egui::Rect::from_min_size(egui::pos2(r.right() - u(304.0), r.center().y - u(13.0)), egui::vec2(u(88.0), u(26.0)));
                    let resp = ui.interact(b, ui.id().with(("power-set", id)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                    ui.painter().rect(b, CornerRadius::same(6), if resp.hovered() { BG_HOVER() } else { Color32::TRANSPARENT }, Stroke::new(1.0, BORDER_DEFAULT()), egui::StrokeKind::Inside);
                    ui.painter().text(b.center(), egui::Align2::CENTER_CENTER, if open { "Close" } else { "Settings" }, FontId::proportional(z(12.5)), PRIMARY_TEXT());
                    if resp.clicked() {
                        if *id == "netlab" {
                            self.netlab.setup = !open;
                        } else if *id == "proxmox" {
                            self.proxmox.setup = !open;
                        } else {
                            self.settings_section = "Special monitoring";
                        }
                    }
                }
                let mut x = r.right() - u(204.0);
                for (c, t) in [(Choice::Auto, "Auto"), (Choice::On, "On"), (Choice::Off, "Off")] {
                    let b = egui::Rect::from_min_size(egui::pos2(x, r.center().y - u(13.0)), egui::vec2(u(66.0), u(26.0)));
                    let resp = ui.interact(b, ui.id().with(("power", id, t)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                    let on = choice == c;
                    ui.painter().rect_filled(b, CornerRadius::same(6), if on { PRIMARY() } else if resp.hovered() { BG_HOVER() } else { BG_MUTED() });
                    ui.painter().text(b.center(), egui::Align2::CENTER_CENTER, t, FontId::proportional(z(12.5)), if on { Color32::WHITE } else { TEXT_MUTED() });
                    if resp.clicked() {
                        change = Some((id.to_string(), c));
                    }
                    x += u(69.0);
                }
                // Its settings, under it.
                if *id == "netlab" && self.netlab.setup {
                    Frame::new().inner_margin(Margin { left: 20, right: 0, top: 4, bottom: 14 }).show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 6.0;
                        ui.set_width(ui.available_width());
                        self.settings_netlab(ui);
                    });
                }
                if *id == "proxmox" && self.proxmox.setup {
                    Frame::new().inner_margin(Margin { left: 20, right: 0, top: 4, bottom: 14 }).show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 6.0;
                        ui.set_width(ui.available_width());
                        self.settings_proxmox(ui);
                    });
                }
            }
        });
        if let Some((id, c)) = change {
            let ids: Vec<String> = if id.is_empty() { list.iter().map(|l| l.0.to_string()).collect() } else { vec![id] };
            for id in ids {
                match c {
                    Choice::Auto => self.prefs.powers.remove(&id),
                    Choice::On => self.prefs.powers.insert(id, "on".into()),
                    Choice::Off => self.prefs.powers.insert(id, "off".into()),
                };
            }
            self.save();
            again = c != Choice::Off;
        }
        if again {
            self.probe_powers(true);
        }
    }
}

/// Reading one address of the API, as it is.
pub(super) fn raw_args(ctx: &str, path: &str) -> Vec<String> {
    ["--context", ctx, "get", "--raw", path, &format!("--request-timeout={}", kube::REQUEST_TIMEOUT)].iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique() {
        let ids: Vec<&str> = OWN.iter().map(|o| o.0).chain(OPS.iter().map(|o| o.id)).collect();
        assert_eq!(ids.iter().collect::<HashSet<_>>().len(), ids.len());
        assert!(OPS.iter().all(|o| !o.find.is_empty() && o.find.iter().all(|f| f.contains('.'))));
        for (i, o) in OPS.iter().enumerate() {
            assert_eq!(power_of(View::Op(i as u8)), Some(o.id));
            assert_eq!(view_from_name(&view_name(View::Op(i as u8))), Some(View::Op(i as u8)));
        }
        assert_eq!(power_of(View::Hive), Some("hive"));
        assert_eq!(power_of(View::Helm), None);
        assert_eq!(view_from_name("op:nothing"), None);
        assert_eq!(raw_args("c", "/apis/x?limit=1")[..4].join(" "), "--context c get --raw");
    }
}
