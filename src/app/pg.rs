//! Postgres clusters run by CloudNativePG (CNPG): a list, a page per cluster (a live replication
//! map, health checks, backups, databases, connections) and a panel on an instance's pod page.
//! Everything here reads from the cluster's own CNPG resources; what's live (positions, lag,
//! archiving) comes from `kubectl cnpg status` when that plugin is installed, and so do the
//! actions, which all go through the protection lock and a confirmation.

use super::*;

pub(super) const CRD_CLUSTERS: &str = "clusters.postgresql.cnpg.io";
const CRD_BACKUPS: &str = "backups.postgresql.cnpg.io";
const CRD_SCHEDULES: &str = "scheduledbackups.postgresql.cnpg.io";
const CRD_POOLERS: &str = "poolers.postgresql.cnpg.io";
const CRD_DATABASES: &str = "databases.postgresql.cnpg.io";
/// How often the live state is read while a page shows it.
const STATUS_EVERY: Duration = Duration::from_secs(10);
const HISTORY: usize = 180;

/// Which cluster: context, namespace, name.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub(super) struct PgId {
    pub ctx: String,
    pub ns: String,
    pub name: String,
}

impl PgId {
    fn key(&self) -> String {
        format!("pgstatus|{}|{}|{}", self.ctx, self.ns, self.name)
    }
}

/// One Postgres instance, as the plugin reports it.
#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct Instance {
    pub name: String,
    pub primary: bool,
    pub node: String,
    pub ready: bool,
    /// Position in the write-ahead log: written (primary) or replayed (replica).
    pub lsn: Option<u64>,
    pub received: Option<u64>,
    pub timeline: i64,
    /// Seconds a replica is behind, and its replication state ("streaming", "async"...).
    pub lag: Option<f64>,
    pub state: String,
    pub sync: String,
    pub pending_restart: bool,
    pub replay_paused: bool,
    pub version: String,
    pub slot_active: Option<bool>,
    pub error: String,
}

/// The live state of a cluster.
#[derive(Clone, Debug, Default)]
pub(super) struct Live {
    pub instances: Vec<Instance>,
    pub archiving: Option<bool>,
    pub last_archived: String,
    pub last_archived_at: Option<i64>,
    pub last_failed: String,
    pub waiting_wals: i64,
}

/// What's kept per cluster: the latest state, and readings for the chart.
#[derive(Default)]
pub(super) struct PgState {
    loading: bool,
    fetched: Option<Instant>,
    error: Option<String>,
    live: Option<Live>,
    /// (when, primary's position, worst lag in seconds)
    hist: std::collections::VecDeque<(i64, u64, f64)>,
}

// ---------- reading ----------

/// "31/5B1D6B70" as a byte position.
pub(super) fn lsn(s: &str) -> Option<u64> {
    let (a, b) = s.split_once('/')?;
    let (a, b) = (u64::from_str_radix(a, 16).ok()?, u64::from_str_radix(b, 16).ok()?);
    if a > u32::MAX as u64 || b > u32::MAX as u64 {
        return None;
    }
    Some((a << 32) | b)
}

/// A Postgres interval ("00:00:00.018255", "1 day 02:00:00") in seconds.
pub(super) fn interval(s: &str) -> Option<f64> {
    let mut total = 0.0;
    let mut seen = false;
    let mut num: Option<f64> = None;
    for w in s.split_whitespace() {
        if w.contains(':') {
            let neg = w.starts_with('-');
            let p: Vec<f64> = w.trim_start_matches('-').split(':').map(|x| x.parse().ok()).collect::<Option<_>>()?;
            let secs = p.iter().fold(0.0, |a, x| a * 60.0 + x);
            total += if neg { -secs } else { secs };
            seen = true;
        } else if let Ok(n) = w.parse::<f64>() {
            num = Some(n);
        } else if w.starts_with("day") {
            total += num.take()? * 86400.0;
            seen = true;
        } else {
            return None;
        }
    }
    seen.then_some(total)
}

/// The parts of `kubectl cnpg status -o json` used here.
pub(super) fn parse_status(v: &Value) -> Live {
    let mut out = Live::default();
    let items = v["instanceStatus"]["items"].as_array().cloned().unwrap_or_default();
    let mut repl: HashMap<String, (Option<f64>, String, String)> = HashMap::new();
    let mut slots: Vec<(String, bool)> = vec![];
    for it in &items {
        for r in it["replicationInfo"].as_array().into_iter().flatten() {
            let name = r["applicationName"].as_str().unwrap_or("").to_string();
            let lag = r["replayLag"].as_str().and_then(interval);
            repl.insert(name, (lag, r["state"].as_str().unwrap_or("").into(), r["syncState"].as_str().unwrap_or("").into()));
        }
        for s in it["replicationSlotsInfo"].as_array().into_iter().flatten() {
            slots.push((s["slotName"].as_str().unwrap_or("").to_string(), s["active"].as_bool().unwrap_or(false)));
        }
    }
    for it in &items {
        let name = it["pod"]["metadata"]["name"].as_str().unwrap_or("").to_string();
        let primary = it["isPrimary"].as_bool().unwrap_or(false);
        let pos = |k: &str| it[k].as_str().and_then(lsn);
        let r = repl.get(&name);
        let slot = format!("_cnpg_{}", name.replace('-', "_"));
        out.instances.push(Instance {
            primary,
            node: it["node"].as_str().unwrap_or("").into(),
            ready: it["isPodReady"].as_bool().unwrap_or(false),
            lsn: if primary { pos("currentLsn") } else { pos("replayLsn").or_else(|| pos("receivedLsn")) },
            received: pos("receivedLsn"),
            timeline: it["timeLineID"].as_i64().unwrap_or(0),
            lag: r.and_then(|r| r.0),
            state: r.map(|r| r.1.clone()).unwrap_or_default(),
            sync: r.map(|r| r.2.clone()).unwrap_or_default(),
            pending_restart: it["pendingRestart"].as_bool().unwrap_or(false),
            replay_paused: it["replayPaused"].as_bool().unwrap_or(false),
            version: it["instanceManagerVersion"].as_str().unwrap_or("").into(),
            slot_active: slots.iter().find(|s| s.0 == slot).map(|s| s.1),
            error: it["error"].as_str().unwrap_or("").into(),
            name,
        });
        if primary {
            out.archiving = it["isArchivingWAL"].as_bool();
            out.last_archived = it["lastArchivedWAL"].as_str().unwrap_or("").into();
            out.last_archived_at = it["lastArchivedWALTime"].as_str().and_then(kube::parse_time);
            out.last_failed = it["lastFailedWAL"].as_str().unwrap_or("").into();
            out.waiting_wals = it["readyWalFiles"].as_i64().or(it["readyWALFiles"].as_i64()).unwrap_or(0);
        }
    }
    out.instances.sort_by(|a, b| b.primary.cmp(&a.primary).then(a.name.cmp(&b.name)));
    out
}

/// "2027-01-08 15:30:05 +0000 UTC" (as CNPG writes certificate dates) in seconds.
fn go_time(s: &str) -> Option<i64> {
    kube::parse_time(&format!("{}T{}Z", s.get(0..10)?, s.get(11..19)?))
}

pub(super) fn bytes(b: f64) -> String {
    if b < 1024.0 {
        return format!("{b:.0} B");
    }
    if b < 1048576.0 {
        return format!("{:.0} KiB", b / 1024.0);
    }
    if b < 1073741824.0 {
        return format!("{:.1} MiB", b / 1048576.0);
    }
    format!("{:.1} GiB", b / 1073741824.0)
}

pub(super) fn lag_text(s: f64) -> String {
    if s < 0.001 {
        "under 1 ms".into()
    } else if s < 1.0 {
        format!("{:.0} ms", s * 1000.0)
    } else if s < 60.0 {
        format!("{s:.1} s")
    } else {
        kube::human_duration(s as i64)
    }
}

/// The Postgres version from an image ("…/postgresql:18.6-system-trixie" → "18.6").
fn pg_version(c: &Value) -> String {
    let img = c["status"]["image"].as_str().or(c["spec"]["imageName"].as_str()).unwrap_or("");
    let tag = img.rsplit('/').next().unwrap_or("").split('@').next().unwrap_or("").rsplit_once(':').map(|x| x.1).unwrap_or("");
    let v: String = tag.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    if !v.is_empty() {
        return v;
    }
    c["status"]["pgDataImageInfo"]["majorVersion"].as_i64().map(|m| m.to_string()).unwrap_or_default()
}

/// A cluster's colour: green when it says it's healthy and everything is ready.
fn cluster_tone(c: &Value) -> Tone {
    let st = &c["status"];
    let (want, ready) = (c["spec"]["instances"].as_i64().unwrap_or(0), st["readyInstances"].as_i64().unwrap_or(0));
    let healthy = st["phase"].as_str().unwrap_or("").contains("healthy");
    if c["metadata"]["annotations"]["cnpg.io/hibernation"].as_str() == Some("on") {
        Tone::Muted
    } else if healthy && ready >= want && want > 0 {
        Tone::Success
    } else if ready == 0 {
        Tone::Danger
    } else {
        Tone::Warning
    }
}

/// Whether backups have somewhere to go.
fn backup_store(c: &Value) -> bool {
    c["spec"]["backup"]["barmanObjectStore"].is_object() || c["spec"]["backup"]["volumeSnapshot"].is_object() || c["spec"]["plugins"].as_array().map(|a| !a.is_empty()).unwrap_or(false)
}

/// One thing looked at by the health checks.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Check {
    pub tone: Tone,
    pub title: String,
    pub detail: String,
}

/// What the checks need besides the cluster itself.
pub(super) struct Facts<'a> {
    pub live: Option<&'a Live>,
    /// This cluster's backups and schedules.
    pub backups: Vec<&'a Value>,
    pub schedules: Vec<&'a Value>,
    /// (instance, node) of its pods.
    pub nodes: Vec<(String, String)>,
    /// (volume, share used)
    pub disks: Vec<(String, f64)>,
    pub now: i64,
}

/// Look a cluster over, worst first.
pub(super) fn checks(c: &Value, f: &Facts) -> Vec<Check> {
    let mut out: Vec<Check> = vec![];
    let mut add = |tone: Tone, title: &str, detail: String| out.push(Check { tone, title: title.into(), detail });
    let (sp, st) = (&c["spec"], &c["status"]);
    let (want, ready) = (sp["instances"].as_i64().unwrap_or(0), st["readyInstances"].as_i64().unwrap_or(0));
    if ready >= want && want > 0 {
        add(Tone::Success, "All instances ready", format!("{ready} of {want}"));
    } else {
        add(if ready == 0 { Tone::Danger } else { Tone::Warning }, "Instances missing", format!("{ready} of {want} ready · {}", st["phase"].as_str().unwrap_or("")));
    }
    if let (Some(cur), Some(target)) = (st["currentPrimary"].as_str(), st["targetPrimary"].as_str()) {
        if cur != target {
            add(Tone::Warning, "Primary is moving", format!("{cur} → {target}"));
        }
    }
    // Redundancy.
    if want == 1 {
        add(Tone::Warning, "No standby", "One instance only: if its pod or node fails, the database is down until it's back".into());
    } else if f.nodes.len() > 1 {
        let mut n: Vec<&str> = f.nodes.iter().map(|x| x.1.as_str()).collect();
        n.sort();
        n.dedup();
        if n.len() < f.nodes.len() {
            add(Tone::Warning, "Instances share a node", format!("{} instances on {} nodes", f.nodes.len(), n.len()));
        } else {
            add(Tone::Success, "Spread over nodes", format!("{} instances on {} nodes", f.nodes.len(), n.len()));
        }
    }
    // Replication.
    if let Some(l) = f.live {
        let worst = l.instances.iter().filter(|i| !i.primary).filter_map(|i| i.lag).fold(0.0f64, f64::max);
        let replicas = l.instances.iter().filter(|i| !i.primary).count();
        let streaming = l.instances.iter().filter(|i| !i.primary && i.state == "streaming").count();
        if replicas > 0 {
            if streaming < replicas {
                add(Tone::Danger, "Replication broken", format!("{streaming} of {replicas} replicas are streaming"));
            }
            if worst >= 60.0 {
                add(Tone::Danger, "Replicas far behind", format!("up to {}", lag_text(worst)));
            } else if worst >= 5.0 {
                add(Tone::Warning, "Replicas behind", format!("up to {}", lag_text(worst)));
            } else if streaming == replicas {
                add(Tone::Success, "Replicas in step", format!("{streaming} streaming, at most {} behind", lag_text(worst)));
            }
        }
        for i in l.instances.iter().filter(|i| i.pending_restart) {
            add(Tone::Warning, "Restart pending", format!("{} has settings waiting for a restart", i.name));
        }
        for i in l.instances.iter().filter(|i| i.replay_paused) {
            add(Tone::Warning, "Replay paused", i.name.clone());
        }
        for i in l.instances.iter().filter(|i| i.slot_active == Some(false) && !i.primary) {
            add(Tone::Warning, "Idle replication slot", format!("{}'s slot isn't in use and keeps WAL on disk", i.name));
        }
        for i in l.instances.iter().filter(|i| !i.error.is_empty()) {
            add(Tone::Warning, "Instance reported an error", format!("{}: {}", i.name, truncate(&i.error, 160)));
        }
    }
    // Archiving and backups.
    let has_backup = backup_store(c);
    let cond = |t: &str| st["conditions"].as_array().into_iter().flatten().find(|x| x["type"].as_str() == Some(t)).cloned();
    // (Without a store CNPG calls archiving fine while archiving nothing.)
    if let Some(a) = cond("ContinuousArchiving").filter(|_| has_backup) {
        if a["status"].as_str() == Some("True") {
            add(Tone::Success, "WAL archiving works", f.live.and_then(|l| l.last_archived_at).map(|t| format!("last file {} ago", kube::human_duration((f.now - t).max(0)))).unwrap_or_default());
        } else {
            add(Tone::Danger, "WAL archiving fails", a["message"].as_str().unwrap_or("").to_string());
        }
    }
    let last_ok = st["lastSuccessfulBackup"].as_str().and_then(kube::parse_time).or_else(|| {
        f.backups.iter().filter(|b| b["status"]["phase"].as_str() == Some("completed")).filter_map(|b| b["status"]["stoppedAt"].as_str().and_then(kube::parse_time)).max()
    });
    if !has_backup && f.backups.is_empty() {
        add(Tone::Danger, "No backups", "CNPG has no backup store for it and archives no WAL: after losing its disks, nothing here could bring the data back".into());
    } else {
        match last_ok {
            Some(t) => {
                let age = f.now - t;
                let text = format!("{} ago", kube::human_duration(age.max(0)));
                if age > 48 * 3600 {
                    add(Tone::Danger, "Backup is old", text);
                } else if age > 26 * 3600 {
                    add(Tone::Warning, "Backup is over a day old", text);
                } else {
                    add(Tone::Success, "Fresh backup", text);
                }
            }
            None => add(Tone::Danger, "No backup has succeeded", "A backup store is set up, but no finished backup is known".into()),
        }
        if f.schedules.is_empty() {
            add(Tone::Warning, "No backup schedule", "Backups only happen when someone starts one".into());
        }
        let newest = f.backups.iter().filter_map(|b| Some((b["metadata"]["creationTimestamp"].as_str()?, b))).max_by_key(|x| x.0);
        if let Some((_, b)) = newest.filter(|(_, b)| b["status"]["phase"].as_str() == Some("failed")) {
            add(Tone::Danger, "Latest backup failed", truncate(b["status"]["error"].as_str().unwrap_or(""), 160));
        }
    }
    // Certificates.
    let soonest = st["certificates"]["expirations"].as_object().into_iter().flatten().filter_map(|(k, v)| Some((go_time(v.as_str()?)?, k.clone()))).min();
    if let Some((t, name)) = soonest {
        let days = (t - f.now) / 86400;
        if t < f.now {
            add(Tone::Danger, "Certificate expired", name);
        } else if days < 7 {
            add(Tone::Warning, "Certificate expires soon", format!("{name} in {days}d (the operator normally renews it in time)"));
        } else {
            add(Tone::Success, "Certificates valid", format!("the first one expires in {days}d"));
        }
    }
    // Disks.
    if let Some((name, share)) = f.disks.iter().max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal)) {
        let text = format!("{name} is {:.0}% full", share * 100.0);
        if *share >= 0.9 {
            add(Tone::Danger, "Disk almost full", text);
        } else if *share >= 0.75 {
            add(Tone::Warning, "Disk filling up", text);
        } else {
            add(Tone::Success, "Room on disk", text);
        }
    }
    let rank = |t: Tone| match t { Tone::Danger => 0, Tone::Warning => 1, _ => 2 };
    out.sort_by_key(|c| rank(c.tone));
    out
}

// ---------- state ----------

impl KubedogApp {
    /// Whether an open cluster has Postgres clusters.
    pub(super) fn has_pg(&self) -> bool {
        self.active.iter().any(|c| !self.pg_list(c, CRD_CLUSTERS).is_empty())
    }

    pub(super) fn pg_list(&self, ctx: &str, crd: &str) -> &[Value] {
        let Some(k) = self.crd_index(crd).and_then(|i| self.crds.get(i as usize)) else { return &[] };
        self.lists.get(&Self::custom_list_key(ctx, k)).map(|l| l.items.as_slice()).unwrap_or(&[])
    }

    fn pg_cluster(&self, id: &PgId) -> Option<&Value> {
        self.pg_list(&id.ctx, CRD_CLUSTERS).iter().find(|o| o["metadata"]["name"].as_str() == Some(&id.name) && o["metadata"]["namespace"].as_str() == Some(&id.ns))
    }

    /// Items of a kind that name this cluster in `spec.cluster.name`.
    fn pg_owned(&self, id: &PgId, crd: &str) -> Vec<&Value> {
        self.pg_list(&id.ctx, crd).iter().filter(|o| o["metadata"]["namespace"].as_str() == Some(&id.ns) && o["spec"]["cluster"]["name"].as_str() == Some(&id.name)).collect()
    }

    fn pg_pods(&self, id: &PgId) -> Vec<&Value> {
        self.lists
            .get(&Self::list_key(&id.ctx, Kind::Pods))
            .map(|l| l.items.as_slice())
            .unwrap_or(&[])
            .iter()
            .filter(|p| {
                let m = &p["metadata"];
                m["namespace"].as_str() == Some(&id.ns) && m["labels"]["cnpg.io/cluster"].as_str() == Some(&id.name) && m["labels"]["cnpg.io/podRole"].as_str().unwrap_or("instance") == "instance"
            })
            .collect()
    }

    /// The cluster an instance's pod belongs to.
    pub(super) fn pg_of_pod(ctx: &str, pod: &Value) -> Option<PgId> {
        let m = &pod["metadata"];
        if m["labels"]["cnpg.io/podRole"].as_str().unwrap_or("instance") != "instance" {
            return None;
        }
        Some(PgId { ctx: ctx.into(), ns: m["namespace"].as_str()?.into(), name: m["labels"]["cnpg.io/cluster"].as_str()?.into() })
    }

    /// The cluster whose live state the current page shows.
    fn pg_shown(&self) -> Option<PgId> {
        if self.power_off("postgres") {
            return None;
        }
        match &self.selected {
            None if self.view == View::Postgres => self.pg_sel.clone(),
            Some(s) if s.kind == Kind::Pods => self.object_of(s).and_then(|o| Self::pg_of_pod(&s.ctx, &o)),
            _ => None,
        }
    }

    pub(super) fn pg_wants_storage(&self) -> bool {
        self.pg_shown().is_some()
    }

    /// Read what the Postgres pages show (from refresh_current).
    pub(super) fn refresh_pg(&mut self, force: bool) {
        let shown = self.pg_shown();
        if self.power_off("postgres") || (self.view != View::Postgres && shown.is_none()) {
            return;
        }
        self.sync_crds();
        for crd in [CRD_CLUSTERS, CRD_BACKUPS, CRD_SCHEDULES, CRD_POOLERS, CRD_DATABASES] {
            if let Some(i) = self.crd_index(crd) {
                self.refresh_custom(i, force);
            }
        }
        if let Some(id) = shown {
            let stale = self.pg_state.get(&id.key()).and_then(|s| s.fetched).map(|t| t.elapsed() >= STATUS_EVERY).unwrap_or(true);
            if stale || force {
                self.fetch_pg_status(&id);
            }
        }
    }

    fn fetch_pg_status(&mut self, id: &PgId) {
        if self.demo || self.kubectl.cnpg.is_none() {
            return;
        }
        let key = id.key();
        let st = self.pg_state.entry(key.clone()).or_default();
        if st.loading {
            return;
        }
        st.loading = true;
        let args = cnpg_args(id, &["status", &id.name, "-o", "json", &format!("--request-timeout={}", kube::REQUEST_TIMEOUT)]);
        self.spawn(move |k| {
            // Only what's used is kept (the plugin also prints every pod in full).
            let result = k.run(&args).and_then(|t| {
                let v: Value = serde_json::from_str(&t).map_err(|e| format!("couldn't read the plugin's answer: {e}"))?;
                let items: Vec<Value> = v["instanceStatus"]["items"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|i| {
                        let mut i = i.clone();
                        let name = i["pod"]["metadata"]["name"].clone();
                        i["pod"] = serde_json::json!({"metadata": {"name": name}});
                        i
                    })
                    .collect();
                Ok(serde_json::json!({"instanceStatus": {"items": items}}).to_string())
            });
            Msg::Text { key, result }
        });
    }

    pub(super) fn on_pg_text(&mut self, key: &str, result: &Result<String, String>) -> bool {
        if !key.starts_with("pgstatus|") {
            return false;
        }
        let st = self.pg_state.entry(key.to_string()).or_default();
        st.loading = false;
        st.fetched = Some(Instant::now());
        match result.as_ref().map_err(|e| e.clone()).and_then(|t| serde_json::from_str::<Value>(t).map_err(|e| e.to_string())) {
            Ok(v) => {
                let live = parse_status(&v);
                if let Some(p) = live.instances.iter().find(|i| i.primary).and_then(|i| i.lsn) {
                    let worst = live.instances.iter().filter(|i| !i.primary).filter_map(|i| i.lag).fold(0.0, f64::max);
                    st.hist.push_back((kube::now_secs(), p, worst));
                    while st.hist.len() > HISTORY {
                        st.hist.pop_front();
                    }
                }
                st.live = Some(live);
                st.error = None;
            }
            Err(e) => st.error = Some(e),
        }
        true
    }

    /// For screenshots: whether the Postgres page's data is in.
    pub(super) fn pg_ready(&self) -> bool {
        let lists = [CRD_CLUSTERS, CRD_BACKUPS].iter().all(|crd| {
            let Some(k) = self.crd_index(crd).and_then(|i| self.crds.get(i as usize)) else { return false };
            self.active.iter().all(|c| self.lists.get(&Self::custom_list_key(c, k)).map(|l| l.fetched.is_some()).unwrap_or(false))
        });
        let live = match self.pg_shown() {
            Some(id) if self.kubectl.cnpg.is_some() => self.pg_state.get(&id.key()).map(|s| s.fetched.is_some() && s.hist.len() >= std::env::var("KUBEDOG_SHOT_READINGS").ok().and_then(|n| n.parse().ok()).unwrap_or(0)).unwrap_or(false) && self.claim_stats_state(&id.ctx).0,
            _ => true,
        };
        lists && live
    }

    fn pg_facts<'a>(&'a self, id: &PgId) -> Facts<'a> {
        let pods = self.pg_pods(id);
        let nodes = pods.iter().map(|p| (p["metadata"]["name"].as_str().unwrap_or("").to_string(), p["spec"]["nodeName"].as_str().unwrap_or("").to_string())).collect();
        let mut disks = vec![];
        for p in &pods {
            for v in p["spec"]["volumes"].as_array().into_iter().flatten() {
                if let Some(claim) = v["persistentVolumeClaim"]["claimName"].as_str() {
                    if let Some(u) = self.claim_usage(&id.ctx, &id.ns, claim) {
                        disks.push((claim.to_string(), u.used / u.capacity.max(1.0)));
                    }
                }
            }
        }
        Facts { live: self.pg_state.get(&id.key()).and_then(|s| s.live.as_ref()), backups: self.pg_owned(id, CRD_BACKUPS), schedules: self.pg_owned(id, CRD_SCHEDULES), nodes, disks, now: kube::now_secs() }
    }

    // ---------- actions ----------

    /// psql in the terminal. While the cluster is protected, the session starts read-only.
    fn pg_psql(&mut self, id: &PgId, replica: bool) {
        if self.screenshot.is_some() || self.demo {
            return;
        }
        let Some(bin) = self.kubectl.bin.clone() else { return };
        let read_only = !self.unlocked.contains(&id.ctx);
        let mut args = cnpg_args(id, &["psql"]);
        if replica {
            args.push("--replica".into());
        }
        args.push(id.name.clone());
        if read_only {
            args.extend(["--".to_string(), "dbname=postgres options=-cdefault_transaction_read_only=on".to_string()]);
        }
        let title = format!("psql {}{}{}", id.name, if replica { " (replica)" } else { "" }, if read_only { " · read-only" } else { "" });
        if read_only {
            self.toast("Protected: this psql session starts read-only. Unlock the cluster for a normal one.".into(), false);
        }
        self.run_in_terminal(title, &bin.to_string_lossy(), args, None);
    }

    fn pg_action(&mut self, id: &PgId, args: &[&str], what: String, title: &str, body: String, button: &str, danger: bool) {
        let action = Action::Cnpg { ctx: id.ctx.clone(), args: cnpg_args(id, args), what };
        self.request(action, title.into(), body, button, danger);
    }

    fn pg_backup(&mut self, id: &PgId) {
        self.pg_action(id, &["backup", &id.name], format!("Backup of {} started", id.name), "Back up now", format!("Start a backup of “{}” in {} now?", id.name, id.ns), "Back up", false);
    }

    fn pg_promote(&mut self, id: &PgId, inst: &str) {
        let lag = self.pg_state.get(&id.key()).and_then(|s| s.live.as_ref()).and_then(|l| l.instances.iter().find(|i| i.name == inst)).and_then(|i| i.lag);
        let behind = match lag {
            Some(l) if l >= 5.0 => format!("\n\nCareful: it is {} behind the primary right now.", lag_text(l)),
            Some(l) => format!("\n\nIt is {} behind the primary right now.", lag_text(l)),
            None => "\n\nHow far it is behind the primary isn't known right now.".into(),
        };
        self.pg_action(
            id,
            &["promote", &id.name, inst],
            format!("Switching {} over to {inst}", id.name),
            "Switch over",
            format!("Make “{inst}” the primary of “{}”? The current primary shuts down and comes back as a replica: open connections are cut and writes stop for a moment.{behind}", id.name),
            "Switch over",
            true,
        );
    }

    fn pg_restart(&mut self, id: &PgId, inst: Option<&str>, primary: bool) {
        match inst {
            Some(i) => {
                let how = if primary { "Postgres restarts in place: connections are cut and writes stop for a moment." } else { "Its pod is deleted and comes back; connections to it are cut." };
                self.pg_action(id, &["restart", &id.name, i], format!("Restarting {i}"), "Restart instance", format!("Restart “{i}”? {how}"), "Restart", true);
            }
            None => self.pg_action(
                id,
                &["restart", &id.name],
                format!("Restarting {}", id.name),
                "Restart cluster",
                format!("Restart every instance of “{}”? Replicas go first, then the primary, whose connections are cut.", id.name),
                "Restart",
                true,
            ),
        }
    }

    fn pg_reload(&mut self, id: &PgId) {
        self.pg_action(id, &["reload", &id.name], format!("Reloading the settings of {}", id.name), "Reload settings", format!("Have every instance of “{}” read its settings again? Nothing restarts.", id.name), "Reload", false);
    }

    fn open_pg(&mut self, id: PgId) {
        self.pg_sel = Some(id);
        if self.view != View::Postgres || self.selected.is_some() {
            self.navigate(View::Postgres, None);
        }
        self.refresh_pg(false);
    }

    /// An instance's pod, on its Overview or straight on its logs.
    fn open_instance(&mut self, id: &PgId, name: &str, logs: bool) {
        self.tab = if logs { Tab::Logs } else { Tab::Overview };
        self.navigate(View::Resource(Kind::Pods), Some(Selected { ctx: id.ctx.clone(), kind: Kind::Pods, ns: id.ns.clone(), name: name.to_string() }));
    }

    // ---------- the list ----------

    pub(super) fn postgres_view(&mut self, ui: &mut Ui) {
        if let Some(id) = self.pg_sel.clone() {
            self.pg_page(ui, &id);
            return;
        }
        let search = self.search.to_lowercase();
        let mut all: Vec<(PgId, Value)> = vec![];
        let mut loading = false;
        let mut errors: Vec<(String, String)> = vec![];
        let kind = self.crd_index(CRD_CLUSTERS).and_then(|i| self.crds.get(i as usize)).cloned();
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            match kind.as_ref().and_then(|k| self.lists.get(&Self::custom_list_key(c, k))) {
                Some(l) => {
                    loading |= l.fetched.is_none();
                    // A cluster without CNPG simply has none.
                    if let Some(e) = l.error.as_ref().filter(|e| !e.contains("the server doesn't have a resource type")) {
                        errors.push((c.clone(), e.clone()));
                    }
                    for o in &l.items {
                        let (ns, name) = (o["metadata"]["namespace"].as_str().unwrap_or("").to_string(), o["metadata"]["name"].as_str().unwrap_or("").to_string());
                        if self.ns_ok(&ns) && (search.is_empty() || name.to_lowercase().contains(&search) || ns.to_lowercase().contains(&search)) {
                            all.push((PgId { ctx: c.clone(), ns, name }, o.clone()));
                        }
                    }
                }
                None => loading = true,
            }
        }
        all.sort_by(|a, b| (&a.0.ns, &a.0.name).cmp(&(&b.0.ns, &b.0.name)));
        self.header(ui, true, Some(format!("{} Postgres Clusters", all.len())), true);
        for (c, e) in &errors {
            ui.label(RichText::new(format!("{}: {}", ctx_label(c), truncate(e, 300))).color(WARNING()));
        }
        if all.is_empty() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                if loading {
                    ui.spinner();
                } else {
                    ui.label(RichText::new("No Postgres clusters here").color(TEXT_SUBTLE()));
                }
            });
            return;
        }
        let mut open: Option<PgId> = None;
        egui::ScrollArea::vertical().id_salt("pg-list").auto_shrink([false, false]).show(ui, |ui| {
            ui.add_space(6.0);
            // In one line: how everything is.
            let inst: i64 = all.iter().map(|(_, c)| c["spec"]["instances"].as_i64().unwrap_or(0)).sum();
            let ready: i64 = all.iter().map(|(_, c)| c["status"]["readyInstances"].as_i64().unwrap_or(0)).sum();
            let healthy = all.iter().filter(|(_, c)| cluster_tone(c) == Tone::Success).count();
            ui.horizontal_wrapped(|ui| {
                pill(ui, &format!("{healthy} of {} healthy", all.len()), if healthy == all.len() { SUCCESS() } else { WARNING() });
                pill(ui, &format!("{ready} of {inst} instances ready"), if ready >= inst { SUCCESS() } else { WARNING() });
                let bare = all.iter().filter(|(_, c)| !c["status"]["lastSuccessfulBackup"].is_string()).count();
                if bare > 0 {
                    pill(ui, &format!("{bare} without a backup"), DANGER());
                }
                if self.kubectl.cnpg.is_none() {
                    pill(ui, "kubectl cnpg isn't installed: no live state or actions", WARNING());
                }
            });
            ui.add_space(12.0);
            let gap = 14.0;
            let avail = ui.available_width();
            let cols = ((avail + gap) / (u(400.0) + gap)).floor().max(1.0);
            let w = ((avail + gap) / cols - gap).min(u(520.0));
            for row in all.chunks(cols as usize) {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = gap;
                    for (id, c) in row {
                        if self.pg_card(ui, w, id, c).clicked() {
                            open = Some(id.clone());
                        }
                    }
                });
                ui.add_space(gap - 5.0);
            }
        });
        if let Some(id) = open {
            self.open_pg(id);
        }
    }

    /// A cluster in the list.
    fn pg_card(&self, ui: &mut Ui, w: f32, id: &PgId, c: &Value) -> egui::Response {
        let (r, resp) = ui.allocate_exact_size(egui::vec2(w, u(158.0)), Sense::click());
        let tone = tone_color(cluster_tone(c));
        let p = ui.painter();
        p.rect_filled(r, CornerRadius::same(10), if resp.hovered() { BG_HOVER() } else { BG_CARD() });
        p.rect_stroke(r, CornerRadius::same(10), Stroke::new(1.0, if resp.hovered() { PRIMARY_TEXT() } else { BORDER_SUBTLE() }), egui::StrokeKind::Inside);
        p.rect_filled(egui::Rect::from_min_size(r.min, egui::vec2(4.0, r.height())), CornerRadius { nw: 10, sw: 10, ne: 0, se: 0 }, tone);
        let x = r.left() + 18.0;
        let text = |pos: egui::Pos2, t: &str, size: f32, col: Color32, max: f32| {
            let g = p.layout_no_wrap(fit(ui, t, max, z(size)), FontId::proportional(z(size)), col);
            p.galley(pos - egui::vec2(0.0, g.size().y / 2.0), g, col);
        };
        let draw_db = r.right_top() + egui::vec2(-30.0, u(30.0));
        database_icon(p, draw_db, 11.0, tone);
        text(egui::pos2(x, r.top() + u(24.0)), &id.name, 15.5, PRIMARY_TEXT(), w - 80.0);
        let multi = self.active.len() > 1;
        let sub = if multi { format!("{} · {}", id.ns, ctx_label(&id.ctx)) } else { id.ns.clone() };
        text(egui::pos2(x, r.top() + u(45.0)), &format!("{sub}  ·  PostgreSQL {}", pg_version(c)), 12.0, TEXT_SUBTLE(), w - 80.0);
        // Instances as dots: the primary is the filled, larger one.
        let st = &c["status"];
        let primary = st["currentPrimary"].as_str().unwrap_or("");
        let healthy: Vec<&str> = st["instancesStatus"]["healthy"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).collect();
        let names: Vec<&str> = st["instanceNames"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).collect();
        let y = r.top() + u(76.0);
        let mut dx = x + 8.0;
        for n in names.iter().take(12) {
            let ok = healthy.contains(n);
            let col = if ok { SUCCESS() } else { DANGER() };
            if *n == primary {
                p.circle_filled(egui::pos2(dx, y), 8.0, col);
                p.text(egui::pos2(dx, y), egui::Align2::CENTER_CENTER, "P", FontId::proportional(10.5), BG_CARD());
            } else {
                p.circle_stroke(egui::pos2(dx, y), 6.5, Stroke::new(2.0, col));
            }
            dx += 24.0;
        }
        text(egui::pos2(dx + 4.0, y), &format!("{}/{} ready", st["readyInstances"].as_i64().unwrap_or(0), c["spec"]["instances"].as_i64().unwrap_or(0)), 12.5, TEXT_MUTED(), w - (dx - r.left()) - 20.0);
        text(egui::pos2(x, r.top() + u(104.0)), st["phase"].as_str().unwrap_or("-"), 12.5, tone, w - 36.0);
        // Backup in a word.
        let now = kube::now_secs();
        let (bt, bc) = match st["lastSuccessfulBackup"].as_str().and_then(kube::parse_time) {
            Some(t) if now - t > 26 * 3600 => (format!("Backup {} ago", kube::human_duration(now - t)), WARNING()),
            Some(t) => (format!("Backup {} ago", kube::human_duration((now - t).max(0))), TEXT_SUBTLE()),
            None => ("No backup".to_string(), DANGER()),
        };
        let dbs = self.pg_owned(id, CRD_DATABASES).len();
        let size = c["spec"]["storage"]["size"].as_str().unwrap_or("");
        let mut tail: Vec<String> = vec![];
        if !size.is_empty() {
            tail.push(format!("{size} disk"));
        }
        if dbs > 0 {
            tail.push(format!("{dbs} database{}", if dbs == 1 { "" } else { "s" }));
        }
        let by = r.top() + u(132.0);
        text(egui::pos2(x, by), &bt, 12.0, bc, w - 36.0);
        let bw = p.layout_no_wrap(bt.clone(), FontId::proportional(z(12.0)), bc).size().x;
        if !tail.is_empty() {
            text(egui::pos2(x + bw, by), &format!("  ·  {}", tail.join("  ·  ")), 12.0, TEXT_SUBTLE(), w - 36.0 - bw);
        }
        resp.on_hover_cursor(egui::CursorIcon::PointingHand)
    }

    // ---------- one cluster ----------

    fn pg_page(&mut self, ui: &mut Ui, id: &PgId) {
        let mut close = ui.input(|i| i.key_pressed(Key::Escape)) && self.dialog.is_none() && self.palette.is_none();
        ui.horizontal(|ui| {
            if back_button(ui).on_hover_text("All Postgres clusters (Esc)").clicked() {
                close = true;
            }
            let (d, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), Sense::hover());
            ui.painter().circle_filled(d.center(), 3.5, context_color(&id.ctx));
            ui.label(RichText::new(format!("{} · Postgres Clusters", ctx_label(&id.ctx))).size(z(12.0)).color(TEXT_SUBTLE()));
            self.ai_corner(ui, true);
        });
        if close {
            self.pg_sel = None;
            return;
        }
        let Some(c) = self.pg_cluster(id).cloned() else {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                ui.spinner();
                ui.label(RichText::new("Reading the cluster…").color(TEXT_SUBTLE()));
            });
            return;
        };
        let plugin = self.kubectl.cnpg.is_some();
        let tone = tone_color(cluster_tone(&c));
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(egui::vec2(u(30.0), u(30.0)), Sense::hover());
            database_icon(ui.painter(), r.center(), 11.0, tone);
            ui.label(RichText::new(format!("{} /", id.ns)).size(z(20.0)).color(TEXT_SUBTLE()));
            ui.label(RichText::new(&id.name).size(z(20.0)).color(TEXT_DEFAULT()));
            pill(ui, &format!("PostgreSQL {}", pg_version(&c)), INFO());
            pill(ui, c["status"]["phase"].as_str().unwrap_or("-"), tone);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if !plugin {
                    ui.label(RichText::new("Install kubectl cnpg for live state and actions").size(z(12.0)).color(WARNING()));
                    return;
                }
                if button(ui, "Restart…", false, false) {
                    self.pg_restart(id, None, false);
                }
                if button(ui, "Reload", false, false) {
                    self.pg_reload(id);
                }
                if backup_store(&c) && button(ui, "Back up now", false, false) {
                    self.pg_backup(id);
                }
                if button(ui, "psql", true, false) {
                    self.pg_psql(id, false);
                }
            });
        });
        ui.add_space(6.0);
        let mut area = egui::ScrollArea::vertical().id_salt("pg-page").auto_shrink([false, false]);
        if self.screenshot.is_some() {
            if let Some(y) = std::env::var("KUBEDOG_SHOT_SCROLL").ok().and_then(|v| v.parse::<f32>().ok()) {
                area = area.vertical_scroll_offset(y);
            }
        }
        let mut act: Vec<PgClick> = vec![];
        area.show(ui, |ui| {
            let st = self.pg_state.get(&id.key());
            let live = st.and_then(|s| s.live.clone());
            if let Some(e) = st.and_then(|s| s.error.clone()) {
                Frame::new().fill(WARN_BG()).corner_radius(CornerRadius::same(6)).inner_margin(Margin::same(8)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(format!("The live state couldn't be read: {}", truncate(&e, 300))).size(z(12.5)).color(WARNING()));
                });
                ui.add_space(6.0);
            }
            self.pg_map(ui, id, &c, live.as_ref(), None, &mut act);
            ui.add_space(12.0);
            let facts = self.pg_facts(id);
            let list = checks(&c, &facts);
            drop(facts);
            two(ui, |ui| check_panel(ui, &list), |ui| self.pg_wal_panel(ui, id));
            ui.add_space(12.0);
            self.pg_instances(ui, id, &c, live.as_ref(), &mut act);
            ui.add_space(12.0);
            two(ui, |ui| self.pg_backups(ui, id, &c), |ui| self.pg_connect(ui, id, &c, &mut act));
            ui.add_space(12.0);
            two(ui, |ui| self.pg_databases(ui, id, &c), |ui| pg_settings(ui, &c));
            ui.add_space(16.0);
        });
        for a in act {
            self.pg_click(id, a);
        }
    }

    fn pg_click(&mut self, id: &PgId, a: PgClick) {
        match a {
            PgClick::Pod(n) => self.open_instance(id, &n, false),
            PgClick::Logs(n) => self.open_instance(id, &n, true),
            PgClick::Promote(n) => self.pg_promote(id, &n),
            PgClick::Restart(n, primary) => self.pg_restart(id, Some(&n), primary),
            PgClick::Psql(replica) => self.pg_psql(id, replica),
            PgClick::Cluster => self.open_pg(id.clone()),
            PgClick::Copy(t) => {
                self.egui_ctx.copy_text(t);
                self.toast("Copied".into(), false);
            }
            PgClick::Service(n) => self.navigate(View::Resource(Kind::Services), Some(Selected { ctx: id.ctx.clone(), kind: Kind::Services, ns: id.ns.clone(), name: n })),
        }
    }

    /// Instances as the page knows them: live when the plugin answered, else from the resource.
    fn pg_members(&self, id: &PgId, c: &Value, live: Option<&Live>) -> Vec<Instance> {
        let mut v: Vec<Instance> = live.map(|l| l.instances.clone()).unwrap_or_default();
        let st = &c["status"];
        let primary = st["currentPrimary"].as_str().unwrap_or("");
        let pods = self.pg_pods(id);
        for n in st["instanceNames"].as_array().into_iter().flatten().filter_map(|x| x.as_str()) {
            if v.iter().any(|i| i.name == n) {
                continue;
            }
            let pod = pods.iter().find(|p| p["metadata"]["name"].as_str() == Some(n));
            v.push(Instance {
                name: n.into(),
                primary: n == primary,
                node: pod.and_then(|p| p["spec"]["nodeName"].as_str()).unwrap_or("").into(),
                ready: st["instancesStatus"]["healthy"].as_array().into_iter().flatten().any(|x| x.as_str() == Some(n)),
                timeline: st["timelineID"].as_i64().unwrap_or(0),
                ..Default::default()
            });
        }
        v.sort_by(|a, b| b.primary.cmp(&a.primary).then(a.name.cmp(&b.name)));
        v
    }

    /// The picture: who writes where, how the log streams to the replicas, where it's archived.
    fn pg_map(&self, ui: &mut Ui, id: &PgId, c: &Value, live: Option<&Live>, mark: Option<&str>, act: &mut Vec<PgClick>) {
        let members = self.pg_members(id, c, live);
        let Some(primary) = members.iter().find(|i| i.primary).cloned() else { return };
        let replicas: Vec<Instance> = members.iter().filter(|i| !i.primary).take(8).cloned().collect();
        let poolers: Vec<String> = self.pg_owned(id, CRD_POOLERS).iter().filter_map(|p| p["metadata"]["name"].as_str().map(String::from)).take(2).collect();
        let backup = c["spec"]["backup"]["barmanObjectStore"]["destinationPath"].as_str().map(String::from).or_else(|| c["spec"]["plugins"].as_array().and_then(|a| a.first()).and_then(|p| p["name"].as_str().map(String::from)));
        Frame::new().fill(BG_SUBTLE()).stroke(Stroke::new(1.0, BORDER_SUBTLE())).corner_radius(CornerRadius::same(12)).inner_margin(Margin::same(0)).show(ui, |ui| {
            let card_h = u(84.0);
            let gap = u(16.0);
            let rows = replicas.len().max(1) as f32;
            let side = u(58.0) + poolers.len() as f32 * u(50.0);
            let center_h = card_h + if backup.is_some() { gap * 2.4 + u(52.0) } else { 0.0 };
            let h = (rows * card_h + (rows - 1.0) * gap).max(center_h).max(side) + u(52.0);
            let (area, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), h), Sense::hover());
            let p = ui.painter().with_clip_rect(ui.clip_rect().intersect(area));
            // A faint grid of dots.
            let mut gy = area.top() + 14.0;
            while gy < area.bottom() {
                let mut gx = area.left() + 14.0;
                while gx < area.right() {
                    p.circle_filled(egui::pos2(gx, gy), 0.8, BORDER_SUBTLE());
                    gx += 22.0;
                }
                gy += 22.0;
            }
            let w = area.width();
            let (svc_w, box_w) = ((w * 0.19).clamp(u(130.0), u(230.0)), (w * 0.27).clamp(u(190.0), u(330.0)));
            let left = area.left() + u(22.0);
            let right = area.right() - u(22.0) - box_w;
            let mid_x = (left + svc_w + right) / 2.0 - box_w / 2.0;
            let mid_y = area.center().y - if backup.is_some() { (gap * 2.4 + u(52.0)) / 2.0 } else { 0.0 };
            let prim = egui::Rect::from_min_size(egui::pos2(mid_x, mid_y - card_h / 2.0), egui::vec2(box_w, card_h));
            let time = ui.input(|i| i.time) as f32;
            // Who writes: the service, and the poolers in front of it.
            let mut entries: Vec<(String, String, Option<String>)> = vec![];
            let rw = c["status"]["writeService"].as_str().unwrap_or("").to_string();
            if !rw.is_empty() {
                entries.push((rw.clone(), "writes".into(), Some(rw)));
            }
            for n in &poolers {
                entries.push((n.clone(), "pooler".into(), None));
            }
            let eh = u(42.0);
            let total = entries.len() as f32 * (eh + 8.0) - 8.0;
            for (i, (name, what, svc)) in entries.iter().enumerate() {
                let r = egui::Rect::from_min_size(egui::pos2(left, prim.center().y - total / 2.0 + i as f32 * (eh + 8.0)), egui::vec2(svc_w, eh));
                let resp = ui.interact(r, egui::Id::new(("pg-svc", &id.name, name, mark.is_some())), if svc.is_some() { Sense::click() } else { Sense::hover() });
                p.rect_filled(r, CornerRadius::same(8), BG_CARD());
                p.rect_stroke(r, CornerRadius::same(8), Stroke::new(1.0, if resp.hovered() && svc.is_some() { PRIMARY_TEXT() } else { INFO().gamma_multiply(0.6) }), egui::StrokeKind::Inside);
                label_at(ui, &p, r.left_top() + egui::vec2(10.0, eh * 0.32), name, 12.5, TEXT_DEFAULT(), svc_w - 20.0);
                label_at(ui, &p, r.left_top() + egui::vec2(10.0, eh * 0.72), what, 11.0, INFO(), svc_w - 20.0);
                stream(&p, r.right_center(), prim.left_center() + egui::vec2(0.0, (i as f32 - (entries.len() as f32 - 1.0) / 2.0) * 12.0), INFO(), time * 0.5 + i as f32 * 0.3, 2, true);
                if let (Some(n), true) = (svc, resp.on_hover_text("Open this service").clicked()) {
                    act.push(PgClick::Service(n.clone()));
                }
            }
            // The replicas, with the log streaming to them.
            let rh = replicas.len() as f32 * (card_h + gap) - gap;
            for (i, rep) in replicas.iter().enumerate() {
                let r = egui::Rect::from_min_size(egui::pos2(right, area.center().y - rh / 2.0 + i as f32 * (card_h + gap)), egui::vec2(box_w, card_h));
                let known = !rep.state.is_empty();
                let ok = rep.ready && (!known || rep.state == "streaming") && (live.is_none() || known);
                let behind = rep.lag.unwrap_or(0.0);
                let col = if !ok { DANGER() } else if behind >= 5.0 { WARNING() } else { SUCCESS() };
                let spread = (i as f32 - (replicas.len() as f32 - 1.0) / 2.0) * 14.0;
                let (a, b) = (prim.right_center() + egui::vec2(0.0, spread), r.left_center());
                stream(&p, a, b, col, time * 0.6 + i as f32 * 0.37, if ok { 4 } else { 0 }, ok);
                // How far behind, on the line.
                let text = match (rep.lag, ok) {
                    (_, false) => "not streaming".to_string(),
                    (Some(l), _) => lag_text(l),
                    (None, _) => String::new(),
                };
                if !text.is_empty() {
                    let m = curve(a, b, 0.5);
                    let g = p.layout_no_wrap(text, FontId::proportional(z(11.0)), col);
                    let br = egui::Rect::from_center_size(m, g.size() + egui::vec2(14.0, 6.0));
                    p.rect_filled(br, CornerRadius::same(9), BG_SUBTLE());
                    p.rect_stroke(br, CornerRadius::same(9), Stroke::new(1.0, col.gamma_multiply(0.6)), egui::StrokeKind::Inside);
                    p.galley(br.center() - g.size() / 2.0, g, col);
                }
                self.pg_box(ui, &p, r, id, rep, live, col, mark == Some(rep.name.as_str()), mark.is_some(), act);
            }
            if replicas.is_empty() {
                label_at(ui, &p, egui::pos2(right, prim.center().y), "No replicas", 13.0, WARNING(), box_w);
            }
            // The archive.
            if let Some(path) = &backup {
                let ok = live.and_then(|l| l.archiving).or_else(|| {
                    c["status"]["conditions"].as_array().into_iter().flatten().find(|x| x["type"].as_str() == Some("ContinuousArchiving")).map(|x| x["status"].as_str() == Some("True"))
                });
                let col = match ok { Some(true) => SUCCESS(), Some(false) => DANGER(), None => TEXT_SUBTLE() };
                let r = egui::Rect::from_min_size(egui::pos2(prim.left(), prim.bottom() + gap * 2.4), egui::vec2(box_w, u(52.0)));
                stream(&p, prim.center_bottom(), r.center_top(), col, time * 0.35, if ok == Some(true) { 2 } else { 0 }, ok != Some(false));
                p.rect_filled(r, CornerRadius::same(8), BG_CARD());
                p.rect_stroke(r, CornerRadius::same(8), Stroke::new(1.0, col.gamma_multiply(0.6)), egui::StrokeKind::Inside);
                label_at(ui, &p, r.left_top() + egui::vec2(12.0, r.height() * 0.32), path, 12.0, TEXT_DEFAULT(), box_w - 24.0);
                let when = live.and_then(|l| l.last_archived_at).map(|t| format!("last WAL file {} ago", kube::human_duration((kube::now_secs() - t).max(0))));
                let sub = match ok { Some(false) => "archiving fails".to_string(), _ => when.unwrap_or_else(|| "backups and WAL archive".into()) };
                label_at(ui, &p, r.left_top() + egui::vec2(12.0, r.height() * 0.70), &sub, 11.0, col, box_w - 24.0);
            }
            self.pg_box(ui, &p, prim, id, &primary, live, if primary.ready { SUCCESS() } else { DANGER() }, mark == Some(primary.name.as_str()), mark.is_some(), act);
        });
        // Keep it moving while it can be seen (not behind another window).
        if ui.input(|i| i.viewport().focused.unwrap_or(false)) {
            ui.ctx().request_repaint_after(Duration::from_millis(40));
        }
    }

    /// One instance in the picture.
    #[allow(clippy::too_many_arguments)]
    fn pg_box(&self, ui: &Ui, p: &egui::Painter, r: egui::Rect, id: &PgId, i: &Instance, live: Option<&Live>, col: Color32, marked: bool, small: bool, act: &mut Vec<PgClick>) {
        let resp = ui.interact(r, egui::Id::new(("pg-box", &id.name, &i.name, small)), Sense::click());
        if i.primary {
            p.rect_filled(r.expand(5.0), CornerRadius::same(15), col.gamma_multiply(0.07));
        }
        p.rect_filled(r, CornerRadius::same(10), if resp.hovered() { BG_HOVER() } else { BG_CARD() });
        let edge = if marked { PRIMARY_TEXT() } else { col.gamma_multiply(if i.primary { 1.0 } else { 0.7 }) };
        p.rect_stroke(r, CornerRadius::same(10), Stroke::new(if i.primary || marked { 2.0 } else { 1.0 }, edge), egui::StrokeKind::Inside);
        database_icon(p, r.left_center() + egui::vec2(u(26.0), 0.0), 11.0, col);
        let x = r.left() + u(52.0);
        let w = r.right() - x - 10.0;
        label_at(ui, p, egui::pos2(x, r.top() + r.height() * 0.22), &i.name, 13.0, if marked { PRIMARY_TEXT() } else { TEXT_DEFAULT() }, w);
        let role = if i.primary { "Primary".to_string() } else if i.sync.is_empty() { "Replica".to_string() } else { format!("Replica · {}", i.sync) };
        let role = if i.node.is_empty() { role } else { format!("{role} · {}", i.node) };
        label_at(ui, p, egui::pos2(x, r.top() + r.height() * 0.45), &role, 11.5, col, w);
        // Disk used, as a thin bar; CPU and memory beside it.
        let usage = self.metrics.get(&id.ctx).and_then(|m| m.pods.get(&(id.ns.clone(), i.name.clone())).copied());
        let mut parts = vec![];
        if let Some((cpu, mem)) = usage {
            let (a, b) = (resources::fmt_cpu(cpu), resources::fmt_mem(mem));
            parts.push(format!("{}{} cpu · {}{}", a.0, a.1, b.0, b.1));
        }
        let disk = self.claim_usage(&id.ctx, &id.ns, &i.name).map(|d| (d.used, d.used / d.capacity.max(1.0)));
        if let Some((used, share)) = disk {
            parts.push(format!("{} disk ({:.0}%)", bytes(used), share * 100.0));
        }
        label_at(ui, p, egui::pos2(x, r.top() + r.height() * 0.67), &parts.join(" · "), 11.0, TEXT_SUBTLE(), w);
        if let Some((_, share)) = disk {
            let b = egui::Rect::from_min_size(egui::pos2(x, r.bottom() - r.height() * 0.15), egui::vec2(w, 4.0));
            p.rect_filled(b, CornerRadius::same(2), BG_MUTED());
            p.rect_filled(egui::Rect::from_min_size(b.min, egui::vec2((b.width() * share.clamp(0.0, 1.0) as f32).max(2.0), 4.0)), CornerRadius::same(2), storage::usage_color(share));
        }
        let mut tip = format!("{}\n{}", i.name, if i.primary { "Primary: takes the writes" } else { "Replica: follows the primary" });
        if let Some(l) = i.lsn {
            tip += &format!("\nLog position {:X}/{:08X} (timeline {})", l >> 32, l & 0xffff_ffff, i.timeline);
        }
        if let (false, Some(pl), Some(l)) = (i.primary, live.and_then(|l| l.instances.iter().find(|x| x.primary)).and_then(|x| x.lsn), i.lsn) {
            tip += &format!("\n{} behind the primary", bytes(pl.saturating_sub(l) as f64));
        }
        tip += "\nClick to open its pod";
        if resp.on_hover_text(tip).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
            act.push(PgClick::Pod(i.name.clone()));
        }
    }

    /// How fast the log grows, and the worst lag, over time.
    fn pg_wal_panel(&self, ui: &mut Ui, id: &PgId) {
        panel(ui, "Write activity", "WAL written per second, and the slowest replica's lag");
        let hist: Vec<(i64, u64, f64)> = self.pg_state.get(&id.key()).map(|s| s.hist.iter().copied().collect()).unwrap_or_default();
        let rates: Vec<f64> = hist.windows(2).map(|w| (w[1].1.saturating_sub(w[0].1)) as f64 / ((w[1].0 - w[0].0).max(1) as f64)).collect();
        if rates.is_empty() {
            ui.add_space(20.0);
            ui.label(RichText::new(if self.kubectl.cnpg.is_some() { "Collecting readings… (one every 10 seconds while this page is open)" } else { "Needs the kubectl cnpg plugin." }).size(z(12.5)).color(TEXT_SUBTLE()));
            return;
        }
        let lags: Vec<f64> = hist.iter().skip(1).map(|h| h.2).collect();
        let last = rates.len() - 1;
        ui.horizontal(|ui| {
            big(ui, &format!("{}/s", bytes(rates[last])), "WAL now", PRIMARY_TEXT());
            ui.add_space(18.0);
            big(ui, &lag_text(lags[last]), "slowest replica", if lags[last] >= 5.0 { WARNING() } else { SUCCESS() });
            ui.add_space(18.0);
            let moved = hist.last().zip(hist.first()).map(|(b, a)| b.1.saturating_sub(a.1)).unwrap_or(0);
            let span = hist.last().zip(hist.first()).map(|(b, a)| b.0 - a.0).unwrap_or(0);
            big(ui, &bytes(moved as f64), &format!("in {}", kube::human_duration(span)), TEXT_MUTED());
        });
        ui.add_space(6.0);
        spark(ui, &rates, u(70.0), PRIMARY_TEXT(), |v| format!("{}/s", bytes(v)));
        ui.add_space(4.0);
        spark(ui, &lags, u(34.0), SUCCESS(), lag_text);
    }

    /// One row per instance, with what can be done to it.
    fn pg_instances(&self, ui: &mut Ui, id: &PgId, c: &Value, live: Option<&Live>, act: &mut Vec<PgClick>) {
        let plugin = self.kubectl.cnpg.is_some();
        let members = self.pg_members(id, c, live);
        card(ui, |ui| {
            panel(ui, "Instances", "");
            let cols = [0.0f32, 0.24, 0.36, 0.48, 0.60];
            let w = ui.available_width();
            let head = ui.cursor().top();
            for (i, t) in ["Name", "Role", "Node", "Log position", "Behind"].iter().enumerate() {
                let p = ui.painter();
                p.text(egui::pos2(ui.max_rect().left() + w * cols[i], head + u(9.0)), egui::Align2::LEFT_CENTER, *t, FontId::proportional(z(12.0)), TEXT_SUBTLE());
            }
            ui.add_space(u(20.0));
            for m in &members {
                let (r, _) = ui.allocate_exact_size(egui::vec2(w, u(34.0)), Sense::hover());
                let p = ui.painter().clone();
                p.hline(r.x_range(), r.top(), Stroke::new(1.0, BORDER_SUBTLE()));
                let y = r.center().y;
                let at = |i: usize| egui::pos2(r.left() + w * cols[i], y);
                let name_w = w * (cols[1] - cols[0]) - 10.0;
                let nr = egui::Rect::from_min_size(egui::pos2(r.left(), r.top()), egui::vec2(name_w, r.height()));
                let resp = ui.interact(nr, egui::Id::new(("pg-row", &id.name, &m.name)), Sense::click());
                label_at(ui, &p, at(0), &m.name, 13.5, PRIMARY_TEXT(), name_w);
                if resp.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Open its pod").clicked() {
                    act.push(PgClick::Pod(m.name.clone()));
                }
                let col = if !m.ready { DANGER() } else { SUCCESS() };
                label_at(ui, &p, at(1), if m.primary { "Primary" } else { "Replica" }, 13.0, col, w * 0.12);
                label_at(ui, &p, at(2), &m.node, 13.0, TEXT_MUTED(), w * 0.11);
                label_at(ui, &p, at(3), &m.lsn.map(|l| format!("{:X}/{:X}", l >> 32, l & 0xffff_ffff)).unwrap_or_else(|| "-".into()), 12.5, TEXT_MUTED(), w * 0.11);
                let behind = if m.primary { "-".to_string() } else { m.lag.map(lag_text).unwrap_or_else(|| "-".into()) };
                label_at(ui, &p, at(4), &behind, 13.0, if m.lag.unwrap_or(0.0) >= 5.0 { WARNING() } else { TEXT_MUTED() }, w * 0.09);
                let br = egui::Rect::from_min_max(egui::pos2(r.left() + w * 0.69, r.top() + 3.0), r.max);
                ui.scope_builder(egui::UiBuilder::new().max_rect(br).layout(Layout::right_to_left(Align::Center)), |ui| {
                    if plugin {
                        if button(ui, "Restart…", false, false) {
                            act.push(PgClick::Restart(m.name.clone(), m.primary));
                        }
                        if !m.primary && button(ui, "Make primary…", false, false) {
                            act.push(PgClick::Promote(m.name.clone()));
                        }
                    }
                    if button(ui, "Logs", false, false) {
                        act.push(PgClick::Logs(m.name.clone()));
                    }
                });
            }
        });
    }

    fn pg_backups(&self, ui: &mut Ui, id: &PgId, c: &Value) {
        let mut b = self.pg_owned(id, CRD_BACKUPS);
        b.sort_by_key(|x| x["metadata"]["creationTimestamp"].as_str().unwrap_or("").to_string());
        let sched = self.pg_owned(id, CRD_SCHEDULES);
        panel(ui, "Backups", "");
        let now = kube::now_secs();
        let first = c["status"]["firstRecoverabilityPoint"].as_str().and_then(kube::parse_time);
        match first {
            Some(t) => {
                let failing = c["status"]["conditions"].as_array().into_iter().flatten().any(|x| x["type"].as_str() == Some("ContinuousArchiving") && x["status"].as_str() == Some("False"));
                let (head, sub, col) = if failing {
                    (format!("Since {}", netmap::iso_date(t)), "restorable only up to the last archived WAL: archiving is failing", WARNING())
                } else {
                    (format!("The last {}", kube::human_duration((now - t).max(0))), "any moment in it can be restored, up to the last archived WAL", SUCCESS())
                };
                ui.horizontal(|ui| big(ui, &head, sub, col));
                let bar_col = col;
                // The recovery window as a bar from the first point to now.
                let (r, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(12.0)), Sense::hover());
                let p = ui.painter();
                p.rect_filled(r, CornerRadius::same(6), bar_col.gamma_multiply(0.22));
                p.rect_stroke(r, CornerRadius::same(6), Stroke::new(1.0, bar_col.gamma_multiply(0.6)), egui::StrokeKind::Inside);
                for x in &b {
                    if let Some(done) = x["status"]["stoppedAt"].as_str().and_then(kube::parse_time).filter(|d| *d >= t) {
                        let px = r.left() + r.width() * ((done - t) as f32 / (now - t).max(1) as f32);
                        p.circle_filled(egui::pos2(px.clamp(r.left() + 5.0, r.right() - 5.0), r.center().y), 4.0, SUCCESS());
                    }
                }
                resp.on_hover_text("Dots are backups; the log between them fills the gaps.");
                ui.horizontal(|ui| {
                    ui.label(RichText::new(netmap::iso_date(t)).size(z(11.0)).color(TEXT_SUBTLE()));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| ui.label(RichText::new("now").size(z(11.0)).color(TEXT_SUBTLE())));
                });
            }
            None => {
                ui.label(RichText::new(if backup_store(c) { "No point to recover to is known yet." } else { "No backup store is set up in CNPG for this cluster." }).color(DANGER()));
            }
        }
        // The latest backups: one bar each, as tall as it took.
        let recent: Vec<&&Value> = b.iter().rev().take(24).collect();
        if !recent.is_empty() {
            ui.add_space(8.0);
            let secs = |x: &Value| x["status"]["stoppedAt"].as_str().and_then(kube::parse_time).zip(x["status"]["startedAt"].as_str().and_then(kube::parse_time)).map(|(a, b)| (a - b).max(1)).unwrap_or(1);
            let max = recent.iter().map(|x| secs(x)).max().unwrap_or(1) as f32;
            let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(46.0)), Sense::hover());
            let step = (r.width() / recent.len() as f32).min(26.0);
            for (i, x) in recent.iter().rev().enumerate() {
                let phase = x["status"]["phase"].as_str().unwrap_or("pending");
                let col = match phase { "completed" => SUCCESS(), "failed" => DANGER(), _ => WARNING() };
                let h = (r.height() * secs(x) as f32 / max).max(8.0);
                let bar = egui::Rect::from_min_max(egui::pos2(r.left() + i as f32 * step + 2.0, r.bottom() - h), egui::pos2(r.left() + (i + 1) as f32 * step - 2.0, r.bottom()));
                ui.painter().rect_filled(bar, CornerRadius::same(3), col);
                let hit = egui::Rect::from_min_max(egui::pos2(bar.left(), r.top()), bar.max);
                ui.interact(hit, egui::Id::new(("pg-backup", &id.name, i)), Sense::hover()).on_hover_text(format!(
                    "{}\n{phase}, took {}{}",
                    x["status"]["stoppedAt"].as_str().or(x["metadata"]["creationTimestamp"].as_str()).unwrap_or(""),
                    kube::human_duration(secs(x)),
                    x["status"]["error"].as_str().map(|e| format!("\n{}", truncate(e, 200))).unwrap_or_default()
                ));
            }
            ui.label(RichText::new(format!("the last {} backups; the taller, the longer it took", recent.len())).size(z(11.0)).color(TEXT_PLACEHOLDER()));
        }
        ui.add_space(6.0);
        for s in sched {
            let next = s["status"]["nextScheduleTime"].as_str().and_then(kube::parse_time);
            let suspended = s["spec"]["suspend"].as_bool() == Some(true);
            let text = if suspended { "suspended".to_string() } else { next.map(|t| format!("next in {}", kube::human_duration((t - now).max(0)))).unwrap_or_default() };
            kv(ui, "Schedule", format!("{}  ·  {text}", s["spec"]["schedule"].as_str().unwrap_or("")));
        }
        if let Some(r) = c["spec"]["backup"]["retentionPolicy"].as_str() {
            kv(ui, "Kept for", r);
        }
    }

    fn pg_connect(&self, ui: &mut Ui, id: &PgId, c: &Value, act: &mut Vec<PgClick>) {
        panel(ui, "Connect", "click an address to copy it");
        let base = c["status"]["writeService"].as_str().map(|s| s.trim_end_matches("-rw").to_string()).unwrap_or_else(|| id.name.clone());
        for (svc, what, note) in [(format!("{base}-rw"), "Read and write", "the primary"), (format!("{base}-ro"), "Read only", "the replicas"), (format!("{base}-r"), "Read", "any instance")] {
            address(ui, what, note, &format!("{svc}.{}.svc:5432", id.ns), act);
        }
        for pl in self.pg_owned(id, CRD_POOLERS) {
            let n = pl["metadata"]["name"].as_str().unwrap_or("");
            address(ui, "Pooler", pl["spec"]["pgbouncer"]["poolMode"].as_str().unwrap_or("pgbouncer"), &format!("{n}.{}.svc:5432", id.ns), act);
        }
        ui.add_space(6.0);
        if self.kubectl.cnpg.is_some() {
            ui.horizontal(|ui| {
                if button(ui, "psql on the primary", false, false) {
                    act.push(PgClick::Psql(false));
                }
                if c["spec"]["instances"].as_i64().unwrap_or(1) > 1 && button(ui, "psql on a replica", false, false) {
                    act.push(PgClick::Psql(true));
                }
            });
            let locked = !self.unlocked.contains(&id.ctx);
            ui.label(RichText::new(if locked { "While the cluster is protected, psql starts read-only." } else { "Unlocked: psql can change data." }).size(z(11.5)).color(if locked { TEXT_SUBTLE() } else { WARNING() }));
        }
    }

    fn pg_databases(&self, ui: &mut Ui, id: &PgId, c: &Value) {
        panel(ui, "Databases and roles", "");
        let mut dbs = self.pg_owned(id, CRD_DATABASES);
        dbs.sort_by_key(|d| d["spec"]["name"].as_str().unwrap_or("").to_string());
        if dbs.is_empty() {
            ui.label(RichText::new("No Database resources; databases made by hand aren't listed here.").size(z(12.5)).color(TEXT_SUBTLE()));
        }
        for d in dbs {
            let applied = d["status"]["applied"].as_bool();
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(egui::vec2(u(18.0), u(20.0)), Sense::hover());
                database_icon(ui.painter(), r.center(), 6.0, match applied { Some(true) => SUCCESS(), Some(false) => DANGER(), None => TEXT_SUBTLE() });
                ui.label(RichText::new(d["spec"]["name"].as_str().unwrap_or("")).color(TEXT_DEFAULT()));
                if let Some(o) = d["spec"]["owner"].as_str() {
                    ui.label(RichText::new(format!("owned by {o}")).size(z(12.0)).color(TEXT_SUBTLE()));
                }
                if applied == Some(false) {
                    ui.label(RichText::new(truncate(d["status"]["message"].as_str().unwrap_or("not applied"), 120)).size(z(12.0)).color(DANGER()));
                }
            });
        }
        let roles = c["spec"]["managed"]["roles"].as_array().cloned().unwrap_or_default();
        if !roles.is_empty() {
            ui.add_space(6.0);
            let ok: Vec<&str> = c["status"]["managedRolesStatus"]["byStatus"]["reconciled"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).collect();
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Managed roles").size(z(12.0)).color(TEXT_SUBTLE()));
                for r in &roles {
                    let n = r["name"].as_str().unwrap_or("");
                    pill(ui, n, if ok.contains(&n) { SUCCESS() } else { WARNING() });
                }
            });
        }
        let exp = c["status"]["certificates"]["expirations"].as_object().cloned().unwrap_or_default();
        if !exp.is_empty() {
            ui.add_space(8.0);
            panel(ui, "Certificates", "renewed by the operator");
            let now = kube::now_secs();
            for (k, v) in exp {
                if let Some(t) = v.as_str().and_then(go_time) {
                    let d = (t - now) / 86400;
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&k).size(z(12.5)).color(TEXT_MUTED()));
                        ui.label(RichText::new(if t < now { "expired".to_string() } else { format!("{d} days left") }).size(z(12.5)).color(if t < now { DANGER() } else if d < 7 { WARNING() } else { SUCCESS() }));
                    });
                }
            }
        }
    }

    // ---------- on a pod's page ----------

    /// The Postgres panel of an instance's pod.
    pub(super) fn pg_pod_panel(&mut self, ui: &mut Ui, sel: &Selected, pod: &Value) {
        if self.power_off("postgres") {
            return;
        }
        let Some(id) = Self::pg_of_pod(&sel.ctx, pod) else { return };
        let Some(c) = self.pg_cluster(&id).cloned() else { return };
        let live = self.pg_state.get(&id.key()).and_then(|s| s.live.clone());
        let me = self.pg_members(&id, &c, live.as_ref()).into_iter().find(|i| i.name == sel.name);
        let primary = me.as_ref().map(|m| m.primary).unwrap_or(pod["metadata"]["labels"]["cnpg.io/instanceRole"].as_str() == Some("primary"));
        let plugin = self.kubectl.cnpg.is_some();
        let mut act: Vec<PgClick> = vec![];
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(egui::vec2(u(22.0), u(26.0)), Sense::hover());
            database_icon(ui.painter(), r.center(), 8.0, tone_color(cluster_tone(&c)));
            ui.label(RichText::new("Postgres").strong().color(TEXT_SUBTLE()));
            pill(ui, if primary { "Primary" } else { "Replica" }, if primary { SUCCESS() } else { INFO() });
            let resp = ui.add(egui::Label::new(RichText::new(&id.name).color(PRIMARY_TEXT())).sense(Sense::click())).on_hover_cursor(egui::CursorIcon::PointingHand);
            if resp.on_hover_text("Open this Postgres cluster").clicked() {
                act.push(PgClick::Cluster);
            }
            ui.label(RichText::new(format!("PostgreSQL {}", pg_version(&c))).size(z(12.0)).color(TEXT_SUBTLE()));
            if let Some(m) = &me {
                if let (false, Some(l)) = (m.primary, m.lag) {
                    pill(ui, &format!("{} behind", lag_text(l)), if l >= 5.0 { WARNING() } else { SUCCESS() });
                }
                if m.pending_restart {
                    pill(ui, "restart pending", WARNING());
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if plugin {
                    if button(ui, "Restart…", false, false) {
                        act.push(PgClick::Restart(sel.name.clone(), primary));
                    }
                    if !primary && button(ui, "Make primary…", false, false) {
                        act.push(PgClick::Promote(sel.name.clone()));
                    }
                    if button(ui, "psql", false, false) {
                        act.push(PgClick::Psql(!primary));
                    }
                }
                if button(ui, "Open cluster", true, false) {
                    act.push(PgClick::Cluster);
                }
            });
        });
        ui.add_space(4.0);
        self.pg_map(ui, &id, &c, live.as_ref(), Some(&sel.name), &mut act);
        ui.add_space(12.0);
        for a in act {
            // Clicking this very pod changes nothing.
            if matches!(&a, PgClick::Pod(n) if n == &sel.name) {
                continue;
            }
            self.pg_click(&id, a);
        }
    }
}

/// Something clicked on a Postgres page.
enum PgClick {
    Pod(String),
    Logs(String),
    Promote(String),
    Restart(String, bool),
    Psql(bool),
    Cluster,
    Copy(String),
    Service(String),
}

fn cnpg_args(id: &PgId, rest: &[&str]) -> Vec<String> {
    let mut a: Vec<String> = vec!["cnpg".into()];
    let mut rest = rest.iter();
    if let Some(cmd) = rest.next() {
        a.push(cmd.to_string());
    }
    a.extend(["--context".to_string(), id.ctx.clone(), "--namespace".into(), id.ns.clone()]);
    a.extend(rest.map(|s| s.to_string()));
    a
}

// ---------- drawing ----------

/// Two panels side by side (one above the other in a narrow window).
pub(super) fn two(ui: &mut Ui, a: impl FnOnce(&mut Ui), b: impl FnOnce(&mut Ui)) {
    let gap = 12.0;
    let w = ui.available_width();
    if w < u(760.0) {
        card(ui, a);
        ui.add_space(gap);
        card(ui, b);
        return;
    }
    let half = (w - gap) / 2.0;
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = gap;
        ui.allocate_ui_with_layout(egui::vec2(half, 0.0), Layout::top_down(Align::Min), |ui| {
            ui.set_width(half);
            ui.spacing_mut().item_spacing.x = 8.0;
            card(ui, |ui| {
                ui.set_width(half - 26.0);
                a(ui)
            })
        });
        ui.allocate_ui_with_layout(egui::vec2(half, 0.0), Layout::top_down(Align::Min), |ui| {
            ui.set_width(half);
            ui.spacing_mut().item_spacing.x = 8.0;
            card(ui, |ui| {
                ui.set_width(half - 26.0);
                b(ui)
            })
        });
    });
}

pub(super) fn panel(ui: &mut Ui, title: &str, hint: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(title).size(z(14.5)).strong().color(TEXT_DEFAULT()));
        if !hint.is_empty() {
            ui.label(RichText::new(hint).size(z(11.5)).color(TEXT_PLACEHOLDER()));
        }
    });
    ui.add_space(4.0);
}

pub(super) fn pill(ui: &mut Ui, text: &str, col: Color32) {
    Frame::new().fill(col.gamma_multiply(0.13)).stroke(Stroke::new(1.0, col.gamma_multiply(0.45))).corner_radius(CornerRadius::same(10)).inner_margin(Margin::symmetric(9, 2)).show(ui, |ui| {
        ui.label(RichText::new(text).size(z(12.0)).color(col));
    });
}

pub(super) fn big(ui: &mut Ui, value: &str, label: &str, col: Color32) {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 1.0;
        ui.label(RichText::new(value).size(z(19.0)).color(col));
        ui.label(RichText::new(label).size(z(11.0)).color(TEXT_SUBTLE()));
    });
}

pub(super) fn label_at(ui: &Ui, p: &egui::Painter, pos: egui::Pos2, text: &str, size: f32, col: Color32, max: f32) {
    let g = p.layout_no_wrap(fit(ui, text, max, z(size)), FontId::proportional(z(size)), col);
    p.galley(pos - egui::vec2(0.0, g.size().y / 2.0), g, col);
}

fn address(ui: &mut Ui, what: &str, note: &str, addr: &str, act: &mut Vec<PgClick>) {
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(egui::vec2(z(112.0), u(22.0)), Layout::left_to_right(Align::Center), |ui| {
            ui.set_min_width(z(112.0));
            ui.label(RichText::new(what).size(z(12.5)).color(TEXT_MUTED())).on_hover_text(note);
        });
        let r = ui.add(egui::Label::new(RichText::new(addr).monospace().size(z(12.0)).color(PRIMARY_TEXT())).truncate().sense(Sense::click()));
        if r.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text(format!("{note}: click to copy")).clicked() {
            act.push(PgClick::Copy(addr.to_string()));
        }
    });
}

pub(super) fn check_panel(ui: &mut Ui, list: &[Check]) {
    let bad = list.iter().filter(|c| c.tone == Tone::Danger).count();
    let warn = list.iter().filter(|c| c.tone == Tone::Warning).count();
    let hint = if bad + warn == 0 { "everything looks good".to_string() } else { format!("{} to look at", bad + warn) };
    panel(ui, "Health checks", &hint);
    for c in list {
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(egui::vec2(u(18.0), u(20.0)), Sense::hover());
            let col = tone_color(c.tone);
            let o = r.center();
            let p = ui.painter();
            p.circle_filled(o, 7.0, col.gamma_multiply(0.18));
            let s = Stroke::new(1.7, col);
            if c.tone == Tone::Success {
                p.line_segment([o + egui::vec2(-3.2, 0.2), o + egui::vec2(-0.8, 2.6)], s);
                p.line_segment([o + egui::vec2(-0.8, 2.6), o + egui::vec2(3.4, -2.6)], s);
            } else {
                p.line_segment([o + egui::vec2(0.0, -3.6), o + egui::vec2(0.0, 0.8)], s);
                p.circle_filled(o + egui::vec2(0.0, 3.4), 1.0, col);
            }
            ui.label(RichText::new(&c.title).size(z(13.0)).color(if c.tone == Tone::Success { TEXT_DEFAULT() } else { col }));
            ui.add(egui::Label::new(RichText::new(&c.detail).size(z(12.0)).color(TEXT_SUBTLE())).truncate()).on_hover_text(&c.detail);
        });
    }
}

fn pg_settings(ui: &mut Ui, c: &Value) {
    let sp = &c["spec"];
    panel(ui, "Settings", "");
    if let Some(d) = sp["description"].as_str() {
        kv(ui, "Description", d);
    }
    kv(ui, "Image", sp["imageName"].as_str().or(c["status"]["image"].as_str()).unwrap_or(""));
    kv(ui, "Disk", format!("{} {}", sp["storage"]["size"].as_str().unwrap_or(""), sp["storage"]["storageClass"].as_str().unwrap_or("")));
    if let Some(w) = sp["walStorage"]["size"].as_str() {
        kv(ui, "WAL disk", w);
    }
    let r = &sp["resources"];
    let q = |k: &str| format!("request {} · limit {}", r["requests"][k].as_str().unwrap_or("-"), r["limits"][k].as_str().unwrap_or("-"));
    kv(ui, "CPU", q("cpu"));
    kv(ui, "Memory", q("memory"));
    kv(ui, "Updates", format!("{} ({})", sp["primaryUpdateStrategy"].as_str().unwrap_or("-"), sp["primaryUpdateMethod"].as_str().unwrap_or("-")));
    if let Some(m) = sp["postgresql"]["parameters"].as_object() {
        // The ones people ask about; the rest is in the YAML.
        for k in ["max_connections", "shared_buffers", "work_mem", "maintenance_work_mem", "effective_cache_size", "wal_level", "max_slot_wal_keep_size"] {
            if let Some(v) = m.get(k).and_then(|v| v.as_str()) {
                kv(ui, k, v);
            }
        }
    }
}

/// A database: three stacked discs.
pub(super) fn database_icon(p: &egui::Painter, c: egui::Pos2, half: f32, col: Color32) {
    let (w, h) = (half * 0.86, half);
    let ry = half * 0.30;
    let s = Stroke::new((half * 0.15).max(1.2), col);
    let arc = |y: f32, from: f32, to: f32| -> Vec<egui::Pos2> {
        (0..=20)
            .map(|i| {
                let a = from + (to - from) * i as f32 / 20.0;
                egui::pos2(c.x + a.cos() * w, y + a.sin() * ry)
            })
            .collect()
    };
    let (top, bottom) = (c.y - h + ry, c.y + h - ry);
    p.add(egui::Shape::convex_polygon(arc(top, 0.0, std::f32::consts::TAU), col.gamma_multiply(0.25), s));
    for t in [0.36f32, 0.68, 1.0] {
        p.add(egui::Shape::line(arc(top + (bottom - top) * t, 0.0, std::f32::consts::PI), s));
    }
    p.line_segment([egui::pos2(c.x - w, top), egui::pos2(c.x - w, bottom)], s);
    p.line_segment([egui::pos2(c.x + w, top), egui::pos2(c.x + w, bottom)], s);
}

/// A point on the curve between two boxes (level at both ends, or straight down).
pub(super) fn curve(a: egui::Pos2, b: egui::Pos2, t: f32) -> egui::Pos2 {
    let (c1, c2) = if (b.x - a.x).abs() >= (b.y - a.y).abs() * 0.3 && (b.x - a.x).abs() > 4.0 {
        let m = (a.x + b.x) / 2.0;
        (egui::pos2(m, a.y), egui::pos2(m, b.y))
    } else {
        let m = (a.y + b.y) / 2.0;
        (egui::pos2(a.x, m), egui::pos2(b.x, m))
    };
    let k = 1.0 - t;
    let f = |p0: f32, p1: f32, p2: f32, p3: f32| k * k * k * p0 + 3.0 * k * k * t * p1 + 3.0 * k * t * t * p2 + t * t * t * p3;
    egui::pos2(f(a.x, c1.x, c2.x, b.x), f(a.y, c1.y, c2.y, b.y))
}

/// A line with dots travelling along it (dashed when it's broken), ending in an arrowhead.
pub(super) fn stream(p: &egui::Painter, a: egui::Pos2, b: egui::Pos2, col: Color32, phase: f32, dots: usize, solid: bool) {
    let pts: Vec<egui::Pos2> = (0..=40).map(|i| curve(a, b, i as f32 / 40.0)).collect();
    let s = Stroke::new(1.6, col.gamma_multiply(0.45));
    if solid {
        p.add(egui::Shape::line(pts.clone(), s));
    } else {
        p.extend(egui::Shape::dashed_line(&pts, Stroke::new(1.6, col), 6.0, 5.0));
    }
    let end = pts[40];
    let dir = (end - pts[37]).normalized();
    let n = egui::vec2(-dir.y, dir.x);
    p.add(egui::Shape::convex_polygon(vec![end, end - dir * 8.0 + n * 4.0, end - dir * 8.0 - n * 4.0], col, Stroke::NONE));
    for i in 0..dots {
        let t = (phase + i as f32 / dots as f32).rem_euclid(1.0);
        let q = curve(a, b, t);
        let fade = (t * 6.0).min((1.0 - t) * 6.0).clamp(0.0, 1.0);
        p.circle_filled(q, 5.5, col.gamma_multiply(0.18 * fade));
        p.circle_filled(q, 2.6, col.gamma_multiply(fade));
    }
}

/// A small filled line chart; hovering shows a value.
pub(super) fn spark(ui: &mut Ui, vals: &[f64], h: f32, col: Color32, fmt: impl Fn(f64) -> String) {
    let (r, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), h), Sense::hover());
    let p = ui.painter();
    let max = vals.iter().cloned().fold(0.0, f64::max).max(1e-9) * 1.15;
    p.hline(r.x_range(), r.bottom(), Stroke::new(1.0, BORDER_SUBTLE()));
    let n = vals.len();
    let at = |i: usize| egui::pos2(if n < 2 { r.right() } else { r.left() + r.width() * i as f32 / (n - 1) as f32 }, r.bottom() - r.height() * (vals[i] / max) as f32);
    let mut mesh = egui::Mesh::default();
    for i in 0..n.saturating_sub(1) {
        let base = mesh.vertices.len() as u32;
        let (a, b) = (at(i), at(i + 1));
        mesh.colored_vertex(a, col.gamma_multiply(0.22));
        mesh.colored_vertex(b, col.gamma_multiply(0.22));
        mesh.colored_vertex(egui::pos2(b.x, r.bottom()), Color32::TRANSPARENT);
        mesh.colored_vertex(egui::pos2(a.x, r.bottom()), Color32::TRANSPARENT);
        mesh.add_triangle(base, base + 1, base + 2);
        mesh.add_triangle(base, base + 2, base + 3);
    }
    p.add(egui::Shape::mesh(mesh));
    if n >= 2 {
        p.add(egui::Shape::line((0..n).map(at).collect(), Stroke::new(1.8, col)));
    }
    if n > 0 {
        p.circle_filled(at(n - 1), 3.0, col);
    }
    p.text(r.right_top(), egui::Align2::RIGHT_TOP, format!("peak {}", fmt(vals.iter().cloned().fold(0.0, f64::max))), FontId::proportional(z(10.5)), TEXT_PLACEHOLDER());
    if let (Some(pos), true) = (resp.hover_pos(), n > 0) {
        let i = (((pos.x - r.left()) / r.width()) * (n.max(2) - 1) as f32).round().clamp(0.0, (n - 1) as f32) as usize;
        p.vline(at(i).x, r.y_range(), Stroke::new(1.0, TEXT_PLACEHOLDER()));
        resp.on_hover_text(fmt(vals[i]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_and_intervals() {
        assert_eq!(lsn("31/5B1D6B70"), Some((0x31u64 << 32) + 0x5B1D6B70));
        assert_eq!(lsn("0/0"), Some(0));
        assert_eq!(lsn("nope"), None);
        assert_eq!(lsn("1/FFFFFFFFF"), None);
        assert!((interval("00:00:00.018255").unwrap() - 0.018255).abs() < 1e-9);
        assert_eq!(interval("1 day 02:00:30"), Some(86400.0 + 7230.0));
        assert_eq!(interval("-00:00:01"), Some(-1.0));
        assert_eq!(interval(""), None);
        assert_eq!((lag_text(0.0182).as_str(), lag_text(7.25).as_str()), ("18 ms", "7.2 s"));
        assert_eq!(go_time("2027-01-08 15:30:05 +0000 UTC"), kube::parse_time("2027-01-08T15:30:05Z"));
        assert_eq!(pg_version(&serde_json::json!({"status": {"image": "ghcr.io/x/postgresql:18.6-system-trixie@sha256:ab"}})), "18.6");
    }

    fn status() -> Value {
        serde_json::json!({"instanceStatus": {"items": [
            {"pod": {"metadata": {"name": "db-2"}}, "isPrimary": false, "replayLsn": "0/90", "receivedLsn": "0/A0", "isPodReady": true, "node": "n2", "timeLineID": 1},
            {"pod": {"metadata": {"name": "db-1"}}, "isPrimary": true, "currentLsn": "0/100", "isPodReady": true, "node": "n1", "isArchivingWAL": true, "lastArchivedWAL": "X", "lastArchivedWALTime": "2026-11-23T08:06:13.10994Z",
             "replicationInfo": [{"applicationName": "db-2", "state": "streaming", "syncState": "async", "replayLag": "00:00:02"}],
             "replicationSlotsInfo": [{"slotName": "_cnpg_db_2", "active": false}]}
        ]}})
    }

    #[test]
    fn reads_status() {
        let l = parse_status(&status());
        assert_eq!(l.instances.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["db-1", "db-2"]);
        assert_eq!((l.instances[0].lsn, l.instances[1].lsn), (Some(0x100), Some(0x90)));
        assert_eq!((l.instances[1].lag, l.instances[1].state.as_str(), l.instances[1].slot_active), (Some(2.0), "streaming", Some(false)));
        assert_eq!((l.archiving, l.last_archived_at), (Some(true), kube::parse_time("2026-11-23T08:06:13Z")));
        assert!(parse_status(&Value::Null).instances.is_empty());
    }

    #[test]
    fn health() {
        let now = kube::parse_time("2026-11-23T08:00:00Z").unwrap();
        let good = serde_json::json!({
            "spec": {"instances": 2, "backup": {"barmanObjectStore": {}}},
            "status": {"readyInstances": 2, "phase": "Cluster in healthy state", "currentPrimary": "db-1", "targetPrimary": "db-1", "lastSuccessfulBackup": "2026-11-23T01:00:00Z",
                "conditions": [{"type": "ContinuousArchiving", "status": "True"}], "certificates": {"expirations": {"ca": "2027-01-08 15:30:05 +0000 UTC"}}}
        });
        let sched = serde_json::json!({});
        let mut live = parse_status(&status());
        live.instances[1].slot_active = Some(true);
        let nodes = vec![("db-1".to_string(), "n1".to_string()), ("db-2".to_string(), "n2".to_string())];
        let facts = |live: Option<&'static Live>, disk: f64| Facts { live, backups: vec![], schedules: vec![], nodes: nodes.clone(), disks: vec![("db-1".into(), disk)], now };
        let live: &'static Live = Box::leak(Box::new(live));
        let mut f = facts(Some(live), 0.2);
        f.schedules = vec![&sched];
        let r = checks(&good, &f);
        assert!(r.iter().all(|c| c.tone == Tone::Success), "{r:?}");
        assert_eq!(cluster_tone(&good), Tone::Success);
        let has = |r: &[Check], t: &str, tone: Tone| r.iter().any(|c| c.title == t && c.tone == tone);
        // No schedule, a full disk.
        let r = checks(&good, &facts(Some(live), 0.95));
        assert!(has(&r, "No backup schedule", Tone::Warning) && has(&r, "Disk almost full", Tone::Danger));
        assert_eq!(r[0].tone, Tone::Danger);
        // Trouble.
        let mut bad = good.clone();
        bad["status"]["readyInstances"] = 1.into();
        bad["status"]["lastSuccessfulBackup"] = "2026-11-20T01:00:00Z".into();
        bad["status"]["targetPrimary"] = "db-2".into();
        bad["status"]["conditions"][0]["status"] = "False".into();
        bad["status"]["certificates"]["expirations"]["ca"] = "2026-11-20 00:00:00 +0000 UTC".into();
        let mut broken = live.clone();
        broken.instances[1].state = "".into();
        broken.instances[1].pending_restart = true;
        let mut f = facts(Some(Box::leak(Box::new(broken))), 0.1);
        f.nodes[1].1 = "n1".into();
        let r = checks(&bad, &f);
        for (t, tone) in [("Instances missing", Tone::Warning), ("Backup is old", Tone::Danger), ("Primary is moving", Tone::Warning), ("WAL archiving fails", Tone::Danger), ("Certificate expired", Tone::Danger), ("Replication broken", Tone::Danger), ("Restart pending", Tone::Warning), ("Instances share a node", Tone::Warning)] {
            assert!(has(&r, t, tone), "{t}: {r:?}");
        }
        let none = serde_json::json!({"spec": {"instances": 1}, "status": {"readyInstances": 1, "conditions": [{"type": "ContinuousArchiving", "status": "True"}]}});
        let r = checks(&none, &Facts { live: None, backups: vec![], schedules: vec![], nodes: vec![], disks: vec![], now });
        assert!(!r.iter().any(|c| c.title.contains("archiving")), "{r:?}");
        assert!(has(&r, "No backups", Tone::Danger) && has(&r, "No standby", Tone::Warning));
    }

    #[test]
    fn commands() {
        let id = PgId { ctx: "c".into(), ns: "n".into(), name: "db".into() };
        assert_eq!(cnpg_args(&id, &["promote", "db", "db-2"]).join(" "), "cnpg promote --context c --namespace n db db-2");
    }
}
