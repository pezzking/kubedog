//! Several rows of a list at once: ticking them, the bar that appears, and what it does with them (pods are
//! deleted, workloads restarted). Always behind the lock and one confirmation that says what will happen.

use super::face::many;
use super::ops::{ns_of, text};
use super::work::name_of;
use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// Names in one kubectl call.
const AT_ONCE: usize = 50;

/// (cluster, namespace, name)
pub(super) type Key3 = (String, String, String);

/// What's ticked: the objects themselves, so sorting and refreshing don't change it. An object that was made
/// again under its old name is another one.
#[derive(Default)]
pub(super) struct Picks {
    /// What it was ticked in (kind, clusters, namespaces): elsewhere it's gone.
    place: String,
    /// What the list they're from is of.
    pub what: Option<What>,
    pub set: BTreeMap<Key3, String>,
    /// The last one that was ticked: shift goes from there.
    anchor: Option<Key3>,
    /// What's in the list now, in its order, with how many of the ticked ones aren't.
    pub shown: Vec<Key3>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub(super) enum Verb {
    Delete,
    Restart,
}

/// What a list is of.
#[derive(Clone, PartialEq, Debug)]
pub(super) enum What {
    Kind(Kind),
    /// A custom kind, by its full name ("plural.group").
    Custom(String),
}

impl What {
    fn resource(&self) -> String {
        match self {
            What::Kind(k) => k.resource().into(),
            What::Custom(k) => k.clone(),
        }
    }
    fn kind(&self) -> Option<Kind> {
        match self {
            What::Kind(k) => Some(*k),
            What::Custom(_) => None,
        }
    }
}

/// What can be done with several of a kind. Not for what the cluster itself lives on, or what takes everything
/// in it along: those are deleted one at a time, on their own page.
pub(super) fn verbs(kind: Kind) -> &'static [Verb] {
    match kind {
        Kind::Nodes | Kind::Namespaces | Kind::CustomResourceDefinitions | Kind::Events | Kind::VolumeAttachments | Kind::CSINodes => &[],
        k if k.can_restart() => &[Verb::Restart, Verb::Delete],
        _ => &[Verb::Delete],
    }
}

/// "policy" in the plural.
fn plural(n: usize, one: &str) -> String {
    if n == 1 {
        return format!("1 {one}");
    }
    let many = match one.strip_suffix('y') {
        Some(x) if !x.ends_with(['a', 'e', 'o']) => format!("{x}ies"),
        _ if one.ends_with(['s', 'x']) || one.ends_with("ch") => format!("{one}es"),
        _ => format!("{one}s"),
    };
    format!("{n} {many}")
}

impl Picks {
    pub fn clear(&mut self) {
        self.set.clear();
        self.anchor = None;
    }
    pub fn on(&self, k: &Key3) -> bool {
        self.set.contains_key(k)
    }
    /// Ticked ones that the filter hides.
    pub fn hidden(&self) -> usize {
        let shown: BTreeSet<&Key3> = self.shown.iter().collect();
        self.set.keys().filter(|k| !shown.contains(k)).count()
    }
    /// One more or less; with shift everything from the last one to here.
    pub fn click(&mut self, k: &Key3, shift: bool, uid: &dyn Fn(&Key3) -> Option<String>) {
        let from = self.anchor.as_ref().filter(|_| shift).and_then(|a| self.shown.iter().position(|x| x == a));
        let to = self.shown.iter().position(|x| x == k);
        match (from, to) {
            (Some(a), Some(b)) => {
                for x in self.shown[a.min(b)..=a.max(b)].to_vec() {
                    if let Some(u) = uid(&x) {
                        self.set.insert(x, u);
                    }
                }
            }
            _ => {
                if self.set.remove(k).is_none() {
                    if let Some(u) = uid(k) {
                        self.set.insert(k.clone(), u);
                    }
                }
            }
        }
        self.anchor = Some(k.clone());
    }
    /// Everything that's shown; or nothing, when that was ticked already.
    pub fn all(&mut self, uid: &dyn Fn(&Key3) -> Option<String>) {
        if !self.shown.is_empty() && self.shown.iter().all(|k| self.on(k)) {
            for k in &self.shown {
                self.set.remove(k);
            }
            return;
        }
        for k in self.shown.clone() {
            if let Some(u) = uid(&k) {
                self.set.insert(k, u);
            }
        }
    }
    /// Only what's still the same object stays ticked.
    pub fn prune(&mut self, uid: &dyn Fn(&Key3) -> Option<String>) {
        self.set.retain(|k, u| uid(k).as_ref() == Some(u));
    }
}

// ---------- what will happen ----------

fn over(p: &Value) -> bool {
    matches!(p["status"]["phase"].as_str(), Some("Failed" | "Succeeded"))
}

/// Who makes a pod again: (kind, name of the workload). None: nobody.
fn maker(p: &Value) -> Option<(String, String)> {
    let o = p["metadata"]["ownerReferences"].as_array()?.iter().find(|o| o["controller"] == true)?;
    let (k, n) = (text(&o["kind"]), text(&o["name"]));
    Some(match k.as_str() {
        "ReplicaSet" if p["metadata"]["labels"]["pod-template-hash"].is_string() => ("Deployment".into(), n.rsplit_once('-').map(|x| x.0.to_string()).unwrap_or(n)),
        _ => (k, n),
    })
}

fn some(l: &[String], n: usize) -> String {
    let rest = l.len().saturating_sub(n);
    format!("{}{}", l.iter().take(n).cloned().collect::<Vec<_>>().join(", "), if rest > 0 { format!(" and {rest} more") } else { String::new() })
}

/// What deleting these pods does. `all`: every pod of the cluster, to see what stays up. Also whether it only
/// cleans up what is over.
pub(super) fn delete_words(pods: &[&Value], all: &[&Value]) -> (String, bool) {
    let gone = pods.iter().filter(|p| over(p)).count();
    let mut out: Vec<String> = vec![];
    if gone > 0 {
        out.push(format!("{} over already (evicted, failed or finished): only cleaned up.", if gone == 1 { "1 is".into() } else { format!("{gone} are") }));
    }
    let live: Vec<&&Value> = pods.iter().filter(|p| !over(p)).collect();
    let mine: HashSet<(&str, &str)> = pods.iter().map(|p| (ns_of(p), name_of(p))).collect();
    let mut by: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    let mut alone: Vec<String> = vec![];
    let mut fixed: Vec<String> = vec![];
    for p in &live {
        if p["metadata"]["annotations"]["kubernetes.io/config.mirror"].is_string() {
            fixed.push(name_of(p).into());
            continue;
        }
        match maker(p) {
            Some((k, n)) => *by.entry((ns_of(p).into(), k, n)).or_default() += 1,
            None => alone.push(format!("{}/{}", ns_of(p), name_of(p))),
        }
    }
    let mut again: Vec<String> = vec![];
    let mut down: Vec<String> = vec![];
    for ((ns, k, n), count) in &by {
        again.push(format!("{n} ({})", many(*count as i64, "pod")));
        // Ready ones that stay.
        let stay = all.iter().any(|p| ns_of(p) == ns && !over(p) && pod::cond(p, "Ready").map(|c| c["status"] == "True").unwrap_or(false) && maker(p).as_ref() == Some(&(k.clone(), n.clone())) && !mine.contains(&(ns_of(p), name_of(p))));
        if !stay && k != "Job" {
            down.push(format!("{ns}/{n}"));
        }
    }
    if !again.is_empty() {
        out.push(format!("Made again by: {}.", some(&again, 8)));
    }
    if !down.is_empty() {
        out.push(format!("No other ready pod is left, so it's down until new ones are: {}.", some(&down, 6)));
    }
    if !alone.is_empty() {
        out.push(format!("Nothing makes these again: {}.", some(&alone, 6)));
    }
    if !fixed.is_empty() {
        out.push(format!("Started by their node itself, so deleting does nothing lasting: {}.", some(&fixed, 4)));
    }
    if !live.is_empty() {
        out.push("Disruption budgets don't hold this back.".into());
    }
    (out.join("\n"), live.is_empty())
}

/// What's common to deleting anything: who makes it again, what holds it back, what belongs to the cluster.
pub(super) fn common_words(l: &[&Value]) -> Vec<String> {
    let full = |o: &Value| if ns_of(o).is_empty() { name_of(o).to_string() } else { format!("{}/{}", ns_of(o), name_of(o)) };
    let (mut again, mut tools, mut held, mut own) = (vec![], vec![], vec![], vec![]);
    for o in l {
        let md = &o["metadata"];
        if let Some((k, n)) = maker(o) {
            again.push(format!("{} (by {k} {n})", name_of(o)));
        } else if matches!(name_of(o), "kube-root-ca.crt" | "openshift-service-ca.crt") {
            again.push(format!("{} (by the cluster)", name_of(o)));
        } else if md["annotations"]["argocd.argoproj.io/tracking-id"].is_string() || md["labels"]["argocd.argoproj.io/instance"].is_string() {
            tools.push(format!("{} (Argo CD)", name_of(o)));
        } else if let Some(r) = md["annotations"]["meta.helm.sh/release-name"].as_str() {
            tools.push(format!("{} (Helm release {r})", name_of(o)));
        }
        if md["finalizers"].as_array().map(|f| f.iter().any(|x| !matches!(x.as_str(), Some("kubernetes.io/pvc-protection" | "kubernetes.io/pv-protection")))).unwrap_or(false) {
            held.push(full(o));
        }
        let (ns, n) = (ns_of(o), name_of(o));
        if ns.starts_with("openshift") || ns.starts_with("kube-") || (ns.is_empty() && (n.starts_with("system:") || n.starts_with("openshift"))) || md["labels"]["kubernetes.io/bootstrapping"].is_string() {
            own.push(full(o));
        }
    }
    let mut out = vec![];
    if !own.is_empty() {
        out.push(format!("Belong to the cluster itself: {}.", some(&own, 6)));
    }
    if !again.is_empty() {
        out.push(format!("Likely made again: {}.", some(&again, 6)));
    }
    if !tools.is_empty() {
        out.push(format!("Managed by a tool, which may put them back or miss them: {}.", some(&tools, 6)));
    }
    if !held.is_empty() {
        out.push(format!("Only gone when their finalizers let go: {}.", some(&held, 6)));
    }
    out
}

/// What goes wrong without some of a kind, from the objects alone.
pub(super) fn kind_words(kind: Kind, l: &[&Value]) -> Vec<String> {
    let names = |f: &dyn Fn(&Value) -> bool| -> Vec<String> { l.iter().filter(|o| f(o)).map(|o| name_of(o).to_string()).collect() };
    let mut out: Vec<String> = vec![];
    match kind {
        Kind::Deployments | Kind::DaemonSets | Kind::ReplicaSets | Kind::Jobs => out.push("Their pods go with them.".into()),
        Kind::StatefulSets => {
            let gone = names(&|o| o["spec"]["persistentVolumeClaimRetentionPolicy"]["whenDeleted"] == "Delete");
            out.push("Their pods go with them; their volume claims stay.".into());
            if !gone.is_empty() {
                out.push(format!("Set to take their volume claims, and the data, along: {}.", some(&gone, 6)));
            }
        }
        Kind::CronJobs => out.push("Their jobs and those jobs' pods go with them.".into()),
        Kind::Services => out.push("Their names stop working in the cluster.".into()),
        Kind::Ingresses => {
            let hosts: BTreeSet<String> = l.iter().flat_map(|o| o["spec"]["rules"].as_array().into_iter().flatten()).filter_map(|r| r["host"].as_str().map(String::from)).collect();
            if !hosts.is_empty() {
                out.push(format!("No longer reachable through them: {}.", some(&hosts.into_iter().collect::<Vec<_>>(), 6)));
            }
        }
        Kind::NetworkPolicies => out.push("What they kept out may get in.".into()),
        Kind::HorizontalPodAutoscalers => out.push("Their workloads stay at the number of pods they have now.".into()),
        Kind::PodDisruptionBudgets => out.push("Nothing holds back draining those pods any more.".into()),
        Kind::ResourceQuotas | Kind::LimitRanges => out.push("Their limits no longer hold in those namespaces.".into()),
        Kind::Roles | Kind::RoleBindings | Kind::ClusterRoles | Kind::ClusterRoleBindings => out.push("Rights that were given through them are gone at once.".into()),
        Kind::MutatingWebhooks | Kind::ValidatingWebhooks => out.push("What they checked or changed goes through without them.".into()),
        Kind::StorageClasses => out.push("New claims that name them wait; disks that exist stay.".into()),
        Kind::PersistentVolumes => {
            let bound = names(&|o| o["status"]["phase"] == "Bound");
            let wipe = names(&|o| o["spec"]["persistentVolumeReclaimPolicy"] == "Delete");
            if !bound.is_empty() {
                out.push(format!("In use, so only gone when their claim is: {}.", some(&bound, 6)));
            }
            if !wipe.is_empty() {
                out.push(format!("The data can go with them (policy Delete): {}.", some(&wipe, 6)));
            }
        }
        Kind::Leases => out.push("Whoever holds them has to get them again.".into()),
        _ => {}
    }
    out
}

/// Which workloads a restart replaces pods of, and what's to know. (those it can't be done for left out)
pub(super) fn restart_words(l: &[(&Key3, Kind, &Value)]) -> (Vec<Key3>, String) {
    let mut go: Vec<Key3> = vec![];
    let (mut names, mut paused, mut off, mut manual, mut down) = (vec![], vec![], vec![], vec![], vec![]);
    for (k, kind, o) in l {
        let n = format!("{}/{}", k.1, k.2);
        if *kind == Kind::Deployments && o["spec"]["paused"] == true {
            paused.push(n);
            continue;
        }
        go.push((*k).clone());
        let want = o["spec"]["replicas"].as_i64().unwrap_or(1);
        if *kind != Kind::DaemonSets && want == 0 {
            off.push(n.clone());
        } else if o["spec"]["strategy"]["type"] == "Recreate" || (*kind == Kind::StatefulSets && want == 1) {
            down.push(n.clone());
        }
        if *kind != Kind::Deployments && o["spec"]["updateStrategy"]["type"] == "OnDelete" {
            manual.push(n.clone());
        }
        names.push(n);
    }
    let mut out = vec![];
    if !names.is_empty() {
        out.push(format!("All their pods are replaced, a few at a time: {}.", some(&names, 10)));
    }
    if !down.is_empty() {
        out.push(format!("Down while it restarts: {}.", some(&down, 6)));
    }
    if !manual.is_empty() {
        out.push(format!("Set to replace pods only when they're deleted: {}.", some(&manual, 6)));
    }
    if !off.is_empty() {
        out.push(format!("Scaled to zero, so nothing runs: {}.", some(&off, 6)));
    }
    if !paused.is_empty() {
        out.push(format!("Left out, because their rollout is paused: {}.", some(&paused, 6)));
    }
    (go, out.join("\n"))
}

/// The kubectl calls: a namespace at a time, so many names each.
pub(super) fn calls(verb: Verb, resource: &str, ctx: &str, l: &[Key3]) -> Vec<(usize, Vec<String>)> {
    let mut by: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for k in l.iter().filter(|k| k.0 == ctx) {
        by.entry(&k.1).or_default().push(&k.2);
    }
    let mut out = vec![];
    for (ns, names) in by {
        for part in names.chunks(AT_ONCE) {
            let mut a: Vec<String> = ["--context", ctx].iter().map(|s| s.to_string()).collect();
            if !ns.is_empty() {
                a.extend(["-n".to_string(), ns.to_string()]);
            }
            let full = part.iter().map(|n| format!("{resource}/{n}"));
            match verb {
                Verb::Delete => {
                    a.push("delete".into());
                    a.extend(full);
                    a.extend(["--wait=false".to_string(), "--ignore-not-found".into()]);
                }
                Verb::Restart => {
                    a.extend(["rollout".to_string(), "restart".into()]);
                    a.extend(full);
                }
            }
            out.push((part.len(), a));
        }
    }
    out
}

/// Runs them all; what fails doesn't stop the others. (how many calls' worth went well, what didn't)
pub(super) fn run_calls(k: &Kubectl, l: &[(usize, Vec<String>)]) -> Result<String, String> {
    let mut bad: Vec<String> = vec![];
    for (_, a) in l {
        if let Err(e) = k.run(a) {
            bad.push(truncate(&e, 300));
        }
    }
    if bad.is_empty() { Ok(String::new()) } else { Err(format!("{}{}", bad[0], if bad.len() > 1 { format!(" (and {} more failures)", bad.len() - 1) } else { String::new() })) }
}

// ---------- in the list ----------

/// A tick box: empty, ticked, or a dash for some of them.
fn draw_box(p: &egui::Painter, c: egui::Pos2, on: bool, part: bool, hot: bool) {
    let r = egui::Rect::from_center_size(c, egui::vec2(u(14.0), u(14.0)));
    let fill = if on || part { PRIMARY() } else if hot { BG_HOVER() } else { BG_DEFAULT() };
    p.rect(r, CornerRadius::same(4), fill, Stroke::new(1.0, if on || part { PRIMARY() } else if hot { PRIMARY_TEXT() } else { TEXT_PLACEHOLDER() }), egui::StrokeKind::Inside);
    let s = Stroke::new(1.8, Color32::WHITE);
    if on {
        let (w, h) = (r.width(), r.height());
        p.line_segment([r.min + egui::vec2(w * 0.24, h * 0.52), r.min + egui::vec2(w * 0.43, h * 0.71)], s);
        p.line_segment([r.min + egui::vec2(w * 0.43, h * 0.71), r.min + egui::vec2(w * 0.77, h * 0.31)], s);
    } else if part {
        p.line_segment([egui::pos2(r.left() + 3.5, c.y), egui::pos2(r.right() - 3.5, c.y)], s);
    }
}

/// A row's bin.
pub(super) fn bin_icon(ui: &mut Ui) -> egui::Response {
    icon_button(ui, |p, r, col| {
        let s = Stroke::new(1.3, col);
        let (l, t, rr, b) = (r.left() + 2.0, r.top() + 3.0, r.right() - 2.0, r.bottom());
        p.line_segment([egui::pos2(l - 1.5, t), egui::pos2(rr + 1.5, t)], s);
        p.add(egui::Shape::line(vec![egui::pos2(r.center().x - 2.2, t), egui::pos2(r.center().x - 2.2, t - 2.4), egui::pos2(r.center().x + 2.2, t - 2.4), egui::pos2(r.center().x + 2.2, t)], s));
        p.add(egui::Shape::line(vec![egui::pos2(l, t), egui::pos2(l + 0.8, b), egui::pos2(rr - 0.8, b), egui::pos2(rr, t)], s));
        for x in [-1.8f32, 1.8] {
            p.line_segment([egui::pos2(r.center().x + x, t + 2.6), egui::pos2(r.center().x + x, b - 2.2)], Stroke::new(1.0, col));
        }
    })
}

/// A row's restart arrow.
pub(super) fn restart_icon(ui: &mut Ui) -> egui::Response {
    icon_button(ui, |p, r, col| {
        let c = r.center();
        let rad = 5.4;
        let (from, to) = (-0.30f32, 5.05f32);
        let at = |a: f32| c + egui::vec2(a.cos(), a.sin()) * rad;
        p.add(egui::Shape::line((0..=32).map(|i| at(from + (to - from) * i as f32 / 32.0)).collect(), Stroke::new(1.4, col)));
        let (along, out, e) = (egui::vec2(-to.sin(), to.cos()), egui::vec2(to.cos(), to.sin()), at(to));
        p.add(egui::Shape::convex_polygon(vec![e + along * 3.8, e + out * 2.8 - along * 0.5, e - out * 2.8 - along * 0.5], col, Stroke::NONE));
    })
}

impl KubedogApp {
    fn pick_list(&self, ctx: &str, what: &What) -> &[Value] {
        let key = match what {
            What::Kind(k) => Some(Self::list_key(ctx, *k)),
            What::Custom(k) => self.crd_index(k).and_then(|i| self.crds.get(i as usize)).map(|k| Self::custom_list_key(ctx, k)),
        };
        key.and_then(|k| self.lists.get(&k)).map(|l| l.items.as_slice()).unwrap_or_default()
    }

    fn pick_object(&self, what: &What, k: &Key3) -> Option<&Value> {
        self.pick_list(&k.0, what).iter().find(|o| name_of(o) == k.2 && ns_of(o) == k.1)
    }

    /// What the list that's open is of, when its rows can be ticked.
    pub(super) fn pick_what(&self) -> Option<What> {
        match self.view {
            View::Resource(k) if self.selected.is_none() && !verbs(k).is_empty() => Some(What::Kind(k)),
            View::Custom(i) if self.custom_sel.is_none() => self.crds.get(i as usize).map(|k| What::Custom(k.key.clone())),
            _ => None,
        }
    }

    /// One of them, in words.
    fn pick_noun(&self, what: &What) -> String {
        match what {
            What::Kind(k) => k.singular().into(),
            What::Custom(k) => self.crd_index(k).and_then(|i| self.crds.get(i as usize)).map(|k| k.kind.clone()).unwrap_or("object".into()),
        }
    }

    /// The unique id of every object of a kind that's read.
    fn pick_ids(&self, what: &What) -> HashMap<Key3, String> {
        let mut m = HashMap::new();
        for c in &self.active {
            for o in self.pick_list(c, what) {
                m.insert((c.clone(), ns_of(o).to_string(), name_of(o).to_string()), text(&o["metadata"]["uid"]));
            }
        }
        m
    }

    /// Before a list is drawn: what's in it. Another kind, cluster or namespace starts anew.
    pub(super) fn picks_begin(&mut self, what: &What, rebuilt: bool, len: usize, rows: impl Iterator<Item = Key3>) {
        let place = format!("{what:?}|{:?}|{:?}|{:?}|{:?}", self.active, self.ns_filter, self.ns_multi, self.ns_ctx);
        if self.picks.place != place {
            self.picks.clear();
            self.picks.place = place;
            self.picks.what = Some(what.clone());
            self.picks.shown.clear();
        } else if !rebuilt && self.picks.shown.len() == len {
            return;
        }
        self.picks.shown = rows.collect();
        if !self.picks.set.is_empty() {
            let ids = self.pick_ids(what);
            self.picks.prune(&|k| ids.get(k).cloned());
        }
        // For pictures: the lock open, to see a confirmation (nothing is run in them).
        if self.screenshot.is_some() && std::env::var("KUBEDOG_SHOT_UNLOCK").is_ok() {
            self.unlocked.extend(self.active.clone());
        }
        // For pictures: names with commas, or "failed".
        if self.screenshot.is_some() && self.picks.set.is_empty() {
            if let Ok(w) = std::env::var("KUBEDOG_SHOT_PICK") {
                let ids = self.pick_ids(what);
                let hit: Vec<Key3> = self.picks.shown.iter().filter(|k| w.split(',').any(|x| x == k.2) || (w == "failed" && self.pick_object(what, k).map(over).unwrap_or(false))).cloned().collect();
                for k in hit {
                    if let Some(u) = ids.get(&k) {
                        self.picks.set.insert(k, u.clone());
                    }
                }
            }
        }
    }

    pub(super) fn pick_click(&mut self, what: &What, k: &Key3, shift: bool) {
        let ids = self.pick_ids(what);
        self.picks.click(k, shift, &|k| ids.get(k).cloned());
        // What uses them is read now, for the confirmation.
        self.refresh_current(false);
    }

    pub(super) fn pick_all(&mut self, what: &What) {
        let ids = self.pick_ids(what);
        self.picks.all(&|k| ids.get(k).cloned());
        self.refresh_current(false);
    }

    /// The tick boxes, in the margin left of the table: rows (where, which), and the line with the names of
    /// the columns. Drawn when the mouse is on a row, and all of them once one is ticked.
    pub(super) fn pick_boxes(&mut self, ui: &mut Ui, what: &What, area: egui::Rect, head: Option<egui::Rect>, rows: &[(egui::Rect, usize)]) {
        let x = area.left() - u(11.0);
        let any = !self.picks.set.is_empty();
        // Not through a dialog or a right-click menu on top.
        let pos = ui.input(|i| i.pointer.hover_pos()).filter(|_| self.dialog.is_none() && self.menu_row.is_none());
        let wide = |r: &egui::Rect| egui::Rect::from_min_max(egui::pos2(x - u(11.0), r.top()), egui::pos2(area.right(), r.bottom()));
        let body = head.map(|h| h.bottom()).unwrap_or(area.top());
        let mut click: Option<(Key3, bool)> = None;
        let mut all = false;
        if let Some(h) = head {
            let total = self.picks.shown.iter().filter(|k| self.picks.on(k)).count();
            let hot = pos.map(|p| wide(&h).contains(p)).unwrap_or(false);
            if any || hot {
                let spot = egui::Rect::from_center_size(egui::pos2(x, h.center().y), egui::vec2(u(20.0), h.height()));
                let r = ui.interact(spot, ui.id().with("pick-all"), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                let full = total > 0 && total == self.picks.shown.len();
                draw_box(ui.painter(), spot.center(), full, total > 0 && !full, r.hovered());
                all = r.on_hover_text(if full { "Untick all" } else { "Tick everything that's shown (⌘A)" }).clicked();
            }
        }
        for (rr, idx) in rows {
            let Some(k) = self.picks.shown.get(*idx) else { continue };
            let seen = egui::Rect::from_min_max(egui::pos2(rr.left(), rr.top().max(body)), egui::pos2(rr.right(), rr.bottom().min(area.bottom())));
            if seen.height() < u(8.0) {
                continue;
            }
            let on = self.picks.on(k);
            let hot = pos.map(|p| wide(&seen).contains(p)).unwrap_or(false);
            if on {
                ui.painter().rect_filled(egui::Rect::from_min_max(egui::pos2(area.left(), seen.top()), egui::pos2(area.right(), seen.bottom())), CornerRadius::ZERO, PRIMARY_TEXT().gamma_multiply(0.10));
            }
            if !(any || hot) {
                continue;
            }
            let spot = egui::Rect::from_min_max(egui::pos2(x - u(10.0), seen.top()), egui::pos2(x + u(10.0), seen.bottom()));
            let r = ui.interact(spot, ui.id().with(("pick", idx)), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
            draw_box(&ui.painter().with_clip_rect(spot.expand(2.0)), egui::pos2(x, rr.center().y), on, false, r.hovered());
            if r.clicked() {
                click = Some((k.clone(), ui.input(|i| i.modifiers.shift)));
            }
        }
        if let Some((k, shift)) = click {
            self.pick_click(what, &k, shift);
        }
        if all {
            self.pick_all(what);
        }
    }

    /// The bar with what's ticked and what can be done.
    pub(super) fn picks_bar(&mut self, ui: &mut Ui) {
        let Some(what) = self.pick_what() else { return };
        // (Another page's, until its list is drawn.)
        if self.picks.set.is_empty() || self.picks.what.as_ref() != Some(&what) {
            return;
        }
        let can: &[Verb] = what.kind().map(verbs).unwrap_or(&[Verb::Delete]);
        let noun = self.pick_noun(&what);
        let n = self.picks.set.len();
        let hidden = self.picks.hidden();
        let ctxs: Vec<String> = self.picks.set.keys().map(|k| k.0.clone()).collect::<BTreeSet<_>>().into_iter().collect();
        let mut act: Option<(Verb, String)> = None;
        let (mut copy, mut clear) = (false, false);
        let mut want: Option<&str> = None;
        egui::Panel::bottom("picks").exact_size(u(46.0)).frame(Frame::new().fill(BG_CARD()).inner_margin(Margin::symmetric(22, 8)).stroke(Stroke::new(1.0, BORDER_DEFAULT()))).show(ui, |ui| {
            ui.horizontal_centered(|ui| {
                ui.label(RichText::new(format!("{} selected", plural(n, &noun))).size(z(14.0)).strong().color(TEXT_DEFAULT()));
                if hidden > 0 {
                    ui.label(RichText::new(format!("{hidden} hidden by the filter")).size(z(12.5)).color(WARNING()));
                }
                ui.add_space(6.0);
                for verb in can.iter().copied() {
                    for c in &ctxs {
                        let here = self.picks.set.keys().filter(|k| k.0 == *c).count();
                        let clean = verb == Verb::Delete && what == What::Kind(Kind::Pods) && self.picks.set.keys().filter(|k| k.0 == *c).all(|k| self.pick_object(&what, k).map(over).unwrap_or(false));
                        let word = match verb {
                            Verb::Restart => "Restart",
                            Verb::Delete if clean => "Clean up",
                            Verb::Delete => "Delete",
                        };
                        // A change is for one cluster at a time.
                        let t = if ctxs.len() > 1 { format!("{word} {here} in {}", ctx_label(c)) } else { word.to_string() };
                        if button(ui, &t, verb == Verb::Restart, verb == Verb::Delete) {
                            act = Some((verb, c.clone()));
                        }
                    }
                }
                ui.menu_button(RichText::new("Select…").size(z(13.0)), |ui| {
                    ui.set_min_width(u(170.0));
                    let mut l = vec![("All shown", "all")];
                    if what == What::Kind(Kind::Pods) {
                        l.extend([("Evicted or failed", "failed"), ("Finished", "done"), ("Same workload", "same")]);
                    }
                    for (t, w) in l {
                        if ui.button(t).clicked() {
                            want = Some(w);
                            ui.close();
                        }
                    }
                });
                copy = button(ui, "Copy names", false, false);
                clear = button(ui, "Clear", false, false);
                ui.label(RichText::new("⇧ for a range · Esc clears").size(z(11.5)).color(TEXT_PLACEHOLDER()));
            });
        });
        if copy {
            let t = self.picks.set.keys().map(|k| k.2.clone()).collect::<Vec<_>>().join("\n");
            ui.ctx().copy_text(t);
            self.toast(format!("{} copied", many(n as i64, "name")), false);
        }
        if clear {
            self.picks.clear();
        }
        if let Some(w) = want {
            self.pick_like(&what, w);
        }
        if let Some((verb, c)) = act {
            self.ask_many(&what, verb, &c);
        }
    }

    /// Ticks more of what's shown.
    fn pick_like(&mut self, of: &What, what: &str) {
        let ids = self.pick_ids(of);
        let mine: BTreeSet<(Key3, String)> = if what == "same" { self.picks.set.keys().filter_map(|k| Some(((k.0.clone(), k.1.clone(), String::new()), maker(self.pick_object(of, k)?)?.1))).collect() } else { BTreeSet::new() };
        let more: Vec<Key3> = self
            .picks
            .shown
            .iter()
            .filter(|k| match what {
                "all" => true,
                "same" => self.pick_object(of, k).and_then(maker).map(|m| mine.contains(&((k.0.clone(), k.1.clone(), String::new()), m.1))).unwrap_or(false),
                w => self.pick_object(of, k).map(|o| o["status"]["phase"] == if w == "failed" { "Failed" } else { "Succeeded" }).unwrap_or(false),
            })
            .cloned()
            .collect();
        for k in more {
            if let Some(u) = ids.get(&k) {
                self.picks.set.insert(k, u.clone());
            }
        }
    }

    /// Who still uses a config map, secret, claim or service account; None: not known (yet).
    fn pick_users(&self, kind: Kind, keys: &[Key3]) -> Result<Vec<String>, String> {
        let Some(c) = keys.first().map(|k| k.0.clone()) else { return Ok(vec![]) };
        let mut gone: Vec<String> = vec![];
        for k in objects::needs(kind) {
            match self.missing(&c, k) {
                Some(w) if w.starts_with("reading") => return Err("What uses them is still being read: close this and look again in a moment to see it.".into()),
                Some(w) => gone.push(w),
                None => {}
            }
        }
        let mut v = vec![];
        for k in keys {
            let s = Selected { ctx: k.0.clone(), kind, ns: k.1.clone(), name: k.2.clone() };
            let l = self.users_of(&s);
            if !l.is_empty() {
                let who: Vec<String> = l.iter().map(|u| format!("{} {}", u.0.singular(), u.1)).collect();
                v.push(format!("{} (by {})", k.2, some(&who, 2)));
            }
        }
        if v.is_empty() && !gone.is_empty() {
            return Err(format!("Whether something uses them isn't known: {}.", gone.join("; ")));
        }
        Ok(v)
    }

    /// What deleting some of a kind does, in lines.
    fn delete_lines(&self, kind: Kind, keys: &[Key3], l: &[&Value]) -> Vec<String> {
        let mut out = kind_words(kind, l);
        let c = keys.first().map(|k| k.0.as_str()).unwrap_or("");
        match kind {
            Kind::ConfigMaps | Kind::Secrets | Kind::ServiceAccounts | Kind::PersistentVolumeClaims => match self.pick_users(kind, keys) {
                Ok(v) if v.is_empty() => out.push("No workload that can be seen uses them.".into()),
                Ok(v) => out.push(format!("Still used: {}.{}", some(&v, 6), if kind == Kind::PersistentVolumeClaims { " They only go when those pods are gone." } else { " Those can't start new pods without them." })),
                Err(e) => out.push(e),
            },
            Kind::Services => {
                let led: Vec<String> = self.refs(c, Kind::Ingresses, "").unwrap_or_default().into_iter().filter(|i| podxray::pick_ingress(i).iter().any(|e| keys.iter().any(|k| k.1 == ns_of(i) && k.2 == e.service))).map(|i| name_of(i).to_string()).collect();
                if !led.is_empty() {
                    out.push(format!("These ingresses lead to them: {}.", some(&led, 6)));
                }
            }
            _ => {}
        }
        if kind == Kind::PersistentVolumeClaims {
            let vols = self.refs(c, Kind::PersistentVolumes, "");
            let policy = |o: &Value| vols.as_ref().and_then(|v| v.iter().find(|p| p["metadata"]["name"] == o["spec"]["volumeName"])).map(|p| text(&p["spec"]["persistentVolumeReclaimPolicy"]));
            let wipe: Vec<String> = l.iter().filter(|o| policy(o).as_deref() == Some("Delete")).map(|o| name_of(o).to_string()).collect();
            if !wipe.is_empty() {
                out.push(format!("The data is lost with them: {}.", some(&wipe, 8)));
            }
            if l.iter().any(|o| o["spec"]["volumeName"].is_string() && policy(o).is_none()) {
                out.push("Whether the data is lost depends on their volume's policy, which isn't known here.".into());
            }
        }
        out
    }

    /// One confirmation for all of them in a cluster.
    pub(super) fn ask_many(&mut self, what: &What, verb: Verb, ctx: &str) {
        let keys: Vec<Key3> = self.picks.set.keys().filter(|k| k.0 == ctx).cloned().collect();
        let there: Vec<(&Key3, &Value)> = keys.iter().filter_map(|k| Some((k, self.pick_object(what, k)?))).collect();
        let hidden: Vec<String> = keys.iter().filter(|k| !self.picks.shown.contains(k)).map(|k| k.2.clone()).collect();
        let note = if hidden.is_empty() { String::new() } else { format!("\nThe filter hides {} of them: {}.", hidden.len(), some(&hidden, 6)) };
        let noun = self.pick_noun(what);
        let (items, title, body, word) = match verb {
            Verb::Delete => {
                let objs: Vec<&Value> = there.iter().map(|x| x.1).collect();
                let names: Vec<String> = there.iter().map(|x| if x.0 .1.is_empty() { x.0 .2.clone() } else { format!("{}/{}", x.0 .1, x.0 .2) }).collect();
                let mut word = "Delete";
                let mut lines = vec![some(&names, 8)];
                match what {
                    What::Kind(Kind::Pods) => {
                        let (w, clean) = delete_words(&objs, &self.pick_list(ctx, what).iter().collect::<Vec<_>>());
                        lines.push(w);
                        if clean {
                            word = "Clean up";
                        }
                    }
                    What::Kind(k) => {
                        let mine: Vec<Key3> = there.iter().map(|x| x.0.clone()).collect();
                        lines.extend(self.delete_lines(*k, &mine, &objs));
                        lines.extend(common_words(&objs));
                        lines.push("There's no way back.".into());
                    }
                    What::Custom(_) => {
                        lines.push("What their operator made for them usually goes too, and that can include data.".into());
                        lines.extend(common_words(&objs));
                        lines.push("There's no way back.".into());
                    }
                }
                (there.iter().map(|x| x.0.clone()).collect::<Vec<_>>(), format!("{word} {}", plural(there.len(), &noun)), lines.join("\n"), word)
            }
            Verb::Restart => {
                let Some(kind) = what.kind() else { return };
                let l: Vec<(&Key3, Kind, &Value)> = there.iter().map(|x| (x.0, kind, x.1)).collect();
                let (go, w) = restart_words(&l);
                let t = format!("Restart {}", plural(go.len(), &noun));
                (go, t, w, "Restart")
            }
        };
        if items.is_empty() {
            return self.toast(if body.trim().is_empty() { "They aren't there any more.".into() } else { body }, true);
        }
        self.request(Action::Many { ctx: ctx.into(), what: what.clone(), verb, items }, title, format!("{body}{note}"), word, verb == Verb::Delete);
    }

    /// Confirmed. Only what's still the same object.
    pub(super) fn start_many(&mut self, ctx: &str, what: &What, verb: Verb, items: &[Key3]) {
        let ids = self.pick_ids(what);
        let l: Vec<Key3> = items.iter().filter(|k| self.picks.set.get(*k).map(|u| ids.get(*k) == Some(u)).unwrap_or(false)).cloned().collect();
        if l.is_empty() {
            return self.toast("They aren't there any more.".into(), true);
        }
        let of = plural(l.len(), &self.pick_noun(what));
        let words = match verb {
            Verb::Delete => format!("Deleting {of}"),
            Verb::Restart => format!("Restarting {of}"),
        };
        let c = calls(verb, &what.resource(), ctx, &l);
        self.picks.clear();
        self.busy += 1;
        self.spawn(move |k| Msg::ActionDone { what: words, result: run_calls(k, &c) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key(n: &str) -> Key3 {
        ("c".into(), "shop".into(), n.into())
    }
    fn set(p: &Picks) -> String {
        p.set.keys().map(|k| k.2.as_str()).collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn ticking() {
        let id = |k: &Key3| Some(format!("id-{}", k.2));
        let mut p = Picks { shown: ["a", "b", "c", "d", "e"].iter().map(|n| key(n)).collect(), ..Default::default() };
        p.click(&key("b"), false, &id);
        p.click(&key("d"), true, &id);
        assert_eq!(set(&p), "b c d");
        p.click(&key("c"), false, &id);
        assert_eq!(set(&p), "b d");
        // Back up from the last one.
        p.click(&key("a"), true, &id);
        assert_eq!(set(&p), "a b c d");
        // A filter hides some; they stay, and all that's shown comes to it and goes again.
        p.shown = ["d", "e"].iter().map(|n| key(n)).collect();
        assert_eq!(p.hidden(), 3);
        p.all(&id);
        assert_eq!(set(&p), "a b c d e");
        p.all(&id);
        assert_eq!(set(&p), "a b c");
        // Gone, and made again under the same name: not the same any more.
        p.prune(&|k| match k.2.as_str() { "a" => Some("id-a".into()), "b" => Some("another".into()), _ => None });
        assert_eq!(set(&p), "a");
    }

    fn pod(name: &str, phase: &str, owner: Option<(&str, &str)>) -> Value {
        let mut p = json!({"metadata": {"name": name, "namespace": "shop", "labels": {"pod-template-hash": "5f"}}, "status": {"phase": phase, "conditions": [{"type": "Ready", "status": if phase == "Running" { "True" } else { "False" }}]}});
        if let Some((k, n)) = owner {
            p["metadata"]["ownerReferences"] = json!([{"kind": k, "name": n, "controller": true}]);
        }
        p
    }

    #[test]
    fn deleting_in_words() {
        let web = |n: &str, ph: &str| pod(n, ph, Some(("ReplicaSet", "web-5f")));
        let (a, b, gone, one, job) = (web("web-1", "Running"), web("web-2", "Running"), web("web-0", "Failed"), pod("lone", "Running", None), pod("j-1", "Running", Some(("Job", "j"))));
        let all = [&a, &b, &gone, &one, &job];
        // Only what's over.
        let (w, clean) = delete_words(&[&gone], &all);
        assert!(clean && w.starts_with("1 is over already"), "{w}");
        // One of two: it stays up.
        let (w, clean) = delete_words(&[&a, &gone], &all);
        assert!(!clean && w.contains("Made again by: web (1 pod).") && !w.contains("down until"), "{w}");
        // Both: it goes down. Nobody makes the lone one again.
        let (w, _) = delete_words(&[&a, &b, &one, &job], &all);
        assert!(w.contains("it's down until new ones are: shop/web.") && w.contains("Nothing makes these again: shop/lone.") && w.contains("Disruption budgets"), "{w}");
        // A node's own.
        let mut m = pod("etcd-1", "Running", Some(("Node", "n")));
        m["metadata"]["annotations"]["kubernetes.io/config.mirror"] = json!("x");
        assert!(delete_words(&[&m], &[&m]).0.contains("Started by their node"));
    }

    #[test]
    fn other_kinds_in_words() {
        let o = |name: &str, md: Value| {
            let mut v = json!({"metadata": md});
            v["metadata"]["name"] = json!(name);
            v
        };
        let a = [
            o("made", json!({"namespace": "shop", "ownerReferences": [{"kind": "ExternalSecret", "name": "es", "controller": true}]})),
            o("helm", json!({"namespace": "shop", "annotations": {"meta.helm.sh/release-name": "web"}})),
            o("argo", json!({"namespace": "shop", "annotations": {"argocd.argoproj.io/tracking-id": "x"}})),
            o("held", json!({"namespace": "kube-system", "finalizers": ["example.com/wait"]})),
            o("claim", json!({"namespace": "shop", "finalizers": ["kubernetes.io/pvc-protection"]})),
            o("system:node", json!({})),
        ];
        let w = common_words(&a.iter().collect::<Vec<_>>());
        assert_eq!(w, vec!["Belong to the cluster itself: kube-system/held, system:node.", "Likely made again: made (by ExternalSecret es).", "Managed by a tool, which may put them back or miss them: helm (Helm release web), argo (Argo CD).", "Only gone when their finalizers let go: kube-system/held."]);
        assert!(common_words(&[&a[4]]).is_empty());
        let s = json!({"metadata": {"name": "db"}, "spec": {"persistentVolumeClaimRetentionPolicy": {"whenDeleted": "Delete"}}});
        assert!(kind_words(Kind::StatefulSets, &[&s])[1].ends_with("along: db."));
        let i = json!({"spec": {"rules": [{"host": "web.example.com"}]}});
        assert_eq!(kind_words(Kind::Ingresses, &[&i]), vec!["No longer reachable through them: web.example.com."]);
        let v = json!({"metadata": {"name": "pv"}, "status": {"phase": "Bound"}, "spec": {"persistentVolumeReclaimPolicy": "Delete"}});
        assert_eq!(kind_words(Kind::PersistentVolumes, &[&v]).len(), 2);
        assert_eq!((plural(1, "ingress"), plural(2, "ingress"), plural(3, "network policy"), plural(2, "storage class")), ("1 ingress".into(), "2 ingresses".into(), "3 network policies".into(), "2 storage classes".into()));
    }

    #[test]
    fn restarting_in_words() {
        let (k, d) = (["web", "old", "off", "one", "hand", "paused"].map(key), |s: Value| json!({"spec": s}));
        let o = [d(json!({"replicas": 2})), d(json!({"replicas": 1, "strategy": {"type": "Recreate"}})), d(json!({"replicas": 0})), d(json!({"replicas": 1})), d(json!({"updateStrategy": {"type": "OnDelete"}})), d(json!({"paused": true}))];
        let kinds = [Kind::Deployments, Kind::Deployments, Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::Deployments];
        let l: Vec<(&Key3, Kind, &Value)> = (0..6).map(|i| (&k[i], kinds[i], &o[i])).collect();
        let (go, w) = restart_words(&l);
        assert_eq!(go.len(), 5);
        for x in ["a few at a time: shop/web, shop/old, shop/off, shop/one, shop/hand.", "Down while it restarts: shop/old, shop/one.", "only when they're deleted: shop/hand.", "Scaled to zero, so nothing runs: shop/off.", "rollout is paused: shop/paused."] {
            assert!(w.contains(x), "{x}: {w}");
        }
    }

    #[test]
    fn one_call_per_namespace() {
        let mut l: Vec<Key3> = (0..120).map(|i| key(&format!("p{i:03}"))).collect();
        l.push(("c".into(), "db".into(), "x".into()));
        l.push(("other".into(), "db".into(), "y".into()));
        let c = calls(Verb::Delete, "pods", "c", &l);
        assert_eq!(c.iter().map(|x| x.0).collect::<Vec<_>>(), vec![1, 50, 50, 20]);
        assert_eq!(c[0].1.join(" "), "--context c -n db delete pods/x --wait=false --ignore-not-found");
        let c = calls(Verb::Restart, "statefulsets.apps", "c", &[key("a"), key("b")]);
        assert_eq!(c[0].1.join(" "), "--context c -n shop rollout restart statefulsets.apps/a statefulsets.apps/b");
        // What fails doesn't stop the rest.
        #[cfg(unix)]
        {
            let k = Kubectl { bin: Some("/bin/sh".into()), ..Kubectl::detect() };
            let sh = |s: &str| (1, vec!["-c".to_string(), s.to_string()]);
            let f = std::env::temp_dir().join(format!("kubedog-picks-{}", std::process::id()));
            let r = run_calls(&k, &[sh("echo no >&2; exit 1"), sh(&format!("touch {}", f.display()))]);
            assert!(r.unwrap_err().contains("no") && f.exists());
            let _ = std::fs::remove_file(f);
            assert_eq!(run_calls(&k, &[sh("true")]), Ok(String::new()));
        }
        // Cluster-wide kinds have no namespace.
        let c = calls(Verb::Delete, "backups.example.com", "c", &[("c".into(), String::new(), "b".into())]);
        assert_eq!(c[0].1.join(" "), "--context c delete backups.example.com/b --wait=false --ignore-not-found");
        assert_eq!((verbs(Kind::Pods), verbs(Kind::DaemonSets), verbs(Kind::Secrets)), (&[Verb::Delete][..], &[Verb::Restart, Verb::Delete][..], &[Verb::Delete][..]));
        assert!([Kind::Nodes, Kind::Namespaces, Kind::CustomResourceDefinitions, Kind::Events].into_iter().all(|k| verbs(k).is_empty()));
    }
}
