#![allow(deprecated)]
//! The Kubedog window: sidebar, resource tables, details, logs, actions.

use crate::kube::{self, ContextInfo, Kubectl, Msg};
use crate::logparse::{self, Level};

mod clusters;
mod settings;
mod nodeview;
mod podnet;
mod crds;
mod workload;
mod search;
mod certs;
mod pg;
mod login;
mod elastic;
mod pulsar;
mod hive;
mod grafana;
mod pod;
mod podfiles;
mod podplace;
mod podxray;
mod face;
mod work;
mod objects;
mod powers;
mod ops;
mod argo;
mod opsec;
mod opinfra;
mod opnet;
mod incident;
mod detect;
mod loghunt;
mod connect;
mod compare;
mod readiness;
mod aifacts;
mod aiharness;
mod ai;
mod aichat;
mod aipage;
mod aitools;
mod companion;
mod proxmox;
mod nettest;
mod netlab;
mod nettry;
mod ovntrace;
mod packets;
mod nethelp;
mod picks;
mod shells;
mod backup;
mod update;
mod relogin;
mod side;
mod rowmenu;
mod favs;
mod netpath;
mod openshift;
mod oscatalog;
mod columns;
use columns::ColAction;
mod dash;
mod netmap;
mod storage;
mod terminal;
use crate::resources::{self, Cell, Kind, SortKey, Tone, GROUPS};
use crate::theme::*;
use eframe::egui::{
    self, Align, Color32, CornerRadius, FontId, Frame, Key, Layout, Margin, RichText, Sense,
    Stroke, Ui,
};
use egui_extras::{Column, TableBuilder};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::process::Child;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

/// How often the visible list is fetched again.
const REFRESH_EVERY: Duration = Duration::from_secs(5);
/// A log view keeps this many lines. When it's full the oldest tenth goes at once, so a busy
/// log isn't shifted for every new line.
const MAX_LOG_LINES: usize = 60_000;
/// In wrapped mode only the newest lines are laid out each frame (ours, for speed).
const WRAP_RENDER_LINES: usize = 3_000;
/// How far back a log view starts.
const NEW_LINES: &str = "New lines only";
const EVERYTHING: &str = "Everything";
const SINCE_CHOICES: [&str; 11] = [NEW_LINES, "1m", "10m", "30m", "1h", "3h", "12h", "1d", "3d", "1w", EVERYTHING];
const DEFAULT_SINCE: &str = "10m";
const SIDEBAR_WIDTH: f32 = 218.0;
/// ⌘= and ⌘- go through these; ⌘0 is 1.
const ZOOMS: [f32; 13] = [0.5, 0.67, 0.75, 0.8, 0.9, 1.0, 1.1, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0];
/// How often CPU/memory usage is read again (estimated). Settings can change it.
const METRICS_EVERY: Duration = Duration::from_secs(15);
/// The refresh choices offered in Settings, in seconds.
const REFRESH_CHOICES: [u64; 5] = [2, 5, 10, 30, 60];
const METRICS_CHOICES: [u64; 4] = [10, 15, 30, 60];
/// Pages that can open first after connecting: (setting value, label).
const FIRST_PAGES: [(&str, &str); 6] = [
    ("pods", "Pods"),
    ("cluster", "Cluster overview"),
    ("workloads", "Workloads overview"),
    ("deployments", "Deployments"),
    ("nodes", "Nodes"),
    ("events", "Events"),
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum View {
    ClusterOverview,
    WorkloadsOverview,
    Resource(Kind),
    PortForwards,
    Helm,
    Settings,
    ServiceMap,
    StorageUsage,
    /// A custom resource kind (index into `crds`).
    Custom(u32),
    /// Postgres clusters run by CloudNativePG.
    Postgres,
    Elastic,
    Pulsar,
    /// A honeycomb of pods.
    Hive,
    /// Nodes as a Grafana sees them.
    Observatory,
    /// Proxmox VE: hosts and machines.
    Proxmox,
    /// Testing the network.
    NetLab,
    /// Full-size shells.
    Shells,
    /// An operator's page (index into `powers::OPS`).
    Op(u8),
    Incident,
    Readiness,
}

#[derive(Default)]
struct ListState {
    /// Bumped on every update, so cached views know when to rebuild.
    gen: u64,
    loading: bool,
    error: Option<String>,
    items: Vec<Value>,
    rows: Vec<Row>,
    fetched: Option<Instant>,
    note: Option<String>,
}

#[derive(Clone)]
struct Row {
    ns: String,
    name: String,
    cells: Vec<Cell>,
    /// cpu request m, cpu limit m, memory request B, memory limit B
    req: [f64; 4],
    /// For pods: the workload they belong to (Deployment via its ReplicaSet,
    /// StatefulSet, DaemonSet), used to add up usage per workload.
    workload: Option<(Kind, String)>,
}

#[derive(Default)]
struct Metrics {
    gen: u64,
    loading: bool,
    fetched: Option<Instant>,
    /// Why pod usage couldn't be read.
    error: Option<String>,
    /// The account may not read node usage (not asked for again until a refresh by hand).
    nodes_refused: bool,
    /// Readings of each pod: (reading number, cpu m, memory B), and when each was taken.
    pod_hist: HashMap<(String, String), std::collections::VecDeque<(u32, f32, f32)>>,
    times: std::collections::VecDeque<(u32, i64)>,
    reading: u32,
    /// (namespace, pod) -> (cpu m, memory B)
    pods: HashMap<(String, String), (f64, f64)>,
    /// node -> (cpu m, memory B)
    nodes: HashMap<String, (f64, f64)>,
    /// node -> its recent readings, oldest first (for the node page's chart).
    node_hist: HashMap<String, std::collections::VecDeque<(f64, f64)>>,
}

/// A list page's rows, already filtered and sorted, with their usage. Rebuilt only when
/// the data, the filter, the namespace or the sort changes, not on every frame, so
/// scrolling through hundreds of pods stays smooth.
struct ListCache {
    key: String,
    rows: Vec<(String, Row)>,
    usage: Vec<Option<(f64, f64)>>,
    total: usize,
    /// How wide each column would need to be to show its longest text (measured once).
    content_w: Option<HashMap<String, f32>>,
}

#[derive(Clone, PartialEq)]
struct Nav {
    view: View,
    selected: Option<Selected>,
}

#[derive(Clone, PartialEq, Debug)]
struct Selected {
    ctx: String,
    kind: Kind,
    ns: String,
    name: String,
}

impl Selected {
    fn key(&self) -> String {
        format!("{}|{:?}|{}|{}", self.ctx, self.kind, self.ns, self.name)
    }
    fn ns_args(&self) -> Vec<String> {
        if self.kind.namespaced() {
            vec!["-n".into(), self.ns.clone()]
        } else {
            vec![]
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Overview,
    /// Pods only.
    Containers,
    Environment,
    Network,
    Scheduling,
    Storage,
    Files,
    WhatIf,
    Revisions,
    Yaml,
    Events,
    Logs,
}

struct LogState {
    id: u64,
    target: String,
    child: Option<Child>,
    lines: Vec<LogLine>,
    dropped: usize,
    running: bool,
}

#[derive(Clone)]
struct LogLine {
    text: String,
    err: bool,
    level: Level,
}

impl LogLine {
    fn new(raw: String, err: bool) -> Self {
        let text = logparse::strip_ansi(&raw);
        let level = if err { Level::Error } else { logparse::level_of(logparse::split_prefixes(&text).1) };
        LogLine { text, err, level }
    }
}

struct LogPrefs {
    /// Levels hidden by "Filter by Log Level".
    hidden_levels: HashSet<Level>,
    container: String,
    follow: bool,
    timestamps: bool,
    wrap: bool,
    previous: bool,
    since: &'static str,
    filter: String,
}

struct PortForward {
    id: u64,
    ctx: String,
    ns: String,
    target: String,
    local: u16,
    remote: u16,
    child: Option<Child>,
    status: String,
    output: Vec<String>,
    open_browser: bool,
}

#[derive(Clone)]
enum Action {
    /// force: grace period 0; orphan: leave dependents.
    Delete(Selected, bool, bool),
    Restart(Selected),
    Scale(Selected, i64),
    Cordon(Selected, bool),
    /// delete emptyDir data, disable eviction, force.
    Drain(Selected, bool, bool, bool),
    Apply(Selected, String),
    /// A merge patch (edited config map / secret data).
    Patch(Selected, String),
    HelmUninstall { ctx: String, ns: String, name: String },
    /// kubectl rollout undo --to-revision.
    Rollback(Selected, i64),
    /// Run a cron job now, suspend or resume it, pause or resume a rollout.
    Run { sel: Selected, args: Vec<String>, what: String },
    /// Tests from inside pods (Network Lab), all in one cluster.
    NetTry { tries: Vec<nettry::Try> },
    /// Several objects of a list, all in one cluster.
    Many { ctx: String, what: picks::What, verb: picks::Verb, items: Vec<picks::Key3> },
    /// A capture of packets (Network Lab).
    Grab { grab: Box<packets::Grab> },
    /// A path computed by OVN (Network Lab).
    OvnTrace { ask: Box<ovntrace::Ask> },
    /// Make an object from its text (kubectl create).
    Create { sel: Selected, manifest: String, what: String },
    /// A `kubectl cnpg` command.
    Cnpg { ctx: String, args: Vec<String>, what: String },
    /// Delete any object by resource name (custom resources).
    DeleteRaw { ctx: String, resource: String, ns: Option<String>, name: String },
}

impl Action {
    fn ctx(&self) -> &str {
        match self {
            Action::Rollback(s, _) | Action::Delete(s, _, _)
            | Action::Restart(s)
            | Action::Scale(s, _)
            | Action::Cordon(s, _)
            | Action::Drain(s, _, _, _)
            | Action::Apply(s, _)
            | Action::Patch(s, _) => &s.ctx,
            Action::HelmUninstall { ctx, .. } => ctx,
            Action::Many { ctx, .. } => ctx,
            Action::OvnTrace { ask } => &ask.ctx,
            Action::Grab { grab } => &grab.ctx,
            Action::NetTry { tries } => tries.first().map(|t| t.ctx.as_str()).unwrap_or(""),
            Action::Run { sel, .. } | Action::Create { sel, .. } => &sel.ctx,
            Action::DeleteRaw { ctx, .. } | Action::Cnpg { ctx, .. } => ctx,
        }
    }
}

enum Dialog {
    Confirm {
        title: String,
        body: String,
        button: String,
        danger: bool,
        action: Action,
    },
    Protected {
        ctx: String,
    },
    Scale {
        sel: Selected,
        replicas: String,
    },
    Drain {
        sel: Selected,
        delete_emptydir: bool,
        disable_eviction: bool,
        force: bool,
    },
    Delete {
        sel: Selected,
        force: bool,
        orphan: bool,
        advanced: bool,
    },
    /// Remove a context entry from its kubeconfig file (asked for on the start page).
    DeleteContext {
        name: String,
        file: String,
    },
    /// Save edited data of a config map or secret.
    SaveData {
        sel: Selected,
        patch: String,
        summary: String,
    },
    PortForward {
        sel: Selected,
        ports: Vec<u16>,
        remote: String,
        local: String,
        open_browser: bool,
    },
    /// Before connecting: clusters whose name is too long get a short one (context, new name).
    NameClusters {
        names: Vec<(String, String)>,
    },
}

struct Toast {
    text: String,
    error: bool,
    at: Instant,
}

pub struct KubedogApp {
    egui_ctx: egui::Context,
    kubectl: Kubectl,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    demo: bool,

    contexts: Vec<ContextInfo>,
    contexts_error: Option<String>,
    connected: bool,
    current_context: Option<String>,
    file_errors: Option<String>,
    add_file_path: String,
    /// The path to kubectl typed on the start page when it wasn't found.
    kubectl_typed: String,
    paste_config: String,
    paste_name: String,
    paste_open: bool,
    show_hidden: bool,
    /// Settings is open on the start page, before any cluster is.
    start_settings: bool,
    pings: HashMap<String, (bool, Result<String, String>)>,
    /// Keyboard focus on the start screen's grid.
    picker_focus: usize,
    picker: HashSet<String>,
    picker_search: String,
    collapsed: HashSet<String>,
    back: Vec<Nav>,
    forward: Vec<Nav>,
    metrics: HashMap<String, Metrics>,
    threshold: u32,
    contexts_loading: bool,
    active: Vec<String>,
    unlocked: HashSet<String>,

    view: View,
    lists: HashMap<String, ListState>,
    namespaces: HashMap<String, Vec<String>>,
    ns_filter: Option<String>,
    /// Two or more namespaces ticked in the namespace menu (then `ns_filter` is None).
    ns_multi: Vec<String>,
    /// What's typed in the namespace menu's search box.
    ns_search: String,
    /// (Screenshot test aid.)
    shot_filtered: bool,
    shot_opened: bool,
    /// With several clusters open: show only this one (its namespace `ns_filter`, or all of it).
    ns_ctx: Option<String>,
    search: String,
    /// Each page keeps its own filter text (key: the page).
    /// The shared filter while on Nodes, and the Nodes filter while elsewhere.
    filter_stash: String,
    node_filter: String,
    focus_search: bool,
    prefs: Prefs,
    term: terminal::Dock,
    certs: HashMap<String, (bool, Result<certs::CertInfo, String>)>,
    claim_stats: HashMap<String, storage::ClaimStats>,
    /// An object a sub-page asked to open (applied after drawing).
    pending_open: Option<Selected>,
    list_cache: Option<ListCache>,
    /// The start-up choice ("reconnect") has been acted on.
    startup_done: bool,
    /// "G" was pressed: the next letter goes to a page (see Settings → Shortcuts).
    chord: Option<Instant>,
    settings_section: &'static str,
    /// A column header being dragged to a new place.
    col_drag: Option<String>,
    /// Menu bar choices waiting for the next frame.
    menu_pending: Vec<String>,
    /// The last session's page and namespace were brought back (only once, on the first connect).
    session_restored: bool,
    /// The filter box over a pod's environment variables.
    env_filter: String,
    /// Long environment values unfolded by a click (pod key + container + name).
    env_open: HashSet<String>,
    /// Custom resource kinds found in the open clusters' CRDs (only grows).
    crds: Vec<crds::CrdKind>,
    crd_gen: u64,
    crd_filter: String,
    /// API groups unfolded in the sidebar.
    crd_open: HashSet<String>,
    custom_sel: Option<crds::CustomSel>,
    powers: powers::Powers,
    ai: ai::AiState,
    companion: companion::Companion,
    proxmox: proxmox::Proxmox,
    netlab: netlab::NetLab,
    picks: picks::Picks,
    /// The row whose right-click menu is open: it stays marked while the mouse is in the menu.
    menu_row: Option<picks::Key3>,
    shells: shells::Shells,
    backup: backup::Backup,
    update: update::Update,
    relogin: relogin::Relogin,
    catalog: oscatalog::Catalog,
    incident: incident::Room,
    ready: readiness::Ready,
    custom_tab: u8,
    /// Sort column (0 name, 1 namespace, 2.. printer columns, MAX age) and direction.
    custom_sort: (usize, bool),
    /// A custom object's YAML and events: key -> (loading, text).
    custom_text: HashMap<String, (bool, Result<String, String>)>,
    /// The search box (⌘K): what's typed and the highlighted result.
    palette: Option<(String, usize)>,
    /// The Postgres cluster whose page is open, and what's known of each cluster's live state.
    pg_sel: Option<pg::PgId>,
    pg_state: HashMap<String, pg::PgState>,
    es_sel: Option<pg::PgId>,
    pu_sel: Option<pg::PgId>,
    hive: hive::Hive,
    pod: pod::PodPage,
    grafana: grafana::Grafana,
    /// What services inside the clusters answered (Elasticsearch, Pulsar).
    served: HashMap<String, login::Served>,
    /// Whether there's a Pulsar, for a state of the pod lists.
    pulsar_seen: std::cell::Cell<(u64, bool)>,
    /// What's being typed in a cluster's namespaces box (context -> text).
    ns_edit: HashMap<String, String>,
    /// The column picker was asked for from the menu.
    open_columns: bool,
    /// The system shows light windows (for the Auto theme).
    system_light: bool,
    /// A scripted mouse for test runs (see raw_input_hook): steps still to do.
    shot_mouse: Option<std::collections::VecDeque<String>>,
    sort: (Option<String>, bool),

    selected: Option<Selected>,
    tab: Tab,
    yaml: HashMap<String, (bool, Result<String, String>)>,
    yaml_edit: Option<(String, String)>,
    events: HashMap<String, (bool, Result<Vec<Value>, String>)>,
    reveal_secrets: bool,
    /// Secret values the person clicked to reveal (key: object + data key).
    revealed: HashSet<String>,
    /// Editing a config map's or secret's data: (object key, rows of key/value, original keys).
    data_edit: Option<(String, Vec<(String, String)>, Vec<String>)>,

    log: Option<LogState>,
    log_prefs: LogPrefs,
    next_id: u64,
    port_forwards: Vec<PortForward>,

    helm: HashMap<String, (bool, Result<Vec<Value>, String>)>,

    dialog: Option<Dialog>,
    toasts: Vec<Toast>,
    busy: usize,

    screenshot: Option<String>,
    frames: u64,
    started: Instant,
    shot_requested: bool,
}

impl KubedogApp {
    pub fn new(egui_ctx: egui::Context, screenshot: Option<String>) -> Self {
        let (tx, rx) = channel();
        let kubectl = Kubectl::detect();
        let mut app = KubedogApp {
            egui_ctx,
            // Sample data is only shown when asked for (the start page offers it when kubectl is missing).
            demo: false,
            kubectl,
            tx,
            rx,
            contexts: vec![],
            contexts_error: None,
            connected: false,
            current_context: None,
            file_errors: None,
            add_file_path: String::new(),
            kubectl_typed: String::new(),
            paste_config: String::new(),
            paste_name: String::new(),
            paste_open: false,
            show_hidden: false,
            start_settings: false,
            pings: HashMap::new(),
            picker_focus: 0,
            picker: HashSet::new(),
            picker_search: String::new(),
            collapsed: ["Helm", "Access Control", "Administration"].iter().map(|s| s.to_string()).collect(),
            back: vec![],
            forward: vec![],
            metrics: HashMap::new(),
            threshold: 95,
            contexts_loading: true,
            active: vec![],
            unlocked: HashSet::new(),
            view: View::Resource(Kind::Pods),
            lists: HashMap::new(),
            namespaces: HashMap::new(),
            ns_filter: None,
            ns_multi: vec![],
            ns_search: String::new(),
            shot_filtered: false,
            shot_opened: false,
            ns_ctx: None,
            search: String::new(),
            filter_stash: String::new(),
            node_filter: String::new(),
            focus_search: false,
            prefs: Prefs::default(),
            term: terminal::Dock::default(),
            certs: HashMap::new(),
            claim_stats: HashMap::new(),
            pending_open: None,
            list_cache: None,
            startup_done: false,
            chord: None,
            settings_section: "General",
            col_drag: None,
            menu_pending: vec![],
            ns_edit: HashMap::new(),
            session_restored: false,
            env_filter: String::new(),
            env_open: HashSet::new(),
            crds: vec![],
            crd_gen: 0,
            crd_filter: String::new(),
            crd_open: HashSet::new(),
            custom_sel: None,
            powers: Default::default(),
            ai: Default::default(),
            companion: Default::default(),
            proxmox: Default::default(),
            netlab: Default::default(),
            picks: Default::default(),
            menu_row: None,
            shells: Default::default(),
            backup: Default::default(),
            update: Default::default(),
            relogin: Default::default(),
            catalog: Default::default(),
            incident: Default::default(),
            ready: Default::default(),
            custom_tab: 0,
            custom_sort: (0, true),
            custom_text: HashMap::new(),
            palette: None,
            pg_sel: None,
            pg_state: HashMap::new(),
            es_sel: None,
            pu_sel: None,
            hive: hive::Hive::default(),
            pod: pod::PodPage::default(),
            grafana: grafana::Grafana::default(),
            served: HashMap::new(),
            pulsar_seen: std::cell::Cell::new((0, false)),
            open_columns: false,
            system_light: false,
            shot_mouse: None,
            sort: (None, true),
            selected: None,
            tab: Tab::Overview,
            yaml: HashMap::new(),
            yaml_edit: None,
            events: HashMap::new(),
            reveal_secrets: false,
            revealed: HashSet::new(),
            data_edit: None,
            log: None,
            log_prefs: LogPrefs {
                container: String::new(),
                follow: true,
                timestamps: true,
                wrap: true,
                previous: false,
                since: DEFAULT_SINCE,
                filter: String::new(),
                hidden_levels: HashSet::new(),
            },
            next_id: 1,
            port_forwards: vec![],
            helm: HashMap::new(),
            dialog: None,
            toasts: vec![],
            busy: 0,
            screenshot,
            frames: 0,
            started: Instant::now(),
            shot_requested: false,
        };
        if app.screenshot.is_none() {
            app.prefs = load_prefs();
            grafana::set_shared(&app.prefs.authorities);
        } else if let Ok(j) = std::env::var("KUBEDOG_SHOT_PREFS") {
            // Test aid: sample settings for a screenshot, kept in memory only (nothing is saved).
            if let Ok(v) = serde_json::from_str::<Value>(&j) {
                app.prefs = prefs_from_json(&v);
            }
        }
        set_ctx_look(&app.prefs);
        // The theme: saved choice, or KUBEDOG_SHOT_THEME for a screenshot.
        if app.screenshot.is_some() {
            let var = |k: &str| std::env::var(k).ok();
            let (t, a) = (var("KUBEDOG_SHOT_THEME"), var("KUBEDOG_SHOT_ACCENT"));
            if t.is_some() || a.is_some() {
                (app.prefs.theme, app.prefs.accent) = crate::theme::read_look(t.as_deref(), a.as_deref());
            }
        }
        app.apply_theme();
        app.apply_font();
        // Test aid: fold the built-in sidebar groups (and open some API groups) for a screenshot.
        if app.screenshot.is_some() {
            if let Ok(open) = std::env::var("KUBEDOG_SHOT_FOLD") {
                app.collapsed = GROUPS.iter().map(|g| g.0.to_string()).chain(["Helm".to_string()]).collect();
                app.crd_open = open.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
            }
        }
        if app.screenshot.is_none() {
            let s = app.prefs.session.clone();
            if s.zoom > 0.0 && (s.zoom - 1.0).abs() > 0.01 {
                app.egui_ctx.set_zoom_factor(s.zoom);
            }
            if !s.collapsed.is_empty() {
                app.collapsed = s.collapsed.into_iter().collect();
            }
        }
        app.log_prefs.wrap = app.prefs.log_wrap;
        app.log_prefs.timestamps = app.prefs.log_timestamps;
        app.log_prefs.since = SINCE_CHOICES.iter().copied().find(|x| *x == app.prefs.log_since).unwrap_or(DEFAULT_SINCE);
        app.apply_kubeconfigs();
        app.wsl_app_start();
        if app.kubectl.bin.is_none() {
            // Pointed out by hand earlier?
            let by_hand = std::path::PathBuf::from(app.prefs.kubectl_path.trim());
            if !app.prefs.kubectl_path.trim().is_empty() && by_hand.is_file() {
                app.kubectl.bin = Some(by_hand);
            }
        }
        if app.kubectl.bin.is_some() {
            app.load_contexts();
        } else {
            // The start page says what's missing and what to do.
            app.contexts_loading = false;
        }
        app
    }

    // ---------------- background work ----------------

    fn spawn(&self, f: impl FnOnce(&Kubectl) -> Msg + Send + 'static) {
        let k = self.kubectl.clone();
        let tx = self.tx.clone();
        let ctx = self.egui_ctx.clone();
        std::thread::spawn(move || {
            let m = f(&k);
            let _ = tx.send(m);
            ctx.request_repaint();
        });
    }

    fn load_contexts(&mut self) {
        self.load_contexts_from_files();
    }

    fn list_key(ctx: &str, kind: Kind) -> String {
        format!("list|{ctx}|{kind:?}")
    }

    /// Whether something in this namespace is shown under the namespace choice (one, several or all).
    fn ns_ok(&self, ns: &str) -> bool {
        if !self.ns_multi.is_empty() {
            return self.ns_multi.iter().any(|n| n == ns);
        }
        self.ns_filter.as_deref().map(|n| n == ns).unwrap_or(true)
    }

    /// Some namespace choice is in effect (not "All namespaces").
    fn ns_any(&self) -> bool {
        self.ns_filter.is_some() || !self.ns_multi.is_empty()
    }

    /// Tick or untick a namespace in the menu: one ticked is a plain choice, two or more a set.
    fn ns_toggle(&mut self, ns: &str) {
        let mut set: Vec<String> = if self.ns_multi.is_empty() { self.ns_filter.iter().cloned().collect() } else { self.ns_multi.clone() };
        if let Some(i) = set.iter().position(|n| n == ns) {
            set.remove(i);
        } else {
            set.push(ns.to_string());
        }
        set.sort();
        self.set_ns_choice(set);
    }

    fn set_ns_choice(&mut self, set: Vec<String>) {
        match set.len() {
            0 => {
                self.ns_filter = None;
                self.ns_multi.clear();
            }
            1 => {
                self.ns_filter = set.into_iter().next();
                self.ns_multi.clear();
            }
            _ => {
                self.ns_filter = None;
                self.ns_multi = set;
            }
        }
    }

    /// Whether a cluster's things are shown (several clusters open, one picked in the namespace box).
    fn ctx_shown(&self, ctx: &str) -> bool {
        self.ns_ctx.as_deref().map(|c| c == ctx).unwrap_or(true)
    }

    fn default_ns(&self, ctx: &str) -> String {
        self.contexts
            .iter()
            .find(|c| c.name == ctx)
            .map(|c| c.namespace.clone())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "default".into())
    }

    /// Whether the cluster said this account may not list a kind.
    fn refused(&self, ctx: &str, kind: Kind) -> bool {
        self.lists.get(&Self::list_key(ctx, kind)).and_then(|l| l.error.as_deref()).map(is_refusal).unwrap_or(false)
    }

    /// Whether every open cluster that's shown refuses its nodes.
    fn nodes_refused(&self) -> bool {
        let mut shown = self.active.iter().filter(|c| self.ctx_shown(c)).peekable();
        shown.peek().is_some() && shown.all(|c| self.refused(c, Kind::Nodes))
    }

    fn fetch_list(&mut self, ctx: &str, kind: Kind) {
        if self.demo {
            return;
        }
        let key = Self::list_key(ctx, kind);
        let st = self.lists.entry(key.clone()).or_default();
        if st.loading {
            return;
        }
        st.loading = true;
        let ctx = ctx.to_string();
        let fallback_ns = self.default_ns(&ctx);
        // A cluster limited to some namespaces: read only those.
        if let Some(patterns) = self.prefs.ctx_namespaces.get(&ctx).cloned() {
            let known = self.namespaces.get(&ctx).cloned().unwrap_or_default();
            self.spawn(move |k| {
                let result = if kind == Kind::Namespaces {
                    limited_namespace_items(k, &ctx, &patterns)
                } else if kind.namespaced() {
                    expand_namespaces(k, &ctx, &patterns, &known).and_then(|names| get_in_namespaces(k, &ctx, kind, &names))
                } else {
                    k.run(&["--context".into(), ctx.clone(), "get".into(), kind.resource().into(), "-o".into(), "json".into(), format!("--request-timeout={}", kube::REQUEST_TIMEOUT)])
                        .and_then(|j| kube::parse_items(&j))
                };
                let result = match result {
                    Err(e) if kind == Kind::CustomResourceDefinitions && is_refusal(&e) => Ok(crds::discovered(k, &ctx)),
                    r => r,
                };
                let rows = result.as_ref().ok().map(|items| Box::new(items.iter().map(|o| make_row(kind, o)).collect::<Vec<Row>>()) as Box<dyn std::any::Any + Send>);
                Msg::List { key, result, rows }
            });
            return;
        }
        self.spawn(move |k| {
            let mut args: Vec<String> = vec![
                "--context".into(),
                ctx.clone(),
                "get".into(),
                kind.resource().into(),
                "-o".into(),
                "json".into(),
                format!("--request-timeout={}", kube::REQUEST_TIMEOUT),
            ];
            if kind.namespaced() {
                args.push("--all-namespaces".into());
            }
            let mut result = k.run(&args).and_then(|j| kube::parse_items(&j));
            // No right to list across namespaces: read the namespaces this account can see
            // (OpenShift lists them as projects), else the context's own namespace.
            if let Err(e) = &result {
                if e.contains("forbidden") || e.contains("Forbidden") {
                    let visible = visible_namespaces(k, &ctx).ok().filter(|v| !v.is_empty());
                    if kind == Kind::Namespaces {
                        if let Some(v) = visible {
                            result = Ok(v.into_iter().map(|n| serde_json::json!({"metadata": {"name": n}, "status": {"phase": "Active"}})).collect());
                        }
                    } else if kind == Kind::CustomResourceDefinitions {
                        result = Ok(crds::discovered(k, &ctx));
                    } else if kind.namespaced() {
                        let tried = visible.map(|mut v| {
                            v.truncate(60);
                            get_in_namespaces(k, &ctx, kind, &v)
                        });
                        result = match tried {
                            Some(Ok(items)) => Ok(items),
                            _ => {
                                args.retain(|a| a != "--all-namespaces");
                                args.push("-n".into());
                                args.push(fallback_ns);
                                k.run(&args).and_then(|j| kube::parse_items(&j))
                            }
                        };
                    }
                }
            }
            let rows = result.as_ref().ok().map(|items| {
                Box::new(items.iter().map(|o| make_row(kind, o)).collect::<Vec<Row>>()) as Box<dyn std::any::Any + Send>
            });
            Msg::List { key, result, rows }
        });
    }

    fn fetch_namespaces(&mut self, ctx: &str) {
        if self.demo || self.namespaces.contains_key(ctx) {
            return;
        }
        self.namespaces.insert(ctx.to_string(), vec![]);
        self.fetch_list(ctx, Kind::Namespaces);
    }

    fn fetch_text(&mut self, key: String, args: Vec<String>) {
        self.spawn(move |k| Msg::Text { key, result: k.run(&args) });
    }

    fn fetch_yaml(&mut self, sel: &Selected) {
        if self.demo {
            return;
        }
        let key = format!("yaml|{}", sel.key());
        self.yaml.insert(key.clone(), (true, Ok(String::new())));
        let mut args = vec!["--context".into(), sel.ctx.clone(), "get".into(), sel.kind.resource().into(), sel.name.clone()];
        args.extend(sel.ns_args());
        args.extend(["-o".into(), "yaml".into(), format!("--request-timeout={}", kube::REQUEST_TIMEOUT)]);
        self.fetch_text(key, args);
    }

    fn fetch_events(&mut self, sel: &Selected) {
        if self.demo {
            return;
        }
        let key = format!("events|{}", sel.key());
        self.events.insert(key.clone(), (true, Ok(vec![])));
        let mut args = vec![
            "--context".into(),
            sel.ctx.clone(),
            "get".into(),
            "events".into(),
            "--field-selector".into(),
            format!("involvedObject.name={}", sel.name),
            "-o".into(),
            "json".into(),
            format!("--request-timeout={}", kube::REQUEST_TIMEOUT),
        ];
        if sel.kind.namespaced() {
            args.extend(sel.ns_args());
        } else {
            args.push("--all-namespaces".into());
        }
        self.fetch_text(key, args);
    }

    fn fetch_helm(&mut self, ctx: &str) {
        if self.demo {
            return;
        }
        let key = format!("helm|{ctx}");
        if self.helm.get(&key).map(|h| h.0).unwrap_or(false) {
            return;
        }
        self.helm.insert(key.clone(), (true, Ok(vec![])));
        let ctx = ctx.to_string();
        let limited = self.prefs.ctx_namespaces.get(&ctx).cloned();
        let known = self.namespaces.get(&ctx).cloned().unwrap_or_default();
        let own = self.default_ns(&ctx);
        self.spawn(move |k| {
            let list = |ns: Option<&str>| {
                let mut a: Vec<String> = ["list", "--kube-context", &ctx, "-o", "json"].iter().map(|s| s.to_string()).collect();
                match ns {
                    Some(n) => a.extend(["-n".to_string(), n.to_string()]),
                    None => a.push("--all-namespaces".into()),
                }
                k.run_helm(&a)
            };
            let each = |names: Vec<String>| -> Result<String, String> {
                let results: Vec<Result<Vec<Value>, String>> = names.iter().map(|n| list(Some(n)).and_then(|t| serde_json::from_str::<Vec<Value>>(&t).map_err(|e| e.to_string()))).collect();
                if results.iter().all(|r| r.is_err()) {
                    return Err(results.into_iter().find_map(|r| r.err()).unwrap_or_default());
                }
                Ok(Value::Array(results.into_iter().flatten().flatten().collect()).to_string())
            };
            let result = match &limited {
                Some(p) => expand_namespaces(k, &ctx, p, &known).and_then(each),
                None => match list(None) {
                    Err(e) if is_refusal(&e) => each(visible_namespaces(k, &ctx).ok().filter(|v| !v.is_empty()).map(|mut v| {
                        v.truncate(60);
                        v
                    }).unwrap_or_else(|| vec![own])),
                    r => r,
                },
            };
            Msg::Text { key, result }
        });
    }

    fn view_kinds(&self) -> Vec<Kind> {
        match self.view {
            // A workload's page: its pods, what leads to them, what scales and guards them.
            View::Resource(k) if work::is_work(k) && self.selected.as_ref().map(|s| s.kind == k).unwrap_or(false) => {
                let mut v = work::needs(k);
                match self.tab {
                    Tab::Environment => v.push(Kind::ConfigMaps),
                    Tab::Scheduling => v.push(Kind::Nodes),
                    _ => {}
                }
                v
            }
            // A pod's page: what sends it traffic, the policies on it, and its config maps (for env values).
            View::Resource(Kind::Pods) if self.selected.as_ref().map(|s| s.kind == Kind::Pods).unwrap_or(false) => {
                let mut v = vec![Kind::Pods, Kind::Services, Kind::Ingresses, Kind::NetworkPolicies, Kind::ConfigMaps];
                match self.tab {
                    Tab::Storage => v.push(Kind::PersistentVolumeClaims),
                    Tab::Scheduling => v.push(Kind::Nodes),
                    Tab::WhatIf => v.extend([Kind::Nodes, Kind::PodDisruptionBudgets]),
                    _ => {}
                }
                v
            }
            // Other pages: what they point at and what uses them.
            View::Resource(k) if self.selected.as_ref().map(|s| s.kind == k).unwrap_or(false) => objects::needs(k),
            // Workload usage is added up from their pods, so those load too.
            View::Resource(k @ (Kind::Deployments | Kind::StatefulSets | Kind::DaemonSets)) => vec![k, Kind::Pods],
            // Without the right to read nodes, the page shows the ones your pods run on.
            View::Resource(Kind::Nodes) if self.active.iter().any(|c| self.refused(c, Kind::Nodes)) => vec![Kind::Nodes, Kind::Pods],
            // Ticked ones: what uses them, for the confirmation.
            View::Resource(k) if !self.picks.set.is_empty() && self.picks.what == Some(picks::What::Kind(k)) => {
                let mut v = objects::needs(k);
                if k == Kind::PersistentVolumeClaims {
                    v.push(Kind::PersistentVolumes);
                }
                v
            }
            View::Resource(k) => vec![k],
            View::ClusterOverview => vec![Kind::Nodes, Kind::PersistentVolumes, Kind::Namespaces, Kind::CustomResourceDefinitions, Kind::Pods, Kind::Events, Kind::Deployments],
            View::WorkloadsOverview => vec![
                Kind::Pods,
                Kind::Deployments,
                Kind::ReplicaSets,
                Kind::DaemonSets,
                Kind::StatefulSets,
                Kind::CronJobs,
                Kind::Jobs,
                Kind::ResourceQuotas,
                Kind::Events,
            ],
            View::PortForwards | View::Helm | View::Settings | View::Custom(_) => vec![],
            View::Postgres | View::Elastic | View::Pulsar => vec![Kind::Pods],
            View::Hive => vec![Kind::Pods, Kind::Events, Kind::ResourceQuotas],
            View::Observatory => vec![Kind::Pods],
            View::Proxmox => vec![Kind::Pods, Kind::Nodes],
            View::NetLab => self.netlab_kinds(),
            View::Shells => vec![Kind::Deployments],
            View::Op(i) => powers::OPS.get(i as usize).map(|o| o.kinds.to_vec()).unwrap_or_default(),
            View::Incident => self.incident_kinds(),
            View::Readiness => self.ready_kinds(),
            View::ServiceMap => vec![Kind::Ingresses, Kind::Services, Kind::EndpointSlices, Kind::Pods],
            View::StorageUsage => vec![Kind::PersistentVolumeClaims, Kind::Pods],
        }
    }

    /// Views that show CPU and memory usage from the metrics API.
    fn wants_metrics(&self) -> bool {
        matches!(
            self.view,
            View::ClusterOverview
                | View::WorkloadsOverview
                | View::Postgres
                | View::Op(_)
                | View::Incident
                | View::Readiness
                | View::Hive
                | View::Observatory
                | View::Resource(Kind::Pods | Kind::Deployments | Kind::StatefulSets | Kind::DaemonSets | Kind::Nodes)
        ) || (self.selected.is_some() && matches!(self.view, View::Resource(Kind::ReplicaSets | Kind::Jobs | Kind::CronJobs | Kind::Services | Kind::Namespaces)))
    }

    fn refresh_current(&mut self, force: bool) {
        if !self.connected {
            return;
        }
        self.ensure_crds();
        if let View::Custom(i) = self.view {
            self.refresh_custom(i, force);
        }
        self.refresh_op(force);
        self.refresh_incident(force);
        self.refresh_readiness(force);
        self.refresh_pg(force);
        self.refresh_elastic(force);
        self.refresh_pulsar(force);
        self.refresh_grafana(force);
        self.refresh_proxmox(force);
        self.refresh_netlab(force);
        self.refresh_pod(force);
        let ctxs = self.active.clone();
        if self.view == View::Helm {
            for c in &ctxs {
                if force {
                    if let Some(h) = self.helm.get_mut(&format!("helm|{c}")) {
                        h.0 = false;
                    }
                }
                if !self.helm.contains_key(&format!("helm|{c}")) || force {
                    self.fetch_helm(c);
                }
            }
        }
        let kinds = self.view_kinds();
        let metrics = self.wants_metrics();
        let refresh_every = self.refresh_every();
        let metrics_every = Duration::from_secs(self.prefs.metrics_secs.max(1));
        self.refresh_storage(force);
        for c in &ctxs {
            self.fetch_namespaces(c);
            for k in &kinds {
                let key = Self::list_key(c, *k);
                let stale = self
                    .lists
                    .get(&key)
                    .and_then(|s| s.fetched)
                    .map(|t| t.elapsed() >= refresh_every)
                    .unwrap_or(true);
                // Something refused isn't asked for again by itself.
                if force || (stale && !self.refused(c, *k)) {
                    self.fetch_list(c, *k);
                }
            }
            if metrics {
                let stale = self
                    .metrics
                    .get(c)
                    .map(|m| !m.loading && m.fetched.map(|t| t.elapsed() >= metrics_every).unwrap_or(true))
                    .unwrap_or(true);
                if force || stale {
                    if let Some(m) = self.metrics.get_mut(c).filter(|_| force) {
                        m.nodes_refused = false;
                    }
                    self.fetch_metrics(c);
                }
            }
        }
    }

    /// CPU and memory usage from `kubectl top` (needs the cluster's metrics API).
    fn fetch_metrics(&mut self, ctx: &str) {
        if self.demo {
            return;
        }
        let m = self.metrics.entry(ctx.to_string()).or_default();
        if m.loading {
            return;
        }
        m.loading = true;
        let skip_nodes = m.nodes_refused;
        let ctx = ctx.to_string();
        let fallback_ns = self.default_ns(&ctx);
        let limited = self.prefs.ctx_namespaces.get(&ctx).cloned();
        let known = self.namespaces.get(&ctx).cloned().unwrap_or_default();
        self.spawn(move |k| {
            let base = |what: &str| -> Vec<String> {
                vec!["--context".into(), ctx.clone(), "top".into(), what.into(), "--no-headers".into(), format!("--request-timeout={}", kube::REQUEST_TIMEOUT)]
            };
            let mut pa = base("pods");
            pa.push("--all-namespaces".into());
            let mut pods = match &limited {
                // Limited to some namespaces: read each, written as "namespace name cpu memory".
                Some(patterns) => expand_namespaces(k, &ctx, patterns, &known).and_then(|names| top_in_namespaces(k, &ctx, &names)).map(|o| (o, true)),
                None => k.run(&pa).map(|o| (o, true)),
            };
            if let Err(e) = &pods {
                if e.contains("forbidden") || e.contains("Forbidden") {
                    // Each namespace this account can see, else the context's own one.
                    let visible = visible_namespaces(k, &ctx).ok().filter(|v| !v.is_empty());
                    pods = match visible {
                        Some(mut names) => {
                            names.truncate(60);
                            top_in_namespaces(k, &ctx, &names).map(|o| (o, true))
                        }
                        None => {
                            let mut pa = base("pods");
                            pa.extend(["-n".to_string(), fallback_ns.clone()]);
                            k.run(&pa).map(|o| (o, false))
                        }
                    };
                }
            }
            let nodes = if skip_nodes { Err(String::new()) } else { k.run(&base("nodes")) };
            let text = serde_json::json!({
                "pods": pods.as_ref().map(|p| p.0.clone()).unwrap_or_default(),
                "pods_all": pods.as_ref().map(|p| p.1).unwrap_or(false),
                "pods_ns": fallback_ns,
                "nodes": nodes.as_ref().cloned().unwrap_or_default(),
                "error": pods.as_ref().err(),
                "nodes_refused": skip_nodes || nodes.as_ref().err().map(|e| is_refusal(e)).unwrap_or(false),
            });
            Msg::Text { key: format!("top|{ctx}"), result: Ok(text.to_string()) }
        });
    }

    fn handle_messages(&mut self) {
        while let Ok(m) = self.rx.try_recv() {
            match m {
                Msg::Contexts(r) => {
                    self.contexts_loading = false;
                    match r {
                        Ok((list, current)) => {
                            self.contexts = list;
                            self.contexts_error = None;
                            // The start screen pre-selects the contexts used last time.
                            self.current_context = current;
                            // (A screenshot starts empty, unless KUBEDOG_SHOT_RESUME tests carrying on.)
                            let resume_test = std::env::var("KUBEDOG_SHOT_RESUME").is_ok();
                            let saved = if self.screenshot.is_some() && !resume_test { vec![] } else { self.prefs.contexts.clone() };
                            self.picker = saved
                                .into_iter()
                                .filter(|n| self.contexts.iter().any(|c| &c.name == n))
                                .collect();
                            if self.contexts.is_empty() {
                                self.contexts_error = Some("Your kubeconfig has no contexts.".into());
                            }
                            // "Reconnect": open the clusters used last time (never in screenshot mode).
                            // A cluster that can't be reached shows its error on the page; the
                            // context button in the sidebar goes back to the start page.
                            if !self.startup_done && (self.screenshot.is_none() || resume_test) && self.prefs.startup == "reconnect" && !self.picker.is_empty() {
                                self.connect();
                            }
                            self.startup_done = true;
                        }
                        Err(e) => self.contexts_error = Some(e),
                    }
                }
                Msg::List { key, result, rows } => {
                    let kind = kind_from_key(&key);
                    let ctx = key.split('|').nth(1).unwrap_or("").to_string();
                    let watched = ctx.clone();
                    let st = self.lists.entry(key).or_default();
                    st.loading = false;
                    st.gen += 1;
                    st.fetched = Some(Instant::now());
                    match result {
                        Ok(items) => {
                            st.error = None;
                            if let Some(kind) = kind {
                                st.rows = match rows.and_then(|b| b.downcast::<Vec<Row>>().ok()) {
                                    Some(r) => *r,
                                    None => items.iter().map(|o| make_row(kind, o)).collect(),
                                };
                                if kind == Kind::Namespaces {
                                    let mut names: Vec<String> = st.rows.iter().map(|r| r.name.clone()).collect();
                                    names.sort();
                                    self.namespaces.insert(ctx, names);
                                }
                            }
                            st.items = items;
                        }
                        Err(e) => st.error = Some(e),
                    }
                    if let Some(k) = kind {
                        self.watch_list(&watched, k);
                        if k == Kind::Deployments || k == Kind::Nodes {
                            self.companion_look(&watched);
                        }
                    }
                }
                Msg::Grafana { ctx, binding, what } => {
                    if let Ok(what) = what.downcast::<grafana::Answer>() {
                        self.on_grafana(&ctx, &binding, *what);
                        self.refresh_grafana(false);
                    }
                }
                Msg::Text { key, result } if self.on_cluster_text(&key, &result) => {}
                Msg::Text { key, result } if self.on_custom_text(&key, &result) => {}
                Msg::Text { key, result } if self.on_pg_text(&key, &result) => {}
                Msg::Text { key, result } if self.on_served(&key, &result) => {}
                Msg::Text { key, result } if self.on_rights(&key, &result) => {}
                Msg::Text { key, result } if self.on_pod(&key, &result) => {}
                Msg::Text { key, result } if self.on_powers(&key, &result) => {}
                Msg::Text { key, result } if self.on_ai(&key, &result) => {}
                Msg::Text { key, result } if self.on_proxmox(&key, &result) => {}
                Msg::Text { key, result } if self.on_trace(&key, &result) => {}
                Msg::Text { key, result } if self.on_packets(&key, &result) => {}
                Msg::Text { key, result } if self.on_tried(&key, &result) => {}
                Msg::Text { key, result } if self.on_nettest(&key, &result) => {}
                Msg::Text { key, result } => {
                    if let Some(ctx) = key.strip_prefix("pvcstats|") {
                        let ctx = ctx.to_string();
                        self.on_claim_stats(&ctx, result);
                    } else if key.starts_with("cert|") {
                        self.on_cert(key, result);
                    } else if let Some(ctx) = key.strip_prefix("top|") {
                        let m = self.metrics.entry(ctx.to_string()).or_default();
                        m.loading = false;
                        m.gen += 1;
                        m.fetched = Some(Instant::now());
                        if let Ok(v) = result.as_deref().map(|t| serde_json::from_str::<Value>(t).unwrap_or_default()) {
                            m.error = v["error"].as_str().map(String::from);
                            m.nodes_refused = v["nodes_refused"].as_bool().unwrap_or(false);
                            let all = v["pods_all"].as_bool().unwrap_or(false);
                            let ns = v["pods_ns"].as_str().unwrap_or("").to_string();
                            let mut pods = HashMap::new();
                            for line in v["pods"].as_str().unwrap_or("").lines() {
                                let f: Vec<&str> = line.split_whitespace().collect();
                                let (pns, name, cpu, mem) = if all && f.len() >= 4 {
                                    (f[0].to_string(), f[1], f[2], f[3])
                                } else if !all && f.len() >= 3 {
                                    (ns.clone(), f[0], f[1], f[2])
                                } else {
                                    continue;
                                };
                                pods.insert((pns, name.to_string()), (resources::cpu_milli(cpu), resources::mem_bytes(mem)));
                            }
                            let mut nodes = HashMap::new();
                            for line in v["nodes"].as_str().unwrap_or("").lines() {
                                let f: Vec<&str> = line.split_whitespace().collect();
                                if f.len() >= 4 {
                                    nodes.insert(f[0].to_string(), (resources::cpu_milli(f[1]), resources::mem_bytes(f[3])));
                                }
                            }
                            if !pods.is_empty() {
                                m.reading += 1;
                                let n = m.reading;
                                m.times.push_back((n, kube::now_secs()));
                                while m.times.len() > nodeview::NODE_HISTORY {
                                    m.times.pop_front();
                                }
                                for (k, u) in &pods {
                                    let h = m.pod_hist.entry(k.clone()).or_default();
                                    h.push_back((n, u.0 as f32, u.1 as f32));
                                    while h.len() > nodeview::NODE_HISTORY {
                                        h.pop_front();
                                    }
                                }
                                m.pod_hist.retain(|k, _| pods.contains_key(k));
                            }
                            if !pods.is_empty() || m.error.is_some() {
                                m.pods = pods;
                            }
                            if !nodes.is_empty() {
                                for (n, u) in &nodes {
                                    let h = m.node_hist.entry(n.clone()).or_default();
                                    h.push_back(*u);
                                    while h.len() > nodeview::NODE_HISTORY {
                                        h.pop_front();
                                    }
                                }
                                m.nodes = nodes;
                            }
                        }
                    } else if key.starts_with("yaml|") {
                        self.yaml.insert(key, (false, result));
                    } else if key.starts_with("events|") {
                        let r = result.and_then(|j| kube::parse_items(&j));
                        self.events.insert(key, (false, r));
                    } else if key.starts_with("helm|") {
                        let r = result.and_then(|j| {
                            serde_json::from_str::<Value>(&j)
                                .map(|v| v.as_array().cloned().unwrap_or_default())
                                .map_err(|e| e.to_string())
                        });
                        self.helm.insert(key, (false, r));
                    }
                }
                Msg::ActionDone { what, result } => {
                    self.busy = self.busy.saturating_sub(1);
                    match result {
                        Ok(out) => {
                            let out = out.trim();
                            self.toast(if out.is_empty() { what } else { format!("{what}: {out}") }, false);
                            self.refresh_current(true);
                            if let Some(sel) = self.selected.clone() {
                                self.fetch_yaml(&sel);
                            }
                        }
                        Err(e) => {
                            self.toast(format!("{what} failed: {e}"), true);
                            // Part of it may have been done.
                            self.refresh_current(true);
                        }
                    }
                }
                Msg::StreamLine { id, line, err } => {
                    if let Some(l) = self.log.as_mut().filter(|l| l.id == id) {
                        l.lines.push(LogLine::new(line, err));
                        if l.lines.len() > MAX_LOG_LINES {
                            let cut = MAX_LOG_LINES / 10;
                            l.lines.drain(0..cut);
                            l.dropped += cut;
                        }
                    } else if let Some(pf) = self.port_forwards.iter_mut().find(|p| p.id == id) {
                        if line.starts_with("Forwarding from") {
                            if pf.status != "Active" && pf.open_browser {
                                let _ = std::process::Command::new("/usr/bin/open").arg(format!("http://localhost:{}", pf.local)).spawn();
                            }
                            pf.status = "Active".into();
                        } else if err {
                            pf.status = "Error".into();
                        }
                        pf.output.push(line);
                        if pf.output.len() > 200 {
                            pf.output.remove(0);
                        }
                    }
                }
                Msg::StreamEnded { id } => {
                    if let Some(l) = self.log.as_mut().filter(|l| l.id == id) {
                        l.running = false;
                    } else if let Some(pf) = self.port_forwards.iter_mut().find(|p| p.id == id) {
                        if pf.status != "Error" {
                            pf.status = "Stopped".into();
                        }
                        pf.child = None;
                    }
                }
            }
        }
    }

    fn toast(&mut self, text: String, error: bool) {
        self.toasts.push(Toast { text, error, at: Instant::now() });
    }

    // ---------------- actions ----------------

    fn request(&mut self, action: Action, title: String, body: String, button: &str, danger: bool) {
        if self.demo {
            self.toast("Demo data: actions are turned off.".into(), true);
            return;
        }
        if !self.unlocked.contains(action.ctx()) {
            self.dialog = Some(Dialog::Protected { ctx: action.ctx().to_string() });
            return;
        }
        self.dialog = Some(Dialog::Confirm { title, body, button: button.into(), danger, action });
    }

    /// A node's page; without the right to read nodes, what's known of it from the pods.
    fn open_node(&mut self, ctx: &str, node: &str) {
        if self.refused(ctx, Kind::Nodes) {
            self.open_hive(Some(node.to_string()));
        } else {
            self.navigate(View::Resource(Kind::Nodes), Some(Selected { ctx: ctx.into(), kind: Kind::Nodes, ns: String::new(), name: node.into() }));
        }
    }

    fn ask_restart(&mut self, sel: &Selected) {
        let body = format!("Restart all pods of {} “{}”? They are replaced one by one (rollout restart).", sel.kind.singular(), sel.name);
        self.request(Action::Restart(sel.clone()), "Restart".into(), body, "Restart", false);
    }

    fn ask_delete(&mut self, sel: &Selected) {
        if self.demo {
            self.toast("Demo data: actions are turned off.".into(), true);
        } else if !self.unlocked.contains(&sel.ctx) {
            self.dialog = Some(Dialog::Protected { ctx: sel.ctx.clone() });
        } else {
            self.dialog = Some(Dialog::Delete { sel: sel.clone(), force: false, orphan: false, advanced: false });
        }
    }

    /// Pods on a node that block a drain unless an option is ticked:
    /// (pods with emptyDir volumes, pods with no controller).
    /// DaemonSet pods, mirror pods and finished pods don't count.
    fn drain_blockers(&self, ctx: &str, node: &str) -> Option<(Vec<String>, Vec<String>)> {
        let l = self.lists.get(&Self::list_key(ctx, Kind::Pods))?;
        l.fetched?;
        let mut emptydir = vec![];
        let mut unmanaged = vec![];
        for o in &l.items {
            if o["spec"]["nodeName"].as_str() != Some(node) {
                continue;
            }
            let phase = o["status"]["phase"].as_str().unwrap_or("");
            if phase == "Succeeded" || phase == "Failed" {
                continue;
            }
            if o["metadata"]["annotations"]["kubernetes.io/config.mirror"].is_string() {
                continue;
            }
            let owner = o["metadata"]["ownerReferences"]
                .as_array()
                .and_then(|a| a.iter().find(|r| r["controller"].as_bool() == Some(true)).cloned());
            if owner.as_ref().map(|r| r["kind"] == "DaemonSet").unwrap_or(false) {
                continue;
            }
            let name = format!("{}/{}", o["metadata"]["namespace"].as_str().unwrap_or(""), o["metadata"]["name"].as_str().unwrap_or(""));
            if owner.is_none() {
                unmanaged.push(name.clone());
            }
            let has_emptydir = o["spec"]["volumes"].as_array().map(|v| v.iter().any(|x| x["emptyDir"].is_object())).unwrap_or(false);
            if has_emptydir {
                emptydir.push(name);
            }
        }
        Some((emptydir, unmanaged))
    }

    fn run_action(&mut self, action: Action) {
        // Pictures never change anything, whatever is clicked in them.
        if self.screenshot.is_some() {
            return;
        }
        if let Action::DeleteRaw { ctx, resource, ns, name } = &action {
            let mut args = vec!["--context".to_string(), ctx.clone(), "delete".into(), resource.clone(), name.clone(), "--wait=false".into()];
            if let Some(n) = ns {
                args.extend(["-n".to_string(), n.clone()]);
            }
            let what = format!("{resource} {} is being deleted", name);
            self.custom_sel = None;
            self.spawn(move |k| Msg::ActionDone { what, result: k.run(&args) });
            return;
        }
        if let Action::NetTry { tries } = action {
            self.start_tries(tries);
            return;
        }
        if let Action::Many { ctx, what, verb, items } = &action {
            self.start_many(ctx, what, *verb, items);
            return;
        }
        if let Action::Grab { grab } = action {
            self.start_grab(*grab);
            return;
        }
        if let Action::OvnTrace { ask } = action {
            self.start_trace(*ask);
            return;
        }
        self.busy += 1;
        match action {
            Action::DeleteRaw { .. } | Action::NetTry { .. } | Action::OvnTrace { .. } | Action::Grab { .. } | Action::Many { .. } => {}
            Action::Create { sel, manifest, what } => {
                let args: Vec<String> = ["--context", &sel.ctx, "create", "-f", "-"].iter().map(|x| x.to_string()).collect();
                self.spawn(move |k| Msg::ActionDone { what, result: k.run_with_input(&args, &manifest) })
            }
            Action::Run { args, what, .. } => self.spawn(move |k| Msg::ActionDone { what, result: k.run(&args) }),
            Action::Cnpg { args, what, .. } => self.spawn(move |k| Msg::ActionDone { what, result: k.run(&args) }),
            Action::Rollback(s, rev) => {
                let what = format!("Rolling back to revision {rev}");
                let args = vec![
                    "--context".to_string(),
                    s.ctx.clone(),
                    "-n".into(),
                    s.ns.clone(),
                    "rollout".into(),
                    "undo".into(),
                    format!("{}/{}", s.kind.resource(), s.name),
                    format!("--to-revision={rev}"),
                ];
                self.spawn(move |k| Msg::ActionDone { what, result: k.run(&args) });
            }
            Action::Delete(s, force, orphan) => {
                let what = format!("Deleting {} {}", s.kind.singular(), s.name);
                let args = delete_args(&s, force, orphan);
                if self.selected.as_ref() == Some(&s) {
                    self.close_detail();
                }
                self.spawn(move |k| Msg::ActionDone { what, result: k.run(&args) });
            }
            Action::Restart(s) => {
                let what = format!("Restarting {} {}: its pods are replaced one after another", s.kind.singular(), s.name);
                let args = restart_args(&s);
                self.spawn(move |k| Msg::ActionDone { what, result: k.run(&args) });
            }
            Action::Scale(s, n) => {
                let what = format!("Scaled {} to {n}", s.name);
                let mut args = vec!["--context".into(), s.ctx.clone(), "scale".into(), format!("{}/{}", s.kind.resource(), s.name), format!("--replicas={n}")];
                args.extend(s.ns_args());
                self.spawn(move |k| Msg::ActionDone { what, result: k.run(&args) });
            }
            Action::Cordon(s, on) => {
                let verb = if on { "cordon" } else { "uncordon" };
                let what = format!("{} {}", if on { "Cordoned" } else { "Uncordoned" }, s.name);
                let args = vec!["--context".into(), s.ctx.clone(), verb.into(), s.name.clone()];
                self.spawn(move |k| Msg::ActionDone { what, result: k.run(&args) });
            }
            Action::Drain(s, delete_emptydir, disable_eviction, force) => {
                let what = format!("Drained {}", s.name);
                let args = drain_args(&s, delete_emptydir, disable_eviction, force);
                self.spawn(move |k| Msg::ActionDone { what, result: k.run(&args) });
            }
            Action::Patch(s, patch) => {
                let what = format!("Saved {}", s.name);
                let mut args = vec!["--context".into(), s.ctx.clone(), "patch".into(), s.kind.resource().into(), s.name.clone(), "--type".into(), "merge".into(), "-p".into(), patch];
                args.extend(s.ns_args());
                self.data_edit = None;
                self.spawn(move |k| Msg::ActionDone { what, result: k.run(&args) });
            }
            Action::Apply(s, yaml) => {
                let what = format!("Applied changes to {}", s.name);
                let args = vec!["--context".into(), s.ctx.clone(), "apply".into(), "-f".into(), "-".into()];
                self.yaml_edit = None;
                self.spawn(move |k| Msg::ActionDone { what, result: k.run_with_input(&args, &yaml) });
            }
            Action::HelmUninstall { ctx, ns, name } => {
                let what = format!("Uninstalled release {name}");
                if let Some(h) = self.helm.get_mut(&format!("helm|{ctx}")) {
                    h.0 = false;
                }
                let args = vec!["uninstall".into(), name, "-n".into(), ns, "--kube-context".into(), ctx];
                self.spawn(move |k| Msg::ActionDone { what, result: k.run_helm(&args) });
            }
        }
    }

    fn open_shell(&mut self, sel: &Selected, container: &str) {
        if self.demo {
            self.toast("Demo data: shells are turned off.".into(), true);
            return;
        }
        let Some((program, mut first)) = self.kubectl.program() else { return };
        let mut cmd = String::new();
        if let Some(kc) = &self.kubectl.kubeconfig {
            cmd.push_str(&format!("KUBECONFIG={} ", sh_quote(kc)));
        }
        let windows = self
            .selected_object()
            .map(|o| o["spec"]["nodeSelector"]["kubernetes.io/os"] == "windows")
            .unwrap_or(false);
        let mut args: Vec<String> = vec!["--context".into(), sel.ctx.clone(), "exec".into(), "-n".into(), sel.ns.clone(), sel.name.clone()];
        if !container.is_empty() {
            args.push("-c".into());
            args.push(container.to_string());
        }
        args.extend(["--stdin".to_string(), "--tty".to_string(), "--".to_string()]);
        args.extend(shell_program(windows).iter().map(|x| x.to_string()));
        let _ = cmd;
        let mut title = format!("{}/{}", sel.ns, if container.is_empty() { sel.name.clone() } else { format!("{} ({container})", sel.name) });
        if self.active.len() > 1 {
            title = format!("{} · {title}", ctx_label(&sel.ctx));
        }
        first.extend(args);
        self.run_in_terminal(title, &program, first, None);
    }

    /// Run a command in the terminal chosen in Settings (built-in or a Mac app).
    fn run_in_terminal(&mut self, title: String, program: &str, args: Vec<String>, input: Option<String>) {
        let mut env: Vec<(String, String)> = vec![];
        if let Some(kc) = &self.kubectl.kubeconfig {
            env.push(("KUBECONFIG".into(), kc.clone()));
        }
        let app = self.prefs.terminal.clone();
        if app == "builtin" {
            let path = std::env::var("PATH").unwrap_or_default();
            let extra = self.kubectl.bin.as_ref().and_then(|b| b.parent()).map(|d| d.to_string_lossy().to_string()).unwrap_or_default();
            let cnpg = self.kubectl.cnpg.as_ref().and_then(|b| b.parent()).map(|d| d.to_string_lossy().to_string()).unwrap_or_default();
            env.push(("PATH".into(), format!("{extra}:{cnpg}:/opt/homebrew/bin:/usr/local/bin:{path}")));
            let ctx = self.egui_ctx.clone();
            match self.term.spawn(title.clone(), program, &args, &env, input, &ctx) {
                Ok(()) => {}
                Err(e) => self.toast(format!("Could not start the built-in terminal: {e}"), true),
            }
            return;
        }
        let mut cmd = String::new();
        for (k, v) in &env {
            cmd.push_str(&format!("export {k}={}; ", sh_quote(v)));
        }
        cmd.push_str(&sh_quote(program));
        for a in &args {
            cmd.push(' ');
            cmd.push_str(&sh_quote(a));
        }
        if let Some(i) = input {
            // External apps get the extra input as commands run first.
            cmd = format!("{} {}", i.trim_end_matches('\n').replace('\n', "; "), if args.is_empty() && program.ends_with("zsh") { String::new() } else { format!("; {cmd}") });
        }
        if !terminal::installed(&app) {
            self.toast(format!("{app} isn't installed; choose another terminal in Settings."), true);
            return;
        }
        match terminal::launch_external(&app, &cmd) {
            Ok(()) => self.toast(format!("Opened {title} in {app}"), false),
            Err(e) => self.toast(e, true),
        }
    }

    /// A local shell with kubectl pointed at one context (the overview's ">_" button).
    fn open_context_shell(&mut self, ctx: &str) {
        let Some(bin) = self.kubectl.bin.clone() else { return };
        let alias = format!("alias kubectl={}", sh_quote(&format!("{} --context {}", sh_quote(&bin.to_string_lossy()), sh_quote(ctx))));
        if self.prefs.terminal == "builtin" {
            let input = format!("{alias}; clear; kubectl config get-contexts {}\n", sh_quote(ctx));
            // macOS: zsh, its own shell. Elsewhere: the person's shell.
            let shell = if cfg!(target_os = "macos") { "/bin/zsh".to_string() } else { std::env::var("SHELL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "/bin/sh".into()) };
            self.run_in_terminal(ctx_label(ctx), &shell, vec!["-il".into()], Some(input));
        } else {
            let mut cmd = String::new();
            if let Some(kc) = &self.kubectl.kubeconfig {
                cmd.push_str(&format!("export KUBECONFIG={}; ", sh_quote(kc)));
            }
            cmd.push_str(&format!("{alias}; kubectl config get-contexts {}; exec /bin/zsh -il", sh_quote(ctx)));
            let app = self.prefs.terminal.clone();
            if let Err(e) = terminal::launch_external(&app, &format!("/bin/zsh -ilc {}", sh_quote(&cmd))) {
                self.toast(e, true);
            }
        }
    }

    fn start_port_forward(&mut self, sel: &Selected, local: u16, remote: u16, open_browser: bool) {
        let id = self.next_id;
        self.next_id += 1;
        let prefix = if sel.kind == Kind::Services { "svc" } else { "pod" };
        let target = format!("{prefix}/{}", sel.name);
        let args = vec![
            "--context".into(),
            sel.ctx.clone(),
            "-n".into(),
            sel.ns.clone(),
            "port-forward".into(),
            "--address".into(),
            // Both 127.0.0.1 and [::1].
            "localhost".into(),
            target.clone(),
            format!("{local}:{remote}"),
        ];
        let rp = {
            let c = self.egui_ctx.clone();
            move || c.request_repaint()
        };
        let child = self.kubectl.spawn_stream(&args, id, self.tx.clone(), rp);
        let (child, status) = match child {
            Ok(c) => (Some(c), "Starting".to_string()),
            Err(e) => (None, format!("Error: {e}")),
        };
        self.port_forwards.push(PortForward {
            id,
            ctx: sel.ctx.clone(),
            ns: sel.ns.clone(),
            target,
            local,
            remote,
            child,
            status,
            output: vec![],
            open_browser,
        });
        self.toast(format!("Forwarding localhost:{local} to {}:{remote}", sel.name), false);
    }

    fn stop_logs(&mut self) {
        if let Some(mut l) = self.log.take() {
            if let Some(mut c) = l.child.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    fn start_logs(&mut self, sel: &Selected) {
        self.stop_logs();
        let id = self.next_id;
        self.next_id += 1;
        let p = &self.log_prefs;
        let mut args: Vec<String> = vec!["--context".into(), sel.ctx.clone(), "-n".into(), sel.ns.clone(), "logs".into()];
        let mut problem: Option<String> = None;
        if sel.kind == Kind::Pods {
            args.push(sel.name.clone());
        } else {
            // A workload: every pod its selector picks (up to 20 at once), each line prefixed with its pod.
            match self.object_of(sel).as_ref().and_then(workload_selector) {
                Some(l) => {
                    args.push("-l".into());
                    args.push(l);
                    args.push("--max-log-requests=20".into());
                    if !p.container.is_empty() {
                        args.push("--prefix".into());
                    }
                }
                None => problem = Some(format!("Couldn't work out which pods belong to {} “{}”.", sel.kind.singular(), sel.name)),
            }
        }
        if p.container.is_empty() {
            args.push("--all-containers".into());
            args.push("--prefix".into());
        } else {
            args.push("-c".into());
            args.push(p.container.clone());
        }
        match p.since {
            NEW_LINES => args.push("--tail=0".into()),
            EVERYTHING => args.push("--tail=-1".into()),
            other => args.push(format!("--since={}", kubectl_since(other))),
        }
        if p.follow && !p.previous && self.screenshot.is_none() {
            args.push("-f".into());
        }
        if p.timestamps {
            args.push("--timestamps".into());
        }
        if p.previous {
            args.push("--previous".into());
        }
        let target = sel.key();
        if self.demo {
            self.log = Some(LogState {
                id,
                target,
                child: None,
                lines: demo_logs(),
                dropped: 0,
                running: false,
            });
            return;
        }
        let rp = {
            let c = self.egui_ctx.clone();
            move || c.request_repaint()
        };
        if let Some(e) = problem {
            self.log = Some(LogState { id, target, child: None, lines: vec![LogLine::new(e, true)], running: false, dropped: 0 });
            return;
        }
        let (child, lines) = match self.kubectl.spawn_stream(&args, id, self.tx.clone(), rp) {
            Ok(c) => (Some(c), vec![]),
            Err(e) => (None, vec![LogLine::new(e, true)]),
        };
        let running = child.is_some();
        self.log = Some(LogState { id, target, child, lines, running, dropped: 0 });
    }

    /// Open an object's page, remembering where we came from (Back / ⌘←).
    fn select(&mut self, sel: Selected) {
        self.navigate(self.view, Some(sel));
    }

    fn close_object(&mut self) {
        self.close_detail();
    }

    fn open_object(&mut self, sel: Selected) {
        if self.selected.as_ref() == Some(&sel) {
            return;
        }
        self.stop_logs();
        self.yaml_edit = None;
        self.reveal_secrets = false;
        self.log_prefs.container.clear();
        self.log_prefs.previous = false;
        self.env_filter.clear();
        self.pod.reset();
        if self.tab == Tab::Logs && !sel.kind.has_logs() {
            self.tab = Tab::Overview;
        }
        self.fetch_yaml(&sel);
        self.fetch_events(&sel);
        self.selected = Some(sel.clone());
        if self.tab == Tab::Logs {
            self.start_logs(&sel);
        }
    }

    fn close_detail(&mut self) {
        self.stop_logs();
        self.pod.reset();
        self.selected = None;
        self.yaml_edit = None;
    }

    /// The object a selection points at, from the loaded lists.
    fn object_of(&self, s: &Selected) -> Option<Value> {
        let l = self.lists.get(&Self::list_key(&s.ctx, s.kind))?;
        l.items
            .iter()
            .find(|o| {
                o["metadata"]["name"].as_str() == Some(&s.name)
                    && (!s.kind.namespaced() || o["metadata"]["namespace"].as_str() == Some(&s.ns))
            })
            .cloned()
    }

    fn selected_object(&self) -> Option<Value> {
        let s = self.selected.as_ref()?;
        let l = self.lists.get(&Self::list_key(&s.ctx, s.kind))?;
        l.items
            .iter()
            .find(|o| {
                o["metadata"]["name"].as_str() == Some(&s.name)
                    && (!s.kind.namespaced() || o["metadata"]["namespace"].as_str() == Some(&s.ns))
            })
            .cloned()
    }

    fn set_view(&mut self, v: View) {
        if self.view != v || self.selected.is_some() {
            self.navigate(v, None);
        }
    }

    fn toggle_context(&mut self, name: &str) {
        if let Some(i) = self.active.iter().position(|n| n == name) {
            if self.active.len() > 1 {
                self.active.remove(i);
            }
        } else {
            self.active.push(name.to_string());
        }
        if let Some(s) = &self.selected {
            if !self.active.contains(&s.ctx) {
                self.close_detail();
            }
        }
        if self.screenshot.is_none() {
            self.prefs.contexts = self.active.clone();
            self.save();
        }
        self.refresh_current(false);
    }

    // ---------------- demo data (no kubectl on this computer) ----------------

    /// Show the sample cluster (asked for on the start page when kubectl is missing).
    pub(crate) fn enter_demo(&mut self) {
        self.demo = true;
        self.load_demo();
    }

    /// Away with the sample cluster and everything read from it.
    pub(crate) fn leave_demo(&mut self) {
        self.demo = false;
        self.contexts.clear();
        self.active.clear();
        self.picker.clear();
        self.lists.retain(|k, _| !k.contains("demo-cluster"));
        self.namespaces.remove("demo-cluster");
        self.contexts_error = None;
        self.connected = false;
    }

    /// Look for kubectl once more: where programs are usually found, then at the path that was typed.
    pub(crate) fn find_kubectl_again(&mut self) {
        let mut found = Kubectl::detect();
        let typed = self.kubectl_typed.trim().trim_matches('"').to_string();
        if found.bin.is_none() && !typed.is_empty() {
            let mut p = std::path::PathBuf::from(&typed);
            if p.is_dir() {
                let (k, o) = if cfg!(windows) { ("kubectl.exe", "oc.exe") } else { ("kubectl", "oc") };
                p = if p.join(k).is_file() { p.join(k) } else { p.join(o) };
            }
            if p.is_file() {
                self.prefs.kubectl_path = p.to_string_lossy().to_string();
                save_prefs(&self.prefs);
                found.bin = Some(p);
            }
        }
        if found.bin.is_none() {
            let what = if typed.is_empty() { "kubectl still wasn't found.".to_string() } else { format!("There's no kubectl at {typed}.") };
            self.toast(what, true);
            return;
        }
        if self.demo {
            self.leave_demo();
        }
        self.kubectl.bin = found.bin;
        self.kubectl.helm = found.helm;
        self.kubectl.cnpg = found.cnpg;
        self.apply_kubeconfigs();
        self.load_contexts();
    }

    fn load_demo(&mut self) {
        self.contexts_loading = false;
        self.contexts = vec![
            ContextInfo { name: "demo-cluster".into(), cluster: "demo".into(), user: "demo".into(), namespace: "default".into(), server: "https://127.0.0.1:6443".into(), source: "sample data".into() },
        ];
        self.active = vec!["demo-cluster".into()];
        self.contexts_error = Some("Sample data: this cluster isn't real, and nothing can be changed.".into());
        for kind in GROUPS.iter().flat_map(|g| g.1.iter().copied()) {
            let items = demo_items(kind);
            let rows = items.iter().map(|o| make_row(kind, o)).collect();
            self.lists.insert(
                Self::list_key("demo-cluster", kind),
                ListState { gen: 1, loading: false, error: None, items, rows, fetched: Some(Instant::now()), note: None },
            );
        }
        self.namespaces.insert("demo-cluster".into(), vec!["default".into(), "kube-system".into(), "shop".into()]);
    }
}

// ---------------- rows ----------------

/// A padlock, drawn (no font's lock reads well this small): closed, or with its shackle swung open.
fn padlock(p: &egui::Painter, c: egui::Pos2, h: f32, locked: bool, colour: Color32) {
    let w = h * 0.78;
    let body = egui::Rect::from_min_max(egui::pos2(c.x - w / 2.0, c.y - h * 0.06), egui::pos2(c.x + w / 2.0, c.y + h / 2.0));
    p.rect_filled(body, CornerRadius::same((h * 0.14).round().max(1.0) as u8), colour);
    // The shackle: two legs and half a circle. Open, it stands higher and its right leg is off the body.
    let r = w * 0.30;
    let top = if locked { c.y - h / 2.0 + r } else { c.y - h / 2.0 + r - h * 0.14 };
    let mut l = vec![egui::pos2(c.x - r, body.top())];
    l.extend((0..=12).map(|i| {
        let a = std::f32::consts::PI * (1.0 - i as f32 / 12.0);
        egui::pos2(c.x + r * a.cos(), top - r * a.sin())
    }));
    l.push(egui::pos2(c.x + r, if locked { body.top() } else { top + h * 0.10 }));
    p.add(egui::Shape::line(l, Stroke::new((h * 0.13).max(1.2), colour)));
}

/// A small round icon button: a soft disc on hover, the glyph in the accent colour.
thread_local! {
    /// Icon buttons drawn as buttons, with a frame (the Controls column of a list).
    static FRAMED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Icon buttons drawn inside `f` get a frame of their own.
fn framed<R>(f: impl FnOnce() -> R) -> R {
    FRAMED.with(|x| x.set(true));
    let r = f();
    FRAMED.with(|x| x.set(false));
    r
}

fn icon_button(ui: &mut Ui, draw: impl FnOnce(&egui::Painter, egui::Rect, Color32)) -> egui::Response {
    let (r, resp) = ui.allocate_exact_size(egui::vec2(26.0, 24.0), Sense::click());
    let hot = resp.hovered();
    let p = ui.painter();
    let disc = egui::Rect::from_center_size(r.center(), egui::vec2(24.0, 22.0));
    if FRAMED.with(|x| x.get()) {
        p.rect(disc, CornerRadius::same(6), if hot { PRIMARY_TEXT().gamma_multiply(0.16) } else { BG_MUTED() }, Stroke::new(1.0, if hot { PRIMARY_TEXT().gamma_multiply(0.6) } else { BORDER_DEFAULT() }), egui::StrokeKind::Inside);
    } else if hot {
        p.rect_filled(disc, CornerRadius::same(6), PRIMARY_TEXT().gamma_multiply(0.16));
    }
    if hot {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    draw(p, egui::Rect::from_center_size(r.center(), egui::vec2(14.0, 14.0)), if hot { PRIMARY_TEXT() } else if FRAMED.with(|x| x.get()) { TEXT_MUTED() } else { TEXT_SUBTLE() });
    resp
}

/// Logs: a sheet with a folded corner and lines of text of different lengths.
fn logs_icon_button(ui: &mut Ui) -> egui::Response {
    icon_button(ui, |p, r, col| {
        let s = Stroke::new(1.3, col);
        let (l, t, rr, b) = (r.left() + 1.5, r.top(), r.right() - 1.5, r.bottom());
        let fold = 3.5;
        p.add(egui::Shape::closed_line(
            vec![egui::pos2(l, t), egui::pos2(rr - fold, t), egui::pos2(rr, t + fold), egui::pos2(rr, b), egui::pos2(l, b)],
            s,
        ));
        p.line_segment([egui::pos2(rr - fold, t), egui::pos2(rr - fold, t + fold)], Stroke::new(1.0, col));
        p.line_segment([egui::pos2(rr - fold, t + fold), egui::pos2(rr, t + fold)], Stroke::new(1.0, col));
        for (i, w) in [6.5f32, 4.5, 7.0].iter().enumerate() {
            let y = t + 5.2 + i as f32 * 2.9;
            p.line_segment([egui::pos2(l + 2.5, y), egui::pos2(l + 2.5 + w, y)], Stroke::new(1.2, col));
        }
    })
}

/// Shell: a terminal window with a prompt.
fn shell_icon_button(ui: &mut Ui) -> egui::Response {
    icon_button(ui, |p, r, col| {
        let s = Stroke::new(1.3, col);
        let w = egui::Rect::from_min_max(egui::pos2(r.left(), r.top() + 1.0), egui::pos2(r.right(), r.bottom() - 1.0));
        p.rect_stroke(w, CornerRadius::same(2), s, egui::StrokeKind::Inside);
        let (x, y) = (w.left() + 3.0, w.center().y);
        p.line_segment([egui::pos2(x, y - 2.5), egui::pos2(x + 2.8, y)], Stroke::new(1.4, col));
        p.line_segment([egui::pos2(x + 2.8, y), egui::pos2(x, y + 2.5)], Stroke::new(1.4, col));
        p.line_segment([egui::pos2(x + 4.5, y + 2.8), egui::pos2(x + 8.0, y + 2.8)], Stroke::new(1.4, col));
    })
}

/// One column of a list's table.
#[derive(Clone, Copy, PartialEq)]
enum Slot {
    Context,
    Namespace,
    Star,
    Name,
    /// The buttons of a row: logs, shell, AI, restart, delete.
    Controls,
    /// An index into `Kind::all_columns` (and a row's cells).
    Data(usize),
}

/// A list column's width at a usual window size.
fn base_column_width(h: &str) -> f32 {
    z(match h {
        "Name" => 300.0,
        "Namespace" => 170.0,
        "Context" => 150.0,
        "Message" => 380.0,
        "Object" => 270.0,
        "CPU Usage" | "Memory Usage" => 170.0,
        "Usage" => 140.0,
        "★" => 34.0,
        "" => 30.0,
        "Images" | "Labels" => 260.0,
        "Selector" => 200.0,
        "Created" => 150.0,
        "Containers" | "Service Account" | "Priority Class" => 160.0,
        "QoS Class" | "Host IP" | "Strategy" | "Architecture" => 110.0,
        "CPU Capacity" | "Memory Capacity" => 120.0,
        "CPU Requests" | "CPU Limits" | "Memory Requests" | "Memory Limits" => 124.0,
        "TLS" => 180.0,
        "Controller" => 110.0,
        "Last Restart Reason" | "Operating System" | "Kernel Version" | "Container Runtime" => 160.0,
        "Ports" | "Hosts" | "Claim" | "Keys" => 180.0,
        "Ready" | "Desired" | "Current" | "Restarts" => 72.0,
        _ => 96.0,
    })
}

/// How wide each column must be to show its header and its longest text without cutting it,
/// by column name. Only the few longest texts of each column (by character count) are measured.
fn measure_columns(ui: &Ui, kind: Kind, rows: &[(String, Row)]) -> HashMap<String, f32> {
    const PAD: f32 = 14.0;
    const MAX: f32 = 1000.0;
    let font = egui::FontId::proportional(z(14.0));
    let all = kind.all_columns();
    let mut names: Vec<&str> = vec!["Context", "Namespace", "Name"];
    names.extend(all.iter().copied());
    let mut out = HashMap::new();
    for h in names {
        if matches!(h, "CPU Usage" | "Memory Usage" | "Usage") {
            out.insert(h.to_string(), base_column_width(h));
            continue;
        }
        let ci = all.iter().position(|c| *c == h);
        let text_of = |r: &(String, Row)| -> Option<String> {
            match h {
                "Context" => Some(ctx_label(&r.0)),
                "Namespace" => Some(r.1.ns.clone()),
                "Name" => Some(r.1.name.clone()),
                _ => ci.and_then(|i| r.1.cells.get(i)).map(|c| c.text.clone()),
            }
        };
        // The few longest texts, by character count.
        let mut longest: Vec<(usize, String)> = vec![];
        for r in rows {
            if let Some(t) = text_of(r) {
                let n = t.chars().count();
                if longest.len() < 4 || n > longest.last().map(|x| x.0).unwrap_or(0) {
                    longest.push((n, t));
                    longest.sort_by(|a, b| b.0.cmp(&a.0));
                    longest.truncate(4);
                }
            }
        }
        let mut w = ui.ctx().fonts_mut(|f| f.layout_no_wrap(format!("{h} "), font.clone(), Color32::WHITE).size().x);
        for (_, t) in longest {
            let tw = ui.ctx().fonts_mut(|f| f.layout_no_wrap(t, font.clone(), Color32::WHITE).size().x);
            w = w.max(tw);
        }
        out.insert(h.to_string(), (w + PAD).min(MAX));
    }
    out
}

/// The room the context's colour stripe takes before its name.
const CTX_STRIPE: f32 = 20.0;

/// The Context and Namespace columns are as wide as their longest name (or their header), up to a limit:
/// a cluster called "P" doesn't need the room of a long name. `text` is the measured width, padding included.
fn snug_width(text: f32, stripe: bool) -> f32 {
    (text + if stripe { CTX_STRIPE } else { 0.0 }).min(z(360.0))
}

/// As `measure_columns`, for one column of a table that has no cache: the width of its header or its longest text.
fn measure_texts<'a>(ui: &Ui, header: &str, texts: impl Iterator<Item = &'a str>) -> f32 {
    let font = egui::FontId::proportional(z(14.0));
    let mut longest: Vec<&str> = texts.collect();
    longest.sort_by_key(|t| std::cmp::Reverse(t.chars().count()));
    longest.dedup();
    longest.truncate(4);
    let wide = |t: String| ui.ctx().fonts_mut(|f| f.layout_no_wrap(t, font.clone(), Color32::WHITE).size().x);
    longest.into_iter().map(|t| wide(t.to_string())).fold(wide(format!("{header}  ")), f32::max) + 14.0
}

/// Share `room` among the columns: each starts at its usual width; spare room then goes to the
/// columns whose text is cut off, evenly, so short cut-off columns are shown in full first.
/// The last column takes whatever is left (it fills the rest of the window anyway).
fn fit_columns(base: &[f32], want: &[f32], room: f32) -> Vec<f32> {
    let n = base.len();
    let mut w: Vec<f32> = base.to_vec();
    if n < 2 {
        return w;
    }
    let last_min = base[n - 1].min(120.0).max(want[n - 1].min(base[n - 1]));
    let mut extra = room - w[..n - 1].iter().sum::<f32>() - last_min;
    // The last column may show its whole text too, if it fits.
    let mut deficit: Vec<f32> = (0..n - 1).map(|i| (want[i] - w[i]).max(0.0)).collect();
    while extra > 0.5 {
        let open: Vec<usize> = (0..n - 1).filter(|&i| deficit[i] > 0.5).collect();
        if open.is_empty() {
            break;
        }
        let step = (extra / open.len() as f32).min(open.iter().map(|&i| deficit[i]).fold(f32::MAX, f32::min));
        for i in open {
            w[i] += step;
            deficit[i] -= step;
            extra -= step;
        }
    }
    w[n - 1] = last_min.max(if extra > 0.0 { want[n - 1].min(last_min + extra) } else { last_min });
    w
}

/// Test aid (KUBEDOG_SHOT_TIMING=1 with --screenshot): how long a list page takes to lay out per frame.
mod frame_timing {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    use std::time::Duration;
    static N: AtomicU64 = AtomicU64::new(0);
    static SUM: AtomicU64 = AtomicU64::new(0);
    static MAX: AtomicU64 = AtomicU64::new(0);
    pub fn add(d: Duration) {
        let us = d.as_micros() as u64;
        N.fetch_add(1, Relaxed);
        SUM.fetch_add(us, Relaxed);
        MAX.fetch_max(us, Relaxed);
    }
    static RB: AtomicU64 = AtomicU64::new(0);
    static RB_US: AtomicU64 = AtomicU64::new(0);
    static ROWS: AtomicU64 = AtomicU64::new(0);
    pub fn rebuilt(d: Duration, rows: usize) {
        RB.fetch_add(1, Relaxed);
        RB_US.store(d.as_micros() as u64, Relaxed);
        ROWS.store(rows as u64, Relaxed);
    }
    pub fn report() {
        let n = N.load(Relaxed);
        if n > 0 && std::env::var("KUBEDOG_SHOT_TIMING").is_ok() {
            eprintln!("list page: {n} frames, mean {} us, max {} us", SUM.load(Relaxed) / n, MAX.load(Relaxed));
            eprintln!(
                "row list rebuilt {} times, last took {} us for {} rows",
                RB.load(Relaxed),
                RB_US.load(Relaxed),
                ROWS.load(Relaxed)
            );
        }
    }
}

/// A pattern with * (any run of characters) and ? (one character) against a name.
fn glob_match(p: &str, s: &str) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (p.chars().collect(), s.chars().collect());
    let (mut pi, mut si, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Whether kubectl's error says the account isn't allowed to.
fn is_refusal(e: &str) -> bool {
    e.contains("forbidden") || e.contains("Forbidden")
}

fn is_pattern(p: &str) -> bool {
    p.contains('*') || p.contains('?')
}

/// The namespaces this account can see: all namespaces when allowed, otherwise OpenShift's
/// projects (which lists only your own).
fn visible_namespaces(k: &Kubectl, ctx: &str) -> Result<Vec<String>, String> {
    let get = |res: &str| {
        k.run(&["--context".into(), ctx.into(), "get".into(), res.into(), "-o".into(), "json".into(), format!("--request-timeout={}", kube::REQUEST_TIMEOUT)])
            .and_then(|j| kube::parse_items(&j))
            .map(|items| items.iter().filter_map(|o| o["metadata"]["name"].as_str().map(String::from)).collect::<Vec<_>>())
    };
    get("namespaces").or_else(|e| get("projects.project.openshift.io").map_err(|_| e))
}

/// A limited cluster's namespace patterns as names: plain names as given, patterns matched
/// against the namespaces already known, or else the ones this account can see.
fn expand_namespaces(k: &Kubectl, ctx: &str, patterns: &[String], known: &[String]) -> Result<Vec<String>, String> {
    let mut names: Vec<String> = patterns.iter().filter(|p| !is_pattern(p)).cloned().collect();
    if patterns.iter().any(|p| is_pattern(p)) {
        let pool = if known.is_empty() { visible_namespaces(k, ctx) } else { Ok(known.to_vec()) };
        match pool {
            Ok(all) => names.extend(all.into_iter().filter(|n| patterns.iter().any(|p| is_pattern(p) && glob_match(p, n)))),
            Err(e) if names.is_empty() => return Err(format!("This account can't list namespaces, so {} can't be matched. Enter the full names instead. ({})", patterns.join(", "), truncate(&e, 200))),
            Err(_) => {}
        }
    }
    names.sort();
    names.dedup();
    if names.is_empty() {
        return Err(format!("No namespace matches {}.", patterns.join(", ")));
    }
    names.truncate(60);
    Ok(names)
}

/// Pod usage of each of these namespaces, as "namespace name cpu memory" lines.
fn top_in_namespaces(k: &Kubectl, ctx: &str, names: &[String]) -> Result<String, String> {
    let results: Vec<Result<String, String>> = std::thread::scope(|sc| {
        let hs: Vec<_> = names
            .iter()
            .map(|ns| {
                let a: Vec<String> = ["--context", ctx, "-n", ns, "top", "pods", "--no-headers", &format!("--request-timeout={}", kube::REQUEST_TIMEOUT)].iter().map(|s| s.to_string()).collect();
                sc.spawn(move || k.run(&a).map(|o| o.lines().map(|l| format!("{ns} {l}\n")).collect::<String>()))
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap_or_else(|_| Err("failed".into()))).collect()
    });
    if results.iter().all(|r| r.is_err()) {
        return Err(results.into_iter().find_map(|r| r.err()).unwrap_or_else(|| "no namespaces".into()));
    }
    Ok(results.into_iter().flatten().collect())
}

/// One kind of object from each of these namespaces, read side by side.
fn get_in_namespaces(k: &Kubectl, ctx: &str, kind: Kind, names: &[String]) -> Result<Vec<Value>, String> {
    let results: Vec<Result<Vec<Value>, String>> = std::thread::scope(|sc| {
        let hs: Vec<_> = names
            .iter()
            .map(|ns| {
                let args: Vec<String> = vec![
                    "--context".into(),
                    ctx.into(),
                    "-n".into(),
                    ns.clone(),
                    "get".into(),
                    kind.resource().into(),
                    "-o".into(),
                    "json".into(),
                    format!("--request-timeout={}", kube::REQUEST_TIMEOUT),
                ];
                sc.spawn(move || k.run(&args).and_then(|j| kube::parse_items(&j)))
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap_or_else(|_| Err("failed".into()))).collect()
    });
    let mut items = vec![];
    let mut first_err = None;
    let mut ok = 0;
    for r in results {
        match r {
            Ok(mut v) => {
                ok += 1;
                items.append(&mut v);
            }
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    if ok == 0 {
        return Err(first_err.unwrap_or_else(|| "nothing could be read".into()));
    }
    Ok(items)
}

/// The Namespaces list of a limited cluster: the real ones that match when they can be read,
/// otherwise one entry per name (so the namespace picker still offers them).
fn limited_namespace_items(k: &Kubectl, ctx: &str, patterns: &[String]) -> Result<Vec<Value>, String> {
    let all = k
        .run(&["--context".into(), ctx.into(), "get".into(), "namespaces".into(), "-o".into(), "json".into(), format!("--request-timeout={}", kube::REQUEST_TIMEOUT)])
        .and_then(|j| kube::parse_items(&j));
    let matches = |n: &str| patterns.iter().any(|p| if is_pattern(p) { glob_match(p, n) } else { p == n });
    if let Ok(items) = all {
        return Ok(items.into_iter().filter(|o| o["metadata"]["name"].as_str().map(|n| matches(n)).unwrap_or(false)).collect());
    }
    let names = expand_namespaces(k, ctx, patterns, &[])?;
    Ok(names.into_iter().map(|n| serde_json::json!({"metadata": {"name": n}, "status": {"phase": "Active"}})).collect())
}

/// "G" then one of these keys goes to that page: (key, page, label).
const GO_KEYS: [(Key, View, &str); 14] = [
    (Key::O, View::ClusterOverview, "Cluster overview"),
    (Key::W, View::WorkloadsOverview, "Workloads overview"),
    (Key::N, View::Resource(Kind::Nodes), "Nodes"),
    (Key::E, View::Resource(Kind::Events), "Events"),
    (Key::D, View::Resource(Kind::Deployments), "Deployments"),
    (Key::P, View::Resource(Kind::Pods), "Pods"),
    (Key::J, View::Resource(Kind::Jobs), "Jobs"),
    (Key::H, View::Helm, "Helm releases"),
    (Key::S, View::Resource(Kind::Services), "Services"),
    (Key::I, View::Resource(Kind::Ingresses), "Ingresses"),
    (Key::C, View::Resource(Kind::ConfigMaps), "Config maps"),
    (Key::T, View::Resource(Kind::Secrets), "Secrets"),
    (Key::V, View::Resource(Kind::PersistentVolumeClaims), "Persistent volume claims"),
    (Key::Comma, View::Settings, "Settings"),
];

/// A workload's pod selector as a kubectl `-l` value (matchLabels, plus simple matchExpressions).
fn workload_selector(o: &Value) -> Option<String> {
    let sel = &o["spec"]["selector"];
    let mut parts: Vec<String> = sel["matchLabels"]
        .as_object()
        .map(|m| m.iter().filter_map(|(k, v)| Some(format!("{k}={}", v.as_str()?))).collect())
        .unwrap_or_default();
    for e in sel["matchExpressions"].as_array().into_iter().flatten() {
        let key = e["key"].as_str()?;
        let vals: Vec<&str> = e["values"].as_array().map(|a| a.iter().filter_map(|v| v.as_str()).collect()).unwrap_or_default();
        parts.push(match e["operator"].as_str()? {
            "In" => format!("{key} in ({})", vals.join(",")),
            "NotIn" => format!("{key} notin ({})", vals.join(",")),
            "Exists" => key.to_string(),
            "DoesNotExist" => format!("!{key}"),
            _ => return None,
        });
    }
    (!parts.is_empty()).then(|| parts.join(","))
}

/// The longest cluster name Kubedog shows; longer ones are asked to be shortened on connecting.
const MAX_CLUSTER_NAME: usize = 10;

/// A short name for a cluster: the context's first part ("team-lab/api-…" → "team-lab"), else
/// the server's host without "api." ("api.acmecorp.example.com" → "acmecorp"), made unique.
fn suggest_short_name(ctx: &str, server: &str, taken: &[String]) -> String {
    let first = ctx.split(['/', ':', '@']).find(|p| !p.is_empty()).unwrap_or(ctx);
    let host = server.trim_start_matches("https://").trim_start_matches("http://").split([':', '/']).next().unwrap_or("");
    let host_part = host.split('.').find(|p| !p.is_empty() && *p != "api").unwrap_or("");
    let mut base: String = if first.chars().count() <= MAX_CLUSTER_NAME && !first.starts_with("api-") {
        first.to_string()
    } else if !host_part.is_empty() {
        host_part.to_string()
    } else {
        first.trim_start_matches("api-").to_string()
    };
    base = base.chars().take(MAX_CLUSTER_NAME).collect::<String>().trim_end_matches(['-', '.', '_']).to_string();
    if base.is_empty() {
        base = "cluster".into();
    }
    let mut name = base.clone();
    let mut i = 2;
    while taken.iter().any(|t| t == &name) {
        let suffix = format!("-{i}");
        name = base.chars().take(MAX_CLUSTER_NAME - suffix.len()).collect::<String>() + &suffix;
        i += 1;
    }
    name
}

/// A page as a word for the settings file ("Pods", "ClusterOverview"...), and back.
fn view_name(v: View) -> String {
    match v {
        View::Resource(k) => format!("{k:?}"),
        View::Op(i) => format!("op:{}", powers::OPS.get(i as usize).map(|o| o.id).unwrap_or("")),
        other => format!("{other:?}"),
    }
}

fn view_from_name(name: &str) -> Option<View> {
    let simple = [
        View::ClusterOverview,
        View::WorkloadsOverview,
        View::PortForwards,
        View::Helm,
        View::Settings,
        View::ServiceMap,
        View::StorageUsage,
        View::Postgres,
        View::Elastic,
        View::Pulsar,
        View::Hive,
        View::Observatory,
        View::Proxmox,
        View::NetLab,
        View::Shells,
        View::Incident,
        View::Readiness,
    ];
    if let Some(id) = name.strip_prefix("op:") {
        return powers::op_index(id).map(View::Op);
    }
    if let Some(v) = simple.into_iter().find(|v| format!("{v:?}") == name) {
        return Some(v);
    }
    GROUPS.iter().flat_map(|g| g.1.iter().copied()).find(|k| format!("{k:?}") == name).map(View::Resource)
}

/// The view a "first page" setting stands for.
fn first_page_view(v: &str) -> View {
    match v {
        "cluster" => View::ClusterOverview,
        "workloads" => View::WorkloadsOverview,
        "deployments" => View::Resource(Kind::Deployments),
        "nodes" => View::Resource(Kind::Nodes),
        "events" => View::Resource(Kind::Events),
        _ => View::Resource(Kind::Pods),
    }
}

fn kind_from_key(key: &str) -> Option<Kind> {
    let k = key.split('|').nth(2)?;
    GROUPS.iter().flat_map(|g| g.1.iter().copied()).find(|x| format!("{x:?}") == k)
}

fn make_row(kind: Kind, o: &Value) -> Row {
    let workload = if kind == Kind::Pods {
        o["metadata"]["ownerReferences"].as_array().and_then(|a| a.first()).and_then(|r| {
            let name = r["name"].as_str()?.to_string();
            match r["kind"].as_str()? {
                "ReplicaSet" => name.rsplit_once('-').map(|(d, _)| (Kind::Deployments, d.to_string())),
                "StatefulSet" => Some((Kind::StatefulSets, name)),
                "DaemonSet" => Some((Kind::DaemonSets, name)),
                _ => None,
            }
        })
    } else {
        None
    };
    Row {
        ns: o["metadata"]["namespace"].as_str().unwrap_or("").to_string(),
        name: o["metadata"]["name"].as_str().unwrap_or("").to_string(),
        cells: {
            let mut c = kind.cells(o);
            c.extend(kind.extra_cells(o));
            c
        },
        req: resources::requests(kind, o),
        workload,
    }
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn prefs_path() -> Option<std::path::PathBuf> {
    Some(kube::data_dir()?.join("prefs.json"))
}

/// Everything Kubedog remembers between runs. Saved as one record (read-modify-write),
/// so changing one setting never wipes the others.
#[derive(Clone)]
pub(crate) struct Prefs {
    contexts: Vec<String>,
    starred_namespaces: Vec<String>,
    /// "builtin" (the default), "Terminal", "iTerm", "Ghostty", "Warp", "WezTerm", "kitty", "Tabby", "Alacritty"
    terminal: String,
    /// Set once the person picks a terminal in Settings; until then the built-in one is used.
    terminal_chosen: bool,
    /// Filter link on: one filter shared by every page except Nodes (which keeps its own).
    /// Off: a page's filter is cleared when you leave it.
    shared_filter: bool,
    /// Look for a newer Kubedog once a day; when GitHub last answered, what it named, and the version not to remind of.
    update_check: bool,
    update_last: i64,
    update_latest: String,
    update_skip: String,
    /// When GitHub was last asked by itself, answered or not (clock time).
    update_tried: i64,
    /// Tries in a row that got no answer.
    update_fails: u32,
    /// Kubedog itself asks the internet for nothing.
    airgapped: bool,
    /// It was switched on by Kubedog, after days without an answer; an answer switches it off again.
    airgapped_auto: bool,
    /// Kubeconfig files Kubedog reads, in order (first one wins on a name clash).
    kubeconfigs: Vec<KubeFile>,
    /// Contexts hidden from the start page (Kubedog only; the files aren't touched).
    hidden_contexts: Vec<String>,
    /// "start" (show the start page, the default) or "reconnect" (open the last clusters).
    startup: String,
    /// The page shown after connecting: "pods" (default), "cluster", "workloads", "deployments", "nodes", "events".
    first_page: String,
    /// Seconds between list refreshes (default 5) and between CPU/memory readings (default 15).
    refresh_secs: u64,
    metrics_secs: u64,
    /// Log viewer: text size, and the defaults a new log view starts with.
    log_size: f32,
    log_since: String,
    log_wrap: bool,
    log_timestamps: bool,
    /// Where kubectl is, when it was pointed out by hand because it wasn't found by itself.
    kubectl_path: String,
    /// Per-context display name and colour (index into the context palette). Kubedog only.
    ctx_alias: HashMap<String, String>,
    /// Superpowers that aren't on Auto: "on" or "off".
    powers: HashMap<String, String>,
    /// AI: off by default.
    ai: ai::AiPrefs,
    ctx_color: HashMap<String, usize>,
    /// The order clusters are listed in on the start page (others follow, as the files list them).
    ctx_order: Vec<String>,
    /// The order of the sidebar's parts, once the person has changed it.
    sidebar: Vec<String>,
    /// Clusters that start with changes allowed; `open_all`: every one.
    open_at_start: Vec<String>,
    /// Favorite pages: (page, what it's called), in the order they were starred.
    fav_pages: Vec<(String, String)>,
    open_all: bool,
    /// What the Shell superpower opens: empty for the usual shell, or "wsl:<name>".
    shell: String,
    /// On Windows, with a Linux chosen above: the whole app works through it (its kubectl, helm and kubeconfig).
    wsl_app: bool,
    /// Named groups of contexts, opened together.
    groups: Vec<Group>,
    /// Per list ("Pods", "Deployments"...): the columns shown, in order. Missing = the usual ones.
    columns: HashMap<String, Vec<String>>,
    /// Leave out columns that are empty ("-") in every row on screen.
    hide_empty_columns: bool,
    /// Per list: every column in its order, hidden ones included. Missing = the standard order.
    column_order: HashMap<String, Vec<String>>,
    /// Per context: the only namespaces Kubedog reads (for accounts that can't see the whole
    /// cluster). Names or patterns with * and ?. Missing = the whole cluster.
    ctx_namespaces: HashMap<String, Vec<String>>,
    /// "auto" (follows the system), "dark" (default), "light" or "sand".
    theme: String,
    /// The colour of names, links, buttons and highlights ("orange", "blue"...).
    accent: String,
    /// Services Kubedog may log in to with the login in their secret (the answer, never the login).
    logins: Vec<String>,
    /// A Grafana per cluster, for node figures (never its password).
    grafana: HashMap<String, grafana::Conf>,
    /// Certificate authorities (PEM) kept once for all of Kubedog; a server uses them when its settings say so.
    authorities: String,
    proxmox: Vec<proxmox::Conf>,
    netlab: nethelp::Prefs,
    /// The font ("ubuntu", "inter"...) and the text size (16 is normal).
    font: String,
    text_size: u8,
    /// Where the person was when Kubedog closed, to carry on from there.
    session: Session,
}

/// The page, namespace, cluster pick, zoom and folded sidebar groups of the last session.
#[derive(Clone, Default, PartialEq, Debug)]
pub(crate) struct Session {
    view: String,
    ns: Option<String>,
    ns_multi: Vec<String>,
    ns_ctx: Option<String>,
    zoom: f32,
    collapsed: Vec<String>,
}

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct Group {
    name: String,
    contexts: Vec<String>,
}

#[derive(Clone, PartialEq)]
pub(crate) struct KubeFile {
    path: String,
    enabled: bool,
    /// Added by pasting into Kubedog: the file lives in Kubedog's own folder.
    managed: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            contexts: vec![],
            starred_namespaces: vec![],
            terminal: "builtin".into(),
            terminal_chosen: false,
            shared_filter: true,
            update_check: true,
            update_last: 0,
            update_latest: String::new(),
            update_skip: String::new(),
            update_tried: 0,
            update_fails: 0,
            airgapped: false,
            airgapped_auto: false,
            kubeconfigs: vec![],
            hidden_contexts: vec![],
            startup: "reconnect".into(),
            first_page: "pods".into(),
            refresh_secs: REFRESH_EVERY.as_secs(),
            metrics_secs: METRICS_EVERY.as_secs(),
            log_size: 12.0,
            log_since: DEFAULT_SINCE.into(),
            log_wrap: true,
            kubectl_path: String::new(),
            log_timestamps: true,
            ctx_alias: HashMap::new(),
            powers: HashMap::new(),
            ai: Default::default(),
            ctx_color: HashMap::new(),
            ctx_order: vec![],
            sidebar: vec![],
            open_at_start: vec![],
            fav_pages: vec![],
            open_all: false,
            shell: String::new(),
            wsl_app: false,
            groups: vec![],
            columns: HashMap::new(),
            hide_empty_columns: false,
            column_order: HashMap::new(),
            ctx_namespaces: HashMap::new(),
            theme: "dark".into(),
            accent: "orange".into(),
            logins: vec![],
            grafana: HashMap::new(),
            authorities: String::new(),
            proxmox: vec![],
            netlab: nethelp::Prefs::default(),
            font: "ubuntu".into(),
            text_size: crate::theme::NORMAL_TEXT,
            session: Session::default(),
        }
    }
}

fn load_prefs() -> Prefs {
    let Some(p) = prefs_path() else { return Prefs::default() };
    // Choices saved under the app's earlier name are carried over.
    let old = p.parent().and_then(|d| d.parent()).map(|d| d.join("Superkube/prefs.json"));
    let p = if p.exists() { p } else { old.filter(|o| o.exists()).unwrap_or(p) };
    let v = std::fs::read_to_string(p).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()).unwrap_or_default();
    prefs_from_json(&v)
}

/// Read saved settings; anything missing (an older file) takes its default.
fn prefs_from_json(v: &Value) -> Prefs {
    let strs = |k: &str| -> Vec<String> {
        v[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
    };
    let d = Prefs::default();
    let terminal_chosen = v["terminal_chosen"].as_bool().unwrap_or(false);
    Prefs {
        contexts: strs("contexts"),
        starred_namespaces: strs("starred_namespaces"),
        // The built-in terminal is the default until a terminal is chosen in Settings.
        terminal: if terminal_chosen { v["terminal"].as_str().map(String::from).unwrap_or(d.terminal) } else { d.terminal },
        terminal_chosen,
        shared_filter: v["shared_filter"].as_bool().or(v["keep_filters"].as_bool()).unwrap_or(d.shared_filter),
        update_check: v["update_check"].as_bool().unwrap_or(true),
        update_last: v["update_last"].as_i64().unwrap_or(0),
        update_latest: v["update_latest"].as_str().unwrap_or("").to_string(),
        update_skip: v["update_skip"].as_str().unwrap_or("").to_string(),
        update_tried: v["update_tried"].as_i64().unwrap_or(0),
        update_fails: v["update_fails"].as_u64().unwrap_or(0).min(1000) as u32,
        airgapped: v["airgapped"].as_bool().unwrap_or(false),
        airgapped_auto: v["airgapped"].as_bool().unwrap_or(false) && v["airgapped_auto"].as_bool().unwrap_or(false),
        kubeconfigs: v["kubeconfigs"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|f| {
                        Some(KubeFile {
                            path: f["path"].as_str()?.to_string(),
                            enabled: f["enabled"].as_bool().unwrap_or(true),
                            managed: f["managed"].as_bool().unwrap_or(false),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
        hidden_contexts: strs("hidden_contexts"),
        sidebar: strs("sidebar"),
        open_at_start: strs("open_at_start"),
        fav_pages: v["fav_pages"].as_array().map(|a| a.iter().filter_map(|f| Some((f["page"].as_str()?.to_string(), f["label"].as_str()?.to_string()))).collect()).unwrap_or_default(),
        open_all: v["open_all"].as_bool().unwrap_or(false),
        shell: v["shell"].as_str().unwrap_or("").to_string(),
        wsl_app: v["wsl_app"].as_bool().unwrap_or(false),
        // "Continue where I left off" is the default; a file from before it existed (its "startup"
        // was always written as "start") takes the new default too.
        startup: match v["startup2"].as_str() {
            Some("start") => "start".into(),
            _ => d.startup.clone(),
        },
        session: Session {
            view: v["session"]["view"].as_str().unwrap_or("").to_string(),
            ns: v["session"]["ns"].as_str().map(String::from),
            ns_multi: v["session"]["ns_multi"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
            ns_ctx: v["session"]["ns_ctx"].as_str().map(String::from),
            zoom: v["session"]["zoom"].as_f64().map(|z| (z as f32).clamp(ZOOMS[0], ZOOMS[ZOOMS.len() - 1])).unwrap_or(1.0),
            collapsed: v["session"]["collapsed"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
        },
        first_page: v["first_page"].as_str().filter(|x| FIRST_PAGES.iter().any(|f| f.0 == *x)).map(String::from).unwrap_or(d.first_page.clone()),
        refresh_secs: v["refresh_secs"].as_u64().filter(|x| REFRESH_CHOICES.contains(x)).unwrap_or(d.refresh_secs),
        metrics_secs: v["metrics_secs"].as_u64().filter(|x| METRICS_CHOICES.contains(x)).unwrap_or(d.metrics_secs),
        log_size: v["log_size"].as_f64().map(|x| (x as f32).clamp(9.0, 20.0)).unwrap_or(d.log_size),
        log_since: v["log_since"].as_str().map(since_choice).filter(|x| SINCE_CHOICES.contains(x)).map(String::from).unwrap_or(d.log_since.clone()),
        log_wrap: v["log_wrap"].as_bool().unwrap_or(d.log_wrap),
        kubectl_path: v["kubectl_path"].as_str().unwrap_or("").to_string(),
        log_timestamps: v["log_timestamps"].as_bool().unwrap_or(d.log_timestamps),
        ctx_alias: v["ctx_alias"]
            .as_object()
            .map(|m| m.iter().filter_map(|(k, x)| Some((k.clone(), x.as_str()?.to_string()))).filter(|(_, x)| !x.trim().is_empty()).collect())
            .unwrap_or_default(),
        powers: v["powers"].as_object().map(|m| m.iter().filter_map(|(k, x)| Some((k.clone(), x.as_str()?.to_string()))).filter(|(_, x)| x == "on" || x == "off").collect()).unwrap_or_default(),
        ai: ai::AiPrefs::from_json(&v["ai"]),
        ctx_color: v["ctx_color"]
            .as_object()
            .map(|m| m.iter().filter_map(|(k, x)| Some((k.clone(), x.as_u64()? as usize))).filter(|(_, x)| *x < CTX_PALETTE.len()).collect())
            .unwrap_or_default(),
        ctx_order: strs("ctx_order"),
        column_order: v["column_order"]
            .as_object()
            .map(|m| {
                m.iter()
                    .filter_map(|(k, x)| Some((k.clone(), x.as_array()?.iter().filter_map(|c| c.as_str().map(String::from)).collect::<Vec<_>>())))
                    .filter(|(_, x)| !x.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        columns: v["columns"]
            .as_object()
            .map(|m| {
                m.iter()
                    .filter_map(|(k, x)| Some((k.clone(), x.as_array()?.iter().filter_map(|c| c.as_str().map(String::from)).collect::<Vec<_>>())))
                    .filter(|(_, x)| !x.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        hide_empty_columns: v["hide_empty_columns"].as_bool().unwrap_or(false),
        theme: crate::theme::read_look(v["theme"].as_str(), v["accent"].as_str()).0,
        logins: strs("logins"),
        netlab: nethelp::Prefs::from_json(&v["netlab"]),
        proxmox: v["proxmox"].as_array().map(|l| l.iter().map(proxmox::Conf::from_json).collect()).unwrap_or_default(),
        grafana: v["grafana"].as_object().map(|m| m.iter().map(|(k, c)| (k.clone(), grafana::Conf::from_json(c))).collect()).unwrap_or_default(),
        authorities: v["authorities"].as_str().unwrap_or("").to_string(),
        font: v["font"].as_str().filter(|f| crate::theme::FONTS.iter().any(|x| x.0 == *f)).unwrap_or("ubuntu").to_string(),
        text_size: v["text_size"].as_u64().map(|n| n as u8).filter(|n| crate::theme::TEXT_SIZES.contains(n)).unwrap_or(crate::theme::NORMAL_TEXT),
        accent: crate::theme::read_look(v["theme"].as_str(), v["accent"].as_str()).1,
        ctx_namespaces: v["ctx_namespaces"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, x)| (k.clone(), x.as_array().map(|a| a.iter().filter_map(|c| c.as_str().map(String::from)).collect::<Vec<_>>()).unwrap_or_default()))
                    .filter(|(_, x)| !x.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        groups: v["groups"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|g| {
                        Some(Group {
                            name: g["name"].as_str()?.to_string(),
                            contexts: g["contexts"].as_array()?.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn save_prefs(p: &Prefs) {
    let Some(path) = prefs_path() else { return };
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(path, serde_json::to_string_pretty(&prefs_to_json(p)).unwrap_or_default());
}

fn prefs_to_json(p: &Prefs) -> Value {
    serde_json::json!({
        "contexts": p.contexts,
        "starred_namespaces": p.starred_namespaces,
        "terminal": p.terminal,
        "terminal_chosen": p.terminal_chosen,
        "shared_filter": p.shared_filter,
        "update_check": p.update_check,
        "update_last": p.update_last,
        "update_latest": p.update_latest,
        "update_skip": p.update_skip,
        "update_tried": p.update_tried,
        "update_fails": p.update_fails,
        "airgapped": p.airgapped,
        "airgapped_auto": p.airgapped_auto,
        "kubeconfigs": p.kubeconfigs.iter().map(|f| serde_json::json!({"path": f.path, "enabled": f.enabled, "managed": f.managed})).collect::<Vec<_>>(),
        "hidden_contexts": p.hidden_contexts,
        "sidebar": p.sidebar,
        "open_at_start": p.open_at_start,
        "fav_pages": p.fav_pages.iter().map(|f| serde_json::json!({"page": f.0, "label": f.1})).collect::<Vec<_>>(),
        "open_all": p.open_all,
        "shell": p.shell,
        "wsl_app": p.wsl_app,
        "startup2": p.startup,
        "session": {
            "view": p.session.view,
            "ns": p.session.ns,
            "ns_multi": p.session.ns_multi,
            "ns_ctx": p.session.ns_ctx,
            "zoom": p.session.zoom,
            "collapsed": p.session.collapsed,
        },
        "first_page": p.first_page,
        "refresh_secs": p.refresh_secs,
        "metrics_secs": p.metrics_secs,
        "log_size": p.log_size,
        "log_since": p.log_since,
        "log_wrap": p.log_wrap,
        "kubectl_path": p.kubectl_path,
        "log_timestamps": p.log_timestamps,
        "ctx_alias": p.ctx_alias,
        "powers": p.powers,
        "netlab": p.netlab.json(),
        "proxmox": p.proxmox.iter().filter(|c| **c != Default::default()).map(|c| c.json()).collect::<Vec<_>>(),
        "ai": p.ai.json(),
        "ctx_color": p.ctx_color,
        "ctx_order": p.ctx_order,
        "columns": p.columns,
        "column_order": p.column_order,
        "hide_empty_columns": p.hide_empty_columns,
        "ctx_namespaces": p.ctx_namespaces,
        "theme": p.theme,
        "accent": p.accent,
        "logins": p.logins,
        "grafana": p.grafana.iter().map(|(k, c)| (k.clone(), c.json())).collect::<serde_json::Map<String, Value>>(),
        "authorities": p.authorities,
        "font": p.font,
        "text_size": p.text_size,
        "groups": p.groups.iter().map(|g| serde_json::json!({"name": g.name, "contexts": g.contexts})).collect::<Vec<_>>(),
    })
}

/// Colours a context can have. Each context gets one from its name unless one is picked in Settings.
const CTX_PALETTE: [Color32; 8] = [
    Color32::from_rgb(0x60, 0xa7, 0xe9),
    Color32::from_rgb(0x5e, 0xe9, 0xb5),
    Color32::from_rgb(0xff, 0xd2, 0x36),
    Color32::from_rgb(0xc4, 0xb5, 0xfd),
    Color32::from_rgb(0xf9, 0xa8, 0xd4),
    Color32::from_rgb(0xfd, 0xba, 0x74),
    Color32::from_rgb(0x67, 0xe8, 0xf9),
    Color32::from_rgb(0xbe, 0xf2, 0x64),
];

thread_local! {
    /// Display names and colours picked in Settings (the window's thread only).
    static CTX_LOOK: std::cell::RefCell<(HashMap<String, String>, HashMap<String, usize>)> = Default::default();
}

fn set_ctx_look(p: &Prefs) {
    CTX_LOOK.with(|l| *l.borrow_mut() = (p.ctx_alias.clone(), p.ctx_color.clone()));
}

/// A context's palette colour: the one picked in Settings, or one stable per name.
fn context_color(name: &str) -> Color32 {
    CTX_PALETTE[context_color_index(name)]
}

fn context_color_index(name: &str) -> usize {
    if let Some(i) = CTX_LOOK.with(|l| l.borrow().1.get(name).copied()) {
        return i.min(CTX_PALETTE.len() - 1);
    }
    let h = name.bytes().fold(5381u32, |h, b| h.wrapping_mul(33) ^ b as u32);
    (h % 8) as usize
}

/// The name shown for a context: its alias from Settings, or its kubeconfig name.
/// (kubectl always gets the real name.)
fn ctx_label(name: &str) -> String {
    CTX_LOOK.with(|l| l.borrow().0.get(name).cloned()).unwrap_or_else(|| name.to_string())
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\n' | b'\r' => continue,
            _ => return None,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn level_color(l: Level) -> Color32 {
    match l {
        Level::Trace | Level::Debug => TEXT_SUBTLE(),
        Level::Info => TEXT_MUTED(),
        Level::Warn => WARNING(),
        Level::Error | Level::Fatal => DANGER(),
        Level::Other => TEXT_MUTED(),
    }
}

// ---------------- UI helpers ----------------

/// Empty space that moves the window when dragged (the title bar is hidden on macOS).
fn drag_area(ui: &mut Ui, w: f32, h: f32) {
    if w <= 4.0 {
        return;
    }
    let (_, resp) = ui.allocate_exact_size(egui::vec2(w, h), Sense::drag());
    if resp.drag_started() {
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
    }
}

/// A secret value drawn as a blurred strip of soft dots. Clicking it reveals the value.
fn blurred(ui: &mut Ui) -> egui::Response {
    // The same strip for every value, so it gives away neither its length nor which ones are equal.
    let n = 24usize;
    let w = n as f32 * 7.2 + 16.0;
    let (r, resp) = ui.allocate_exact_size(egui::vec2(w, 22.0), Sense::click());
    let p = ui.painter();
    p.rect_filled(r, CornerRadius::same(5), if resp.hovered() { BG_STRONG() } else { BG_MUTED() });
    // Layered soft blobs read as blurred text.
    let mut seed: u32 = 4242;
    for i in 0..n {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let x = r.left() + 8.0 + i as f32 * 7.2 + 3.6;
        let h = 3.0 + (seed >> 16) as f32 % 5.0;
        let a = 0.25 + ((seed >> 8) & 0xff) as f32 / 255.0 * 0.35;
        p.circle_filled(egui::pos2(x, r.center().y), h, TEXT_SUBTLE().gamma_multiply(a * 0.5));
        p.circle_filled(egui::pos2(x, r.center().y), h * 0.55, TEXT_MUTED().gamma_multiply(a));
    }
    if resp.hovered() {
        p.text(r.right_center() - egui::vec2(6.0, 0.0), egui::Align2::RIGHT_CENTER, "reveal", FontId::proportional(z(10.5)), TEXT_DEFAULT());
    }
    resp
}

/// Standard base64 with padding.
fn b64_encode(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

/// The filter's link toggle: two chain links, joined when on, apart when off.
/// A filter or search box with an × in it that empties it.
fn filter_box(ui: &mut Ui, text: &mut String, hint: &str, width: f32) -> egui::Response {
    filter_styled(ui, text, hint, width, 4, None)
}

fn filter_styled(ui: &mut Ui, text: &mut String, hint: &str, width: f32, tall: i8, size: Option<f32>) -> egui::Response {
    let side = u(22.0);
    let mut edit = egui::TextEdit::singleline(text).hint_text(hint).desired_width((width - side + 8.0).max(20.0)).margin(Margin { left: 8, right: side as i8, top: tall, bottom: tall });
    if let Some(s) = size {
        edit = edit.font(FontId::proportional(s));
    }
    let mut r = ui.add(edit);
    if text.is_empty() {
        return r;
    }
    let spot = egui::Rect::from_min_max(egui::pos2(r.rect.right() - side, r.rect.top()), r.rect.max);
    let x = ui.interact(spot, r.id.with("clear"), Sense::click()).on_hover_cursor(egui::CursorIcon::Default).on_hover_text("Clear");
    let c = spot.center();
    let p = ui.painter();
    if x.hovered() {
        p.circle_filled(c, u(8.5), BG_HOVER());
    }
    let (d, s) = (u(3.6), Stroke::new(1.5, if x.hovered() { TEXT_DEFAULT() } else { TEXT_SUBTLE() }));
    p.line_segment([c + egui::vec2(-d, -d), c + egui::vec2(d, d)], s);
    p.line_segment([c + egui::vec2(-d, d), c + egui::vec2(d, -d)], s);
    if x.clicked() {
        text.clear();
        r.request_focus();
        r.mark_changed();
    }
    r
}

fn link_toggle(ui: &mut Ui, on: bool) -> egui::Response {
    let (r, resp) = ui.allocate_exact_size(egui::vec2(26.0, 26.0), Sense::click());
    let p = ui.painter();
    if on || resp.hovered() {
        p.rect_filled(r, CornerRadius::same(6), if on { PRIMARY_TEXT().gamma_multiply(0.16) } else { BG_HOVER() });
    }
    let col = if on { PRIMARY_TEXT() } else if resp.hovered() { TEXT_MUTED() } else { TEXT_PLACEHOLDER() };
    let c = r.center();
    let s = Stroke::new(1.6, col);
    let gap = if on { 0.0 } else { 2.5 };
    let a = egui::Rect::from_center_size(c + egui::vec2(-3.6 - gap, 0.0), egui::vec2(9.0, 6.0));
    let b = egui::Rect::from_center_size(c + egui::vec2(3.6 + gap, 0.0), egui::vec2(9.0, 6.0));
    p.rect_stroke(a, CornerRadius::same(3), s, egui::StrokeKind::Middle);
    p.rect_stroke(b, CornerRadius::same(3), s, egui::StrokeKind::Middle);
    if !on {
        p.line_segment([c + egui::vec2(-1.5, -6.0), c + egui::vec2(1.5, 6.0)], Stroke::new(1.4, col));
    }
    resp
}

/// The way back from a page within a page: wide, in the accent colour, an arrow drawn with "Back" beside it.
pub(crate) fn back_button(ui: &mut Ui) -> egui::Response {
    let (r, resp) = ui.allocate_exact_size(egui::vec2(u(84.0), u(28.0)), Sense::click());
    let hot = resp.hovered();
    let p = ui.painter();
    p.rect(r, CornerRadius::same(7), PRIMARY().gamma_multiply(if hot { 0.32 } else { 0.18 }), Stroke::new(1.0, PRIMARY().gamma_multiply(if hot { 1.0 } else { 0.7 })), egui::StrokeKind::Inside);
    let c = PRIMARY_TEXT();
    let s = Stroke::new(u(1.8), c);
    let (x, y, w) = (r.left() + u(14.0), r.center().y, u(12.0));
    p.line_segment([egui::pos2(x, y), egui::pos2(x + w, y)], s);
    p.line_segment([egui::pos2(x, y), egui::pos2(x + u(5.0), y - u(5.0))], s);
    p.line_segment([egui::pos2(x, y), egui::pos2(x + u(5.0), y + u(5.0))], s);
    p.text(egui::pos2(x + w + u(8.0), y), egui::Align2::LEFT_CENTER, "Back", FontId::proportional(z(13.5)), c);
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A back (‹) or forward (›) arrow drawn as two strokes.
fn chevron(ui: &mut Ui, left: bool, enabled: bool) -> egui::Response {
    let (r, resp) = ui.allocate_exact_size(egui::vec2(18.0, 22.0), if enabled { Sense::click() } else { Sense::hover() });
    let c = r.center();
    let color = if !enabled { TEXT_PLACEHOLDER() } else if resp.hovered() { TEXT_DEFAULT() } else { TEXT_MUTED() };
    let d = if left { 1.0 } else { -1.0 };
    let tip = c + egui::vec2(-3.5 * d, 0.0);
    let s = Stroke::new(1.6, color);
    ui.painter().line_segment([c + egui::vec2(3.5 * d, -7.0), tip], s);
    ui.painter().line_segment([tip, c + egui::vec2(3.5 * d, 7.0)], s);
    resp
}

/// Thin separator under a table cell; widened by the column gap so lines join up.
fn cell_line(ui: &mut Ui, stroke: Stroke) {
    let r = ui.max_rect();
    let gap = ui.spacing().item_spacing.x;
    let clip = ui.clip_rect().expand2(egui::vec2(gap, 0.0));
    ui.painter()
        .with_clip_rect(clip)
        .hline((r.left() - gap)..=(r.right() + gap), clip.bottom() - 0.5, stroke);
}

thread_local! {
    /// The logo as textures, by the size asked for.
    static LOGO: std::cell::RefCell<HashMap<u32, egui::TextureHandle>> = std::cell::RefCell::new(HashMap::new());
}

/// The app's mark: the logo, from the picture closest to the size it's drawn at.
fn app_mark(p: &egui::Painter, r: egui::Rect) {
    let want = (r.width() * p.ctx().pixels_per_point()).ceil() as u32;
    let tex = LOGO.with(|l| {
        l.borrow_mut()
            .entry(want)
            .or_insert_with(|| {
                let (n, px) = crate::logo::rgba(want);
                let img = egui::ColorImage::from_rgba_unmultiplied([n as usize, n as usize], &px);
                p.ctx().load_texture("kubedog-logo", img, egui::TextureOptions::LINEAR)
            })
            .clone()
    });
    p.image(tex.id(), r, egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)), Color32::WHITE);
}

/// A context's mark: a rounded square in the context's colour with its initial.
fn ctx_mark(p: &egui::Painter, r: egui::Rect, name: &str) {
    let c = context_color(name);
    p.rect_filled(r, CornerRadius::same(6), c.gamma_multiply(0.35));
    p.rect_stroke(r, CornerRadius::same(6), Stroke::new(1.0, c), egui::StrokeKind::Inside);
    let label = ctx_label(name);
    let initial = label.chars().find(|ch| ch.is_alphanumeric()).map(|ch| ch.to_ascii_uppercase().to_string()).unwrap_or_default();
    p.text(r.center(), egui::Align2::CENTER_CENTER, initial, FontId::proportional(r.height() * 0.55), if crate::theme::palette().dark { Color32::WHITE } else { TEXT_DEFAULT() });
}

/// A cluster's mark and name on a tinted strip (dialogs, object pages).
fn cluster_badge(ui: &mut Ui, ctx: &str) {
    let col = context_color(ctx);
    Frame::new()
        .fill(col.gamma_multiply(0.12))
        .stroke(Stroke::new(1.0, col.gamma_multiply(0.45)))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), Sense::hover());
                ctx_mark(ui.painter(), r, ctx);
                let label = ctx_label(ctx);
                ui.label(RichText::new(&label).size(z(13.0)).strong().color(TEXT_DEFAULT()));
                if label != ctx {
                    ui.add(egui::Label::new(RichText::new(ctx).size(z(11.5)).color(TEXT_SUBTLE())).truncate());
                }
            });
        });
}

/// Text cut with an ellipsis to fit a width.
fn fit(ui: &Ui, text: &str, width: f32, size: f32) -> String {
    let font = FontId::proportional(size);
    let w = |t: &str| ui.painter().layout_no_wrap(t.to_string(), font.clone(), Color32::WHITE).size().x;
    if w(text) <= width {
        return text.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    let mut n = chars.len();
    while n > 1 {
        n -= 1;
        let t: String = chars[..n].iter().collect::<String>() + "...";
        if w(&t) <= width {
            return t;
        }
    }
    "...".into()
}

fn gib(b: f64) -> String {
    let (v, u) = resources::fmt_mem(b);
    format!("{v}{u}")
}

/// A usage cell: value with a small unit, then a bar. The bar's end is the limit
/// (or, for nodes, allocatable); the white tick marks the request. Amber when
/// usage is above the request (estimated rule).
fn usage_bar(ui: &mut Ui, cpu: bool, val: f64, req: f64, lim: f64, node: bool) {
    let (num, unit) = if cpu { resources::fmt_cpu(val) } else { resources::fmt_mem(val) };
    let mut job = egui::text::LayoutJob::default();
    job.append(&num, 0.0, egui::TextFormat { font_id: FontId::proportional(z(14.0)), color: TEXT_DEFAULT(), ..Default::default() });
    job.append(unit, 0.0, egui::TextFormat { font_id: FontId::proportional(z(10.0)), color: TEXT_DEFAULT(), valign: Align::BOTTOM, ..Default::default() });
    ui.add_sized([z(63.0), z(20.0)], egui::Label::new(job).selectable(false).halign(Align::LEFT));
    let max = if lim > 0.0 { lim } else if req > 0.0 { (req * 2.0).max(val * 1.1) } else { 0.0 };
    let (r, _) = ui.allocate_exact_size(egui::vec2(u(96.0), 8.0), Sense::hover());
    if max <= 0.0 {
        return;
    }
    ui.painter().rect_filled(r, CornerRadius::same(4), BG_MUTED());
    let frac = (val / max).clamp(0.0, 1.0) as f32;
    let over = !node && req > 0.0 && val > req;
    let color = if over { WARNING() } else if cpu { CPU_BAR() } else { MEM_BAR() };
    let fill = egui::Rect::from_min_size(r.min, egui::vec2((r.width() * frac).max(4.0), r.height()));
    ui.painter().rect_filled(fill, CornerRadius::same(4), color);
    if !node && req > 0.0 {
        let x = r.left() + r.width() * ((req / max).clamp(0.0, 1.0) as f32);
        ui.painter().vline(x, (r.top() - 3.0)..=(r.bottom() + 3.0), Stroke::new(1.5, TEXT_MUTED()));
    }
}

/// One "Usage / Capacity" or "Requests / Allocatable" line.
fn ratio_row(ui: &mut Ui, label: &str, frac: f64, text: String, color: Color32, thick: bool) {
    let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(20.0)), Sense::hover());
    let p = ui.painter();
    pg::label_at(ui, p, r.left_center(), label, 13.5, TEXT_DEFAULT(), u(64.0));
    p.text(egui::pos2(r.left() + u(104.0), r.center().y), egui::Align2::RIGHT_CENTER, format!("{:.0}%", frac * 100.0), FontId::proportional(z(13.5)), TEXT_DEFAULT());
    let x = r.left() + u(112.0);
    let h = if thick { 10.0 } else { 3.0 };
    let bar = egui::Rect::from_min_max(egui::pos2(x, r.center().y - h / 2.0), egui::pos2((r.right() - u(118.0)).max(x + 20.0), r.center().y + h / 2.0));
    p.rect_filled(bar, CornerRadius::same(5), BG_MUTED());
    p.rect_filled(egui::Rect::from_min_size(bar.min, egui::vec2(bar.width() * frac.clamp(0.0, 1.0) as f32, h)), CornerRadius::same(5), color);
    pg::label_at(ui, p, egui::pos2(bar.right() + 8.0, r.center().y), &text, 13.0, TEXT_DEFAULT(), u(110.0));
}

/// Count rows by the text of one cell. Patterns are matched in order; "*" catches the rest.
fn count_by(rows: &[Row], cell: usize, pats: &[(&str, Color32, &str)]) -> Vec<(Color32, usize, String)> {
    let mut counts = vec![0usize; pats.len()];
    for r in rows {
        let t = r.cells.get(cell).map(|c| c.text.as_str()).unwrap_or("");
        if let Some(i) = pats.iter().position(|p| p.0 == t || p.0 == "*") {
            counts[i] += 1;
        }
    }
    pats.iter().zip(counts).filter(|(_, n)| *n > 0).map(|(p, n)| (p.1, n, p.2.to_string())).collect()
}

/// Split rows into "good" (green), "idle" (grey) and the rest (amber).
fn split(rows: &[Row], good: impl Fn(&Row) -> bool, good_label: &str, idle: impl Fn(&Row) -> bool, idle_label: &str) -> Vec<(Color32, usize, String)> {
    let (mut g, mut i, mut o) = (0, 0, 0);
    for r in rows {
        if idle(r) {
            i += 1;
        } else if good(r) {
            g += 1;
        } else {
            o += 1;
        }
    }
    let mut v = vec![];
    if g > 0 {
        v.push((SUCCESS(), g, good_label.to_string()));
    }
    if o > 0 {
        v.push((WARNING(), o, "Progressing".to_string()));
    }
    if i > 0 {
        v.push((TEXT_SUBTLE(), i, idle_label.to_string()));
    }
    v
}

/// A kind's health: title, a segmented bar and coloured counts.
fn health_card(ui: &mut Ui, title: &str, parts: Option<Vec<(Color32, usize, String)>>) {
    let h = 46.0 + 20.0 * parts.as_ref().map(|p| p.len()).unwrap_or(1).max(1) as f32;
    ui.allocate_ui_with_layout(egui::vec2(206.0, h), Layout::top_down(Align::Min), |ui| {
        ui.set_width(206.0);
        ui.spacing_mut().item_spacing.y = 4.0;
        ui.label(RichText::new(title).size(z(17.0)).color(TEXT_DEFAULT()));
        let (r, _) = ui.allocate_exact_size(egui::vec2(206.0, 11.0), Sense::hover());
        match &parts {
            None => {
                ui.painter().rect_filled(r, CornerRadius::same(3), BG_CARD());
                ui.spinner();
            }
            Some(p) if p.is_empty() || p.iter().all(|x| x.1 == 0) => {
                ui.painter().rect_filled(r, CornerRadius::same(3), BG_CARD());
                dashed_rect(ui.painter(), r, BORDER_DEFAULT());
            }
            Some(p) => {
                let total: usize = p.iter().map(|x| x.1).sum();
                let mut x = r.left();
                for (i, (c, n, _)) in p.iter().enumerate() {
                    let w = r.width() * *n as f32 / total as f32;
                    let seg = egui::Rect::from_min_max(egui::pos2(x, r.top()), egui::pos2((x + w).min(r.right()), r.bottom()));
                    let cr = CornerRadius {
                        nw: if i == 0 { 3 } else { 0 },
                        sw: if i == 0 { 3 } else { 0 },
                        ne: if i + 1 == p.len() { 3 } else { 0 },
                        se: if i + 1 == p.len() { 3 } else { 0 },
                    };
                    ui.painter().rect_filled(seg, cr, *c);
                    x += w;
                }
                ui.add_space(4.0);
                for (c, n, label) in p {
                    if label.is_empty() {
                        ui.label(RichText::new("No access").size(z(14.0)).color(*c));
                        continue;
                    }
                    ui.label(RichText::new(format!("{n} {label}")).size(z(14.0)).color(*c));
                }
            }
        }
    });
}

fn dashed_rect(p: &egui::Painter, r: egui::Rect, color: Color32) {
    let s = Stroke::new(1.0, color);
    let pts = [r.left_top(), r.right_top(), r.right_bottom(), r.left_bottom(), r.left_top()];
    for w in pts.windows(2) {
        p.extend(egui::Shape::dashed_line(&[w[0], w[1]], s, 4.0, 3.0));
    }
}

/// The kind an event is about, by its Kubernetes name.
fn event_kind(name: &str) -> Option<Kind> {
    let plural = match name {
        n if n.ends_with('y') => format!("{}ies", &n[..n.len() - 1]),
        n if n.ends_with('s') => format!("{n}es"),
        n => format!("{n}s"),
    };
    GROUPS.iter().flat_map(|g| g.1.iter().copied()).find(|k| format!("{k:?}") == plural)
}

/// The dashed empty-state box from the overview pages.
fn empty_box(ui: &mut Ui, height: f32, add: impl FnOnce(&mut Ui)) {
    let w = ui.available_width();
    let (r, _) = ui.allocate_exact_size(egui::vec2(w, height), Sense::hover());
    ui.painter().rect_filled(r, CornerRadius::same(2), BG_CARD());
    dashed_rect(ui.painter(), r, BORDER_DEFAULT());
    let mut child = ui.new_child(egui::UiBuilder::new().max_rect(r.shrink(14.0)).layout(Layout::top_down(Align::Center)));
    child.add_space((height / 2.0 - 26.0).max(0.0));
    add(&mut child);
}

/// Open Terminal.app with kubectl pointed at a context (the overview's ">_" button).
// ---------------- UI ----------------

fn section_label(ui: &mut Ui, text: &str) {
    ui.add_space(10.0);
    ui.label(RichText::new(text).size(z(11.0)).color(TEXT_PLACEHOLDER()).strong());
    ui.add_space(2.0);
}

/// A list row's name: the one place a click opens it (the rest of the row is for ticking and its menu).
pub(crate) fn name_link(ui: &mut Ui, name: &str) -> egui::Response {
    let l = ui.add(egui::Label::new(RichText::new(name).color(PRIMARY_TEXT()).size(z(14.0))).truncate().selectable(false).sense(Sense::click()));
    if l.hovered() {
        ui.painter().hline(l.rect.x_range(), l.rect.bottom() - 1.0, Stroke::new(1.0, PRIMARY_TEXT()));
    }
    l.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A sidebar entry: white text, grey rounded background when open.
fn nav_item(ui: &mut Ui, selected: bool, label: &str, suffix: Option<&str>) -> bool {
    nav_item_star(ui, selected, label, suffix, None).0
}

/// The same with a star at its right end when `star` is given: shown under the mouse, and always when it's on
/// (`Some(true)`). Returns (the entry was clicked, the star was).
fn nav_item_star(ui: &mut Ui, selected: bool, label: &str, suffix: Option<&str>, star: Option<bool>) -> (bool, bool) {
    let h = u(25.5);
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), h), Sense::click());
    let bg = if selected {
        BG_SELECTED()
    } else if resp.hovered() {
        BG_HOVER()
    } else {
        Color32::TRANSPARENT
    };
    ui.painter().rect_filled(rect, CornerRadius::same(5), bg);
    let g = ui.painter().layout_no_wrap(label.to_string(), FontId::proportional(z(14.0)), TEXT_DEFAULT());
    let w = g.size().x;
    ui.painter().galley(rect.left_center() + egui::vec2(8.0, -g.size().y / 2.0), g, TEXT_DEFAULT());
    if let Some(sfx) = suffix {
        ui.painter().text(
            rect.left_center() + egui::vec2(8.0 + w + 5.0, 1.0),
            egui::Align2::LEFT_CENTER,
            sfx,
            FontId::proportional(z(11.0)),
            TEXT_SUBTLE(),
        );
    }
    let mut star_hit = false;
    if let Some(on) = star {
        // Over the row: the star takes the click on its own spot.
        let spot = egui::Rect::from_center_size(egui::pos2(rect.right() - u(13.0), rect.center().y), egui::vec2(u(22.0), h));
        let near = ui.rect_contains_pointer(rect);
        if on || near {
            let r = ui.interact(spot, resp.id.with("star"), Sense::click());
            let hot = r.hovered();
            let color = if on { WARNING() } else if hot { TEXT_DEFAULT() } else { TEXT_PLACEHOLDER() };
            ui.painter().text(spot.center(), egui::Align2::CENTER_CENTER, if on || hot { "★" } else { "☆" }, FontId::proportional(z(13.0)), color);
            star_hit = r.on_hover_text(if on { "Take out of Favorites" } else { "Put in Favorites" }).clicked();
        }
    }
    (resp.clicked() && !star_hit, star_hit)
}

fn chip(ui: &mut Ui, text: &str) {
    Frame::new()
        .fill(BG_MUTED())
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin::symmetric(6, 2))
        .show(ui, |ui| {
            ui.set_max_width(460.0);
            ui.add(egui::Label::new(RichText::new(text).size(z(11.5)).color(TEXT_MUTED())).truncate());
        });
}

/// A label at the left of a space of its own.
fn left_cell(ui: &mut Ui, size: [f32; 2], label: egui::Label) -> egui::Response {
    ui.allocate_ui_with_layout(egui::vec2(size[0], size[1]), Layout::left_to_right(Align::Center), |ui| {
        ui.set_min_size(egui::vec2(size[0], size[1]));
        ui.set_max_width(size[0]);
        ui.add(label)
    })
    .inner
}

fn kv(ui: &mut Ui, k: &str, v: impl Into<String>) {
    ui.horizontal_wrapped(|ui| {
        left_cell(ui, [z(130.0), z(18.0)], egui::Label::new(RichText::new(k).color(TEXT_SUBTLE())));
        let v: String = v.into();
        ui.label(RichText::new(if v.is_empty() { "-".to_string() } else { v }).color(TEXT_DEFAULT()));
    });
}

fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    Frame::new()
        .fill(BG_CARD())
        .stroke(Stroke::new(1.0, BORDER_SUBTLE()))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

fn button(ui: &mut Ui, text: &str, primary: bool, danger: bool) -> bool {
    let (fill, fg) = if danger {
        (DANGER_BG(), Color32::WHITE)
    } else if primary {
        (PRIMARY(), Color32::WHITE)
    } else {
        (BG_MUTED(), TEXT_DEFAULT())
    };
    ui.add(
        egui::Button::new(RichText::new(text).color(fg))
            .fill(fill)
            .stroke(Stroke::new(1.0, if primary || danger { fill } else { BORDER_DEFAULT() }))
            .corner_radius(CornerRadius::same(6)),
    )
    .clicked()
}

impl KubedogApp {
    // ---------------- start screen ----------------

    /// The first screen: pick one or more contexts, then Connect.
    /// Save settings (never in screenshot mode).
    fn save(&self) {
        set_ctx_look(&self.prefs);
        grafana::set_shared(&self.prefs.authorities);
        if self.screenshot.is_none() {
            save_prefs(&self.prefs);
        }
    }

    /// Keep the page, namespace, zoom and folded groups in the settings file as they change, so the
    /// next start carries on from here (never in screenshot mode).
    fn remember_session(&mut self, ctx: &egui::Context) {
        if self.screenshot.is_some() || !self.connected || !self.session_restored {
            return;
        }
        let mut collapsed: Vec<String> = self.collapsed.iter().cloned().collect();
        collapsed.sort();
        let now = Session {
            view: view_name(self.view),
            ns: self.ns_filter.clone(),
            ns_multi: self.ns_multi.clone(),
            ns_ctx: self.ns_ctx.clone(),
            zoom: (ctx.zoom_factor() * 100.0).round() / 100.0,
            collapsed,
        };
        if now != self.prefs.session {
            self.prefs.session = now;
            self.save();
        }
    }

    /// Use the font in the settings, and measure the columns again (its letters differ in width).
    fn apply_font(&mut self) {
        crate::theme::install_font(&self.egui_ctx, &self.prefs.font);
        self.list_cache = None;
    }

    /// Switch the colours and the text size to the ones in the settings.
    fn apply_theme(&self) {
        let theme = match self.prefs.theme.as_str() {
            "auto" => if self.system_light { "light" } else { "dark" },
            t => t,
        };
        crate::theme::set_look(theme, &self.prefs.accent);
        crate::theme::set_text_size(self.prefs.text_size);
        crate::theme::install(&self.egui_ctx);
    }

    fn refresh_every(&self) -> Duration {
        Duration::from_secs(self.prefs.refresh_secs.max(1))
    }

    fn is_starred(&self, ns: &str) -> bool {
        self.prefs.starred_namespaces.iter().any(|n| n == ns)
    }

    fn toggle_star(&mut self, ns: &str) {
        if let Some(i) = self.prefs.starred_namespaces.iter().position(|n| n == ns) {
            self.prefs.starred_namespaces.remove(i);
        } else {
            self.prefs.starred_namespaces.push(ns.to_string());
            self.prefs.starred_namespaces.sort();
        }
        self.save();
    }

    fn connect(&mut self) {
        let mut chosen: Vec<String> = self
            .contexts
            .iter()
            .filter(|c| self.picker.contains(&c.name))
            .map(|c| c.name.clone())
            .collect();
        if chosen.is_empty() {
            return;
        }
        chosen.dedup();
        // Long names must get a short one first (not in screenshot mode, which saves nothing).
        if self.screenshot.is_none() || std::env::var("KUBEDOG_SHOT_NAMES").is_ok() {
            let long: Vec<String> = chosen.iter().filter(|c| ctx_label(c).chars().count() > MAX_CLUSTER_NAME).cloned().collect();
            if !long.is_empty() {
                let mut taken: Vec<String> = chosen.iter().filter(|c| !long.contains(c)).map(|c| ctx_label(c)).collect();
                let names = long
                    .into_iter()
                    .map(|c| {
                        let server = self.contexts.iter().find(|x| x.name == c).map(|x| x.server.clone()).unwrap_or_default();
                        let s = suggest_short_name(&c, &server, &taken);
                        taken.push(s.clone());
                        (c, s)
                    })
                    .collect();
                self.dialog = Some(Dialog::NameClusters { names });
                return;
            }
        }
        // The same clusters as last time: carry on with the page and namespace left open.
        let same = {
            let (mut a, mut b) = (chosen.clone(), self.prefs.contexts.clone());
            a.sort();
            b.sort();
            !a.is_empty() && a == b
        };
        self.active = chosen;
        self.connected = true;
        // Changes allowed from the start where Settings says so (never in a picture, never with demo data).
        if self.screenshot.is_none() && !self.demo {
            for c in &self.active {
                if self.prefs.open_all || self.prefs.open_at_start.contains(c) {
                    self.unlocked.insert(c.clone());
                }
            }
        }
        if self.screenshot.is_none() {
            self.prefs.contexts = self.active.clone();
            self.save();
        }
        self.view = first_page_view(&self.prefs.first_page);
        self.ns_filter = None;
        self.ns_multi.clear();
        self.ns_ctx = None;
        if same && !self.session_restored {
            let s = self.prefs.session.clone();
            if let Some(v) = view_from_name(&s.view).filter(|v| !powers::power_of(*v).map(|p| self.power_off(p)).unwrap_or(false)) {
                self.view = v;
            }
            self.ns_ctx = s.ns_ctx.filter(|c| self.active.len() > 1 && self.active.contains(c));
            self.ns_filter = s.ns;
            if s.ns_multi.len() > 1 {
                self.set_ns_choice(s.ns_multi);
            }
        }
        self.session_restored = true;
        self.back.clear();
        self.forward.clear();
        self.close_detail();
        self.refresh_current(true);
    }

    /// Open a saved group: its contexts that are still in the kubeconfig files.
    fn open_group(&mut self, i: usize) {
        let Some(g) = self.prefs.groups.get(i) else { return };
        let names: HashSet<String> = g.contexts.iter().filter(|n| self.contexts.iter().any(|c| &c.name == *n)).cloned().collect();
        if names.is_empty() {
            return;
        }
        if self.connected {
            self.disconnect();
        }
        self.picker = names;
        self.connect();
    }

    fn disconnect(&mut self) {
        self.close_detail();
        self.connected = false;
        self.picker = self.active.iter().cloned().collect();
    }

    // ---------------- sidebar ----------------

    fn sidebar(&mut self, ui: &mut Ui) {
        // Title-bar row: window buttons sit at the left; back/forward at the right.
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.set_height(22.0);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(2.0);
                if chevron(ui, false, !self.forward.is_empty()).on_hover_text("Forward (⌘→ or the mouse's forward button)").clicked() {
                    self.go_forward();
                }
                ui.add_space(10.0);
                if chevron(ui, true, self.can_step_back()).on_hover_text(if cfg!(target_os = "macos") { "Back (⌘[, ⌘← or the mouse's back button)" } else { "Back (Alt+← or the mouse's back button)" }).clicked() {
                    self.back_pressed();
                }
                drag_area(ui, ui.available_width(), 22.0);
            });
        });
        ui.add_space(4.0);

        // Search: a box at the top of the sidebar (⌘K).
        {
            let (r, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(28.0)), Sense::click());
            let p = ui.painter();
            p.rect_stroke(r, CornerRadius::same(6), Stroke::new(1.0, if resp.hovered() { BORDER_DEFAULT() } else { BORDER_SUBTLE() }), egui::StrokeKind::Inside);
            p.text(r.left_center() + egui::vec2(10.0, 0.0), egui::Align2::LEFT_CENTER, "🔍  Search", FontId::proportional(z(13.5)), TEXT_PLACEHOLDER());
            p.text(r.right_center() - egui::vec2(10.0, 0.0), egui::Align2::RIGHT_CENTER, "⌘K", FontId::proportional(z(12.0)), TEXT_PLACEHOLDER());
            if resp.clicked() && self.connected {
                self.open_search();
            }
            ui.add_space(6.0);
        }
        // Connected context(s); click to go back to the context picker.
        let label = if self.active.len() == 1 { ctx_label(&self.active[0]) } else { format!("{} clusters", self.active.len()) };
        let all_locked = self.active.iter().all(|c| !self.unlocked.contains(c));
        ui.horizontal(|ui| {
            // The name takes what the padlock leaves: together they are exactly as wide as the sidebar.
            let lock_w = z(18.0);
            let (r, resp) = ui.allocate_exact_size(egui::vec2((ui.available_width() - lock_w - ui.spacing().item_spacing.x).max(40.0), 32.0), Sense::click());
            if resp.hovered() {
                ui.painter().rect_filled(r, CornerRadius::same(6), BG_HOVER());
            }
            let icon = egui::Rect::from_center_size(r.left_center() + egui::vec2(16.0, 0.0), egui::vec2(24.0, 24.0));
            ctx_mark(ui.painter(), icon, self.active.first().map(|s| s.as_str()).unwrap_or(""));
            let g = ui.painter().layout_no_wrap(fit(ui, &label, r.width() - 40.0, z(15.0)), FontId::proportional(z(15.0)), TEXT_DEFAULT());
            ui.painter().galley(r.left_center() + egui::vec2(34.0, -g.size().y / 2.0), g, TEXT_DEFAULT());
            if resp.on_hover_text(format!("{}\nClick to switch contexts", self.active.join("\n"))).clicked() {
                self.disconnect();
            }
            let (spot, lock) = ui.allocate_exact_size(egui::vec2(lock_w, z(18.0)), Sense::click());
            padlock(ui.painter(), spot.center(), z(13.0), all_locked, if all_locked { TEXT_SUBTLE() } else { WARNING() });
            if lock
                .on_hover_text(if all_locked {
                    "Protected: changes are blocked. Click to allow changes for this session."
                } else {
                    "Changes allowed. Click to protect again."
                })
                .clicked()
            {
                for c in self.active.clone() {
                    if all_locked {
                        self.unlocked.insert(c);
                    } else {
                        self.unlocked.remove(&c);
                    }
                }
            }
        });
        // Several clusters: one row each in its colour (the same colour marks its rows in every list).
        // Clicking one shows only that cluster; clicking it again shows them all.
        if self.active.len() > 1 {
            ui.add_space(2.0);
            for c in self.active.clone() {
                let on = self.ns_ctx.as_deref() == Some(c.as_str());
                let (r, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(24.0)), Sense::click());
                let p = ui.painter();
                if on {
                    p.rect_filled(r, CornerRadius::same(5), BG_SELECTED());
                } else if resp.hovered() {
                    p.rect_filled(r, CornerRadius::same(5), BG_HOVER());
                }
                p.rect_filled(egui::Rect::from_min_size(r.left_top() + egui::vec2(10.0, 5.0), egui::vec2(4.0, 14.0)), CornerRadius::same(2), context_color(&c));
                let locked = !self.unlocked.contains(&c);
                let g = p.layout_no_wrap(fit(ui, &ctx_label(&c), r.width() - 48.0, z(13.0)), FontId::proportional(z(13.0)), if on { TEXT_DEFAULT() } else { TEXT_MUTED() });
                p.galley(egui::pos2(r.left() + 22.0, r.center().y - g.size().y / 2.0), g, TEXT_MUTED());
                padlock(&p, r.right_center() - egui::vec2(8.0 + z(5.0), 0.0), z(11.0), locked, if locked { TEXT_PLACEHOLDER() } else { WARNING() });
                if resp.on_hover_text(format!("{c}\nClick to show only this cluster")).clicked() {
                    self.ns_filter = None;
                    self.ns_ctx = if on { None } else { Some(c.clone()) };
                }
            }
        }
        ui.add_space(8.0);

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            if !self.port_forwards.is_empty() {
                let n = self.port_forwards.iter().filter(|p| p.child.is_some()).count();
                if self.group_header(ui, "Port Forwards", "⇄") {
                    if nav_item(ui, self.view == View::PortForwards && self.selected.is_none(), &format!("{n} active"), None) {
                        self.set_view(View::PortForwards);
                    }
                }
                ui.add_space(14.0);
            }
            // Favorites: starred pages.
            self.sidebar_favs(ui);
            self.sidebar_parts(ui);
            if nav_item(ui, self.view == View::Settings && self.selected.is_none(), "⚙  Settings", None) {
                self.set_view(View::Settings);
            }
            ui.add_space(12.0);
        });
    }

    /// Settings: terminal choice, filters, starred namespaces (Kubedog additions).
    /// A collapsible group heading. Returns whether the group is open.
    fn group_header(&mut self, ui: &mut Ui, title: &str, icon: &str) -> bool {
        let open = !self.collapsed.contains(title);
        let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(26.0)), Sense::click());
        let p = ui.painter();
        p.text(rect.left_center() + egui::vec2(4.0, 0.0), egui::Align2::LEFT_CENTER, icon, FontId::proportional(z(12.0)), TEXT_SUBTLE());
        p.text(rect.left_center() + egui::vec2(22.0, 0.0), egui::Align2::LEFT_CENTER, title, FontId::proportional(z(13.5)), TEXT_SUBTLE());
        if open || resp.hovered() {
            p.text(
                rect.right_center() - egui::vec2(8.0, 0.0),
                egui::Align2::RIGHT_CENTER,
                if open { "⌄" } else { "›" },
                FontId::proportional(z(13.0)),
                TEXT_SUBTLE(),
            );
        }
        if resp.clicked() {
            if open {
                self.collapsed.insert(title.to_string());
            } else {
                self.collapsed.remove(title);
            }
        }
        open
    }

    // ---------------- navigation ----------------

    fn navigate(&mut self, view: View, selected: Option<Selected>) {
        let cur = Nav { view: self.view, selected: self.selected.clone() };
        let next = Nav { view, selected: selected.clone() };
        if cur == next {
            return;
        }
        self.back.push(cur);
        if self.back.len() > 100 {
            self.back.remove(0);
        }
        self.forward.clear();
        self.apply_nav(next);
    }

    fn apply_nav(&mut self, nav: Nav) {
        if self.view != nav.view {
            self.custom_sel = None;
            if matches!(nav.view, View::Op(_)) && matches!(self.view, View::Op(_)) {
                self.powers.sel = None;
            }
            self.sort = (None, true);
            // Filter link on: one filter for every page except Nodes, which keeps its own.
            // Off: each page loses its filter when you leave it.
            let from_nodes = self.view == View::Resource(Kind::Nodes);
            let to_nodes = nav.view == View::Resource(Kind::Nodes);
            if self.prefs.shared_filter {
                if from_nodes && !to_nodes {
                    self.node_filter = std::mem::take(&mut self.search);
                    self.search = std::mem::take(&mut self.filter_stash);
                } else if to_nodes && !from_nodes {
                    self.filter_stash = std::mem::take(&mut self.search);
                    self.search = std::mem::take(&mut self.node_filter);
                }
            } else {
                self.search.clear();
                self.filter_stash.clear();
                self.node_filter.clear();
            }
        }
        self.view = nav.view;
        match nav.selected {
            Some(s) => self.open_object(s),
            None => self.close_object(),
        }
        self.refresh_current(false);
    }

    /// The page open within this one (a custom object, a database cluster, a machine), if any.
    fn sub_page(&self) -> Option<String> {
        match self.view {
            View::Custom(i) => self.custom_sel.as_ref().filter(|s| s.idx == i).map(|s| format!("{s:?}")),
            View::Postgres => self.pg_sel.as_ref().map(|s| format!("{s:?}")),
            View::Elastic => self.es_sel.as_ref().map(|s| format!("{s:?}")),
            View::Pulsar => self.pu_sel.as_ref().map(|s| format!("{s:?}")),
            View::Observatory => self.grafana.sel.as_ref().map(|s| format!("{s:?}")),
            View::Proxmox => self.proxmox.sel.as_ref().map(|s| format!("{s:?}")),
            View::NetLab => self.netlab_sub(),
            View::Op(i) => self.powers.sel.as_ref().map(|s| format!("{s:?}")).or_else(|| self.catalog.pick.as_ref().filter(|_| powers::OPS.get(i as usize).map(|o| o.id) == Some("openshift") && self.powers.os_tab == 5).map(|p| format!("{p:?}"))),
            View::Incident => self.incident.sel.as_ref().map(|s| format!("{s:?}")),
            _ => None,
        }
    }

    fn can_step_back(&self) -> bool {
        !self.back.is_empty() || self.selected.is_some() || self.sub_page().is_some()
    }

    fn close_sub(&mut self) {
        match self.view {
            View::Postgres => self.pg_sel = None,
            View::Elastic => self.es_sel = None,
            View::Pulsar => self.pu_sel = None,
            View::Observatory => self.grafana.sel = None,
            View::Proxmox => self.proxmox.sel = None,
            View::NetLab => self.netlab_close(),
            View::Op(_) => {
                if self.powers.sel.take().is_none() {
                    self.catalog.pick = None;
                }
            }
            View::Incident => self.incident.sel = None,
            _ => self.custom_sel = None,
        }
    }

    /// Back, the one and only: the ← on a page, Esc on an object, the mouse's back button, ⌘[ and ⌘←
    /// (Alt+← elsewhere), the menu and ‹. From an object to its list, out of a page within a page, else to
    /// where you came from. (The object isn't put in the way back, so pressing on doesn't go in circles.)
    fn back_pressed(&mut self) {
        if !self.connected || self.dialog.is_some() || self.palette.is_some() {
            return;
        }
        if self.selected.is_some() {
            let list = Nav { view: self.view, selected: None };
            if self.back.last() == Some(&list) {
                self.back.pop();
            }
            self.forward.push(Nav { view: self.view, selected: self.selected.clone() });
            self.apply_nav(list);
        } else if self.sub_page().is_some() {
            self.close_sub();
        } else {
            self.go_back();
        }
    }

    fn forward_pressed(&mut self) {
        if self.connected && self.dialog.is_none() && self.palette.is_none() {
            self.go_forward();
        }
    }

    fn go_back(&mut self) {
        if let Some(n) = self.back.pop() {
            self.forward.push(Nav { view: self.view, selected: self.selected.clone() });
            self.apply_nav(n);
        }
    }

    fn go_forward(&mut self) {
        if let Some(n) = self.forward.pop() {
            self.back.push(Nav { view: self.view, selected: self.selected.clone() });
            self.apply_nav(n);
        }
    }

    fn count_for(&self, k: Kind) -> Option<usize> {
        let mut total = 0;
        let mut any = false;
        for c in &self.active {
            if let Some(l) = self.lists.get(&Self::list_key(c, k)) {
                if l.fetched.is_some() && l.error.is_none() {
                    any = true;
                    total += l
                        .rows
                        .iter()
                        .filter(|r| !k.namespaced() || self.ns_ok(&r.ns))
                        .count();
                }
            }
        }
        any.then_some(total)
    }

    /// The bar above a list: namespace chip, filter box, "● N kind" and refresh.
    /// The namespace menu with several clusters open: each cluster as a heading (pick it to see
    /// only that cluster), its namespaces under it. Returns whether to close.
    fn ns_menu_by_cluster(&mut self, ui: &mut Ui) -> bool {
        let r = filter_box(ui, &mut self.ns_search, "Search namespaces", 220.0);
        if !r.has_focus() && self.ns_search.is_empty() && ui.input(|i| i.events.iter().any(|e| matches!(e, egui::Event::Text(_)))) {
            r.request_focus();
        }
        let mut close = false;
        let none = !self.ns_any() && self.ns_ctx.is_none();
        if ui.selectable_label(none, "All clusters, all namespaces").clicked() {
            self.set_ns_choice(vec![]);
            self.ns_ctx = None;
            close = true;
        }
        let mut toggle: Option<String> = None;
        for c in self.active.clone() {
            ui.separator();
            let on = self.ns_filter.is_none() && self.ns_ctx.as_deref() == Some(c.as_str());
            let r = ui
                .horizontal(|ui| {
                    let (d, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), Sense::hover());
                    ui.painter().rect_filled(d, CornerRadius::same(3), context_color(&c));
                    ui.selectable_label(on, RichText::new(format!("{}  (all)", ctx_label(&c))).strong())
                })
                .inner;
            if r.on_hover_text(format!("Only {}", c)).clicked() {
                self.ns_filter = None;
                self.ns_ctx = Some(c.clone());
                close = true;
            }
            let mut list = self.namespaces.get(&c).cloned().unwrap_or_default();
            list.sort_by_key(|n| (!self.is_starred(n), n.clone()));
            if list.is_empty() {
                ui.label(RichText::new("    (namespaces not read yet)").size(z(12.0)).color(TEXT_PLACEHOLDER()));
            }
            let q = self.ns_search.to_lowercase();
            for n in list.into_iter().filter(|n| q.is_empty() || n.to_lowercase().contains(&q)) {
                close |= self.ns_menu_row(ui, &n, Some(&c), &mut toggle);
            }
        }
        if let Some(n) = toggle {
            self.toggle_star(&n);
        }
        close
    }

    /// The top of the namespace menu: a search box and "All namespaces". Returns whether to close.
    fn ns_menu_top(&mut self, ui: &mut Ui) -> bool {
        let r = filter_box(ui, &mut self.ns_search, "Search namespaces", 220.0);
        if !r.has_focus() && self.ns_search.is_empty() && ui.input(|i| i.events.iter().any(|e| matches!(e, egui::Event::Text(_)))) {
            r.request_focus();
        }
        let all = !self.ns_any() && self.ns_ctx.is_none();
        let picked = ui.selectable_label(all, "All namespaces").clicked();
        if picked {
            self.set_ns_choice(vec![]);
            self.ns_ctx = None;
        }
        picked
    }

    /// One namespace in the menu: a tick box (add or remove it), the name (only this one), a star.
    /// Returns whether the menu should close.
    fn ns_menu_row(&mut self, ui: &mut Ui, n: &str, ctx: Option<&str>, toggle: &mut Option<String>) -> bool {
        let mut close = false;
        ui.horizontal(|ui| {
            if ctx.is_some() {
                ui.add_space(14.0);
            }
            let mut on = self.ns_ok(n) && self.ns_any() && ctx.map(|c| self.ns_ctx.as_deref().map(|x| x == c).unwrap_or(true)).unwrap_or(true);
            if ui.checkbox(&mut on, "").on_hover_text("Tick several to see them together").changed() {
                self.ns_toggle(n);
                if let Some(c) = ctx {
                    if self.ns_ctx.as_deref() != Some(c) && self.ns_multi.len() <= 1 {
                        self.ns_ctx = Some(c.to_string());
                    }
                    if self.ns_multi.len() > 1 {
                        self.ns_ctx = None;
                    }
                }
            }
            let only = self.ns_filter.as_deref() == Some(n);
            if ui.selectable_label(only, n).on_hover_text("Only this namespace").clicked() {
                self.set_ns_choice(vec![n.to_string()]);
                if let Some(c) = ctx {
                    self.ns_ctx = Some(c.to_string());
                }
                close = true;
            }
            let st = self.is_starred(n);
            if ui.add(egui::Button::new(RichText::new(if st { "★" } else { "☆" }).color(if st { WARNING() } else { TEXT_PLACEHOLDER() })).frame(false)).on_hover_text(if st { "Unstar" } else { "Star this namespace" }).clicked() {
                *toggle = Some(n.to_string());
            }
        });
        close
    }

    fn header(&mut self, ui: &mut Ui, namespaced: bool, count: Option<String>, show_filter: bool) {
        ui.horizontal(|ui| {
            ui.set_height(u(32.0));
            if namespaced {
                let mut all: Vec<String> = self
                    .active
                    .iter()
                    .flat_map(|c| self.namespaces.get(c).cloned().unwrap_or_default())
                    .collect();
                all.sort();
                all.dedup();
                let multi = self.active.len() > 1;
                let current = match (&self.ns_filter, &self.ns_ctx) {
                    (None, _) if !self.ns_multi.is_empty() => format!("{} namespaces", self.ns_multi.len()),
                    (Some(n), _) => n.clone(),
                    (None, Some(c)) if multi => format!("All of {}", ctx_label(c)),
                    _ => "All namespaces".into(),
                };
                Frame::new()
                    .stroke(Stroke::new(1.0, BORDER_SUBTLE()))
                    .corner_radius(CornerRadius::same(6))
                    .inner_margin(Margin::symmetric(4, 2))
                    .show(ui, |ui| {
                        ui.set_min_width(186.0);
                        ui.horizontal(|ui| {
                            // Which cluster the choice belongs to, when several are open.
                            if let (true, Some(c)) = (multi, &self.ns_ctx) {
                                let (d, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), Sense::hover());
                                ui.painter().rect_filled(d, CornerRadius::same(3), context_color(c));
                            }
                            // Chip look: no button fill, the frame's border is the outline.
                            let w = &mut ui.visuals_mut().widgets;
                            for st in [&mut w.inactive, &mut w.hovered, &mut w.active, &mut w.open] {
                                st.weak_bg_fill = Color32::TRANSPARENT;
                                st.bg_fill = Color32::TRANSPARENT;
                                st.bg_stroke = Stroke::NONE;
                            }
                            let r = egui::ComboBox::from_id_salt("ns-filter")
                                .selected_text(RichText::new(truncate(&current, 22)).size(z(14.0)).color(TEXT_DEFAULT()))
                                .width(150.0)
                                .height(460.0)
                                .icon(|_, _, _, _| {})
                                // A click in the search box, on a tick box or on a star keeps it open; a name closes it.
                                .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
                                .show_ui(ui, |ui| {
                                    if multi {
                                        if self.ns_menu_by_cluster(ui) {
                                            ui.close();
                                        }
                                        return;
                                    }
                                    if self.ns_menu_top(ui) {
                                        ui.close();
                                    }
                                    // Starred namespaces first, then the rest. Tick several to see them together;
                                    // click a name to see only that one; ☆ stars it.
                                    let q = self.ns_search.to_lowercase();
                                    let (mut starred, mut rest): (Vec<String>, Vec<String>) = (vec![], vec![]);
                                    for n in all.iter().filter(|n| q.is_empty() || n.to_lowercase().contains(&q)).cloned() {
                                        if self.is_starred(&n) { starred.push(n) } else { rest.push(n) }
                                    }
                                    let mut toggle: Option<String> = None;
                                    {
                                        for (group, list) in [("Starred", &starred), ("All", &rest)] {
                                            if list.is_empty() {
                                                continue;
                                            }
                                            if group == "All" && !starred.is_empty() {
                                                ui.separator();
                                            }
                                            for n in list.iter() {
                                                if self.ns_menu_row(ui, n, None, &mut toggle) {
                                                    ui.close();
                                                }
                                            }
                                        }
                                    }
                                    if let Some(n) = toggle {
                                        self.toggle_star(&n);
                                    }
                                });
                            r.response.on_hover_text("Namespace");
                            // Test aid: draw the cluster-grouped namespace menu open for a screenshot.
                            if self.screenshot.is_some() && std::env::var("KUBEDOG_SHOT_NSMENU").is_ok() {
                                let at = ui.min_rect().left_bottom() + egui::vec2(0.0, 6.0);
                                egui::Area::new(egui::Id::new("shot-nsmenu")).fixed_pos(at).show(ui.ctx(), |ui| {
                                    Frame::popup(ui.style()).show(ui, |ui| {
                                        ui.set_width(240.0);
                                        if multi {
                                            egui::ScrollArea::vertical().max_height(420.0).show(ui, |ui| {
                                                self.ns_menu_by_cluster(ui);
                                            });
                                        } else {
                                            self.ns_menu_top(ui);
                                            let mut t = None;
                                            for n in all.iter().take(14) {
                                                self.ns_menu_row(ui, n, None, &mut t);
                                            }
                                        }
                                    });
                                });
                            }
                            if (self.ns_any() || self.ns_ctx.is_some())
                                && ui.add(egui::Button::new(RichText::new("×").size(z(17.0)).color(TEXT_SUBTLE())).frame(false)).on_hover_text("All namespaces").clicked()
                            {
                                self.ns_filter = None;
                                self.ns_multi.clear();
                                self.ns_ctx = None;
                            }
                        });
                    });
            }
            if show_filter {
                let r = filter_styled(ui, &mut self.search, "Filter", 292.0, 6, None);
                if self.focus_search {
                    r.request_focus();
                    self.focus_search = false;
                }
                // The link toggle: on keeps the filter across pages (Nodes has its own).
                let on = self.prefs.shared_filter;
                if link_toggle(ui, on)
                    .on_hover_text(if on {
                        "Filter linked: it stays as you move between pages (Nodes keeps its own). Click to unlink."
                    } else {
                        "Filter unlinked: each page starts with an empty filter. Click to link."
                    })
                    .clicked()
                {
                    self.prefs.shared_filter = !on;
                    if on {
                        self.filter_stash.clear();
                        self.node_filter.clear();
                    }
                    self.save();
                }
            }
            if let Some(c) = count {
                ui.add_space(8.0);
                let (r, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), Sense::hover());
                ui.painter().circle_filled(r.center(), 3.0, if self.is_loading() { WARNING() } else { SUCCESS() });
                ui.label(RichText::new(c).size(z(14.0)).color(TEXT_SUBTLE()));
            }
            if self.busy > 0 {
                ui.spinner();
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                // Settings, at the far right (⌘, too).
                let on = self.view == View::Settings;
                if columns::top_icon(ui, on, columns::draw_gear).on_hover_text("Settings (⌘,)").clicked() {
                    if on {
                        self.go_back();
                    } else {
                        self.navigate(View::Settings, None);
                    }
                }
                self.ai_top(ui);
                self.update_top(ui);
                if columns::top_icon(ui, false, columns::draw_refresh).on_hover_text("Refresh (⌘R)").clicked() {
                    self.refresh_current(true);
                }
                // Columns, on list pages: drag to order, tick to show.
                if let (View::Resource(kind), None) = (self.view, &self.selected) {
                    let popup_id = egui::Id::new("column-menu");
                    let open = egui::Popup::is_id_open(ui.ctx(), popup_id);
                    let b = columns::top_icon(ui, open, columns::draw_sliders).on_hover_text("Columns: show, hide and drag to reorder");
                    if std::mem::take(&mut self.open_columns) {
                        egui::Popup::open_id(ui.ctx(), popup_id);
                    }
                    let order = self.column_order(kind);
                    let on: HashSet<&str> = order.iter().copied().filter(|c| self.column_on(kind, c)).collect();
                    let changed = self.columns_changed(kind);
                    let mut act = None;
                    egui::Popup::from_toggle_button_response(&b)
                        .id(popup_id)
                        .align(egui::RectAlign::BOTTOM_END)
                        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
                        .show(|ui| act = columns::column_menu(ui, &order, |n| on.contains(n), changed, &mut self.prefs.hide_empty_columns));
                    // Test aid: draw the menu open for a screenshot (changes go nowhere; nothing is saved).
                    if self.screenshot.is_some() && std::env::var("KUBEDOG_SHOT_PICKER").is_ok() {
                        let mut he = self.prefs.hide_empty_columns;
                        egui::Area::new(egui::Id::new("shot-picker")).pivot(egui::Align2::RIGHT_TOP).fixed_pos(b.rect.right_bottom() + egui::vec2(0.0, 4.0)).order(egui::Order::Foreground).show(ui.ctx(), |ui| {
                            Frame::popup(ui.style()).show(ui, |ui| {
                                let _ = columns::column_menu(ui, &order, |n| on.contains(n), changed, &mut he);
                            });
                        });
                    }
                    if let Some(a) = act {
                        self.apply_column_action(kind, a);
                    }
                }
                // The empty part of this bar sits under the hidden title bar: let it move the window.
                drag_area(ui, ui.available_width(), 30.0);
            });
        });
        ui.add_space(4.0);
    }

    fn is_loading(&self) -> bool {
        if self.view == View::Helm {
            return self.active.iter().any(|c| self.helm.get(&format!("helm|{c}")).map(|h| h.0).unwrap_or(false));
        }
        if self.op_loading() || self.netlab_loading() {
            return true;
        }
        let kinds = self.view_kinds();
        self.active.iter().any(|c| kinds.iter().any(|k| self.lists.get(&Self::list_key(c, *k)).map(|l| l.loading).unwrap_or(false)))
    }

    /// Usage of one row: (cpu m, memory B) from metrics, or None when unknown.
    fn usage_of(&self, ctx: &str, kind: Kind, r: &Row, workload_usage: &HashMap<(String, Kind, String, String), (f64, f64)>) -> Option<(f64, f64)> {
        let m = self.metrics.get(ctx)?;
        match kind {
            Kind::Pods => m.pods.get(&(r.ns.clone(), r.name.clone())).copied(),
            Kind::Nodes => m.nodes.get(&r.name).copied(),
            _ => workload_usage.get(&(ctx.to_string(), kind, r.ns.clone(), r.name.clone())).copied(),
        }
    }

    fn workload_usage(&self, kind: Kind) -> HashMap<(String, Kind, String, String), (f64, f64)> {
        let mut out: HashMap<(String, Kind, String, String), (f64, f64)> = HashMap::new();
        if !matches!(kind, Kind::Deployments | Kind::StatefulSets | Kind::DaemonSets) {
            return out;
        }
        for c in &self.active {
            let (Some(m), Some(pods)) = (self.metrics.get(c), self.lists.get(&Self::list_key(c, Kind::Pods))) else { continue };
            for p in &pods.rows {
                if let (Some((k, w)), Some(u)) = (&p.workload, m.pods.get(&(p.ns.clone(), p.name.clone()))) {
                    if *k == kind {
                        let e = out.entry((c.clone(), kind, p.ns.clone(), w.clone())).or_default();
                        e.0 += u.0;
                        e.1 += u.1;
                    }
                }
            }
        }
        out
    }

    fn resource_view(&mut self, ui: &mut Ui, kind: Kind) {
        let multi = self.active.len() > 1;
        let mut errors: Vec<(String, String)> = vec![];
        let mut first_load = false;
        for c in &self.active {
            match self.lists.get(&Self::list_key(c, kind)) {
                Some(l) => {
                    if let Some(e) = &l.error {
                        errors.push((c.clone(), e.clone()));
                    }
                    if l.fetched.is_none() {
                        first_load = true;
                    }
                }
                None => first_load = true,
            }
        }

        let show_ns = kind.namespaced() && self.ns_filter.is_none();
        let all_cols = kind.all_columns();
        let mut layout = self.column_layout(kind);
        layout.retain(|c| match *c {
            "Context" => multi,
            "Namespace" => show_ns,
            _ => true,
        });

        let default_sort = if kind == Kind::Events { "Last Seen" } else { "Name" };
        let sort_col = self.sort.0.clone().filter(|c| layout.contains(&c.as_str())).unwrap_or_else(|| default_sort.to_string());
        let asc = self.sort.1;
        let has_usage = all_cols.contains(&"CPU Usage");
        // Everything the filtered, sorted rows depend on.
        let gens: Vec<u64> = self
            .active
            .iter()
            .map(|c| {
                let g = |k: Kind| self.lists.get(&Self::list_key(c, k)).map(|l| l.gen).unwrap_or(0);
                let m = if has_usage { self.metrics.get(c).map(|m| m.gen).unwrap_or(0) } else { 0 };
                g(kind) * 1_000_003 + if has_usage { g(Kind::Pods) * 1009 + m } else { 0 }
            })
            .collect();
        let key = format!("{kind:?}|{}|{:?}|{:?}|{:?}|{sort_col}|{asc}|{:?}|{gens:?}", self.search, self.ns_filter, self.ns_multi, self.ns_ctx, self.active);
        let can = picks::verbs(kind);
        let pickable = !can.is_empty();
        let pick_of = picks::What::Kind(kind);
        let mut rebuilt = false;
        let mut cache = match self.list_cache.take() {
            Some(c) if c.key == key => c,
            _ => {
                rebuilt = true;
                let t = Instant::now();
                let c = self.build_list_cache(kind, key, &sort_col, asc);
                frame_timing::rebuilt(t.elapsed(), c.rows.len());
                c
            }
        };
        if pickable {
            self.picks_begin(&pick_of, rebuilt, cache.rows.len(), cache.rows.iter().map(|(c, r)| (c.clone(), r.ns.clone(), r.name.clone())));
        }
        let total = cache.total;
        let shown = cache.rows.len();
        // "Hide empty columns": leave out the ones with nothing in any row (bars always count).
        if self.prefs.hide_empty_columns && !cache.rows.is_empty() {
            layout.retain(|c| {
                columns::is_fixed(c)
                    || matches!(*c, "CPU Usage" | "Memory Usage" | "Usage")
                    || all_cols.iter().position(|x| x == c).map(|ci| cache.rows.iter().any(|(_, r)| r.cells.get(ci).map(|c| !c.text.is_empty() && c.text != "-").unwrap_or(false))).unwrap_or(false)
            });
        }
        // The table's columns: the name brings its star and a column with the row's buttons along.
        let (has_logs, has_shell, has_ai) = (kind.has_logs(), kind == Kind::Pods, self.prefs.ai.on);
        let n_controls = has_logs as usize + has_shell as usize + has_ai as usize + can.len();
        let mut headers: Vec<&str> = vec![];
        let mut slots: Vec<Slot> = vec![];
        for c in layout.iter().copied() {
            match c {
                "Context" => slots.push(Slot::Context),
                "Namespace" => slots.push(Slot::Namespace),
                "Name" => {
                    if kind == Kind::Namespaces {
                        headers.push("★");
                        slots.push(Slot::Star);
                    }
                    headers.push("Name");
                    slots.push(Slot::Name);
                    if n_controls > 0 {
                        headers.push("Controls");
                        slots.push(Slot::Controls);
                    }
                    continue;
                }
                _ => match all_cols.iter().position(|x| *x == c) {
                    Some(ci) => slots.push(Slot::Data(ci)),
                    None => continue,
                },
            }
            headers.push(c);
        }

        let noun = kind.label();
        let count = if shown == total { format!("{shown} {noun}") } else { format!("{shown} of {total} {noun}") };
        self.header(ui, kind.namespaced(), Some(count), true);

        // Nodes refused, but Grafana shows this cluster's nodes below: nothing is missing, so nothing is said.
        let answered: Vec<String> = if kind == Kind::Nodes { errors.iter().filter(|(c, e)| is_refusal(e) && !self.grafana_nodes(c).is_empty()).map(|x| x.0.clone()).collect() } else { vec![] };
        for (c, e) in errors.iter().filter(|(c, _)| !answered.contains(c)) {
            Frame::new()
                .fill(WARN_BG())
                .corner_radius(CornerRadius::same(6))
                .inner_margin(Margin::same(8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if is_refusal(e) {
                        ui.label(RichText::new(format!("{}: your account can't list {}", ctx_label(c), noun.to_lowercase())).color(WARNING()).strong()).on_hover_text(truncate(e, 400));
                        ui.add(egui::Label::new(RichText::new(if kind.namespaced() { "The cluster refused it for these namespaces." } else { "This needs a right for the whole cluster, which yours doesn't have. The rest of Kubedog works without it." }).color(TEXT_MUTED()).size(z(12.5))).wrap());
                    } else {
                        ui.label(RichText::new(format!("{}: couldn't list {}", ctx_label(c), noun.to_lowercase())).color(WARNING()).strong());
                        ui.label(RichText::new(truncate(e, 400)).color(TEXT_MUTED()).size(z(12.0)));
                    }
                });
            ui.add_space(6.0);
        }
        // Refused, and the cluster isn't limited to some namespaces yet: offer that here.
        if matches!(kind, Kind::Namespaces) || kind.namespaced() {
            for c in errors.iter().filter(|(c, e)| is_refusal(e) && !self.prefs.ctx_namespaces.contains_key(c)).map(|x| x.0.clone()).collect::<Vec<_>>() {
                card(ui, |ui| self.namespaces_field(ui, &c, true));
                ui.add_space(6.0);
            }
        }
        if kind == Kind::Nodes && !errors.is_empty() {
            let gone: Vec<String> = errors.iter().filter(|(_, e)| is_refusal(e)).map(|x| x.0.clone()).collect();
            if gone.iter().any(|c| self.grafana_conf(c).is_some()) {
                self.page_scroll().show(ui, |ui| {
                    for c in &gone {
                        self.grafana_board(ui, c);
                        ui.add_space(22.0);
                    }
                    ui.label(RichText::new("What your own pods use there").size(z(17.0)).color(TEXT_DEFAULT()));
                    ui.add_space(8.0);
                    if let Some(n) = self.nodes_from_pods(ui, &gone, u(96.0)) {
                        self.open_hive(Some(n));
                    }
                });
                // With clusters that can be read, their table follows below.
                if cache.rows.is_empty() {
                    self.list_cache = Some(cache);
                    return;
                }
            }
            for c in gone.iter().filter(|c| self.grafana_conf(c).is_none()).cloned().collect::<Vec<_>>() {
                self.grafana_hint(ui, &c);
            }
            ui.label(RichText::new("Nodes your pods run on").size(z(17.0)).color(TEXT_DEFAULT()));
            ui.label(RichText::new("what your own pods use there, not the whole node").size(z(12.0)).color(TEXT_PLACEHOLDER()));
            ui.add_space(8.0);
            let gone: Vec<String> = errors.iter().filter(|(_, e)| is_refusal(e)).map(|x| x.0.clone()).collect();
            if let Some(n) = self.nodes_from_pods(ui, &gone, u(96.0)) {
                self.open_hive(Some(n));
            }
            ui.add_space(12.0);
        }

        if cache.rows.is_empty() {
            self.list_cache = Some(cache);
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                if first_load || self.is_loading() {
                    ui.spinner();
                    ui.label(RichText::new(format!("Loading {}…", noun.to_lowercase())).color(TEXT_SUBTLE()));
                } else if errors.is_empty() {
                    ui.label(RichText::new(format!("No {} found", noun.to_lowercase())).color(TEXT_SUBTLE()));
                    if !self.search.is_empty() || self.ns_any() {
                        ui.label(RichText::new("Try clearing the filter or namespace.").color(TEXT_PLACEHOLDER()).size(z(12.0)));
                    }
                }
            });
            return;
        }

        let mut clicked: Option<Selected> = None;
        let mut sort_click: Option<String> = None;
        let mut star_click: Option<String> = None;
        let mut logs_click: Option<Selected> = None;
        let mut shell_click: Option<Selected> = None;
        let mut explain_click: Option<Selected> = None;
        let mut act_click: Option<(Selected, picks::Verb)> = None;
        let mut node_click: Option<(String, String)> = None;
        let mut pick_row: Option<(picks::Key3, bool)> = None;
        let mut menu_do: Option<rowmenu::RowDo> = None;
        let mut menu_on: Option<picks::Key3> = None;
        // Where the rows and the Name header were drawn, to keep names in view when scrolled sideways.
        let mut sticky_rows: Vec<(egui::Rect, usize)> = vec![];
        let mut name_header: Option<egui::Rect> = None;
        let starred = self.prefs.starred_namespaces.clone();
        let ncols = headers.len();
        // Column widths: the usual sizes, then any room a big window has left over goes to the
        // columns whose text is cut off, shortest first, until everything fits or the room runs out.
        let mut base: Vec<f32> = headers.iter().map(|h| base_column_width(h)).collect();
        if cache.content_w.is_none() {
            cache.content_w = Some(measure_columns(ui, kind, &cache.rows));
        }
        let want: Vec<f32> = headers
            .iter()
            .map(|h| {
                let arrow = if sort_col == *h { 18.0 } else { 0.0 };
                cache.content_w.as_ref().and_then(|m| m.get(*h).copied()).map(|w| w + arrow).unwrap_or(base_column_width(h))
            })
            .collect();
        // A pod's state is what people look for: "Rejected: memory" isn't cut.
        if kind == Kind::Pods {
            for (i, h) in headers.iter().enumerate().filter(|(_, h)| **h == "Status") {
                base[i] = want[i].clamp(base_column_width(h), z(140.0));
            }
        }
        let mut want = want;
        // Context and Namespace: as wide as the longest name shown, not a fixed width.
        for (i, h) in headers.iter().enumerate().filter(|(_, h)| matches!(**h, "Context" | "Namespace")) {
            base[i] = snug_width(want[i], *h == "Context");
            want[i] = base[i];
        }
        // As wide as its buttons (or its name, if that's wider).
        let controls_w = (n_controls as f32 * 30.0 + 6.0).max(z(72.0));
        for (i, h) in headers.iter().enumerate().filter(|(_, h)| **h == "Controls") {
            base[i] = controls_w;
            want[i] = controls_w;
        }
        let room = ui.available_width() - ui.spacing().item_spacing.x * ncols as f32;
        let widths = fit_columns(&base, &want, room);
        let mut col_action: Option<ColAction> = None;
        let dragging = self.col_drag.clone();
        // Wide tables scroll sideways.
        let mut hsa = egui::ScrollArea::horizontal().auto_shrink([false, false]);
        // Test aid: KUBEDOG_SHOT_HSCROLL=<points> scrolls a list sideways for a screenshot.
        if self.screenshot.is_some() {
            if let Some(x) = std::env::var("KUBEDOG_SHOT_HSCROLL").ok().and_then(|v| v.parse::<f32>().ok()) {
                hsa = hsa.horizontal_scroll_offset(x);
            }
        }
        let hscroll = hsa.show(ui, |ui| {
            // The row of an open right-click menu: a soft tint, so its names stay readable.
            ui.visuals_mut().selection.bg_fill = PRIMARY().gamma_multiply(0.32);
            let ui_painter = ui.painter().clone();
            let mut tb = TableBuilder::new(ui)
                .striped(false)
                .resizable(false)
                .sense(Sense::click())
                .cell_layout(Layout::left_to_right(Align::Center))
                .min_scrolled_height(0.0);
            for (i, w) in widths.iter().copied().enumerate() {
                tb = if i + 1 == ncols {
                    tb.column(Column::remainder().at_least(w))
                } else {
                    tb.column(Column::initial(w).at_least(w.min(40.0)).clip(true))
                };
            }
            let line = Stroke::new(1.0, BORDER_SUBTLE());
            tb.header(u(30.0), |mut header| {
                for h in headers.iter() {
                    header.col(|ui| {
                        cell_line(ui, line);
                        if *h == "Name" {
                            name_header = Some(ui.max_rect());
                        }
                        let movable = layout.contains(h);
                        let cell = ui.max_rect();
                        // Dropping a dragged header here puts it before this one (after, on the right half).
                        if let (Some(d), true) = (&dragging, movable) {
                            if d != h && ui.rect_contains_pointer(cell) {
                                let after = ui.ctx().pointer_latest_pos().map(|p| p.x > cell.center().x).unwrap_or(false);
                                let x = if after { cell.right() } else { cell.left() };
                                ui.painter().vline(x, cell.y_range(), Stroke::new(2.0, PRIMARY_TEXT()));
                                if ui.input(|i| i.pointer.any_released()) {
                                    col_action = Some(ColAction::Place(d.clone(), h.to_string(), after));
                                }
                            }
                        }
                        if !h.is_empty() {
                            // Time columns sort by age, so "newest first" shows as ↓.
                            let up = if matches!(*h, "Age" | "Last Seen" | "Last Restart") { !asc } else { asc };
                            let arrow = if sort_col == *h { if up { " ↑" } else { " ↓" } } else { "" };
                            let colr = if dragging.as_deref() == Some(*h) { PRIMARY_TEXT() } else { TEXT_SUBTLE() };
                            let r = ui.add(
                                egui::Label::new(RichText::new(format!("{h}{arrow}")).size(z(14.0)).color(colr))
                                    .sense(if movable { Sense::click_and_drag() } else { Sense::click() })
                                    .selectable(false),
                            );
                            if r.clicked() && *h != "Controls" {
                                sort_click = Some(h.to_string());
                            }
                            if movable && r.drag_started() {
                                col_action = Some(ColAction::DragStart(h.to_string()));
                            }
                            if movable {
                                r.on_hover_text("Click to sort · drag to move · right-click for more").context_menu(|ui| {
                                    if !columns::is_fixed(h) && ui.button(format!("Hide “{h}”")).clicked() {
                                        col_action = Some(ColAction::Hide(h.to_string()));
                                    }
                                    let at = layout.iter().position(|c| c == h).unwrap_or(0);
                                    if at > 0 && ui.button("Move left").clicked() {
                                        col_action = Some(ColAction::Place(h.to_string(), layout[at - 1].to_string(), false));
                                    }
                                    if at + 1 < layout.len() && ui.button("Move right").clicked() {
                                        col_action = Some(ColAction::Place(h.to_string(), layout[at + 1].to_string(), true));
                                    }
                                    ui.separator();
                                    if ui.button("Reset to default").clicked() {
                                        col_action = Some(ColAction::Reset);
                                    }
                                });
                            }
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(u(30.0), cache.rows.len(), |mut row| {
                    let idx = row.index();
                    let (ctx, r) = &cache.rows[idx];
                    let mut name_hit = false;
                    let mut name_resp: Option<egui::Response> = None;
                    // While a menu is open, the mouse is in the menu: no row under it lights up, only the menu's own.
                    let menu_here = self.menu_row.as_ref().is_some_and(|m| m.0 == *ctx && m.1 == r.ns && m.2 == r.name);
                    if self.menu_row.is_some() {
                        row.set_hovered(false);
                        row.set_selected(menu_here);
                    }
                    for slot in &slots {
                    if *slot == Slot::Context {
                        row.col(|ui| {
                            cell_line(ui, line);
                            // A colour stripe down the row's left edge says which cluster it's from.
                            let cell = ui.max_rect();
                            ui.painter().rect_filled(egui::Rect::from_min_size(egui::pos2(cell.left(), cell.top() + 3.0), egui::vec2(4.0, cell.height() - 6.0)), CornerRadius::same(2), context_color(ctx));
                            ui.add_space(12.0);
                            ui.add(egui::Label::new(RichText::new(ctx_label(ctx)).color(TEXT_MUTED()).size(z(14.0))).truncate().selectable(false));
                        });
                    }
                    if *slot == Slot::Namespace {
                        row.col(|ui| {
                            cell_line(ui, line);
                            ui.add(egui::Label::new(RichText::new(&r.ns).color(TEXT_DEFAULT()).size(z(14.0))).truncate().selectable(false));
                        });
                    }
                    if *slot == Slot::Star {
                        row.col(|ui| {
                            cell_line(ui, line);
                            let on = starred.contains(&r.name);
                            let b = ui.add(egui::Button::new(RichText::new(if on { "★" } else { "☆" }).size(z(15.0)).color(if on { WARNING() } else { TEXT_PLACEHOLDER() })).frame(false));
                            if b.on_hover_text(if on { "Unstar" } else { "Star this namespace" }).clicked() {
                                star_click = Some(r.name.clone());
                            }
                        });
                    }
                    if *slot == Slot::Name {
                        row.col(|ui| {
                            cell_line(ui, line);
                            let l = name_link(ui, &r.name);
                            name_hit |= l.clicked();
                            name_resp = Some(l);
                        });
                    }
                    if *slot == Slot::Controls {
                        row.col(|ui| {
                            cell_line(ui, line);
                            ui.spacing_mut().item_spacing.x = 4.0;
                            let here = || Selected { ctx: ctx.clone(), kind, ns: r.ns.clone(), name: r.name.clone() };
                            framed(|| {
                                if has_logs && logs_icon_button(ui).on_hover_text("Open logs (L)").clicked() {
                                    logs_click = Some(here());
                                }
                                if has_shell && shell_icon_button(ui).on_hover_text("Open a shell in this pod").clicked() {
                                    shell_click = Some(here());
                                }
                                if has_ai && aichat::explain_icon(ui).on_hover_text("Explain with AI").clicked() {
                                    explain_click = Some(here());
                                }
                                for v in can {
                                    let bin = *v == picks::Verb::Delete;
                                    let b = if bin { picks::bin_icon(ui).on_hover_text(format!("Delete this {}", kind.singular())) } else { picks::restart_icon(ui).on_hover_text("Restart: its pods are replaced one by one") };
                                    if b.clicked() {
                                        act_click = Some((here(), *v));
                                    }
                                }
                            });
                        });
                    }
                    if let Slot::Data(ci) = *slot {
                        let col = all_cols[ci];
                        row.col(|ui| {
                            cell_line(ui, line);
                            let Some(c) = r.cells.get(ci) else { return };
                            match col {
                            "CPU Usage" | "Memory Usage" => {
                                let cpu = col == "CPU Usage";
                                if let Some(u) = cache.usage[idx] {
                                    let (val, req, lim) = if cpu { (u.0, r.req[0], r.req[1]) } else { (u.1, r.req[2], r.req[3]) };
                                    usage_bar(ui, cpu, val, req, lim, kind == Kind::Nodes);
                                }
                            }
                            "Node" => {
                                if c.text.is_empty() || c.text == "-" {
                                    return;
                                }
                                let l = ui.add(egui::Label::new(RichText::new(&c.text).color(PRIMARY_TEXT()).size(z(14.0))).truncate().selectable(false).sense(Sense::click())).on_hover_cursor(egui::CursorIcon::PointingHand);
                                if l.hovered() {
                                    let y = l.rect.bottom() - 1.0;
                                    ui.painter().hline(l.rect.x_range(), y, Stroke::new(1.0, PRIMARY_TEXT()));
                                }
                                if l.on_hover_text(format!("Open node {}", c.text)).clicked() {
                                    node_click = Some((ctx.clone(), c.text.clone()));
                                }
                            }
                            "Usage" => match self.claim_usage(ctx, &r.ns, &r.name) {
                                Some(u) => {
                                    let frac = u.used / u.capacity.max(1.0);
                                    storage::claim_bar(ui, 90.0, frac);
                                    ui.label(RichText::new(format!("{:.0}%", frac * 100.0)).size(z(13.0)).color(storage::usage_color(frac)));
                                }
                                None => {
                                    ui.label(RichText::new(if self.claim_stats_state(ctx).0 { "not mounted" } else { "…" }).size(z(12.5)).color(TEXT_PLACEHOLDER()));
                                }
                            },
                            _ => {
                                // Nothing meant to run (0/0, a finished pod) is dimmed.
                                let dim = c.text == "-" || (col == "Ready" && c.tone == Tone::Muted);
                                let color = if dim { TEXT_SUBTLE() } else { tone_color(c.tone) };
                                let l = ui.add(egui::Label::new(RichText::new(&c.text).color(color).size(z(14.0))).truncate().selectable(false));
                                // Why a pod failed, or restarted, in full.
                                if kind == Kind::Pods && l.hovered() && ((col == "Status" && c.tone == Tone::Danger) || (col == "Last Restart Reason" && c.text != "-")) {
                                    let o = self.lists.get(&Self::list_key(ctx, kind)).and_then(|x| x.items.iter().find(|o| o["metadata"]["name"].as_str() == Some(&r.name) && o["metadata"]["namespace"].as_str() == Some(&r.ns)));
                                    let why = o.and_then(|o| if col == "Status" { resources::pod_over(o) } else { resources::last_restart(o) }).map(|w| w.1).filter(|w| !w.is_empty());
                                    if let Some(w) = why {
                                        l.on_hover_text(truncate(&w, 600));
                                    }
                                }
                            }
                        }
                        });
                    }
                    }
                    sticky_rows.push((row.response().rect, idx));
                    if menu_here {
                        let rr = row.response().rect;
                        ui_painter.rect_filled(egui::Rect::from_min_size(rr.left_top(), egui::vec2(3.0, rr.height())), CornerRadius::same(1), PRIMARY());
                    }
                    {
                        let here = Selected { ctx: ctx.clone(), kind, ns: r.ns.clone(), name: r.name.clone() };
                        let k3 = (ctx.clone(), r.ns.clone(), r.name.clone());
                        let picked = if pickable && self.picks.on(&k3) { self.picks.set.len() } else { 0 };
                        // The name takes its own clicks, so it gets the same menu.
                        for resp in std::iter::once(row.response()).chain(name_resp.take()) {
                            resp.context_menu(|ui| {
                                menu_on = Some(k3.clone());
                                if let Some(d) = self.row_menu(ui, &here, picked) {
                                    menu_do = Some(d);
                                }
                            });
                        }
                    }
                    if (row.response().clicked() || name_hit) && logs_click.is_none() && shell_click.is_none() && explain_click.is_none() && act_click.is_none() && node_click.is_none() {
                        // ⌘ ticks it, ⇧ everything up to it, anywhere on the row; only its name opens it.
                        let m = row.response().ctx.input(|i| i.modifiers);
                        if pickable && (m.command || m.shift) {
                            pick_row = Some(((ctx.clone(), r.ns.clone(), r.name.clone()), m.shift));
                            return;
                        }
                        if name_hit {
                            clicked = Some(Selected { ctx: ctx.clone(), kind, ns: r.ns.clone(), name: r.name.clone() });
                        }
                    }
                });
            });
        });
        if menu_on != self.menu_row {
            self.menu_row = menu_on;
            ui.ctx().request_repaint();
        }
        if pickable {
            self.pick_boxes(ui, &pick_of, hscroll.inner_rect, name_header, &sticky_rows);
            if let Some((k, shift)) = pick_row {
                self.pick_click(&pick_of, &k, shift);
            }
        }
        // Scrolled sideways past the names: draw them over the table's left edge (clickable).
        if let Some(nh) = name_header.filter(|nh| kind.shows_name() && nh.left() < hscroll.inner_rect.left() - 2.0) {
            let area = hscroll.inner_rect;
            let w = nh.width().clamp(160.0, 300.0);
            let p = ui.painter().with_clip_rect(area);
            let head = egui::Rect::from_min_size(egui::pos2(area.left(), nh.top()), egui::vec2(w, nh.height()));
            p.rect_filled(head, CornerRadius::ZERO, BG_DEFAULT());
            p.text(head.left_center() + egui::vec2(4.0, 0.0), egui::Align2::LEFT_CENTER, "Name", FontId::proportional(z(14.0)), TEXT_SUBTLE());
            let body_clip = egui::Rect::from_min_max(egui::pos2(area.left(), nh.bottom()), area.max);
            let pb = ui.painter().with_clip_rect(body_clip);
            let mut bottom = nh.bottom();
            for (rr, idx) in &sticky_rows {
                let cell = egui::Rect::from_min_size(egui::pos2(area.left(), rr.top()), egui::vec2(w, rr.height()));
                if !body_clip.intersects(cell) {
                    continue;
                }
                bottom = bottom.max(cell.bottom());
                let resp = ui.interact(cell.intersect(body_clip), egui::Id::new(("sticky-name", *idx)), Sense::click());
                pb.rect_filled(cell, CornerRadius::ZERO, if resp.hovered() { BG_HOVER() } else { BG_DEFAULT() });
                pb.hline(cell.x_range(), cell.bottom() - 0.5, Stroke::new(1.0, BORDER_SUBTLE()));
                let (ctx, r) = &cache.rows[*idx];
                let mut x = cell.left() + 4.0;
                if multi {
                    pb.rect_filled(egui::Rect::from_min_size(egui::pos2(cell.left(), cell.top() + 3.0), egui::vec2(4.0, cell.height() - 6.0)), CornerRadius::same(2), context_color(ctx));
                    x += 8.0;
                }
                let g = pb.layout_no_wrap(fit(ui, &r.name, w - (x - cell.left()) - 8.0, z(14.0)), FontId::proportional(z(14.0)), PRIMARY_TEXT());
                pb.galley(egui::pos2(x, cell.center().y - g.size().y / 2.0), g, PRIMARY_TEXT());
                if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                    clicked = Some(Selected { ctx: ctx.clone(), kind, ns: r.ns.clone(), name: r.name.clone() });
                }
            }
            // A soft shadow on the right edge, so it reads as lifted over the table.
            let edge = area.left() + w;
            let shade = if crate::theme::palette().dark { 0.45 } else { 0.12 };
            for i in 0..10 {
                let a = shade * (1.0 - i as f32 / 10.0).powi(2);
                p.vline(edge + 0.5 + i as f32, nh.top()..=bottom.min(area.bottom()), Stroke::new(1.0, Color32::from_black_alpha((a * 255.0) as u8)));
            }
            p.vline(edge, nh.top()..=bottom.min(area.bottom()), Stroke::new(1.0, BORDER_DEFAULT()));
        }
        if let Some(s) = shell_click {
            // The pod's default container (its annotation), else the first one.
            let obj = self.object_of(&s);
            let container = obj
                .as_ref()
                .and_then(|o| o["metadata"]["annotations"]["kubectl.kubernetes.io/default-container"].as_str().map(String::from).or_else(|| o["spec"]["containers"][0]["name"].as_str().map(String::from)))
                .unwrap_or_default();
            self.open_shell(&s, &container);
        }
        if let Some(h) = sort_click {
            self.sort = if h == sort_col { (Some(h), !asc) } else { (Some(h), true) };
        }
        if self.col_drag.is_some() && ui.input(|i| !i.pointer.any_down()) {
            self.col_drag = None;
        }
        if self.col_drag.is_some() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::Grabbing);
        }
        if let Some(a) = col_action {
            self.apply_column_action(kind, a);
        }
        self.list_cache = Some(cache);
        if let Some((ctx, node)) = node_click {
            self.open_node(&ctx, &node);
        } else if let Some(d) = menu_do {
            self.row_do(d);
        } else if let Some((s, v)) = act_click {
            match v {
                picks::Verb::Delete => self.ask_delete(&s),
                picks::Verb::Restart => self.ask_restart(&s),
            }
        } else if let Some(s) = explain_click {
            let f = self.object_facts(&s);
            self.ai_explain(f);
        } else if let Some(s) = logs_click {
            // Open the object on its Logs tab.
            self.tab = Tab::Logs;
            self.select(s);
        } else if let Some(n) = star_click {
            self.toggle_star(&n);
        } else if let Some(s) = clicked {
            self.select(s);
        }
    }

    /// Filter and sort a list page's rows (and look up their usage) once.
    fn build_list_cache(&self, kind: Kind, key: String, sort_col: &str, asc: bool) -> ListCache {
        let search = self.search.to_lowercase();
        let mut rows: Vec<(String, Row)> = vec![];
        let mut total = 0usize;
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            if let Some(l) = self.lists.get(&Self::list_key(c, kind)) {
                for r in &l.rows {
                    if kind.namespaced() && !self.ns_ok(&r.ns) {
                        continue;
                    }
                    total += 1;
                    if !search.is_empty()
                        && !r.name.to_lowercase().contains(&search)
                        && !r.ns.to_lowercase().contains(&search)
                        && !r.cells.iter().any(|x| x.text.to_lowercase().contains(&search))
                    {
                        continue;
                    }
                    rows.push((c.clone(), r.clone()));
                }
            }
        }
        let usage: Vec<Option<(f64, f64)>> = if kind.all_columns().contains(&"CPU Usage") {
            let wl = self.workload_usage(kind);
            rows.iter().map(|(c, r)| self.usage_of(c, kind, r, &wl)).collect()
        } else {
            vec![None; rows.len()]
        };
        let cell_index = kind.all_columns().iter().position(|c| *c == sort_col);
        let mut order: Vec<usize> = (0..rows.len()).collect();
        let sk = |i: usize| -> SortKey {
            let x = &rows[i];
            match sort_col {
                "Context" => SortKey::Text(x.0.clone()),
                "Namespace" => SortKey::Text(x.1.ns.clone()),
                "Name" => SortKey::Text(x.1.name.clone()),
                "CPU Usage" => SortKey::Num(usage[i].map(|u| u.0).unwrap_or(-1.0)),
                "Memory Usage" => SortKey::Num(usage[i].map(|u| u.1).unwrap_or(-1.0)),
                _ => cell_index.and_then(|ci| x.1.cells.get(ci)).map(|c| c.sort.clone()).unwrap_or(SortKey::Text(String::new())),
            }
        };
        let keys: Vec<SortKey> = (0..rows.len()).map(sk).collect();
        order.sort_by(|&a, &b| {
            let o = keys[a].partial_cmp(&keys[b]).unwrap_or(std::cmp::Ordering::Equal).then_with(|| rows[a].1.name.cmp(&rows[b].1.name));
            if asc { o } else { o.reverse() }
        });
        let mut sorted_rows = Vec::with_capacity(rows.len());
        let mut sorted_usage = Vec::with_capacity(rows.len());
        let mut rows: Vec<Option<(String, Row)>> = rows.into_iter().map(Some).collect();
        for i in order {
            sorted_rows.push(rows[i].take().unwrap());
            sorted_usage.push(usage[i]);
        }
        ListCache { key, rows: sorted_rows, usage: sorted_usage, total, content_w: None }
    }

    // ---------------- overview pages ----------------

    /// Cluster overview: health bars per kind, resource usage
    /// per context, nodes above a usage threshold.
    fn cluster_overview(&mut self, ui: &mut Ui) {
        self.header(ui, false, None, false);
        let ctxs = self.active.clone();
        let rows_of = |s: &Self, k: Kind| -> Option<Vec<Row>> {
            let mut out = vec![];
            let mut any = false;
            for c in &ctxs {
                if let Some(l) = s.lists.get(&Self::list_key(c, k)) {
                    if l.fetched.is_some() {
                        any = true;
                        out.extend(l.rows.iter().cloned());
                    }
                }
            }
            any.then_some(out)
        };
        let nodes = rows_of(self, Kind::Nodes);
        let pvs = rows_of(self, Kind::PersistentVolumes);
        let nss = rows_of(self, Kind::Namespaces);
        let crds = rows_of(self, Kind::CustomResourceDefinitions);
        let threshold = self.threshold;
        let mut new_threshold = threshold;
        let mut open_pick: Option<Selected> = None;
        let mut open_shell_for: Option<String> = None;
        let mut open_node: Option<String> = None;
        let mut open_grafana: Option<(String, String)> = None;
        self.page_scroll().show(ui, |ui| {
            ui.add_space(6.0);
            self.ai_note(ui);
            ui.with_layout(Layout::left_to_right(Align::Min).with_main_wrap(true), |ui| {
                ui.spacing_mut().item_spacing = egui::vec2(22.0, 16.0);
                let no = |k: Kind, p: Option<Vec<(Color32, usize, String)>>| {
                    let refused = ctxs.iter().all(|c| self.refused(c, k));
                    if refused { Some(vec![(TEXT_PLACEHOLDER(), 1, String::new())]) } else { p }
                };
                health_card(ui, "Nodes", no(Kind::Nodes, nodes.as_ref().map(|r| count_by(r, 0, &[("Ready", SUCCESS(), "Ready"), ("*", DANGER(), "Not Ready")]))));
                health_card(ui, "Namespaces", no(Kind::Namespaces, nss.as_ref().map(|r| count_by(r, 0, &[("Active", SUCCESS(), "Active"), ("*", INFO(), "Terminating")]))));
                health_card(ui, "Persistent Volumes", no(Kind::PersistentVolumes, pvs.as_ref().map(|r| count_by(r, 3, &[("Bound", SUCCESS(), "Bound"), ("Available", TEXT_SUBTLE(), "Available"), ("Released", WARNING(), "Released"), ("*", DANGER(), "Failed")]))));
                let stubs = ctxs.iter().any(|c| self.lists.get(&Self::list_key(c, Kind::CustomResourceDefinitions)).and_then(|l| l.items.first()).map(|o| o["kubedogStub"] == true).unwrap_or(false));
                health_card(ui, if stubs { "Custom kinds" } else { "CRDs" }, crds.as_ref().map(|r| vec![(SUCCESS(), r.len(), if stubs { "Found" } else { "Active" }.to_string())]));
            });
            if let Some(p) = self.cluster_dashboard(ui, &mut open_node) {
                open_pick = Some(p);
            }
            ui.add_space(26.0);
            ui.label(RichText::new("Resource Usage").size(z(17.0)).color(TEXT_DEFAULT()));
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                for c in &ctxs {
                    let info = self.contexts.iter().find(|x| &x.name == c).cloned();
                    let nodes = self.lists.get(&Self::list_key(c, Kind::Nodes));
                    let pods = self.lists.get(&Self::list_key(c, Kind::Pods));
                    let m = self.metrics.get(c);
                    let mut cap = [0.0f64; 3]; // cpu m, mem B, pods
                    let mut alloc = [0.0f64; 3];
                    if let Some(n) = nodes {
                        for o in &n.items {
                            let st = &o["status"];
                            cap[0] += resources::cpu_milli(st["capacity"]["cpu"].as_str().unwrap_or(""));
                            cap[1] += resources::mem_bytes(st["capacity"]["memory"].as_str().unwrap_or(""));
                            alloc[0] += resources::cpu_milli(st["allocatable"]["cpu"].as_str().unwrap_or(""));
                            alloc[1] += resources::mem_bytes(st["allocatable"]["memory"].as_str().unwrap_or(""));
                            alloc[2] += st["allocatable"]["pods"].as_str().and_then(|p| p.parse::<f64>().ok()).unwrap_or(0.0);
                        }
                    }
                    let used = m.map(|m| m.nodes.values().fold((0.0, 0.0), |a, b| (a.0 + b.0, a.1 + b.1)));
                    let mut req = [0.0f64; 3];
                    if let Some(p) = pods {
                        for (o, r) in p.items.iter().zip(&p.rows) {
                            // What's over (evicted too) asks for nothing any more.
                            if matches!(o["status"]["phase"].as_str(), Some("Failed" | "Succeeded")) {
                                continue;
                            }
                            req[0] += r.req[0];
                            req[1] += r.req[2];
                            req[2] += 1.0;
                        }
                    }
                    ui.allocate_ui_with_layout(egui::vec2(u(380.0), u(290.0)), Layout::top_down(Align::Min), |ui| Frame::new()
                        .fill(BG_CARD())
                        .stroke(Stroke::new(1.0, BORDER_SUBTLE()))
                        .corner_radius(CornerRadius::same(4))
                        .show(ui, |ui| {
                            ui.set_width(u(380.0) - 2.0);
                            Frame::new().inner_margin(Margin::symmetric(12, 8)).show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.vertical(|ui| {
                                        ui.set_width(u(380.0) - u(80.0));
                                        ui.label(RichText::new(fit(ui, ctx_label(c).as_ref(), u(290.0), z(16.0))).size(z(16.0)).color(TEXT_DEFAULT())).on_hover_text(c);
                                        ui.label(RichText::new(info.as_ref().map(|i| i.cluster.clone()).unwrap_or_default()).size(z(12.5)).color(TEXT_SUBTLE()));
                                    });
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        if ui.add(egui::Button::new(RichText::new(">_").monospace().size(z(12.0))).frame(true)).on_hover_text("Open a terminal with this context").clicked() {
                                            open_shell_for = Some(c.clone());
                                        }
                                    });
                                });
                            });
                            let y = ui.cursor().top();
                            ui.painter().hline(ui.max_rect().x_range(), y, Stroke::new(1.0, BORDER_SUBTLE()));
                            Frame::new().inner_margin(Margin::symmetric(12, 8)).show(ui, |ui| {
                                if self.refused(c, Kind::Nodes) {
                                    ui.label(RichText::new("Your pods: used / asked for").size(z(12.5)).color(TEXT_SUBTLE()));
                                    let (cu, mu) = m.map(|m| m.pods.values().fold((0.0, 0.0), |a, b| (a.0 + b.0, a.1 + b.1))).unwrap_or_default();
                                    ratio_row(ui, "CPU", cu / req[0].max(1.0), format!("{:.1} / {:.1}", cu / 1000.0, req[0] / 1000.0), CPU_BAR(), true);
                                    ratio_row(ui, "Memory", mu / req[1].max(1.0), format!("{} / {}", gib(mu), gib(req[1])), MEM_BAR(), true);
                                    ui.add_space(6.0);
                                    ui.add(egui::Label::new(RichText::new(format!("{:.0} pods. Your account can't read nodes, so the cluster's own size isn't known.", req[2])).size(z(12.0)).color(TEXT_PLACEHOLDER())).wrap());
                                } else {
                                ui.label(RichText::new("Usage / Capacity").size(z(12.5)).color(TEXT_SUBTLE()));
                                match used {
                                    Some((cu, mu)) if cap[0] > 0.0 && (cu > 0.0 || mu > 0.0) => {
                                        ratio_row(ui, "CPU", cu / cap[0], format!("{:.1} / {:.0}", cu / 1000.0, cap[0] / 1000.0), CPU_BAR(), true);
                                        ratio_row(ui, "Memory", mu / cap[1].max(1.0), format!("{} / {}", gib(mu), gib(cap[1])), MEM_BAR(), true);
                                    }
                                    _ => {
                                        ui.label(RichText::new(m.and_then(|m| m.error.clone()).map(|_| "Metrics aren't available on this cluster").unwrap_or("Reading metrics…")).size(z(12.0)).color(TEXT_PLACEHOLDER()));
                                    }
                                }
                                ui.add_space(6.0);
                                ui.label(RichText::new("Requests / Allocatable").size(z(12.5)).color(TEXT_SUBTLE()));
                                ratio_row(ui, "Pods", req[2] / alloc[2].max(1.0), format!("{:.0} / {:.0}", req[2], alloc[2]), TEXT_DEFAULT(), false);
                                ratio_row(ui, "CPU", req[0] / alloc[0].max(1.0), format!("{:.1} / {:.1}", req[0] / 1000.0, alloc[0] / 1000.0), TEXT_DEFAULT(), false);
                                ratio_row(ui, "Memory", req[1] / alloc[1].max(1.0), format!("{} / {}", gib(req[1]), gib(alloc[1])), TEXT_DEFAULT(), false);
                                }
                            });
                        }));
                }
            });
            ui.add_space(26.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("High Resource Usage").size(z(17.0)).color(TEXT_DEFAULT()));
                egui::ComboBox::from_id_salt("hi-usage").selected_text(format!("{threshold}%")).width(60.0).show_ui(ui, |ui| {
                    for t in [50u32, 70, 80, 90, 95] {
                        ui.selectable_value(&mut new_threshold, t, format!("{t}%"));
                    }
                });
            });
            ui.add_space(8.0);
            let mut hot: Vec<(String, String, f64, f64)> = vec![];
            for c in &ctxs {
                if let (Some(m), Some(n)) = (self.metrics.get(c), self.lists.get(&Self::list_key(c, Kind::Nodes))) {
                    for r in &n.rows {
                        if let Some(u) = m.nodes.get(&r.name) {
                            let cp = u.0 / r.req[1].max(1.0) * 100.0;
                            let mp = u.1 / r.req[3].max(1.0) * 100.0;
                            if cp >= threshold as f64 || mp >= threshold as f64 {
                                hot.push((c.clone(), r.name.clone(), cp, mp));
                            }
                        }
                    }
                }
            }
            let mut from_grafana = false;
            for c in ctxs.iter().filter(|c| self.refused(c, Kind::Nodes)) {
                for n in self.grafana_nodes(c) {
                    from_grafana = true;
                    let (cp, mp) = (n.cpu.unwrap_or(0.0) * 100.0, n.mem().unwrap_or(0.0) * 100.0);
                    if cp >= threshold as f64 || mp >= threshold as f64 {
                        hot.push((c.clone(), n.kube.clone().unwrap_or_else(|| n.uname.clone()), cp, mp));
                    }
                }
            }
            if from_grafana {
                ui.label(RichText::new("from Grafana").size(z(11.5)).color(TEXT_PLACEHOLDER()));
            }
            if hot.is_empty() {
                empty_box(ui, 160.0, |ui| {
                    if self.nodes_refused() && !from_grafana {
                        ui.label(RichText::new("Your account can't read nodes, so this can't be checked.").size(z(14.5)).color(TEXT_SUBTLE()));
                        return;
                    }
                    ui.label(RichText::new(format!("Every node is below {threshold}% CPU and memory.")).size(z(14.5)).color(TEXT_SUBTLE()));
                });
            } else {
                hot.sort_by(|a, b| b.2.max(b.3).partial_cmp(&a.2.max(a.3)).unwrap_or(std::cmp::Ordering::Equal));
                card(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    for (c, n, cp, mp) in &hot {
                        let (r, resp) = dash::line(ui, u(28.0), true);
                        let name = if ctxs.len() > 1 { format!("{n}  ·  {}", ctx_label(c)) } else { n.clone() };
                        dash::at(ui, r, 0.0, 0.3, &name, 13.5, PRIMARY_TEXT());
                        for (x, label, v) in [(0.32, "CPU", *cp), (0.67, "Memory", *mp)] {
                            let col = if v >= threshold as f64 { DANGER() } else { TEXT_MUTED() };
                            dash::at(ui, r, x, 0.08, label, 12.0, TEXT_SUBTLE());
                            dash::bar(ui, r, x + 0.07, 0.19, v / 100.0, if v >= threshold as f64 { DANGER() } else { SUCCESS() });
                            dash::at_end(ui, r, x + 0.32, &format!("{v:.0}%"), 13.0, col);
                        }
                        if resp.clicked() && self.refused(c, Kind::Nodes) {
                            open_grafana = Some((c.clone(), n.clone()));
                        } else if resp.clicked() {
                            open_pick = Some(Selected { ctx: c.clone(), kind: Kind::Nodes, ns: String::new(), name: n.clone() });
                        }
                    }
                });
            }
        });
        self.threshold = new_threshold;
        if let Some(c) = open_shell_for {
            self.open_context_shell(&c);
        }
        if let Some(n) = open_node {
            self.open_hive(Some(n));
        }
        if open_grafana.is_some() {
            self.grafana.sel = open_grafana;
            self.navigate(View::Observatory, None);
        }
        if let Some(p) = open_pick {
            self.navigate(View::Resource(if p.kind == Kind::Nodes { Kind::Nodes } else { Kind::Pods }), Some(p));
        }
    }

    /// A page's scroll area. Test aid: KUBEDOG_SHOT_SCROLL=<points> scrolls it for a screenshot.
    fn page_scroll(&self) -> egui::ScrollArea {
        let area = egui::ScrollArea::vertical().auto_shrink([false, false]);
        match std::env::var("KUBEDOG_SHOT_SCROLL").ok().and_then(|v| v.parse::<f32>().ok()).filter(|_| self.screenshot.is_some()) {
            Some(y) => area.vertical_scroll_offset(y),
            None => area,
        }
    }

    /// Workloads overview.
    fn workloads_overview(&mut self, ui: &mut Ui) {
        self.header(ui, true, None, false);
        let ctxs = self.active.clone();
        let ns = self.ns_filter.clone();
        let rows_of = |s: &Self, k: Kind| -> Option<Vec<(String, Row)>> {
            let mut out = vec![];
            let mut any = false;
            for c in &ctxs {
                if let Some(l) = s.lists.get(&Self::list_key(c, k)) {
                    if l.fetched.is_some() {
                        any = true;
                        out.extend(l.rows.iter().filter(|r| s.ns_ok(&r.ns)).cloned().map(|r| (c.clone(), r)));
                    }
                }
            }
            any.then_some(out)
        };
        let only = |v: Option<Vec<(String, Row)>>| v.map(|v| v.into_iter().map(|x| x.1).collect::<Vec<Row>>());
        let pods = rows_of(self, Kind::Pods);
        let threshold = self.threshold;
        let mut new_threshold = threshold;
        let mut open: Option<Selected> = None;
        let events = rows_of(self, Kind::Events);
        let mut show_events = false;
        self.page_scroll().show(ui, |ui| {
            ui.add_space(6.0);
            ui.with_layout(Layout::left_to_right(Align::Min).with_main_wrap(true), |ui| {
                ui.spacing_mut().item_spacing = egui::vec2(22.0, 16.0);
                let p = pods.clone().map(|v| v.into_iter().map(|x| x.1).collect::<Vec<Row>>());
                health_card(ui, "Pods", p.as_ref().map(|r| count_by(r, 1, &[("Running", SUCCESS(), "Running"), ("Completed", TEXT_SUBTLE(), "Completed"), ("Pending", WARNING(), "Pending"), ("ContainerCreating", INFO(), "Creating"), ("*", DANGER(), "Failing")])));
                let ready = |r: &Row| -> bool { r.cells.first().map(|c| c.tone == Tone::Success).unwrap_or(false) };
                health_card(ui, "Deployments", only(rows_of(self, Kind::Deployments)).map(|r| split(&r, |x| ready(x), "Running", |x| x.cells.get(1).map(|c| c.text == "0").unwrap_or(false), "Idle")));
                health_card(ui, "ReplicaSets", only(rows_of(self, Kind::ReplicaSets)).map(|r| {
                    split(&r, |x| x.cells.first().map(|c| c.text != "0").unwrap_or(false) && x.cells.get(2).map(|c| c.text.clone()) == x.cells.first().map(|c| c.text.clone()), "Running", |x| x.cells.first().map(|c| c.text == "0").unwrap_or(false), "Idle")
                }));
                health_card(ui, "DaemonSets", only(rows_of(self, Kind::DaemonSets)).map(|r| split(&r, |x| x.cells.get(1).map(|c| c.text.clone()) == x.cells.get(2).map(|c| c.text.clone()), "Running", |_| false, "")));
                health_card(ui, "StatefulSets", only(rows_of(self, Kind::StatefulSets)).map(|r| split(&r, |x| ready(x), "Running", |x| x.cells.get(1).map(|c| c.text == "0").unwrap_or(false), "Idle")));
                health_card(ui, "CronJobs", only(rows_of(self, Kind::CronJobs)).map(|r| {
                    split(&r, |x| x.cells.get(3).map(|c| c.text == "No").unwrap_or(false), "Scheduled", |x| x.cells.get(3).map(|c| c.text == "Yes").unwrap_or(false), "Suspended")
                }));
                health_card(ui, "Jobs", only(rows_of(self, Kind::Jobs)).map(|r| count_by(&r, 0, &[("Complete", TEXT_SUBTLE(), "Complete"), ("Running", SUCCESS(), "Running"), ("*", DANGER(), "Failed")])));
            });
            ui.add_space(22.0);
            health_card(ui, "Resource Quotas", only(rows_of(self, Kind::ResourceQuotas)).map(|r| vec![(SUCCESS(), r.len(), "Defined".to_string())]));
            ui.add_space(22.0);
            if let Some(s) = self.work_summary(ui) {
                open = Some(s);
            }
            let hour = 3600.0;
            let age = |c: &Cell| match c.sort {
                SortKey::Num(x) => x,
                _ => f64::MAX,
            };
            let mut warn: Vec<(String, Row)> = events.clone().unwrap_or_default().into_iter().filter(|(_, r)| r.cells.get(3).map(|c| c.text == "Warning").unwrap_or(false) && r.cells.get(5).map(|c| age(c) < hour).unwrap_or(false)).collect();
            warn.sort_by(|a, b| age(&a.1.cells[5]).partial_cmp(&age(&b.1.cells[5])).unwrap_or(std::cmp::Ordering::Equal));
            let mut restarts: Vec<(String, Row)> = pods.clone().unwrap_or_default().into_iter().filter(|(_, r)| r.cells.get(5).map(|c| age(c) < hour).unwrap_or(false)).collect();
            restarts.sort_by(|a, b| age(&a.1.cells[5]).partial_cmp(&age(&b.1.cells[5])).unwrap_or(std::cmp::Ordering::Equal));
            let (wh, rh) = (u(46.0), u(28.0));
            let more = |n: usize, max: usize| if n > max { u(24.0) } else { 0.0 };
            let height = |n: usize, max: usize, h: f32| if n == 0 { u(136.0) } else { n.min(max) as f32 * h + more(n, max) };
            let mut all_events = false;
            let mut picked = (open.take(), all_events);
            dash::pair(
                ui,
                &mut picked,
                ("Recent Warnings", height(warn.len(), 6, wh)),
                ("Recent Restarts", height(restarts.len(), 9, rh)),
                |ui, picked| {
                    if warn.is_empty() {
                        dash::nothing(ui, u(136.0), "A quiet hour: no warnings.", TEXT_SUBTLE());
                    }
                    for (c, r) in warn.iter().take(6) {
                        let obj = &r.cells[0].text;
                        let target = obj.split_once(": ").and_then(|(k, n)| event_kind(k).map(|k| (k, n.to_string())));
                        let (rect, resp) = dash::line(ui, wh, target.is_some());
                        let half = |f: f32| egui::Rect::from_center_size(egui::pos2(rect.center().x, rect.top() + rect.height() * f), egui::vec2(rect.width(), u(18.0)));
                        let top = half(0.3);
                        let p = ui.painter();
                        let g = p.layout_no_wrap(r.cells[1].text.clone(), FontId::proportional(z(13.5)), WARNING());
                        let x = top.left() + g.size().x + 12.0;
                        p.galley(egui::pos2(top.left(), top.center().y - g.size().y / 2.0), g, WARNING());
                        let a = p.text(top.right_center(), egui::Align2::RIGHT_CENTER, format!("{} ago", r.cells[5].text), FontId::proportional(z(12.0)), TEXT_SUBTLE());
                        pg::label_at(ui, p, egui::pos2(x, top.center().y), obj, 13.0, if target.is_some() { PRIMARY_TEXT() } else { TEXT_MUTED() }, (a.left() - x - 12.0).max(10.0));
                        dash::at(ui, half(0.71), 0.0, 1.0, &r.cells[2].text, 12.5, TEXT_MUTED());
                        if resp.on_hover_text(format!("{obj}{}\n{}", if r.ns.is_empty() { String::new() } else { format!(" in {}", r.ns) }, r.cells[2].text)).clicked() {
                            if let Some((kind, name)) = target {
                                picked.0 = Some(Selected { ctx: c.clone(), kind, ns: if kind.namespaced() { r.ns.clone() } else { String::new() }, name });
                            }
                        }
                    }
                    if warn.len() > 6 {
                        let (rect, resp) = dash::line(ui, u(24.0), true);
                        dash::at(ui, rect, 0.0, 1.0, &format!("{} more in Events", warn.len() - 6), 12.5, PRIMARY_TEXT());
                        picked.1 = resp.clicked();
                    }
                },
                |ui, picked| {
                    if restarts.is_empty() {
                        dash::nothing(ui, u(136.0), "Nothing has restarted this past hour.", TEXT_SUBTLE());
                    }
                    for (c, r) in restarts.iter().take(9) {
                        let (rect, resp) = dash::line(ui, rh, true);
                        let why = if r.cells[6].text == "-" { "" } else { &r.cells[6].text };
                        dash::at(ui, rect, 0.0, 0.55, &format!("{}/{}", r.ns, r.name), 13.0, PRIMARY_TEXT());
                        dash::at(ui, rect, 0.56, 0.28, why, 12.0, WARNING());
                        dash::at_end(ui, rect, 1.0, &format!("{} ago", r.cells[5].text), 12.0, TEXT_SUBTLE());
                        if resp.on_hover_text(format!("{}/{}\n{why}", r.ns, r.name)).clicked() {
                            picked.0 = Some(Selected { ctx: c.clone(), kind: Kind::Pods, ns: r.ns.clone(), name: r.name.clone() });
                        }
                    }
                    if restarts.len() > 9 {
                        let (rect, _) = dash::line(ui, u(24.0), false);
                        dash::at(ui, rect, 0.0, 1.0, &format!("and {} more", restarts.len() - 9), 12.5, TEXT_SUBTLE());
                    }
                },
            );
            (open, all_events) = picked;
            show_events |= all_events;
            ui.add_space(26.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Abnormal Resource Usage").size(z(17.0)).color(TEXT_DEFAULT()));
                egui::ComboBox::from_id_salt("abn-usage").selected_text(format!("{threshold}% of Limit")).width(130.0).show_ui(ui, |ui| {
                    for t in [50u32, 70, 80, 90, 95] {
                        ui.selectable_value(&mut new_threshold, t, format!("{t}% of Limit"));
                    }
                });
            });
            ui.add_space(8.0);
            let mut hot: Vec<(String, String, String, &str, f64)> = vec![];
            for (c, r) in pods.clone().unwrap_or_default() {
                if let Some(used) = self.metrics.get(&c).and_then(|m| m.pods.get(&(r.ns.clone(), r.name.clone()))) {
                    for (what, limit, v) in [("CPU", r.req[1], used.0), ("Memory", r.req[3], used.1)] {
                        if limit > 0.0 && v / limit * 100.0 >= threshold as f64 {
                            hot.push((c.clone(), r.ns.clone(), r.name.clone(), what, v / limit * 100.0));
                        }
                    }
                }
            }
            hot.sort_by(|a, b| b.4.partial_cmp(&a.4).unwrap_or(std::cmp::Ordering::Equal));
            if hot.is_empty() {
                empty_box(ui, 160.0, |ui| {
                    ui.label(RichText::new(format!("Every container is below {threshold}% of its limits.")).size(z(14.5)).color(TEXT_SUBTLE()));
                });
            } else {
                card(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    for (c, ns, name, what, v) in hot.iter().take(12) {
                        let (r, resp) = dash::line(ui, u(28.0), true);
                        let col = if *v >= 100.0 { DANGER() } else { WARNING() };
                        dash::at(ui, r, 0.0, 0.48, &format!("{ns}/{name}"), 13.0, PRIMARY_TEXT());
                        dash::at(ui, r, 0.49, 0.1, what, 12.5, TEXT_SUBTLE());
                        dash::bar(ui, r, 0.58, 0.26, v / 100.0, col);
                        dash::at_end(ui, r, 1.0, &format!("{v:.0}% of limit"), 12.5, col);
                        if resp.on_hover_text(format!("{ns}/{name}")).clicked() {
                            open = Some(Selected { ctx: c.clone(), kind: Kind::Pods, ns: ns.clone(), name: name.clone() });
                        }
                    }
                    if hot.len() > 12 {
                        let (r, _) = dash::line(ui, u(24.0), false);
                        dash::at(ui, r, 0.0, 1.0, &format!("and {} more", hot.len() - 12), 12.5, TEXT_SUBTLE());
                    }
                });
            }
            if let Some(p) = self.work_map(ui) {
                open = Some(p);
            }
            if let Some(p) = self.workloads_dashboard(ui, &ns) {
                open = Some(p);
            }
            ui.add_space(16.0);
        });
        self.threshold = new_threshold;
        if show_events {
            self.set_view(View::Resource(Kind::Events));
        }
        if let Some(s) = open {
            self.navigate(View::Resource(s.kind), Some(s));
        }
    }

    fn port_forward_view(&mut self, ui: &mut Ui) {
        self.header(ui, false, Some(format!("{} Port Forwards", self.port_forwards.len())), false);
        if self.port_forwards.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("No port forwards yet").color(TEXT_SUBTLE()));
                ui.label(RichText::new("Open a pod or service and choose “Port forward”.").color(TEXT_PLACEHOLDER()).size(z(12.0)));
            });
            return;
        }
        let mut stop: Option<u64> = None;
        let mut remove: Option<u64> = None;
        let mut restart: Option<u64> = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            for pf in &self.port_forwards {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        let col = match pf.status.as_str() {
                            "Active" => SUCCESS(),
                            "Starting" => WARNING(),
                            "Stopped" => TEXT_SUBTLE(),
                            _ => DANGER(),
                        };
                        ui.label(RichText::new("●").color(col));
                        ui.label(RichText::new(format!("localhost:{}", pf.local)).strong().color(TEXT_DEFAULT()));
                        ui.label(RichText::new("→").color(TEXT_SUBTLE()));
                        ui.label(RichText::new(format!("{}:{}", pf.target, pf.remote)).color(TEXT_MUTED()));
                        ui.label(RichText::new(format!("{} · {}", pf.ns, ctx_label(&pf.ctx))).color(TEXT_PLACEHOLDER()).size(z(12.0)));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if pf.child.is_some() {
                                if button(ui, "Stop", false, false) {
                                    stop = Some(pf.id);
                                }
                                if button(ui, "Open in browser", false, false) {
                                    let _ = std::process::Command::new("/usr/bin/open").arg(format!("http://localhost:{}", pf.local)).spawn();
                                }
                            } else {
                                if button(ui, "Remove", false, false) {
                                    remove = Some(pf.id);
                                }
                                if button(ui, "Start again", false, false) {
                                    restart = Some(pf.id);
                                }
                            }
                            ui.label(RichText::new(&pf.status).color(col));
                        });
                    });
                    if let Some(last) = pf.output.last() {
                        ui.label(RichText::new(truncate(last, 200)).monospace().color(TEXT_SUBTLE()).size(z(11.5)));
                    }
                });
                ui.add_space(6.0);
            }
        });
        if let Some(id) = stop {
            if let Some(pf) = self.port_forwards.iter_mut().find(|p| p.id == id) {
                if let Some(mut c) = pf.child.take() {
                    let _ = c.kill();
                    let _ = c.wait();
                }
                pf.status = "Stopped".into();
            }
        }
        if let Some(id) = remove {
            self.port_forwards.retain(|p| p.id != id);
        }
        if let Some(id) = restart {
            if let Some(i) = self.port_forwards.iter().position(|p| p.id == id) {
                let pf = self.port_forwards.remove(i);
                let kind = if pf.target.starts_with("svc/") { Kind::Services } else { Kind::Pods };
                let name = pf.target.split_once('/').map(|x| x.1.to_string()).unwrap_or_default();
                let sel = Selected { ctx: pf.ctx, kind, ns: pf.ns, name };
                self.start_port_forward(&sel, pf.local, pf.remote, false);
            }
        }
    }

    fn helm_view(&mut self, ui: &mut Ui) {
        let multi = self.active.len() > 1;
        let mut rows: Vec<(String, Value)> = vec![];
        let mut errors = vec![];
        let mut loading = false;
        for c in &self.active {
            match self.helm.get(&format!("helm|{c}")) {
                Some((l, r)) => {
                    loading |= *l;
                    match r {
                        Ok(v) => rows.extend(v.iter().cloned().map(|x| (c.clone(), x))),
                        Err(e) => errors.push((c.clone(), e.clone())),
                    }
                }
                None => loading = true,
            }
        }
        let search = self.search.to_lowercase();
        rows.retain(|(c, v)| {
            self.ctx_shown(c)
                && self.ns_ok(v["namespace"].as_str().unwrap_or(""))
                && (search.is_empty() || v.to_string().to_lowercase().contains(&search))
        });
        rows.sort_by(|a, b| a.1["name"].as_str().cmp(&b.1["name"].as_str()));
        self.header(ui, true, Some(format!("{} Releases", rows.len())), true);
        if self.kubectl.helm.is_none() && !self.demo {
            ui.label(RichText::new("helm was not found on this computer, so releases can't be listed.").color(WARNING()));
            return;
        }
        for (c, e) in errors {
            ui.label(RichText::new(format!("{}: {}", ctx_label(&c), truncate(&e, 300))).color(WARNING()));
        }
        if rows.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                if loading {
                    ui.spinner();
                } else {
                    ui.label(RichText::new("No Helm releases found").color(TEXT_SUBTLE()));
                }
            });
            return;
        }
        let mut uninstall: Option<(String, String, String)> = None;
        let mut headers = vec![];
        if multi {
            headers.push("Context");
        }
        headers.extend(["Name", "Namespace", "Revision", "Status", "Chart", "App Version", "Updated", ""]);
        let ctx_names: Vec<String> = if multi { rows.iter().map(|r| ctx_label(&r.0)).collect() } else { vec![] };
        let ctx_w = snug_width(measure_texts(ui, "Context", ctx_names.iter().map(|s| s.as_str())), false);
        let ns_w = snug_width(measure_texts(ui, "Namespace", rows.iter().filter_map(|r| r.1["namespace"].as_str())), false);
        let mut tb = TableBuilder::new(ui).striped(false).resizable(false).cell_layout(Layout::left_to_right(Align::Center));
        for h in &headers {
            tb = tb.column(match *h {
                "Context" => Column::initial(ctx_w).clip(true),
                "Namespace" => Column::initial(ns_w).clip(true),
                "Name" | "Chart" => Column::initial(220.0).clip(true),
                "Updated" => Column::initial(200.0).clip(true),
                "" => Column::remainder(),
                _ => Column::initial(110.0).clip(true),
            });
        }
        tb.header(u(26.0), |mut hr| {
            for h in &headers {
                hr.col(|ui| {
                    ui.label(RichText::new(*h).size(z(12.0)).color(TEXT_SUBTLE()));
                });
            }
        })
        .body(|body| {
            body.rows(u(28.0), rows.len(), |mut row| {
                let (c, v) = &rows[row.index()];
                let s = |k: &str| v[k].as_str().map(String::from).unwrap_or_else(|| v[k].to_string());
                if multi {
                    row.col(|ui| {
                        ui.label(RichText::new(ctx_label(c)).color(TEXT_SUBTLE()));
                    });
                }
                row.col(|ui| {
                    ui.label(RichText::new(s("name")).color(TEXT_DEFAULT()));
                });
                row.col(|ui| {
                    ui.label(RichText::new(s("namespace")).color(TEXT_SUBTLE()));
                });
                row.col(|ui| {
                    ui.label(s("revision"));
                });
                row.col(|ui| {
                    let st = s("status");
                    let col = match st.as_str() {
                        "deployed" => SUCCESS(),
                        "failed" => DANGER(),
                        x if x.starts_with("pending") => WARNING(),
                        _ => TEXT_SUBTLE(),
                    };
                    ui.label(RichText::new(st).color(col).strong());
                });
                row.col(|ui| {
                    ui.label(s("chart"));
                });
                row.col(|ui| {
                    ui.label(RichText::new(s("app_version")).color(TEXT_SUBTLE()));
                });
                row.col(|ui| {
                    ui.label(RichText::new(truncate(&s("updated"), 19)).color(TEXT_SUBTLE()));
                });
                row.col(|ui| {
                    if ui.small_button("Uninstall…").clicked() {
                        uninstall = Some((c.clone(), s("namespace"), s("name")));
                    }
                });
            });
        });
        if let Some((ctx, ns, name)) = uninstall {
            let body = format!("Uninstall Helm release “{name}” from namespace {ns} in {ctx}? Its resources will be removed.");
            self.request(Action::HelmUninstall { ctx, ns, name }, "Uninstall release".into(), body, "Uninstall", true);
        }
    }

    // ---------------- detail panel ----------------

    /// The object's page. It replaces the list rather than opening beside it; Back or Esc returns to the list.
    fn detail(&mut self, ui: &mut Ui) {
        let Some(sel) = self.selected.clone() else { return };
        let obj = self.selected_object();
        ui.horizontal(|ui| {
            if back_button(ui)
                .on_hover_text("Back to the list (Esc)")
                .clicked()
            {
                self.back_pressed();
            }
            let (r, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), Sense::hover());
            ui.painter().circle_filled(r.center(), 3.5, context_color(&sel.ctx));
            ui.label(RichText::new(format!("{} · {}", ctx_label(&sel.ctx), sel.kind.label())).size(z(12.0)).color(TEXT_SUBTLE()));
            self.ai_corner(ui, false);
        });
        if self.selected.is_none() {
            return;
        }
        let mut explain = false;
        ui.horizontal(|ui| {
            if sel.kind.namespaced() {
                ui.label(RichText::new(format!("{} /", sel.ns)).size(z(19.0)).color(TEXT_SUBTLE()));
            }
            ui.add(egui::Label::new(RichText::new(&sel.name).size(z(19.0)).strong().color(TEXT_DEFAULT())).truncate());
            if ui.small_button("❐").on_hover_text("Copy name").clicked() {
                ui.ctx().copy_text(sel.name.clone());
                self.toast("Name copied".into(), false);
            }
            if let Some(o) = &obj {
                ui.label(RichText::new(kube::age(o["metadata"]["creationTimestamp"].as_str().unwrap_or(""))).color(TEXT_PLACEHOLDER()));
            } else if self.lists.get(&Self::list_key(&sel.ctx, sel.kind)).map(|l| l.fetched.is_some()).unwrap_or(false) {
                chip(ui, "Deleted");
            }
            if obj.is_some() && self.ai_button(ui) {
                explain = true;
            }
            // A pod has many tabs, so its buttons are up here.
            if sel.kind == Kind::Pods {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    self.action_bar(ui, &sel, obj.as_ref());
                });
            }
        });
        ui.add_space(6.0);

        if self.screenshot.is_some() && self.ai.chat.is_none() && obj.is_some() && std::env::var("KUBEDOG_SHOT_AI").map(|v| v != "chat").unwrap_or(false) {
            let f = self.object_facts(&sel);
            self.ai_canned(f);
        }
        if explain {
            let f = self.object_facts(&sel);
            self.ai_explain(f);
        }
        // Tab strip with the actions at its right end.
        let warnings = self
            .events
            .get(&format!("events|{}", sel.key()))
            .and_then(|e| e.1.as_ref().ok())
            .map(|v| v.iter().filter(|e| e["type"] == "Warning").count())
            .unwrap_or(0);
        ui.horizontal(|ui| {
            // Events only where the kind has them (or some were found for this object).
            let found = self
                .events
                .get(&format!("events|{}", sel.key()))
                .and_then(|e| e.1.as_ref().ok())
                .map(|v| !v.is_empty())
                .unwrap_or(false);
            let show_events = sel.kind.has_events() || found;
            let mut tabs = vec![(Tab::Overview, "Overview")];
            if sel.kind == Kind::Pods {
                tabs.extend([(Tab::Containers, "Containers"), (Tab::Environment, "Environment"), (Tab::Network, "Network"), (Tab::Scheduling, "Scheduling"), (Tab::Storage, "Storage"), (Tab::Files, "Files"), (Tab::WhatIf, "What if")]);
            } else if work::is_work(sel.kind) {
                tabs.extend([(Tab::Containers, "Containers"), (Tab::Environment, "Environment"), (Tab::Scheduling, "Scheduling")]);
                if pod_tab(self.tab) && !matches!(self.tab, Tab::Containers | Tab::Environment | Tab::Scheduling) {
                    self.tab = Tab::Overview;
                }
            } else if pod_tab(self.tab) {
                self.tab = Tab::Overview;
            }
            if matches!(sel.kind, Kind::Deployments | Kind::StatefulSets | Kind::DaemonSets) {
                tabs.push((Tab::Revisions, "Revisions"));
            } else if self.tab == Tab::Revisions {
                self.tab = Tab::Overview;
            }
            tabs.push((Tab::Yaml, "YAML"));
            if show_events {
                tabs.push((Tab::Events, "Events"));
            } else if self.tab == Tab::Events {
                self.tab = Tab::Overview;
            }
            // Logs open from the Logs button on the right (one place only).
            for (t, label) in tabs {
                let on = self.tab == t;
                let text = if t == Tab::Events && warnings > 0 { format!("{label}  {warnings}") } else { label.to_string() };
                let r = ui.add(
                    egui::Button::new(RichText::new(text).color(if on { TEXT_DEFAULT() } else if t == Tab::Events && warnings > 0 { WARNING() } else { TEXT_SUBTLE() }))
                        .fill(if on { BG_MUTED() } else { Color32::TRANSPARENT })
                        .stroke(Stroke::NONE),
                );
                if r.clicked() && !on {
                    self.set_tab(t, &sel);
                }
            }
            if sel.kind != Kind::Pods {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    self.action_bar(ui, &sel, obj.as_ref());
                });
            }
        });
        let y = ui.cursor().top();
        ui.painter().hline(ui.max_rect().x_range(), y, Stroke::new(1.0, BORDER_SUBTLE()));
        ui.add_space(8.0);
        // A workload's tabs read its template.
        let sample = obj.as_ref().filter(|_| work::is_work(sel.kind) && pod_tab(self.tab)).map(|o| work::sample(sel.kind, o));
        let shown = sample.as_ref().or(obj.as_ref());
        match self.tab {
            Tab::Overview if work::is_work(sel.kind) && obj.is_some() => self.work_overview(ui, &sel, obj.as_ref().unwrap_or(&Value::Null)),
            Tab::Overview if sel.kind == Kind::Pods && obj.is_some() => self.pod_overview(ui, &sel, obj.as_ref().unwrap_or(&Value::Null)),
            Tab::Containers | Tab::Environment | Tab::Network | Tab::Scheduling | Tab::Storage | Tab::Files | Tab::WhatIf => match (self.tab, shown) {
                (_, None) => {
                    ui.label(RichText::new("This object is no longer in the list.").color(TEXT_SUBTLE()));
                }
                (Tab::Containers, Some(o)) => self.pod_containers(ui, &sel, o),
                (Tab::Environment, Some(o)) => self.pod_side(ui, &sel, o, true),
                (Tab::Network, Some(o)) => self.pod_side(ui, &sel, o, false),
                (Tab::Scheduling, Some(o)) => self.pod_scheduling(ui, &sel, o),
                (Tab::Storage, Some(o)) => self.pod_storage(ui, &sel, o),
                (Tab::Files, Some(o)) => self.pod_files(ui, &sel, o),
                (_, Some(o)) => self.pod_what_if(ui, &sel, o),
            },
            Tab::Overview => self.detail_overview(ui, &sel, obj.as_ref()),
            Tab::Yaml => self.detail_yaml(ui, &sel),
            Tab::Events => self.detail_events(ui, &sel),
            Tab::Logs => self.detail_logs(ui, &sel, obj.as_ref()),
            Tab::Revisions if sel.kind != Kind::Deployments => self.controller_revisions(ui, &sel, obj.as_ref()),
            Tab::Revisions => self.detail_revisions(ui, &sel, obj.as_ref()),
        }
    }

    /// A pod's Environment or Network tab.
    fn pod_side(&mut self, ui: &mut Ui, sel: &Selected, o: &Value, env: bool) {
        let mut open = None;
        self.page_scroll().id_salt(("pod-side", env)).show(ui, |ui| {
            open = if env { self.pod_env(ui, sel, o) } else { self.pod_network(ui, sel, o) };
            ui.add_space(20.0);
        });
        if let Some(s) = open {
            self.navigate(View::Resource(s.kind), Some(s));
        }
    }

    fn set_tab(&mut self, t: Tab, sel: &Selected) {
        self.tab = t;
        if t == Tab::Logs {
            self.start_logs(sel);
        } else {
            self.stop_logs();
            // Some tabs need more lists.
            if pod_tab(t) {
                self.refresh_current(false);
            }
        }
    }

    fn action_bar(&mut self, ui: &mut Ui, sel: &Selected, obj: Option<&Value>) {
        ui.horizontal(|ui| {
            // Laid out right to left, so on screen it reads: … Logs · Shell · Port forward · Delete.
            if sel.kind != Kind::Events && button(ui, "Delete", false, false) {
                self.ask_delete(sel);
            }
            if sel.kind.can_port_forward() {
                if button(ui, "Port forward", false, false) {
                    let ports = obj.map(|o| ports_of(sel.kind, o)).unwrap_or_default();
                    let remote = ports.first().map(|p| p.to_string()).unwrap_or_default();
                    let local = ports.first().map(|p| suggest_local(*p).to_string()).unwrap_or_default();
                    self.dialog = Some(Dialog::PortForward { sel: sel.clone(), ports, remote, local, open_browser: false });
                }
            }
            if sel.kind == Kind::Pods {
                let containers: Vec<String> = obj
                    .and_then(|o| o["spec"]["containers"].as_array().cloned())
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|c| c["name"].as_str().map(String::from))
                    .collect();
                if containers.len() <= 1 {
                    if button(ui, "Shell", false, false) {
                        self.open_shell(sel, containers.first().map(|s| s.as_str()).unwrap_or(""));
                    }
                } else {
                    ui.menu_button("Shell ▾", |ui| {
                        for c in &containers {
                            if ui.button(c).clicked() {
                                self.open_shell(sel, c);
                                ui.close();
                            }
                        }
                    });
                }
            }
            // Logs: blue while showing; pressing it again goes back to the Overview.
            if sel.kind == Kind::CustomResourceDefinitions {
                let key = obj.and_then(|o| Some(format!("{}.{}", o["spec"]["names"]["plural"].as_str()?, o["spec"]["group"].as_str()?)));
                if let Some(i) = key.and_then(|k| { self.sync_crds(); self.crd_index(&k) }) {
                    if button(ui, "Browse objects", true, false) {
                        self.selected = None;
                        self.open_custom(i);
                    }
                }
            }
            if sel.kind.has_logs() {
                let on = self.tab == Tab::Logs;
                let r = ui.add(
                    egui::Button::new(RichText::new("≡ Logs").color(if on { Color32::WHITE } else { TEXT_DEFAULT() }))
                        .fill(if on { PRIMARY() } else { BG_MUTED() })
                        .stroke(Stroke::new(1.0, if on { PRIMARY() } else { BORDER_DEFAULT() }))
                        .corner_radius(CornerRadius::same(6)),
                );
                if r.on_hover_text(if on { "Back to the Overview" } else { "Show the logs (L)" }).clicked() {
                    self.set_tab(if on { Tab::Overview } else { Tab::Logs }, sel);
                }
            }
            if sel.kind.can_restart() && button(ui, "Restart", false, false) {
                self.ask_restart(sel);
            }
            if sel.kind.can_scale() && button(ui, "Scale", false, false) {
                let cur = obj.and_then(|o| o["spec"]["replicas"].as_i64()).unwrap_or(1);
                if !self.unlocked.contains(&sel.ctx) && !self.demo {
                    self.dialog = Some(Dialog::Protected { ctx: sel.ctx.clone() });
                } else {
                    self.dialog = Some(Dialog::Scale { sel: sel.clone(), replicas: cur.to_string() });
                }
            }
            if let (Kind::CronJobs, Some(o)) = (sel.kind, obj) {
                let off = o["spec"]["suspend"] == true;
                if button(ui, if off { "Resume" } else { "Suspend" }, false, false) {
                    let body = if off { format!("Let cron job “{}” start its jobs on schedule again?", sel.name) } else { format!("Suspend cron job “{}”? No new jobs start until it's resumed; a running one goes on.", sel.name) };
                    let word = if off { "Resume" } else { "Suspend" };
                    self.request(Action::Run { sel: sel.clone(), args: suspend_args(sel, !off), what: format!("{} {}", if off { "Resumed" } else { "Suspended" }, sel.name) }, format!("{word} cron job"), body, word, false);
                }
                if button(ui, "Run now", false, false) {
                    let job = job_name(&sel.name, kube::now_secs());
                    let body = format!("Start a job of cron job “{}” now? It becomes job “{job}” (kubectl create job --from).", sel.name);
                    self.request(Action::Run { sel: sel.clone(), args: run_args(sel, &job), what: format!("Started {job}") }, "Run cron job now".into(), body, "Run now", false);
                }
            }
            if let (Kind::Deployments, Some(o)) = (sel.kind, obj) {
                let off = o["spec"]["paused"] == true;
                if button(ui, if off { "Resume rollout" } else { "Pause rollout" }, false, false) {
                    let verb = if off { "resume" } else { "pause" };
                    let body = if off { format!("Resume the rollout of deployment “{}”? Changes made while it was paused are rolled out.", sel.name) } else { format!("Pause the rollout of deployment “{}”? Changes to it wait until it's resumed; its pods go on.", sel.name) };
                    self.request(Action::Run { sel: sel.clone(), args: pause_args(sel, verb), what: format!("Rollout {}", if off { "resumed" } else { "paused" }) }, format!("{} rollout", if off { "Resume" } else { "Pause" }), body, if off { "Resume" } else { "Pause" }, false);
                }
            }
            if sel.kind == Kind::Nodes {
                let cordoned = obj.and_then(|o| o["spec"]["unschedulable"].as_bool()).unwrap_or(false);
                if cordoned {
                    if button(ui, "Uncordon", false, false) {
                        let body = format!("Allow new pods to be scheduled on node “{}” again?", sel.name);
                        self.request(Action::Cordon(sel.clone(), false), "Uncordon node".into(), body, "Uncordon", false);
                    }
                } else if button(ui, "Cordon", false, false) {
                    let body = format!("Stop new pods from being scheduled on node “{}”? Running pods stay.", sel.name);
                    self.request(Action::Cordon(sel.clone(), true), "Cordon node".into(), body, "Cordon", false);
                }
                if button(ui, "Drain…", false, false) {
                    if !self.unlocked.contains(&sel.ctx) && !self.demo {
                        self.dialog = Some(Dialog::Protected { ctx: sel.ctx.clone() });
                    } else {
                        self.fetch_list(&sel.ctx, Kind::Pods);
                        self.dialog = Some(Dialog::Drain { sel: sel.clone(), delete_emptydir: false, disable_eviction: false, force: false });
                    }
                }
            }
        });
    }

    fn detail_overview(&mut self, ui: &mut Ui, sel: &Selected, obj: Option<&Value>) {
        let Some(o) = obj else {
            ui.label(RichText::new("This object is no longer in the list.").color(TEXT_SUBTLE()));
            return;
        };
        let mut open_pod: Option<Selected> = None;
        let mut go: Option<podxray::Go> = None;
        let mut area = egui::ScrollArea::vertical().auto_shrink([false, false]);
        // Test aid: KUBEDOG_SHOT_SCROLL=<points> scrolls an object's Overview for a screenshot.
        if self.screenshot.is_some() {
            if let Some(y) = std::env::var("KUBEDOG_SHOT_SCROLL").ok().and_then(|v| v.parse::<f32>().ok()) {
                area = area.vertical_scroll_offset(y);
            }
        }
        area.show(ui, |ui| {
            let (f, side) = self.object_face(sel, o, kube::now_secs());
            if let Some(t) = face::show(ui, &f, side) {
                open_pod = Some(t);
            }
            ui.add_space(12.0);
            if sel.kind == Kind::Nodes {
                if let Some(t) = self.node_visuals(ui, sel, o) {
                    open_pod = Some(t);
                }
            }
            if let Some(t) = self.object_body(ui, sel, o, &f, &mut go) {
                open_pod = Some(t);
            }
            // Ingress TLS and claim usage (Kubedog additions).
            if sel.kind == Kind::Ingresses {
                self.ingress_tls(ui, sel, o);
            }
            if sel.kind == Kind::PersistentVolumeClaims {
                self.claim_detail(ui, sel);
            }

            // Data (config maps & secrets): key in the first column, value in the second.
            // Certificates are decoded and shown as is; other secret values are blurred until
            // clicked. Both can be edited here (Kubedog additions, asked for by the person).
            if matches!(sel.kind, Kind::ConfigMaps | Kind::Secrets) {
                let secret = sel.kind == Kind::Secrets;
                let obj_key = sel.key();
                let empty = serde_json::Map::new();
                let data = o["data"].as_object().unwrap_or(&empty).clone();
                let decode = |raw: &str| -> Option<String> {
                    if secret {
                        b64_decode(raw).and_then(|b| String::from_utf8(b).ok())
                    } else {
                        Some(raw.to_string())
                    }
                };
                ui.add_space(8.0);
                let editing = self.data_edit.as_ref().map(|e| e.0 == obj_key).unwrap_or(false);
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("Data ({})", data.len())).color(TEXT_SUBTLE()).strong());
                    if !editing {
                        if ui.small_button("Edit").on_hover_text("Edit the keys and values here").clicked() {
                            if !self.unlocked.contains(&sel.ctx) && !self.demo {
                                self.dialog = Some(Dialog::Protected { ctx: sel.ctx.clone() });
                            } else {
                                let rows: Vec<(String, String)> = data.iter().map(|(k, v)| (k.clone(), decode(v.as_str().unwrap_or("")).unwrap_or_default())).collect();
                                let keys = data.keys().cloned().collect();
                                self.data_edit = Some((obj_key.clone(), rows, keys));
                            }
                        }
                        if secret && !data.is_empty() {
                            let all = data.keys().all(|k| self.revealed.contains(&format!("{obj_key}|{k}")));
                            if ui.small_button(if all { "Hide all" } else { "Reveal all" }).clicked() {
                                for k in data.keys() {
                                    let rk = format!("{obj_key}|{k}");
                                    if all { self.revealed.remove(&rk); } else { self.revealed.insert(rk); }
                                }
                            }
                        }
                    }
                });
                if editing {
                    let mut save: Option<(String, String)> = None;
                    let mut cancel = false;
                    card(ui, |ui| {
                        let (_, rows, original) = self.data_edit.as_mut().unwrap();
                        let mut remove: Option<usize> = None;
                        ui.horizontal(|ui| {
                            left_cell(ui, [230.0, 16.0], egui::Label::new(RichText::new("Key").size(z(12.0)).color(TEXT_SUBTLE())));
                            ui.label(RichText::new("Value").size(z(12.0)).color(TEXT_SUBTLE()));
                        });
                        for (i, (k, v)) in rows.iter_mut().enumerate() {
                            ui.horizontal_top(|ui| {
                                ui.add(egui::TextEdit::singleline(k).font(egui::TextStyle::Monospace).desired_width(220.0).hint_text("key"));
                                let w = (ui.available_width() - 40.0).max(200.0);
                                egui::ScrollArea::vertical().id_salt(format!("edit-v-{i}")).max_height(320.0).max_width(w).show(ui, |ui| {
                                    ui.add(egui::TextEdit::multiline(v).font(egui::TextStyle::Monospace).desired_rows(1).desired_width(w - 16.0).hint_text("value"));
                                });
                                if ui.add(egui::Button::new(RichText::new("×").size(z(15.0)).color(TEXT_SUBTLE())).frame(false)).on_hover_text("Remove this key").clicked() {
                                    remove = Some(i);
                                }
                            });
                            ui.add_space(6.0);
                        }
                        if let Some(i) = remove {
                            rows.remove(i);
                        }
                        ui.horizontal(|ui| {
                            if ui.small_button("+ Add key").clicked() {
                                rows.push((String::new(), String::new()));
                            }
                        });
                        ui.add_space(6.0);
                        let keys: Vec<&String> = rows.iter().map(|r| &r.0).collect();
                        let dup = keys.iter().enumerate().any(|(i, k)| keys[..i].contains(k));
                        let blank = rows.iter().any(|r| r.0.trim().is_empty());
                        if dup {
                            ui.label(RichText::new("Two keys have the same name.").color(WARNING()));
                        }
                        if blank {
                            ui.label(RichText::new("Every key needs a name.").color(WARNING()));
                        }
                        ui.horizontal(|ui| {
                            if ui.add_enabled(!dup && !blank, egui::Button::new(RichText::new("Save…").color(Color32::WHITE)).fill(PRIMARY())).clicked() {
                                // A merge patch: new and changed keys, removed keys as null.
                                let mut m = serde_json::Map::new();
                                for (k, v) in rows.iter() {
                                    let val = if secret { b64_encode(v.as_bytes()) } else { v.clone() };
                                    m.insert(k.trim().to_string(), Value::String(val));
                                }
                                let mut removed = vec![];
                                for k in original.iter() {
                                    if !rows.iter().any(|r| r.0.trim() == k) {
                                        m.insert(k.clone(), Value::Null);
                                        removed.push(k.clone());
                                    }
                                }
                                let patch = serde_json::json!({ "data": Value::Object(m) }).to_string();
                                let summary = format!(
                                    "{} key{} will be written{}.",
                                    rows.len(),
                                    if rows.len() == 1 { "" } else { "s" },
                                    if removed.is_empty() { String::new() } else { format!(" and {} removed ({})", removed.len(), removed.join(", ")) }
                                );
                                save = Some((patch, summary));
                            }
                            if ui.button("Cancel").clicked() {
                                cancel = true;
                            }
                        });
                    });
                    if let Some((patch, summary)) = save {
                        if self.demo {
                            self.toast("Demo data: saving is turned off.".into(), true);
                        } else if !self.unlocked.contains(&sel.ctx) {
                            self.dialog = Some(Dialog::Protected { ctx: sel.ctx.clone() });
                        } else {
                            self.dialog = Some(Dialog::SaveData { sel: sel.clone(), patch, summary });
                        }
                    }
                    if cancel {
                        self.data_edit = None;
                    }
                } else if data.is_empty() {
                    ui.label(RichText::new("No data.").color(TEXT_SUBTLE()));
                } else {
                    let mut toggle: Option<String> = None;
                    let mut copy: Option<String> = None;
                    // Width of the key column: the longest key, within limits.
                    let key_w = data
                        .keys()
                        .map(|k| ui.painter().layout_no_wrap(k.clone(), FontId::monospace(z(12.5)), TEXT_DEFAULT()).size().x)
                        .fold(80.0f32, f32::max)
                        .min(280.0)
                        + 12.0;
                    // Certificates and other long secret values (keys, files) get a panel each;
                    // short values stay in two columns.
                    let long = |v: &Value| -> bool {
                        secret && decode(v.as_str().unwrap_or("")).map(|t| t.trim().contains('\n') || t.contains("-----BEGIN CERTIFICATE-----")).unwrap_or(false)
                    };
                    for (k, v) in data.iter().filter(|(_, v)| long(v)) {
                        let t = decode(v.as_str().unwrap_or("")).unwrap_or_default();
                        let rk = format!("{obj_key}|{k}");
                        let pem_key = format!("pem|{rk}");
                        if t.contains("-----BEGIN CERTIFICATE-----") {
                            let pem_on = self.env_open.contains(&pem_key);
                            let (mut flip, mut cp) = (false, false);
                            certs::key_panel(
                                ui,
                                k,
                                |ui| {
                                    flip = logs_icon_button(ui).on_hover_text(if pem_on { "Show the decoded certificate" } else { "Show the PEM text" }).clicked();
                                    cp = icon_button(ui, certs::draw_copy).on_hover_text("Copy the PEM text").clicked();
                                },
                                |ui| {
                                    // Certificates aren't secret: shown decoded, no click needed.
                                    if pem_on {
                                        ui.add(egui::Label::new(RichText::new(truncate(&t, 20_000)).monospace().size(z(12.0)).color(TEXT_MUTED())).wrap());
                                    } else {
                                        certs::cert_panel(ui, &t);
                                    }
                                },
                            );
                            if flip && !self.env_open.remove(&pem_key) {
                                self.env_open.insert(pem_key);
                            }
                            if cp {
                                copy = Some(t);
                            }
                        } else {
                            let shown = self.revealed.contains(&rk);
                            let mut flip = false;
                            let mut cp = false;
                            let body = std::cell::Cell::new(false);
                            certs::key_panel(
                                ui,
                                k,
                                |ui| {
                                    flip = ui.small_button(if shown { "Hide" } else { "Reveal" }).clicked();
                                    if shown {
                                        cp = icon_button(ui, certs::draw_copy).on_hover_text("Copy").clicked();
                                    }
                                },
                                |ui| {
                                    if shown {
                                        ui.add(egui::Label::new(RichText::new(truncate(&t, 20_000)).monospace().size(z(12.0)).color(TEXT_DEFAULT())).wrap());
                                    } else {
                                        body.set(certs::blurred_block(ui).on_hover_text("Click to reveal").clicked());
                                    }
                                },
                            );
                            if flip || body.get() {
                                toggle = Some(rk);
                            }
                            if cp {
                                copy = Some(t);
                            }
                        }
                    }
                    if data.values().any(|v| !long(v)) {
                    card(ui, |ui| {
                        {
                            for (k, v) in data.iter().filter(|(_, v)| !long(v)) {
                                let raw = v.as_str().unwrap_or("");
                                ui.horizontal_top(|ui| {
                                left_cell(ui, [key_w, 18.0], egui::Label::new(RichText::new(k).monospace().size(z(12.5)).color(PRIMARY_TEXT())).truncate())
                                    .on_hover_text(k);
                                let text = decode(raw);
                                let is_cert = text.as_deref().map(|t| t.contains("-----BEGIN CERTIFICATE-----")).unwrap_or(false);
                                ui.vertical(|ui| match (&text, is_cert) {
                                    (None, _) => {
                                        ui.label(RichText::new(format!("binary data, {} bytes", b64_decode(raw).map(|b| b.len()).unwrap_or(0))).color(TEXT_SUBTLE()));
                                    }
                                    (Some(t), true) => {
                                        // Certificates aren't secret: shown decoded, no click needed.
                                        certs::cert_panel(ui, t);
                                        egui::CollapsingHeader::new(RichText::new("PEM text").size(z(12.0)).color(TEXT_SUBTLE())).id_salt(format!("pem-{obj_key}-{k}")).show(ui, |ui| {
                                            ui.add(egui::Label::new(RichText::new(truncate(t, 20_000)).monospace().size(z(11.0)).color(TEXT_MUTED())).wrap());
                                        });
                                    }
                                    (Some(t), false) if secret => {
                                        let rk = format!("{obj_key}|{k}");
                                        if self.revealed.contains(&rk) {
                                            ui.horizontal(|ui| {
                                                ui.add(egui::Label::new(RichText::new(truncate(t, 8000)).monospace().size(z(12.0)).color(TEXT_DEFAULT())).wrap().sense(Sense::click()))
                                                    .on_hover_text("Click to hide")
                                                    .clicked()
                                                    .then(|| toggle = Some(rk.clone()));
                                                if ui.small_button("Copy").clicked() {
                                                    copy = Some(t.clone());
                                                }
                                            });
                                        } else if blurred(ui).on_hover_text("Click to reveal").clicked() {
                                            toggle = Some(rk);
                                        }
                                    }
                                    (Some(t), false) => {
                                        let lines = t.lines().count();
                                        if lines > 24 {
                                            let head: String = t.lines().take(24).collect::<Vec<_>>().join("\n");
                                            egui::CollapsingHeader::new(RichText::new(format!("Show all {lines} lines")).size(z(12.0)).color(TEXT_SUBTLE()))
                                                .id_salt(format!("cmv-{obj_key}-{k}"))
                                                .show_unindented(ui, |ui| {
                                                    ui.add(egui::Label::new(RichText::new(truncate(t, 200_000)).monospace().size(z(12.0)).color(TEXT_DEFAULT())).wrap());
                                                })
                                                .body_returned
                                                .is_none()
                                                .then(|| ui.add(egui::Label::new(RichText::new(head).monospace().size(z(12.0)).color(TEXT_DEFAULT())).wrap()));
                                        } else {
                                            ui.add(egui::Label::new(RichText::new(truncate(t, 8000)).monospace().size(z(12.0)).color(TEXT_DEFAULT())).wrap());
                                        }
                                    }
                                });
                                });
                                ui.add_space(10.0);
                            }
                        }
                    });
                    }
                    if let Some(rk) = toggle {
                        if !self.revealed.remove(&rk) {
                            self.revealed.insert(rk);
                        }
                    }
                    if let Some(t) = copy {
                        ui.ctx().copy_text(t);
                        self.toast("Value copied".into(), false);
                    }
                }
            }

            // Conditions, with what they say.
            if let Some(conds) = o["status"]["conditions"].as_array().filter(|a| !a.is_empty()) {
                ui.add_space(8.0);
                egui::CollapsingHeader::new(RichText::new(format!("Conditions ({})", conds.len())).size(z(14.0)).color(TEXT_MUTED())).id_salt("conds").show(ui, |ui| card(ui, |ui| {
                    for c in conds {
                        let ok = c["status"] == "True";
                        let ty = c["type"].as_str().unwrap_or("");
                        let good = face::good_when_true(ty).map(|g| g == ok);
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new(match good { Some(true) => "✓", Some(false) => "×", None => "·" }).strong().color(match good { Some(true) => SUCCESS(), Some(false) => DANGER(), None => INFO() }));
                            ui.label(RichText::new(ty).color(TEXT_DEFAULT()).strong());
                            if let Some(m) = c["message"].as_str().filter(|m| !m.is_empty()).or(c["reason"].as_str()) {
                                ui.add(egui::Label::new(RichText::new(truncate(m, 400)).color(TEXT_SUBTLE()).size(z(12.0))).wrap());
                            }
                        });
                    }
                }));
            }
            if let Some(t) = face::meta(ui, &sel.key(), &self.refs_of(sel, o), o) {
                open_pod = Some(t);
            }
            ui.add_space(12.0);
        });
        if let Some(g) = go {
            self.follow(g, sel);
        }
        if let Some(p) = open_pod {
            // Back (⌘[ or ←) returns here.
            self.navigate(View::Resource(p.kind), Some(p));
        }
    }

    fn detail_yaml(&mut self, ui: &mut Ui, sel: &Selected) {
        let key = format!("yaml|{}", sel.key());
        let entry = self.yaml.get(&key).cloned();
        let text = match entry {
            None | Some((true, _)) => {
                if self.demo {
                    Some(demo_yaml(sel))
                } else {
                    ui.spinner();
                    None
                }
            }
            Some((false, Err(e))) => {
                ui.label(RichText::new(e).color(WARNING()));
                None
            }
            Some((false, Ok(t))) => Some(t),
        };
        let Some(text) = text else { return };
        let editing = self.yaml_edit.as_ref().map(|e| e.0 == key).unwrap_or(false);
        ui.horizontal(|ui| {
            if editing {
                if button(ui, "Apply changes", true, false) {
                    let y = self.yaml_edit.as_ref().map(|e| e.1.clone()).unwrap_or_default();
                    let body = format!("Apply your edited YAML to {} “{}” in {}?", sel.kind.singular(), sel.name, sel.ctx);
                    self.request(Action::Apply(sel.clone(), y), "Apply changes".into(), body, "Apply", false);
                }
                if button(ui, "Cancel", false, false) {
                    self.yaml_edit = None;
                }
            } else {
                if button(ui, "Edit", false, false) {
                    self.yaml_edit = Some((key.clone(), text.clone()));
                }
                if button(ui, "Copy", false, false) {
                    ui.ctx().copy_text(text.clone());
                    self.toast("YAML copied".into(), false);
                }
            }
            ui.label(RichText::new(format!("{} lines", text.lines().count())).color(TEXT_PLACEHOLDER()).size(z(12.0)));
        });
        ui.add_space(4.0);
        Frame::new().fill(BG_SUBTLE()).corner_radius(CornerRadius::same(6)).inner_margin(Margin::same(8)).show(ui, |ui| {
            egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                if let Some((_, buf)) = self.yaml_edit.as_mut().filter(|e| e.0 == key) {
                    ui.add(egui::TextEdit::multiline(buf).code_editor().desired_width(f32::INFINITY));
                } else {
                    let mut job = egui::text::LayoutJob::default();
                    for line in text.lines() {
                        yaml_line(&mut job, line);
                    }
                    ui.add(egui::Label::new(job).extend());
                }
            });
        });
    }

    fn detail_events(&mut self, ui: &mut Ui, sel: &Selected) {
        let key = format!("events|{}", sel.key());
        match self.events.get(&key) {
            None if self.demo => {
                ui.label(RichText::new("Scheduled · Successfully assigned to node worker-1").color(TEXT_MUTED()));
                ui.label(RichText::new("Pulled · Container image already present on machine").color(TEXT_MUTED()));
                ui.label(RichText::new("Started · Started container").color(TEXT_MUTED()));
            }
            None | Some((true, _)) => {
                ui.spinner();
            }
            Some((false, Err(e))) => {
                ui.label(RichText::new(e).color(WARNING()));
            }
            Some((false, Ok(items))) => {
                if items.is_empty() {
                    ui.label(RichText::new("No recent events for this object.").color(TEXT_SUBTLE()));
                    return;
                }
                let mut items = items.clone();
                items.sort_by_key(|e| {
                    kube::age_secs(e["lastTimestamp"].as_str().or(e["eventTime"].as_str()).or(e["metadata"]["creationTimestamp"].as_str()).unwrap_or(""))
                });
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    for e in items {
                        let warn = e["type"] == "Warning";
                        card(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(e["reason"].as_str().unwrap_or("")).strong().color(if warn { WARNING() } else { TEXT_DEFAULT() }));
                                ui.label(RichText::new(format!(
                                    "{} ago{}",
                                    kube::age(e["lastTimestamp"].as_str().or(e["eventTime"].as_str()).or(e["metadata"]["creationTimestamp"].as_str()).unwrap_or("")),
                                    e["count"].as_i64().filter(|c| *c > 1).map(|c| format!(" · ×{c}")).unwrap_or_default()
                                )).color(TEXT_PLACEHOLDER()).size(z(12.0)));
                            });
                            ui.label(RichText::new(e["message"].as_str().unwrap_or("")).color(TEXT_MUTED()));
                        });
                        ui.add_space(4.0);
                    }
                });
            }
        }
    }

    fn detail_logs(&mut self, ui: &mut Ui, sel: &Selected, obj: Option<&Value>) {
        let containers: Vec<String> = obj
            .and_then(|o| o["spec"]["containers"].as_array().or(o["spec"]["template"]["spec"]["containers"].as_array()).cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|c| c["name"].as_str().map(String::from))
            .collect();
        let mut restart = false;
        ui.horizontal_wrapped(|ui| {
            if containers.len() > 1 {
                let label = if self.log_prefs.container.is_empty() { "All containers".to_string() } else { self.log_prefs.container.clone() };
                egui::ComboBox::from_id_salt("log-container").selected_text(label).show_ui(ui, |ui| {
                    if ui.selectable_value(&mut self.log_prefs.container, String::new(), "All containers").clicked() {
                        restart = true;
                    }
                    for c in &containers {
                        if ui.selectable_value(&mut self.log_prefs.container, c.clone(), c).clicked() {
                            restart = true;
                        }
                    }
                });
            }
            let since_label = |t: &str| match t {
                NEW_LINES | EVERYTHING => t.to_string(),
                x => format!("Last {x}"),
            };
            egui::ComboBox::from_id_salt("log-since").selected_text(since_label(self.log_prefs.since)).show_ui(ui, |ui| {
                for t in SINCE_CHOICES {
                    if ui.selectable_value(&mut self.log_prefs.since, t, since_label(t)).clicked() {
                        restart = true;
                    }
                }
            })
            .response
            .on_hover_text("How far back to read");
            restart |= ui.checkbox(&mut self.log_prefs.follow, "Follow").changed();
            restart |= ui.checkbox(&mut self.log_prefs.timestamps, "Timestamps (UTC)").changed();
            restart |= ui.checkbox(&mut self.log_prefs.previous, "Previous").on_hover_text("Logs of the previous, crashed container").changed();
            ui.checkbox(&mut self.log_prefs.wrap, "Wrap");
        });
        ui.horizontal(|ui| {
            filter_box(ui, &mut self.log_prefs.filter, "Filter lines…", 220.0);
            let (n, running) = self.log.as_ref().map(|l| (l.lines.len(), l.running)).unwrap_or((0, false));
            ui.label(RichText::new(format!("{n} lines")).color(TEXT_PLACEHOLDER()).size(z(12.0)));
            if running {
                ui.label(RichText::new("● live").color(SUCCESS()).size(z(12.0)));
            }
            if button(ui, "Copy", false, false) {
                if let Some(l) = &self.log {
                    let t: Vec<&str> = l.lines.iter().map(|x| x.text.as_str()).collect();
                    ui.ctx().copy_text(t.join("\n"));
                }
            }
            if button(ui, "Clear", false, false) {
                if let Some(l) = self.log.as_mut() {
                    l.lines.clear();
                }
            }
        });
        // One toggle per level, with its count.
        let mut counts: HashMap<Level, usize> = HashMap::new();
        if let Some(l) = &self.log {
            for x in &l.lines {
                *counts.entry(x.level).or_default() += 1;
            }
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Levels").size(z(12.0)).color(TEXT_SUBTLE()));
            for lv in Level::ALL {
                let n = counts.get(&lv).copied().unwrap_or(0);
                let on = !self.log_prefs.hidden_levels.contains(&lv);
                let text = RichText::new(format!("{} {n}", lv.label())).size(z(11.5)).color(if on { level_color(lv) } else { TEXT_PLACEHOLDER() });
                if ui.add(egui::Button::new(text).fill(if on { BG_MUTED() } else { Color32::TRANSPARENT }).stroke(Stroke::new(1.0, BORDER_SUBTLE()))).clicked() {
                    if on {
                        self.log_prefs.hidden_levels.insert(lv);
                    } else {
                        self.log_prefs.hidden_levels.remove(&lv);
                    }
                }
            }
            if let Some(d) = self.log.as_ref().map(|l| l.dropped).filter(|d| *d > 0) {
                ui.label(RichText::new(format!("{d} older lines dropped")).size(z(11.5)).color(TEXT_PLACEHOLDER()));
            }
        });
        if restart || self.log.as_ref().map(|l| l.target != sel.key()).unwrap_or(true) {
            self.start_logs(sel);
        }
        let hidden = self.log_prefs.hidden_levels.clone();
        let filter = self.log_prefs.filter.to_lowercase();
        let wrap = self.log_prefs.wrap;
        Frame::new().fill(LOG_BG()).corner_radius(CornerRadius::same(6)).inner_margin(Margin::same(8)).show(ui, |ui| {
            let lines: Vec<&LogLine> = self
                .log
                .as_ref()
                .map(|l| {
                    l.lines
                        .iter()
                        .filter(|x| !hidden.contains(&x.level))
                        .filter(|x| filter.is_empty() || x.text.to_lowercase().contains(&filter))
                        .collect()
                })
                .unwrap_or_default();
            let log_size = self.prefs.log_size;
            // One line's height in the log font, so rows never overlap at larger sizes.
            let row_h = ui.fonts_mut(|f| f.row_height(&FontId::monospace(log_size)));
            let mut sa = egui::ScrollArea::both().auto_shrink([false, false]).stick_to_bottom(true);
            if wrap {
                sa = egui::ScrollArea::vertical().auto_shrink([false, false]).stick_to_bottom(true);
            }
            if lines.is_empty() {
                ui.label(RichText::new(if self.log.as_ref().map(|l| l.running).unwrap_or(false) { "Waiting for log lines…" } else { "No log lines." }).color(TEXT_SUBTLE()).monospace());
            }
            if wrap {
                sa.show(ui, |ui| {
                    let start = lines.len().saturating_sub(WRAP_RENDER_LINES);
                    for x in &lines[start..] {
                        ui.add(egui::Label::new(RichText::new(&x.text).monospace().size(log_size).color(level_color(x.level))).wrap());
                    }
                });
            } else {
                sa.show_rows(ui, row_h, lines.len(), |ui, range| {
                    for x in &lines[range] {
                        ui.add(egui::Label::new(RichText::new(&x.text).monospace().size(log_size).color(level_color(x.level))).extend());
                    }
                });
            }
        });
    }

    // ---------------- dialogs ----------------

    fn dialogs(&mut self, ctx: &egui::Context) {
        let Some(d) = self.dialog.take() else { return };
        let drain_blockers = match &d {
            Dialog::Drain { sel, .. } => self.drain_blockers(&sel.ctx, &sel.name),
            _ => None,
        };
        let mut keep = true;
        let mut run: Option<Action> = None;
        let mut start_pf: Option<(Selected, u16, u16, bool)> = None;
        let mut next: Option<Dialog> = None;
        let mut connect_after = false;
        let mut go_settings = false;
        let mut d = d;
        let dctx: Option<String> = match &d {
            Dialog::Confirm { action, .. } => Some(action.ctx().to_string()),
            Dialog::Protected { ctx } => Some(ctx.clone()),
            Dialog::Scale { sel, .. } | Dialog::Drain { sel, .. } | Dialog::Delete { sel, .. } | Dialog::SaveData { sel, .. } | Dialog::PortForward { sel, .. } => Some(sel.ctx.clone()),
            Dialog::DeleteContext { name, .. } => Some(name.clone()),
            Dialog::NameClusters { .. } => None,
        };
        let modal = egui::Modal::new(egui::Id::new("dialog"))
            .frame(Frame::new().fill(BG_DEFAULT()).stroke(Stroke::new(1.0, BORDER_DEFAULT())).corner_radius(CornerRadius::same(10)).inner_margin(Margin::same(18)))
            .show(ctx, |ui| {
                ui.set_width(420.0);
                // Which cluster this is about, so a change never lands on the wrong one.
                if let Some(c) = &dctx {
                    cluster_badge(ui, c);
                    ui.add_space(10.0);
                }
                match &mut d {
                    Dialog::Confirm { title, body, button: b, danger, action } => {
                        ui.label(RichText::new(title.as_str()).size(z(16.0)).strong().color(TEXT_DEFAULT()));
                        ui.add_space(6.0);
                        ui.label(RichText::new(body.as_str()).color(TEXT_MUTED()));
                        ui.add_space(14.0);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if button(ui, b, !*danger, *danger) {
                                run = Some(action.clone());
                                keep = false;
                            }
                            if button(ui, "Cancel", false, false) {
                                keep = false;
                            }
                        });
                    }
                    Dialog::Protected { ctx } => {
                        ui.label(RichText::new("This context is protected").size(z(16.0)).strong().color(TEXT_DEFAULT()));
                        ui.add_space(6.0);
                        ui.add(egui::Label::new(RichText::new(format!("Changes to “{}” are blocked so nothing is changed by accident: every cluster starts protected when Kubedog opens. Allow changes for this session (the lock at the top left does the same), then try again.", ctx_label(ctx))).color(TEXT_MUTED())).wrap());
                        ui.add_space(4.0);
                        ui.add(egui::Label::new(RichText::new("In Settings > Clusters a cluster, or all of them, can start with changes allowed. Changes still ask before they're done.").size(z(12.5)).color(TEXT_SUBTLE())).wrap());
                        ui.add_space(14.0);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if button(ui, "Allow changes", true, false) {
                                self.unlocked.insert(ctx.clone());
                                keep = false;
                            }
                            if button(ui, "Keep protected", false, false) {
                                keep = false;
                            }
                            if button(ui, "Settings…", false, false) {
                                go_settings = true;
                                keep = false;
                            }
                        });
                    }
                    Dialog::Scale { sel, replicas } => {
                        ui.label(RichText::new(format!("Scale {}", sel.name)).size(z(16.0)).strong().color(TEXT_DEFAULT()));
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Replicas").color(TEXT_MUTED()));
                            if ui.button("−").clicked() {
                                let n = replicas.parse::<i64>().unwrap_or(1).saturating_sub(1).max(0);
                                *replicas = n.to_string();
                            }
                            ui.add(egui::TextEdit::singleline(replicas).desired_width(60.0));
                            if ui.button("+").clicked() {
                                let n = replicas.parse::<i64>().unwrap_or(0) + 1;
                                *replicas = n.to_string();
                            }
                        });
                        ui.add_space(14.0);
                        let valid = replicas.trim().parse::<i64>().ok().filter(|n| *n >= 0);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.add_enabled(valid.is_some(), egui::Button::new(RichText::new("Scale").color(Color32::WHITE)).fill(PRIMARY())).clicked() {
                                run = Some(Action::Scale(sel.clone(), valid.unwrap_or(0)));
                                keep = false;
                            }
                            if button(ui, "Cancel", false, false) {
                                keep = false;
                            }
                        });
                    }
                    Dialog::Drain { sel, delete_emptydir, disable_eviction, force } => {
                        ui.label(RichText::new(format!("Drain node {}", sel.name)).size(z(16.0)).strong().color(TEXT_DEFAULT()));
                        ui.add_space(6.0);
                        ui.label(RichText::new("No new pods land on it, and the ones there move to other nodes. Daemon sets stay. It gives up after 10 minutes; what hasn't moved by then stays.").color(TEXT_MUTED()));
                        ui.add_space(6.0);
                        ui.checkbox(delete_emptydir, "Throw away temporary data (emptyDir volumes)");
                        ui.checkbox(disable_eviction, "Ignore disruption budgets");
                        ui.checkbox(force, "Also remove pods that nothing will start again");
                        ui.add_space(8.0);
                        let blockers = drain_blockers.clone();
                        let blocked = match &blockers {
                            None => {
                                ui.horizontal(|ui| {
                                    ui.spinner();
                                    ui.label(RichText::new("Checking the pods on this node…").color(TEXT_SUBTLE()));
                                });
                                true
                            }
                            Some((ed, um)) => {
                                let mut b = false;
                                if !*delete_emptydir && !ed.is_empty() {
                                    b = true;
                                    ui.label(RichText::new(format!("These would lose their temporary data: {}", some_names(ed))).color(WARNING()));
                                }
                                if !*force && !um.is_empty() {
                                    b = true;
                                    ui.label(RichText::new(format!("These would be gone for good: {}", some_names(um))).color(WARNING()));
                                }
                                b
                            }
                        };
                        ui.add_space(14.0);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let start = ui.add_enabled(!blocked, egui::Button::new(RichText::new("Drain").color(Color32::WHITE)).fill(PRIMARY()));
                            if start.clicked() {
                                run = Some(Action::Drain(sel.clone(), *delete_emptydir, *disable_eviction, *force));
                                keep = false;
                            }
                            if button(ui, "Cancel", false, false) {
                                keep = false;
                            }
                        });
                    }
                    Dialog::DeleteContext { name, file } => {
                        ui.label(RichText::new(format!("Delete {name}?")).size(z(16.0)).strong().color(TEXT_DEFAULT()));
                        ui.add_space(6.0);
                        ui.label(RichText::new(format!("This removes the context entry from {}. Its cluster and user entries stay in the file. To only hide it from Kubedog, use “Hide from list” instead.", clusters::short_path(file))).color(TEXT_MUTED()));
                        ui.add_space(14.0);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if button(ui, "Delete from file", false, true) {
                                let key = format!("ctxdel|{name}");
                                let args = vec!["config".into(), "delete-context".into(), name.clone(), "--kubeconfig".into(), file.clone()];
                                self.prefs.contexts.retain(|c| c != name);
                                self.picker.remove(name.as_str());
                                self.spawn(move |k| Msg::Text { key, result: k.run(&args) });
                                keep = false;
                            }
                            if button(ui, "Cancel", false, false) {
                                keep = false;
                            }
                        });
                    }
                    Dialog::SaveData { sel, patch, summary } => {
                        ui.label(RichText::new(format!("Save {}?", sel.name)).size(z(16.0)).strong().color(TEXT_DEFAULT()));
                        ui.add_space(6.0);
                        ui.label(RichText::new(summary.as_str()).color(TEXT_MUTED()));
                        ui.add_space(14.0);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if button(ui, "Save", true, false) {
                                run = Some(Action::Patch(sel.clone(), patch.clone()));
                                keep = false;
                            }
                            if button(ui, "Cancel", false, false) {
                                keep = false;
                            }
                        });
                    }
                    Dialog::Delete { sel, force, orphan, advanced } => {
                        let what = if sel.kind.namespaced() { format!("{}/{}", sel.ns, sel.name) } else { sel.name.clone() };
                        ui.label(RichText::new(format!("Delete {}", what)).size(z(16.0)).strong().color(TEXT_DEFAULT()));
                        ui.label(RichText::new(format!("{} · {}", sel.kind.label(), ctx_label(&sel.ctx))).size(z(12.0)).color(TEXT_SUBTLE()));
                        ui.add_space(10.0);
                        if ui.add(egui::Button::new(RichText::new(if *advanced { "Fewer options ▾" } else { "More options ▸" }).size(z(12.5)).color(TEXT_SUBTLE())).frame(false)).clicked() {
                            *advanced = !*advanced;
                        }
                        if *advanced {
                            ui.checkbox(force, "Don't wait for it to stop by itself");
                            // For everything that runs pods of its own.
                            if matches!(sel.kind, Kind::Deployments | Kind::StatefulSets | Kind::DaemonSets | Kind::ReplicaSets | Kind::Jobs) {
                                ui.checkbox(orphan, "Keep its pods running");
                            }
                        }
                        ui.add_space(8.0);
                        ui.label(RichText::new("There's no way back once it's gone.").size(z(12.5)).color(TEXT_SUBTLE()));
                        ui.add_space(12.0);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if button(ui, "Delete", false, true) {
                                run = Some(Action::Delete(sel.clone(), *force, *orphan));
                                keep = false;
                            }
                            if button(ui, "Cancel", false, false) {
                                keep = false;
                            }
                        });
                    }
                    Dialog::PortForward { sel, ports, remote, local, open_browser } => {
                        ui.label(RichText::new(format!("Port forward {}", sel.name)).size(z(16.0)).strong().color(TEXT_DEFAULT()));
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.add_sized([110.0, 20.0], egui::Label::new(RichText::new("Remote port").color(TEXT_MUTED())));
                            ui.add(egui::TextEdit::singleline(remote).desired_width(80.0));
                            for p in ports.clone() {
                                if ui.small_button(p.to_string()).clicked() {
                                    *remote = p.to_string();
                                    *local = suggest_local(p).to_string();
                                }
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.add_sized([110.0, 20.0], egui::Label::new(RichText::new("Local port").color(TEXT_MUTED())));
                            ui.label(RichText::new("localhost:").color(TEXT_SUBTLE()));
                            ui.add(egui::TextEdit::singleline(local).desired_width(80.0));
                            if ui.small_button("Any free port").on_hover_text("A port that's free on this computer").clicked() {
                                *local = free_port().to_string();
                            }
                        });
                        ui.checkbox(open_browser, "Open in browser when it starts");
                        ui.add_space(14.0);
                        let r = remote.trim().parse::<u16>().ok().filter(|p| *p > 0);
                        let l = local.trim().parse::<u16>().ok().filter(|p| *p > 0);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.add_enabled(r.is_some() && l.is_some(), egui::Button::new(RichText::new("Start").color(Color32::WHITE)).fill(PRIMARY())).clicked() {
                                start_pf = Some((sel.clone(), l.unwrap_or(0), r.unwrap_or(0), *open_browser));
                                keep = false;
                            }
                            if button(ui, "Cancel", false, false) {
                                keep = false;
                            }
                        });
                    }
                    Dialog::NameClusters { names } => {
                        ui.label(RichText::new("Give your clusters short names").size(z(16.0)).strong().color(TEXT_DEFAULT()));
                        ui.add_space(4.0);
                        ui.label(RichText::new(format!("Names of up to {MAX_CLUSTER_NAME} characters keep the sidebar, the lists and the namespace menu readable. Kubedog keeps them; kubectl still uses the real names.")).size(z(12.5)).color(TEXT_SUBTLE()));
                        ui.add_space(10.0);
                        for (ctx, name) in names.iter_mut() {
                            ui.horizontal(|ui| {
                                let (r, _) = ui.allocate_exact_size(egui::vec2(22.0, 22.0), Sense::hover());
                                ctx_mark(ui.painter(), r, ctx);
                                ui.add(egui::TextEdit::singleline(name).char_limit(MAX_CLUSTER_NAME).desired_width(150.0));
                                let n = name.trim().chars().count();
                                ui.label(RichText::new(format!("{n}/{MAX_CLUSTER_NAME}")).size(z(11.5)).color(if n == 0 { WARNING() } else { TEXT_PLACEHOLDER() }));
                            });
                            ui.horizontal(|ui| {
                                ui.add_space(30.0);
                                ui.add(egui::Label::new(RichText::new(ctx.as_str()).size(z(11.0)).color(TEXT_PLACEHOLDER())).truncate());
                            });
                            ui.add_space(4.0);
                        }
                        let trimmed: Vec<String> = names.iter().map(|(_, n)| n.trim().to_string()).collect();
                        let mut uniq = trimmed.clone();
                        uniq.sort();
                        uniq.dedup();
                        let ok = trimmed.iter().all(|n| !n.is_empty() && n.chars().count() <= MAX_CLUSTER_NAME) && uniq.len() == trimmed.len();
                        if !ok && uniq.len() != trimmed.len() {
                            ui.label(RichText::new("Each cluster needs its own name.").size(z(12.0)).color(WARNING()));
                        }
                        ui.add_space(10.0);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.add_enabled(ok, egui::Button::new(RichText::new("Save and connect").color(Color32::WHITE)).fill(PRIMARY())).clicked() {
                                for (ctx, name) in names.iter() {
                                    self.prefs.ctx_alias.insert(ctx.clone(), name.trim().to_string());
                                }
                                self.save();
                                keep = false;
                                connect_after = true;
                            }
                            if button(ui, "Cancel", false, false) {
                                keep = false;
                            }
                        });
                    }
                }
            });
        if modal.should_close() {
            keep = false;
        }
        if let Some(a) = run {
            if matches!(a, Action::Scale(..) | Action::Drain(..) | Action::Delete(..) | Action::Patch(..) | Action::Many { .. }) {
                // Scale/drain dialogs already passed the protection check.
                if self.unlocked.contains(a.ctx()) {
                    self.run_action(a);
                } else {
                    next = Some(Dialog::Protected { ctx: a.ctx().to_string() });
                }
            } else {
                self.run_action(a);
            }
        }
        if let Some((sel, l, r, open)) = start_pf {
            if self.demo {
                self.toast("Demo data: port forwards are turned off.".into(), true);
            } else {
                self.start_port_forward(&sel, l, r, open);
            }
        }
        if keep {
            self.dialog = Some(d);
        } else if next.is_some() {
            self.dialog = next;
        }
        if go_settings {
            self.settings_section = "Clusters";
            self.set_view(View::Settings);
        }
        if connect_after {
            self.connect();
        }
    }

    fn toasts_ui(&mut self, ctx: &egui::Context) {
        self.toasts.retain(|t| t.at.elapsed() < Duration::from_secs(if t.error { 8 } else { 4 }));
        if self.toasts.is_empty() {
            return;
        }
        ctx.request_repaint_after(Duration::from_millis(500));
        egui::Area::new(egui::Id::new("toasts"))
            .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-16.0, -36.0))
            .show(ctx, |ui| {
                for t in &self.toasts {
                    Frame::new()
                        .fill(if t.error { ERROR_BG() } else { BG_MUTED() })
                        .stroke(Stroke::new(1.0, if t.error { DANGER_BG() } else { BORDER_DEFAULT() }))
                        .corner_radius(CornerRadius::same(8))
                        .inner_margin(Margin::symmetric(12, 8))
                        .show(ui, |ui| {
                            ui.set_max_width(420.0);
                            ui.label(RichText::new(truncate(&t.text, 300)).color(if t.error { DANGER() } else { TEXT_DEFAULT() }));
                        });
                    ui.add_space(6.0);
                }
            });
    }

    fn shortcuts(&mut self, ctx: &egui::Context) {
        // The mouse's back and forward buttons, wherever the keyboard is.
        if self.connected && self.dialog.is_none() && self.palette.is_none() {
            let (back, fwd) = ctx.input(|i| (i.pointer.button_pressed(egui::PointerButton::Extra1), i.pointer.button_pressed(egui::PointerButton::Extra2)));
            if back {
                self.back_pressed();
            } else if fwd {
                self.forward_pressed();
            }
        }
        // ⌘J shows or hides the built-in terminal.
        if ctx.input(|i| i.modifiers.command && i.key_pressed(Key::J)) && self.term.has_sessions() {
            self.term.open = !self.term.open;
            self.term.focused = self.term.open;
        }
        // While the built-in terminal has focus, keys belong to the shell, not to Kubedog.
        if (self.term.focused && self.term.open) || self.shell_typing() {
            return;
        }
        if self.connected && ctx.input(|i| i.modifiers.command && i.key_pressed(Key::K)) {
            if self.palette.is_some() {
                self.palette = None;
            } else {
                self.open_search();
            }
        }
        if self.palette.is_some() {
            return;
        }
        let (find, refresh, esc, zin, zout, zreset) = ctx.input(|i| {
            let cmd = i.modifiers.command;
            (
                cmd && i.key_pressed(Key::F),
                cmd && i.key_pressed(Key::R),
                i.key_pressed(Key::Escape),
                cmd && (i.key_pressed(Key::Equals) || i.key_pressed(Key::Plus)),
                cmd && i.key_pressed(Key::Minus),
                cmd && i.key_pressed(Key::Num0),
            )
        });
        if find {
            self.focus_search = true;
        }
        if refresh {
            self.refresh_current(true);
        }
        let typing_now = ctx.memory(|m| m.focused().is_some());
        // As in a browser: ⌘[ and ⌘← on a Mac (the menu brings ⌘[ and ⌘]), Alt+← elsewhere, and a keyboard's
        // own Back and Forward keys.
        let (hb, hf, kb, kf) = ctx.input(|i| {
            let mac = cfg!(target_os = "macos");
            let with = if mac { i.modifiers.command } else { i.modifiers.alt || i.modifiers.command };
            let bracket = !mac && i.modifiers.command;
            (with && i.key_pressed(Key::ArrowLeft) || bracket && i.key_pressed(Key::OpenBracket), with && i.key_pressed(Key::ArrowRight) || bracket && i.key_pressed(Key::CloseBracket), i.key_pressed(Key::BrowserBack), i.key_pressed(Key::BrowserForward))
        });
        // While typing the arrows move in the text.
        if hb && !typing_now || kb {
            self.back_pressed();
        } else if hf && !typing_now || kf {
            self.forward_pressed();
        }
        if esc && self.dialog.is_none() && self.selected.is_some() {
            self.back_pressed();
        } else if esc && self.dialog.is_none() && !typing_now {
            self.picks.clear();
        }
        // ⌘A ticks everything the list shows.
        if let (Some(w), None, false) = (self.pick_what(), &self.dialog, typing_now) {
            if self.connected && self.picks.what.as_ref() == Some(&w) && ctx.input(|i| i.modifiers.command && i.key_pressed(Key::A)) {
                self.pick_all(&w);
            }
        }
        // ⌃1-9 opens a saved group; "G" then a letter goes to a page.
        if !typing_now && self.dialog.is_none() {
            let digit = ctx.input(|i| {
                if !i.modifiers.ctrl || i.modifiers.command {
                    return None;
                }
                [Key::Num1, Key::Num2, Key::Num3, Key::Num4, Key::Num5, Key::Num6, Key::Num7, Key::Num8, Key::Num9].iter().position(|k| i.key_pressed(*k))
            });
            if let Some(d) = digit {
                self.open_group(d);
                return;
            }
        }
        if self.connected && !typing_now && self.dialog.is_none() {
            if self.chord.map(|t| t.elapsed() > Duration::from_millis(1500)).unwrap_or(false) {
                self.chord = None;
            }
            if self.chord.is_some() {
                let hit = ctx.input_mut(|i| {
                    if i.modifiers.any() {
                        return None;
                    }
                    GO_KEYS.iter().find(|(k, _, _)| i.consume_key(egui::Modifiers::NONE, *k)).map(|g| g.1)
                });
                if let Some(v) = hit {
                    self.chord = None;
                    self.navigate(v, None);
                    return;
                }
                // Another key ends the chord without doing anything else.
                if ctx.input(|i| i.events.iter().any(|e| matches!(e, egui::Event::Key { pressed: true, .. }))) {
                    self.chord = None;
                    return;
                }
            } else if ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, Key::G)) {
                self.chord = Some(Instant::now());
                return;
            }
        }
        // Single-key shortcuts on an object's page:
        // L logs, E YAML, R restart, S scale, ⌘⌫ delete (only when not typing).
        let typing = ctx.memory(|m| m.focused().is_some());
        if let (Some(sel), false, None) = (self.selected.clone(), typing, self.dialog.as_ref()) {
            let (l, e, r, sc, del) = ctx.input(|i| {
                let plain = !i.modifiers.any();
                (
                    plain && i.key_pressed(Key::L),
                    plain && i.key_pressed(Key::E),
                    plain && i.key_pressed(Key::R),
                    plain && i.key_pressed(Key::S),
                    i.modifiers.command && i.key_pressed(Key::Backspace),
                )
            });
            if l && sel.kind.has_logs() {
                self.set_tab(Tab::Logs, &sel);
            }
            if e {
                self.set_tab(Tab::Yaml, &sel);
            }
            if r && sel.kind.can_restart() {
                self.ask_restart(&sel);
            }
            if sc && sel.kind.can_scale() {
                let cur = self.selected_object().and_then(|o| o["spec"]["replicas"].as_i64()).unwrap_or(1);
                if !self.unlocked.contains(&sel.ctx) && !self.demo {
                    self.dialog = Some(Dialog::Protected { ctx: sel.ctx.clone() });
                } else {
                    self.dialog = Some(Dialog::Scale { sel: sel.clone(), replicas: cur.to_string() });
                }
            }
            if del && sel.kind != Kind::Events {
                self.ask_delete(&sel);
            }
        }
        let z = ctx.zoom_factor();
        if zin {
            ctx.set_zoom_factor(zoom_step(z, true));
        }
        if zout {
            ctx.set_zoom_factor(zoom_step(z, false));
        }
        if zreset {
            ctx.set_zoom_factor(1.0);
        }
    }

    /// Choices from the macOS menu bar (see menu.rs).
    fn menu_commands(&mut self, ctx: &egui::Context) {
        for id in std::mem::take(&mut self.menu_pending) {
            let z = ctx.zoom_factor();
            match id.as_str() {
                "refresh" => self.refresh_current(true),
                "find" => self.focus_search = true,
                "zoomin" => ctx.set_zoom_factor(zoom_step(z, true)),
                "zoomout" => ctx.set_zoom_factor(zoom_step(z, false)),
                "zoomreset" => ctx.set_zoom_factor(1.0),
                "terminal" => {
                    if self.term.has_sessions() {
                        self.term.open = !self.term.open;
                        self.term.focused = self.term.open;
                    } else {
                        self.toast("No terminal yet: open a Shell on a pod first.".into(), false);
                    }
                }
                "switch" => {
                    if self.connected {
                        self.disconnect();
                    }
                }
                _ if !self.connected => self.toast("Connect to a cluster first.".into(), false),
                "back" => self.back_pressed(),
                "forward" => self.forward_pressed(),
                "columns" => {
                    if matches!(self.view, View::Resource(_)) {
                        if self.selected.is_some() {
                            self.navigate(self.view, None);
                        }
                        self.open_columns = true;
                    } else {
                        self.toast("Columns can be chosen on list pages.".into(), false);
                    }
                }
                "settings" | "go:settings" => self.navigate(View::Settings, None),
                "shortcuts" => {
                    self.settings_section = "Shortcuts";
                    self.navigate(View::Settings, None);
                }
                other => {
                    if let Some(v) = other.strip_prefix("go:") {
                        let view = match v {
                            "cluster" => View::ClusterOverview,
                            "workloads" => View::WorkloadsOverview,
                            "nodes" => View::Resource(Kind::Nodes),
                            "pods" => View::Resource(Kind::Pods),
                            "deployments" => View::Resource(Kind::Deployments),
                            "services" => View::Resource(Kind::Services),
                            "events" => View::Resource(Kind::Events),
                            "helm" => View::Helm,
                            _ => continue,
                        };
                        self.navigate(view, None);
                    }
                }
            }
        }
    }

    fn maybe_screenshot(&mut self, ctx: &egui::Context) {
        self.frames += 1;
        let Some(path) = self.screenshot.clone() else { return };
        ctx.send_viewport_cmd(egui::ViewportCommand::RequestPaintWhileHidden);
        ctx.request_repaint();
        if self.shot_requested {
            if self.started.elapsed() > Duration::from_secs(60) {
                eprintln!("screenshot never arrived");
                std::process::exit(3);
            }
            return;
        }
        let elapsed = self.started.elapsed();
        // For checking pages by hand (read-only): KUBEDOG_SHOT_PAGE=pods|deployments|nodes|
        // namespaces|events|cluster|workloads|detail|logs|yaml, KUBEDOG_SHOT_NS=<namespace>.
        let page = std::env::var("KUBEDOG_SHOT_PAGE").ok();
        // KUBEDOG_SHOT_THRESHOLD=50 for the overviews' "high usage" lists.
        if let Some(t) = std::env::var("KUBEDOG_SHOT_THRESHOLD").ok().and_then(|v| v.parse().ok()) {
            self.threshold = t;
        }
        // KUBEDOG_SHOT_ZOOM=0.6 shows more of a long page (1.5 makes the window small).
        if let Some(z) = std::env::var("KUBEDOG_SHOT_ZOOM").ok().and_then(|v| v.parse::<f32>().ok()) {
            ctx.set_zoom_factor(z);
        }
        if let Some(page) = &page {
            if !self.connected && !self.contexts_loading && self.frames > 3 {
                if let Some(c) = self.contexts.first().map(|c| c.name.clone()) {
                    self.picker.insert(c);
                    // KUBEDOG_SHOT_CTXS=all (or names with commas): open several clusters at once.
                    if let Ok(want) = std::env::var("KUBEDOG_SHOT_CTXS") {
                        // Exactly the clusters named (or all of them), not the first one.
                        self.picker.clear();
                        for x in &self.contexts {
                            if want == "all" || want.split(',').any(|w| w.trim() == x.name) {
                                self.picker.insert(x.name.clone());
                            }
                        }
                    }
                    self.connect();
                    // KUBEDOG_SHOT_NS=a or a,b,c (several namespaces at once).
                    let want: Vec<String> = std::env::var("KUBEDOG_SHOT_NS").unwrap_or_default().split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
                    self.set_ns_choice(want);
                    if let Ok(since) = std::env::var("KUBEDOG_SHOT_SINCE") {
                        if let Some(c) = SINCE_CHOICES.iter().find(|c| **c == since) {
                            self.log_prefs.since = c;
                        }
                    }
                    let v = match page.as_str() {
                        "deployments" => View::Resource(Kind::Deployments),
                        "nodes" => View::Resource(Kind::Nodes),
                        "namespaces" => View::Resource(Kind::Namespaces),
                        "events" => View::Resource(Kind::Events),
                        "cluster" => View::ClusterOverview,
                        "workloads" => View::WorkloadsOverview,
                        "helm" => View::Helm,
                        "servicemap" => View::ServiceMap,
                        "storage" => View::StorageUsage,
                        "settings" => View::Settings,
                        "pvcs" => View::Resource(Kind::PersistentVolumeClaims),
                        "ingresses" | "ingressdetail" => View::Resource(Kind::Ingresses),
                        "secret" => View::Resource(Kind::Secrets),
                        "configmap" => View::Resource(Kind::ConfigMaps),
                        "deploylogs" | "deploy" => View::Resource(Kind::Deployments),
                        "postgres" | "pgcluster" => View::Postgres,
                        "elastic" | "escluster" => View::Elastic,
                        "pulsar" | "pucluster" => View::Pulsar,
                        "hive" => View::Hive,
                        "incident" => View::Incident,
                        "readiness" => View::Readiness,
                        p if p.starts_with("op:") => powers::op_index(&p[3..]).map(View::Op).unwrap_or(View::Helm),
                        "observatory" => View::Observatory,
                        "proxmox" => View::Proxmox,
                        "netlab" => View::NetLab,
                        "shell" => View::Shells,
                        "node" => View::Resource(Kind::Nodes),
                        _ => View::Resource(Kind::Pods),
                    };
                    self.set_view(v);
                }
            }
            // Manual check of the built-in terminal: a local shell only, never the cluster.
            if self.connected && page == "terminal" && !self.term.has_sessions() && self.frames > 10 {
                self.prefs.terminal = "builtin".into();
                self.run_in_terminal(
                    "local test".into(),
                    "/bin/zsh",
                    vec!["-f".into(), "-c".into(), "print -P '%F{green}kubedog built-in terminal%f'; ls -la /; print -P '%B%F{yellow}done%f%b'; sleep 60".into()],
                    None,
                );
            }
            if self.connected && self.selected.is_none() && (page == "secret" || page == "configmap") {
                let kind = if page == "secret" { Kind::Secrets } else { Kind::ConfigMaps };
                let want = std::env::var("KUBEDOG_SHOT_OBJ").unwrap_or_default();
                if let Some(ctx0) = self.active.first().cloned() {
                    let first = self.lists.get(&Self::list_key(&ctx0, kind)).and_then(|l| l.rows.iter().find(|r| r.name == want).cloned());
                    if let Some(r) = first {
                        self.view = View::Resource(kind);
                        self.select(Selected { ctx: ctx0, kind, ns: r.ns, name: r.name });
                        if std::env::var("KUBEDOG_SHOT_EDIT").is_ok() && kind == Kind::ConfigMaps {
                            if let Some(o) = self.selected_object() {
                                let rows: Vec<(String, String)> = o["data"].as_object().map(|m| m.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").chars().take(200).collect())).collect()).unwrap_or_default();
                                let keys = rows.iter().map(|r| r.0.clone()).collect();
                                self.data_edit = Some((self.selected.as_ref().unwrap().key(), rows, keys));
                            }
                        }
                        if std::env::var("KUBEDOG_SHOT_REVEAL").is_ok() {
                            if let Some(o) = self.selected_object() {
                                let k = self.selected.as_ref().unwrap().key();
                                if let Some(m) = o["data"].as_object() {
                                    if let Some(first) = m.keys().next() {
                                        self.revealed.insert(format!("{k}|{first}"));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // An Elasticsearch's or a Pulsar's page (KUBEDOG_SHOT_OBJ in KUBEDOG_SHOT_NS; KUBEDOG_SHOT_LOGIN=1 logs in).
            if self.connected && matches!(page.as_str(), "escluster" | "pucluster") && self.es_sel.is_none() && self.pu_sel.is_none() {
                if let Some(ctx) = self.active.first().cloned() {
                    let id = Some(pg::PgId { ctx, ns: self.ns_filter.clone().unwrap_or_default(), name: std::env::var("KUBEDOG_SHOT_OBJ").unwrap_or_default() });
                    if page == "escluster" { self.es_sel = id } else { self.pu_sel = id }
                }
            }
            // A Postgres cluster's page (KUBEDOG_SHOT_OBJ=name, in KUBEDOG_SHOT_NS).
            if self.connected && page == "pgcluster" && self.pg_sel.is_none() {
                if let Some(ctx) = self.active.first().cloned() {
                    let ns = self.ns_filter.clone().unwrap_or_default();
                    self.pg_sel = Some(pg::PgId { ctx, ns, name: std::env::var("KUBEDOG_SHOT_OBJ").unwrap_or_default() });
                }
            }
            // The search box with text typed (KUBEDOG_SHOT_SEARCH=text).
            if self.connected && self.frames > 30 {
                if let Ok(q) = std::env::var("KUBEDOG_SHOT_SEARCH") {
                    if self.palette.is_none() {
                        self.open_search();
                        self.palette = Some((q, 0));
                    }
                }
            }
            // A custom kind (KUBEDOG_SHOT_CRD=plural.group), and with page "crdobj" its first object.
            if self.connected && matches!(page.as_str(), "crd" | "crdobj") {
                self.sync_crds();
                let want = std::env::var("KUBEDOG_SHOT_CRD").unwrap_or_default();
                if let Some(i) = self.crd_index(&want) {
                    if self.view != View::Custom(i) {
                        self.open_custom(i);
                    } else if page == "crdobj" && self.custom_sel.is_none() && !self.shot_opened {
                        let k = self.crds[i as usize].clone();
                        let first = self.active.first().and_then(|c| {
                            let l = self.lists.get(&Self::custom_list_key(c, &k))?;
                            let o = l.items.first()?;
                            Some(crds::CustomSel { ctx: c.clone(), idx: i, ns: o["metadata"]["namespace"].as_str().unwrap_or("").to_string(), name: o["metadata"]["name"].as_str()?.to_string() })
                        });
                        if let Some(sel) = first {
                            self.refresh_custom(i, false);
                            self.shot_opened = true;
                            self.custom_sel = Some(sel.clone());
                            self.refresh_custom(i, true);
                        }
                    }
                }
            }
            // Any object's page: KUBEDOG_SHOT_PAGE=obj:Services, KUBEDOG_SHOT_OBJ=start of its name.
            if let Some(k) = page.strip_prefix("obj:").and_then(|n| GROUPS.iter().flat_map(|g| g.1.iter().copied()).find(|k| k.label().replace(' ', "").eq_ignore_ascii_case(n))) {
                if self.connected && self.selected.is_none() {
                    if self.view != View::Resource(k) {
                        self.set_view(View::Resource(k));
                    }
                    let want = std::env::var("KUBEDOG_SHOT_OBJ").unwrap_or_default();
                    if let Some(ctx0) = self.active.first().cloned() {
                        let first = self.lists.get(&Self::list_key(&ctx0, k)).and_then(|l| l.rows.iter().find(|r| r.name == want).or(l.rows.iter().find(|r| r.name.starts_with(&want))).cloned());
                        if let Some(r) = first {
                            self.select(Selected { ctx: ctx0, kind: k, ns: r.ns, name: r.name });
                            let sel = self.selected.clone().unwrap();
                            match std::env::var("KUBEDOG_SHOT_TAB").as_deref() {
                                Ok("containers") => self.set_tab(Tab::Containers, &sel),
                                Ok("environment") => self.set_tab(Tab::Environment, &sel),
                                Ok("scheduling") => self.set_tab(Tab::Scheduling, &sel),
                                Ok("revisions") => self.set_tab(Tab::Revisions, &sel),
                                _ => {}
                            }
                        }
                    }
                }
            }
            // A node's page (KUBEDOG_SHOT_OBJ picks the node; the first one otherwise).
            if self.connected && self.selected.is_none() && page == "node" {
                if let Some(ctx0) = self.active.first().cloned() {
                    let want = std::env::var("KUBEDOG_SHOT_OBJ").unwrap_or_default();
                    let first = self.lists.get(&Self::list_key(&ctx0, Kind::Nodes)).and_then(|l| l.rows.iter().find(|r| r.name == want).or(l.rows.first()).cloned());
                    if let Some(r) = first {
                        self.select(Selected { ctx: ctx0, kind: Kind::Nodes, ns: r.ns, name: r.name });
                    }
                }
            }
            // Test aid: fill a node's history with made-up readings around the current one, so the
            // chart can be looked at in a screenshot (memory only; screenshot mode only).
            if let Ok(t) = std::env::var("KUBEDOG_SHOT_FILTER") {
                if !self.shot_filtered {
                    self.shot_filtered = true;
                    self.search = t;
                }
            }
            if std::env::var("KUBEDOG_SHOT_HISTORY").is_ok() {
                for m in self.metrics.values_mut() {
                    for (n, u) in m.nodes.clone() {
                        let h = m.node_hist.entry(n).or_default();
                        if h.len() < 40 {
                            h.clear();
                            for i in 0..40 {
                                let w = 1.0 + 0.25 * ((i as f64) * 0.45).sin() + 0.1 * ((i as f64) * 1.7).cos();
                                h.push_back((u.0 * w, u.1 * (0.92 + 0.08 * (i as f64 / 40.0))));
                            }
                        }
                    }
                }
            }
            // A workload's logs (every pod it runs), read-only and without following.
            if self.connected && self.selected.is_none() && (page == "deploylogs" || page == "deploy") {
                if let Some(ctx0) = self.active.first().cloned() {
                    let want = std::env::var("KUBEDOG_SHOT_OBJ").unwrap_or_default();
                    let first = self.lists.get(&Self::list_key(&ctx0, Kind::Deployments)).and_then(|l| l.rows.iter().find(|r| r.name == want).or(l.rows.first()).cloned());
                    if let Some(r) = first {
                        self.tab = if page == "deploylogs" {
                            Tab::Logs
                        } else if std::env::var("KUBEDOG_SHOT_TAB").as_deref() == Ok("revisions") {
                            Tab::Revisions
                        } else {
                            Tab::Overview
                        };
                        self.select(Selected { ctx: ctx0, kind: Kind::Deployments, ns: r.ns, name: r.name });
                    }
                }
            }
            if self.connected && self.selected.is_none() && page == "ingressdetail" {
                if let Some(ctx0) = self.active.first().cloned() {
                    let first = self.lists.get(&Self::list_key(&ctx0, Kind::Ingresses)).and_then(|l| l.rows.first().cloned());
                    if let Some(r) = first {
                        self.view = View::Resource(Kind::Ingresses);
                        self.select(Selected { ctx: ctx0, kind: Kind::Ingresses, ns: r.ns, name: r.name });
                    }
                }
            }
            if self.connected && self.selected.is_none() && !self.shot_opened && matches!(page.as_str(), "detail" | "logs" | "yaml") {
                if let Some(ctx0) = self.active.first().cloned() {
                    let want = std::env::var("KUBEDOG_SHOT_OBJ").unwrap_or_default();
                    let first = self.lists.get(&Self::list_key(&ctx0, Kind::Pods)).and_then(|l| {
                        l.rows
                            .iter()
                            .find(|r| !want.is_empty() && r.name.starts_with(&want))
                            .or_else(|| l.rows.iter().find(|r| r.cells.get(1).map(|c| c.text == "Running").unwrap_or(false)))
                            .cloned()
                    });
                    if let Some(r) = first {
                        self.shot_opened = true;
                        self.select(Selected { ctx: ctx0, kind: Kind::Pods, ns: r.ns, name: r.name });
                        let sel = self.selected.clone().unwrap();
                        match page.as_str() {
                            "logs" => self.set_tab(Tab::Logs, &sel),
                            "yaml" => self.set_tab(Tab::Yaml, &sel),
                            _ => match std::env::var("KUBEDOG_SHOT_TAB").as_deref() {
                                Ok("containers") => self.set_tab(Tab::Containers, &sel),
                                Ok("environment") => self.set_tab(Tab::Environment, &sel),
                                Ok("network") => self.set_tab(Tab::Network, &sel),
                                Ok("scheduling") => self.set_tab(Tab::Scheduling, &sel),
                                Ok("storage") => self.set_tab(Tab::Storage, &sel),
                                Ok("files") => self.set_tab(Tab::Files, &sel),
                                Ok("whatif") => self.set_tab(Tab::WhatIf, &sel),
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        let data_ready = if !self.connected {
            !self.contexts_loading && page.is_none()
        } else {
            !self.is_loading()
                && self.view_kinds().iter().all(|k| self.active.iter().all(|c| self.lists.get(&Self::list_key(c, *k)).map(|l| l.fetched.is_some()).unwrap_or(false)))
                && (!self.wants_metrics() || self.active.iter().all(|c| self.metrics.get(c).map(|m| m.fetched.is_some()).unwrap_or(false)))
        } || self.demo && page.is_none();
        let data_ready = data_ready
            && !(self.view == View::Helm && self.active.iter().any(|c| self.helm.get(&format!("helm|{c}")).map(|h| h.0).unwrap_or(true)));
        let data_ready = data_ready && !(self.wants_storage() && self.active.iter().any(|c| !self.claim_stats_state(c).0));
        let data_ready = data_ready && !(page.as_deref() == Some("ingressdetail") && (self.selected.is_none() || self.certs.is_empty() || self.certs.values().any(|c| c.0)));
        let data_ready = data_ready && !(page.as_deref() == Some("terminal") && self.frames < 200);
        let data_ready = data_ready && !(matches!(page.as_deref(), Some("postgres") | Some("pgcluster")) && !self.pg_ready());
        let data_ready = data_ready && !(matches!(page.as_deref(), Some("elastic") | Some("escluster")) && !self.elastic_ready());
        let data_ready = data_ready && !(matches!(page.as_deref(), Some("pulsar") | Some("pucluster")) && !self.pulsar_ready());
        let data_ready = data_ready && !(page.as_deref() == Some("hive") && !self.hive_ready());
        // Custom resource pages wait for their list (and an object's page for its YAML).
        let data_ready = data_ready
            && !(matches!(self.view, View::Custom(_)) && {
                let View::Custom(i) = self.view else { unreachable!() };
                self.crds.get(i as usize).map(|k| self.active.iter().any(|c| self.lists.get(&Self::custom_list_key(c, k)).map(|l| l.fetched.is_none()).unwrap_or(true))).unwrap_or(true)
            })
            && !(page.as_deref() == Some("crdobj") && (!self.shot_opened || self.custom_text.values().any(|t| t.0)))
            && !(matches!(page.as_deref(), Some("crd") | Some("crdobj")) && !matches!(self.view, View::Custom(_)));
        let data_ready = data_ready && !self.shot_mouse.as_ref().map(|q| !q.is_empty()).unwrap_or(false);
        // The namespace menu test waits for the namespaces.
        let data_ready = data_ready && !(std::env::var("KUBEDOG_SHOT_NSMENU").is_ok() && self.active.iter().any(|c| self.namespaces.get(c).map(|v| v.is_empty()).unwrap_or(true)));
        // On a Logs tab, wait for the first lines (or the stream to end).
        let data_ready = data_ready
            && !(self.selected.is_some() && self.tab == Tab::Logs && self.log.as_ref().map(|l| l.running && l.lines.is_empty()).unwrap_or(true));
        let errors = self.active.iter().any(|c| self.lists.get(&Self::list_key(c, Kind::Pods)).map(|l| l.error.is_some()).unwrap_or(false));
        if self.frames >= 120 && (data_ready || errors || elapsed > Duration::from_secs(25)) {
            self.shot_requested = true;
            ctx.request_screenshot(move |image| {
                let (w, h) = (image.width() as u32, image.height() as u32);
                let mut bytes = Vec::with_capacity((w * h * 4) as usize);
                for p in &image.pixels {
                    bytes.extend_from_slice(&p.to_array());
                }
                match image::RgbaImage::from_raw(w, h, bytes).map(|img| img.save(&path)) {
                    Some(Ok(())) => {
                        eprintln!("screenshot saved: {path}");
                        frame_timing::report();
                        login::close_all();
                        std::process::exit(0);
                    }
                    Some(Err(e)) => {
                        eprintln!("screenshot save failed: {e}");
                        std::process::exit(2);
                    }
                    None => {
                        eprintln!("screenshot buffer size mismatch");
                        std::process::exit(2);
                    }
                }
            });
        }
    }
}

impl eframe::App for KubedogApp {
    /// Only the window's size and place are kept by eframe; Kubedog's own state is in prefs.json.
    fn persist_egui_memory(&self) -> bool {
        false
    }

    /// Menu bar editing commands become the input a text box expects; the rest wait for `ui`.
    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw: &mut egui::RawInput) {
        // Auto: take over the system's dark or light before anything is drawn.
        // (KUBEDOG_SHOT_SYSTEM=light|dark stands in for the system in a screenshot.)
        let mut light = raw.system_theme == Some(egui::Theme::Light);
        if self.screenshot.is_some() {
            if let Ok(v) = std::env::var("KUBEDOG_SHOT_SYSTEM") {
                light = v == "light";
            }
        }
        if light != self.system_light {
            self.system_light = light;
            if self.prefs.theme == "auto" {
                self.apply_theme();
            }
        }
        // Test aid, only with --screenshot: KUBEDOG_SHOT_MOUSE="click 900,20; right 900,300; hover 5,5; drag 910,300 910,120; hold 1,1 2,2; back 900,400; forward 900,400"
        // (points; back and forward are the mouse's side buttons; hold presses and moves without letting go). Runs once the page has its data.
        // Test aid: KUBEDOG_SHOT_PROTECTED=1 shows what a change in a protected cluster says.
        if self.screenshot.is_some() && self.connected && self.frames == 70 && std::env::var("KUBEDOG_SHOT_PROTECTED").is_ok() {
            if let Some(c) = self.active.first().cloned() {
                self.dialog = Some(Dialog::Protected { ctx: c });
            }
        }
        if self.screenshot.is_some() && (self.connected || !self.contexts_loading) {
            if self.shot_mouse.is_none() {
                let mut steps = std::collections::VecDeque::new();
                for part in std::env::var("KUBEDOG_SHOT_MOUSE").unwrap_or_default().split(';') {
                    let w: Vec<&str> = part.split_whitespace().collect();
                    match w.as_slice() {
                        ["hover", a] => steps.push_back(format!("m {a}")),
                        ["back", a] => steps.extend([format!("m {a}"), format!("b {a}"), format!("r {a}")]),
                        ["forward", a] => steps.extend([format!("m {a}"), format!("f {a}"), format!("g {a}")]),
                        ["click", a] => steps.extend([format!("m {a}"), format!("d {a}"), format!("u {a}")]),
                        ["right", a] => steps.extend([format!("m {a}"), format!("s {a}"), format!("t {a}")]),
                        [k @ ("drag" | "hold"), a, b] => {
                            steps.extend([format!("m {a}"), format!("d {a}")]);
                            let xy = |s: &str| s.split_once(',').and_then(|(x, y)| Some((x.parse::<f32>().ok()?, y.parse::<f32>().ok()?)));
                            if let (Some(p), Some(q)) = (xy(a), xy(b)) {
                                for i in 1..=10 {
                                    let t = i as f32 / 10.0;
                                    steps.push_back(format!("m {},{}", p.0 + (q.0 - p.0) * t, p.1 + (q.1 - p.1) * t));
                                }
                            }
                            if *k == "drag" {
                                steps.push_back(format!("u {b}"));
                            }
                        }
                        _ => {}
                    }
                    steps.extend((0..20).map(|_| "wait".to_string()));
                }
                self.shot_mouse = Some(steps);
            }
            let ready = self.frames > 60 && !self.is_loading();
            if ready && self.frames % 3 == 0 {
                if let Some(step) = self.shot_mouse.as_mut().and_then(|q| q.pop_front()) {
                    if let Some((k, (x, y))) = step.split_once(' ').and_then(|(k, p)| Some((k.to_string(), p.split_once(',')?))) {
                        if let (Ok(x), Ok(y)) = (x.parse::<f32>(), y.parse::<f32>()) {
                            let pos = egui::pos2(x, y);
                            let button = match k.as_str() { "b" | "r" => egui::PointerButton::Extra1, "f" | "g" => egui::PointerButton::Extra2, "s" | "t" => egui::PointerButton::Secondary, _ => egui::PointerButton::Primary };
                            raw.events.push(if k == "m" { egui::Event::PointerMoved(pos) } else { egui::Event::PointerButton { pos, button, pressed: matches!(k.as_str(), "d" | "b" | "f" | "s"), modifiers: Default::default() } });
                        }
                    }
                }
            }
        }
        for id in crate::menu::take() {
            let key = |k: Key, shift: bool| {
                let modifiers = egui::Modifiers { shift, ..egui::Modifiers::COMMAND };
                egui::Event::Key { key: k, physical_key: Some(k), pressed: true, repeat: false, modifiers }
            };
            let ev = match id.as_str() {
                "copy" => Some(egui::Event::Copy),
                "cut" => Some(egui::Event::Cut),
                "paste" => std::process::Command::new("pbpaste").output().ok().map(|o| egui::Event::Paste(String::from_utf8_lossy(&o.stdout).to_string())),
                "undo" => Some(key(Key::Z, false)),
                "redo" => Some(key(Key::Z, true)),
                "selectall" => Some(key(Key::A, false)),
                _ => None,
            };
            match ev {
                Some(e) => raw.events.push(e),
                None => self.menu_pending.push(id),
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.handle_messages();
        self.menu_commands(&ctx);
        self.remember_session(&ctx);
        self.companion_tick();
        self.update_tick();
        self.relogin_tick();
        self.maybe_screenshot(&ctx);
        self.shortcuts(&ctx);
        if !self.demo && !self.contexts_loading && self.connected {
            self.refresh_current(false);
            ctx.request_repaint_after(self.refresh_every());
        }

        if !self.connected {
            egui::CentralPanel::default()
                .frame(Frame::new().fill(BG_DEFAULT()))
                .show(ui, |ui| if self.start_settings || (self.screenshot.is_some() && std::env::var("KUBEDOG_SHOT_START").as_deref() == Ok("settings")) { self.settings_at_start(ui) } else { self.start_page(ui) });
            self.dialogs(&ctx);
            self.toasts_ui(&ctx);
            return;
        }

        // Sidebar: same background as the page with a divider line; resizable.
        // (A new id per text size, so the width starts right for it.)
        let wide = if self.prefs.font == "jetbrains" { 1.15 } else { 1.0 };
        egui::Panel::left(format!("sidebar-{}-{wide}", self.prefs.text_size))
            .resizable(true)
            .default_size(u(SIDEBAR_WIDTH) * wide)
            .size_range(180.0..=480.0)
            .frame(Frame::new().fill(BG_DEFAULT()).inner_margin(Margin { left: 12, right: 12, top: 0, bottom: 0 }).stroke(Stroke::new(1.0, BORDER_SUBTLE())))
            .show(ui, |ui| {
                // What's drawn never makes the sidebar wider: on a screen scaled by 125% or 150% a row can come out a
                // fraction too wide, and the divider would then creep to the right by itself. Only dragging moves it.
                let room = ui.available_rect_before_wrap();
                let mut inside = ui.new_child(egui::UiBuilder::new().max_rect(room).layout(Layout::top_down(Align::Min)));
                base_size(&mut inside, |ui| self.sidebar(ui));
                ui.allocate_rect(room, Sense::hover());
            });

        if self.screenshot.is_some() && self.ai.chat.is_none() && std::env::var("KUBEDOG_SHOT_AI").map(|v| v == "chat").unwrap_or(false) {
            self.ai_canned_chat();
        }
        let ai_open = self.ai.chat.is_some() && !self.ai.hidden;
        if ai_open {
            egui::Panel::right("ai-panel")
                .resizable(true)
                .default_size(u(430.0))
                .size_range(300.0..=900.0)
                .frame(Frame::new().fill(BG_DEFAULT()).inner_margin(Margin::symmetric(16, 4)).stroke(Stroke::new(1.0, BORDER_SUBTLE())))
                .show(ui, |ui| self.ai_panel(ui));
        }

        // Built-in terminal dock along the bottom (Kubedog addition).
        if self.term.open && self.term.has_sessions() {
            let r = egui::Panel::bottom("terminal-dock")
                .resizable(true)
                .default_size(self.term.height())
                .size_range(120.0..=900.0)
                .frame(Frame::new().fill(BG_DEFAULT()).inner_margin(Margin::symmetric(8, 6)).stroke(Stroke::new(1.0, BORDER_SUBTLE())))
                .show(ui, |ui| self.term.ui(ui));
            self.term.set_height(r.response.rect.height());
        } else if self.term.has_sessions() {
            egui::Panel::bottom("terminal-tab")
                .exact_size(26.0)
                .frame(Frame::new().fill(BG_DEFAULT()).inner_margin(Margin::symmetric(8, 3)).stroke(Stroke::new(1.0, BORDER_SUBTLE())))
                .show(ui, |ui| {
                    if ui.add(egui::Button::new(RichText::new("⌃  Terminal").size(z(12.5)).color(TEXT_SUBTLE())).frame(false)).on_hover_text("Show the built-in terminal (⌘J)").clicked() {
                        self.term.open = true;
                        self.term.focused = true;
                    }
                });
        }

        self.picks_bar(ui);
        // With the AI's panel open, what the page shows is written down for it.
        // (Only of the pages that are told that way.)
        aipage::begin(ai_open && matches!(self.view, View::Op(_) | View::Incident | View::Readiness | View::NetLab));
        egui::CentralPanel::default()
            .frame(Frame::new().fill(BG_DEFAULT()))
            .show(ui, |ui| {
                let side = if self.view == View::Shells && self.selected.is_none() { 12 } else { 22 };
                Frame::new().inner_margin(Margin { left: side, right: side, top: 6, bottom: 0 }).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.set_height(ui.available_height());
                    self.relogin_cards(ui);
                    if self.selected.is_some() {
                        self.detail(ui);
                    } else {
                        match self.view {
                            View::Resource(k) => {
                                let t = Instant::now();
                                self.resource_view(ui, k);
                                frame_timing::add(t.elapsed());
                            }
                            View::ClusterOverview => self.cluster_overview(ui),
                            View::WorkloadsOverview => self.workloads_overview(ui),
                            View::PortForwards => self.port_forward_view(ui),
                            View::Helm => self.helm_view(ui),
                            View::Settings => self.settings_view(ui),
                            View::ServiceMap => self.service_map(ui),
                            View::StorageUsage => self.storage_usage(ui),
                            View::Custom(i) => self.custom_view(ui, i),
                            View::Postgres => self.postgres_view(ui),
                            View::Elastic => self.elastic_view(ui),
                            View::Pulsar => self.pulsar_view(ui),
                            View::Hive => self.hive_view(ui),
                            View::Observatory => self.observatory_view(ui),
                            View::Proxmox => self.proxmox_view(ui),
                            View::NetLab => self.netlab_view(ui),
                            View::Shells => self.shells_view(ui),
                            View::Op(i) => self.op_view(ui, i),
                            View::Incident => self.incident_view(ui),
                            View::Readiness => self.readiness_view(ui),
                        }
                    }
                });
            });

        self.ai.notes = aipage::end();
        if let Some(s) = self.pending_open.take() {
            self.navigate(View::Resource(s.kind), Some(s));
        }
        self.search_ui(&ctx);
        self.dialogs(&ctx);
        self.toasts_ui(&ctx);
    }

    fn on_exit(&mut self) {
        self.term.close_all();
        self.close_shells();
        login::close_all();
        self.relogin_end_all();
        self.ai.chat = None;
        self.companion.chat = None;
        aiharness::end_all();
        self.stop_logs();
        for pf in &mut self.port_forwards {
            if let Some(mut c) = pf.child.take() {
                let _ = c.kill();
            }
        }
    }
}

/// Tabs only pods have.
fn pod_tab(t: Tab) -> bool {
    matches!(t, Tab::Containers | Tab::Environment | Tab::Network | Tab::Scheduling | Tab::Storage | Tab::Files | Tab::WhatIf)
}

/// A port nothing uses on this computer now.
fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0)).and_then(|l| l.local_addr()).map(|a| a.port()).unwrap_or(10_080)
}

/// Up to four names, and how many more.
fn some_names(list: &[String]) -> String {
    let more = list.len().saturating_sub(4);
    format!("{}{}", list.iter().take(4).cloned().collect::<Vec<_>>().join(", "), if more > 0 { format!(" and {more} more") } else { String::new() })
}

/// The next zoom up or down.
fn zoom_step(z: f32, up: bool) -> f32 {
    if up {
        ZOOMS.iter().copied().find(|x| *x > z + 0.01).unwrap_or(ZOOMS[ZOOMS.len() - 1])
    } else {
        ZOOMS.iter().rev().copied().find(|x| *x < z - 0.01).unwrap_or(ZOOMS[0])
    }
}

/// kubectl knows hours, not days and weeks.
fn kubectl_since(choice: &str) -> String {
    let (n, unit) = choice.split_at(choice.len() - 1);
    match (n.parse::<u32>(), unit) {
        (Ok(n), "d") => format!("{}h", n * 24),
        (Ok(n), "w") => format!("{}h", n * 24 * 7),
        _ => choice.to_string(),
    }
}

/// A choice saved by an earlier version, as the nearest one there is now.
fn since_choice(saved: &str) -> &str {
    match saved {
        "Live Tail" => NEW_LINES,
        "All Logs" => EVERYTHING,
        "5m" => "10m",
        "2h" => "3h",
        "6h" => "12h",
        "24h" => "1d",
        "7d" | "30d" => "1w",
        x => x,
    }
}

/// What runs in a container: the best shell it has.
fn shell_program(windows: bool) -> &'static [&'static str] {
    if windows {
        &["powershell", "-NoLogo"]
    } else {
        &["sh", "-c", "for s in bash zsh ash; do command -v $s >/dev/null 2>&1 && exec $s; done; exec sh"]
    }
}

fn on_cluster(s: &Selected, rest: &[&str]) -> Vec<String> {
    ["--context", s.ctx.as_str()].iter().chain(rest).map(|x| x.to_string()).chain(s.ns_args()).collect()
}

fn delete_args(s: &Selected, force: bool, orphan: bool) -> Vec<String> {
    let mut a = on_cluster(s, &["delete", s.kind.resource(), s.name.as_str(), "--wait=false"]);
    if orphan {
        a.push("--cascade=orphan".into());
    }
    if force {
        a.extend(["--grace-period=0".to_string(), "--force".to_string()]);
    }
    a
}

fn restart_args(s: &Selected) -> Vec<String> {
    on_cluster(s, &["rollout", "restart", &format!("{}/{}", s.kind.resource(), s.name)])
}

/// A name for a job started by hand: a job's name is at most 63 characters.
fn job_name(cron: &str, now: i64) -> String {
    let start: String = cron.chars().take(44).collect();
    format!("{}-manual-{now}", start.trim_end_matches(['-', '.']))
}

fn run_args(s: &Selected, job: &str) -> Vec<String> {
    on_cluster(s, &["create", "job", job, &format!("--from=cronjob/{}", s.name)])
}

fn suspend_args(s: &Selected, on: bool) -> Vec<String> {
    on_cluster(s, &["patch", s.kind.resource(), &s.name, "--type=merge", "-p", &format!("{{\"spec\":{{\"suspend\":{on}}}}}")])
}

fn pause_args(s: &Selected, verb: &str) -> Vec<String> {
    on_cluster(s, &["rollout", verb, &format!("{}/{}", s.kind.resource(), s.name)])
}

fn drain_args(s: &Selected, temporary: bool, ignore_budgets: bool, unmanaged: bool) -> Vec<String> {
    let mut a: Vec<String> = ["--context", &s.ctx, "drain", &s.name, "--ignore-daemonsets", "--timeout=10m"].iter().map(|x| x.to_string()).collect();
    for (on, flag) in [(temporary, "--delete-emptydir-data"), (ignore_budgets, "--disable-eviction"), (unmanaged, "--force")] {
        if on {
            a.push(flag.into());
        }
    }
    a
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n).collect();
        t.push('…');
        t
    }
}

fn ports_of(kind: Kind, o: &Value) -> Vec<u16> {
    let mut v: Vec<u16> = if kind == Kind::Services {
        o["spec"]["ports"].as_array().map(|a| a.iter().filter_map(|p| p["port"].as_u64().map(|x| x as u16)).collect()).unwrap_or_default()
    } else {
        o["spec"]["containers"]
            .as_array()
            .map(|cs| {
                cs.iter()
                    .flat_map(|c| c["ports"].as_array().cloned().unwrap_or_default())
                    .filter_map(|p| p["containerPort"].as_u64().map(|x| x as u16))
                    .collect()
            })
            .unwrap_or_default()
    };
    v.dedup();
    v
}

/// The same port on this computer when it can be had (below 1024 needs an administrator:
/// 443 becomes 10443), else any free one.
fn suggest_local(remote: u16) -> u16 {
    let want = if remote < 1024 { 10_000 + remote } else { remote };
    if std::net::TcpListener::bind(("127.0.0.1", want)).is_ok() {
        want
    } else {
        free_port()
    }
}

fn yaml_line(job: &mut egui::text::LayoutJob, line: &str) {
    let font = FontId::monospace(z(12.5));
    let fmt = |c: Color32| egui::TextFormat { font_id: font.clone(), color: c, ..Default::default() };
    let trimmed = line.trim_start();
    let indent = &line[..line.len() - trimmed.len()];
    job.append(indent, 0.0, fmt(TEXT_MUTED()));
    if trimmed.starts_with('#') {
        job.append(trimmed, 0.0, fmt(TEXT_PLACEHOLDER()));
    } else {
        let (dash, rest) = if let Some(r) = trimmed.strip_prefix("- ") { ("- ", r) } else { ("", trimmed) };
        job.append(dash, 0.0, fmt(TEXT_SUBTLE()));
        match rest.find(": ").map(|i| (i, 2)).or_else(|| rest.strip_suffix(':').map(|r| (r.len(), 1))) {
            Some((i, sep)) if !rest.starts_with('"') => {
                job.append(&rest[..i], 0.0, fmt(PRIMARY_TEXT()));
                job.append(&rest[i..i + sep], 0.0, fmt(TEXT_SUBTLE()));
                job.append(&rest[i + sep..], 0.0, fmt(SUCCESS()));
            }
            _ => job.append(rest, 0.0, fmt(TEXT_MUTED())),
        }
    }
    job.append("\n", 0.0, fmt(TEXT_MUTED()));
}

// ---------------- demo data ----------------

fn demo_items(kind: Kind) -> Vec<Value> {
    use serde_json::json;
    let ts = |secs: i64| {
        let t = kube::now_secs() - secs;
        let days = t.div_euclid(86400);
        let rem = t.rem_euclid(86400);
        // civil from days
        let z = days + 719468;
        let era = z.div_euclid(146097);
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
    };
    let pod = |name: &str, ns: &str, phase: &str, waiting: Option<&str>, restarts: i64, age: i64| {
        let state = match waiting {
            Some(r) => json!({"waiting": {"reason": r}}),
            None => json!({"running": {}}),
        };
        json!({"metadata": {"name": name, "namespace": ns, "creationTimestamp": ts(age), "labels": {"app": name.split('-').next().unwrap_or(name)}},
               "spec": {"nodeName": "worker-1", "containers": [{"name": "app", "image": "registry.example/app:1.4.2", "ports": [{"containerPort": 8080, "protocol": "TCP"}]}]},
               "status": {"phase": phase, "podIP": "10.244.1.17", "qosClass": "Burstable",
                          "containerStatuses": [{"name": "app", "ready": waiting.is_none(), "restartCount": restarts, "state": state}],
                          "conditions": [{"type": "Ready", "status": if waiting.is_none() {"True"} else {"False"}}]}})
    };
    match kind {
        Kind::Pods => vec![
            pod("web-7d9c7b5f4-x2v9k", "shop", "Running", None, 0, 3 * 86400),
            pod("web-7d9c7b5f4-k81qa", "shop", "Running", None, 0, 3 * 86400),
            pod("api-6f8b7d9b5c-p4q2m", "shop", "Running", None, 2, 5 * 86400),
            pod("worker-5c9d8-mm2kd", "shop", "Running", Some("CrashLoopBackOff"), 14, 7200),
            pod("coredns-5d78c9869d-2xw7r", "kube-system", "Running", None, 0, 30 * 86400),
            pod("report-28351200-9zq", "default", "Pending", Some("ContainerCreating"), 0, 40),
        ],
        Kind::Deployments => vec![
            json!({"metadata": {"name": "web", "namespace": "shop", "creationTimestamp": ts(14 * 86400)}, "spec": {"replicas": 2, "strategy": {"type": "RollingUpdate"}}, "status": {"readyReplicas": 2, "updatedReplicas": 2, "availableReplicas": 2}}),
            json!({"metadata": {"name": "api", "namespace": "shop", "creationTimestamp": ts(14 * 86400)}, "spec": {"replicas": 1}, "status": {"readyReplicas": 1, "updatedReplicas": 1, "availableReplicas": 1}}),
            json!({"metadata": {"name": "worker", "namespace": "shop", "creationTimestamp": ts(9 * 86400)}, "spec": {"replicas": 1}, "status": {"readyReplicas": 0, "updatedReplicas": 1, "availableReplicas": 0}}),
        ],
        Kind::Services => vec![
            json!({"metadata": {"name": "kubernetes", "namespace": "default", "creationTimestamp": ts(30 * 86400)}, "spec": {"type": "ClusterIP", "clusterIP": "10.96.0.1", "ports": [{"port": 443, "protocol": "TCP"}]}}),
            json!({"metadata": {"name": "web", "namespace": "shop", "creationTimestamp": ts(14 * 86400)}, "spec": {"type": "LoadBalancer", "clusterIP": "10.96.12.34", "ports": [{"port": 80, "nodePort": 30080, "protocol": "TCP"}], "selector": {"app": "web"}}}),
        ],
        Kind::Nodes => vec![
            json!({"metadata": {"name": "control-plane", "creationTimestamp": ts(30 * 86400), "labels": {"node-role.kubernetes.io/control-plane": ""}}, "spec": {}, "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.31.2"}, "addresses": [{"type": "InternalIP", "address": "192.168.1.10"}]}}),
            json!({"metadata": {"name": "worker-1", "creationTimestamp": ts(29 * 86400)}, "spec": {}, "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.31.2"}, "addresses": [{"type": "InternalIP", "address": "192.168.1.11"}]}}),
        ],
        Kind::Namespaces => ["default", "kube-system", "shop"].iter().map(|n| json!({"metadata": {"name": n, "creationTimestamp": ts(30 * 86400)}, "status": {"phase": "Active"}})).collect(),
        Kind::Events => vec![
            json!({"metadata": {"name": "e1", "namespace": "shop", "creationTimestamp": ts(60)}, "type": "Warning", "reason": "BackOff", "message": "Back-off restarting failed container app", "involvedObject": {"kind": "Pod", "name": "worker-5c9d8-mm2kd"}, "count": 14, "lastTimestamp": ts(60)}),
            json!({"metadata": {"name": "e2", "namespace": "default", "creationTimestamp": ts(40)}, "type": "Normal", "reason": "Scheduled", "message": "Successfully assigned default/report-28351200-9zq to worker-1", "involvedObject": {"kind": "Pod", "name": "report-28351200-9zq"}, "count": 1, "lastTimestamp": ts(40)}),
        ],
        Kind::ConfigMaps => vec![json!({"metadata": {"name": "web-config", "namespace": "shop", "creationTimestamp": ts(14 * 86400)}, "data": {"LOG_LEVEL": "info", "FEATURE_X": "on"}})],
        _ => vec![],
    }
}

fn demo_yaml(sel: &Selected) -> String {
    format!(
        "apiVersion: v1\nkind: {}\nmetadata:\n  name: {}\n  namespace: {}\nspec:\n  # sample data: kubectl was not found\n",
        sel.kind.singular(),
        sel.name,
        sel.ns
    )
}

fn demo_logs() -> Vec<LogLine> {
    (0..40)
        .map(|i| {
            let lvl = if i % 13 == 7 { "WARN" } else if i % 17 == 11 { "ERROR" } else { "INFO()" };
            (format!("2026-01-01T10:{:02}:{:02}Z {lvl} request handled path=/api/items status=200 took={}ms", i / 60, i % 60, 3 + i % 9), false)
        })
        .map(|(t, e)| LogLine::new(t, e))
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn context_and_namespace_columns_follow_their_names() {
        use super::*;
        // A short name gives a narrow column, the stripe's room included; a very long one stops at the limit.
        assert_eq!(snug_width(30.0, false), 30.0);
        assert_eq!(snug_width(30.0, true), 30.0 + CTX_STRIPE);
        assert!(snug_width(30.0, true) < base_column_width("Context"));
        assert_eq!(snug_width(5000.0, true), z(360.0));
    }

    #[test]
    fn keys_and_mouse_go_back() {
        use super::*;
        let cmd = if cfg!(target_os = "macos") { egui::Modifiers { mac_cmd: true, command: true, ..Default::default() } } else { egui::Modifiers::ALT };
        let key = |key: Key, m: egui::Modifiers| vec![egui::Event::ModifiersChanged(m), egui::Event::Key { key, physical_key: None, pressed: true, repeat: false, modifiers: m }];
        let mouse = |b: egui::PointerButton| vec![egui::Event::PointerMoved(egui::pos2(9.0, 9.0)), egui::Event::PointerButton { pos: egui::pos2(9.0, 9.0), button: b, pressed: true, modifiers: Default::default() }];
        for (back, forward) in [
            (key(Key::ArrowLeft, cmd), key(Key::ArrowRight, cmd)),
            (key(Key::BrowserBack, Default::default()), key(Key::BrowserForward, Default::default())),
            (mouse(egui::PointerButton::Extra1), mouse(egui::PointerButton::Extra2)),
        ] {
            let mut a = KubedogApp::new(egui::Context::default(), Some("none".into()));
            a.connected = true;
            a.view = View::Resource(Kind::Pods);
            a.navigate(a.view, Some(Selected { ctx: "c".into(), kind: Kind::Pods, ns: "x".into(), name: "web-1".into() }));
            for (events, open) in [(back, false), (forward, true)] {
                let ctx = egui::Context::default();
                let mut out = ctx.run_ui(egui::RawInput { events: events.clone(), ..Default::default() }, |ui| a.shortcuts(&ui.ctx().clone()));
                out.textures_delta.clear();
                assert_eq!(a.selected.is_some(), open, "{events:?}");
            }
        }
    }

    #[test]
    fn one_way_back() {
        use super::*;
        let mut a = KubedogApp::new(egui::Context::default(), Some("none".into()));
        let sel = |k: Kind, n: &str| Selected { ctx: "c".into(), kind: k, ns: "x".into(), name: n.into() };
        let pods = View::Resource(Kind::Pods);
        let deps = View::Resource(Kind::Deployments);
        a.connected = true;
        a.view = deps;
        a.selected = None;
        // From a deployment on to one of its pods: the arrow there leads to the list of pods.
        a.navigate(deps, Some(sel(Kind::Deployments, "web")));
        a.navigate(pods, Some(sel(Kind::Pods, "web-1")));
        a.back_pressed();
        assert!(a.view == pods && a.selected.is_none());
        // On the list: to where you came from, and not back into the pod.
        a.back_pressed();
        assert!(a.view == deps && a.selected.as_ref().map(|s| s.name == "web").unwrap_or(false));
        a.back_pressed();
        assert!(a.view == deps && a.selected.is_none());
        a.back_pressed();
        assert!(a.view == deps && a.selected.is_none() && a.back.is_empty());
        // Forward goes the same way.
        a.go_forward();
        assert!(a.selected.as_ref().map(|s| s.name == "web").unwrap_or(false));
        // A page within a page.
        a.navigate(View::Postgres, None);
        a.pg_sel = Some(pg::PgId { ctx: "c".into(), ns: "x".into(), name: "db".into() });
        a.back_pressed();
        assert!(a.view == View::Postgres && a.pg_sel.is_none());
    }

    #[test]
    fn actions_and_choices() {
        use super::*;
        let d = Selected { ctx: "c".into(), kind: Kind::Deployments, ns: "n".into(), name: "x".into() };
        assert_eq!(delete_args(&d, false, false).join(" "), "--context c delete deployments.apps x --wait=false -n n");
        assert!(delete_args(&d, true, true).join(" ").ends_with("-n n --cascade=orphan --grace-period=0 --force"));
        assert_eq!(pause_args(&d, "pause").join(" "), "--context c rollout pause deployments.apps/x -n n");
        let cj = Selected { ctx: "c".into(), kind: Kind::CronJobs, ns: "n".into(), name: "nightly".into() };
        assert_eq!(run_args(&cj, &job_name("nightly", 7)).join(" "), "--context c create job nightly-manual-7 --from=cronjob/nightly -n n");
        assert_eq!(suspend_args(&cj, true).join(" "), "--context c patch cronjobs.batch nightly --type=merge -p {\"spec\":{\"suspend\":true}} -n n");
        assert!(job_name(&"x".repeat(60), 1_800_000_000).len() <= 63);
        assert_eq!(restart_args(&d).join(" "), "--context c rollout restart deployments.apps/x -n n");
        let n = Selected { ctx: "c".into(), kind: Kind::Nodes, ns: String::new(), name: "w".into() };
        assert_eq!(drain_args(&n, false, false, false).join(" "), "--context c drain w --ignore-daemonsets --timeout=10m");
        assert!(drain_args(&n, true, true, true).join(" ").ends_with("--delete-emptydir-data --disable-eviction --force"));
        assert_eq!((kubectl_since("10m"), kubectl_since("3d"), kubectl_since("1w")), ("10m".into(), "72h".into(), "168h".into()));
        for old in ["Live Tail", "5m", "10m", "30m", "1h", "2h", "6h", "24h", "7d", "30d", "All Logs"] {
            assert!(SINCE_CHOICES.contains(&since_choice(old)), "{old}");
        }
        assert_eq!((zoom_step(1.0, true), zoom_step(1.0, false), zoom_step(3.0, true), zoom_step(0.5, false), zoom_step(1.2, true)), (1.1, 0.9, 3.0, 0.5, 1.25));
        assert!(free_port() > 1023);
        let busy = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let taken = busy.local_addr().unwrap().port();
        assert_ne!(suggest_local(taken), taken);
        assert_eq!(some_names(&["a".to_string(), "b".into(), "c".into(), "d".into(), "e".into()]), "a, b, c, d and 1 more");
    }

    #[test]
    fn event_kinds() {
        use super::{event_kind, Kind};
        assert_eq!(event_kind("Pod"), Some(Kind::Pods));
        assert_eq!(event_kind("NetworkPolicy"), Some(Kind::NetworkPolicies));
        assert_eq!(event_kind("Ingress"), Some(Kind::Ingresses));
        assert_eq!(event_kind("HorizontalPodAutoscaler"), Some(Kind::HorizontalPodAutoscalers));
        assert_eq!(event_kind("Application"), None);
    }

    #[test]
    fn prefs_round_trip_and_old_files() {
        use super::*;
        let mut p = Prefs::default();
        p.startup = "reconnect".into();
        p.first_page = "events".into();
        p.refresh_secs = 30;
        p.metrics_secs = 60;
        p.log_size = 15.0;
        p.log_since = "1h".into();
        p.log_wrap = false;
        p.log_timestamps = false;
        p.ctx_alias.insert("a/b/c".into(), "Lab".into());
        p.powers.insert("argo".into(), "off".into());
        p.ctx_color.insert("a/b/c".into(), 3);
        p.ctx_order = vec!["x".into(), "a/b/c".into()];
        p.groups = vec![Group { name: "Prod".into(), contexts: vec!["x".into(), "y".into()] }];
        p.columns.insert("Pods".into(), vec!["Status".into(), "Images".into(), "Age".into()]);
        p.column_order.insert("Pods".into(), vec!["Name".into(), "Age".into(), "Ready".into()]);
        p.theme = "auto".into();
        p.accent = "teal".into();
        p.logins = vec!["es|c|n|x".into()];
        p.grafana.insert("c".into(), grafana::Conf { url: "https://g.example".into(), user: "me".into(), uid: "x".into(), ..Default::default() });
        p.font = "plex".into();
        p.text_size = 18;
        p.session = Session { view: "Deployments".into(), ns: None, ns_multi: vec!["a".into(), "b".into()], ns_ctx: None, zoom: 1.2, collapsed: vec!["Helm".into()] };
        p.hide_empty_columns = true;
        let back = prefs_from_json(&prefs_to_json(&p));
        assert_eq!(back.startup, "reconnect");
        assert_eq!(back.session, p.session);
        assert_eq!(back.first_page, "events");
        assert_eq!((back.refresh_secs, back.metrics_secs), (30, 60));
        assert_eq!(back.log_size, 15.0);
        assert_eq!(back.log_since, "1h");
        assert!(!back.log_wrap && !back.log_timestamps);
        assert_eq!(back.ctx_alias, p.ctx_alias);
        assert_eq!(back.powers, p.powers);
        assert_eq!(back.ctx_color, p.ctx_color);
        assert_eq!(back.ctx_order, p.ctx_order);
        assert_eq!(back.groups, p.groups);
        assert_eq!(back.columns, p.columns);
        assert_eq!(back.column_order, p.column_order);
        assert_eq!((back.theme.as_str(), back.accent.as_str()), ("auto", "teal"));
        assert_eq!((back.font.as_str(), back.text_size), ("plex", 18));
        assert_eq!(back.logins, p.logins);
        assert_eq!(back.grafana, p.grafana);
        assert!(back.hide_empty_columns);
        // A file from an earlier version: new settings take their defaults.
        let old: Value = serde_json::json!({"contexts": ["x"], "terminal": "Terminal", "terminal_chosen": true, "keep_filters": false});
        let o = prefs_from_json(&old);
        let d = Prefs::default();
        assert_eq!(o.contexts, vec!["x".to_string()]);
        assert_eq!(o.terminal, "Terminal");
        assert!(!o.shared_filter);
        assert_eq!((o.startup.as_str(), o.first_page.as_str(), o.refresh_secs, o.metrics_secs), ("reconnect", "pods", 5, 15));
        assert_eq!((o.log_size, o.log_wrap, o.log_timestamps), (d.log_size, d.log_wrap, d.log_timestamps));
        assert!(o.groups.is_empty() && o.ctx_alias.is_empty());
        assert!(o.columns.is_empty() && !o.hide_empty_columns);
        assert_eq!((o.theme.as_str(), o.accent.as_str()), ("dark", "orange"));
        assert_eq!((o.font.as_str(), o.text_size), ("ubuntu", 16));
        assert_eq!(prefs_from_json(&serde_json::json!({"font": "wingdings", "text_size": 400})).text_size, 16);
        // Values out of range fall back too.
        let bad: Value = serde_json::json!({"refresh_secs": 0, "first_page": "nowhere", "ctx_color": {"x": 99}, "startup2": "weird"});
        let b = prefs_from_json(&bad);
        assert_eq!((b.refresh_secs, b.first_page.as_str(), b.startup.as_str()), (5, "pods", "reconnect"));
        // Choosing the start page sticks.
        assert_eq!(prefs_from_json(&serde_json::json!({"startup2": "start"})).startup, "start");
        // Pages survive the round trip.
        for v in [View::Resource(Kind::Pods), View::Resource(Kind::Ingresses), View::Helm, View::ClusterOverview, View::Settings] {
            assert_eq!(view_from_name(&view_name(v)), Some(v));
        }
        assert!(b.ctx_color.is_empty());
    }

    #[test]
    fn label_selectors() {
        use super::*;
        let labels = serde_json::json!({"app": "web", "tier": "front"});
        assert!(podnet::selector_matches(&serde_json::json!({"app": "web"}), &labels));
        assert!(!podnet::selector_matches(&serde_json::json!({"app": "api"}), &labels));
        assert!(podnet::selector_matches(&serde_json::json!({}), &labels));
        assert!(podnet::selector_matches(&serde_json::json!({"matchLabels": {"tier": "front"}}), &labels));
        assert!(podnet::selector_matches(&serde_json::json!({"matchExpressions": [{"key": "app", "operator": "In", "values": ["web", "x"]}]}), &labels));
        assert!(!podnet::selector_matches(&serde_json::json!({"matchExpressions": [{"key": "env", "operator": "Exists"}]}), &labels));
        assert!(podnet::selector_matches(&serde_json::json!({"matchExpressions": [{"key": "env", "operator": "DoesNotExist"}]}), &labels));
    }

    #[test]
    fn short_cluster_names() {
        use super::*;
        assert_eq!(suggest_short_name("team-lab/api-ocp-example-com:6443/system:admin", "https://api.ocp.example.com:6443", &[]), "team-lab");
        assert_eq!(suggest_short_name("/api-acmecorp-example-com:6443/user@example.com", "https://api.acmecorp.example.com:6443", &[]), "acmecorp");
        assert_eq!(suggest_short_name("ocp", "", &["ocp".into()]), "ocp-2");
        let n = suggest_short_name("averyveryverylongname", "", &["averyveryv".into()]);
        assert!(n.chars().count() <= MAX_CLUSTER_NAME && n != "averyveryv");
    }

    #[test]
    fn namespace_patterns() {
        use super::*;
        assert!(glob_match("team-*", "team-a"));
        assert!(glob_match("team-*", "team-"));
        assert!(!glob_match("team-*", "teams"));
        assert!(glob_match("*-prod", "shop-prod"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("x*y*z", "x12y34z"));
        assert!(!glob_match("x*y*z", "x12y34"));
        assert_eq!(clusters::parse_namespace_patterns(" Team-A, shop-*  ops,,bad/name "), vec!["team-a", "shop-*", "ops"]);
        let mut p = Prefs::default();
        p.ctx_namespaces.insert("c".into(), vec!["a".into(), "b-*".into()]);
        assert_eq!(prefs_from_json(&prefs_to_json(&p)).ctx_namespaces, p.ctx_namespaces);
    }

    #[test]
    fn base64_round_trip() {
        for s in ["", "a", "ab", "abc", "hello world", "pa$$w0rd!\n✓"] {
            let e = super::b64_encode(s.as_bytes());
            assert_eq!(super::b64_decode(&e).unwrap(), s.as_bytes(), "{s}");
        }
        assert_eq!(super::b64_encode(b"hello"), "aGVsbG8=");
    }
}
