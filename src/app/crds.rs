//! Custom resources: every CRD of the open clusters in the sidebar, grouped by API group, with a
//! filter; each kind opens a list (its printer columns, or hand-made ones for well-known kinds
//! such as Argo CD Applications), and each object a page with Overview, YAML and Events.

use super::*;

/// One printer column: header, JSONPath, type ("date", "integer", "boolean", "exists", "short"...).
#[derive(Clone, Debug)]
pub(super) struct PCol {
    pub name: String,
    pub path: String,
    pub ty: String,
    pub priority: i64,
}

#[derive(Clone, Debug)]
pub(super) struct CrdKind {
    /// "plural.group", what kubectl takes.
    pub key: String,
    pub group: String,
    pub kind: String,
    pub plural: String,
    pub version: String,
    pub namespaced: bool,
    pub cols: Vec<PCol>,
    /// Found without reading the definitions (no columns of its own).
    pub stub: bool,
}

/// Groups that come with Kubernetes: what's in them has its own page or is no list of objects.
const BUILT_IN_GROUPS: [&str; 24] = [
    "", "apps", "batch", "autoscaling", "policy", "extensions", "networking.k8s.io", "rbac.authorization.k8s.io", "storage.k8s.io", "apiextensions.k8s.io",
    "admissionregistration.k8s.io", "apiregistration.k8s.io", "authentication.k8s.io", "authorization.k8s.io", "certificates.k8s.io", "coordination.k8s.io",
    "discovery.k8s.io", "events.k8s.io", "flowcontrol.apiserver.k8s.io", "node.k8s.io", "scheduling.k8s.io", "resource.k8s.io", "metrics.k8s.io", "internal.apiserver.k8s.io",
];

/// Custom kinds an account may ask for without the right to read their definitions: what
/// Kubernetes tells every account it serves. The same shape as definitions, without columns.
pub(super) fn discovered(k: &Kubectl, ctx: &str) -> Vec<Value> {
    let args: Vec<String> = ["--context", ctx, "api-resources", "--verbs=list", "--no-headers", &format!("--request-timeout={}", kube::REQUEST_TIMEOUT)].iter().map(|s| s.to_string()).collect();
    // One broken API group makes kubectl fail, but it still lists the others.
    let text = k.command(&args).and_then(|mut c| c.output().ok()).map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    let found = parse_api_resources(&text);
    if !found.is_empty() {
        return found;
    }
    // Nothing told: the ones Kubedog has pages for.
    [("postgresql.cnpg.io", "v1", "Cluster", "clusters"), ("postgresql.cnpg.io", "v1", "Backup", "backups"), ("postgresql.cnpg.io", "v1", "ScheduledBackup", "scheduledbackups"), ("postgresql.cnpg.io", "v1", "Pooler", "poolers"), ("postgresql.cnpg.io", "v1", "Database", "databases"), ("elasticsearch.k8s.elastic.co", "v1", "Elasticsearch", "elasticsearches")]
        .iter()
        .map(|(g, v, kind, plural)| stub(g, v, kind, plural, true))
        .collect()
}

fn stub(group: &str, version: &str, kind: &str, plural: &str, namespaced: bool) -> Value {
    serde_json::json!({
        "metadata": {"name": format!("{plural}.{group}")},
        "spec": {"group": group, "scope": if namespaced { "Namespaced" } else { "Cluster" }, "names": {"kind": kind, "plural": plural}, "versions": [{"name": version, "served": true, "storage": true}]},
        "kubedogStub": true
    })
}

/// "name [short] group/version namespaced kind" lines.
fn parse_api_resources(text: &str) -> Vec<Value> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let n = f.len();
            if n < 4 {
                return None;
            }
            let (plural, api, namespaced, kind) = (f[0], f[n - 3], f[n - 2], f[n - 1]);
            let (group, version) = api.split_once('/')?;
            if BUILT_IN_GROUPS.contains(&group) || !matches!(namespaced, "true" | "false") {
                return None;
            }
            Some(stub(group, version, kind, plural, namespaced == "true"))
        })
        .collect()
}

impl CrdKind {
    fn from_crd(o: &Value) -> Option<CrdKind> {
        let spec = &o["spec"];
        let group = spec["group"].as_str()?.to_string();
        let plural = spec["names"]["plural"].as_str()?.to_string();
        let kind = spec["names"]["kind"].as_str()?.to_string();
        let versions = spec["versions"].as_array().cloned().unwrap_or_default();
        let v = versions.iter().find(|v| v["storage"].as_bool() == Some(true)).or_else(|| versions.iter().find(|v| v["served"].as_bool() == Some(true))).or(versions.first());
        let version = v.and_then(|v| v["name"].as_str()).or(spec["version"].as_str()).unwrap_or("").to_string();
        let raw_cols = v.and_then(|v| v["additionalPrinterColumns"].as_array().cloned()).or_else(|| spec["additionalPrinterColumns"].as_array().cloned()).unwrap_or_default();
        let mut cols: Vec<PCol> = raw_cols
            .iter()
            .filter_map(|c| {
                Some(PCol {
                    name: c["name"].as_str()?.to_string(),
                    path: c["jsonPath"].as_str().or(c["JSONPath"].as_str())?.to_string(),
                    ty: c["type"].as_str().unwrap_or("string").to_string(),
                    priority: c["priority"].as_i64().unwrap_or(0),
                })
            })
            // Age is shown anyway.
            .filter(|c| c.path != ".metadata.creationTimestamp")
            .collect();
        let key = format!("{plural}.{group}");
        if let Some(special) = well_known_columns(&key) {
            cols = special;
        }
        Some(CrdKind { key, group, kind, plural, version, namespaced: spec["scope"].as_str() == Some("Namespaced"), cols, stub: o["kubedogStub"].as_bool().unwrap_or(false) })
    }

    /// Where it sits in the sidebar: the group's last two parts, then the rest
    /// ("acme.cert-manager.io" → ("cert-manager.io", "acme")).
    fn place(&self) -> (String, String) {
        let parts: Vec<&str> = self.group.split('.').collect();
        if parts.len() <= 2 {
            return (self.group.clone(), String::new());
        }
        let n = parts.len();
        (parts[n - 2..].join("."), parts[..n - 2].join("."))
    }
}

/// Hand-made columns for kinds whose own printer columns say little.
fn well_known_columns(key: &str) -> Option<Vec<PCol>> {
    let c = |name: &str, path: &str, ty: &str| PCol { name: name.into(), path: path.into(), ty: ty.into(), priority: 0 };
    match key {
        "applications.argoproj.io" => Some(vec![
            c("Project", ".spec.project", "string"),
            c("Sync", ".status.sync.status", "string"),
            c("Health", ".status.health.status", "string"),
            c("Repository", ".spec.source.repoURL|.spec.sources[0].repoURL", "repo"),
            c("Revision", ".status.sync.revision|.status.sync.revisions[0]", "short"),
            c("Destination", ".spec.destination.namespace|.spec.destination.name|.spec.destination.server", "string"),
            c("Auto-sync", ".spec.syncPolicy.automated", "exists"),
            c("Prune", ".spec.syncPolicy.automated.prune", "boolean"),
            c("Self-heal", ".spec.syncPolicy.automated.selfHeal", "boolean"),
        ]),
        "applicationsets.argoproj.io" => Some(vec![c("Generators", ".spec.generators", "count"), c("Template", ".spec.template.metadata.name", "string")]),
        _ => None,
    }
}

/// Follow a printer-column JSONPath (`.a.b`, `[0]`, `[*]`, `[?(@.type=="Ready")]`); `a|b` tries
/// `a` first. Several results are joined with commas.
pub(super) fn json_path(o: &Value, path: &str) -> Vec<Value> {
    for alt in path.split('|') {
        let r = json_path_one(o, alt.trim());
        if !r.is_empty() {
            return r;
        }
    }
    vec![]
}

fn json_path_one(o: &Value, path: &str) -> Vec<Value> {
    let path = path.trim().trim_start_matches('{').trim_end_matches('}');
    let chars: Vec<char> = path.chars().collect();
    let mut cur: Vec<Value> = vec![o.clone()];
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '.' => {
                i += 1;
                let start = i;
                while i < chars.len() && chars[i] != '.' && chars[i] != '[' {
                    i += 1;
                }
                let field: String = chars[start..i].iter().collect();
                if field.is_empty() {
                    continue;
                }
                cur = cur.iter().filter_map(|v| v.get(&field).cloned()).filter(|v| !v.is_null()).collect();
            }
            '[' => {
                let start = i + 1;
                let mut depth = 0;
                while i < chars.len() {
                    if chars[i] == '[' {
                        depth += 1;
                    } else if chars[i] == ']' {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    i += 1;
                }
                let inner: String = chars[start..i.min(chars.len())].iter().collect();
                i += 1;
                let inner = inner.trim();
                if inner == "*" {
                    cur = cur.iter().flat_map(|v| v.as_array().cloned().unwrap_or_default()).collect();
                } else if let Ok(n) = inner.parse::<usize>() {
                    cur = cur.iter().filter_map(|v| v.get(n).cloned()).collect();
                } else if let Some(f) = inner.strip_prefix("?(").and_then(|x| x.strip_suffix(')')) {
                    // @.field == "value"
                    let (lhs, rhs) = f.split_once("==").unwrap_or((f, ""));
                    let field = lhs.trim().trim_start_matches("@.").to_string();
                    let want = rhs.trim().trim_matches('"').trim_matches('\'').to_string();
                    cur = cur
                        .iter()
                        .flat_map(|v| v.as_array().cloned().unwrap_or_default())
                        .filter(|e| {
                            let got = &e[&field];
                            got.as_str().map(|s| s == want).unwrap_or_else(|| got.to_string() == want)
                        })
                        .collect();
                } else {
                    let key = inner.trim_matches('\'').trim_matches('"').to_string();
                    cur = cur.iter().filter_map(|v| v.get(&key).cloned()).collect();
                }
            }
            _ => i += 1,
        }
    }
    cur
}

fn plain(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        Value::Array(a) => a.iter().map(plain).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}

/// A column's text and colour for one object.
pub(super) fn cell_of(o: &Value, c: &PCol) -> (String, Tone) {
    let vals = json_path(o, &c.path);
    let text = match c.ty.as_str() {
        "exists" => if vals.is_empty() { "No".into() } else { "Yes".into() },
        "boolean" => match vals.first() {
            Some(Value::Bool(true)) => "Yes".into(),
            Some(Value::Bool(false)) => "No".into(),
            Some(v) => plain(v),
            None => "-".into(),
        },
        "date" => vals.first().and_then(|v| v.as_str()).map(kube::age).unwrap_or_default(),
        "short" => vals.first().map(plain).map(|s| s.chars().take(8).collect()).unwrap_or_default(),
        "count" => vals.first().and_then(|v| v.as_array()).map(|a| a.len().to_string()).unwrap_or_default(),
        "repo" => vals.first().map(plain).map(|s| s.trim_start_matches("https://").trim_end_matches(".git").to_string()).unwrap_or_default(),
        _ => vals.iter().map(plain).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(", "),
    };
    let text = if text.is_empty() { "-".to_string() } else { text };
    let tone = value_tone(&text);
    (text, tone)
}

/// Status words in colour: good green, in-between amber, bad red.
pub(super) fn value_tone(v: &str) -> Tone {
    match v {
        "True" | "Synced" | "Healthy" | "Ready" | "Running" | "Bound" | "Active" | "Succeeded" | "Complete" | "Available" | "Established" | "Valid" | "Approved" | "Yes" => Tone::Success,
        "OutOfSync" | "Progressing" | "Pending" | "Unknown" | "Suspended" | "Issuing" | "Waiting" => Tone::Warning,
        "Degraded" | "Missing" | "False" | "Failed" | "Error" | "Invalid" | "Denied" | "Expired" => Tone::Danger,
        "-" | "No" => Tone::Muted,
        _ => Tone::Normal,
    }
}

/// A JSON value written out like YAML, for reading.
pub(super) fn yamlish(v: &Value, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                match x {
                    Value::Object(o) if !o.is_empty() => {
                        out.push_str(&format!("{pad}{k}:\n"));
                        yamlish(x, indent + 1, out);
                    }
                    Value::Array(a) if !a.is_empty() => {
                        out.push_str(&format!("{pad}{k}:\n"));
                        yamlish(x, indent + 1, out);
                    }
                    _ => out.push_str(&format!("{pad}{k}: {}\n", scalar(x))),
                }
            }
        }
        Value::Array(a) => {
            for x in a {
                match x {
                    Value::Object(_) | Value::Array(_) => {
                        let mut inner = String::new();
                        yamlish(x, indent + 1, &mut inner);
                        let inner = inner.trim_start_matches(' ').to_string();
                        out.push_str(&format!("{pad}- {inner}"));
                    }
                    _ => out.push_str(&format!("{pad}- {}\n", scalar(x))),
                }
            }
        }
        other => out.push_str(&format!("{pad}{}\n", scalar(other))),
    }
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) if s.contains('\n') => format!("|\n    {}", s.replace('\n', "\n    ")),
        Value::String(s) => s.clone(),
        Value::Object(_) => "{}".into(),
        Value::Array(_) => "[]".into(),
        other => other.to_string(),
    }
}

/// An open custom object.
#[derive(Clone, PartialEq, Debug)]
pub(super) struct CustomSel {
    pub ctx: String,
    pub idx: u32,
    pub ns: String,
    pub name: String,
}

pub(super) struct CRow {
    ctx: String,
    ns: String,
    name: String,
    cells: Vec<(String, Tone)>,
    age: String,
    age_secs: f64,
}

impl KubedogApp {
    pub(super) fn custom_list_key(ctx: &str, k: &CrdKind) -> String {
        format!("list|{ctx}|crd:{}", k.key)
    }

    /// Read the CRDs of every open cluster once (refresh in the sidebar reads them again).
    pub(super) fn ensure_crds(&mut self) {
        for c in self.active.clone() {
            if !self.lists.contains_key(&Self::list_key(&c, Kind::CustomResourceDefinitions)) {
                self.fetch_list(&c, Kind::CustomResourceDefinitions);
            }
        }
    }

    /// Add kinds from newly read CRD lists (the list only grows, so views keep their index).
    pub(super) fn sync_crds(&mut self) {
        let gen: u64 = self.active.iter().map(|c| self.lists.get(&Self::list_key(c, Kind::CustomResourceDefinitions)).map(|l| l.gen).unwrap_or(0)).sum();
        if gen == self.crd_gen {
            return;
        }
        self.crd_gen = gen;
        let mut found = vec![];
        for c in &self.active {
            if let Some(l) = self.lists.get(&Self::list_key(c, Kind::CustomResourceDefinitions)) {
                found.extend(l.items.iter().filter_map(CrdKind::from_crd));
            }
        }
        for k in found {
            match self.crds.iter_mut().find(|x| x.key == k.key) {
                // Another cluster's account may read the definition itself.
                Some(x) if x.stub && !k.stub => *x = k,
                Some(_) => {}
                None => self.crds.push(k),
            }
        }
    }

    pub(super) fn crd_index(&self, key: &str) -> Option<u32> {
        self.crds.iter().position(|k| k.key == key).map(|i| i as u32)
    }

    /// Read a custom kind's objects (each namespace on its own for accounts that can't list all).
    pub(super) fn fetch_custom(&mut self, ctx: &str, idx: u32) {
        let Some(k) = self.crds.get(idx as usize).cloned() else { return };
        let key = Self::custom_list_key(ctx, &k);
        let st = self.lists.entry(key.clone()).or_default();
        if st.loading {
            return;
        }
        st.loading = true;
        let ctx = ctx.to_string();
        let own = self.default_ns(&ctx);
        let limited = self.prefs.ctx_namespaces.get(&ctx).cloned();
        let known = self.namespaces.get(&ctx).cloned().unwrap_or_default();
        self.spawn(move |kc| {
            let get = |ns: Option<&str>| -> Result<Vec<Value>, String> {
                let mut args: Vec<String> = vec!["--context".into(), ctx.clone(), "get".into(), k.key.clone(), "-o".into(), "json".into(), format!("--request-timeout={}", kube::REQUEST_TIMEOUT)];
                match ns {
                    Some(n) => args.extend(["-n".to_string(), n.to_string()]),
                    None if k.namespaced => args.push("--all-namespaces".into()),
                    None => {}
                }
                kc.run(&args).and_then(|j| kube::parse_items(&j))
            };
            let per_ns = |names: Vec<String>| -> Result<Vec<Value>, String> {
                let mut items = vec![];
                let mut err = None;
                for n in names.iter().take(60) {
                    match get(Some(n)) {
                        Ok(mut v) => items.append(&mut v),
                        Err(e) => {
                            err.get_or_insert(e);
                        }
                    }
                }
                if items.is_empty() {
                    if let Some(e) = err {
                        return Err(e);
                    }
                }
                Ok(items)
            };
            let result = match (&limited, k.namespaced) {
                (Some(p), true) => expand_namespaces(kc, &ctx, p, &known).and_then(per_ns),
                _ => match get(None) {
                    Err(e) if k.namespaced && is_refusal(&e) => match visible_namespaces(kc, &ctx) {
                        Ok(v) if !v.is_empty() => per_ns(v),
                        // Else the context's own namespace.
                        _ => per_ns(vec![own]),
                    },
                    r => r,
                },
            };
            Msg::List { key, result, rows: None }
        });
    }

    pub(super) fn refresh_custom(&mut self, idx: u32, force: bool) {
        let Some(k) = self.crds.get(idx as usize).cloned() else { return };
        let every = self.refresh_every();
        for c in self.active.clone() {
            let stale = self.lists.get(&Self::custom_list_key(&c, &k)).and_then(|s| s.fetched).map(|t| t.elapsed() >= every).unwrap_or(true);
            if stale || force {
                self.fetch_custom(&c, idx);
            }
        }
        if let Some(s) = self.custom_sel.clone() {
            let ykey = format!("cyaml|{}|{}|{}|{}", s.ctx, k.key, s.ns, s.name);
            if force || !self.custom_text.contains_key(&ykey) {
                self.fetch_custom_texts(&s);
            }
        }
    }

    fn fetch_custom_texts(&mut self, s: &CustomSel) {
        let Some(k) = self.crds.get(s.idx as usize).cloned() else { return };
        let mut ns_args: Vec<String> = vec![];
        if k.namespaced {
            ns_args = vec!["-n".into(), s.ns.clone()];
        }
        let ykey = format!("cyaml|{}|{}|{}|{}", s.ctx, k.key, s.ns, s.name);
        self.custom_text.insert(ykey.clone(), (true, Ok(String::new())));
        let mut args = vec!["--context".to_string(), s.ctx.clone(), "get".into(), k.key.clone(), s.name.clone(), "-o".into(), "yaml".into(), format!("--request-timeout={}", kube::REQUEST_TIMEOUT)];
        args.extend(ns_args.clone());
        self.fetch_text(ykey, args);
        let ekey = format!("cevents|{}|{}|{}|{}", s.ctx, k.key, s.ns, s.name);
        self.custom_text.insert(ekey.clone(), (true, Ok(String::new())));
        let mut args = vec![
            "--context".to_string(),
            s.ctx.clone(),
            "get".into(),
            "events".into(),
            "--field-selector".into(),
            format!("involvedObject.name={},involvedObject.kind={}", s.name, k.kind),
            "-o".into(),
            "json".into(),
            format!("--request-timeout={}", kube::REQUEST_TIMEOUT),
        ];
        args.extend(ns_args);
        self.fetch_text(ekey, args);
    }

    pub(super) fn on_custom_text(&mut self, key: &str, result: &Result<String, String>) -> bool {
        if key.starts_with("cyaml|") || key.starts_with("cevents|") {
            self.custom_text.insert(key.to_string(), (false, result.clone()));
            return true;
        }
        false
    }

    pub(super) fn custom_object(&self, s: &CustomSel) -> Option<Value> {
        let k = self.crds.get(s.idx as usize)?;
        let l = self.lists.get(&Self::custom_list_key(&s.ctx, k))?;
        l.items.iter().find(|o| o["metadata"]["name"].as_str() == Some(&s.name) && (!k.namespaced || o["metadata"]["namespace"].as_str() == Some(&s.ns))).cloned()
    }

    /// A custom kind's list page.
    pub(super) fn custom_view(&mut self, ui: &mut Ui, idx: u32) {
        let Some(k) = self.crds.get(idx as usize).cloned() else {
            self.header(ui, false, None, false);
            ui.label(RichText::new("Reading the cluster's custom resources…").color(TEXT_SUBTLE()));
            return;
        };
        if self.custom_sel.as_ref().map(|s| s.idx == idx).unwrap_or(false) {
            self.custom_detail(ui, &k);
            return;
        }
        let multi = self.active.len() > 1;
        let search = self.search.to_lowercase();
        let mut rows: Vec<CRow> = vec![];
        let mut total = 0;
        let mut loading = false;
        let mut errors: Vec<(String, String)> = vec![];
        let cols: Vec<PCol> = k.cols.iter().filter(|c| c.priority == 0).cloned().collect();
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            match self.lists.get(&Self::custom_list_key(c, &k)) {
                Some(l) => {
                    if l.fetched.is_none() {
                        loading = true;
                    }
                    if let Some(e) = &l.error {
                        errors.push((c.clone(), e.clone()));
                    }
                    for o in &l.items {
                        let ns = o["metadata"]["namespace"].as_str().unwrap_or("").to_string();
                        if k.namespaced && !self.ns_ok(&ns) {
                            continue;
                        }
                        total += 1;
                        let name = o["metadata"]["name"].as_str().unwrap_or("").to_string();
                        let cells: Vec<(String, Tone)> = cols.iter().map(|pc| cell_of(o, pc)).collect();
                        if !search.is_empty() && !name.to_lowercase().contains(&search) && !ns.to_lowercase().contains(&search) && !cells.iter().any(|x| x.0.to_lowercase().contains(&search)) {
                            continue;
                        }
                        let ts = o["metadata"]["creationTimestamp"].as_str().unwrap_or("");
                        rows.push(CRow { ctx: c.clone(), ns, name, cells, age: kube::age(ts), age_secs: kube::age_secs(ts) as f64 });
                    }
                }
                None => loading = true,
            }
        }
        // Sort: by the clicked column (Name by default).
        let (sc, asc) = self.custom_sort;
        rows.sort_by(|a, b| {
            let o = match sc {
                0 => a.name.cmp(&b.name),
                1 => a.ns.cmp(&b.ns).then(a.name.cmp(&b.name)),
                usize::MAX => a.age_secs.partial_cmp(&b.age_secs).unwrap_or(std::cmp::Ordering::Equal),
                i => {
                    let (x, y) = (a.cells.get(i - 2).map(|c| c.0.as_str()).unwrap_or(""), b.cells.get(i - 2).map(|c| c.0.as_str()).unwrap_or(""));
                    match (x.parse::<f64>(), y.parse::<f64>()) {
                        (Ok(p), Ok(q)) => p.partial_cmp(&q).unwrap_or(std::cmp::Ordering::Equal),
                        _ => x.cmp(y),
                    }
                }
            };
            if asc { o } else { o.reverse() }
        });
        let shown = rows.len();
        let noun = if k.kind.ends_with('s') { k.kind.clone() } else { format!("{}s", k.kind) };
        let count = if shown == total { format!("{shown} {noun}") } else { format!("{shown} of {total} {noun}") };
        self.header(ui, k.namespaced, Some(count), true);
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{} · {}/{}", k.kind, k.group, k.version)).size(z(12.0)).color(TEXT_PLACEHOLDER()));
            if !k.namespaced {
                ui.label(RichText::new("cluster-wide").size(z(12.0)).color(TEXT_PLACEHOLDER()));
            }
        });
        for (c, e) in &errors {
            Frame::new().fill(WARN_BG()).corner_radius(CornerRadius::same(6)).inner_margin(Margin::same(8)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new(format!("{}: couldn't list {}", ctx_label(c), noun)).color(WARNING()).strong());
                ui.label(RichText::new(truncate(e, 400)).color(TEXT_MUTED()).size(z(12.0)));
            });
        }
        if rows.is_empty() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                if loading {
                    ui.spinner();
                } else if errors.is_empty() {
                    ui.label(RichText::new(format!("No {noun}")).color(TEXT_SUBTLE()));
                }
            });
            return;
        }
        let show_ns = k.namespaced && self.ns_filter.is_none();
        let mut headers: Vec<(String, usize)> = vec![];
        if multi {
            headers.push(("Context".into(), 0));
        }
        if show_ns {
            headers.push(("Namespace".into(), 1));
        }
        headers.push(("Name".into(), 0));
        // Delete.
        headers.push((String::new(), 0));
        for (i, c) in cols.iter().enumerate() {
            headers.push((c.name.clone(), i + 2));
        }
        headers.push(("Age".into(), usize::MAX));
        let mut clicked: Option<CustomSel> = None;
        let mut bin: Option<CustomSel> = None;
        let mut pick_row: Option<(picks::Key3, bool)> = None;
        let mut pick_rects: Vec<(egui::Rect, usize)> = vec![];
        let mut head: Option<egui::Rect> = None;
        let pick_of = picks::What::Custom(k.key.clone());
        self.picks_begin(&pick_of, true, rows.len(), rows.iter().map(|r| (r.ctx.clone(), r.ns.clone(), r.name.clone())));
        let mut sort_click: Option<usize> = None;
        let line = Stroke::new(1.0, BORDER_SUBTLE());
        let n = headers.len();
        let ctx_names: Vec<String> = if multi { rows.iter().map(|r| ctx_label(&r.ctx)).collect() } else { vec![] };
        let ctx_w = snug_width(measure_texts(ui, "Context", ctx_names.iter().map(|s| s.as_str())), true);
        let ns_w = snug_width(measure_texts(ui, "Namespace", rows.iter().map(|r| r.ns.as_str())), false);
        let area = egui::ScrollArea::horizontal().auto_shrink([false, false]).show(ui, |ui| {
            let mut tb = TableBuilder::new(ui).striped(false).resizable(false).sense(Sense::click()).cell_layout(Layout::left_to_right(Align::Center)).min_scrolled_height(0.0);
            for (i, (h, _)) in headers.iter().enumerate() {
                let w = match h.as_str() {
                    "Name" => 300.0,
                    "Namespace" => ns_w,
                    "Context" => ctx_w,
                    "Repository" | "Message" | "Status" => 240.0,
                    "Age" => 80.0,
                    "" => 30.0,
                    _ => 120.0,
                };
                tb = if i + 1 == n { tb.column(Column::remainder().at_least(70.0)) } else { tb.column(Column::initial(w).at_least(40.0).clip(true)) };
            }
            tb.header(u(30.0), |mut hr| {
                for (h, si) in &headers {
                    hr.col(|ui| {
                        cell_line(ui, line);
                        if h.is_empty() {
                            return;
                        }
                        if h == "Name" {
                            head = Some(ui.max_rect());
                        }
                        let sorted = self.custom_sort.0 == *si && !(h == "Context");
                        let arrow = if sorted { if self.custom_sort.1 { " ↑" } else { " ↓" } } else { "" };
                        if ui.add(egui::Label::new(RichText::new(format!("{h}{arrow}")).size(z(14.0)).color(TEXT_SUBTLE())).sense(Sense::click()).selectable(false)).clicked() {
                            sort_click = Some(*si);
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(u(30.0), rows.len(), |mut row| {
                    let at = row.index();
                    let r = &rows[at];
                    if multi {
                        row.col(|ui| {
                            cell_line(ui, line);
                            let cell = ui.max_rect();
                            ui.painter().rect_filled(egui::Rect::from_min_size(egui::pos2(cell.left(), cell.top() + 3.0), egui::vec2(4.0, cell.height() - 6.0)), CornerRadius::same(2), context_color(&r.ctx));
                            ui.add_space(12.0);
                            ui.add(egui::Label::new(RichText::new(ctx_label(&r.ctx)).color(TEXT_MUTED()).size(z(14.0))).truncate().selectable(false));
                        });
                    }
                    if show_ns {
                        row.col(|ui| {
                            cell_line(ui, line);
                            ui.add(egui::Label::new(RichText::new(&r.ns).color(TEXT_DEFAULT()).size(z(14.0))).truncate().selectable(false));
                        });
                    }
                    let mut name_hit = false;
                    row.col(|ui| {
                        cell_line(ui, line);
                        name_hit = name_link(ui, &r.name).clicked();
                    });
                    row.col(|ui| {
                        cell_line(ui, line);
                        if picks::bin_icon(ui).on_hover_text(format!("Delete this {}", k.kind)).clicked() {
                            bin = Some(CustomSel { ctx: r.ctx.clone(), idx, ns: r.ns.clone(), name: r.name.clone() });
                        }
                    });
                    for (t, tone) in &r.cells {
                        row.col(|ui| {
                            cell_line(ui, line);
                            let col = if t == "-" { TEXT_SUBTLE() } else { tone_color(*tone) };
                            ui.add(egui::Label::new(RichText::new(t).color(col).size(z(14.0))).truncate().selectable(false));
                        });
                    }
                    row.col(|ui| {
                        cell_line(ui, line);
                        ui.label(RichText::new(&r.age).color(TEXT_DEFAULT()).size(z(14.0)));
                    });
                    pick_rects.push((row.response().rect, at));
                    if (row.response().clicked() || name_hit) && bin.is_none() {
                        let m = row.response().ctx.input(|i| i.modifiers);
                        if m.command || m.shift {
                            pick_row = Some(((r.ctx.clone(), r.ns.clone(), r.name.clone()), m.shift));
                        } else if name_hit {
                            clicked = Some(CustomSel { ctx: r.ctx.clone(), idx, ns: r.ns.clone(), name: r.name.clone() });
                        }
                    }
                });
            });
        });
        self.pick_boxes(ui, &pick_of, area.inner_rect, head, &pick_rects);
        if let Some((key, shift)) = pick_row {
            self.pick_click(&pick_of, &key, shift);
        }
        if let Some(s) = bin {
            self.ask_delete_custom(&s, &k);
        }
        if let Some(si) = sort_click {
            self.custom_sort = if self.custom_sort.0 == si { (si, !self.custom_sort.1) } else { (si, si != usize::MAX) };
        }
        if let Some(s) = clicked {
            self.custom_tab = 0;
            self.fetch_custom_texts(&s);
            self.custom_sel = Some(s);
        }
    }

    fn ask_delete_custom(&mut self, s: &CustomSel, k: &CrdKind) {
        let ns = k.namespaced.then(|| s.ns.clone());
        let what = if k.namespaced { format!("{} {}/{}", k.kind, s.ns, s.name) } else { format!("{} {}", k.kind, s.name) };
        self.request(Action::DeleteRaw { ctx: s.ctx.clone(), resource: k.key.clone(), ns, name: s.name.clone() }, format!("Delete {}", k.kind), format!("Delete {what}? This can't be undone."), "Delete", true);
    }

    /// A custom object's page: Overview, YAML, Events.
    fn custom_detail(&mut self, ui: &mut Ui, k: &CrdKind) {
        let Some(s) = self.custom_sel.clone() else { return };
        let obj = self.custom_object(&s);
        let mut close = false;
        ui.horizontal(|ui| {
            if back_button(ui).on_hover_text("Back to the list (Esc)").clicked() {
                close = true;
            }
            let (d, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), Sense::hover());
            ui.painter().circle_filled(d.center(), 3.5, context_color(&s.ctx));
            ui.label(RichText::new(format!("{} · {}", ctx_label(&s.ctx), k.kind)).size(z(12.0)).color(TEXT_SUBTLE()));
            self.ai_corner(ui, obj.is_some());
        });
        if close || ui.input(|i| i.key_pressed(Key::Escape)) && self.dialog.is_none() {
            self.custom_sel = None;
            return;
        }
        ui.horizontal(|ui| {
            if k.namespaced {
                ui.label(RichText::new(format!("{} /", s.ns)).size(z(22.0)).color(TEXT_SUBTLE()));
            }
            ui.label(RichText::new(&s.name).size(z(22.0)).color(TEXT_DEFAULT()));
            if let Some(o) = &obj {
                ui.label(RichText::new(kube::age(o["metadata"]["creationTimestamp"].as_str().unwrap_or(""))).size(z(13.0)).color(TEXT_PLACEHOLDER()));
            }
        });
        ui.horizontal(|ui| {
            for (i, t) in ["Overview", "YAML", "Events"].iter().enumerate() {
                let on = self.custom_tab == i as u8;
                let r = ui.add(egui::Button::new(RichText::new(*t).color(if on { TEXT_DEFAULT() } else { TEXT_SUBTLE() })).fill(if on { BG_MUTED() } else { Color32::TRANSPARENT }).stroke(Stroke::NONE));
                if r.clicked() {
                    self.custom_tab = i as u8;
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if button(ui, "Delete", false, false) {
                    self.ask_delete_custom(&s, k);
                }
                if let Some(o) = &obj {
                    self.custom_actions(ui, &k.key, &s, o);
                }
                if button(ui, "Refresh", false, false) {
                    self.fetch_custom_texts(&s);
                    self.fetch_custom(&s.ctx, s.idx);
                }
            });
        });
        let y = ui.cursor().top();
        ui.painter().hline(ui.max_rect().x_range(), y, Stroke::new(1.0, BORDER_SUBTLE()));
        ui.add_space(8.0);
        let key_tail = format!("{}|{}|{}|{}", s.ctx, k.key, s.ns, s.name);
        match self.custom_tab {
            1 => {
                let txt = self.custom_text.get(&format!("cyaml|{key_tail}")).cloned();
                match txt {
                    Some((true, _)) | None => {
                        ui.spinner();
                    }
                    Some((false, Err(e))) => {
                        ui.label(RichText::new(e).color(DANGER()));
                    }
                    Some((false, Ok(t))) => {
                        if button(ui, "Copy", false, false) {
                            ui.ctx().copy_text(t.clone());
                            self.toast("YAML copied".into(), false);
                        }
                        egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                            Frame::new().fill(LOG_BG()).corner_radius(CornerRadius::same(6)).inner_margin(Margin::same(10)).show(ui, |ui| {
                                ui.add(egui::Label::new(RichText::new(t).monospace().size(z(12.5)).color(TEXT_DEFAULT())).extend());
                            });
                        });
                    }
                }
            }
            2 => {
                let txt = self.custom_text.get(&format!("cevents|{key_tail}")).cloned();
                match txt {
                    Some((true, _)) | None => {
                        ui.spinner();
                    }
                    Some((false, Err(e))) => {
                        ui.label(RichText::new(e).color(DANGER()));
                    }
                    Some((false, Ok(t))) => {
                        let mut items = kube::parse_items(&t).unwrap_or_default();
                        items.sort_by_key(|e| std::cmp::Reverse(e["lastTimestamp"].as_str().or(e["eventTime"].as_str()).unwrap_or("").to_string()));
                        if items.is_empty() {
                            ui.label(RichText::new("No events for this object.").color(TEXT_SUBTLE()));
                        }
                        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                            for e in items {
                                card(ui, |ui| {
                                    ui.horizontal_wrapped(|ui| {
                                        let warn = e["type"].as_str() == Some("Warning");
                                        ui.label(RichText::new(e["reason"].as_str().unwrap_or("")).strong().color(if warn { WARNING() } else { TEXT_DEFAULT() }));
                                        ui.label(RichText::new(kube::age(e["lastTimestamp"].as_str().or(e["eventTime"].as_str()).unwrap_or(""))).size(z(12.0)).color(TEXT_SUBTLE()));
                                        if let Some(n) = e["count"].as_i64().filter(|n| *n > 1) {
                                            ui.label(RichText::new(format!("×{n}")).size(z(12.0)).color(TEXT_SUBTLE()));
                                        }
                                    });
                                    ui.add(egui::Label::new(RichText::new(e["message"].as_str().unwrap_or("")).color(TEXT_MUTED())).wrap());
                                });
                                ui.add_space(4.0);
                            }
                        });
                    }
                }
            }
            _ => {
                let Some(o) = obj else {
                    ui.label(RichText::new("This object is no longer in the list.").color(TEXT_SUBTLE()));
                    return;
                };
                self.custom_overview(ui, k, &s, &o);
            }
        }
    }

    fn custom_overview(&mut self, ui: &mut Ui, k: &CrdKind, s: &CustomSel, o: &Value) {
        let md = &o["metadata"];
        let mut to: Option<Selected> = None;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            let now = kube::now_secs();
            let (tone, head, notes) = face::generic(o);
            let ts = md["creationTimestamp"].as_str().unwrap_or("");
            let mut facts: Vec<face::Fact> = k.cols.iter().filter_map(|c| {
                let (t, tone) = cell_of(o, c);
                (t != "-").then(|| face::Fact::new(c.name.clone(), t).col(tone_color(tone)))
            }).collect();
            facts.push(face::Fact::new("Kind", k.kind.clone()));
            facts.push(face::Fact::new("Group", format!("{}/{}", k.group, k.version)));
            if md["ownerReferences"][0]["name"].is_string() {
                let sel = Selected { ctx: s.ctx.clone(), kind: Kind::Pods, ns: s.ns.clone(), name: s.name.clone() };
                facts.push(self.owner_fact(&sel, o));
            }
            facts.push(face::Fact::new("Created", format!("{} ago", kube::age(ts))));
            let f = face::Face { tone, head: if head.is_empty() { k.kind.clone() } else { head }, sub: format!("created {} ago", kube::age(ts)), notes, pills: face::pills(o, now), facts };
            if let Some(t) = face::show(ui, &f, face::Side::None) {
                to = Some(t);
            }
            // Conditions.
            if let Some(conds) = o["status"]["conditions"].as_array().filter(|a| !a.is_empty()) {
                ui.add_space(8.0);
                ui.label(RichText::new(format!("Conditions ({})", conds.len())).color(TEXT_SUBTLE()).strong());
                card(ui, |ui| {
                    for c in conds {
                        ui.horizontal_wrapped(|ui| {
                            let st = c["status"].as_str().unwrap_or("");
                            let good = st == "True";
                            ui.label(RichText::new(if good { "✓" } else if st == "False" { "×" } else { "?" }).strong().color(if good { SUCCESS() } else if st == "False" { DANGER() } else { WARNING() }));
                            ui.label(RichText::new(c["type"].as_str().unwrap_or("")).strong().color(TEXT_DEFAULT()));
                            if let Some(r) = c["reason"].as_str() {
                                ui.label(RichText::new(r).size(z(12.5)).color(TEXT_MUTED()));
                            }
                            if let Some(t) = c["lastTransitionTime"].as_str() {
                                ui.label(RichText::new(format!("{} ago", kube::age(t))).size(z(12.0)).color(TEXT_PLACEHOLDER()));
                            }
                        });
                        if let Some(m) = c["message"].as_str().filter(|m| !m.is_empty()) {
                            ui.add(egui::Label::new(RichText::new(truncate(m, 400)).size(z(12.5)).color(TEXT_SUBTLE())).wrap());
                        }
                    }
                });
            }
            // Spec and status, written out (long ones fold).
            for part in ["spec", "status"] {
                let v = &o[part];
                if v.is_null() || v.as_object().map(|m| m.is_empty()).unwrap_or(false) {
                    continue;
                }
                let mut text = String::new();
                yamlish(v, 0, &mut text);
                let lines = text.lines().count();
                let fold_key = format!("{}|{}|{part}", s.ctx, s.name);
                let open = self.env_open.contains(&fold_key);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new(if part == "spec" { "Spec" } else { "Status" }).color(TEXT_SUBTLE()).strong());
                    if lines > 40 {
                        let t = if open { "▴ fold".to_string() } else { format!("▾ show all {lines} lines") };
                        if ui.add(egui::Label::new(RichText::new(t).size(z(12.0)).color(PRIMARY_TEXT())).sense(Sense::click())).clicked() {
                            if open {
                                self.env_open.remove(&fold_key);
                            } else {
                                self.env_open.insert(fold_key.clone());
                            }
                        }
                    }
                });
                let shown: String = if lines > 40 && !open { text.lines().take(30).collect::<Vec<_>>().join("\n") + "\n…" } else { text };
                Frame::new().fill(LOG_BG()).corner_radius(CornerRadius::same(6)).inner_margin(Margin::same(10)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.add(egui::Label::new(RichText::new(shown).monospace().size(z(12.0)).color(TEXT_DEFAULT())).wrap());
                });
            }
            let own = &md["ownerReferences"][0];
            let refs: Vec<face::Ref> = own["name"].as_str().map(|n| {
                let kind = own["kind"].as_str().unwrap_or("");
                ("Owner", kind.to_string(), n.to_string(), workload::kind_named(kind).map(|k| Selected { ctx: s.ctx.clone(), kind: k, ns: if k.namespaced() { s.ns.clone() } else { String::new() }, name: n.into() }))
            }).into_iter().collect();
            if let Some(t) = face::meta(ui, &format!("{s:?}"), &refs, o) {
                to = Some(t);
            }
            ui.add_space(12.0);
        });
        if let Some(t) = to {
            self.navigate(View::Resource(t.kind), Some(t));
        }
    }

    /// The sidebar's GitOps part (Argo CD).
    pub(super) fn sidebar_gitops(&mut self, ui: &mut Ui) {
        self.ensure_crds();
        self.sync_crds();
        // GitOps.
        let argo: Vec<(u32, String)> = ["applications.argoproj.io", "applicationsets.argoproj.io", "appprojects.argoproj.io"]
            .iter()
            .filter_map(|key| self.crd_index(key).map(|i| (i, self.crds[i as usize].kind.clone())))
            .collect();
        if !argo.is_empty() && self.group_header(ui, "GitOps", "⎇") {
            for (i, kind) in argo {
                let label = match kind.as_str() { "Application" => "Applications".to_string(), "ApplicationSet" => "Application Sets".into(), "AppProject" => "Projects".into(), k => k.to_string() };
                if self.nav_fav(ui, self.view == View::Custom(i) && self.custom_sel.is_none(), View::Custom(i), &label, &format!("Argo CD {label}"), None) {
                    self.open_custom(i);
                }
            }
            ui.add_space(14.0);
        }
    }

    /// The sidebar's custom resources: every API group.
    pub(super) fn sidebar_custom(&mut self, ui: &mut Ui) {
        self.ensure_crds();
        self.sync_crds();
        let loading = self.active.iter().any(|c| self.lists.get(&Self::list_key(c, Kind::CustomResourceDefinitions)).map(|l| l.fetched.is_none()).unwrap_or(true));
        if !self.group_header(ui, "Custom Resources", "◇") {
            return;
        }
        ui.horizontal(|ui| {
            let w = ui.available_width() - 30.0;
            filter_box(ui, &mut self.crd_filter, "Filter CRDs…", w);
            if ui.add(egui::Button::new(RichText::new("⟳").size(z(14.0)).color(TEXT_SUBTLE())).frame(false)).on_hover_text("Read the custom resource definitions again").clicked() {
                for c in self.active.clone() {
                    self.fetch_list(&c, Kind::CustomResourceDefinitions);
                }
            }
        });
        if self.crds.is_empty() {
            ui.label(RichText::new(if loading { "Reading…" } else { "None (or no permission to list them)." }).size(z(12.0)).color(TEXT_PLACEHOLDER()));
            return;
        }
        let q = self.crd_filter.to_lowercase();
        // top group -> sub group -> kinds
        let mut tree: std::collections::BTreeMap<String, std::collections::BTreeMap<String, Vec<(u32, String)>>> = Default::default();
        for (i, k) in self.crds.iter().enumerate() {
            if !q.is_empty() && !k.kind.to_lowercase().contains(&q) && !k.group.to_lowercase().contains(&q) && !k.plural.contains(&q) {
                continue;
            }
            let (top, sub) = k.place();
            tree.entry(top).or_default().entry(sub).or_default().push((i as u32, k.kind.clone()));
        }
        if tree.is_empty() {
            ui.label(RichText::new("No match.").size(z(12.0)).color(TEXT_PLACEHOLDER()));
        }
        for (top, subs) in tree {
            let n: usize = subs.values().map(|v| v.len()).sum();
            let has_current = subs.values().flatten().any(|(i, _)| self.view == View::Custom(*i));
            let open = !q.is_empty() || has_current || self.crd_open.contains(&top);
            let (r, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(24.0)), Sense::click());
            if resp.hovered() {
                ui.painter().rect_filled(r, CornerRadius::same(5), BG_HOVER());
            }
            let p = ui.painter();
            p.text(r.left_center() + egui::vec2(8.0, 0.0), egui::Align2::LEFT_CENTER, if open { "▾" } else { "▸" }, FontId::proportional(z(11.0)), TEXT_SUBTLE());
            let g = p.layout_no_wrap(fit(ui, &top, r.width() - 60.0, z(13.5)), FontId::proportional(z(13.5)), TEXT_MUTED());
            p.galley(egui::pos2(r.left() + 22.0, r.center().y - g.size().y / 2.0), g, TEXT_MUTED());
            p.text(r.right_center() - egui::vec2(8.0, 0.0), egui::Align2::RIGHT_CENTER, n.to_string(), FontId::proportional(z(11.5)), TEXT_PLACEHOLDER());
            if resp.clicked() {
                if self.crd_open.contains(&top) {
                    self.crd_open.remove(&top);
                } else {
                    self.crd_open.insert(top.clone());
                }
            }
            if !open {
                continue;
            }
            for (sub, mut kinds) in subs {
                kinds.sort_by(|a, b| a.1.cmp(&b.1));
                if !sub.is_empty() {
                    ui.horizontal(|ui| {
                        ui.add_space(22.0);
                        ui.label(RichText::new(&sub).size(z(12.0)).color(TEXT_PLACEHOLDER()));
                    });
                }
                for (i, kind) in kinds {
                    ui.horizontal(|ui| {
                        ui.add_space(if sub.is_empty() { 14.0 } else { 24.0 });
                        if self.nav_fav(ui, self.view == View::Custom(i) && self.custom_sel.is_none(), View::Custom(i), &kind, &kind, None) {
                            self.open_custom(i);
                        }
                    });
                }
            }
        }
        ui.add_space(14.0);
    }

    pub(super) fn open_custom(&mut self, i: u32) {
        if self.view == View::Custom(i) && self.custom_sel.is_some() {
            self.custom_sel = None;
        } else {
            self.set_view(View::Custom(i));
        }
        self.refresh_custom(i, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kinds_without_definitions() {
        let text = "pods po v1 true Pod\ndeployments deploy apps/v1 true Deployment\nclusters postgresql.cnpg.io/v1 true Cluster\nelasticsearches es elasticsearch.k8s.elastic.co/v1 true Elasticsearch\ngatewayclasses gc gateway.networking.k8s.io/v1 false GatewayClass\nerror: x";
        let v = super::parse_api_resources(text);
        assert_eq!(v.len(), 3);
        let k = super::CrdKind::from_crd(&v[0]).unwrap();
        assert_eq!((k.key.as_str(), k.version.as_str(), k.namespaced, k.stub, k.cols.is_empty()), ("clusters.postgresql.cnpg.io", "v1", true, true, true));
        assert!(!super::CrdKind::from_crd(&v[2]).unwrap().namespaced);
    }

    #[test]
    fn printer_column_paths() {
        let o = serde_json::json!({
            "spec": {"sources": [{"repoURL": "https://git.example.com/a.git"}], "syncPolicy": {"automated": {"prune": true}}},
            "status": {"conditions": [{"type": "Synced", "status": "False"}, {"type": "Ready", "status": "True"}], "sync": {"status": "Synced"}}
        });
        assert_eq!(json_path(&o, ".status.sync.status"), vec![serde_json::json!("Synced")]);
        assert_eq!(json_path(&o, r#".status.conditions[?(@.type=="Ready")].status"#), vec![serde_json::json!("True")]);
        assert_eq!(json_path(&o, ".spec.source.repoURL|.spec.sources[0].repoURL"), vec![serde_json::json!("https://git.example.com/a.git")]);
        assert_eq!(json_path(&o, ".status.conditions[*].type").len(), 2);
        let c = |path: &str, ty: &str| PCol { name: "x".into(), path: path.into(), ty: ty.into(), priority: 0 };
        assert_eq!(cell_of(&o, &c(".spec.syncPolicy.automated", "exists")).0, "Yes");
        assert_eq!(cell_of(&o, &c(".spec.syncPolicy.automated.selfHeal", "boolean")).0, "-");
        assert_eq!(cell_of(&o, &c(".spec.syncPolicy.automated.prune", "boolean")).0, "Yes");
        assert_eq!(cell_of(&o, &c(".nothing", "string")).0, "-");
        let crd = serde_json::json!({"spec": {"group": "acme.cert-manager.io", "scope": "Namespaced", "names": {"kind": "Order", "plural": "orders"},
            "versions": [{"name": "v1", "served": true, "storage": true, "additionalPrinterColumns": [{"name": "State", "jsonPath": ".status.state", "type": "string"}]}]}});
        let k = CrdKind::from_crd(&crd).unwrap();
        assert_eq!((k.key.as_str(), k.namespaced, k.cols.len()), ("orders.acme.cert-manager.io", true, 1));
        assert_eq!(k.place(), ("cert-manager.io".to_string(), "acme".to_string()));
    }
}
