//! Look-ups for the AI: a few fixed ways of reading the cluster. The AI names one; Kubedog checks it,
//! runs kubectl itself and gives the result back as facts. Nothing here can change anything or read a secret.

use super::aifacts::{Class, Facts};
use super::ops::{obj, text};
use super::work::name_of;
use super::*;

/// Rounds of look-ups per question, and look-ups per round.
pub(super) const ROUNDS: usize = 6;
pub(super) const EACH: usize = 3;

#[derive(Clone, Copy, PartialEq, Debug)]
pub(super) enum Tool {
    List,
    Show,
    Events,
    Logs,
    Usage,
}

/// A look-up that was checked.
#[derive(Clone, PartialEq, Debug)]
pub(super) struct Look {
    pub tool: Tool,
    pub ctx: String,
    pub kind: Kind,
    pub ns: String,
    pub name: String,
    pub container: String,
    pub previous: bool,
    pub find: String,
}

/// The kinds that may be read. Secrets aren't one of them.
const KINDS: [(Kind, &str); 24] = [
    (Kind::Pods, "pod"),
    (Kind::Deployments, "deployment"),
    (Kind::StatefulSets, "statefulset"),
    (Kind::DaemonSets, "daemonset"),
    (Kind::ReplicaSets, "replicaset"),
    (Kind::Jobs, "job"),
    (Kind::CronJobs, "cronjob"),
    (Kind::Services, "service"),
    (Kind::Ingresses, "ingress"),
    (Kind::EndpointSlices, "endpointslice"),
    (Kind::NetworkPolicies, "networkpolicy"),
    (Kind::ConfigMaps, "configmap"),
    (Kind::HorizontalPodAutoscalers, "horizontalpodautoscaler"),
    (Kind::PodDisruptionBudgets, "poddisruptionbudget"),
    (Kind::ResourceQuotas, "resourcequota"),
    (Kind::LimitRanges, "limitrange"),
    (Kind::PersistentVolumeClaims, "persistentvolumeclaim"),
    (Kind::PersistentVolumes, "persistentvolume"),
    (Kind::StorageClasses, "storageclass"),
    (Kind::Nodes, "node"),
    (Kind::Namespaces, "namespace"),
    (Kind::Events, "event"),
    (Kind::IngressClasses, "ingressclass"),
    (Kind::ServiceAccounts, "serviceaccount"),
];

fn kind_of(t: &str) -> Option<Kind> {
    let t = t.trim().to_lowercase();
    let short = match t.as_str() {
        "po" => "pod",
        "deploy" => "deployment",
        "sts" => "statefulset",
        "ds" => "daemonset",
        "rs" => "replicaset",
        "svc" => "service",
        "ing" => "ingress",
        "cm" => "configmap",
        "hpa" => "horizontalpodautoscaler",
        "pdb" => "poddisruptionbudget",
        "pvc" => "persistentvolumeclaim",
        "pv" => "persistentvolume",
        "netpol" => "networkpolicy",
        "ns" => "namespace",
        "no" => "node",
        "networkpolicies" => "networkpolicy",
        "ingresses" => "ingress",
        "storageclasses" => "storageclass",
        "ingressclasses" => "ingressclass",
        x => x.strip_suffix('s').filter(|y| KINDS.iter().any(|k| k.1 == *y)).unwrap_or(x),
    };
    KINDS.iter().find(|k| k.1 == short).map(|k| k.0)
}

/// Names as Kubernetes has them; never something kubectl could take for an option.
fn good(name: &str) -> bool {
    !name.is_empty() && name.len() <= 253 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.' | b':')) && name.as_bytes()[0].is_ascii_alphanumeric()
}

/// What's asked for in an answer: (the rest of the text, the JSON of each line).
pub(super) fn asked(t: &str) -> (String, Vec<Value>) {
    let mut rest = String::new();
    let mut out = vec![];
    for l in t.lines() {
        let s = l.trim().trim_start_matches(['-', '*', '`', ' ']).trim_end_matches('`');
        if let Some(v) = s.strip_prefix("LOOK").map(|x| x.trim_start_matches([':', ' '])).filter(|x| x.starts_with('{')).and_then(|x| serde_json::Deserializer::from_str(x).into_iter::<Value>().next()?.ok()) {
            out.push(v);
        } else {
            rest.push_str(l);
            rest.push('\n');
        }
    }
    // A fence that held only look-ups.
    let rest = rest.replace("```json\n```", "").replace("```\n```", "");
    (rest.trim().to_string(), out)
}

/// What a check may know: the clusters of the conversation (name, label), the namespaces a cluster is
/// limited to, and whether log lines may go where the answer comes from.
pub(super) struct Allowed<'a> {
    pub ctxs: &'a [(String, String)],
    pub limits: &'a HashMap<String, Vec<String>>,
    pub logs: bool,
}

/// Checks one look-up. The names in it are real ones again.
pub(super) fn check(v: &Value, a: &Allowed) -> Result<Look, String> {
    let s = |k: &str| v[k].as_str().unwrap_or("").trim().to_string();
    let tool = match s("tool").as_str() {
        "list" => Tool::List,
        "show" => Tool::Show,
        "events" => Tool::Events,
        "logs" if a.logs => Tool::Logs,
        "logs" => return Err("log lines may not be sent where you run".into()),
        "usage" => Tool::Usage,
        t => return Err(format!("there's no tool {}", truncate(t, 30))),
    };
    let want = s("cluster");
    let ctx = if want.is_empty() && a.ctxs.len() == 1 {
        a.ctxs[0].0.clone()
    } else {
        a.ctxs.iter().find(|c| c.0 == want || c.1 == want).map(|c| c.0.clone()).ok_or(if want.is_empty() { "name the cluster" } else { "that cluster isn't part of this conversation" })?
    };
    let kind = match tool {
        Tool::List | Tool::Show => {
            let k = s("kind");
            if k.to_lowercase().starts_with("secret") {
                return Err("secrets can't be read".into());
            }
            kind_of(&k).ok_or(format!("{} can't be looked up", truncate(&k, 40)))?
        }
        Tool::Events => Kind::Events,
        Tool::Logs => Kind::Pods,
        Tool::Usage => if s("ns").is_empty() { Kind::Nodes } else { Kind::Pods },
    };
    let ns = if kind.namespaced() { s("ns") } else { String::new() };
    if !ns.is_empty() && (!good(&ns) || ns.contains([':', '.'])) {
        return Err("that isn't a namespace's name".into());
    }
    let name = match s("name") {
        n if n.is_empty() => s("pod"),
        n => n,
    };
    let name = name.rsplit('/').next().unwrap_or("").to_string();
    if !name.is_empty() && !good(&name) {
        return Err("that isn't an object's name".into());
    }
    let container = s("container");
    if !container.is_empty() && (!good(&container) || container.contains(':')) {
        return Err("that isn't a container's name".into());
    }
    match tool {
        Tool::Show | Tool::Logs if name.is_empty() => return Err("name the object".into()),
        Tool::Show | Tool::Logs if kind.namespaced() && ns.is_empty() => return Err("name the namespace".into()),
        _ => {}
    }
    if let Some(l) = a.limits.get(&ctx).filter(|_| kind.namespaced()) {
        if ns.is_empty() {
            return Err("name a namespace: this cluster is limited to some".into());
        }
        if !l.iter().any(|p| glob_match(p, &ns)) {
            return Err("that namespace isn't one Kubedog reads here".into());
        }
    } else if a.limits.contains_key(&ctx) && !kind.namespaced() && kind != Kind::Nodes {
        return Err("only namespaces are read in this cluster".into());
    }
    Ok(Look { tool, ctx, kind, ns, name, container, previous: v["previous"] == true, find: truncate(&s("find"), 60).to_lowercase() })
}

impl Look {
    /// For people.
    pub fn words(&self) -> String {
        let at = if self.ns.is_empty() { String::new() } else { format!(" in {}", self.ns) };
        let of = if self.name.is_empty() { String::new() } else { format!(" of {}", self.name) };
        match self.tool {
            Tool::List => format!("{}{at}{}", self.kind.label(), if self.find.is_empty() { String::new() } else { format!(" with \"{}\"", self.find) }),
            Tool::Show => format!("{} {}{at}", self.kind.singular(), self.name),
            Tool::Events => format!("events{of}{at}"),
            Tool::Logs => format!("{}log{of}{}{at}", if self.previous { "previous " } else { "" }, if self.container.is_empty() { String::new() } else { format!(" ({})", self.container) }),
            Tool::Usage => format!("usage of {}{at}", if self.kind == Kind::Nodes { "nodes" } else { "pods" }),
        }
    }

    /// What kubectl is run with; more than one when it takes more to answer.
    pub fn args(&self) -> Vec<Vec<String>> {
        let wait = format!("--request-timeout={}", kube::REQUEST_TIMEOUT);
        let mut base: Vec<String> = vec!["--context".into(), self.ctx.clone()];
        if !self.ns.is_empty() {
            base.extend(["-n".into(), self.ns.clone()]);
        }
        let mk = |l: &[&str]| -> Vec<String> { base.iter().cloned().chain(l.iter().map(|s| s.to_string())).chain(std::iter::once(wait.clone())).collect() };
        let all: &[&str] = if self.ns.is_empty() && self.kind.namespaced() { &["--all-namespaces"] } else { &[] };
        let about = format!("--field-selector=involvedObject.name={}", self.name);
        match self.tool {
            Tool::List => vec![mk(&[&["get", self.kind.resource()], all, &["-o", "json"]].concat())],
            Tool::Show => {
                let mut v = vec![mk(&["get", self.kind.resource(), &self.name, "-o", "json"])];
                if self.kind.namespaced() && self.kind != Kind::Events {
                    v.push(mk(&["get", "events", &about, "-o", "json"]));
                }
                v
            }
            Tool::Events if self.name.is_empty() => vec![mk(&[&["get", "events"], all, &["--field-selector=type=Warning", "-o", "json"]].concat())],
            Tool::Events => vec![mk(&[&["get", "events"], all, &[about.as_str(), "-o", "json"]].concat())],
            Tool::Logs => {
                let mut l = vec!["logs", self.name.as_str(), "--tail=400", "--limit-bytes=300000", "--timestamps"];
                if self.container.is_empty() {
                    l.push("--all-containers");
                } else {
                    l.extend(["-c", self.container.as_str()]);
                }
                if self.previous {
                    l.push("--previous");
                }
                vec![mk(&l)]
            }
            Tool::Usage => vec![mk(&["top", if self.kind == Kind::Nodes { "nodes" } else { "pods" }, "--no-headers"])],
        }
    }
}

/// The commands themselves, one after the other. Only called behind the gate, with checked look-ups.
pub(super) fn run(k: &Kubectl, l: &[Look], stop: &std::sync::atomic::AtomicBool) -> Value {
    Value::Array(l.iter().map(|x| {
        let mut out = vec![];
        for a in x.args() {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            match k.run(&a) {
                Ok(t) => out.push(if matches!(x.tool, Tool::Logs | Tool::Usage) { Value::String(t) } else { serde_json::from_str(&t).unwrap_or(Value::Null) }),
                Err(e) if out.is_empty() => return serde_json::json!({"error": truncate(&e, 240)}),
                Err(_) => {}
            }
        }
        Value::Array(out)
    }).collect())
}

/// What the AI is told about look-ups.
pub(super) fn manual(logs: bool, clusters: &[String]) -> String {
    format!(
        "You may have the app look things up, reading only. To do that, answer with nothing but 1 to {EACH} lines, each the word LOOK and JSON, then stop; you get the results as more facts. The tools:\n\
LOOK {{\"tool\":\"list\",\"kind\":\"pods\",\"ns\":\"x\",\"find\":\"text\"}} (ns and find may be left out)\n\
LOOK {{\"tool\":\"show\",\"kind\":\"deployment\",\"ns\":\"x\",\"name\":\"y\"}}\n\
LOOK {{\"tool\":\"events\",\"ns\":\"x\",\"name\":\"y\"}} (both may be left out)\n{}\
LOOK {{\"tool\":\"usage\",\"ns\":\"x\"}} (pods; without ns nodes)\n{}\
Kinds: {}. Secrets can't be read and nothing can be changed. Look only for what you need, at most {ROUNDS} times, then answer. Use no tools of your own.",
        if logs { "LOOK {\"tool\":\"logs\",\"ns\":\"x\",\"pod\":\"y\",\"container\":\"c\",\"previous\":true} (container and previous may be left out)\n" } else { "" },
        if clusters.len() > 1 { format!("Add \"cluster\" with one of: {}.\n", clusters.join(", ")) } else { String::new() },
        KINDS.iter().map(|k| k.1).collect::<Vec<_>>().join(", ")
    )
}

impl KubedogApp {
    /// Results as facts.
    pub(super) fn look_facts(&self, looks: &[Look], results: &Value) -> Facts {
        let mut f = Facts::default();
        for (i, l) in looks.iter().enumerate() {
            let r = &results[i];
            let what = l.words();
            if !f.ctxs.contains(&l.ctx) {
                f.ctxs.push(l.ctx.clone());
            }
            if let Some(e) = r["error"].as_str() {
                f.add(Class::State, format!("Look-up of {what} failed: {e}"), None);
                continue;
            }
            let items = |n: usize| r[n]["items"].as_array().cloned().unwrap_or_default();
            let mut events = |f: &mut Facts, mut v: Vec<Value>| {
                v.sort_by_key(|e| std::cmp::Reverse(text(&e["lastTimestamp"]).max(text(&e["eventTime"]))));
                for e in v.iter().take(25) {
                    f.add(Class::State, format!("Event {} {} on {} {} ({} times, last {}): {}", text(&e["type"]), text(&e["reason"]), text(&e["involvedObject"]["kind"]), text(&e["involvedObject"]["name"]), e["count"].as_i64().unwrap_or(1), text(&e["lastTimestamp"]), truncate(e["message"].as_str().unwrap_or(""), 300)), None);
                }
                if v.is_empty() {
                    f.add(Class::State, format!("No events ({what})"), None);
                }
            };
            match l.tool {
                Tool::List => {
                    let mut rows: Vec<(bool, String, Row)> = items(0).iter().map(|o| make_row(l.kind, o)).map(|r| (!r.cells.iter().any(|c| matches!(c.tone, Tone::Danger | Tone::Warning)), aipage::row_text(l.kind, &r), r)).filter(|x| l.find.is_empty() || x.2.name.contains(&l.find) || x.1.to_lowercase().contains(&l.find)).collect();
                    rows.sort_by_key(|r| r.0);
                    f.add(Class::State, format!("Looked up {what}: {} found", rows.len()), None);
                    for (_, t, r) in rows.iter().take(40) {
                        f.add(Class::State, format!("{} {}{}: {t}", l.kind.singular(), r.name, if r.ns.is_empty() { String::new() } else { format!(" in {}", r.ns) }), Some(obj(&l.ctx, l.kind, &r.ns, &r.name)));
                    }
                }
                Tool::Show => {
                    let o = &r[0];
                    if name_of(o).is_empty() {
                        f.add(Class::State, format!("Look-up of {what}: it isn't there"), None);
                        continue;
                    }
                    let sel = Selected { ctx: l.ctx.clone(), kind: l.kind, ns: l.ns.clone(), name: l.name.clone() };
                    f.list.extend(self.object_facts_of(&sel, o).list);
                    if l.kind.namespaced() {
                        events(&mut f, items(1));
                    }
                }
                Tool::Events => events(&mut f, items(0)),
                Tool::Logs => {
                    let t = r[0].as_str().unwrap_or("");
                    let lines: Vec<LogLine> = t.lines().map(|x| LogLine::new(x.to_string(), false)).collect();
                    let bad: Vec<usize> = lines.iter().enumerate().filter(|(_, x)| matches!(x.level, Level::Error | Level::Fatal | Level::Warn)).map(|x| x.0).collect();
                    f.add(Class::State, format!("Looked up the {what}: {} lines, {} of them errors or warnings", lines.len(), bad.len()), None);
                    let mut pick: std::collections::BTreeSet<usize> = bad.into_iter().rev().take(25).collect();
                    pick.extend(lines.len().saturating_sub(15)..lines.len());
                    for i in pick {
                        f.add(Class::Log, format!("Log of {}: {}", l.name, truncate(&lines[i].text, 350)), None);
                    }
                }
                Tool::Usage => {
                    for line in r[0].as_str().unwrap_or("").lines().take(60) {
                        let w: Vec<&str> = line.split_whitespace().collect();
                        match (l.kind, w.as_slice()) {
                            (Kind::Nodes, [n, c, cp, m, mp, ..]) => f.add(Class::State, format!("node {n} uses {c} CPU ({cp}) and {m} memory ({mp})"), None),
                            (_, [n, c, m, ..]) => f.add(Class::State, format!("pod {n} uses {c} CPU and {m} memory"), None),
                            _ => {}
                        }
                    }
                }
            }
        }
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn one(v: Value) -> Result<Look, String> {
        let limits = HashMap::from([("limited".to_string(), vec!["shop".to_string(), "team-*".to_string()])]);
        check(&v, &Allowed { ctxs: &[("a".into(), "Alpha".into())], limits: &limits, logs: true })
    }

    #[test]
    fn only_reading() {
        for v in [
            json!({"tool": "list", "kind": "secrets"}),
            json!({"tool": "show", "kind": "Secret", "ns": "x", "name": "y"}),
            json!({"tool": "show", "kind": "secrets/y", "ns": "x", "name": "y"}),
            json!({"tool": "exec", "ns": "x", "pod": "y"}),
            json!({"tool": "delete", "kind": "pod", "ns": "x", "name": "y"}),
            json!({"tool": "list", "kind": "pods/exec"}),
            json!({"tool": "list", "kind": "--raw=/api"}),
            json!({"tool": "list", "kind": "pods,secrets"}),
            json!({"tool": "list", "kind": "pods", "ns": "--kubeconfig=x"}),
            json!({"tool": "list", "kind": "pods", "ns": "x -o yaml"}),
            json!({"tool": "show", "kind": "pod", "ns": "x", "name": "-oyaml"}),
            json!({"tool": "show", "kind": "pod", "ns": "x", "name": "a b"}),
            json!({"tool": "show", "kind": "pod", "ns": "x"}),
            json!({"tool": "show", "kind": "pod", "name": "x"}),
            json!({"tool": "logs", "ns": "x", "pod": "y", "container": "--follow"}),
            json!({"tool": "list", "kind": "pods", "cluster": "other"}),
            json!({"tool": "list", "kind": "clusterroles"}),
            json!({}),
        ] {
            assert!(one(v.clone()).is_err(), "{v}");
        }
        // Whatever passes is one of three verbs, and nothing a check let through is an option.
        for v in [
            json!({"tool": "list", "kind": "Pods", "ns": "shop", "find": "--all"}),
            json!({"tool": "list", "kind": "deploy"}),
            json!({"tool": "show", "kind": "deployments", "ns": "shop", "name": "deployment/web"}),
            json!({"tool": "events"}),
            json!({"tool": "events", "ns": "shop", "name": "web-1"}),
            json!({"tool": "logs", "ns": "shop", "pod": "web-1", "previous": true, "cluster": "Alpha"}),
            json!({"tool": "usage"}),
            json!({"tool": "usage", "ns": "shop"}),
        ] {
            let l = one(v.clone()).unwrap_or_else(|e| panic!("{v}: {e}"));
            for a in l.args() {
                let verb = a.iter().find(|x| ["get", "logs", "top"].contains(&x.as_str()));
                assert!(verb.is_some() && a[0] == "--context" && a[1] == "a", "{a:?}");
                assert!(!a.iter().any(|x| x.contains("secret") || x.contains("raw") || x.contains("kubeconfig") || x == "-f" || x.contains("follow")), "{a:?}");
                for x in a.iter().filter(|x| x.starts_with('-')) {
                    assert!(["--context", "-n", "-o", "-c", "--all-namespaces", "--all-containers", "--previous", "--timestamps", "--no-headers"].contains(&x.as_str()) || ["--request-timeout=", "--tail=", "--limit-bytes=", "--field-selector="].iter().any(|p| x.starts_with(p)), "{x}");
                }
            }
        }
    }

    #[test]
    fn limits() {
        let limits = HashMap::from([("b".to_string(), vec!["shop".to_string(), "team-*".to_string()])]);
        let ctxs = [("a".to_string(), "Alpha".to_string()), ("b".to_string(), "Beta".to_string())];
        let c = |v: Value, logs: bool| check(&v, &Allowed { ctxs: &ctxs, limits: &limits, logs });
        assert!(c(json!({"tool": "list", "kind": "pods"}), true).unwrap_err().contains("cluster"));
        assert!(c(json!({"tool": "list", "kind": "pods", "cluster": "Beta"}), true).unwrap_err().contains("namespace"));
        assert!(c(json!({"tool": "list", "kind": "pods", "cluster": "Beta", "ns": "other"}), true).is_err());
        assert!(c(json!({"tool": "list", "kind": "pods", "cluster": "Beta", "ns": "team-x"}), true).is_ok());
        assert!(c(json!({"tool": "list", "kind": "namespaces", "cluster": "Beta"}), true).is_err());
        assert!(c(json!({"tool": "list", "kind": "pods", "cluster": "a"}), true).is_ok());
        // Logs only where log lines may go.
        assert!(c(json!({"tool": "logs", "cluster": "a", "ns": "x", "pod": "y"}), false).is_err());
        assert!(!manual(false, &[]).contains("\"logs\"") && manual(true, &[]).contains("\"logs\""));
        assert!(manual(true, &["A".into(), "B".into()]).contains("A, B"));
    }

    #[test]
    fn what_is_asked() {
        let (rest, l) = asked("I'll check.\n```json\nLOOK {\"tool\":\"usage\"}\n```\n- LOOK: {\"tool\":\"events\",\"ns\":\"x\"}\n");
        assert_eq!((rest.as_str(), l.len(), l[1]["ns"].as_str()), ("I'll check.", 2, Some("x")));
        assert_eq!(asked("Look at the pod. LOOK at this {x}").1.len(), 0);
        assert_eq!(asked("LOOK {broken").1.len(), 0);
    }

    /// A stand-in for kubectl that says what it was run with.
    #[cfg(unix)]
    #[test]
    fn a_stand_in_kubectl() {
        use std::os::unix::fs::PermissionsExt;
        let p = std::env::temp_dir().join(format!("kubedog-kubectl-{}", std::process::id()));
        std::fs::write(&p, "#!/bin/sh\ncase \"$*\" in *logs*) echo 'ERROR made up';; *missing*) echo 'not found' >&2; exit 1;; *) echo '{\"items\":[{\"metadata\":{\"name\":\"made-up\"}}]}';; esac\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let k = Kubectl { bin: Some(p.clone()), kubeconfig: None, helm: None, cnpg: None, wsl: None };
        let l: Vec<Look> = [json!({"tool": "list", "kind": "pods"}), json!({"tool": "logs", "ns": "x", "pod": "y"}), json!({"tool": "show", "kind": "pod", "ns": "x", "name": "missing"})].into_iter().map(|v| one(v).unwrap()).collect();
        let v = run(&k, &l, &std::sync::atomic::AtomicBool::new(false));
        assert_eq!((v[0][0]["items"][0]["metadata"]["name"].as_str(), v[1][0].as_str(), v[2]["error"].as_str()), (Some("made-up"), Some("ERROR made up\n"), Some("not found")));
        assert_eq!(run(&k, &l, &std::sync::atomic::AtomicBool::new(true))[0], json!([]));
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn results_become_facts() {
        // Without a window; no cluster is asked.
        let app = KubedogApp::new(egui::Context::default(), Some("none".into()));
        let l: Vec<Look> = [
            json!({"tool": "list", "kind": "pods", "find": "web"}),
            json!({"tool": "show", "kind": "deployment", "ns": "x", "name": "web"}),
            json!({"tool": "logs", "ns": "x", "pod": "web-1"}),
        ].into_iter().map(|v| one(v).unwrap()).collect();
        let r = json!([
            [{"items": [{"metadata": {"name": "web-1", "namespace": "x"}, "status": {"phase": "Running"}}, {"metadata": {"name": "other", "namespace": "x"}, "status": {"phase": "Running"}}]}],
            [{"metadata": {"name": "web", "namespace": "x", "annotations": {"a": "hidden-annotation"}}, "spec": {"replicas": 1, "template": {"spec": {"containers": [{"name": "c", "image": "web:1", "env": [{"name": "E", "value": "hidden-value"}], "args": ["hidden-arg"]}]}}}}, {"items": []}],
            ["2026-01-01T00:00:00Z ERROR made up\n2026-01-01T00:00:01Z INFO fine"],
        ]);
        let f = app.look_facts(&l, &r);
        let state: String = f.list.iter().filter(|x| x.class == Class::State).map(|x| x.text.clone() + "\n").collect();
        assert!(state.contains("1 found") && state.contains("pod web-1") && !state.contains("other") && state.contains("image web:1"), "{state}");
        // Nothing of what it's set to, and no log lines, count as plain facts.
        assert!(!state.contains("hidden-value") && !state.contains("hidden-arg") && !state.contains("hidden-annotation") && !state.contains("ERROR made up"), "{state}");
        assert!(f.list.iter().any(|x| x.class == Class::Log && x.text.contains("ERROR made up")));
        assert_eq!(f.ctxs, vec!["a".to_string()]);
    }
}
