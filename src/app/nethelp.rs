//! Network Lab: helpers, for what can't be done from outside or with what a container has. Off for every
//! cluster until it's switched on for that one; then still behind the lock and a confirmation each time.
//! A helper carries a label of its own, ends by itself, and is removed; what's left is shown.

use super::face::many;
use super::nettry::Ran;
use super::ops::{ago, ns_of, obj, table, text, Item};
use super::pg::panel;
use super::podxray::Go;
use super::work::{name_of, said};
use super::*;

/// The label every helper has, and nothing else.
const LABEL: (&str, &str) = ("kubedog-helper", "netlab");
/// Used where nothing else is filled in and the cluster has no tools image: a fixed one that was tried.
const IMAGE: (&str, &str) = ("nicolaka/netshoot", "v0.13");

#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct Prefs {
    /// The clusters that may get helpers.
    pub on: Vec<String>,
    /// (image, tag) per cluster; under "": for all.
    pub images: HashMap<String, (String, String)>,
    /// Where helpers for nodes are made.
    pub ns: String,
}

impl Prefs {
    pub fn json(&self) -> Value {
        serde_json::json!({"on": self.on, "images": self.images, "ns": self.ns})
    }
    pub fn from_json(v: &Value) -> Prefs {
        Prefs {
            on: v["on"].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect(),
            images: v["images"].as_object().into_iter().flatten().map(|(k, x)| (k.clone(), (text(&x[0]), text(&x[1])))).collect(),
            ns: text(&v["ns"]),
        }
    }
    fn home(&self) -> String {
        if self.ns.is_empty() { "default".into() } else { self.ns.clone() }
    }
}

/// Only what an image's name may hold; never something that could be taken for an option.
pub(super) fn check_image(image: &str) -> Result<(), String> {
    let ok = !image.is_empty()
        && image.len() <= 255
        && image.as_bytes()[0].is_ascii_alphanumeric()
        && image.bytes().all(|b| b.is_ascii_alphanumeric() || b"./:_-".contains(&b))
        && !image.contains("//")
        && !image.contains("..")
        // After the last slash there's no colon: the tag has a field of its own.
        && !image.rsplit('/').next().unwrap_or("").contains(':');
    if ok { Ok(()) } else { Err("Write an image without its tag, like registry.example.com/tools/netshoot".into()) }
}

/// A tag, or a digest.
pub(super) fn check_tag(tag: &str) -> Result<(), String> {
    let t = tag.trim_start_matches('@');
    let digest = t.strip_prefix("sha256:").map(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()));
    let plain = !tag.starts_with('@') && !t.is_empty() && t.len() <= 128 && !t.starts_with(['.', '-']) && t.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if digest.unwrap_or(plain) { Ok(()) } else { Err("Write a tag like v1.2, or a digest like sha256:…".into()) }
}

/// The full name.
fn full(image: &str, tag: &str) -> Result<String, String> {
    check_image(image)?;
    check_tag(tag)?;
    let t = tag.trim_start_matches('@');
    Ok(if t.starts_with("sha256:") { format!("{image}@{t}") } else { format!("{image}:{t}") })
}

/// A full name that the cluster gave.
fn check_full(s: &str) -> Result<String, String> {
    match s.split_once('@') {
        Some((i, d)) => full(i.rsplit_once('/').filter(|(_, l)| l.contains(':')).map(|_| i.rsplit_once(':').unwrap().0).unwrap_or(i), d),
        None => {
            let (i, t) = s.rsplit_once(':').ok_or("no tag")?;
            full(i, t)
        }
    }
}

fn label_json() -> Value {
    let mut m = serde_json::Map::new();
    m.insert(LABEL.0.into(), LABEL.1.into());
    Value::Object(m)
}

/// A new name; names only have to differ.
pub(super) fn new_name(what: &str) -> String {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    format!("kubedog-{what}-{:x}", (t / 1000) & 0xff_ffff_ffff)
}

/// What kind of pod is made.
#[derive(Clone, PartialEq, Debug)]
pub(super) enum Make {
    /// On a node, with all its rights: for captures.
    Node(String),
    /// On a node's network, without rights.
    NodeNet(String),
    /// In a namespace, as any pod there.
    Plain,
}

/// The pod, as JSON: our label only, no token, a time limit, small.
pub(super) fn pod_json(name: &str, ns: &str, image: &str, make: &Make, secs: u64, openshift: bool) -> Value {
    let mut sec = serde_json::json!({"allowPrivilegeEscalation": false, "runAsNonRoot": true, "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}});
    // OpenShift gives a user by itself.
    if !openshift {
        sec["runAsUser"] = 65534.into();
    }
    if matches!(make, Make::Node(_)) {
        sec = serde_json::json!({"privileged": true, "runAsUser": 0});
    }
    let mut spec = serde_json::json!({
        "restartPolicy": "Never",
        "activeDeadlineSeconds": secs + 120,
        "automountServiceAccountToken": false,
        "enableServiceLinks": false,
        "terminationGracePeriodSeconds": 0,
        "containers": [{
            "name": "tools", "image": image, "command": ["sleep", (secs + 110).to_string()], "securityContext": sec,
            "resources": {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"cpu": "500m", "memory": "128Mi"}},
        }],
    });
    match make {
        Make::Node(n) => {
            spec["nodeName"] = n.as_str().into();
            spec["hostPID"] = true.into();
            spec["hostNetwork"] = true.into();
            spec["tolerations"] = serde_json::json!([{"operator": "Exists"}]);
        }
        Make::NodeNet(n) => {
            spec["nodeName"] = n.as_str().into();
            spec["hostNetwork"] = true.into();
            spec["dnsPolicy"] = "ClusterFirstWithHostNet".into();
            spec["tolerations"] = serde_json::json!([{"operator": "Exists"}]);
        }
        Make::Plain => {}
    }
    serde_json::json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": ns, "labels": label_json()}, "spec": spec})
}

fn strs(l: &[&str]) -> Vec<String> {
    l.iter().map(|s| s.to_string()).collect()
}

/// Makes a pod, runs a command in it, and removes the pod whatever came of it.
pub(super) fn run_in_pod(k: &Kubectl, ctx: &str, ns: &str, name: &str, manifest: &Value, command: &[String], secs: u64) -> Result<String, String> {
    k.run_with_input(&strs(&["--context", ctx, "create", "-f", "-"]), &manifest.to_string())?;
    let r = k
        .run(&strs(&["--context", ctx, "-n", ns, "wait", "--for=condition=Ready", &format!("pod/{name}"), "--timeout=90s"]))
        .map_err(|e| {
            // Why it didn't start says more.
            let why = k.run(&strs(&["--context", ctx, "-n", ns, "get", "pod", name, "-o", "json", "--request-timeout=15s"])).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).map(|p| {
                let w = &p["status"]["containerStatuses"][0]["state"]["waiting"];
                format!("{} {}", text(&w["reason"]), text(&w["message"])).trim().to_string()
            });
            match why.filter(|w| !w.is_empty()) {
                Some(w) => format!("the helper didn't start: {}", truncate(&w, 200)),
                None => format!("the helper didn't start: {}", truncate(&e, 200)),
            }
        })
        .and_then(|_| {
            let mut a = strs(&["--context", ctx, "-n", ns, "exec", name, "-c", "tools", "--"]);
            a.extend(command.iter().cloned());
            k.run_for(&a, Duration::from_secs(secs + 30))
        });
    let gone = k.run(&strs(&["--context", ctx, "-n", ns, "delete", "pod", name, "--wait=false", "--ignore-not-found"]));
    match (r, gone) {
        (Err(e), _) => Err(e),
        (Ok(o), _) => Ok(o),
    }
}

/// A container in a pod that runs, on the pod's own network, and what it said. It stays listed in the pod.
pub(super) fn run_beside(k: &Kubectl, ctx: &str, ns: &str, pod: &str, user: Option<i64>, image: &str, command: &[String]) -> Result<String, String> {
    let name = new_name("test");
    let spec = serde_json::json!({"securityContext": {"allowPrivilegeEscalation": false, "runAsNonRoot": true, "runAsUser": user.filter(|u| *u > 0).unwrap_or(65534), "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}});
    // kubectl takes this only as a file; it says nothing secret.
    let file = std::env::temp_dir().join(format!("{name}.json"));
    std::fs::write(&file, spec.to_string()).map_err(|e| e.to_string())?;
    let mut a = strs(&["--context", ctx, "-n", ns, "debug", pod, &format!("--image={image}"), &format!("--container={name}"), "--profile=restricted", "--attach=false", "--quiet", &format!("--custom={}", file.display()), "--"]);
    a.extend(command.iter().cloned());
    let r = k.run(&a);
    let _ = std::fs::remove_file(&file);
    r?;
    let began = Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(700));
        let p: Value = k.run(&strs(&["--context", ctx, "-n", ns, "get", "pod", pod, "-o", "json", "--request-timeout=15s"])).and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))?;
        let st = p["status"]["ephemeralContainerStatuses"].as_array().into_iter().flatten().find(|c| c["name"] == name.as_str()).map(|c| c["state"].clone()).unwrap_or_default();
        if st["terminated"].is_object() {
            return k.run(&strs(&["--context", ctx, "-n", ns, "logs", pod, "-c", &name, "--request-timeout=20s"]));
        }
        let late = began.elapsed() > Duration::from_secs(100);
        let w = &st["waiting"];
        let stuck = matches!(w["reason"].as_str(), Some("ErrImagePull" | "ImagePullBackOff" | "CreateContainerConfigError" | "CreateContainerError" | "InvalidImageName"));
        if stuck || late {
            return Err(format!("the helper didn't start: {}", truncate(format!("{} {}", text(&w["reason"]), text(&w["message"])).trim(), 200)));
        }
    }
}

impl KubedogApp {
    pub(super) fn helpers_on(&self, ctx: &str) -> bool {
        self.prefs.netlab.on.iter().any(|c| c == ctx)
    }

    pub(super) fn is_openshift(&self, ctx: &str) -> bool {
        self.lists.get(&Self::list_key(ctx, Kind::CustomResourceDefinitions)).map(|l| l.items.iter().any(|o| o["metadata"]["name"] == "clusterversions.config.openshift.io")).unwrap_or(false)
    }

    /// The cluster's own tools image, on OpenShift.
    pub(super) fn ask_tools(&mut self) {
        for c in self.active.clone() {
            if self.helpers_on(&c) && self.is_openshift(&c) {
                let a = strs(&["--context", &c, "-n", "openshift", "get", "imagestreamtags.image.openshift.io", "tools:latest", "-o", "json", "--request-timeout=15s"]);
                self.ask(&format!("nettools|{c}"), 3600, false, move |k| {
                    let v: Value = serde_json::from_str(&k.run(&a)?).map_err(|e| e.to_string())?;
                    Ok(Value::String(text(&v["image"]["dockerImageReference"])).to_string())
                });
            }
        }
    }

    /// The image a helper in this cluster runs: filled in for it, for all, the cluster's own, or ours.
    pub(super) fn helper_image(&self, ctx: &str) -> Result<String, String> {
        for k in [ctx, ""] {
            if let Some((i, t)) = self.prefs.netlab.images.get(k).filter(|x| !x.0.is_empty()) {
                return full(i, if t.is_empty() && i == IMAGE.0 { IMAGE.1 } else { t }).map_err(|e| format!("The image in Settings: {e}"));
            }
        }
        if self.is_openshift(ctx) {
            return match self.answer(&format!("nettools|{ctx}")) {
                Some(Ok(v)) => check_full(v.as_str().unwrap_or("")).map_err(|_| "The cluster's own tools image isn't known: fill in an image in Settings > Superpowers > Network Lab.".into()),
                Some(Err(_)) => Err("The cluster's own tools image can't be read: fill in an image in Settings > Superpowers > Network Lab.".into()),
                None => Err("Still looking for the cluster's own tools image.".into()),
            };
        }
        full(IMAGE.0, IMAGE.1)
    }

    /// Why a helper can't be used here, or the image it would run.
    pub(super) fn helper_ready(&self, ctx: &str) -> Result<String, String> {
        if !self.helpers_on(ctx) {
            return Err("Helpers are off for this cluster: switch them on in Settings > Superpowers > Network Lab.".into());
        }
        self.helper_image(ctx)
    }

    pub(super) fn note_run(&mut self, ctx: &str, what: String, place: String) {
        self.netlab.tries.ran.push(Ran { at: kube::now_secs(), ctx: ctx.into(), what, place });
    }

    /// Helpers that are still there.
    pub(super) fn leftovers(&mut self, ui: &mut Ui) -> Option<Go> {
        let now = kube::now_secs();
        let mut l: Vec<Item> = vec![];
        let mut first: Option<Selected> = None;
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            for p in self.refs(c, Kind::Pods, "").unwrap_or_default().into_iter().filter(|p| p["metadata"]["labels"][LABEL.0] == LABEL.1) {
                let over = matches!(p["status"]["phase"].as_str(), Some("Succeeded" | "Failed"));
                l.push(Item::new(if over { Tone::Muted } else { Tone::Warning }, vec![format!("{}/{}", ns_of(p), name_of(p)), if over { "ended, still listed".into() } else { "runs; it ends by itself".into() }, text(&p["spec"]["nodeName"]), ago(now, pod::time_of(&p["metadata"]["creationTimestamp"])), ctx_label(c)]).go(Some(obj(c, Kind::Pods, ns_of(p), name_of(p)))));
                first = first.or(Some(Selected { ctx: c.clone(), kind: Kind::Pods, ns: ns_of(p).into(), name: name_of(p).into() }));
            }
        }
        let s = first?;
        let go = table(ui, &format!("Helpers that are still there ({})", l.len()), "", &[("Pod", 0.36), ("State", 0.2), ("Node", 0.18), ("Made", 0.12), ("Cluster", 0.14)], &l, 20, "");
        if button(ui, &if l.len() == 1 { "Remove it".to_string() } else { format!("Remove {}", s.name) }, false, false) && self.screenshot.is_none() {
            let body = format!("Remove the helper “{}” in namespace “{}”?", s.name, s.ns);
            self.request(Action::Delete(s, false, false), "Remove helper".into(), body, "Remove", true);
        }
        ui.add_space(10.0);
        go
    }

    /// Settings > Superpowers > Network Lab.
    pub(super) fn settings_netlab(&mut self, ui: &mut Ui) {
        said(ui, "The overview, tests from this computer and paths need nothing. Some tests need a helper in the cluster: a small pod or container with network tools, made after you confirm, that ends by itself. Kubedog doesn't know which cluster is production, so helpers are off until you switch them on for a cluster.", TEXT_SUBTLE());
        ui.add_space(8.0);
        let mut changed = false;
        let mut names: Vec<String> = self.active.clone();
        for c in &self.prefs.netlab.on {
            if !names.contains(c) {
                names.push(c.clone());
            }
        }
        card(ui, |ui| {
            panel(ui, "Helpers may be used in", if names.is_empty() { "open a cluster to see it here" } else { "the lock and a confirmation come on top, each time" });
            for c in &names {
                let mut on = self.prefs.netlab.on.contains(c);
                if ui.checkbox(&mut on, ctx_label(c)).changed() {
                    self.prefs.netlab.on.retain(|x| x != c);
                    if on {
                        self.prefs.netlab.on.push(c.clone());
                    }
                    changed = true;
                }
            }
        });
        ui.add_space(8.0);
        let mut errors: Vec<String> = vec![];
        card(ui, |ui| {
            panel(ui, "Image", "empty: the cluster's own tools on OpenShift, elsewhere nicolaka/netshoot");
            let rows: Vec<(String, String)> = std::iter::once((String::new(), "All clusters".to_string())).chain(names.iter().filter(|c| self.prefs.netlab.on.contains(c)).map(|c| (c.clone(), ctx_label(c)))).collect();
            for (key, label) in rows {
                ui.horizontal(|ui| {
                    ui.allocate_ui_with_layout(egui::vec2(u(150.0), u(26.0)), Layout::left_to_right(Align::Center), |ui| {
                        ui.set_min_width(u(150.0));
                        ui.add(egui::Label::new(RichText::new(&label).size(z(13.0)).color(TEXT_MUTED())).truncate());
                    });
                    let mut v = self.prefs.netlab.images.get(&key).cloned().unwrap_or_default();
                    let a = ui.add(egui::TextEdit::singleline(&mut v.0).hint_text("image").desired_width(u(330.0)));
                    let b = ui.add(egui::TextEdit::singleline(&mut v.1).hint_text("tag or sha256:…").desired_width(u(170.0)));
                    if a.changed() || b.changed() {
                        v = (v.0.trim().to_string(), v.1.trim().to_string());
                        if v.0.is_empty() && v.1.is_empty() {
                            self.prefs.netlab.images.remove(&key);
                        } else {
                            self.prefs.netlab.images.insert(key.clone(), v.clone());
                        }
                    }
                    changed |= a.lost_focus() || b.lost_focus();
                    if !v.0.is_empty() {
                        if let Err(e) = check_image(&v.0).and_then(|_| if v.1.is_empty() && v.0 == IMAGE.0 { Ok(()) } else { check_tag(&v.1) }) {
                            errors.push(format!("{label}: {e}"));
                        } else if v.1 == "latest" {
                            errors.push(format!("{label}: “latest” can be another image tomorrow. A fixed tag or a digest is safer."));
                        }
                    }
                });
            }
            for e in &errors {
                said(ui, e, WARNING());
            }
            for c in names.iter().filter(|c| self.prefs.netlab.on.contains(c)) {
                said(ui, &match self.helper_image(c) { Ok(i) => format!("{}: uses {i}", ctx_label(c)), Err(e) => format!("{}: {e}", ctx_label(c)) }, TEXT_PLACEHOLDER());
            }
            said(ui, "The cluster pulls it, with its own rights; Kubedog doesn't. The confirmation names it each time.", TEXT_PLACEHOLDER());
        });
        ui.add_space(8.0);
        card(ui, |ui| {
            panel(ui, "Namespace for helpers on a node", "empty: default");
            let r = ui.add(egui::TextEdit::singleline(&mut self.prefs.netlab.ns).hint_text("default").desired_width(u(220.0)));
            if r.changed() {
                self.prefs.netlab.ns.retain(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
            }
            changed |= r.lost_focus();
        });
        if changed {
            self.save();
            self.ask_tools();
        }
    }

    pub(super) fn helper_home(&self) -> String {
        self.prefs.netlab.home()
    }
}

/// What a helper is made of, in a sentence for the confirmation.
pub(super) fn in_words(make: &Make, image: &str, secs: u64, ns: &str, control: bool) -> String {
    let t = many((secs + 120) as i64, "second");
    match make {
        Make::Node(n) => format!("This makes a pod with all rights on node “{n}” (privileged, the node's network and processes) in namespace “{ns}”, from image {image}. It's removed afterwards, and ends by itself after {t}.{}", if control { " This is a control plane node." } else { "" }),
        Make::NodeNet(n) => format!("This makes a pod on the network of node “{n}”, without rights, in namespace “{ns}”, from image {image}. It's removed afterwards, and ends by itself after {t}.{}", if control { " This is a control plane node." } else { "" }),
        Make::Plain => format!("This makes a pod in namespace “{ns}”, without rights and without an app's labels, from image {image}. It's removed afterwards, and ends by itself after {t}."),
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    #[test]
    fn images() {
        assert_eq!(full("nicolaka/netshoot", "v0.13").unwrap(), "nicolaka/netshoot:v0.13");
        let d = format!("sha256:{}", "a".repeat(64));
        assert_eq!(full("registry.example.com:5000/tools/net", &d).unwrap(), format!("registry.example.com:5000/tools/net@{d}"));
        assert_eq!(full("x", &format!("@{d}")).unwrap(), format!("x@{d}"));
        for (i, t) in [("", "v1"), ("--image=x", "v1"), ("a b", "v1"), ("x:v1", "v2"), ("x;rm", "v1"), ("x\n", "v1"), ("../x", "v1"), ("x//y", "v1"), ("x", ""), ("x", "-v1"), ("x", "v 1"), ("x", "sha256:abc"), ("x", "@v1"), ("x", "v1,y"), ("x$(id)", "v1")] {
            assert!(full(i, t).is_err(), "{i} {t}");
        }
        assert!(check_full(&format!("quay.io/okd/content@{d}")).is_ok());
        assert!(check_full("registry.example.com:5000/a/b:v1").is_ok());
        assert!(check_full("--x@y").is_err() && check_full("").is_err());
    }

    #[test]
    fn what_is_made() {
        for make in [Make::Node("worker-1".into()), Make::NodeNet("worker-1".into()), Make::Plain] {
            for os in [true, false] {
                let p = pod_json("n", "ns", "img:1", &make, 30, os);
                // Our label only, no token, and an end of its own.
                assert_eq!(p["metadata"]["labels"], serde_json::json!({"kubedog-helper": "netlab"}));
                assert_eq!(p["spec"]["automountServiceAccountToken"], false);
                assert_eq!(p["spec"]["activeDeadlineSeconds"], 150);
                assert_eq!(p["spec"]["containers"][0]["command"], serde_json::json!(["sleep", "140"]));
                assert_eq!(p["spec"]["restartPolicy"], "Never");
                let s = &p["spec"]["containers"][0]["securityContext"];
                // Rights only for captures.
                assert_eq!(s["privileged"] == true, matches!(make, Make::Node(_)));
                assert_eq!(p["spec"]["hostPID"] == true, matches!(make, Make::Node(_)));
                assert_eq!(p["spec"]["hostNetwork"] == true, make != Make::Plain);
                assert_eq!(p["spec"]["nodeName"].is_string(), make != Make::Plain);
                if make == Make::Plain {
                    assert_eq!(s["runAsUser"].is_null(), os);
                    assert_eq!(s["capabilities"]["drop"][0], "ALL");
                }
            }
        }
        assert!(in_words(&Make::Node("m".into()), "i:1", 30, "default", true).contains("control plane"));
        assert!(new_name("x").starts_with("kubedog-x-"));
    }

    #[test]
    fn kept() {
        let p = Prefs { on: vec!["a".into()], images: [("a".to_string(), ("x".to_string(), "v1".to_string()))].into(), ns: "tools".into() };
        assert_eq!(Prefs::from_json(&p.json()), p);
        assert_eq!(Prefs::from_json(&Value::Null), Prefs::default());
        // Nothing is on by itself.
        assert!(Prefs::default().on.is_empty());
        assert_eq!(Prefs::default().home(), "default");
    }

    /// The throwaway cluster, and nothing else.
    pub(in crate::app) fn kind() -> Kubectl {
        let k = Kubectl { kubeconfig: Some(std::env::var("KUBEDOG_KIND").unwrap()), ..Kubectl::detect() };
        let server = k.run(&strs(&["--context", "kind-kubedog-netlab", "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}"])).unwrap();
        assert!(server.starts_with("https://127.0.0.1:"), "{server}");
        k
    }
}
