//! External Secrets (with Vault) and cert-manager: from store to secret to app, and certificates with
//! what's stuck. Values of secrets are never read here.

use super::face::{many, Side};
use super::ops::{ago, ns_of, obj, summary, table, text, worst_first, Item};
use super::pg::{label_at, panel};
use super::podxray::Go;
use super::work::name_of;
use super::*;

const ES: &str = "externalsecrets.external-secrets.io";
const STORES: [&str; 2] = ["secretstores.external-secrets.io", "clustersecretstores.external-secrets.io"];
const CERTS: &str = "certificates.cert-manager.io";

/// "1h30m", "90s", "0" as seconds.
pub(super) fn seconds(t: &str) -> Option<i64> {
    let mut total = 0f64;
    let mut num = String::new();
    let mut unit = String::new();
    let add = |n: &str, u: &str| -> Option<f64> {
        let n: f64 = n.parse().ok()?;
        Some(n * match u { "ms" => 0.001, "s" | "" => 1.0, "m" => 60.0, "h" => 3600.0, "d" => 86400.0, _ => return None })
    };
    for c in t.trim().chars() {
        if c.is_ascii_digit() || c == '.' {
            if !unit.is_empty() {
                total += add(&num, &unit)?;
                num.clear();
                unit.clear();
            }
            num.push(c);
        } else {
            unit.push(c);
        }
    }
    total += add(&num, &unit)?;
    Some(total as i64)
}

/// How an external secret is: (tone, word, why).
fn es_state(o: &Value, now: i64) -> (Tone, String, String) {
    let Some(c) = pod::cond(o, "Ready") else { return (Tone::Warning, "Not synced yet".into(), String::new()) };
    let msg = truncate(c["message"].as_str().unwrap_or(""), 300);
    if c["status"] != "True" {
        return (Tone::Danger, face::spaced(c["reason"].as_str().unwrap_or("Not ready")), msg);
    }
    let every = seconds(o["spec"]["refreshInterval"].as_str().unwrap_or("1h")).unwrap_or(3600);
    let last = pod::time_of(&o["status"]["refreshTime"]);
    match last {
        // Once a minute is checked now and then; give it time.
        Some(t) if every > 0 && now - t > every * 2 + 300 => (Tone::Warning, "Late".into(), format!("last synced {} ago, it should be every {}", kube::human_duration(now - t), kube::human_duration(every))),
        _ => (Tone::Success, "Synced".into(), String::new()),
    }
}

/// A certificate's state: (tone, word, why).
pub(super) fn cert_state(o: &Value, now: i64) -> (Tone, String, String) {
    let st = &o["status"];
    let end = pod::time_of(&st["notAfter"]);
    let ready = pod::cond(o, "Ready");
    let msg = ready.map(|c| truncate(c["message"].as_str().unwrap_or(""), 300)).unwrap_or_default();
    let issuing = pod::cond(o, "Issuing").map(|c| c["status"] == "True").unwrap_or(false);
    let tries = st["failedIssuanceAttempts"].as_i64().unwrap_or(0);
    let why = |m: String| if tries > 0 { format!("{m}{}{} failed", if m.is_empty() { "" } else { "; " }, many(tries, "try").replace("trys", "tries")) } else { m };
    if end.map(|t| t < now).unwrap_or(false) {
        return (Tone::Danger, "Expired".into(), why(msg));
    }
    if ready.map(|c| c["status"] == "True").unwrap_or(false) {
        let late = pod::time_of(&st["renewalTime"]).map(|t| now - t > 6 * 3600).unwrap_or(false);
        if late {
            return (Tone::Warning, "Renewal overdue".into(), why(format!("should have been renewed {}", ago(now, pod::time_of(&st["renewalTime"])))));
        }
        if tries > 0 {
            return (Tone::Warning, "Renewal failing".into(), why(String::new()));
        }
        return (Tone::Success, "Ready".into(), String::new());
    }
    if issuing && tries == 0 {
        return (Tone::Info, "Being issued".into(), msg);
    }
    (if end.is_none() { Tone::Danger } else { Tone::Warning }, "Not ready".into(), why(msg))
}

impl KubedogApp {
    /// What uses each secret of the shown namespaces: (cluster, namespace, secret) -> workloads.
    fn secret_users(&self) -> HashMap<(String, String, String), Vec<(Kind, String)>> {
        let mut m: HashMap<(String, String, String), Vec<(Kind, String)>> = HashMap::new();
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            for k in [Kind::Deployments, Kind::StatefulSets, Kind::DaemonSets, Kind::CronJobs] {
                for w in self.refs(c, k, "").unwrap_or_default() {
                    for (uk, n) in workload::uses_of(workload::pod_spec(k, w)) {
                        if uk == Kind::Secrets {
                            m.entry((c.clone(), ns_of(w).to_string(), n)).or_default().push((k, name_of(w).to_string()));
                        }
                    }
                }
            }
        }
        m
    }

    pub(super) fn secrets_page(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        let now = kube::now_secs();
        let users = self.secret_users();
        let items: Vec<Item> = self
            .op_items(ES)
            .into_iter()
            .map(|(c, o)| {
                let (t, w, why) = es_state(o, now);
                let target = o["spec"]["target"]["name"].as_str().filter(|n| !n.is_empty()).unwrap_or(name_of(o)).to_string();
                let used = users.get(&(c.to_string(), ns_of(o).to_string(), target.clone())).cloned().unwrap_or_default();
                let names: Vec<String> = used.iter().map(|u| u.1.clone()).collect();
                let keys = o["spec"]["data"].as_array().map(|a| a.len()).unwrap_or(0) + o["spec"]["dataFrom"].as_array().map(|a| a.len()).unwrap_or(0);
                Item::new(t, vec![self.full_name(c, o), w, why.clone(), text(&o["spec"]["secretStoreRef"]["name"]), target, if names.is_empty() { "-".into() } else { some_names(&names) }, ago(now, pod::time_of(&o["status"]["refreshTime"]))])
                    .tip(format!("{}\n{}\n{why}\nused by: {}", self.full_name(c, o), many(keys as i64, "value"), if names.is_empty() { "nothing found".into() } else { names.join(", ") }))
                    .go(self.custom_go(c, ES, o))
            })
            .collect();
        // Stores.
        let mut stores: Vec<Item> = vec![];
        for key in STORES {
            for (c, o) in self.op_items(key) {
                let v = face::generic(o);
                let provider = o["spec"]["provider"].as_object().and_then(|m| m.keys().next().cloned()).unwrap_or_default();
                let whole = key.starts_with("cluster");
                let n = self.op_all(c, ES).iter().filter(|e| e["spec"]["secretStoreRef"]["name"].as_str() == Some(name_of(o)) && (whole == (e["spec"]["secretStoreRef"]["kind"] == "ClusterSecretStore")) && (whole || ns_of(e) == ns_of(o))).count();
                // Only where it is; how it logs in isn't shown.
                let server = text(&o["spec"]["provider"][provider.as_str()]["server"]);
                stores.push(Item::new(v.0, vec![self.full_name(c, o), v.1, provider, server, many(n as i64, "secret")]).tip(v.2.join("\n")).go(self.custom_go(c, key, o)));
            }
        }
        // Vault's own pods say whether they're sealed.
        let mut vaults: Vec<Item> = vec![];
        for c in self.active.iter().filter(|c| self.ctx_shown(c)) {
            for p in self.refs(c, Kind::Pods, "").unwrap_or_default() {
                let l = &p["metadata"]["labels"];
                let Some(sealed) = l["vault-sealed"].as_str() else { continue };
                let (t, w) = match (sealed, l["vault-initialized"].as_str(), l["vault-active"].as_str()) {
                    ("true", _, _) => (Tone::Danger, "Sealed: it answers nothing until it's unsealed"),
                    (_, Some("false"), _) => (Tone::Danger, "Not initialised"),
                    (_, _, Some("true")) => (Tone::Success, "Unsealed, active"),
                    _ => (Tone::Success, "Unsealed, standby"),
                };
                vaults.push(Item::new(t, vec![self.full_name(c, p), w.into(), text(&l["vault-version"]), text(&p["spec"]["nodeName"])]).go(Some(obj(c, Kind::Pods, ns_of(p), name_of(p)))));
            }
        }
        let mut f = summary(&items, "external secret");
        let bad = stores.iter().filter(|s| s.bad()).count();
        if bad > 0 {
            f.notes.push(format!("{} not ready: what they feed isn't renewed.", many(bad as i64, "store")));
            f.tone = Tone::Danger;
        }
        if vaults.iter().any(|v| v.tone == Tone::Danger) {
            f.notes.push("A Vault pod is sealed.".into());
            f.tone = Tone::Danger;
        }
        face::show(ui, &f, Side::None);
        ui.add_space(10.0);
        self.bad_switch(ui);
        if !vaults.is_empty() {
            let mut v = self.op_filter(vaults);
            worst_first(&mut v);
            go = table(ui, "Vault", "from what its pods say about themselves", &[("Pod", 0.35), ("State", 0.35), ("Version", 0.15), ("Node", 0.15)], &v, 20, "Nothing here.").or(go);
        }
        let mut stores = self.op_filter(stores);
        worst_first(&mut stores);
        go = table(ui, &format!("Stores ({})", stores.len()), "where values come from", &[("Store", 0.28), ("State", 0.16), ("Kind", 0.12), ("Server", 0.3), ("Feeds", 0.14)], &stores, 40, "None.").or(go);
        let mut items = self.op_filter(items);
        worst_first(&mut items);
        let none = self.op_missing(ES).unwrap_or("None.".into());
        go = table(ui, &format!("External secrets ({})", items.len()), "store → secret → what uses it", &[("External secret", 0.24), ("State", 0.1), ("Why", 0.2), ("Store", 0.12), ("Secret", 0.16), ("Used by", 0.12), ("Synced", 0.06)], &items, 200, &none).or(go);
        go
    }

    pub(super) fn certs_page(&mut self, ui: &mut Ui) -> Option<Go> {
        let mut go = None;
        let now = kube::now_secs();
        let mut rows: Vec<(i64, i64, Item)> = vec![];
        for (c, o) in self.op_items(CERTS) {
            let (t, w, why) = cert_state(o, now);
            let (a, b) = (pod::time_of(&o["status"]["notBefore"]).unwrap_or(0), pod::time_of(&o["status"]["notAfter"]).unwrap_or(i64::MAX));
            let names: Vec<String> = o["spec"]["dnsNames"].as_array().into_iter().flatten().map(text).collect();
            let issuer = &o["spec"]["issuerRef"];
            let left = if b == i64::MAX { "-".to_string() } else if b < now { "expired".into() } else { format!("{} days", (b - now) / 86400) };
            rows.push((a, b, Item::new(t, vec![self.full_name(c, o), w, why, some_names(&names), text(&issuer["name"]), left, ago(now, pod::time_of(&o["status"]["renewalTime"]))]).go(self.custom_go(c, CERTS, o))));
        }
        let all: Vec<Item> = rows.iter().map(|r| Item::new(r.2.tone, r.2.cells.clone())).collect();
        let mut f = summary(&all, "certificate");
        if let Some(r) = rows.iter().filter(|r| r.1 != i64::MAX && r.1 > now).min_by_key(|r| r.1) {
            f.sub = format!("{}; the next to expire in {} days", f.sub, (r.1 - now) / 86400);
        }
        face::show(ui, &f, Side::None);
        ui.add_space(10.0);
        self.bad_switch(ui);
        // The soonest, as bars.
        let mut soon: Vec<&(i64, i64, Item)> = rows.iter().filter(|r| r.0 > 0 && r.1 != i64::MAX && r.1 > r.0).collect();
        soon.sort_by_key(|r| r.1);
        soon.truncate(8);
        if !soon.is_empty() {
            card(ui, |ui| {
                panel(ui, "Next to expire", "from issued to expiry; the line is now");
                ui.spacing_mut().item_spacing.y = 0.0;
                for (a, b, it) in soon {
                    let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), u(26.0)), Sense::hover());
                    label_at(ui, ui.painter(), r.left_center(), &it.cells[0], 12.5, TEXT_DEFAULT(), r.width() * 0.3);
                    let bar = egui::Rect::from_min_max(egui::pos2(r.left() + r.width() * 0.32, r.center().y - 5.0), egui::pos2(r.right() - u(90.0), r.center().y + 5.0));
                    let share = ((now - a) as f32 / (b - a) as f32).clamp(0.0, 1.0);
                    let col = if (b - now) < 7 * 86400 { DANGER() } else if share > 0.8 { WARNING() } else { SUCCESS() };
                    ui.painter().rect_filled(bar, CornerRadius::same(5), BG_MUTED());
                    ui.painter().rect_filled(egui::Rect::from_min_max(bar.min, egui::pos2(bar.left() + bar.width() * share, bar.bottom())), CornerRadius::same(5), col.gamma_multiply(0.7));
                    ui.painter().vline(bar.left() + bar.width() * share, (bar.top() - 4.0)..=(bar.bottom() + 4.0), Stroke::new(1.5, TEXT_DEFAULT()));
                    ui.painter().text(r.right_center(), egui::Align2::RIGHT_CENTER, &it.cells[5], FontId::proportional(z(12.0)), col);
                }
            });
            ui.add_space(12.0);
        }
        let mut items = self.op_filter(rows.into_iter().map(|r| r.2).collect());
        worst_first(&mut items);
        let none = self.op_missing(CERTS).unwrap_or("None.".into());
        go = table(ui, &format!("Certificates ({})", items.len()), "", &[("Certificate", 0.25), ("State", 0.1), ("Why", 0.2), ("Names", 0.2), ("Issuer", 0.1), ("Left", 0.07), ("Renews", 0.08)], &items, 200, &none).or(go);
        let mut issuers: Vec<Item> = vec![];
        for key in ["issuers.cert-manager.io", "clusterissuers.cert-manager.io"] {
            for (c, o) in self.op_items(key) {
                let v = face::generic(o);
                let how = ["acme", "ca", "selfSigned", "vault", "venafi"].iter().find(|k| !o["spec"][**k].is_null()).copied().unwrap_or("other");
                let why = pod::cond(o, "Ready").map(|c| truncate(c["message"].as_str().unwrap_or(""), 200)).unwrap_or_default();
                issuers.push(Item::new(v.0, vec![self.full_name(c, o), v.1, how.into(), text(&o["spec"]["acme"]["server"]), why]).go(self.custom_go(c, key, o)));
            }
        }
        worst_first(&mut issuers);
        go = table(ui, &format!("Issuers ({})", issuers.len()), "", &[("Issuer", 0.25), ("State", 0.12), ("Kind", 0.1), ("Server", 0.28), ("Message", 0.25)], &issuers, 40, "None.").or(go);
        // What's under way: many objects, so only when asked.
        if !self.powers.slow {
            if button(ui, "Show requests, orders and challenges that aren't done", false, false) {
                self.powers.slow = true;
                self.refresh_op(true);
            }
        } else {
            let mut stuck: Vec<Item> = vec![];
            for key in ["certificaterequests.cert-manager.io", "orders.acme.cert-manager.io", "challenges.acme.cert-manager.io"] {
                for (c, o) in self.op_items(key) {
                    let st = &o["status"];
                    let state = text(&st["state"]);
                    let ready = pod::cond(o, "Ready");
                    let done = state == "valid" || ready.map(|c| c["status"] == "True").unwrap_or(false);
                    if done {
                        continue;
                    }
                    let failed = matches!(state.as_str(), "invalid" | "errored" | "expired") || ready.map(|c| c["reason"] == "Failed" || c["reason"] == "Denied").unwrap_or(false);
                    let why = st["reason"].as_str().map(String::from).or_else(|| ready.and_then(|c| c["message"].as_str().map(String::from))).unwrap_or_default();
                    stuck.push(Item::new(if failed { Tone::Danger } else { Tone::Info }, vec![self.full_name(c, o), if state.is_empty() { ready.map(|c| text(&c["reason"])).unwrap_or("pending".into()) } else { state }, key.split('.').next().unwrap_or("").into(), truncate(&why, 300), kube::age(o["metadata"]["creationTimestamp"].as_str().unwrap_or(""))]).go(self.custom_go(c, key, o)));
                }
            }
            worst_first(&mut stuck);
            go = table(ui, &format!("Not done ({})", stuck.len()), "", &[("Name", 0.3), ("State", 0.1), ("Kind", 0.14), ("Why", 0.38), ("Age", 0.08)], &stuck, 60, "Nothing is under way.").or(go);
        }
        go
    }

    /// Buttons for kinds Kubedog knows, on a custom object's page. (Right to left.)
    pub(super) fn custom_actions(&mut self, ui: &mut Ui, key: &str, s: &crds::CustomSel, o: &Value) {
        let sel = || Selected { ctx: s.ctx.clone(), kind: Kind::Pods, ns: s.ns.clone(), name: s.name.clone() };
        match key {
            ES => {
                if button(ui, "Sync now", false, false) {
                    self.request(Action::Run { sel: sel(), args: annotate_args(s, key, &format!("force-sync={}", kube::now_secs())), what: format!("{} is synced again", s.name) }, "Sync now".into(), format!("Ask External Secrets to read “{}” from its store again? It sets an annotation.", s.name), "Sync", false);
                }
            }
            "scaledobjects.keda.sh" => {
                let paused = o["metadata"]["annotations"]["autoscaling.keda.sh/paused"] == "true" || !o["metadata"]["annotations"]["autoscaling.keda.sh/paused-replicas"].is_null();
                if paused {
                    if button(ui, "Resume scaling", false, false) {
                        let mut a = annotate_args(s, key, "autoscaling.keda.sh/paused-");
                        a.insert(a.len() - 1, "autoscaling.keda.sh/paused-replicas-".into());
                        self.request(Action::Run { sel: sel(), args: a, what: format!("{} scales again", s.name) }, "Resume scaling".into(), format!("Let KEDA scale “{}” again?", s.name), "Resume", false);
                    }
                } else if button(ui, "Pause scaling", false, false) {
                    self.request(Action::Run { sel: sel(), args: annotate_args(s, key, "autoscaling.keda.sh/paused=true"), what: format!("Scaling of {} is paused", s.name) }, "Pause scaling".into(), format!("Pause KEDA's scaling of “{}”? It stays at the number of pods it has now.", s.name), "Pause", false);
                }
            }
            "policies.config.kio.kasten.io" => {
                if button(ui, "Run now", false, false) {
                    let m = opnet::kasten_run(&s.ns, &s.name);
                    self.request(Action::Create { sel: sel(), manifest: m, what: format!("Policy {} was started", s.name) }, "Run policy now".into(), format!("Run Kasten policy “{}” now? It makes a RunAction.", s.name), "Run now", false);
                }
            }
            _ => {}
        }
    }
}

pub(super) fn annotate_args(s: &crds::CustomSel, kind: &str, what: &str) -> Vec<String> {
    ["--context", &s.ctx, "-n", &s.ns, "annotate", kind, &s.name, what, "--overwrite"].iter().map(|x| x.to_string()).collect()
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn times_and_states() {
        assert_eq!(seconds("1h30m"), Some(5400));
        assert_eq!(seconds("1h0m0s"), Some(3600));
        assert_eq!(seconds("0"), Some(0));
        assert_eq!(seconds("15"), Some(15));
        assert_eq!(seconds("x"), None);
        let es = |ready: &str, at: &str| json!({"spec": {"refreshInterval": "1h"}, "status": {"refreshTime": at, "conditions": [{"type": "Ready", "status": ready, "reason": "SecretSyncedError", "message": "no"}]}});
        let now = kube::parse_time("2026-01-02T12:00:00Z").unwrap();
        assert_eq!(es_state(&es("True", "2026-01-02T11:30:00Z"), now).1, "Synced");
        assert_eq!(es_state(&es("True", "2026-01-02T06:30:00Z"), now).1, "Late");
        assert_eq!(es_state(&es("False", "2026-01-02T11:30:00Z"), now).0, Tone::Danger);
        let cert = |ready: &str, end: &str, renew: &str, tries: i64| json!({"status": {"notAfter": end, "renewalTime": renew, "failedIssuanceAttempts": tries, "conditions": [{"type": "Ready", "status": ready, "message": "m"}]}});
        assert_eq!(cert_state(&cert("True", "2026-03-01T00:00:00Z", "2026-02-01T00:00:00Z", 0), now).0, Tone::Success);
        assert_eq!(cert_state(&cert("True", "2026-03-01T00:00:00Z", "2026-01-01T00:00:00Z", 0), now).1, "Renewal overdue");
        assert_eq!(cert_state(&cert("True", "2026-03-01T00:00:00Z", "2026-02-01T00:00:00Z", 2), now).1, "Renewal failing");
        assert_eq!(cert_state(&cert("False", "2026-01-01T00:00:00Z", "", 0), now).1, "Expired");
        let s = crds::CustomSel { ctx: "c".into(), idx: 0, ns: "n".into(), name: "x".into() };
        assert_eq!(annotate_args(&s, ES, "force-sync=1").join(" "), "--context c -n n annotate externalsecrets.external-secrets.io x force-sync=1 --overwrite");
    }
}
