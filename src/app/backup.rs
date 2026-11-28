//! Settings as a file: writing all of them out, and reading such a file in (on another computer, or after a reinstall).
use super::*;
use std::path::Path;
use work::said;

/// What stays with the computer it was made on: what was open, where its programs are, which logins its keychain
/// holds, and which clusters start with changes allowed (a file never takes protection away).
const LOCAL: [&str; 13] = ["kubeconfigs", "session", "contexts", "kubectl_path", "logins", "open_at_start", "open_all", "update_last", "update_latest", "update_skip", "update_tried", "update_fails", "airgapped_auto"];

#[derive(Default)]
pub(super) struct Backup {
    path: String,
    /// A file that was read and waits for a yes: the settings it gives, and what it holds in words.
    waiting: Option<(Box<Prefs>, String)>,
    said: Option<(String, bool)>,
}

/// Everything from Settings, the namespaces listed per cluster included. No password or key is in it: those were
/// never in the settings. Kubeconfig files go along by where they are, not by what's in them.
pub(super) fn export_json(p: &Prefs) -> Value {
    let mut s = prefs_to_json(p);
    if let Some(m) = s.as_object_mut() {
        m.retain(|k, _| !LOCAL.contains(&k.as_str()));
        // Only an Air-gapped chosen by hand travels: one Kubedog switched on by itself belongs to that computer.
        m.insert("airgapped".into(), (p.airgapped && !p.airgapped_auto).into());
        // A Grafana password is in this computer's keychain, never in the settings: the file doesn't even say so.
        for c in m.get_mut("grafana").and_then(|g| g.as_object_mut()).into_iter().flat_map(|g| g.values_mut()) {
            c["keep"] = false.into();
        }
    }
    let files: Vec<Value> = p.kubeconfigs.iter().filter(|f| !f.managed).map(|f| serde_json::json!({"path": f.path, "enabled": f.enabled})).collect();
    serde_json::json!({"kubedog_settings": 1, "version": env!("CARGO_PKG_VERSION"), "settings": s, "kubeconfig_files": files})
}

/// The settings a file gives on this computer, and what was done with it, in words.
pub(super) fn import_into(now: &Prefs, file: &Value, exists: &dyn Fn(&str) -> bool) -> Result<(Prefs, String), String> {
    if file["kubedog_settings"] != 1 || !file["settings"].is_object() {
        return Err("This isn't a file with Kubedog's settings.".into());
    }
    let mut j = prefs_to_json(now);
    for (k, v) in file["settings"].as_object().into_iter().flatten().filter(|(k, _)| !LOCAL.contains(&k.as_str())) {
        j[k.as_str()] = v.clone();
    }
    // AI is only ever switched on by hand, on the computer it runs on.
    if !now.ai.on {
        j["ai"]["on"] = false.into();
    }
    // Nor does a file make this computer ask the internet for anything it was told not to.
    if !now.update_check {
        j["update_check"] = false.into();
    }
    // A file can make this computer air-gapped, never the other way round.
    if now.airgapped {
        j["airgapped"] = true.into();
    }
    let (mut added, mut gone) = (0, 0);
    let mut files = j["kubeconfigs"].as_array().cloned().unwrap_or_default();
    for f in file["kubeconfig_files"].as_array().into_iter().flatten() {
        let Some(path) = f["path"].as_str().filter(|p| !p.is_empty()) else { continue };
        if files.iter().any(|x| x["path"] == path) {
            continue;
        }
        if exists(path) {
            files.push(serde_json::json!({"path": path, "enabled": f["enabled"].as_bool().unwrap_or(true), "managed": false}));
            added += 1;
        } else {
            gone += 1;
        }
    }
    j["kubeconfigs"] = files.into();
    let p = prefs_from_json(&j);
    let mut said = format!("From Kubedog {}: settings for {} clusters with their namespaces listed", file["version"].as_str().unwrap_or("of an unknown version"), p.ctx_namespaces.len());
    if added > 0 {
        said += &format!(", {added} kubeconfig files to add");
    }
    if gone > 0 {
        said += &format!(", {gone} kubeconfig files that aren't on this computer (left out)");
    }
    Ok((p, said + "."))
}

impl KubedogApp {
    /// Settings > General: all settings out to a file, or in from one.
    pub(super) fn settings_backup(&mut self, ui: &mut Ui) {
        if self.backup.path.is_empty() {
            let home = kube::home().unwrap_or_default();
            let dir = Some(home.join("Downloads")).filter(|d| d.is_dir()).unwrap_or(home);
            self.backup.path = dir.join("kubedog-settings.json").to_string_lossy().to_string();
        }
        ui.add_space(10.0);
        card(ui, |ui| {
            ui.label(RichText::new("Settings as a file").size(z(15.0)).strong().color(TEXT_DEFAULT()));
            ui.add_space(4.0);
            settings::hint(ui, "Everything from Settings in one file, the namespaces listed per cluster included: for another computer, or to keep. It holds the names and addresses of your clusters, and no password or key. Kubeconfig files go along by where they are, not by what's in them.");
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("File").color(TEXT_MUTED()));
                let w = (ui.available_width() - u(190.0)).clamp(120.0, 560.0);
                ui.add(egui::TextEdit::singleline(&mut self.backup.path).desired_width(w));
                if button(ui, "Export", false, false) {
                    self.backup_export();
                }
                if button(ui, "Import…", false, false) {
                    self.backup_read();
                }
            });
            if let Some((_, what)) = &self.backup.waiting {
                let what = what.clone();
                ui.add_space(8.0);
                said(ui, &what, TEXT_DEFAULT());
                settings::hint(ui, "Your settings are replaced by the file's. What stays as it is here: your kubeconfig files, logins, which clusters start with changes allowed, and AI and the look for a new version stay off unless they're on here, and Air-gapped stays on when it's on here.");
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if button(ui, "Replace my settings", true, false) {
                        self.backup_apply();
                    }
                    if button(ui, "Cancel", false, false) {
                        self.backup.waiting = None;
                    }
                });
            }
            if let Some((t, bad)) = &self.backup.said {
                ui.add_space(6.0);
                said(ui, t, if *bad { DANGER() } else { SUCCESS() });
            }
        });
    }

    fn backup_export(&mut self) {
        if self.screenshot.is_some() {
            return;
        }
        let path = self.backup.path.trim().to_string();
        let text = serde_json::to_string_pretty(&export_json(&self.prefs)).unwrap_or_default();
        self.backup.waiting = None;
        self.backup.said = Some(match std::fs::write(&path, text) {
            Ok(()) => (format!("Written to {}.", clusters::short_path(&path)), false),
            Err(e) => (format!("{} couldn't be written: {e}", clusters::short_path(&path)), true),
        });
    }

    fn backup_read(&mut self) {
        if self.screenshot.is_some() {
            return;
        }
        let path = self.backup.path.trim().to_string();
        let read = std::fs::read_to_string(&path).map_err(|e| format!("{} couldn't be read: {e}", clusters::short_path(&path)));
        let got = read.and_then(|t| serde_json::from_str::<Value>(&t).map_err(|_| "This isn't a file with Kubedog's settings.".to_string())).and_then(|v| import_into(&self.prefs, &v, &|p| Path::new(p).is_file()));
        match got {
            Ok((p, what)) => {
                self.backup.waiting = Some((Box::new(p), what));
                self.backup.said = None;
            }
            Err(e) => {
                self.backup.waiting = None;
                self.backup.said = Some((e, true));
            }
        }
    }

    fn backup_apply(&mut self) {
        let Some((mut p, _)) = self.backup.waiting.take() else { return };
        // What changed here since the file was read stays: a file never switches Air-gapped off or the look on.
        let now = &self.prefs;
        p.airgapped |= now.airgapped;
        p.airgapped_auto = now.airgapped && now.airgapped_auto;
        p.update_check &= now.update_check;
        (p.update_tried, p.update_fails, p.update_last) = (now.update_tried, now.update_fails, now.update_last);
        (p.update_latest, p.update_skip) = (now.update_latest.clone(), now.update_skip.clone());
        self.prefs = *p;
        crate::theme::install_font(&self.egui_ctx, &self.prefs.font);
        self.apply_theme();
        self.save();
        self.load_contexts();
        self.backup.said = Some(("Done. Kubedog uses the file's settings now; start it again to be sure everything follows.".into(), false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_and_in_again() {
        let mut p = Prefs::default();
        p.theme = "sand".into();
        p.text_size = 18;
        p.ctx_namespaces.insert("shop".into(), vec!["web".into(), "team-*".into()]);
        p.ctx_alias.insert("shop".into(), "Shop".into());
        p.powers.insert("shell".into(), "off".into());
        p.kubectl_path = "/opt/tools/kubectl".into();
        p.open_all = true;
        p.ai.on = true;
        p.kubeconfigs = vec![KubeFile { path: "/files/one".into(), enabled: true, managed: false }, KubeFile { path: "/own/pasted".into(), enabled: true, managed: true }];
        let file = export_json(&p);
        let text = file.to_string();
        // Nothing of this computer, and no pasted kubeconfig.
        assert!(!text.contains("/opt/tools/kubectl") && !text.contains("/own/pasted") && !text.contains("open_all") && file["settings"]["session"].is_null());
        assert_eq!(file["kubeconfig_files"], serde_json::json!([{"path": "/files/one", "enabled": true}]));

        // On another computer: its own things stay, the rest follows the file.
        let mut here = Prefs::default();
        here.kubectl_path = "/usr/bin/kubectl".into();
        here.kubeconfigs = vec![KubeFile { path: "/here/config".into(), enabled: true, managed: false }];
        let (got, said) = import_into(&here, &file, &|f| f == "/files/one").unwrap();
        assert_eq!((got.theme.as_str(), got.text_size), ("sand", 18));
        assert_eq!(got.ctx_namespaces["shop"], ["web", "team-*"]);
        assert_eq!(got.ctx_alias["shop"], "Shop");
        assert_eq!(got.powers["shell"], "off");
        assert_eq!(got.kubectl_path, "/usr/bin/kubectl");
        // A file takes no protection away and doesn't switch AI on.
        assert!(!got.open_all && got.open_at_start.is_empty() && !got.ai.on);
        assert_eq!(got.kubeconfigs.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(), ["/here/config", "/files/one"]);
        assert!(said.contains("1 clusters") && said.contains("1 kubeconfig files to add"), "{said}");

        // A file that isn't there is left out, and said; the same file twice adds nothing twice.
        let (got, said) = import_into(&got, &file, &|_| false).unwrap();
        assert_eq!(got.kubeconfigs.len(), 2);
        assert!(!said.contains("left out"), "{said}");
        let (got, said) = import_into(&here, &file, &|_| false).unwrap();
        assert!(got.kubeconfigs.len() == 1 && said.contains("1 kubeconfig files that aren't on this computer"), "{said}");

        // The look for a new version isn't switched on by a file either; switching it off is taken over.
        here.update_check = false;
        assert!(!import_into(&here, &file, &|_| false).unwrap().0.update_check);
        here.update_check = true;
        let mut off = file.clone();
        off["settings"]["update_check"] = false.into();
        assert!(!import_into(&here, &off, &|_| false).unwrap().0.update_check);
        assert!(import_into(&here, &file, &|_| false).unwrap().0.update_check);
        // Air-gapped: a file can switch it on, never off.
        assert!(!import_into(&here, &file, &|_| false).unwrap().0.airgapped);
        let mut gap = file.clone();
        gap["settings"]["airgapped"] = true.into();
        gap["settings"]["airgapped_auto"] = true.into();
        let got = import_into(&here, &gap, &|_| false).unwrap().0;
        assert!(got.airgapped && !got.airgapped_auto);
        // A Grafana login kept in the keychain: the file says nothing of it, and reading one never claims it.
        let mut graf = Prefs::default();
        graf.grafana.insert("shop".into(), grafana::Conf { url: "https://g.example".into(), user: "me".into(), keep: true, ..Default::default() });
        let out = export_json(&graf);
        assert_eq!(out["settings"]["grafana"]["shop"]["keep"], false);
        assert!(!import_into(&Prefs::default(), &out, &|_| false).unwrap().0.grafana["shop"].keep);
        // Switched on by Kubedog itself, it stays with the computer it happened on.
        let mut auto = Prefs::default();
        (auto.airgapped, auto.airgapped_auto) = (true, true);
        assert_eq!(export_json(&auto)["settings"]["airgapped"], false);
        assert!(!import_into(&Prefs::default(), &export_json(&auto), &|_| false).unwrap().0.airgapped);
        auto.airgapped_auto = false;
        assert!(import_into(&Prefs::default(), &export_json(&auto), &|_| false).unwrap().0.airgapped);
        here.airgapped = true;
        here.airgapped_auto = true;
        let got = import_into(&here, &file, &|_| false).unwrap().0;
        assert!(got.airgapped && got.airgapped_auto);
        // Where AI is on already, the file's AI settings are taken as they are.
        here.ai.on = true;
        assert!(import_into(&here, &file, &|_| false).unwrap().0.ai.on);
        // Not ours.
        assert!(import_into(&here, &serde_json::json!({"theme": "dark"}), &|_| true).is_err());
        assert!(import_into(&here, &serde_json::json!({"kubedog_settings": 1}), &|_| true).is_err());
    }
}
