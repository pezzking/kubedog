//! The order of the sidebar's parts, and Settings > Sidebar where the person changes it.

use super::settings::{hint, title};
use super::*;

/// The parts, in the order Kubedog starts with. Favorites and port forwards stay on top, Settings at the bottom.
pub(super) const PARTS: [(&str, &str); 11] = [
    ("Cluster", "◎"),
    ("Superpowers", "⚡"),
    ("Workloads", "❐"),
    ("Configuration", "☰"),
    ("Networking", "⌖"),
    ("Storage", "⛁"),
    ("Access Control", "🔑"),
    ("Helm", "⎈"),
    ("Administration", "⚙"),
    ("GitOps", "⎇"),
    ("Custom Resources", "◇"),
];

/// The order to show: the person's, with parts they haven't placed after the one they usually follow.
pub(super) fn order(saved: &[String]) -> Vec<&'static str> {
    let mut l: Vec<&'static str> = vec![];
    for s in saved {
        if let Some(p) = PARTS.iter().find(|p| p.0 == s) {
            if !l.contains(&p.0) {
                l.push(p.0);
            }
        }
    }
    for (i, p) in PARTS.iter().enumerate() {
        if !l.contains(&p.0) {
            let at = PARTS[..i].iter().rev().find_map(|b| l.iter().position(|x| *x == b.0)).map_or(0, |n| n + 1);
            l.insert(at, p.0);
        }
    }
    l
}

impl KubedogApp {
    pub(super) fn sidebar_parts(&mut self, ui: &mut Ui) {
        for part in order(&self.prefs.sidebar) {
            match part {
                "Superpowers" => self.sidebar_super(ui),
                "GitOps" => self.sidebar_gitops(ui),
                "Custom Resources" => self.sidebar_custom(ui),
                "Helm" => {
                    if self.group_header(ui, "Helm", "⎈") {
                        if self.nav_fav(ui, self.view == View::Helm && self.selected.is_none(), View::Helm, "Releases", "Helm Releases", None) {
                            self.set_view(View::Helm);
                        }
                        ui.add_space(14.0);
                    }
                }
                _ => self.sidebar_kinds(ui, part),
            }
        }
    }

    /// A part with the pages of built-in kinds.
    fn sidebar_kinds(&mut self, ui: &mut Ui, part: &str) {
        let Some((group, kinds)) = GROUPS.iter().find(|g| g.0 == part) else { return };
        let icon = PARTS.iter().find(|p| p.0 == part).map_or("⚙", |p| p.1);
        if !self.group_header(ui, group, icon) {
            return;
        }
        let first = match *group {
            "Cluster" => Some((View::ClusterOverview, "Overview", "Cluster Overview")),
            "Workloads" => Some((View::WorkloadsOverview, "Overview", "Workloads Overview")),
            "Networking" => Some((View::ServiceMap, "Service Map", "Service Map")),
            "Storage" => Some((View::StorageUsage, "Usage", "Storage Usage")),
            _ => None,
        };
        if let Some((v, label, fav)) = first {
            if self.nav_fav(ui, self.view == v && self.selected.is_none(), v, label, fav, None) {
                self.set_view(v);
            }
        }
        for &k in kinds.iter() {
            let sel = self.view == View::Resource(k);
            let suffix = if k == Kind::HorizontalPodAutoscalers { Some("v2") } else { None };
            if self.nav_fav(ui, sel, View::Resource(k), k.label(), k.label(), suffix) {
                if sel && self.selected.is_some() {
                    self.navigate(View::Resource(k), None);
                } else {
                    self.set_view(View::Resource(k));
                }
            }
        }
        ui.add_space(14.0);
    }

    pub(super) fn settings_sidebar(&mut self, ui: &mut Ui) {
        title(ui, "Sidebar", "The order of the menu on the left. Drag a row, or use its arrows.");
        let mut l = order(&self.prefs.sidebar);
        let was = l.clone();
        let mut save = false;
        card(ui, |ui| {
            let (h, gap) = (u(36.0), 4.0);
            let top = ui.cursor().top();
            for (i, name) in was.iter().enumerate() {
                let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width().min(u(460.0)), h), Sense::hover());
                // Named after the part, so it stays the same row while it moves.
                let resp = ui.interact(r, ui.id().with(("side-part", *name)), Sense::drag());
                let held = resp.dragged();
                let p = ui.painter();
                let fill = if held { BG_SELECTED() } else if resp.hovered() { BG_HOVER() } else { BG_MUTED() };
                p.rect_filled(r, CornerRadius::same(6), fill);
                for dx in [0.0, 5.0] {
                    for dy in [-5.0, 0.0, 5.0] {
                        p.circle_filled(egui::pos2(r.left() + 13.0 + dx, r.center().y + dy), 1.3, TEXT_PLACEHOLDER());
                    }
                }
                let icon = PARTS.iter().find(|x| x.0 == *name).map_or("", |x| x.1);
                p.text(egui::pos2(r.left() + u(38.0), r.center().y), egui::Align2::CENTER_CENTER, icon, FontId::proportional(z(13.0)), TEXT_SUBTLE());
                p.text(egui::pos2(r.left() + u(56.0), r.center().y), egui::Align2::LEFT_CENTER, *name, FontId::proportional(z(14.5)), TEXT_DEFAULT());
                for (n, up) in [(1.0, true), (0.0, false)] {
                    let b = egui::Rect::from_center_size(egui::pos2(r.right() - u(20.0) - n * u(30.0), r.center().y), egui::vec2(u(26.0), u(26.0)));
                    let can = if up { i > 0 } else { i + 1 < was.len() };
                    let br = ui.interact(b, ui.id().with(("side-move", *name, up)), if can { Sense::click() } else { Sense::hover() });
                    let p = ui.painter();
                    if can && br.hovered() {
                        p.rect_filled(b, CornerRadius::same(5), BG_SELECTED());
                    }
                    let (c, s, d) = (b.center(), u(5.0), if up { -1.0 } else { 1.0 });
                    p.add(egui::Shape::convex_polygon(vec![c + egui::vec2(-s, -d * s * 0.6), c + egui::vec2(s, -d * s * 0.6), c + egui::vec2(0.0, d * s * 0.6)], if can { TEXT_MUTED() } else { BORDER_SUBTLE() }, Stroke::NONE));
                    if br.on_hover_text(if up { "Up" } else { "Down" }).clicked() && can {
                        l.swap(i, if up { i - 1 } else { i + 1 });
                        save = true;
                    }
                }
                if held {
                    if let Some(at) = resp.interact_pointer_pos() {
                        let to = (((at.y - top) / (h + gap)).floor().max(0.0) as usize).min(was.len() - 1);
                        if to != i {
                            let x = l.remove(i);
                            l.insert(to, x);
                        }
                    }
                }
                save |= resp.drag_stopped();
                resp.on_hover_cursor(egui::CursorIcon::Grab);
                ui.add_space((gap - ui.spacing().item_spacing.y).max(0.0));
            }
        });
        if l != was {
            self.prefs.sidebar = l.iter().map(|s| s.to_string()).collect();
        }
        ui.add_space(10.0);
        if !self.prefs.sidebar.is_empty() && order(&self.prefs.sidebar) != order(&[]) && button(ui, "Back to Kubedog's order", false, false) {
            self.prefs.sidebar.clear();
            save = true;
        }
        ui.add_space(6.0);
        hint(ui, "Port forwards and favorites stay on top, Settings at the bottom. GitOps and Superpowers only show what your clusters have.");
        if save {
            self.save();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sidebar_order() {
        let d = order(&[]);
        assert_eq!(d, PARTS.map(|p| p.0));
        let at = |l: &[&str], n: &str| l.iter().position(|x| *x == n).unwrap();
        assert!(at(&d, "Superpowers") < at(&d, "Workloads"));
        assert_eq!(at(&d, "Helm") + 1, at(&d, "Administration"));
        let s = |l: &[&str]| l.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        // The person's order, whole.
        let mut mine = d.clone();
        mine.reverse();
        assert_eq!(order(&s(&mine)), mine);
        // Unknown and double names are left out; what's missing follows the part it usually follows.
        let o = order(&s(&["Helm", "Nonsense", "Cluster", "Helm"]));
        assert_eq!(o.len(), PARTS.len());
        assert_eq!(at(&o, "Cluster") + 1, at(&o, "Superpowers"));
        assert_eq!(&o[..2], ["Helm", "Administration"]);
        // Every group of kinds has a place.
        assert!(GROUPS.iter().all(|g| PARTS.iter().any(|p| p.0 == g.0)));
    }
}
