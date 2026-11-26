//! Favorite pages: a star on every page of the sidebar (shown under the mouse) puts it in Favorites at the top.
//! Starred namespaces stay where they're chosen: first in the namespace menu, and on the Namespaces page.

use super::*;

impl KubedogApp {
    /// How a page is kept in the settings file. Custom resources by their full name, so the place holds when
    /// clusters change.
    pub(super) fn fav_key(&self, v: View) -> Option<String> {
        match v {
            View::Custom(i) => self.crds.get(i as usize).map(|k| format!("crd:{}", k.key)),
            v => Some(view_name(v)),
        }
    }

    /// The page a kept name stands for, while it's there (a superpower that's off, a kind this cluster lacks: not).
    fn fav_view(&self, key: &str) -> Option<View> {
        if let Some(k) = key.strip_prefix("crd:") {
            return self.crd_index(k).map(View::Custom);
        }
        let v = view_from_name(key)?;
        let power = matches!(v, View::Op(_)) || powers::OWN.iter().any(|o| o.3 == v);
        (!power || self.power_pages().iter().any(|p| p.0 == v)).then_some(v)
    }

    /// A page of the sidebar with its star. `fav` is what it's called in Favorites.
    pub(super) fn nav_fav(&mut self, ui: &mut Ui, selected: bool, view: View, label: &str, fav: &str, suffix: Option<&str>) -> bool {
        let Some(key) = self.fav_key(view) else { return nav_item(ui, selected, label, suffix) };
        let on = self.prefs.fav_pages.iter().any(|f| f.0 == key);
        let (go, star) = nav_item_star(ui, selected, label, suffix, Some(on));
        if star {
            self.toggle_fav(&key, fav);
        }
        go
    }

    fn toggle_fav(&mut self, key: &str, label: &str) {
        if let Some(i) = self.prefs.fav_pages.iter().position(|f| f.0 == key) {
            self.prefs.fav_pages.remove(i);
        } else {
            self.prefs.fav_pages.push((key.to_string(), label.to_string()));
        }
        self.save();
    }

    /// Opens a page the way its own place in the sidebar does.
    pub(super) fn go_page(&mut self, v: View) {
        match v {
            View::Custom(i) => self.open_custom(i),
            View::Resource(_) if self.view == v && self.selected.is_some() => self.navigate(v, None),
            _ => {
                self.powers.sel = None;
                self.incident.sel = None;
                self.pg_sel = None;
                self.es_sel = None;
                self.pu_sel = None;
                self.hive.node = None;
                self.grafana.sel = None;
                self.set_view(v);
            }
        }
    }

    /// The Favorites part of the sidebar: the starred pages, in the order they were starred.
    pub(super) fn sidebar_favs(&mut self, ui: &mut Ui) {
        let l: Vec<(String, String, View)> = self.prefs.fav_pages.iter().filter_map(|(k, n)| Some((k.clone(), n.clone(), self.fav_view(k)?))).collect();
        if l.is_empty() || !self.group_header(ui, "Favorites", "★") {
            return;
        }
        for (key, label, v) in l {
            let on = self.view == v && self.selected.is_none() && (!matches!(v, View::Custom(_)) || self.custom_sel.is_none());
            let (go, star) = nav_item_star(ui, on, &label, None, Some(true));
            if star {
                self.toggle_fav(&key, &label);
            } else if go {
                self.go_page(v);
            }
        }
        ui.add_space(14.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_by_name() {
        for v in [View::Resource(Kind::Pods), View::Resource(Kind::Deployments), View::Helm, View::ClusterOverview, View::ServiceMap, View::Shells, View::Incident] {
            assert_eq!(view_from_name(&view_name(v)), Some(v), "{v:?}");
        }
        let p = Prefs { fav_pages: vec![("Pods".into(), "Pods".into()), ("crd:clusters.postgresql.cnpg.io".into(), "Cluster".into())], ..Default::default() };
        let back = prefs_from_json(&prefs_to_json(&p));
        assert_eq!(back.fav_pages, p.fav_pages);
    }
}
