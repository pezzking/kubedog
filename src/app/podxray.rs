//! The X-ray on a pod's Overview: the ways in from outside, the services behind them, the
//! containers as tanks filled with memory, and what the pod holds. Everything can be clicked.

use super::pg::{label_at, stream};
use super::pod::{cond, containers, status_of};
use super::*;

/// Where a click leads.
#[derive(Clone)]
pub(super) enum Go {
    Object(Selected),
    Custom(crds::CustomSel),
    Tab(Tab),
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub(super) enum Way {
    Ingress,
    Route,
    Http,
}

/// A way in from outside the cluster.
#[derive(Clone, PartialEq, Debug)]
pub(super) struct Entry {
    pub way: Way,
    pub name: String,
    pub host: String,
    pub path: String,
    pub tls: bool,
    pub service: String,
    /// Something is in front of it that took it on.
    pub taken: bool,
    /// Can be opened as it is (no wildcards or patterns).
    pub plain: bool,
}

impl Entry {
    pub fn address(&self) -> String {
        format!("{}{}", self.host, if self.path == "/" { "" } else { &self.path })
    }
    pub fn url(&self) -> String {
        format!("{}://{}{}", if self.tls { "https" } else { "http" }, self.host, self.path)
    }
    fn kind(&self) -> &'static str {
        match self.way {
            Way::Ingress => "ingress",
            Way::Route | Way::Http => "route",
        }
    }
}

fn plain_host(h: &str) -> bool {
    !h.is_empty() && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

fn plain_path(p: &str) -> bool {
    p.starts_with('/') && p.chars().all(|c| c.is_ascii_alphanumeric() || "/-_.~".contains(c))
}

/// What's kept of an OpenShift route. Its TLS part may hold a private key, which is dropped here.
pub(super) fn pick_route(o: &Value) -> Vec<Entry> {
    let s = &o["spec"];
    let name = o["metadata"]["name"].as_str().unwrap_or("").to_string();
    let host = s["host"].as_str().unwrap_or("").to_string();
    let path = s["path"].as_str().unwrap_or("/").to_string();
    let taken = o["status"]["ingress"].as_array().into_iter().flatten().any(|i| i["conditions"].as_array().into_iter().flatten().any(|c| c["type"] == "Admitted" && c["status"] == "True"));
    let wild = s["wildcardPolicy"] == "Subdomain";
    std::iter::once(&s["to"])
        .chain(s["alternateBackends"].as_array().into_iter().flatten())
        .filter(|t| t["kind"].as_str().unwrap_or("Service") == "Service")
        .filter_map(|t| t["name"].as_str())
        .map(|svc| Entry { way: Way::Route, name: name.clone(), host: if wild { format!("*.{}", host.split_once('.').map(|x| x.1).unwrap_or(&host)) } else { host.clone() }, path: path.clone(), tls: s["tls"].is_object(), service: svc.to_string(), taken, plain: !wild && plain_host(&host) && plain_path(&path) })
        .collect()
}

pub(super) fn pick_http(o: &Value) -> Vec<Entry> {
    let name = o["metadata"]["name"].as_str().unwrap_or("").to_string();
    let hosts: Vec<String> = o["spec"]["hostnames"].as_array().into_iter().flatten().filter_map(|h| h.as_str().map(String::from)).collect();
    let hosts = if hosts.is_empty() { vec!["any host".to_string()] } else { hosts };
    let taken = o["status"]["parents"].as_array().into_iter().flatten().any(|p| p["conditions"].as_array().into_iter().flatten().any(|c| c["type"] == "Accepted" && c["status"] == "True"));
    let mut out = vec![];
    for r in o["spec"]["rules"].as_array().into_iter().flatten() {
        let path = r["matches"][0]["path"]["value"].as_str().unwrap_or("/").to_string();
        for b in r["backendRefs"].as_array().into_iter().flatten().filter(|b| b["kind"].as_str().unwrap_or("Service") == "Service") {
            for h in &hosts {
                // Whether it's https is up to the gateway, so it isn't offered to open.
                out.push(Entry { way: Way::Http, name: name.clone(), host: h.clone(), path: path.clone(), tls: false, service: b["name"].as_str().unwrap_or("").to_string(), taken, plain: false });
            }
        }
    }
    out
}

pub(super) fn pick_ingress(o: &Value) -> Vec<Entry> {
    let name = o["metadata"]["name"].as_str().unwrap_or("").to_string();
    let tls: Vec<&str> = o["spec"]["tls"].as_array().into_iter().flatten().flat_map(|t| t["hosts"].as_array().into_iter().flatten().filter_map(|h| h.as_str())).collect();
    // Many controllers never say whether they took an ingress on, so no warning is drawn from that.
    let taken = true;
    let mut out = vec![];
    let mut add = |host: &str, path: &str, svc: Option<&str>| {
        if let Some(s) = svc {
            out.push(Entry { way: Way::Ingress, name: name.clone(), host: if host.is_empty() { "any host".into() } else { host.to_string() }, path: path.to_string(), tls: tls.contains(&host), service: s.to_string(), taken, plain: plain_host(host) && plain_path(path) });
        }
    };
    add("", "/", o["spec"]["defaultBackend"]["service"]["name"].as_str());
    for r in o["spec"]["rules"].as_array().into_iter().flatten() {
        for p in r["http"]["paths"].as_array().into_iter().flatten() {
            add(r["host"].as_str().unwrap_or(""), p["path"].as_str().unwrap_or("/"), p["backend"]["service"]["name"].as_str());
        }
    }
    out
}

/// Routes (OpenShift's, and the Gateway API's) of a namespace. Routes made from an ingress are left
/// out: the ingress is shown. Returns them and whether the cluster knows OpenShift routes.
pub(super) fn read_routes(k: &Kubectl, ctx: &str, ns: &str, openshift: bool, http: bool) -> (Vec<Entry>, bool) {
    let get = |res: &str| {
        let a: Vec<String> = ["--context", ctx, "-n", ns, "get", res, "-o", "json", &format!("--request-timeout={}", kube::REQUEST_TIMEOUT)].iter().map(|x| x.to_string()).collect();
        k.run(&a).and_then(|j| kube::parse_items(&j))
    };
    let mut out = vec![];
    let mut known = openshift;
    if openshift {
        match get("routes.route.openshift.io") {
            Ok(items) => out.extend(items.iter().filter(|o| !o["metadata"]["ownerReferences"].as_array().into_iter().flatten().any(|r| r["kind"] == "Ingress")).flat_map(pick_route)),
            Err(e) => known = !e.contains("doesn't have a resource type"),
        }
    }
    if http {
        out.extend(get("httproutes.gateway.networking.k8s.io").unwrap_or_default().iter().flat_map(pick_http));
    }
    (out, known)
}

pub(super) fn pack(list: &[Entry], known: bool) -> String {
    let way = |w: Way| match w { Way::Ingress => "i", Way::Route => "r", Way::Http => "h" };
    serde_json::json!({"known": known, "list": list.iter().map(|e| serde_json::json!([way(e.way), e.name, e.host, e.path, e.tls, e.service, e.taken, e.plain])).collect::<Vec<_>>()}).to_string()
}

pub(super) fn unpack(t: &str) -> Option<(Vec<Entry>, bool)> {
    let v: Value = serde_json::from_str(t).ok()?;
    let s = |x: &Value| x.as_str().unwrap_or("").to_string();
    let b = |x: &Value| x.as_bool().unwrap_or(false);
    let list = v["list"].as_array()?.iter().map(|e| Entry { way: if e[0] == "r" { Way::Route } else if e[0] == "h" { Way::Http } else { Way::Ingress }, name: s(&e[1]), host: s(&e[2]), path: s(&e[3]), tls: b(&e[4]), service: s(&e[5]), taken: b(&e[6]), plain: b(&e[7]) }).collect();
    Some((list, b(&v["known"])))
}

/// A config map's or secret's part in a pod: (name, how it's used).
fn used(pod: &Value, kind: &str) -> Vec<(String, String)> {
    // The volume every pod gets (its token and the cluster's certificates) says nothing about it.
    let mut p = pod.clone();
    if let Some(v) = p["spec"]["volumes"].as_array_mut() {
        v.retain(|v| !v["name"].as_str().unwrap_or("").starts_with("kube-api-access-"));
    }
    let mut out: Vec<(String, Vec<&str>)> = vec![];
    for (_, n, h) in podplace::config_uses(&p).into_iter().filter(|u| u.0 == kind) {
        let w = match h {
            podplace::How::Variable => "variables",
            podplace::How::Files => "files",
            podplace::How::Fixed => "a fixed file",
        };
        match out.iter_mut().find(|x| x.0 == n) {
            Some(x) => x.1.push(w),
            None => out.push((n, vec![w])),
        }
    }
    if kind == "secret" {
        for s in pod["spec"]["imagePullSecrets"].as_array().into_iter().flatten().filter_map(|s| s["name"].as_str()) {
            match out.iter_mut().find(|x| x.0 == s) {
                Some(x) => x.1.push("to fetch images"),
                None => out.push((s.to_string(), vec!["to fetch images"])),
            }
        }
    }
    out.into_iter().map(|(n, w)| (n, if w == ["to fetch images"] { w[0].to_string() } else { format!("as {}", w.join(", ")) })).collect()
}

/// Columns of the drawing from left to right, as (left, width).
#[derive(Debug, PartialEq, Clone, Copy)]
struct Columns {
    entry: Option<(f32, f32)>,
    door: (f32, f32),
    body: (f32, f32),
    hold: (f32, f32),
}

/// The pod is as wide as its containers want; what's left over goes around it. When it's tight the
/// gaps, then the boxes, then the pod give way, and at last the ways in are left out.
fn columns(w: f32, entries: bool, doors: bool, holds: bool, body: f32, body_min: f32, s: f32) -> Columns {
    let side = |on: bool, want: f32, min: f32| if on { (want * s, min * s) } else { (0.0, 0.0) };
    let cols = [side(entries, 260.0, 130.0), if doors { (220.0 * s, 110.0 * s) } else { (150.0 * s, 90.0 * s) }, side(holds, 230.0, 110.0)];
    let gaps = [entries, true, holds];
    let n = gaps.iter().filter(|g| **g).count() as f32;
    let (gap_want, gap_min, gap_max) = (84.0 * s, 30.0 * s, 130.0 * s);
    let want: f32 = cols.iter().map(|c| c.0).sum::<f32>() + body + n * gap_want;
    let min: f32 = cols.iter().map(|c| c.1).sum::<f32>() + body_min + n * gap_min;
    if entries && min > w {
        return columns(w, false, doors, holds, body, body_min, s);
    }
    let mut short = (want - w).max(0.0);
    let mut give = |have: f32, least: f32| {
        let g = short.min((have - least).max(0.0));
        short -= g;
        have - g
    };
    let mut gap = give(n * gap_want, n * gap_min) / n;
    let (full, least) = (cols.iter().map(|c| c.0).sum::<f32>(), cols.iter().map(|c| c.1).sum::<f32>());
    let sides = give(full, least);
    let t = if full > least { (sides - least) / (full - least) } else { 1.0 };
    let wide = cols.map(|c| c.1 + (c.0 - c.1) * t);
    let body = give(body, body_min).max(40.0);
    let total = wide.iter().sum::<f32>() + body + n * gap;
    gap = (gap + (w - total).max(0.0) / n).min(gap.max(gap_max));
    let total = wide.iter().sum::<f32>() + body + n * gap;
    let mut x = ((w - total) / 2.0).max(0.0);
    let entry = entries.then(|| {
        let at = (x, wide[0]);
        x += wide[0] + gap;
        at
    });
    let door = (x, wide[1]);
    x += wide[1] + gap;
    let b = (x, body);
    x += body + if holds { gap } else { 0.0 };
    Columns { entry, door, body: b, hold: (x, wide[2]) }
}

/// What's drawn: whose ways in and holdings, and how big the middle is.
pub(super) struct Look<'a> {
    pub title: &'a str,
    pub note: String,
    /// A pod, or a pod made from a template.
    pub pod: &'a Value,
    /// Only this service in front, instead of all that pick the pod.
    pub only: Option<&'a str>,
    /// Disks besides the pod's own.
    pub claims: Vec<String>,
    pub tone: Tone,
    pub running: bool,
    pub ready: bool,
    pub want: f32,
    pub least: f32,
    /// How tall the inside is.
    pub tall: f32,
    /// It has a Storage tab.
    pub storage: bool,
    /// Say so when no service leads here.
    pub doors: bool,
}

enum Act {
    None,
    Go(Selected),
    /// A menu: (name, how, where to).
    List(Vec<(String, String, Selected)>),
    Tab(Tab),
}

struct Hold {
    name: String,
    sub: String,
    fill: Option<f64>,
    col: Color32,
    act: Act,
}

impl Hold {
    /// One goes by its name; several together, with a menu.
    fn of(list: Vec<(String, String, Selected)>, one: &str, many: &str, col: Color32) -> Option<Hold> {
        match list.len() {
            0 => None,
            1 => list.into_iter().next().map(|(n, how, s)| Hold { name: n, sub: format!("{one} {how}"), fill: None, col, act: Act::Go(s) }),
            n => Some(Hold { name: format!("{n} {many}"), sub: list.iter().map(|x| x.0.as_str()).collect::<Vec<_>>().join(", "), fill: None, col, act: Act::List(list) }),
        }
    }
}

impl KubedogApp {
    /// The ways in to a service of the open pod's namespace.
    pub(super) fn entries_to(&self, ctx: &str, ns: &str, service: &str) -> Vec<Entry> {
        let mut out: Vec<Entry> = self.items_in(ctx, Kind::Ingresses, ns).unwrap_or_default().iter().flat_map(pick_ingress).collect();
        out.extend(self.pod.routes.iter().cloned());
        out.retain(|e| e.service == service);
        // The same address twice (several paths of one host) is one way in per path.
        let mut seen = HashSet::new();
        out.retain(|e| seen.insert((e.name.clone(), e.host.clone(), e.path.clone())));
        out
    }

    pub(super) fn pod_xray(&self, ui: &mut Ui, sel: &Selected, o: &Value) -> Option<Go> {
        let cs = containers(o);
        let shown = cs.len().clamp(1, 6);
        let gap = 14.0;
        let room = |tank: f32| shown as f32 * tank + gap * (shown as f32 - 1.0) + 44.0;
        let want = room(u(if shown == 1 { 260.0 } else { 230.0 }));
        let look = Look {
            title: "X-ray",
            note: match (&self.pod.top_err, self.pod.tops.back()) {
                (Some(e), _) => e.clone(),
                (None, None) => "reading usage…".into(),
                _ => "tanks fill with memory, up to the limit (or the request); the waves move with CPU".into(),
            },
            pod: o,
            only: None,
            claims: vec![],
            tone: pod::verdict(o, kube::now_secs()).0,
            running: o["status"]["phase"] == "Running",
            ready: cond(o, "Ready").map(|c| c["status"] == "True").unwrap_or(false),
            want,
            least: room(u(80.0)).min(want),
            tall: u(184.0),
            storage: true,
            doors: true,
        };
        self.xray(ui, sel, &look, |ui, p, body, time| {
            self.xray_tanks(ui, p, o, body, gap, shown, time);
            None
        })
    }

    /// What goes in and out of a pod, or of a workload's or service's pods, drawn around a body.
    pub(super) fn xray(&self, ui: &mut Ui, sel: &Selected, look: &Look, inside: impl FnOnce(&mut Ui, &egui::Painter, egui::Rect, f32) -> Option<Selected>) -> Option<Go> {
        let mut go = None;
        let o = look.pod;
        let spec = &o["spec"];
        let labels = &o["metadata"]["labels"];
        let obj = |kind: Kind, name: &str| Selected { ctx: sel.ctx.clone(), kind, ns: sel.ns.clone(), name: name.to_string() };
        // Doors: services that send traffic here, those with a way in first.
        let mut doors: Vec<(String, String, Vec<Entry>)> = vec![];
        let services = self.refs(&sel.ctx, Kind::Services, &sel.ns);
        for s in services.clone().unwrap_or_default() {
            let here = match look.only {
                Some(n) => s["metadata"]["name"].as_str() == Some(n),
                None => s["spec"]["selector"].as_object().map(|m| !m.is_empty()).unwrap_or(false) && podnet::selector_matches(&s["spec"]["selector"], labels),
            };
            if here {
                let name = s["metadata"]["name"].as_str().unwrap_or("").to_string();
                let ports: Vec<String> = s["spec"]["ports"].as_array().into_iter().flatten().map(|p| p["port"].to_string()).collect();
                let e = self.entries_to(&sel.ctx, &sel.ns, &name);
                doors.push((name, ports.join(", "), e));
            }
        }
        doors.sort_by(|a, b| a.2.is_empty().cmp(&b.2.is_empty()).then(a.0.cmp(&b.0)));
        let more_doors = doors.len().saturating_sub(5);
        doors.truncate(5);
        let mut entries: Vec<(usize, Entry)> = doors.iter().enumerate().flat_map(|(i, d)| d.2.iter().map(move |e| (i, e.clone()))).collect();
        let more_entries = entries.len().saturating_sub(6);
        entries.truncate(6);
        // Holds.
        let mut disks: Vec<(String, String, Selected)> = vec![];
        let (mut scratch, mut other) = (0, 0);
        for v in spec["volumes"].as_array().into_iter().flatten() {
            if let Some(c) = v["persistentVolumeClaim"]["claimName"].as_str() {
                if !disks.iter().any(|d| d.0 == c) {
                    disks.push((c.to_string(), String::new(), obj(Kind::PersistentVolumeClaims, c)));
                }
            } else if v["emptyDir"].is_object() || v["ephemeral"].is_object() {
                scratch += 1;
            } else if v["secret"].is_null() && v["configMap"].is_null() && v["projected"].is_null() {
                other += 1;
            }
        }
        for c in &look.claims {
            if !disks.iter().any(|d| &d.0 == c) {
                disks.push((c.clone(), String::new(), obj(Kind::PersistentVolumeClaims, c)));
            }
        }
        let rest = disks.split_off(disks.len().min(if disks.len() > 4 { 3 } else { 4 }));
        let mut holds: Vec<Hold> = disks
            .into_iter()
            .map(|(n, _, s)| {
                let f = self.claim_usage(&sel.ctx, &sel.ns, &n).map(|x| x.used / x.capacity.max(1.0));
                Hold { name: n, sub: f.map(|f| format!("disk, {:.0}% full", f * 100.0)).unwrap_or("disk".into()), fill: f, col: SUCCESS(), act: Act::Go(s) }
            })
            .collect();
        holds.extend(Hold::of(rest, "disk", "more disks", SUCCESS()));
        holds.extend(Hold::of(used(o, "configmap").into_iter().map(|(n, h)| (n.clone(), h, obj(Kind::ConfigMaps, &n))).collect(), "config map", "configurations", INFO()));
        holds.extend(Hold::of(used(o, "secret").into_iter().map(|(n, h)| (n.clone(), h, obj(Kind::Secrets, &n))).collect(), "secret", "secrets", WARNING()));
        for (n, one, many) in [(scratch, "scratch space", "scratch spaces"), (other, "other volume", "other volumes")] {
            if n > 0 {
                let act = if look.storage { Act::Tab(Tab::Storage) } else { Act::None };
                holds.push(Hold { name: format!("{n} {}", if n == 1 { one } else { many }), sub: if look.storage { "see Storage" } else { "in each pod" }.into(), fill: None, col: TEXT_SUBTLE(), act });
            }
        }

        let box_h = u(38.0);
        let step = box_h + 8.0;
        let side = doors.len().max(holds.len()).max(entries.len()).max(1) as f32 * step;
        let h = side.max(look.tall + u(30.0)) + u(58.0);
        Frame::new().fill(BG_SUBTLE()).stroke(Stroke::new(1.0, BORDER_SUBTLE())).corner_radius(CornerRadius::same(12)).inner_margin(Margin::symmetric(16, 10)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            let (area, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), h), Sense::hover());
            let p = ui.painter().clone();
            let time = ui.input(|i| i.time) as f32;
            let title = p.layout_no_wrap(look.title.to_string(), FontId::proportional(z(14.5)), TEXT_DEFAULT());
            let tw = title.size().x + u(14.0);
            p.galley(area.left_top() + egui::vec2(0.0, u(9.0) - title.size().y / 2.0), title, TEXT_DEFAULT());
            label_at(ui, &p, area.left_top() + egui::vec2(tw, u(10.0)), &look.note, 11.5, TEXT_PLACEHOLDER(), area.width() - tw - 10.0);
            let c = columns(area.width(), !entries.is_empty(), !doors.is_empty(), !holds.is_empty(), look.want, look.least, u(1.0));
            let shift = |r: (f32, f32)| (area.left() + r.0, r.1);
            let mid_y = area.top() + u(26.0) + (h - u(26.0)) / 2.0;
            let body = egui::Rect::from_min_max(egui::pos2(area.left() + c.body.0, area.top() + u(30.0)), egui::pos2(area.left() + c.body.0 + c.body.1, area.bottom() - u(2.0)));
            // The pod's skin.
            let (running, ready) = (look.running, look.ready);
            p.rect_filled(body, CornerRadius::same(26), BG_CARD().gamma_multiply(0.7));
            p.rect_stroke(body, CornerRadius::same(26), Stroke::new(1.6, tone_color(look.tone).gamma_multiply(0.7)), egui::StrokeKind::Inside);
            let place = |i: usize, n: usize, col: (f32, f32)| egui::Rect::from_min_size(egui::pos2(col.0, mid_y - n as f32 * step / 2.0 + i as f32 * step + 4.0), egui::vec2(col.1, box_h));
            let rim = |i: usize, n: usize, x: f32| egui::pos2(x, body.top() + body.height() * (i as f32 + 1.0) / (n as f32 + 1.0));
            let small = |ui: &mut Ui, r: egui::Rect, name: &str, sub: &str, col: Color32, id: (&str, usize), click: bool, tip: &str| -> egui::Response {
                let resp = ui.interact(r, ui.id().with(("xray", id)), if click { Sense::click() } else { Sense::hover() });
                let p = ui.painter();
                p.rect_filled(r, CornerRadius::same(8), if click && resp.hovered() { BG_HOVER() } else { BG_CARD() });
                p.rect_stroke(r, CornerRadius::same(8), Stroke::new(1.0, if click && resp.hovered() { col } else { col.gamma_multiply(0.6) }), egui::StrokeKind::Inside);
                label_at(ui, p, egui::pos2(r.left() + 10.0, r.top() + r.height() * 0.31), name, 12.0, if click { PRIMARY_TEXT() } else { TEXT_MUTED() }, r.width() - 20.0);
                label_at(ui, p, egui::pos2(r.left() + 10.0, r.top() + r.height() * 0.68), sub, 10.5, TEXT_SUBTLE(), r.width() - 20.0);
                let resp = if click { resp.on_hover_cursor(egui::CursorIcon::PointingHand) } else { resp };
                resp.on_hover_text(tip)
            };
            // Ways in.
            if let Some(col) = c.entry.map(shift) {
                for (i, (d, e)) in entries.iter().enumerate() {
                    let r = place(i, entries.len(), col);
                    let door = place(*d, doors.len(), shift(c.door));
                    let cc = if e.taken { INFO() } else { WARNING() };
                    stream(&p, r.right_center(), door.left_center(), cc, time * 0.35 + i as f32 * 0.21, if e.taken && ready { 2 } else { 0 }, e.taken);
                    let sub = format!("{} {}{}", e.kind(), e.name, if e.taken { "" } else { ", not taken on yet" });
                    let tip = format!("{}\n{sub}\n{}", e.address(), match e.way { Way::Ingress => "Click to open the ingress", Way::Route => "Click for what you can do with it", Way::Http => "Click to open the route" });
                    let resp = small(ui, r, &e.address(), &sub, cc, ("in", i), true, &tip);
                    match e.way {
                        Way::Ingress => {
                            if resp.clicked() {
                                go = Some(Go::Object(obj(Kind::Ingresses, &e.name)));
                            }
                        }
                        Way::Http => {
                            if resp.clicked() {
                                if let Some(idx) = self.crd_index("httproutes.gateway.networking.k8s.io") {
                                    go = Some(Go::Custom(crds::CustomSel { ctx: sel.ctx.clone(), idx, ns: sel.ns.clone(), name: e.name.clone() }));
                                }
                            }
                        }
                        Way::Route => {
                            egui::Popup::menu(&resp).show(|ui| {
                                ui.set_max_width(u(420.0));
                                ui.label(RichText::new(e.url()).size(z(13.0)).color(TEXT_DEFAULT()));
                                ui.label(RichText::new(format!("route {} to service {}", e.name, e.service)).size(z(12.0)).color(TEXT_SUBTLE()));
                                ui.separator();
                                if e.plain && ui.button("Open in the browser").clicked() {
                                    ui.ctx().open_url(egui::OpenUrl::new_tab(e.url()));
                                    ui.close();
                                }
                                if ui.button("Copy the address").clicked() {
                                    ui.ctx().copy_text(e.url());
                                    ui.close();
                                }
                            });
                        }
                    }
                }
                if more_entries > 0 {
                    p.text(egui::pos2(col.0, area.bottom()), egui::Align2::LEFT_BOTTOM, format!("and {more_entries} more in Network"), FontId::proportional(z(11.0)), TEXT_PLACEHOLDER());
                }
            }
            let dcol = shift(c.door);
            if doors.is_empty() && look.doors {
                label_at(ui, &p, egui::pos2(dcol.0, mid_y), match &services {
                    Some(_) => "no service sends traffic here",
                    None if self.refused(&sel.ctx, Kind::Services) => "can't read services",
                    None => "reading services…",
                }, 11.5, TEXT_PLACEHOLDER(), dcol.1 + u(20.0));
            }
            for (i, (name, ports, ways)) in doors.iter().enumerate() {
                let r = place(i, doors.len(), dcol);
                let col = if ready { PRIMARY_TEXT() } else { TEXT_PLACEHOLDER() };
                stream(&p, r.right_center(), rim(i, doors.len(), body.left()), col, time * 0.35 + i as f32 * 0.27, if ready { 2 } else { 0 }, ready);
                // Without room for the ways in, they're in the tip.
                let tip = format!("{name}{}", ways.iter().map(|e| format!("\n{} {}: {}", e.kind(), e.name, e.address())).collect::<String>());
                if small(ui, r, name, &format!("service, port {ports}"), col, ("door", i), true, &tip).clicked() {
                    go = Some(Go::Object(obj(Kind::Services, name)));
                }
            }
            if more_doors > 0 {
                p.text(egui::pos2(dcol.0, area.bottom()), egui::Align2::LEFT_BOTTOM, format!("and {more_doors} more services"), FontId::proportional(z(11.0)), TEXT_PLACEHOLDER());
            }
            for (i, hold) in holds.iter().enumerate() {
                let r = place(i, holds.len(), shift(c.hold));
                let cc = match hold.fill {
                    Some(f) if f >= 0.9 => DANGER(),
                    Some(f) if f >= 0.75 => WARNING(),
                    _ => hold.col,
                };
                let disk = matches!(&hold.act, Act::Go(s) if s.kind == Kind::PersistentVolumeClaims);
                stream(&p, rim(i, holds.len(), body.right()), r.left_center(), cc, time * 0.2 + i as f32 * 0.31, (running && disk) as usize, true);
                let tip = match &hold.act {
                    Act::List(l) => format!("{}\nClick to choose", l.iter().take(12).map(|x| x.0.as_str()).collect::<Vec<_>>().join("\n")),
                    _ => hold.name.clone(),
                };
                let resp = small(ui, r, &hold.name, &hold.sub, cc, ("hold", i), !matches!(hold.act, Act::None), &tip);
                match &hold.act {
                    Act::None => {}
                    Act::Go(s) => {
                        if resp.clicked() {
                            go = Some(Go::Object(s.clone()));
                        }
                    }
                    Act::Tab(t) => {
                        if resp.clicked() {
                            go = Some(Go::Tab(*t));
                        }
                    }
                    Act::List(l) => {
                        egui::Popup::menu(&resp).show(|ui| {
                            ui.set_width(u(400.0));
                            egui::ScrollArea::vertical().max_height(u(380.0)).show(ui, |ui| {
                                ui.spacing_mut().item_spacing.y = 0.0;
                                for (name, how, to) in l {
                                    // The whole line is the button.
                                    let (r, resp) = dash::line(ui, u(27.0), true);
                                    let g = ui.painter().layout_no_wrap(how.clone(), FontId::proportional(z(11.5)), TEXT_SUBTLE());
                                    let hw = g.size().x;
                                    ui.painter().galley(egui::pos2(r.right() - hw, r.center().y - g.size().y / 2.0), g, TEXT_SUBTLE());
                                    label_at(ui, ui.painter(), r.left_center(), name, 13.0, PRIMARY_TEXT(), r.width() - hw - 16.0);
                                    if resp.on_hover_text(name).clicked() {
                                        go = Some(Go::Object(to.clone()));
                                        ui.close();
                                    }
                                }
                            });
                        });
                    }
                }
                if let Some(f) = hold.fill {
                    let b = egui::Rect::from_min_size(egui::pos2(r.left() + 10.0, r.bottom() - 4.0), egui::vec2((r.width() - 20.0) * f.clamp(0.0, 1.0) as f32, 2.5));
                    ui.painter().rect_filled(b, CornerRadius::same(1), cc);
                }
            }
            if let Some(s) = inside(ui, &p, body, time) {
                go = Some(Go::Object(s));
            }
        });
        go
    }

    /// Init containers as beads along the top, and the containers as tanks.
    #[allow(clippy::too_many_arguments)]
    fn xray_tanks(&self, ui: &mut Ui, p: &egui::Painter, o: &Value, body: egui::Rect, gap: f32, shown: usize, time: f32) {
        let cs = containers(o);
        let latest = self.pod.tops.back();
        // Init containers as a row of beads along the top of the skin.
        let inits = o["spec"]["initContainers"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
        for (i, c) in inits.iter().enumerate() {
            let name = c["name"].as_str().unwrap_or("");
            let s = status_of(o, "initContainerStatuses", name);
            let (word, t) = pod::state_word(s);
            let done = s.map(|s| s["state"]["terminated"]["exitCode"] == 0).unwrap_or(false);
            let at = egui::pos2(body.center().x + (i as f32 - (inits.len() as f32 - 1.0) / 2.0) * u(18.0), body.top() + u(13.0));
            let col = if done { SUCCESS() } else { tone_color(t) };
            p.circle_filled(at, u(5.0), col.gamma_multiply(0.8));
            ui.interact(egui::Rect::from_center_size(at, egui::vec2(u(16.0), u(16.0))), egui::Id::new(("xray-init", i)), Sense::hover()).on_hover_text(format!("{} {name}: {word}", if c["restartPolicy"] == "Always" { "sidecar" } else { "before the start:" }));
        }
        // The tanks.
        let n = cs.len();
        let inner = egui::Rect::from_min_max(egui::pos2(body.left() + 22.0, body.top() + u(if inits.is_empty() { 14.0 } else { 26.0 })), egui::pos2(body.right() - 22.0, body.bottom() - u(12.0)));
        let tw = ((inner.width() - gap * (shown.max(1) as f32 - 1.0)) / shown.max(1) as f32).min(u(260.0));
        let x0 = inner.center().x - (tw * shown as f32 + gap * (shown as f32 - 1.0)) / 2.0;
        for (i, c) in cs.iter().take(shown).enumerate() {
            let name = c["name"].as_str().unwrap_or("");
            let s = status_of(o, "containerStatuses", name);
            let (word, t) = pod::state_word(s);
            let (cr, cl, mr, ml) = pod::asks(c);
            let u_ = latest.and_then(|l| l.1.get(name)).copied();
            let r = egui::Rect::from_min_size(egui::pos2(x0 + i as f32 * (tw + gap), inner.top()), egui::vec2(tw, inner.height()));
            let col = tone_color(t);
            p.rect_filled(r, CornerRadius::same(14), BG_DEFAULT());
            let cap = if ml > 0.0 { ml } else { mr };
            let frac = u_.filter(|_| cap > 0.0).map(|x| x.1 / cap);
            if let Some(f) = frac {
                let hot = if ml > 0.0 { hive::heat(f) } else { hive::heat(f.min(0.6)) };
                let cpu = u_.map(|x| x.0 / cl.max(cr).max(1.0)).unwrap_or(0.0).clamp(0.02, 1.0) as f32;
                pod::tank(p, r.shrink(2.0), f as f32, hot, time, cpu, i as f32);
            }
            // Nothing to measure against: a puddle.
            if frac.is_none() && u_.is_some() {
                pod::tank(p, r.shrink(2.0), 0.07, TEXT_SUBTLE(), time, 0.02, i as f32);
            }
            if mr > 0.0 && ml > mr {
                let y = r.bottom() - r.height() * (mr / ml) as f32;
                p.extend(egui::Shape::dashed_line(&[egui::pos2(r.left() + 4.0, y), egui::pos2(r.right() - 4.0, y)], Stroke::new(1.0, TEXT_SUBTLE()), 4.0, 4.0));
            }
            p.rect_stroke(r, CornerRadius::same(14), Stroke::new(1.6, col.gamma_multiply(0.8)), egui::StrokeKind::Inside);
            let mid = |dy: f32, text: &str, size: f32, c: Color32| {
                let t = fit(ui, text, tw - 14.0, z(size));
                let g = p.layout_no_wrap(t, FontId::proportional(z(size)), c);
                let at = egui::pos2(r.center().x - g.size().x / 2.0, r.center().y + dy - g.size().y / 2.0);
                p.rect_filled(egui::Rect::from_min_size(at, g.size()).expand2(egui::vec2(6.0, 1.0)), CornerRadius::same(6), BG_DEFAULT().gamma_multiply(0.72));
                p.galley(at, g, c);
            };
            mid(-u(38.0), name, 13.0, TEXT_DEFAULT());
            mid(-u(17.0), &word, 11.0, col);
            match u_ {
                Some((cpu, mem)) => {
                    mid(u(8.0), &format!("{}{}", gib(mem), if cap > 0.0 { format!(" of {}", gib(cap)) } else { String::new() }), 12.5, TEXT_DEFAULT());
                    mid(u(29.0), &format!("{} CPU", hive::cores(cpu)), 11.5, TEXT_MUTED());
                    if ml <= 0.0 {
                        mid(u(48.0), "no memory limit", 10.5, TEXT_SUBTLE());
                    }
                }
                None => mid(u(10.0), "no usage yet", 11.0, TEXT_PLACEHOLDER()),
            }
        }
        if n > shown {
            p.text(egui::pos2(body.center().x, body.bottom() - u(8.0)), egui::Align2::CENTER_CENTER, format!("and {} more containers", n - shown), FontId::proportional(z(11.0)), TEXT_PLACEHOLDER());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ways_in() {
        let r = serde_json::json!({"metadata": {"name": "r"}, "spec": {"host": "a.example", "path": "/x", "tls": {"key": "PRIVATE", "termination": "edge"}, "to": {"kind": "Service", "name": "s", "weight": 90}, "alternateBackends": [{"kind": "Service", "name": "t"}], "wildcardPolicy": "None"},
            "status": {"ingress": [{"conditions": [{"type": "Admitted", "status": "True"}]}]}});
        let e = pick_route(&r);
        assert_eq!(e.iter().map(|e| e.service.as_str()).collect::<Vec<_>>(), vec!["s", "t"]);
        assert_eq!((e[0].url().as_str(), e[0].taken, e[0].plain), ("https://a.example/x", true, true));
        // Nothing of the key is kept.
        assert!(!pack(&e, true).contains("PRIVATE"));
        assert_eq!(unpack(&pack(&e, false)).unwrap(), (e, false));
        let w = serde_json::json!({"metadata": {"name": "w"}, "spec": {"host": "x.apps.example", "to": {"name": "s"}, "wildcardPolicy": "Subdomain"}});
        let w = pick_route(&w);
        assert_eq!((w[0].host.as_str(), w[0].plain, w[0].taken), ("*.apps.example", false, false));
        let i = serde_json::json!({"metadata": {"name": "i"}, "spec": {"defaultBackend": {"service": {"name": "d"}}, "tls": [{"hosts": ["h"]}], "rules": [{"host": "h", "http": {"paths": [{"path": "/a(/|$)(.*)", "backend": {"service": {"name": "s"}}}, {"path": "/", "backend": {"resource": {}}}]}}, {"http": {"paths": [{"backend": {"service": {"name": "s"}}}]}}]}, "status": {"loadBalancer": {"ingress": [{"ip": "1"}]}}});
        let l = pick_ingress(&i);
        assert_eq!(l.iter().map(|e| (e.service.as_str(), e.host.as_str(), e.tls, e.plain)).collect::<Vec<_>>(), vec![("d", "any host", false, false), ("s", "h", true, false), ("s", "any host", false, false)]);
        let h = serde_json::json!({"metadata": {"name": "g"}, "spec": {"hostnames": ["a", "b"], "rules": [{"matches": [{"path": {"value": "/v1"}}], "backendRefs": [{"name": "s"}, {"kind": "Other", "name": "o"}]}]}});
        assert_eq!(pick_http(&h).iter().map(|e| e.address()).collect::<Vec<_>>(), vec!["a/v1", "b/v1"]);
        assert!(pick_route(&Value::Null).is_empty() && pick_http(&Value::Null).is_empty() && pick_ingress(&Value::Null).is_empty());
    }

    #[test]
    fn what_it_holds() {
        let p = serde_json::json!({"spec": {"imagePullSecrets": [{"name": "reg"}], "volumes": [{"name": "kube-api-access-x", "projected": {"sources": [{"configMap": {"name": "kube-root-ca.crt"}}]}}, {"name": "c", "configMap": {"name": "conf"}}],
            "containers": [{"envFrom": [{"configMapRef": {"name": "conf"}}, {"secretRef": {"name": "s"}}], "volumeMounts": [{"name": "kube-api-access-x"}, {"name": "c"}]}]}});
        assert_eq!(used(&p, "configmap"), vec![("conf".to_string(), "as variables, files".to_string())]);
        assert_eq!(used(&p, "secret"), vec![("s".to_string(), "as variables".to_string()), ("reg".to_string(), "to fetch images".to_string())]);
    }

    #[test]
    fn layout() {
        for s in [1.0, 1.6] {
            for w in [300.0, 620.0, 900.0, 1400.0, 2400.0] {
                for n in 1..=6 {
                    for (e, d, h) in [(true, true, true), (false, true, true), (false, false, true), (false, false, false), (true, true, false)] {
                        let room = |t: f32| n as f32 * t * s + 14.0 * (n as f32 - 1.0) + 44.0;
                        let c = columns(w, e, d, h, room(230.0), room(80.0), s);
                        // In order, not overlapping.
                        let mut x = 0.0;
                        for (l, cw) in c.entry.into_iter().chain([c.door, c.body, c.hold]) {
                            assert!(l >= x - 0.01 && cw >= 0.0, "{w} {n} {c:?}");
                            x = l + cw;
                        }
                        if w >= 1400.0 && s == 1.0 {
                            assert!(x <= w + 0.01, "{w} {n} {c:?}");
                        }
                        assert!(c.body.1 <= room(230.0) + 0.01);
                    }
                }
            }
        }
        // One container: a narrow pod, in the middle.
        let c = columns(1600.0, false, true, true, 304.0, 124.0, 1.0);
        assert!(c.body.1 == 304.0 && c.door.0 > 100.0, "{c:?}");
        // No room: the ways in go first.
        assert!(columns(500.0, true, true, true, 304.0, 124.0, 1.0).entry.is_none());
        assert!(columns(900.0, true, true, true, 304.0, 124.0, 1.0).entry.is_some());
    }
}
