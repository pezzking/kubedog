//! Themes: colour palettes and text sizes.

use eframe::egui::{self, Color32, CornerRadius, FontFamily, FontId, Stroke, TextStyle};

use std::sync::atomic::{AtomicU8, Ordering};

/// One theme's colours.
pub struct Palette {
    pub bg_default: Color32,
    pub bg_subtle: Color32,
    pub bg_muted: Color32,
    pub bg_strong: Color32,
    pub bg_card: Color32,
    pub bg_selected: Color32,
    pub bg_hover: Color32,
    pub border_subtle: Color32,
    pub border_default: Color32,
    pub text_default: Color32,
    pub text_muted: Color32,
    pub text_subtle: Color32,
    pub text_placeholder: Color32,
    pub success: Color32,
    pub warning: Color32,
    pub danger: Color32,
    pub info: Color32,
    pub cpu_bar: Color32,
    pub danger_bg: Color32,
    /// Behind log lines.
    pub log_bg: Color32,
    /// Behind a warning banner ("couldn't list ...").
    pub warn_bg: Color32,
    /// Behind an error message (toasts).
    pub error_bg: Color32,
    pub dark: bool,
}

const fn c(hex: u32) -> Color32 {
    Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

pub static DARK: Palette = Palette {
    bg_default: c(0x1f2023),
    bg_subtle: c(0x191a1d),
    bg_muted: c(0x303236),
    bg_strong: c(0x41434c),
    bg_card: c(0x27282b),
    bg_selected: c(0x41434c),
    bg_hover: c(0x2a2b2f),
    border_subtle: c(0x303236),
    border_default: c(0x3c3e44),
    text_default: c(0xf7f8f8),
    text_muted: c(0xd4d5d6),
    text_subtle: c(0x8a8f98),
    text_placeholder: c(0x697281),
    success: c(0x4cb782),
    warning: c(0xe9b306),
    danger: c(0xeb5757), // estimated
    info: c(0xa78bfa),   // violet, estimated
    cpu_bar: c(0x4b74e0), // estimated
    danger_bg: c(0xc02626),
    log_bg: c(0x191a1d),
    warn_bg: c(0x3a2a10),
    error_bg: c(0x460809),
    dark: true,
};

pub static LIGHT: Palette = Palette {
    bg_default: c(0xf7f7f8),
    bg_subtle: c(0xefeff1),
    bg_muted: c(0xe6e7ea),
    bg_strong: c(0xd6d8de),
    bg_card: c(0xffffff),
    bg_selected: c(0xdfe2e8),
    bg_hover: c(0xedeef1),
    border_subtle: c(0xe2e3e7),
    border_default: c(0xcdd0d6),
    text_default: c(0x1c1d21),
    text_muted: c(0x3b3e45),
    text_subtle: c(0x6b707a),
    text_placeholder: c(0x969ba5),
    success: c(0x1d9460),
    warning: c(0xb07d00),
    danger: c(0xd23c3c),
    info: c(0x7651d6),
    cpu_bar: c(0x4b74e0),
    danger_bg: c(0xc02626),
    log_bg: c(0xf1f2f4),
    warn_bg: c(0xfff3d4),
    error_bg: c(0xfde2e2),
    dark: false,
};

pub static SAND: Palette = Palette {
    bg_default: c(0xf2ebde),
    bg_subtle: c(0xebe2d2),
    bg_muted: c(0xe2d7c3),
    bg_strong: c(0xd5c7ad),
    bg_card: c(0xf9f4ea),
    bg_selected: c(0xe0d2ba),
    bg_hover: c(0xeadfcc),
    border_subtle: c(0xdfd2bb),
    border_default: c(0xcbba9b),
    text_default: c(0x2d2518),
    text_muted: c(0x493e2c),
    text_subtle: c(0x786a52),
    text_placeholder: c(0x9f9077),
    success: c(0x3b8a55),
    warning: c(0xa47206),
    danger: c(0xbf3a2c),
    info: c(0x7a5cbd),
    cpu_bar: c(0x4a6cc4),
    danger_bg: c(0xb5332a),
    log_bg: c(0xece3d2),
    warn_bg: c(0xf4e2bc),
    error_bg: c(0xf3d6cf),
    dark: false,
};

/// The themes Settings offers: (setting value, label). Auto follows the system's dark or light.
pub const THEMES: [(&str, &str); 4] = [("auto", "Auto"), ("dark", "Dark"), ("light", "Light"), ("sand", "Sand")];

/// A colour for names, links, buttons and highlights, chosen apart from the theme. Each theme has
/// its own shade of it: (button, text).
pub struct Accent {
    pub id: &'static str,
    pub label: &'static str,
    dark: (u32, u32),
    light: (u32, u32),
    sand: (u32, u32),
}

pub static ACCENTS: [Accent; 7] = [
    Accent { id: "orange", label: "Orange", dark: (0xe0620e, 0xff983f), light: (0xdd5f0b, 0xbb5206), sand: (0xbf5617, 0xb24a0b) },
    Accent { id: "blue", label: "Blue", dark: (0x3b5fd9, 0x57a6ff), light: (0x2f62d8, 0x1f5fd0), sand: (0x2f5fb8, 0x2458ad) },
    Accent { id: "green", label: "Green", dark: (0x2f8f4e, 0x8fd46a), light: (0x2c8a48, 0x2f7d1f), sand: (0x4a7d2c, 0x44721f) },
    Accent { id: "teal", label: "Teal", dark: (0x16898c, 0x45cfcf), light: (0x0e7f86, 0x0b7580), sand: (0x1c7a78, 0x146e6c) },
    Accent { id: "purple", label: "Purple", dark: (0x7a52d6, 0xb79bff), light: (0x6d44cf, 0x6a3fcb), sand: (0x6f4fae, 0x664399) },
    Accent { id: "pink", label: "Pink", dark: (0xcf3f83, 0xff8fc0), light: (0xc93579, 0xb92a6c), sand: (0xb03d6c, 0xa5315f) },
    Accent { id: "grey", label: "Grey", dark: (0x5d626d, 0xcdd2db), light: (0x4d525c, 0x3b404a), sand: (0x6b5d45, 0x584a33) },
];

/// An accent as one theme shows it.
#[derive(Clone, Copy)]
pub struct Tint {
    pub primary: Color32,
    pub primary_disabled: Color32,
    pub primary_text: Color32,
    /// Selected text.
    pub selection: Color32,
    /// A picked cluster on the start page.
    pub picked_bg: Color32,
}

fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let m = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(m(a.r(), b.r()), m(a.g(), b.g()), m(a.b(), b.b()))
}

impl Accent {
    pub fn tint(&self, theme: &str) -> Tint {
        let pal = palette_of(theme);
        let (button, text) = match theme {
            "light" => self.light,
            "sand" => self.sand,
            _ => self.dark,
        };
        let (primary, primary_text) = (c(button), c(text));
        Tint {
            primary,
            primary_text,
            primary_disabled: mix(pal.bg_default, primary, 0.34),
            selection: mix(pal.bg_default, primary, 0.40),
            picked_bg: mix(pal.bg_card, primary, if pal.dark { 0.16 } else { 0.11 }),
        }
    }
}

static THEME: AtomicU8 = AtomicU8::new(0);
static ACCENT: AtomicU8 = AtomicU8::new(0);

/// Show a theme ("dark", "light" or "sand") with an accent.
pub fn set_look(theme: &str, accent: &str) {
    THEME.store(match theme { "light" => 1, "sand" => 2, _ => 0 }, Ordering::Relaxed);
    ACCENT.store(ACCENTS.iter().position(|a| a.id == accent).unwrap_or(0) as u8, Ordering::Relaxed);
}

/// The theme being shown.
pub fn theme_name() -> &'static str {
    match THEME.load(Ordering::Relaxed) {
        1 => "light",
        2 => "sand",
        _ => "dark",
    }
}

pub fn palette_of(theme: &str) -> &'static Palette {
    match theme {
        "light" => &LIGHT,
        "sand" => &SAND,
        _ => &DARK,
    }
}

pub fn palette() -> &'static Palette {
    palette_of(theme_name())
}

pub fn tint() -> Tint {
    ACCENTS[(ACCENT.load(Ordering::Relaxed) as usize).min(ACCENTS.len() - 1)].tint(theme_name())
}

/// What a saved theme means: themes used to carry their colour ("darkblue").
pub fn read_look(theme: Option<&str>, accent: Option<&str>) -> (String, String) {
    let (theme, implied) = match theme {
        Some("darkblue") => ("dark", "blue"),
        Some(t) if THEMES.iter().any(|x| x.0 == t) => (t, "orange"),
        _ => ("dark", "orange"),
    };
    let accent = accent.filter(|a| ACCENTS.iter().any(|x| x.id == *a)).unwrap_or(implied);
    (theme.to_string(), accent.to_string())
}

macro_rules! colours {
    ($($name:ident => $field:ident),* $(,)?) => {
        $(
            #[allow(non_snake_case)]
            #[inline]
            pub fn $name() -> Color32 {
                palette().$field
            }
        )*
    };
}

colours! {
    BG_DEFAULT => bg_default, BG_SUBTLE => bg_subtle, BG_MUTED => bg_muted, BG_STRONG => bg_strong,
    BG_CARD => bg_card, BG_SELECTED => bg_selected, BG_HOVER => bg_hover,
    BORDER_SUBTLE => border_subtle, BORDER_DEFAULT => border_default,
    TEXT_DEFAULT => text_default, TEXT_MUTED => text_muted, TEXT_SUBTLE => text_subtle, TEXT_PLACEHOLDER => text_placeholder,
    SUCCESS => success, WARNING => warning, DANGER => danger, INFO => info,
    CPU_BAR => cpu_bar, MEM_BAR => success, DANGER_BG => danger_bg,
    LOG_BG => log_bg, WARN_BG => warn_bg, ERROR_BG => error_bg,
}

macro_rules! tints {
    ($($name:ident => $field:ident),* $(,)?) => {
        $(
            #[allow(non_snake_case)]
            #[inline]
            pub fn $name() -> Color32 {
                tint().$field
            }
        )*
    };
}

tints! {
    PRIMARY => primary, PRIMARY_DISABLED => primary_disabled, PRIMARY_TEXT => primary_text, PICKED_BG => picked_bg,
}

pub fn tone_color(t: crate::resources::Tone) -> Color32 {
    use crate::resources::Tone::*;
    match t {
        Normal => TEXT_DEFAULT(),
        Muted => TEXT_MUTED(),
        Success => SUCCESS(),
        Warning => WARNING(),
        Danger => DANGER(),
        Info => INFO(),
        Link => PRIMARY_TEXT(),
    }
}

pub fn install(ctx: &egui::Context) {
    let pal = palette();
    let mut v = if pal.dark { egui::Visuals::dark() } else { egui::Visuals::light() };
    v.panel_fill = BG_DEFAULT();
    v.window_fill = BG_DEFAULT();
    v.extreme_bg_color = BG_DEFAULT(); // text boxes are outlined, not filled
    v.faint_bg_color = BG_CARD();
    v.code_bg_color = BG_MUTED();
    v.window_stroke = Stroke::new(1.0, BORDER_DEFAULT());
    v.window_corner_radius = CornerRadius::same(8);
    v.menu_corner_radius = CornerRadius::same(6);
    v.override_text_color = None;
    v.hyperlink_color = PRIMARY_TEXT();
    v.selection.bg_fill = tint().selection;
    v.selection.stroke = Stroke::new(1.0, PRIMARY_TEXT());
    let r = CornerRadius::same(6);
    v.widgets.noninteractive.bg_fill = BG_DEFAULT();
    v.widgets.noninteractive.weak_bg_fill = BG_DEFAULT();
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER_SUBTLE());
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_MUTED());
    v.widgets.inactive.bg_fill = BG_MUTED();
    v.widgets.inactive.weak_bg_fill = BG_MUTED();
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER_DEFAULT());
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT_MUTED());
    v.widgets.inactive.corner_radius = r;
    v.widgets.hovered.bg_fill = BG_STRONG();
    v.widgets.hovered.weak_bg_fill = BG_STRONG();
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, BORDER_DEFAULT());
    v.widgets.hovered.fg_stroke = Stroke::new(1.0, TEXT_DEFAULT());
    v.widgets.hovered.corner_radius = r;
    v.widgets.active.bg_fill = BG_STRONG();
    v.widgets.active.weak_bg_fill = BG_STRONG();
    v.widgets.active.fg_stroke = Stroke::new(1.0, TEXT_DEFAULT());
    v.widgets.active.corner_radius = r;
    v.widgets.open.bg_fill = BG_MUTED();
    v.widgets.open.weak_bg_fill = BG_MUTED();
    v.widgets.open.corner_radius = r;
    v.striped = true;
    // The window itself isn't forced dark or light: macOS would then stop telling us when the
    // system changes, which Auto needs.
    ctx.options_mut(|o| o.sync_window_theme = false);
    ctx.set_theme(if pal.dark { egui::Theme::Dark } else { egui::Theme::Light });
    ctx.set_visuals_of(egui::Theme::Dark, v.clone());
    ctx.set_visuals_of(egui::Theme::Light, v);

    // The app's text is drawn at CONTENT_SCALE; the sidebar and the start page's list keep 1.0.
    let content = CONTENT_SCALE * factor();
    set_text_scale(content);
    ctx.all_styles_mut(|s| {
        s.text_styles = text_styles(content);
        s.spacing.item_spacing = egui::vec2(8.0, 5.0);
        s.spacing.button_padding = egui::vec2(10.0, 4.0);
        s.spacing.interact_size.y = u(24.0);
        // No bounce at the edges of scrolling lists (the trackpad "rubber band"), and a slightly
        // shorter coast after a swipe.
        s.spacing.scroll.kinetic.rubber_band = false;
        s.spacing.scroll.kinetic.decay_time = 0.35;
    });
}

/// How much bigger text outside the sidebar is than the base sizes written in the code.
pub const CONTENT_SCALE: f32 = 1.11;

/// The text sizes Settings offers, and the one everything was designed at.
pub const TEXT_SIZES: [u8; 7] = [12, 13, 14, 15, 16, 18, 20];
pub const NORMAL_TEXT: u8 = 16;

static TEXT_SIZE: AtomicU8 = AtomicU8::new(NORMAL_TEXT);

pub fn set_text_size(size: u8) {
    TEXT_SIZE.store(size, Ordering::Relaxed);
}

/// How much bigger than designed the chosen text size makes everything.
pub fn factor() -> f32 {
    TEXT_SIZE.load(Ordering::Relaxed) as f32 / NORMAL_TEXT as f32
}

/// A row height (or another length) that has to follow the chosen text size.
pub fn u(length: f32) -> f32 {
    length * factor()
}

/// The fonts Settings offers: (setting value, label). Ubuntu comes with egui; the others are in
/// assets/fonts, each with its licence (SIL Open Font License).
pub const FONTS: [(&str, &str); 5] = [
    ("ubuntu", "Ubuntu"),
    ("inter", "Inter"),
    ("plex", "IBM Plex Sans"),
    ("atkinson", "Atkinson Hyperlegible"),
    ("jetbrains", "JetBrains Mono"),
];

static FONT_FILES: [(&str, &[u8]); 4] = [
    ("inter", include_bytes!("../assets/fonts/Inter.ttf")),
    ("plex", include_bytes!("../assets/fonts/IBMPlexSans.ttf")),
    ("atkinson", include_bytes!("../assets/fonts/AtkinsonHyperlegible.ttf")),
    ("jetbrains", include_bytes!("../assets/fonts/JetBrainsMono.ttf")),
];

/// A font by its own name, to show it in its own letters.
pub fn font_family(id: &str) -> FontFamily {
    FontFamily::Name(format!("font-{id}").into())
}

/// Make a font the app's text (JetBrains Mono also takes over code, logs and the terminal).
/// egui's own fonts stay behind it, for symbols it doesn't have.
pub fn install_font(ctx: &egui::Context, id: &str) {
    ctx.set_fonts(font_definitions(id));
}

/// The font without its glyph substitutions (the GSUB table, hidden by renaming its entry): they
/// would show other characters than the ones in a name ("6x5" as "6×5", "->" as an arrow).
fn without_substitutions(font: &[u8]) -> Vec<u8> {
    let mut f = font.to_vec();
    let n = if f.len() > 12 { u16::from_be_bytes([f[4], f[5]]) as usize } else { 0 };
    for i in 0..n {
        let at = 12 + 16 * i;
        if f.get(at..at + 4) == Some(b"GSUB") {
            // Still in alphabetical order, as the table of contents must be.
            f[at + 3] = b'X';
        }
    }
    f
}

/// Arrows, ticks, triangles and the like, for every system: what isn't in a font here is looked for among the
/// system's own fonts, and Windows and Linux don't have all of them. Not changed in any way (its licence asks that).
const SYMBOLS: &[u8] = include_bytes!("../assets/fonts/DejaVuSans.ttf");

fn font_definitions(id: &str) -> egui::FontDefinitions {
    let mut f = egui::FontDefinitions::default();
    f.font_data.insert("symbols".into(), std::sync::Arc::new(egui::FontData::from_static(SYMBOLS)));
    // After the letters, before egui's emoji.
    for family in f.families.values_mut() {
        let at = family.iter().position(|n| n == "Ubuntu-Light").map(|i| i + 1).unwrap_or(family.len());
        family.insert(at, "symbols".into());
    }
    let usual = f.families.get(&FontFamily::Proportional).cloned().unwrap_or_default();
    f.families.insert(font_family("ubuntu"), usual.clone());
    for (name, bytes) in FONT_FILES {
        f.font_data.insert(name.to_string(), std::sync::Arc::new(egui::FontData::from_owned(without_substitutions(bytes))));
        let mut family = vec![name.to_string()];
        family.extend(usual.iter().cloned());
        f.families.insert(font_family(name), family);
        if name == id {
            f.families.entry(FontFamily::Proportional).or_default().insert(0, name.to_string());
            if name == "jetbrains" {
                f.families.entry(FontFamily::Monospace).or_default().insert(0, name.to_string());
            }
        }
    }
    f
}

thread_local! {
    static TEXT_SCALE: std::cell::Cell<f32> = const { std::cell::Cell::new(1.0) };
}

fn set_text_scale(scale: f32) {
    TEXT_SCALE.with(|s| s.set(scale));
}

/// A text size (or a length that has to follow it) in the part of the window being drawn.
pub fn z(size: f32) -> f32 {
    size * TEXT_SCALE.with(|s| s.get())
}

fn text_styles(k: f32) -> std::collections::BTreeMap<TextStyle, FontId> {
    [
        (TextStyle::Heading, FontId::new(18.0 * k, FontFamily::Proportional)),
        (TextStyle::Body, FontId::new(13.5 * k, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(12.5 * k, FontFamily::Monospace)),
        (TextStyle::Button, FontId::new(13.5 * k, FontFamily::Proportional)),
        (TextStyle::Small, FontId::new(11.0 * k, FontFamily::Proportional)),
    ]
    .into()
}

/// Draw part of the window at the base text sizes (the sidebar, the start page's cluster list).
pub fn base_size<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let before = TEXT_SCALE.with(|s| s.get());
    set_text_scale(factor());
    ui.style_mut().text_styles = text_styles(factor());
    let r = add(ui);
    set_text_scale(before);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contrast(a: Color32, b: Color32) -> f32 {
        let lum = |c: Color32| {
            let f = |v: u8| {
                let v = v as f32 / 255.0;
                if v <= 0.03928 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) }
            };
            0.2126 * f(c.r()) + 0.7152 * f(c.g()) + 0.0722 * f(c.b())
        };
        let (x, y) = (lum(a), lum(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }

    #[test]
    fn every_colour_is_readable_in_every_theme() {
        for a in &ACCENTS {
            for t in ["dark", "light", "sand"] {
                let (p, tint) = (palette_of(t), a.tint(t));
                for bg in [p.bg_default, p.bg_card] {
                    let r = contrast(tint.primary_text, bg);
                    assert!(r >= 4.3, "{} text in {t}: {r:.2}", a.id);
                }
                let r = contrast(Color32::WHITE, tint.primary);
                assert!(r >= 3.4, "{} button in {t}: {r:.2}", a.id);
            }
        }
    }

    #[test]
    fn no_substitutions() {
        for (name, bytes) in FONT_FILES {
            let f = without_substitutions(bytes);
            let tags = |d: &[u8]| -> Vec<Vec<u8>> { (0..u16::from_be_bytes([d[4], d[5]]) as usize).map(|i| d[12 + 16 * i..16 + 16 * i].to_vec()).collect() };
            assert!(tags(bytes).iter().any(|t| t == b"GSUB"), "{name}");
            let t = tags(&f);
            assert!(!t.iter().any(|t| t == b"GSUB"), "{name}");
            assert!(t.windows(2).all(|w| w[0] < w[1]), "{name}");
        }
    }

    /// Every symbol written on screen is in a font that comes with Kubedog, so no system's own fonts are needed.
    #[test]
    fn fonts_have_every_symbol_on_screen() {
        fn files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    files(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        let mut l = vec![];
        files(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut l);
        let mut used = std::collections::BTreeSet::new();
        for p in l {
            let text = std::fs::read_to_string(&p).unwrap();
            // What tests write isn't drawn; neither is a comment.
            let text = text.split("#[cfg(test)]\nmod tests").next().unwrap_or("");
            for line in text.lines().filter(|l| !l.trim_start().starts_with("//")) {
                used.extend(line.chars().filter(|c| *c as u32 >= 0x2000 && !('\u{e000}'..='\u{f8ff}').contains(c)));
            }
        }
        assert!(used.contains(&'★') && used.len() > 30, "{used:?}");
        for (id, _) in FONTS {
            let ctx = egui::Context::default();
            install_font(&ctx, id);
            let mut missing = String::new();
            let mut out = ctx.run_ui(egui::RawInput::default(), |ui| {
                let font = FontId::new(14.0, FontFamily::Proportional);
                missing = used.iter().filter(|c| !ui.ctx().fonts_mut(|f| f.has_glyph(&font, **c))).map(|c| format!("{c} U+{:04X} ", *c as u32)).collect();
                // The check itself works: this one is in none of them.
                assert!(!ui.ctx().fonts_mut(|f| f.has_glyph(&font, '\u{2315}')));
            });
            out.textures_delta.clear();
            assert_eq!(missing, "", "{id}: no font of Kubedog's own has these");
        }
    }

    #[test]
    fn fonts_have_the_letters() {
        for (id, _) in FONTS {
            let ctx = egui::Context::default();
            install_font(&ctx, id);
            let mut checked = false;
            for _ in 0..2 {
                let mut out = ctx.run_ui(egui::RawInput::default(), |ui| {
                    for fam in [FontFamily::Proportional, font_family(id)] {
                        let font = FontId::new(14.0, fam);
                        let missing: String = "Kubedog éüß 0123/…·-_".chars().filter(|c| !ui.ctx().fonts_mut(|f| f.has_glyph(&font, *c))).collect();
                        assert_eq!(missing, "", "{id}");
                        checked = true;
                    }
                });
                out.textures_delta.clear();
            }
            assert!(checked);
        }
    }

    #[test]
    fn saved_looks() {
        let l = |t, a| read_look(t, a);
        assert_eq!(l(Some("darkblue"), None), ("dark".into(), "blue".into()));
        assert_eq!(l(Some("dark"), None), ("dark".into(), "orange".into()));
        assert_eq!(l(Some("sand"), Some("teal")), ("sand".into(), "teal".into()));
        assert_eq!(l(Some("auto"), Some("nope")), ("auto".into(), "orange".into()));
        assert_eq!(l(None, None), ("dark".into(), "orange".into()));
    }
}
