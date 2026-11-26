//! Terminals: the person's own Mac terminal app, or Kubedog's built-in one.
//!
//! External apps get the command written to a script of its own, then
//! `open -a <app> <script>`; WezTerm is `open -na wezterm --args start --`,
//! Tabby is `open -na Tabby --args run`, Alacritty `--args -e`.
//!
//! The built-in terminal is a pseudo-terminal (portable-pty) whose screen is kept by a
//! VT100 parser (vt100) and drawn by egui, docked at the bottom of the window.

use crate::theme::*;
use eframe::egui::{self, Color32, CornerRadius, FontId, Key, Margin, RichText, Sense, Stroke, Ui};
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Terminal apps Kubedog can use: (setting id, label, app bundle names to look for).
pub(crate) const APPS: &[(&str, &str, &[&str])] = &[
    ("builtin", "Built-in terminal", &[]),
    ("Terminal", "Terminal", &["/System/Applications/Utilities/Terminal.app", "/Applications/Utilities/Terminal.app"]),
    ("iTerm", "iTerm2", &["/Applications/iTerm.app"]),
    ("Ghostty", "Ghostty", &["/Applications/Ghostty.app"]),
    ("Warp", "Warp", &["/Applications/Warp.app"]),
    ("WezTerm", "WezTerm", &["/Applications/WezTerm.app"]),
    ("kitty", "Kitty", &["/Applications/kitty.app"]),
    ("Tabby", "Tabby", &["/Applications/Tabby.app"]),
    ("Alacritty", "Alacritty", &["/Applications/Alacritty.app"]),
];

/// Whether a terminal app is on this Mac.
pub(crate) fn installed(id: &str) -> bool {
    if id == "builtin" {
        return true;
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    APPS.iter().find(|a| a.0 == id).map(|a| {
        a.2.iter().any(|p| {
            std::path::Path::new(p).exists()
                || home.as_ref().map(|h| h.join(p.trim_start_matches('/'))).map(|p| p.exists()).unwrap_or(false)
        })
    }).unwrap_or(false)
}

/// Start `command` (a shell command line) in an external terminal app.
pub(crate) fn launch_external(app: &str, command: &str) -> Result<(), String> {
    let dir = crate::kube::data_dir().ok_or("no home folder")?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // One script per launch so two quick launches can't overwrite each other.
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    let script = dir.join(format!("open-{stamp}.sh"));
    let body = format!("#!/bin/zsh\nrm -f {}\n{}\n", super::sh_quote(&script.to_string_lossy()), command);
    std::fs::write(&script, body).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755));
    }
    let s = script.to_string_lossy().to_string();
    let mut c = std::process::Command::new("/usr/bin/open");
    match app {
        "WezTerm" => c.args(["-na", "WezTerm", "--args", "start", "--", &s]),
        "Tabby" => c.args(["-na", "Tabby", "--args", "run", &s]),
        "Alacritty" => c.args(["-na", "Alacritty", "--args", "-e", &s]),
        other => c.args(["-a", other, &s]),
    };
    c.spawn().map(|_| ()).map_err(|e| format!("could not start {app}: {e}"))
}

/// The program behind a screen.
struct Proc {
    /// Shared with the thread that reads, which answers what programs ask of a terminal.
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
}

struct Session {
    title: String,
    parser: Arc<Mutex<vt100::Parser>>,
    /// None: only a picture of a screen.
    proc: Option<Proc>,
    alive: Arc<AtomicBool>,
    size: (u16, u16),
    scroll: usize,
    /// Scrolling that isn't a whole line yet.
    wheel: f32,
    /// Marked text: (row, column) from and to.
    mark: Option<((u16, u16), (u16, u16))>,
    /// The cluster it was opened for, and a folder of its own that goes with it.
    ctx: String,
    dir: Option<PathBuf>,
}

impl Session {
    fn kill(&mut self) {
        if let Some(p) = &mut self.proc {
            let _ = p.child.kill();
            // Waited for elsewhere: closing a window shouldn't hang on it.
        }
    }
    fn send(&mut self, b: &[u8]) {
        if let Some(p) = &mut self.proc {
            if let Ok(mut w) = p.writer.lock() {
                let _ = w.write_all(b);
                let _ = w.flush();
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.kill();
        if let Some(d) = self.dir.take() {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

/// Finds the questions a program asks a terminal in what it writes, also when one is cut in two.
#[derive(Default)]
struct Asked {
    /// The start of a sequence, while it lasts: "\x1b", "\x1b[", "\x1b[6"...
    part: Vec<u8>,
}

impl Asked {
    /// The next byte; a question is returned with its last byte.
    fn byte(&mut self, b: u8) -> Option<Vec<u8>> {
        if b == 0x1b {
            self.part = vec![b];
            return None;
        }
        match self.part.len() {
            0 => None,
            1 if b == b'[' => {
                self.part.push(b);
                None
            }
            1 => {
                self.part.clear();
                None
            }
            _ if (0x20..0x40).contains(&b) && self.part.len() < 12 => {
                self.part.push(b);
                None
            }
            _ => {
                let mut q = std::mem::take(&mut self.part);
                q.push(b);
                matches!(&q[2..], b"6n" | b"5n" | b"c" | b"0c").then_some(q)
            }
        }
    }
}

/// What a terminal answers, with the cursor where it is (row and column from 0).
fn answer(q: &[u8], at: (u16, u16)) -> Vec<u8> {
    match &q[2..] {
        b"6n" => format!("\x1b[{};{}R", at.0 + 1, at.1 + 1).into_bytes(),
        b"5n" => b"\x1b[0n".to_vec(),
        _ => b"\x1b[?1;2c".to_vec(),
    }
}

/// Text as it's pasted: marked as such when the program asks for that, and nothing in it can end the marking.
fn pasted(t: &str, bracketed: bool) -> Vec<u8> {
    let t = t.replace("\r\n", "\r").replace('\n', "\r");
    if bracketed { format!("\x1b[200~{}\x1b[201~", t.replace("\x1b[201~", "")).into_bytes() } else { t.into_bytes() }
}

/// The docked built-in terminal with its sessions (tabs).
pub(crate) struct Dock {
    sessions: Vec<Session>,
    active: usize,
    pub(crate) open: bool,
    pub(crate) focused: bool,
    height: f32,
    /// The screen size the dock had last time it was drawn (rows, cols).
    last_size: Option<(u16, u16)>,
}

impl Default for Dock {
    fn default() -> Self {
        Dock { sessions: vec![], active: 0, open: false, focused: false, height: 260.0, last_size: None }
    }
}

impl Drop for Dock {
    fn drop(&mut self) {
        self.close_all();
    }
}

impl Dock {
    pub(crate) fn has_sessions(&self) -> bool {
        !self.sessions.is_empty()
    }

    pub(crate) fn close_all(&mut self) {
        for s in &mut self.sessions {
            s.kill();
        }
        self.sessions.clear();
    }

    /// Start `program args` in a new tab. `input` is typed into it once it starts.
    pub(crate) fn spawn(
        &mut self,
        title: String,
        program: &str,
        args: &[String],
        env: &[(String, String)],
        input: Option<String>,
        ctx: &egui::Context,
    ) -> Result<(), String> {
        self.spawn_for(title, program, args, env, input, ctx, String::new(), None)
    }

    /// The same, for a cluster, with a folder that's removed with it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn_for(&mut self, title: String, program: &str, args: &[String], env: &[(String, String)], input: Option<String>, ctx: &egui::Context, cluster: String, dir: Option<PathBuf>) -> Result<(), String> {
        let pty = native_pty_system();
        // Start at the dock's real size so nothing is cut when it first draws.
        let size = self.last_size.unwrap_or_else(|| (((self.height - 46.0) / 15.0).max(5.0) as u16, 160u16));
        let pair = pty
            .openpty(PtySize { rows: size.0, cols: size.1, pixel_width: 0, pixel_height: 0 })
            .map_err(|e| e.to_string())?;
        let mut cmd = CommandBuilder::new(program);
        cmd.args(args);
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        for (k, v) in env {
            cmd.env(k, v);
        }
        if let Some(h) = crate::kube::home() {
            cmd.cwd(h);
        }
        let child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
        let writer = Arc::new(Mutex::new(pair.master.take_writer().map_err(|e| e.to_string())?));
        let parser = Arc::new(Mutex::new(vt100::Parser::new(size.0, size.1, 5000)));
        let alive = Arc::new(AtomicBool::new(true));
        {
            let parser = parser.clone();
            let alive = alive.clone();
            let ctx = ctx.clone();
            let writer = writer.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let mut asked = Asked::default();
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            // Windows' console waits for its first question (where's the cursor?) to be answered
                            // before it shows anything; fish, vim and others ask too.
                            let mut from = 0;
                            let mut out = vec![];
                            if let Ok(mut p) = parser.lock() {
                                for i in 0..n {
                                    if let Some(q) = asked.byte(buf[i]) {
                                        p.process(&buf[from..=i]);
                                        from = i + 1;
                                        out.extend(answer(&q, p.screen().cursor_position()));
                                    }
                                }
                                p.process(&buf[from..n]);
                            }
                            if !out.is_empty() {
                                if let Ok(mut w) = writer.lock() {
                                    let _ = w.write_all(&out);
                                    let _ = w.flush();
                                }
                            }
                            ctx.request_repaint();
                        }
                    }
                }
                alive.store(false, Ordering::SeqCst);
                ctx.request_repaint();
            });
        }
        if let Some(i) = input {
            if let Ok(mut w) = writer.lock() {
                let _ = w.write_all(i.as_bytes());
            }
        }
        self.sessions.push(Session { title, parser, proc: Some(Proc { writer, master: pair.master, child }), alive, size, scroll: 0, wheel: 0.0, mark: None, ctx: cluster, dir });
        self.active = self.sessions.len() - 1;
        self.open = true;
        self.focused = true;
        Ok(())
    }

    /// For pictures: a screen with text and no program behind it.
    pub(crate) fn picture(&mut self, title: &str, cluster: &str, text: &str) {
        let size = self.last_size.unwrap_or((40, 120));
        let mut parser = vt100::Parser::new(size.0, size.1, 1000);
        parser.process(text.replace('\n', "\r\n").as_bytes());
        self.sessions.push(Session { title: title.into(), parser: Arc::new(Mutex::new(parser)), proc: None, alive: Arc::new(AtomicBool::new(true)), size, scroll: 0, wheel: 0.0, mark: None, ctx: cluster.into(), dir: None });
        self.active = self.sessions.len() - 1;
        self.open = true;
    }

    /// Types into the active session, without an Enter.
    pub(crate) fn type_text(&mut self, t: &str) {
        if let Some(s) = self.sessions.get_mut(self.active) {
            s.scroll = 0;
            let t: String = t.chars().filter(|c| !c.is_control()).collect();
            s.send(t.as_bytes());
            self.focused = true;
        }
    }

    /// (title, whether it runs) of every session, and which one is shown.
    pub(crate) fn tabs(&self) -> (Vec<(String, bool)>, usize) {
        (self.sessions.iter().map(|s| (s.title.clone(), s.alive.load(Ordering::SeqCst))).collect(), self.active)
    }

    pub(crate) fn show_tab(&mut self, i: usize) {
        if i < self.sessions.len() {
            self.active = i;
            self.focused = true;
        }
    }

    pub(crate) fn close_tab(&mut self, i: usize) {
        if i >= self.sessions.len() {
            return;
        }
        self.sessions.remove(i);
        if self.active >= self.sessions.len() || (i < self.active) {
            self.active = self.active.saturating_sub(1);
        }
        if self.sessions.is_empty() {
            self.open = false;
            self.focused = false;
        }
    }

    /// The cluster and the folder of the session that's shown.
    pub(crate) fn current(&self) -> Option<(String, Option<PathBuf>)> {
        self.sessions.get(self.active).map(|s| (s.ctx.clone(), s.dir.clone()))
    }

    /// For tests: type with an Enter, and what's on the screen.
    #[cfg(test)]
    pub(crate) fn enter(&mut self, t: &str) {
        let a = self.active;
        self.sessions[a].send(format!("{t}\r").as_bytes());
    }

    #[cfg(test)]
    pub(crate) fn shown(&self) -> String {
        self.sessions[self.active].parser.lock().unwrap().screen().contents()
    }

    pub(crate) fn dirs(&self) -> Vec<PathBuf> {
        self.sessions.iter().filter_map(|s| s.dir.clone()).collect()
    }

    /// Draw the dock: a resize edge, tabs, then the active screen.
    pub(crate) fn ui(&mut self, ui: &mut Ui) {
        // Tabs.
        let mut close: Option<usize> = None;
        ui.horizontal(|ui| {
            ui.label(RichText::new("Terminal").size(z(12.5)).color(TEXT_SUBTLE()));
            for (i, s) in self.sessions.iter().enumerate() {
                let on = i == self.active;
                let dead = !s.alive.load(Ordering::SeqCst);
                let label = format!("{}{}", if dead { "◌ " } else { "" }, super::truncate(&s.title, 32));
                let r = ui.add(
                    egui::Button::new(RichText::new(label).size(z(12.5)).color(if on { TEXT_DEFAULT() } else { TEXT_SUBTLE() }))
                        .fill(if on { BG_MUTED() } else { Color32::TRANSPARENT })
                        .stroke(Stroke::NONE),
                );
                if r.clicked() {
                    self.active = i;
                    self.focused = true;
                }
                if ui.add(egui::Button::new(RichText::new("×").size(z(14.0)).color(TEXT_PLACEHOLDER())).frame(false)).on_hover_text("Close this session").clicked() {
                    close = Some(i);
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add(egui::Button::new(RichText::new("⌄").size(z(14.0)).color(TEXT_SUBTLE())).frame(false)).on_hover_text("Hide the terminal (sessions keep running)").clicked() {
                    self.open = false;
                    self.focused = false;
                }
                ui.label(RichText::new(if self.focused { "typing goes to the shell · click outside to leave" } else { "click to type" }).size(z(11.5)).color(TEXT_PLACEHOLDER()));
            });
        });
        if let Some(i) = close {
            self.close_tab(i);
        }
        self.screen(ui, 12.5);
    }

    /// The active session's screen, filling what's there.
    pub(crate) fn screen(&mut self, ui: &mut Ui, text_size: f32) {
        let Some(s) = self.sessions.get_mut(self.active) else { return };

        // Screen area.
        let font = FontId::monospace(z(text_size));
        let (cw, chh) = {
            let g = ui.painter().layout_no_wrap("M".into(), font.clone(), Color32::WHITE);
            (g.size().x.max(6.0), g.size().y.max(12.0))
        };
        let avail = ui.available_rect_before_wrap();
        let id = ui.id().with("kubedog-terminal");
        let resp = ui.interact(avail, id, Sense::click_and_drag());
        if resp.clicked() || resp.drag_started() {
            resp.request_focus();
            self.focused = true;
        }
        if self.focused && !resp.has_focus() {
            resp.request_focus();
        }
        if resp.clicked_elsewhere() {
            self.focused = false;
            resp.surrender_focus();
        }
        let painter = ui.painter_at(avail);
        painter.rect_filled(avail, CornerRadius::same(4), TERM_BG);
        if self.focused {
            painter.rect_stroke(avail, CornerRadius::same(4), Stroke::new(1.0, PRIMARY_TEXT().gamma_multiply(0.5)), egui::StrokeKind::Inside);
        }
        let inner = avail.shrink(6.0);
        let cols = ((inner.width() / cw).floor() as u16).clamp(20, 400);
        let rows = ((inner.height() / chh).floor() as u16).clamp(3, 200);
        self.last_size = Some((rows, cols));
        if (rows, cols) != s.size {
            s.size = (rows, cols);
            if let Some(p) = &s.proc {
                let _ = p.master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
            }
            s.mark = None;
            if let Ok(mut p) = s.parser.lock() {
                p.set_size(rows, cols);
            }
        }

        // Marking text with the mouse.
        let spot = |p: egui::Pos2| -> (u16, u16) { ((((p.y - inner.top()) / chh).floor().max(0.0) as u16).min(rows - 1), (((p.x - inner.left()) / cw).round().max(0.0) as u16).min(cols)) };
        if resp.drag_started() {
            s.mark = ui.input(|i| i.pointer.press_origin()).map(|p| (spot(p), spot(p)));
        }
        if resp.dragged() {
            if let (Some(m), Some(p)) = (&mut s.mark, resp.interact_pointer_pos()) {
                m.1 = spot(p);
            }
        }
        if resp.clicked() {
            s.mark = None;
        }
        let mark = s.mark.filter(|m| m.0 != m.1).map(|m| if m.0 <= m.1 { m } else { (m.1, m.0) });
        let marked = || mark.and_then(|(a, b)| s.parser.lock().ok().map(|p| p.screen().contents_between(a.0, a.1, b.0, b.1))).unwrap_or_default();

        // Keyboard and paste go to the shell while the terminal has focus.
        let mut out: Vec<u8> = vec![];
        if self.focused && resp.has_focus() {
            ui.memory_mut(|m| {
                m.set_focus_lock_filter(id, egui::EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: true })
            });
            let (app_cursor, bracketed) = s.parser.lock().map(|p| (p.screen().application_cursor(), p.screen().bracketed_paste())).unwrap_or((false, false));
            let events = ui.input(|i| i.events.clone());
            for e in events {
                match e {
                    egui::Event::Text(t) => out.extend_from_slice(t.as_bytes()),
                    egui::Event::Paste(t) => out.extend(pasted(&t, bracketed)),
                    // ⌘C copies. Where that's Ctrl+C it copies what's marked, else it's the shell's.
                    egui::Event::Copy => {
                        let t = marked();
                        if !t.is_empty() {
                            ui.ctx().copy_text(t);
                        } else if !cfg!(target_os = "macos") {
                            out.push(0x03);
                        }
                    }
                    egui::Event::Cut if !cfg!(target_os = "macos") => out.push(0x18),
                    egui::Event::Key { key, pressed: true, modifiers, .. } => {
                        if let Some(b) = key_bytes(key, modifiers, app_cursor) {
                            out.extend_from_slice(&b);
                        }
                    }
                    _ => {}
                }
            }
            if !out.is_empty() {
                s.scroll = 0;
                s.mark = None;
            }
        }
        // The wheel: back through what was said; in a full-screen program it's the program's.
        if resp.hovered() {
            s.wheel += ui.input(|i| i.smooth_scroll_delta.y) / chh;
            let n = s.wheel.trunc() as i64;
            if n != 0 {
                s.wheel -= n as f32;
                s.mark = None;
                let (full, mouse, sgr, app) = s.parser.lock().map(|p| (p.screen().alternate_screen(), p.screen().mouse_protocol_mode() != vt100::MouseProtocolMode::None, p.screen().mouse_protocol_encoding() == vt100::MouseProtocolEncoding::Sgr, p.screen().application_cursor())).unwrap_or_default();
                if mouse && sgr {
                    let at = ui.input(|i| i.pointer.hover_pos()).map(spot).unwrap_or((0, 0));
                    for _ in 0..n.abs().min(12) {
                        out.extend(format!("\x1b[<{};{};{}M", if n > 0 { 64 } else { 65 }, at.1 + 1, at.0 + 1).into_bytes());
                    }
                } else if full {
                    let k = if n > 0 { b'A' } else { b'B' };
                    for _ in 0..n.abs().min(12) {
                        out.extend(if app { [0x1b, b'O', k] } else { [0x1b, b'[', k] });
                    }
                } else {
                    s.scroll = (s.scroll as i64 + n).max(0) as usize;
                }
            }
        }
        if !out.is_empty() {
            s.send(&out);
        }

        // Draw the screen.
        if let Ok(mut p) = s.parser.lock() {
            p.set_scrollback(s.scroll);
            s.scroll = p.screen().scrollback();
            let screen = p.screen();
            let (rows, cols) = screen.size();
            for r in 0..rows {
                let mut job = egui::text::LayoutJob::default();
                let mut run = String::new();
                let mut run_fmt: Option<egui::TextFormat> = None;
                for c in 0..cols {
                    let Some(cell) = screen.cell(r, c) else { continue };
                    if cell.is_wide_continuation() {
                        continue;
                    }
                    let (mut fg, mut bg) = (to_color(cell.fgcolor(), true), to_color(cell.bgcolor(), false));
                    if cell.inverse() {
                        std::mem::swap(&mut fg, &mut bg);
                        if fg == Color32::TRANSPARENT {
                            fg = TERM_BG;
                        }
                    }
                    if cell.bold() && fg == TERM_FG {
                        fg = TERM_BRIGHT;
                    }
                    let fmt = egui::TextFormat {
                        font_id: font.clone(),
                        color: fg,
                        background: bg,
                        underline: if cell.underline() { Stroke::new(1.0, fg) } else { Stroke::NONE },
                        italics: cell.italic(),
                        ..Default::default()
                    };
                    let text = if cell.has_contents() { cell.contents() } else { " ".to_string() };
                    if run_fmt.as_ref() != Some(&fmt) {
                        if let Some(f) = run_fmt.take() {
                            job.append(&run, 0.0, f);
                            run.clear();
                        }
                        run_fmt = Some(fmt);
                    }
                    run.push_str(&text);
                }
                if let Some(f) = run_fmt.take() {
                    job.append(&run, 0.0, f);
                }
                let g = ui.painter().layout_job(job);
                painter.galley(inner.min + egui::vec2(0.0, r as f32 * chh), g, TERM_FG);
            }
            if let Some((a, b)) = mark.filter(|_| s.mark.is_some()) {
                for r in a.0..=b.0 {
                    let from = if r == a.0 { a.1 } else { 0 };
                    let to = if r == b.0 { b.1 } else { cols };
                    let rect = egui::Rect::from_min_max(inner.min + egui::vec2(from as f32 * cw, r as f32 * chh), inner.min + egui::vec2(to as f32 * cw, (r + 1) as f32 * chh));
                    painter.rect_filled(rect, CornerRadius::ZERO, PRIMARY_TEXT().gamma_multiply(0.3));
                }
            }
            if !screen.hide_cursor() && s.scroll == 0 {
                let (cr, cc) = screen.cursor_position();
                let rect = egui::Rect::from_min_size(inner.min + egui::vec2(cc as f32 * cw, cr as f32 * chh), egui::vec2(cw, chh));
                if self.focused {
                    painter.rect_filled(rect, CornerRadius::ZERO, TERM_BRIGHT.gamma_multiply(0.6));
                } else {
                    painter.rect_stroke(rect, CornerRadius::ZERO, Stroke::new(1.0, TEXT_SUBTLE()), egui::StrokeKind::Inside);
                }
            }
        }
        if !s.alive.load(Ordering::SeqCst) {
            painter.text(inner.right_bottom() - egui::vec2(4.0, 4.0), egui::Align2::RIGHT_BOTTOM, "session ended", FontId::proportional(z(11.5)), TEXT_PLACEHOLDER());
        }
        ui.advance_cursor_after_rect(avail);
    }

    pub(crate) fn height(&self) -> f32 {
        self.height
    }

    pub(crate) fn set_height(&mut self, h: f32) {
        self.height = h.clamp(120.0, 900.0);
    }
}

/// Bytes a key press sends to a terminal.
fn key_bytes(key: Key, m: egui::Modifiers, app_cursor: bool) -> Option<Vec<u8>> {
    // Ctrl+letter → control character (Ctrl+C = 0x03 ...). On macOS ⌘ shortcuts stay with the app.
    if m.ctrl && !m.alt {
        let name = key.name();
        if name.len() == 1 {
            let ch = name.as_bytes()[0].to_ascii_lowercase();
            if ch.is_ascii_lowercase() {
                return Some(vec![ch - b'a' + 1]);
            }
        }
        match key {
            Key::OpenBracket => return Some(vec![0x1b]),
            Key::Backslash => return Some(vec![0x1c]),
            _ => {}
        }
    }
    let arrow = |c: u8| if app_cursor { vec![0x1b, b'O', c] } else { vec![0x1b, b'[', c] };
    let b: Vec<u8> = match key {
        Key::Enter => b"\r".to_vec(),
        Key::Backspace => if m.alt { vec![0x1b, 0x7f] } else { vec![0x7f] },
        Key::Tab => if m.shift { b"\x1b[Z".to_vec() } else { b"\t".to_vec() },
        Key::Escape => vec![0x1b],
        Key::ArrowRight if m.ctrl => b"\x1b[1;5C".to_vec(),
        Key::ArrowLeft if m.ctrl => b"\x1b[1;5D".to_vec(),
        Key::ArrowUp => arrow(b'A'),
        Key::ArrowDown => arrow(b'B'),
        Key::ArrowRight => if m.alt { b"\x1bf".to_vec() } else { arrow(b'C') },
        Key::ArrowLeft => if m.alt { b"\x1bb".to_vec() } else { arrow(b'D') },
        Key::Home => b"\x1b[H".to_vec(),
        Key::End => b"\x1b[F".to_vec(),
        Key::PageUp => b"\x1b[5~".to_vec(),
        Key::PageDown => b"\x1b[6~".to_vec(),
        Key::Delete => b"\x1b[3~".to_vec(),
        Key::Insert => b"\x1b[2~".to_vec(),
        Key::F1 => b"\x1bOP".to_vec(),
        Key::F2 => b"\x1bOQ".to_vec(),
        Key::F3 => b"\x1bOR".to_vec(),
        Key::F4 => b"\x1bOS".to_vec(),
        Key::F5 => b"\x1b[15~".to_vec(),
        Key::F6 => b"\x1b[17~".to_vec(),
        Key::F7 => b"\x1b[18~".to_vec(),
        Key::F8 => b"\x1b[19~".to_vec(),
        Key::F9 => b"\x1b[20~".to_vec(),
        Key::F10 => b"\x1b[21~".to_vec(),
        Key::F11 => b"\x1b[23~".to_vec(),
        Key::F12 => b"\x1b[24~".to_vec(),
        _ => return None,
    };
    Some(b)
}

/// The terminal is dark in every theme.
const TERM_BG: Color32 = Color32::from_rgb(0x1b, 0x19, 0x17);
const TERM_FG: Color32 = Color32::from_rgb(0xcf, 0xc6, 0xbb);
const TERM_BRIGHT: Color32 = Color32::from_rgb(0xf5, 0xef, 0xe6);

fn to_color(c: vt100::Color, fg: bool) -> Color32 {
    // Warm colours on a dark brown, to go with the orange.
    const ANSI: [Color32; 16] = [
        Color32::from_rgb(0x2b, 0x27, 0x24),
        Color32::from_rgb(0xe5, 0x58, 0x4f),
        Color32::from_rgb(0x7f, 0xb0, 0x69),
        Color32::from_rgb(0xe8, 0xa3, 0x3d),
        Color32::from_rgb(0x5b, 0x9b, 0xd5),
        Color32::from_rgb(0xb5, 0x8b, 0xd6),
        Color32::from_rgb(0x4f, 0xb3, 0xa5),
        Color32::from_rgb(0xcf, 0xc6, 0xbb),
        Color32::from_rgb(0x8a, 0x80, 0x78),
        Color32::from_rgb(0xff, 0x7f, 0x73),
        Color32::from_rgb(0xa3, 0xcf, 0x8b),
        Color32::from_rgb(0xff, 0xc4, 0x6b),
        Color32::from_rgb(0x86, 0xbd, 0xf0),
        Color32::from_rgb(0xd0, 0xae, 0xea),
        Color32::from_rgb(0x7d, 0xd3, 0xc5),
        Color32::from_rgb(0xf5, 0xef, 0xe6),
    ];
    match c {
        vt100::Color::Default => if fg { TERM_FG } else { Color32::TRANSPARENT },
        vt100::Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
        vt100::Color::Idx(i) if i < 16 => ANSI[i as usize],
        vt100::Color::Idx(i) if i >= 232 => {
            let v = 8 + (i - 232) * 10;
            Color32::from_rgb(v, v, v)
        }
        vt100::Color::Idx(i) => {
            let i = i - 16;
            let s = |x: u8| if x == 0 { 0 } else { 55 + x * 40 };
            Color32::from_rgb(s(i / 36), s((i / 6) % 6), s(i % 6))
        }
    }
}

#[allow(dead_code)]
fn _margin() -> Margin {
    Margin::same(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_questions() {
        let mut a = Asked::default();
        let asks = |a: &mut Asked, t: &str| t.bytes().filter_map(|b| a.byte(b)).collect::<Vec<_>>();
        assert_eq!(asks(&mut a, "hello \x1b[31mred\x1b[0m \x1b[2K\x1b[?25h\x1b]0;title\x07"), Vec::<Vec<u8>>::new());
        assert_eq!(asks(&mut a, "x\x1b[6"), Vec::<Vec<u8>>::new());
        assert_eq!(asks(&mut a, "ny\x1b[c\x1b[\x1b[5n"), vec![b"\x1b[6n".to_vec(), b"\x1b[c".to_vec(), b"\x1b[5n".to_vec()]);
        // What a terminal answers isn't a question itself.
        assert!(asks(&mut a, "\x1b[3;4R\x1b[?1;2c\x1b[0n\x1b[>c").is_empty());
        assert_eq!(answer(b"\x1b[6n", (2, 3)), b"\x1b[3;4R");
    }

    #[cfg(unix)]
    #[test]
    fn answers_in_a_terminal() {
        let mut d = Dock::default();
        // Asks where the cursor is after three letters, and shows what it was told.
        let script = "stty raw -echo; printf 'abc\\033[6n'; a=$(dd bs=1 count=6 2>/dev/null | od -An -c | tr -d ' \\n'); stty sane; echo \"TOLD $a\"; sleep 5";
        d.spawn("x".into(), "/bin/sh", &["-c".into(), script.into()], &[], None, &egui::Context::default()).unwrap();
        for _ in 0..60 {
            if d.shown().contains("TOLD 033[1;4R") {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("{}", d.shown());
    }

    #[test]
    fn keys_and_paste() {
        let none = egui::Modifiers::NONE;
        assert_eq!(key_bytes(Key::C, egui::Modifiers { ctrl: true, ..none }, false), Some(vec![3]));
        assert_eq!(key_bytes(Key::ArrowUp, none, true), Some(b"\x1bOA".to_vec()));
        assert_eq!(key_bytes(Key::ArrowLeft, egui::Modifiers { ctrl: true, ..none }, false), Some(b"\x1b[1;5D".to_vec()));
        assert_eq!(key_bytes(Key::F5, none, false), Some(b"\x1b[15~".to_vec()));
        assert_eq!(pasted("a\nb", false), b"a\rb");
        // Nothing pasted can end the marking and be run.
        assert_eq!(pasted("x\x1b[201~y\r\n", true), b"\x1b[200~xy\r\x1b[201~");
    }

    #[test]
    fn tabs_and_typing() {
        let mut d = Dock::default();
        for t in ["a", "b", "c"] {
            d.picture(t, "c", "hello\nworld");
        }
        assert_eq!((d.tabs().0.len(), d.tabs().1), (3, 2));
        d.show_tab(1);
        d.close_tab(0);
        assert_eq!((d.tabs().0[d.tabs().1].0.as_str(), d.current().unwrap().0.as_str()), ("b", "c"));
        d.close_tab(1);
        d.close_tab(0);
        assert!(!d.has_sessions() && !d.open && d.current().is_none());
        d.close_tab(0);
    }

    /// Typed text never runs by itself: a real shell gets it without an Enter, and its folder goes with it.
    #[cfg(unix)]
    #[test]
    fn typed_not_run() {
        let dir = std::env::temp_dir().join(format!("kubedog-term-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut d = Dock::default();
        d.spawn_for("t".into(), "/bin/cat", &[], &[], None, &egui::Context::default(), "c".into(), Some(dir.clone())).unwrap();
        d.type_text("echo hi\n\x03there");
        std::thread::sleep(std::time::Duration::from_millis(300));
        let text = d.sessions[0].parser.lock().unwrap().screen().contents();
        // The echo of the terminal, once: cat would repeat it after an Enter.
        assert_eq!(text.trim(), "echo hithere");
        d.close_all();
        assert!(!dir.exists());
    }
}
