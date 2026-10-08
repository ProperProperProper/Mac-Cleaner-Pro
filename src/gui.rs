//! eframe/egui GUI: Clean, Disk Usage, History and Security tabs.

use crate::cleaner::{self, CleanCategory, Item};
use crate::history::{ActionRow, CleanupRow, History};
use crate::security::{self, Category, Finding, Fix, Status, report};
use crate::util::{human, tilde};
use eframe::egui::{self, Color32, RichText};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Clean,
    Disk,
    History,
    Security,
}

enum CleanMsg {
    Progress(String),
    Scanned(Vec<(CleanCategory, Vec<Item>)>),
    Cleaned(Vec<(String, u64, u64)>),
}

enum DiskMsg {
    Progress(String),
    Done(Vec<(String, PathBuf, u64)>),
}

enum SecMsg {
    Check(usize, Vec<Finding>),
    Action(usize, Box<security::ActionOutcome>, String),
    Undo(Result<Vec<String>, String>),
}

struct CleanRow {
    cat: CleanCategory,
    items: Vec<Item>,
    checked: bool,
}

pub struct App {
    tab: Tab,
    schedule_on: bool,
    // clean
    clean_rows: Vec<CleanRow>,
    clean_status: String,
    clean_busy: bool,
    cleaning: bool,
    clean_rx: Option<Receiver<CleanMsg>>,
    confirm_clean: bool,
    clean_done_msg: Option<String>,
    // disk
    disk_started: bool,
    disk_busy: bool,
    disk_status: String,
    disk_rows: Vec<(String, PathBuf, u64)>,
    disk_rx: Option<Receiver<DiskMsg>>,
    // history
    hist_cleanups: Vec<CleanupRow>,
    hist_actions: Vec<ActionRow>,
    hist_loaded: bool,
    confirm_undo: Option<ActionRow>,
    // security
    defs: Vec<security::CheckDef>,
    results: Vec<Option<Vec<Finding>>>,
    sec_tx: Sender<SecMsg>,
    sec_rx: Receiver<SecMsg>,
    sec_last_run: Option<String>,
    include_login_items: bool,
    dry_run: bool,
    only_problems: bool,
    pending_fix: Option<(usize, Finding, Fix)>,
    action_busy: bool,
    banner: Option<(bool, String)>,
}

fn status_color(s: Status) -> Color32 {
    match s {
        Status::Ok => Color32::from_rgb(110, 200, 110),
        Status::Info => Color32::from_rgb(130, 170, 220),
        Status::Warning => Color32::from_rgb(235, 170, 60),
        Status::Critical => Color32::from_rgb(235, 85, 85),
        Status::Unknown => Color32::GRAY,
    }
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let defs = security::registry();
        let n = defs.len();
        let (sec_tx, sec_rx) = channel();
        let mut app = App {
            tab: Tab::Clean,
            schedule_on: crate::schedule::enabled(),
            clean_rows: vec![],
            clean_status: "Scanning…".into(),
            clean_busy: false,
            cleaning: false,
            clean_rx: None,
            confirm_clean: false,
            clean_done_msg: None,
            disk_started: false,
            disk_busy: false,
            disk_status: String::new(),
            disk_rows: vec![],
            disk_rx: None,
            hist_cleanups: vec![],
            hist_actions: vec![],
            hist_loaded: false,
            confirm_undo: None,
            defs,
            results: vec![None; n],
            sec_tx,
            sec_rx,
            sec_last_run: None,
            include_login_items: false,
            dry_run: false,
            only_problems: false,
            pending_fix: None,
            action_busy: false,
            banner: None,
        };
        app.start_scan(&cc.egui_ctx);
        app
    }

    // ---------------- clean ----------------
    fn start_scan(&mut self, ctx: &egui::Context) {
        let (tx, rx) = channel();
        self.clean_rx = Some(rx);
        self.clean_busy = true;
        self.clean_status = "Scanning…".into();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let home = crate::util::home();
            let now = std::time::SystemTime::now();
            let mut out = vec![];
            for c in cleaner::categories(&home) {
                let _ = tx.send(CleanMsg::Progress(format!("Scanning {}…", c.label)));
                ctx.request_repaint();
                let items = cleaner::scan_category(&c, now);
                out.push((c, items));
            }
            let _ = tx.send(CleanMsg::Scanned(out));
            ctx.request_repaint();
        });
    }

    fn start_clean(&mut self, ctx: &egui::Context) {
        let selected: Vec<(String, Vec<PathBuf>, Vec<Item>)> = self
            .clean_rows
            .iter()
            .filter(|r| r.checked && !r.items.is_empty())
            .map(|r| (r.cat.label.to_string(), r.cat.paths.clone(), r.items.clone()))
            .collect();
        let (tx, rx) = channel();
        self.clean_rx = Some(rx);
        self.clean_busy = true;
        self.cleaning = true;
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let summary = cleaner::clean(&selected, |m| {
                let _ = tx.send(CleanMsg::Progress(m.to_string()));
                ctx.request_repaint();
            });
            if let Ok(h) = History::open_default() {
                let _ = h.record_cleanup(&summary);
            }
            let _ = tx.send(CleanMsg::Cleaned(summary));
            ctx.request_repaint();
        });
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let mut rescan = false;
        if let Some(rx) = &self.clean_rx {
            while let Ok(m) = rx.try_recv() {
                match m {
                    CleanMsg::Progress(s) => self.clean_status = s,
                    CleanMsg::Scanned(v) => {
                        let total: u64 = v.iter().flat_map(|(_, i)| i.iter()).map(|i| i.size).sum();
                        self.clean_rows = v
                            .into_iter()
                            .map(|(cat, items)| {
                                // Opt-in categories start unchecked.
                                let checked = !items.is_empty() && !cat.opt_in;
                                CleanRow { cat, items, checked }
                            })
                            .collect();
                        self.clean_status = format!("Scan complete — {} reclaimable", human(total));
                        self.clean_busy = false;
                    }
                    CleanMsg::Cleaned(summary) => {
                        self.cleaning = false;
                        let count: u64 = summary.iter().map(|s| s.1).sum();
                        let freed: u64 = summary.iter().map(|s| s.2).sum();
                        self.clean_status = format!("Done — removed {count} items, freed {}", human(freed));
                        self.clean_done_msg = Some(format!(
                            "Removed {count} items and freed approximately {}.\n\nThis run has been added to the History tab.",
                            human(freed)
                        ));
                        self.hist_loaded = false;
                        rescan = true;
                    }
                }
            }
        }
        if rescan {
            self.start_scan(ctx);
        }
        if let Some(rx) = &self.disk_rx {
            while let Ok(m) = rx.try_recv() {
                match m {
                    DiskMsg::Progress(s) => self.disk_status = s,
                    DiskMsg::Done(v) => {
                        self.disk_rows = v;
                        self.disk_busy = false;
                        self.disk_status = "Measurement complete — sorted largest first".into();
                    }
                }
            }
        }
        while let Ok(m) = self.sec_rx.try_recv() {
            match m {
                SecMsg::Check(i, f) => {
                    self.results[i] = Some(f);
                    if self.results.iter().all(|r| r.is_some()) && self.sec_last_run.is_none() {
                        self.sec_last_run = Some(crate::util::now_string());
                    }
                }
                SecMsg::Action(i, out, label) => {
                    self.action_busy = false;
                    if !out.new_findings.is_empty() {
                        self.results[i] = Some(out.new_findings.clone());
                    }
                    let text = if out.history_id.is_none() && out.log.iter().all(|l| l.starts_with("[dry run]")) {
                        format!("Dry run of \"{label}\" — nothing was changed. Would run:\n{}", out.log.join("\n"))
                    } else if out.ok {
                        format!("\"{label}\" applied and logged in History. Now: {}", out.after)
                    } else {
                        format!("\"{label}\" did not complete: {}", out.log.join("; "))
                    };
                    self.banner = Some((out.ok, text));
                    self.hist_loaded = false;
                }
                SecMsg::Undo(r) => {
                    self.action_busy = false;
                    self.banner = Some(match r {
                        Ok(_) => (true, "Undo complete. Run the audit again to see the current state.".into()),
                        Err(e) => (false, format!("Undo failed: {e}")),
                    });
                    self.hist_loaded = false;
                }
            }
        }
    }

    // ---------------- security ----------------
    fn run_audit(&mut self, ctx: &egui::Context) {
        self.results = vec![None; self.defs.len()];
        self.sec_last_run = None;
        let include = self.include_login_items;
        let ctx2 = ctx.clone();
        let tx = self.sec_tx.clone();
        std::thread::spawn(move || {
            let sctx = std::sync::Arc::new(security::Ctx::new(include));
            let defs = security::registry();
            std::thread::scope(|s| {
                for (i, d) in defs.iter().enumerate() {
                    let tx = tx.clone();
                    let ctx2 = ctx2.clone();
                    let sctx = sctx.clone();
                    s.spawn(move || {
                        let f = security::run_check(d, &sctx);
                        let _ = tx.send(SecMsg::Check(i, f));
                        ctx2.request_repaint();
                    });
                }
            });
        });
    }

    fn recheck(&mut self, idx: usize, ctx: &egui::Context) {
        self.results[idx] = None;
        let include = self.include_login_items;
        let tx = self.sec_tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let sctx = security::Ctx::new(include);
            let defs = security::registry();
            let f = security::run_check(&defs[idx], &sctx);
            let _ = tx.send(SecMsg::Check(idx, f));
            ctx.request_repaint();
        });
    }

    fn all_findings(&self) -> Vec<Finding> {
        self.results.iter().flatten().flatten().cloned().collect()
    }

    fn export(&mut self, path: Option<PathBuf>) {
        let findings = self.all_findings();
        if findings.is_empty() {
            self.banner = Some((false, "Run the audit first.".into()));
            return;
        }
        let ts = self.sec_last_run.clone().unwrap_or_else(crate::util::now_string);
        let md = report::markdown(&findings, &ts);
        let path = path.unwrap_or_else(|| {
            crate::util::home()
                .join("Projects/Mac-Cleaner-Pro/reports")
                .join(format!("security-audit-{}.md", crate::util::now_compact()))
        });
        if let Some(d) = path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        self.banner = Some(match std::fs::write(&path, md) {
            Ok(_) => (true, format!("Report saved to {}", tilde(&path))),
            Err(e) => (false, format!("Could not save report: {e}")),
        });
    }

    fn security_tab(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let any_pending = self.results.iter().any(|r| r.is_none());
        let started = self.results.iter().any(|r| r.is_some());
        ui.horizontal_wrapped(|ui| {
            if ui.add_enabled(!any_pending || !started, egui::Button::new(RichText::new("Run audit").strong())).clicked() {
                self.run_audit(&ctx);
            }
            if any_pending && started {
                ui.spinner();
                let n = self.results.iter().filter(|r| r.is_none()).count();
                ui.label(format!("{n} check(s) still running (slow ones like Software Update run in the background)…"));
            }
            match &self.sec_last_run {
                Some(t) => ui.label(RichText::new(format!("Last run: {t}")).weak()),
                None if !started => ui.label(RichText::new("Not run yet").weak()),
                None => ui.label(""),
            };
        });
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(&mut self.include_login_items, "Include login items (macOS may ask once for Automation permission)");
            ui.checkbox(&mut self.dry_run, "Preview only (dry run: Fix buttons show commands, change nothing)");
            ui.checkbox(&mut self.only_problems, "Only show problems");
        });

        let findings = self.all_findings();
        if !findings.is_empty() {
            let s = report::Summary::of(&findings);
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                let sc = if s.critical > 0 { Status::Critical } else if s.warning > 0 { Status::Warning } else { Status::Ok };
                ui.label(RichText::new(format!("Score {}/100", s.score)).size(22.0).strong().color(status_color(sc)));
                for (n, st) in [(s.ok, Status::Ok), (s.info, Status::Info), (s.warning, Status::Warning), (s.critical, Status::Critical), (s.unknown, Status::Unknown)] {
                    ui.label(RichText::new(format!("{} {}", n, st.label())).color(status_color(st)).strong());
                    ui.add_space(6.0);
                }
            });
            ui.horizontal(|ui| {
                if ui.button("Export report").on_hover_text("Saves Markdown to ~/Projects/Mac-Cleaner-Pro/reports/").clicked() {
                    self.export(None);
                }
                if ui.button("Export as…").clicked()
                    && let Some(p) = rfd::FileDialog::new().set_file_name("security-audit.md").add_filter("Markdown", &["md"]).save_file()
                {
                    self.export(Some(p));
                }
            });
        }
        if let Some((ok, msg)) = self.banner.clone() {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(msg).color(if ok { status_color(Status::Ok) } else { status_color(Status::Warning) }));
                if ui.small_button("dismiss").clicked() {
                    self.banner = None;
                }
            });
        }
        ui.separator();
        if !started && !any_pending {
            return;
        }
        if !started {
            ui.label("Click \"Run audit\" to inspect this Mac. The audit only reads; nothing changes unless you click a Fix button and confirm.");
            return;
        }

        let mut recheck: Option<usize> = None;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for cat in Category::ALL {
                let idxs: Vec<usize> = (0..self.defs.len()).filter(|&i| self.defs[i].category == cat).collect();
                let cat_findings: Vec<(usize, &Finding)> = idxs
                    .iter()
                    .flat_map(|&i| self.results[i].iter().flatten().map(move |f| (i, f)))
                    .collect();
                let pending: Vec<&str> = idxs.iter().filter(|&&i| self.results[i].is_none()).map(|&i| self.defs[i].name).collect();
                let worst = cat_findings.iter().map(|(_, f)| f.status).filter(|s| *s != Status::Unknown).max().unwrap_or(Status::Ok);
                let problems = cat_findings.iter().filter(|(_, f)| matches!(f.status, Status::Warning | Status::Critical)).count();
                if self.only_problems && problems == 0 && pending.is_empty() {
                    continue;
                }
                let head = RichText::new(format!("{}  ({} item(s), {} need attention)", cat.label(), cat_findings.len(), problems)).color(status_color(worst)).strong();
                egui::CollapsingHeader::new(head).id_salt(cat.label()).default_open(problems > 0).show(ui, |ui| {
                    for p in &pending {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(format!("Checking {p}…"));
                        });
                    }
                    for (i, f) in &cat_findings {
                        if self.only_problems && !matches!(f.status, Status::Warning | Status::Critical) {
                            continue;
                        }
                        let title = RichText::new(format!("[{}] {} — {}", f.status.label(), f.title, f.summary)).color(status_color(f.status));
                        egui::CollapsingHeader::new(title).id_salt((f.check_id, &f.title)).show(ui, |ui| {
                            for e in &f.evidence {
                                ui.label(RichText::new(e).monospace().weak());
                            }
                            if !f.explanation.is_empty() {
                                ui.label(RichText::new("Why it matters").strong());
                                ui.label(&f.explanation);
                            }
                            if !f.fix_text.is_empty() && f.status != Status::Ok {
                                ui.label(RichText::new("How to fix").strong());
                                ui.label(&f.fix_text);
                            }
                            if let Some(c) = &f.fix_command
                                && f.status != Status::Ok
                            {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(RichText::new(c).monospace());
                                    if ui.small_button("Copy fix command").clicked() {
                                        ui.ctx().copy_text(c.clone());
                                    }
                                });
                            }
                            ui.horizontal_wrapped(|ui| {
                                for fx in &f.fixes {
                                    let label = if fx.opens_settings() { fx.label.clone() } else { format!("Fix: {}", fx.label) };
                                    if ui.add_enabled(!self.action_busy, egui::Button::new(label)).clicked() {
                                        self.pending_fix = Some((*i, (*f).clone(), fx.clone()));
                                    }
                                }
                                if ui.small_button("Re-check").clicked() {
                                    recheck = Some(*i);
                                }
                            });
                        });
                    }
                });
            }
        });
        if let Some(i) = recheck {
            self.recheck(i, &ctx);
        }
    }

    fn fix_modal(&mut self, ctx: &egui::Context) {
        let Some((idx, finding, fx)) = self.pending_fix.clone() else { return };
        let mut close = false;
        let mut apply = false;
        egui::Modal::new(egui::Id::new("fix-confirm")).show(ctx, |ui| {
            ui.set_max_width(640.0);
            ui.heading(&fx.label);
            ui.label(RichText::new(format!("{} — {}", finding.title, finding.summary)).weak());
            ui.separator();
            ui.label(RichText::new("What will change").strong());
            for c in &fx.changes {
                ui.label(format!("• {c}"));
            }
            ui.label(RichText::new("Exact commands").strong());
            egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                for p in fx.preview() {
                    ui.label(RichText::new(p).monospace());
                }
            });
            if let Some(w) = &fx.warning {
                ui.label(RichText::new(format!("Caution: {w}")).color(status_color(Status::Warning)));
            }
            if fx.needs_admin() {
                ui.label("macOS will show its own administrator password dialog. This app never sees or stores your password.");
            }
            ui.label(match &fx.undo {
                Some(_) => "Undo: available from the History tab.",
                None if fx.opens_settings() => "Opens System Settings; you make the change there, then click Re-check.",
                None => "Undo: not available for this action.",
            });
            if self.dry_run {
                ui.label(RichText::new("Preview-only mode is on: nothing will be executed.").color(status_color(Status::Info)));
            }
            ui.separator();
            ui.horizontal(|ui| {
                let label = if self.dry_run { "Preview" } else if fx.opens_settings() { "Open" } else { "Apply" };
                if ui.button(RichText::new(label).strong()).clicked() {
                    apply = true;
                }
                if ui.button("Cancel").clicked() {
                    close = true;
                }
            });
        });
        if apply {
            self.pending_fix = None;
            self.action_busy = true;
            let tx = self.sec_tx.clone();
            let dry = self.dry_run;
            let include = self.include_login_items;
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                let out = security::execute_fix(&finding, &fx, dry, include);
                let _ = tx.send(SecMsg::Action(idx, Box::new(out), fx.label.clone()));
                ctx.request_repaint();
            });
        } else if close {
            self.pending_fix = None;
        }
    }

    // ---------------- tabs ----------------
    fn clean_tab(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.horizontal(|ui| {
            if self.clean_busy {
                ui.spinner();
            }
            ui.label(RichText::new(&self.clean_status).weak());
        });
        ui.separator();
        let bottom = 70.0;
        egui::ScrollArea::vertical().max_height(ui.available_height() - bottom).auto_shrink([false, false]).show(ui, |ui| {
            for (ri, r) in self.clean_rows.iter_mut().enumerate() {
                let size: u64 = r.items.iter().map(|i| i.size).sum();
                ui.add_enabled_ui(!r.items.is_empty() && !self.clean_busy, |ui| {
                    ui.checkbox(&mut r.checked, RichText::new(format!("{} — {} ({} items)", r.cat.label, human(size), r.items.len())).strong());
                });
                ui.indent(ri, |ui| {
                    ui.label(RichText::new(r.cat.description).weak().small());
                    if !r.items.is_empty() {
                        egui::CollapsingHeader::new(RichText::new("Show items").small()).id_salt(("items", ri)).show(ui, |ui| {
                            let mut items: Vec<&Item> = r.items.iter().collect();
                            items.sort_by_key(|a| std::cmp::Reverse(a.size));
                            for it in items.iter().take(300) {
                                ui.label(RichText::new(format!("{:>10}  {}", human(it.size), tilde(&it.path))).monospace().small());
                            }
                            if items.len() > 300 {
                                ui.label(format!("… and {} more", items.len() - 300));
                            }
                        });
                    }
                });
                ui.add_space(4.0);
            }
        });
        ui.separator();
        ui.horizontal(|ui| {
            if ui.add_enabled(!self.clean_busy, egui::Button::new("Rescan")).clicked() {
                self.start_scan(&ctx);
            }
            let any = self.clean_rows.iter().any(|r| r.checked && !r.items.is_empty());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let b = egui::Button::new(RichText::new("Clean Selected").strong().color(Color32::from_rgb(136, 221, 136)));
                if ui.add_enabled(any && !self.clean_busy, b).clicked() {
                    self.confirm_clean = true;
                }
            });
        });
        ui.label(RichText::new("Only well-known cache, log, and temp locations are scanned.\nNothing is removed until you review the list and confirm.").weak().small());
    }

    fn clean_modals(&mut self, ctx: &egui::Context) {
        if self.confirm_clean {
            let (n, total): (usize, u64) = self
                .clean_rows
                .iter()
                .filter(|r| r.checked)
                .fold((0, 0), |(n, t), r| (n + r.items.len(), t + r.items.iter().map(|i| i.size).sum::<u64>()));
            let mut go = false;
            let mut cancel = false;
            egui::Modal::new(egui::Id::new("confirm-clean")).show(ctx, |ui| {
                ui.heading("Confirm Cleanup");
                ui.label(format!(
                    "This will permanently remove {n} items, freeing approximately {}.\n\nThese are all regenerable cache/log/temp files — nothing\ncontaining your documents or unique data will be touched.",
                    human(total)
                ));
                for r in self.clean_rows.iter().filter(|r| r.checked && !r.items.is_empty()) {
                    ui.label(format!("• {} — {} items, {}", r.cat.label, r.items.len(), human(r.items.iter().map(|i| i.size).sum())));
                }
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                    if ui.button(RichText::new("Yes, clean").strong()).clicked() {
                        go = true;
                    }
                });
            });
            if go {
                self.confirm_clean = false;
                self.start_clean(ctx);
            } else if cancel {
                self.confirm_clean = false;
            }
        }
        if let Some(msg) = self.clean_done_msg.clone() {
            egui::Modal::new(egui::Id::new("clean-done")).show(ctx, |ui| {
                ui.heading("Cleanup Complete");
                ui.label(msg);
                if ui.button("OK").clicked() {
                    self.clean_done_msg = None;
                }
            });
        }
    }

    fn disk_tab(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if !self.disk_started {
            self.disk_started = true;
            self.start_disk(&ctx);
        }
        ui.label(RichText::new("Shows where your disk space is going. This tab never deletes anything — it's purely a map to help you decide what to look at.").weak().small());
        ui.horizontal(|ui| {
            if self.disk_busy {
                ui.spinner();
            }
            ui.label(&self.disk_status);
        });
        let max = self.disk_rows.iter().map(|r| r.2).max().unwrap_or(1).max(1);
        egui::ScrollArea::vertical().max_height(ui.available_height() - 40.0).auto_shrink([false, false]).show(ui, |ui| {
            for (label, path, size) in &self.disk_rows {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(label).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| ui.label(human(*size)));
                });
                ui.add(egui::ProgressBar::new(*size as f32 / max as f32).desired_height(8.0));
                ui.label(RichText::new(path.display().to_string()).weak().small());
                ui.add_space(4.0);
            }
        });
        if ui.add_enabled(!self.disk_busy, egui::Button::new("Remeasure")).clicked() {
            self.start_disk(&ctx);
        }
    }

    fn start_disk(&mut self, ctx: &egui::Context) {
        let (tx, rx) = channel();
        self.disk_rx = Some(rx);
        self.disk_busy = true;
        self.disk_rows.clear();
        self.disk_status = "Measuring…".into();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let v = cleaner::measure_disk_usage(&crate::util::home(), |m| {
                let _ = tx.send(DiskMsg::Progress(m.to_string()));
                ctx.request_repaint();
            });
            let _ = tx.send(DiskMsg::Done(v));
            ctx.request_repaint();
        });
    }

    fn history_tab(&mut self, ui: &mut egui::Ui) {
        if !self.hist_loaded {
            if let Ok(h) = History::open_default() {
                self.hist_cleanups = h.load_cleanups(200).unwrap_or_default();
                self.hist_actions = h.load_actions(200).unwrap_or_default();
            }
            self.hist_loaded = true;
        }
        ui.label(RichText::new("A local log of every cleanup and every security action this app has performed — what, when, and the result. Stored only on this Mac.").weak().small());
        if ui.button("Refresh").clicked() {
            self.hist_loaded = false;
        }
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.heading("Cleanups");
            if self.hist_cleanups.is_empty() {
                ui.label("No cleanups recorded yet — run a clean from the Clean tab.");
            } else {
                egui::Grid::new("cleanups").striped(true).num_columns(4).show(ui, |ui| {
                    for h in ["Date / Time", "Category", "Items Removed", "Space Freed"] {
                        ui.label(RichText::new(h).strong());
                    }
                    ui.end_row();
                    for r in &self.hist_cleanups {
                        ui.label(&r.ts);
                        ui.label(&r.category);
                        ui.label(r.items.to_string());
                        ui.label(human(r.bytes_freed.max(0) as u64));
                        ui.end_row();
                    }
                });
                let items: i64 = self.hist_cleanups.iter().map(|r| r.items).sum();
                let freed: i64 = self.hist_cleanups.iter().map(|r| r.bytes_freed).sum();
                ui.label(RichText::new(format!(
                    "All-time: {items} items removed, {} freed across {} logged entries",
                    human(freed.max(0) as u64),
                    self.hist_cleanups.len()
                ))
                .weak());
            }
            ui.add_space(10.0);
            ui.heading("Security actions");
            if self.hist_actions.is_empty() {
                ui.label("No security actions yet.");
            }
            for a in self.hist_actions.clone() {
                egui::CollapsingHeader::new(format!("{}  {} — {}{}", a.ts, a.check_title, a.action, if a.undone { " (undone)" } else { "" }))
                    .id_salt(("act", a.id))
                    .show(ui, |ui| {
                        ui.label(format!("Before: {}", a.before));
                        ui.label(format!("After: {}", a.after));
                        ui.label(format!("Result: {}", a.result));
                        ui.label(RichText::new("Commands:").strong());
                        ui.label(RichText::new(&a.commands).monospace().small());
                        if a.undo_json.is_some() && !a.undone && ui.add_enabled(!self.action_busy, egui::Button::new("Undo…")).clicked() {
                            self.confirm_undo = Some(a.clone());
                        }
                    });
            }
        });
    }

    fn undo_modal(&mut self, ctx: &egui::Context) {
        let Some(a) = self.confirm_undo.clone() else { return };
        let steps: Vec<security::Step> = a.undo_json.as_deref().and_then(|j| serde_json::from_str(j).ok()).unwrap_or_default();
        let mut go = false;
        let mut cancel = false;
        egui::Modal::new(egui::Id::new("undo")).show(ctx, |ui| {
            ui.set_max_width(640.0);
            ui.heading(format!("Undo \"{}\"?", a.action));
            ui.label("These commands will run:");
            for s in &steps {
                ui.label(RichText::new(security::fix::preview_step(s)).monospace());
            }
            if steps.iter().any(|s| matches!(s, security::Step::Admin { .. })) {
                ui.label("macOS will ask for an administrator password in its own dialog.");
            }
            ui.horizontal(|ui| {
                if ui.button("Undo").clicked() {
                    go = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if go {
            self.confirm_undo = None;
            self.action_busy = true;
            let tx = self.sec_tx.clone();
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                let r = security::undo_action(a.id, a.undo_json.as_deref().unwrap_or("[]"), &a.check_title);
                let _ = tx.send(SecMsg::Undo(r));
                ctx.request_repaint();
            });
        } else if cancel {
            self.confirm_undo = None;
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll(&ctx);
        egui::Panel::top("header").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Mac Cleaner Pro").size(20.0).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let quit = egui::Button::new(RichText::new("Quit").color(Color32::from_rgb(221, 136, 136)));
                    if ui.add_enabled(!self.cleaning, quit).on_hover_text("Quit Mac Cleaner Pro").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    let mut on = self.schedule_on;
                    if ui
                        .checkbox(&mut on, "Weekly cleanup reminders")
                        .on_hover_text("Runs a silent background scan (and the read-only security audit) once a week and shows a notification.\nNever deletes or fixes anything automatically — that always requires you to open the app and confirm.")
                        .changed()
                    {
                        let r = if on { crate::schedule::enable() } else { crate::schedule::disable() };
                        if r.is_ok() {
                            self.schedule_on = on;
                        }
                    }
                });
            });
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Clean, "Clean");
                ui.selectable_value(&mut self.tab, Tab::Disk, "Disk Usage");
                ui.selectable_value(&mut self.tab, Tab::History, "History");
                ui.selectable_value(&mut self.tab, Tab::Security, "Security");
            });
            ui.add_space(4.0);
        });
        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Clean => self.clean_tab(ui),
            Tab::Disk => self.disk_tab(ui),
            Tab::History => self.history_tab(ui),
            Tab::Security => self.security_tab(ui),
        });
        self.clean_modals(&ctx);
        self.fix_modal(&ctx);
        self.undo_modal(&ctx);
        if self.clean_busy || self.disk_busy || self.action_busy || self.results.iter().any(|r| r.is_none()) && self.results.iter().any(|r| r.is_some()) {
            ctx.request_repaint_after(std::time::Duration::from_millis(150));
        }
    }
}

pub fn run_gui() -> Result<(), String> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title("Mac Cleaner Pro").with_inner_size([900.0, 700.0]).with_min_inner_size([640.0, 480.0]),
        ..Default::default()
    };
    eframe::run_native("Mac Cleaner Pro", opts, Box::new(|cc| Ok(Box::new(App::new(cc))))).map_err(|e| e.to_string())
}
