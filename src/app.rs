use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc;

use eframe::egui;

use crate::io;
use crate::model::{AuthMethod, Endpoint, EndpointCreds, ServerProfile};
use crate::pages;
use crate::ufw::{self, FirewallState, RuleDraft};
use crate::worker::{self, FailHint, Job, JobDone, JobKind, Outcome, RefreshData};

pub const APP_NAME: &str = "UFW Manager";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Overview,
    Rules,
    Apps,
    Servers,
    Log,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoMode {
    Import,
    Export,
}

#[derive(Clone)]
pub struct IoDialog {
    pub mode: IoMode,
    pub path: String,
    pub format_json: bool,
    pub include_servers: bool,
    pub import_servers: bool,
    pub replace: bool,
    pub error: Option<String>,
}

impl IoDialog {
    pub fn export() -> Self {
        IoDialog {
            mode: IoMode::Export,
            path: "ufw-export.json".into(),
            format_json: true,
            include_servers: false,
            import_servers: false,
            replace: false,
            error: None,
        }
    }

    pub fn import() -> Self {
        IoDialog {
            mode: IoMode::Import,
            path: String::new(),
            format_json: true,
            include_servers: false,
            import_servers: true,
            replace: false,
            error: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptKind {
    Sudo,
    SshPassword,
    KeyPassphrase,
}

pub struct Prompt {
    pub kind: PromptKind,
    pub endpoint_key: String,
    pub title: String,
    pub message: String,
    pub password: String,
}

pub struct ServerDraft {
    pub profile: ServerProfile,
    pub is_new: bool,
    pub port_str: String,
    pub error: Option<String>,
}

pub enum Confirm {
    DeleteRule {
        number: usize,
        desc: String,
    },
    DeleteServer {
        id: String,
        label: String,
    },
    Import {
        script: String,
        servers: Vec<ServerProfile>,
        import_servers: bool,
        commands: usize,
    },
}

pub struct LogEntry {
    pub label: String,
    pub output: String,
    pub ok: bool,
}

pub struct App {
    pub(crate) page: Page,
    pub(crate) endpoint_key: String,
    pub(crate) fw: FirewallState,
    pub(crate) servers: Vec<ServerProfile>,
    pub(crate) connected: HashMap<String, bool>,

    pub(crate) creds: HashMap<String, EndpointCreds>,
    pub(crate) prompt: Option<Prompt>,
    pub(crate) retry: Option<(Endpoint, JobKind)>,

    pub(crate) theme_dark: bool,
    pub(crate) status_msg: String,
    pub(crate) pending: usize,
    pub(crate) next_job_id: u64,
    pub(crate) log: Vec<LogEntry>,

    pub(crate) rule_filter: String,
    pub(crate) selected_rule: Option<usize>,
    pub(crate) add_rule_open: bool,
    pub(crate) rule_draft: RuleDraft,
    pub(crate) rule_error: Option<String>,

    pub(crate) selected_app: Option<String>,
    pub(crate) app_info: Option<(String, String)>,
    pub(crate) app_info_job: Option<(u64, String)>,
    pub(crate) app_direction: crate::ufw::Direction,

    pub(crate) server_draft: Option<ServerDraft>,
    pub(crate) io_dialog: Option<IoDialog>,
    pub(crate) confirm: Option<Confirm>,

    pub(crate) jobs_tx: mpsc::Sender<Job>,
    pub(crate) done_rx: mpsc::Receiver<JobDone>,
    in_flight: HashMap<u64, (Endpoint, JobKind)>,
    last_endpoint_key: String,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let theme_dark = cc
            .storage
            .and_then(|s| eframe::get_value(s, "theme_dark"))
            .unwrap_or(true);
        let (jobs_tx, done_rx) = worker::spawn(cc.egui_ctx.clone());
        let servers = io::load_servers();

        let mut app = App {
            page: Page::Overview,
            endpoint_key: "local".into(),
            fw: FirewallState::default(),
            servers,
            connected: HashMap::new(),
            creds: HashMap::new(),
            prompt: None,
            retry: None,
            theme_dark,
            status_msg: "Ready".into(),
            pending: 0,
            next_job_id: 1,
            log: Vec::new(),
            rule_filter: String::new(),
            selected_rule: None,
            add_rule_open: false,
            rule_draft: RuleDraft::default(),
            rule_error: None,
            selected_app: None,
            app_info: None,
            app_info_job: None,
            app_direction: crate::ufw::Direction::In,
            server_draft: None,
            io_dialog: None,
            confirm: None,
            jobs_tx,
            done_rx,
            in_flight: HashMap::new(),
            last_endpoint_key: "local".into(),
        };
        app.apply_theme(&cc.egui_ctx);
        app.dispatch(JobKind::Refresh);
        app.status_msg = "Loading local firewall state…".into();
        app
    }

    pub(crate) fn apply_theme(&self, ctx: &egui::Context) {
        ctx.set_visuals(if self.theme_dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        });
    }

    pub(crate) fn endpoint(&self) -> Endpoint {
        Endpoint::from_key(&self.endpoint_key)
    }

    pub(crate) fn is_current(&self, ep: &Endpoint) -> bool {
        ep.key() == self.endpoint_key
    }

    pub(crate) fn server(&self, id: &str) -> Option<&ServerProfile> {
        self.servers.iter().find(|s| s.id == id)
    }

    pub(crate) fn endpoint_label(&self, key: &str) -> String {
        if key == "local" {
            "Local machine".to_string()
        } else {
            match self.server(key) {
                Some(s) => format!("{} ({})", s.label, s.target()),
                None => "Unknown server".to_string(),
            }
        }
    }

    pub(crate) fn endpoint_display(&self, ep: &Endpoint) -> String {
        self.endpoint_label(ep.key())
    }

    pub(crate) fn is_connected(&self, key: &str) -> bool {
        if key == "local" {
            return true;
        }
        self.connected.get(key).copied().unwrap_or(false)
    }

    pub(crate) fn push_log(&mut self, label: &str, output: &str, ok: bool) {
        self.log.push(LogEntry {
            label: label.to_string(),
            output: output.to_string(),
            ok,
        });
        if self.log.len() > 500 {
            let excess = self.log.len() - 500;
            self.log.drain(0..excess);
        }
    }

    pub(crate) fn dispatch(&mut self, kind: JobKind) -> u64 {
        let ep = self.endpoint();
        self.dispatch_at(ep, kind)
    }

    pub(crate) fn dispatch_at(&mut self, endpoint: Endpoint, kind: JobKind) -> u64 {
        let id = self.next_job_id;
        self.next_job_id += 1;
        let profile = match &endpoint {
            Endpoint::Local => None,
            Endpoint::Server(sid) => self.server(sid).cloned(),
        };
        if let Endpoint::Server(sid) = &endpoint {
            if profile.is_none() {
                self.push_log("Dispatch", "server profile missing", false);
                return id;
            }
            let _ = sid;
        }
        let creds = self.creds.get(endpoint.key()).cloned().unwrap_or_default();
        let job = Job {
            id,
            endpoint: endpoint.clone(),
            profile,
            creds,
            kind: kind.clone(),
        };
        if self.jobs_tx.send(job).is_ok() {
            self.pending += 1;
            self.in_flight.insert(id, (endpoint, kind));
        }
        id
    }

    /// Run a ufw command; on success the firewall state is refreshed.
    pub(crate) fn run_exec(&mut self, label: &str, script: String) -> u64 {
        let kind = JobKind::Exec {
            script,
            label: label.to_string(),
            privileged: true,
            mutating: true,
        };
        self.dispatch(kind)
    }

    /// Run a read-only ufw command (no refresh afterwards).
    pub(crate) fn run_query(&mut self, label: &str, script: String) -> u64 {
        let kind = JobKind::Exec {
            script,
            label: label.to_string(),
            privileged: true,
            mutating: false,
        };
        self.dispatch(kind)
    }

    fn drain_jobs(&mut self) {
        while let Ok(done) = self.done_rx.try_recv() {
            self.pending = self.pending.saturating_sub(1);
            self.on_done(done);
        }
    }

    fn on_done(&mut self, done: JobDone) {
        let job_info = self.in_flight.remove(&done.id);
        let endpoint = done.endpoint.clone();

        match done.outcome {
            Outcome::Connect(Ok(msg)) => {
                if let Endpoint::Server(sid) = &endpoint {
                    self.connected.insert(sid.clone(), true);
                }
                self.push_log("Connect", &msg, true);
                self.status_msg = msg;
                self.dispatch_at(endpoint, JobKind::Refresh);
            }
            Outcome::Connect(Err(f)) => {
                if let Endpoint::Server(sid) = &endpoint {
                    self.connected.insert(sid.clone(), false);
                }
                self.push_log("Connect failed", &f.message, false);
                self.status_msg = format!("Connect failed: {}", first_line(&f.message));
                let retry = job_info;
                self.maybe_prompt(f.hint, endpoint, retry);
            }
            Outcome::Disconnect => {
                if let Endpoint::Server(sid) = &endpoint {
                    self.connected.insert(sid.clone(), false);
                }
                self.push_log("Disconnect", "session closed", true);
                self.status_msg = "Disconnected".into();
            }
            Outcome::Refresh(Ok(data)) => {
                if self.is_current(&endpoint) {
                    self.apply_refresh(data);
                    self.status_msg = format!("Refreshed {}", self.endpoint_display(&endpoint));
                }
                if let Endpoint::Server(sid) = &endpoint {
                    self.connected.insert(sid.clone(), true);
                }
            }
            Outcome::Refresh(Err(f)) => {
                self.push_log("Refresh failed", &f.message, false);
                self.status_msg = format!("Refresh failed: {}", first_line(&f.message));
                let retry = job_info;
                self.maybe_prompt(f.hint, endpoint, retry);
            }
            Outcome::Exec { label, result } => match result {
                Ok(o) => {
                    let output = join_output(&o.stdout, &o.stderr);
                    let ok = o.status.is_none_or(|s| s == 0);
                    if let Some((jid, name)) = self.app_info_job.take()
                        && jid == done.id
                    {
                        self.app_info = Some((name, output.clone()));
                    }
                    self.push_log(&label, &output, ok);
                    if ok {
                        self.status_msg = format!("{label}: done");
                    } else {
                        self.status_msg =
                            format!("{label}: failed (exit {})", o.status.unwrap_or(-1));
                    }
                    if ok
                        && self.is_current(&endpoint)
                        && let Some((_, kind)) = &job_info
                        && matches!(kind, JobKind::Exec { mutating: true, .. })
                    {
                        self.dispatch(JobKind::Refresh);
                    }
                }
                Err(f) => {
                    self.push_log(&label, &f.message, false);
                    self.status_msg = format!("{label}: {}", first_line(&f.message));
                    let retry = job_info;
                    self.maybe_prompt(f.hint, endpoint, retry);
                }
            },
        }
    }

    fn maybe_prompt(
        &mut self,
        hint: FailHint,
        endpoint: Endpoint,
        retry: Option<(Endpoint, JobKind)>,
    ) {
        if self.prompt.is_some() {
            return;
        }
        let target = self.endpoint_display(&endpoint);
        let (kind, title, message) = match hint {
            FailHint::None => return,
            FailHint::SudoPassword => (
                PromptKind::Sudo,
                "Sudo password required",
                format!("Root privileges are needed for {target}."),
            ),
            FailHint::SshPassword => (
                PromptKind::SshPassword,
                "SSH password",
                format!("Password authentication for {target}."),
            ),
            FailHint::KeyPassphrase => (
                PromptKind::KeyPassphrase,
                "Key passphrase",
                format!("The SSH key for {target} is encrypted."),
            ),
        };
        self.retry = retry;
        self.prompt = Some(Prompt {
            kind,
            endpoint_key: endpoint.key().to_string(),
            title: title.into(),
            message,
            password: String::new(),
        });
    }

    pub(crate) fn prompt_save(&mut self) {
        let Some(p) = self.prompt.take() else { return };
        let pw = p.password.clone();
        let entry = self.creds.entry(p.endpoint_key).or_default();
        let value = (!pw.is_empty()).then_some(pw);
        match p.kind {
            PromptKind::Sudo => entry.sudo_password = value,
            PromptKind::SshPassword => entry.ssh_password = value,
            PromptKind::KeyPassphrase => entry.key_passphrase = value,
        }
        if let Some((ep, kind)) = self.retry.take() {
            self.status_msg = "Retrying…".into();
            self.dispatch_at(ep, kind);
        }
    }

    pub(crate) fn prompt_cancel(&mut self) {
        self.prompt = None;
        self.retry = None;
    }

    fn apply_refresh(&mut self, data: RefreshData) {
        let (active, logging, defaults) = ufw::parse_verbose(&data.verbose);
        let rules = ufw::parse_numbered(&data.numbered);
        let added = ufw::parse_show_added(&data.added);
        let apps = ufw::parse_app_list(&data.apps);
        self.fw = FirewallState {
            loaded: true,
            active,
            logging,
            defaults,
            rules,
            added_commands: added,
            apps,
            raw_verbose: data.verbose,
        };
        if let Some(n) = self.selected_rule
            && !self.fw.rules.iter().any(|r| r.number == n)
        {
            self.selected_rule = None;
        }
    }

    pub(crate) fn save_servers(&mut self) {
        match io::save_servers(&self.servers) {
            Ok(()) => {}
            Err(e) => {
                self.push_log("Save servers", &e, false);
                self.status_msg = format!("Could not save servers: {e}");
            }
        }
    }

    pub(crate) fn merge_servers(&mut self, incoming: Vec<ServerProfile>) {
        for s in incoming {
            match self.servers.iter().position(|e| e.id == s.id) {
                Some(i) => self.servers[i] = s,
                None => self.servers.push(s),
            }
        }
        self.save_servers();
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("top_bar").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("UFW MANAGER").strong().size(15.0));
                ui.separator();

                let mut selected = self.endpoint_key.clone();
                egui::ComboBox::from_id_salt("endpoint_combo")
                    .selected_text(self.endpoint_label(&selected))
                    .width(250.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut selected, "local".into(), "Local machine");
                        for s in &self.servers {
                            ui.selectable_value(
                                &mut selected,
                                s.id.clone(),
                                format!("{} — {}", s.label, s.target()),
                            );
                        }
                    });
                if selected != self.endpoint_key {
                    self.endpoint_key = selected;
                }

                let connected = self.is_connected(&self.endpoint_key.clone());
                ui.colored_label(
                    if connected {
                        egui::Color32::from_rgb(80, 200, 120)
                    } else {
                        egui::Color32::from_rgb(140, 140, 140)
                    },
                    "●",
                );
                ui.label(if connected {
                    "connected"
                } else {
                    "disconnected"
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Export…").clicked() {
                        self.io_dialog = Some(IoDialog::export());
                    }
                    if ui.button("Import…").clicked() {
                        self.io_dialog = Some(IoDialog::import());
                    }
                    let theme_label = if self.theme_dark {
                        "Light mode"
                    } else {
                        "Dark mode"
                    };
                    if ui.button(theme_label).clicked() {
                        self.theme_dark = !self.theme_dark;
                        self.apply_theme(ui.ctx());
                    }
                    if ui.button("Sudo password…").clicked() {
                        let ep = self.endpoint();
                        let target = self.endpoint_display(&ep);
                        self.prompt = Some(Prompt {
                            kind: PromptKind::Sudo,
                            endpoint_key: ep.key().to_string(),
                            title: "Sudo password".into(),
                            message: format!(
                                "Stored in memory for {target}; never written to disk."
                            ),
                            password: String::new(),
                        });
                        self.retry = None;
                    }
                    if ui.button("Refresh").clicked() {
                        self.status_msg = "Refreshing…".into();
                        self.dispatch(JobKind::Refresh);
                    }
                    if self.endpoint_key != "local" {
                        let key = self.endpoint_key.clone();
                        if self.is_connected(&key) {
                            if ui.button("Disconnect").clicked() {
                                let ep = Endpoint::from_key(&key);
                                self.dispatch_at(ep, JobKind::Disconnect);
                            }
                        } else if ui.button("Connect").clicked() {
                            let ep = Endpoint::from_key(&key);
                            self.status_msg = "Connecting…".into();
                            self.dispatch_at(ep, JobKind::Connect);
                        }
                    }
                });
            });
            ui.add_space(6.0);
        });
    }

    fn side_nav(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("nav_panel")
            .resizable(true)
            .default_size(172.0)
            .min_size(140.0)
            .show(ui, |ui| {
                ui.add_space(10.0);
                let items = [
                    (Page::Overview, "Overview"),
                    (Page::Rules, "Rules"),
                    (Page::Apps, "Applications"),
                    (Page::Servers, "Servers"),
                    (Page::Log, "Command log"),
                ];
                for (page, label) in items {
                    let selected = self.page == page;
                    let resp = ui.selectable_label(selected, label);
                    if resp.clicked() {
                        self.page = page;
                    }
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(self.endpoint_label(&self.endpoint_key.clone())).weak(),
                    );
                    ui.label(egui::RichText::new(format!("{} rules", self.fw.rules.len())).weak());
                });
            });
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("status_bar").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if self.pending > 0 {
                    ui.spinner();
                    ui.label(format!("{} operation(s) running", self.pending));
                } else {
                    ui.label("idle");
                }
                ui.separator();
                ui.label(&self.status_msg);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(format!(
                            "{} rules · {} apps · {}",
                            self.fw.rules.len(),
                            self.fw.apps.len(),
                            if self.fw.active { "active" } else { "inactive" }
                        ))
                        .weak(),
                    );
                });
            });
            ui.add_space(4.0);
        });
    }

    fn windows(&mut self, ctx: &egui::Context) {
        self.add_rule_window(ctx);
        self.server_editor_window(ctx);
        self.io_window(ctx);
        self.confirm_window(ctx);
        self.prompt_window(ctx);
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain_jobs();

        if self.endpoint_key != self.last_endpoint_key {
            self.last_endpoint_key = self.endpoint_key.clone();
            self.fw = FirewallState::default();
            self.selected_rule = None;
            self.selected_app = None;
            self.app_info = None;
            self.status_msg = format!(
                "Switched to {} — refreshing…",
                self.endpoint_label(&self.endpoint_key.clone())
            );
            self.dispatch(JobKind::Refresh);
        }

        self.top_bar(ui);
        self.side_nav(ui);
        self.status_bar(ui);

        egui::CentralPanel::default().show(ui, |ui| match self.page {
            Page::Overview => pages::ui_overview(self, ui),
            Page::Rules => pages::ui_rules(self, ui),
            Page::Apps => pages::ui_apps(self, ui),
            Page::Servers => pages::ui_servers(self, ui),
            Page::Log => pages::ui_log(self, ui),
        });

        let ctx = ui.ctx().clone();
        self.windows(&ctx);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, "theme_dark", &self.theme_dark);
    }
}

fn first_line(s: &str) -> String {
    s.lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("unknown error")
        .to_string()
}

pub(crate) fn join_output(stdout: &str, stderr: &str) -> String {
    match (stdout.trim().is_empty(), stderr.trim().is_empty()) {
        (true, true) => String::new(),
        (false, true) => stdout.to_string(),
        (true, false) => stderr.to_string(),
        (false, false) => format!("{}\n{}", stdout.trim_end(), stderr.trim()),
    }
}

// --- Dialog windows -------------------------------------------------------

impl App {
    fn add_rule_window(&mut self, ctx: &egui::Context) {
        if !self.add_rule_open {
            return;
        }
        let mut open = true;
        let mut error = self.rule_error.take();
        egui::Window::new("Add firewall rule")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(380.0)
            .show(ctx, |ui| {
                egui::Grid::new("rule_grid")
                    .num_columns(2)
                    .spacing([12.0, 8.0])
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("Action").strong());
                        ui.horizontal(|ui| {
                            for a in [ufw::Action::Allow, ufw::Action::Deny, ufw::Action::Reject] {
                                ui.selectable_value(&mut self.rule_draft.action, a, a.label());
                            }
                        });
                        ui.end_row();

                        ui.label(egui::RichText::new("Direction").strong());
                        ui.horizontal(|ui| {
                            for d in [
                                ufw::Direction::In,
                                ufw::Direction::Out,
                                ufw::Direction::Routed,
                            ] {
                                ui.selectable_value(&mut self.rule_draft.direction, d, d.as_str());
                            }
                        });
                        ui.end_row();

                        ui.label(egui::RichText::new("Protocol").strong());
                        egui::ComboBox::from_id_salt("rule_proto")
                            .selected_text(self.rule_draft.proto.clone())
                            .width(120.0)
                            .show_ui(ui, |ui| {
                                for p in ["tcp", "udp", "any"] {
                                    ui.selectable_value(
                                        &mut self.rule_draft.proto,
                                        p.to_string(),
                                        p,
                                    );
                                }
                            });
                        ui.end_row();

                        ui.label(egui::RichText::new("Port").strong());
                        ui.add(
                            egui::TextEdit::singleline(&mut self.rule_draft.port)
                                .hint_text("22, 80, 8000:8100")
                                .desired_width(160.0),
                        );
                        ui.end_row();

                        ui.label(egui::RichText::new("Source").strong());
                        ui.add(
                            egui::TextEdit::singleline(&mut self.rule_draft.from_addr)
                                .hint_text("any (default), 10.0.0.0/8")
                                .desired_width(200.0),
                        );
                        ui.end_row();

                        ui.label(egui::RichText::new("Destination").strong());
                        ui.add(
                            egui::TextEdit::singleline(&mut self.rule_draft.to_addr)
                                .hint_text("any (default), 192.168.1.5")
                                .desired_width(200.0),
                        );
                        ui.end_row();

                        ui.label(egui::RichText::new("Interface").strong());
                        ui.add(
                            egui::TextEdit::singleline(&mut self.rule_draft.interface)
                                .hint_text("e.g. eth0")
                                .desired_width(120.0),
                        );
                        ui.end_row();

                        ui.label(egui::RichText::new("Comment").strong());
                        ui.add(
                            egui::TextEdit::singleline(&mut self.rule_draft.comment)
                                .hint_text("optional")
                                .desired_width(200.0),
                        );
                        ui.end_row();
                    });

                ui.checkbox(&mut self.rule_draft.dry_run, "Dry run (preview only)");
                ui.add_space(4.0);

                match ufw::build_rule_command(&self.rule_draft) {
                    Ok(cmd) => {
                        ui.label(egui::RichText::new("Command:").weak());
                        ui.monospace(cmd);
                    }
                    Err(e) => {
                        ui.colored_label(egui::Color32::from_rgb(240, 120, 100), e);
                    }
                }

                if let Some(err) = &error {
                    ui.colored_label(egui::Color32::from_rgb(240, 120, 100), err);
                }

                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Add rule").clicked() {
                        match ufw::build_rule_command(&self.rule_draft) {
                            Ok(cmd) => {
                                let label = if self.rule_draft.dry_run {
                                    "Dry run".to_string()
                                } else {
                                    "Add rule".to_string()
                                };
                                self.run_exec(&label, cmd);
                                self.add_rule_open = false;
                            }
                            Err(e) => error = Some(e),
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        self.add_rule_open = false;
                    }
                });
            });
        if !open {
            self.add_rule_open = false;
        }
        self.rule_error = error;
    }

    fn server_editor_window(&mut self, ctx: &egui::Context) {
        if self.server_draft.is_none() {
            return;
        }
        let mut open = true;
        let mut save = false;
        let mut cancel = false;
        let mut browse = false;
        egui::Window::new(
            if self
                .server_draft
                .as_ref()
                .map(|d| d.is_new)
                .unwrap_or(false)
            {
                "Add server"
            } else {
                "Edit server"
            },
        )
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .default_width(400.0)
        .show(ctx, |ui| {
            if let Some(draft) = self.server_draft.as_mut() {
                egui::Grid::new("server_grid")
                    .num_columns(2)
                    .spacing([12.0, 8.0])
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("Label").strong());
                        ui.add(
                            egui::TextEdit::singleline(&mut draft.profile.label)
                                .hint_text("production web")
                                .desired_width(220.0),
                        );
                        ui.end_row();

                        ui.label(egui::RichText::new("Host").strong());
                        ui.add(
                            egui::TextEdit::singleline(&mut draft.profile.host)
                                .hint_text("192.0.2.10 or srv.example.com")
                                .desired_width(220.0),
                        );
                        ui.end_row();

                        ui.label(egui::RichText::new("Port").strong());
                        ui.add(egui::TextEdit::singleline(&mut draft.port_str).desired_width(80.0));
                        ui.end_row();

                        ui.label(egui::RichText::new("User").strong());
                        ui.add(
                            egui::TextEdit::singleline(&mut draft.profile.user)
                                .hint_text("root or admin")
                                .desired_width(220.0),
                        );
                        ui.end_row();

                        ui.label(egui::RichText::new("Authentication").strong());
                        ui.horizontal(|ui| {
                            ui.selectable_value(
                                &mut draft.profile.auth_method,
                                AuthMethod::Key,
                                "SSH key",
                            );
                            ui.selectable_value(
                                &mut draft.profile.auth_method,
                                AuthMethod::Password,
                                "Password",
                            );
                        });
                        ui.end_row();

                        if draft.profile.auth_method == AuthMethod::Key {
                            ui.label(egui::RichText::new("Key file").strong());
                            ui.horizontal(|ui| {
                                let mut path = draft.profile.key_path.clone().unwrap_or_default();
                                ui.add(
                                    egui::TextEdit::singleline(&mut path)
                                        .hint_text("empty = ~/.ssh/id_ed25519, id_ecdsa, id_rsa")
                                        .desired_width(190.0),
                                );
                                draft.profile.key_path = if path.trim().is_empty() {
                                    None
                                } else {
                                    Some(path.clone())
                                };
                                if ui.button("…").on_hover_text("Browse").clicked() {
                                    browse = true;
                                }
                            });
                            ui.end_row();
                        }

                        ui.label(egui::RichText::new("Privileges").strong());
                        ui.checkbox(
                            &mut draft.profile.use_sudo,
                            "Run firewall commands with sudo",
                        );
                        ui.end_row();

                        ui.label(egui::RichText::new("Host keys").strong());
                        ui.checkbox(
                            &mut draft.profile.accept_new_host_keys,
                            "Automatically accept new host keys",
                        );
                        ui.end_row();
                    });

                if let Some(err) = &draft.error {
                    ui.colored_label(egui::Color32::from_rgb(240, 120, 100), err);
                }

                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        save = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            }
        });
        if !open {
            cancel = true;
        }

        if browse
            && let Some(path) = rfd::FileDialog::new().pick_file()
            && let Some(draft) = self.server_draft.as_mut()
        {
            draft.profile.key_path = Some(path.display().to_string());
        }

        if save {
            if let Some(draft) = self.server_draft.take() {
                match validate_server_draft(draft) {
                    Ok((profile, is_new)) => {
                        if is_new {
                            self.servers.push(profile);
                        } else if let Some(slot) =
                            self.servers.iter_mut().find(|s| s.id == profile.id)
                        {
                            *slot = profile;
                        }
                        self.save_servers();
                        self.status_msg = "Server saved".into();
                    }
                    Err((draft, err)) => {
                        let mut draft = draft;
                        draft.error = Some(err);
                        self.server_draft = Some(*draft);
                    }
                }
            }
        } else if cancel {
            self.server_draft = None;
        }
    }

    fn io_window(&mut self, ctx: &egui::Context) {
        if self.io_dialog.is_none() {
            return;
        }
        let mut open = true;
        let mut browse = false;
        let mut apply = false;
        let mut close = false;
        let title = if self.io_dialog.as_ref().unwrap().mode == IoMode::Export {
            "Export"
        } else {
            "Import"
        };
        egui::Window::new(title)
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(440.0)
            .show(ctx, |ui| {
                if let Some(dlg) = self.io_dialog.as_mut() {
                    ui.label(egui::RichText::new("File").strong());
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut dlg.path)
                                .desired_width(320.0)
                                .hint_text("/path/to/file"),
                        );
                        if ui.button("…").on_hover_text("Browse").clicked() {
                            browse = true;
                        }
                    });
                    ui.add_space(6.0);

                    match dlg.mode {
                        IoMode::Export => {
                            ui.checkbox(
                                &mut dlg.format_json,
                                "JSON format (structured, with settings)",
                            );
                            ui.checkbox(
                                &mut dlg.include_servers,
                                "Include saved server profiles (no passwords)",
                            );
                        }
                        IoMode::Import => {
                            ui.checkbox(
                                &mut dlg.import_servers,
                                "Also import saved server profiles when present",
                            );
                            ui.checkbox(
                                &mut dlg.replace,
                                "Replace mode: reset firewall first (DESTRUCTIVE)",
                            );
                            if dlg.replace {
                                ui.colored_label(
                                    egui::Color32::from_rgb(240, 170, 80),
                                    "All current rules will be deleted before applying the file.",
                                );
                            }
                        }
                    }

                    if let Some(err) = &dlg.error {
                        ui.add_space(4.0);
                        ui.colored_label(egui::Color32::from_rgb(240, 120, 100), err);
                    }

                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button(title).clicked() {
                            apply = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                }
            });
        if close {
            open = false;
        }

        if !open {
            self.io_dialog = None;
            return;
        }

        if browse {
            let picked = match self.io_dialog.as_ref().map(|d| d.mode) {
                Some(IoMode::Export) => rfd::FileDialog::new()
                    .set_file_name("ufw-export.json")
                    .add_filter("JSON", &["json"])
                    .add_filter("Shell script", &["sh"])
                    .save_file(),
                _ => rfd::FileDialog::new()
                    .add_filter("All files", &["*"])
                    .pick_file(),
            };
            if let (Some(path), Some(dlg)) = (picked, self.io_dialog.as_mut()) {
                dlg.path = path.display().to_string();
                dlg.error = None;
            }
        }

        if apply {
            self.apply_io();
        }
    }

    fn apply_io(&mut self) {
        let Some(dlg) = self.io_dialog.clone() else {
            return;
        };
        let path = PathBuf::from(dlg.path.trim());
        if dlg.path.trim().is_empty() {
            if let Some(d) = self.io_dialog.as_mut() {
                d.error = Some("Choose a file path".into());
            }
            return;
        }

        match dlg.mode {
            IoMode::Export => {
                let content = if dlg.format_json {
                    io::build_json_bundle(
                        &self.fw,
                        if dlg.include_servers {
                            Some(self.servers.as_slice())
                        } else {
                            None
                        },
                    )
                } else {
                    Ok(io::build_script(&self.fw))
                };
                match content {
                    Ok(content) => match io::write_file(&path, &content) {
                        Ok(()) => {
                            self.status_msg = format!("Exported to {}", path.display());
                            let msg = self.status_msg.clone();
                            self.push_log("Export", &msg, true);
                            self.io_dialog = None;
                        }
                        Err(e) => {
                            if let Some(d) = self.io_dialog.as_mut() {
                                d.error = Some(e);
                            }
                        }
                    },
                    Err(e) => {
                        if let Some(d) = self.io_dialog.as_mut() {
                            d.error = Some(e);
                        }
                    }
                }
            }
            IoMode::Import => {
                let content = match io::read_file(&path) {
                    Ok(c) => c,
                    Err(e) => {
                        if let Some(d) = self.io_dialog.as_mut() {
                            d.error = Some(e);
                        }
                        return;
                    }
                };
                let plan = match io::parse_import(&content) {
                    Ok(p) => p,
                    Err(e) => {
                        if let Some(d) = self.io_dialog.as_mut() {
                            d.error = Some(e);
                        }
                        return;
                    }
                };
                let commands = plan.commands.len();
                let servers = plan.servers.clone();
                let source = if plan.from_json { "bundle" } else { "script" };
                let script = io::plan_to_script(&plan, dlg.replace, self.fw.active);
                let import_servers = dlg.import_servers && !servers.is_empty();

                if dlg.replace {
                    self.confirm = Some(Confirm::Import {
                        script,
                        servers,
                        import_servers,
                        commands,
                    });
                    self.io_dialog = None;
                } else {
                    if import_servers {
                        let servers = servers.clone();
                        self.merge_servers(servers);
                    }
                    self.status_msg = format!("Importing {commands} command(s) from {source}…");
                    self.run_exec("Import firewall rules", script);
                    self.io_dialog = None;
                }
            }
        }
    }

    fn confirm_window(&mut self, ctx: &egui::Context) {
        if self.confirm.is_none() {
            return;
        }
        let mut open = true;
        let mut close = false;
        let mut confirmed = false;
        let title = match self.confirm.as_ref().unwrap() {
            Confirm::DeleteRule { .. } => "Delete rule",
            Confirm::DeleteServer { .. } => "Delete server",
            Confirm::Import { .. } => "Replace firewall?",
        };
        egui::Window::new(title)
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(360.0)
            .show(ctx, |ui| {
                match self.confirm.as_ref().unwrap() {
                    Confirm::DeleteRule { number, desc } => {
                        ui.label(format!("Delete rule #{number}: {desc}?"));
                    }
                    Confirm::DeleteServer { label, .. } => {
                        ui.label(format!("Remove server \"{label}\" from the list?"));
                    }
                    Confirm::Import { commands, .. } => {
                        ui.colored_label(
                            egui::Color32::from_rgb(240, 170, 80),
                            "This resets the firewall, deleting ALL current rules,",
                        );
                        ui.colored_label(
                            egui::Color32::from_rgb(240, 170, 80),
                            "then applies the imported configuration.",
                        );
                        ui.label(format!("{commands} command(s) will be applied."));
                    }
                }
                ui.separator();
                ui.horizontal(|ui| {
                    let yes_label = match self.confirm.as_ref().unwrap() {
                        Confirm::DeleteRule { .. } => "Delete",
                        Confirm::DeleteServer { .. } => "Remove",
                        Confirm::Import { .. } => "Replace and import",
                    };
                    if ui.button(yes_label).clicked() {
                        confirmed = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });
        if close {
            open = false;
        }
        if !open || !confirmed {
            if !open {
                self.confirm = None;
            }
            return;
        }

        let confirm = self.confirm.take();
        match confirm {
            Some(Confirm::DeleteRule { number, desc }) => {
                self.selected_rule = None;
                self.status_msg = format!("Deleting rule #{number}…");
                self.run_exec(
                    &format!("Delete rule #{number}"),
                    ufw::build_delete_command(number),
                );
                let _ = desc;
            }
            Some(Confirm::DeleteServer { id, label }) => {
                if self.endpoint_key == id {
                    self.dispatch_at(Endpoint::Server(id.clone()), JobKind::Disconnect);
                    self.endpoint_key = "local".into();
                }
                self.servers.retain(|s| s.id != id);
                self.connected.remove(&id);
                self.save_servers();
                self.status_msg = format!("Removed server \"{label}\"");
                let msg = self.status_msg.clone();
                self.push_log("Servers", &msg, true);
            }
            Some(Confirm::Import {
                script,
                servers,
                import_servers,
                commands,
            }) => {
                if import_servers {
                    self.merge_servers(servers);
                }
                self.status_msg = format!("Replacing firewall with {commands} command(s)…");
                self.run_exec("Import firewall rules (replace)", script);
            }
            None => {}
        }
    }

    fn prompt_window(&mut self, ctx: &egui::Context) {
        if self.prompt.is_none() {
            return;
        }
        let mut open = true;
        let mut save = false;
        let mut cancel = false;
        let title = self.prompt.as_ref().unwrap().title.clone();
        egui::Window::new(title)
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(360.0)
            .show(ctx, |ui| {
                if let Some(p) = self.prompt.as_mut() {
                    ui.label(&p.message);
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new("Password").strong());
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut p.password)
                            .password(true)
                            .desired_width(240.0)
                            .hint_text("password"),
                    );
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        save = true;
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            save = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                    });
                }
            });
        if !open {
            cancel = true;
        }
        if save {
            self.prompt_save();
        } else if cancel {
            self.prompt_cancel();
        }
    }
}

fn validate_server_draft(
    draft: ServerDraft,
) -> Result<(ServerProfile, bool), (Box<ServerDraft>, String)> {
    let ServerDraft {
        mut profile,
        is_new,
        port_str,
        error: _,
    } = draft;
    let rebuild = |profile: ServerProfile, port_str: String| ServerDraft {
        profile,
        is_new,
        port_str,
        error: None,
    };
    if profile.label.trim().is_empty() {
        return Err((
            Box::new(rebuild(profile, port_str)),
            "Label is required".into(),
        ));
    }
    if profile.host.trim().is_empty() {
        return Err((
            Box::new(rebuild(profile, port_str)),
            "Host is required".into(),
        ));
    }
    if profile.user.trim().is_empty() {
        return Err((
            Box::new(rebuild(profile, port_str)),
            "User is required".into(),
        ));
    }
    let Ok(port) = port_str.trim().parse::<u16>() else {
        return Err((
            Box::new(rebuild(profile, port_str)),
            "Port must be a number between 1 and 65535".into(),
        ));
    };
    profile.port = port;
    profile.label = profile.label.trim().to_string();
    profile.host = profile.host.trim().to_string();
    profile.user = profile.user.trim().to_string();
    Ok((profile, is_new))
}
