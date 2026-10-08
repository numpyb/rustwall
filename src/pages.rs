use eframe::egui::{self, Color32, RichText};

use crate::app::{App, Confirm, IoDialog, ServerDraft};
use crate::model::{AuthMethod, Endpoint, Policy};
use crate::ufw::{self, Action, Direction, Rule, RuleDraft};
use crate::worker::JobKind;

fn allow_color() -> Color32 {
    Color32::from_rgb(90, 190, 120)
}

fn deny_color() -> Color32 {
    Color32::from_rgb(230, 100, 90)
}

fn reject_color() -> Color32 {
    Color32::from_rgb(235, 170, 80)
}

fn action_color(a: Action) -> Color32 {
    match a {
        Action::Allow => allow_color(),
        Action::Deny => deny_color(),
        Action::Reject => reject_color(),
    }
}

// --- Overview -------------------------------------------------------------

pub fn ui_overview(app: &mut App, ui: &mut egui::Ui) {
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                let (text, color) = if !app.fw.loaded {
                    ("UNKNOWN", ui.visuals().weak_text_color())
                } else if app.fw.active {
                    ("ACTIVE", allow_color())
                } else {
                    ("INACTIVE", reject_color())
                };
                ui.label(RichText::new(text).size(34.0).strong().color(color));
                if app.pending > 0 {
                    ui.add_space(14.0);
                    ui.spinner();
                }
            });
            ui.label(format!(
                "Endpoint: {}",
                app.endpoint_label(&app.endpoint_key.clone())
            ));
            ui.add_space(10.0);

            if !app.fw.loaded {
                ui.label(RichText::new("Firewall state not loaded yet.").weak());
                ui.add_space(6.0);
                if ui.button("Load now").clicked() {
                    app.dispatch(JobKind::Refresh);
                }
                return;
            }

            ui.separator();

            egui::Grid::new("overview_grid")
                .num_columns(2)
                .spacing([16.0, 10.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("Logging").strong());
                    let mut level = app.fw.logging.clone();
                    let changed = egui::ComboBox::from_id_salt("log_level")
                        .selected_text(level.clone())
                        .width(120.0)
                        .show_ui(ui, |ui| {
                            let mut picked = false;
                            for l in ["off", "low", "medium", "high", "full"] {
                                if ui.selectable_value(&mut level, l.to_string(), l).clicked() {
                                    picked = true;
                                }
                            }
                            picked
                        })
                        .inner
                        .unwrap_or(false);
                    if changed {
                        app.fw.logging = level.clone();
                        app.run_exec(
                            &format!("Set logging to {level}"),
                            format!("ufw logging {level}"),
                        );
                    }
                    ui.end_row();

                    ui.label(RichText::new("Incoming default").strong());
                    if let Some(p) = policy_row(ui, "def_in", app.fw.defaults.incoming, &[]) {
                        app.fw.defaults.incoming = p;
                        app.run_exec(
                            &format!("Incoming default: {}", p.as_str()),
                            format!("ufw default {} incoming", p.as_str()),
                        );
                    }
                    ui.end_row();

                    ui.label(RichText::new("Outgoing default").strong());
                    if let Some(p) = policy_row(ui, "def_out", app.fw.defaults.outgoing, &[]) {
                        app.fw.defaults.outgoing = p;
                        app.run_exec(
                            &format!("Outgoing default: {}", p.as_str()),
                            format!("ufw default {} outgoing", p.as_str()),
                        );
                    }
                    ui.end_row();

                    ui.label(RichText::new("Routed default").strong());
                    if let Some(p) =
                        policy_row(ui, "def_rte", app.fw.defaults.routed, &[Policy::Disabled])
                    {
                        app.fw.defaults.routed = p;
                        app.run_exec(
                            &format!("Routed default: {}", p.as_str()),
                            format!("ufw default {} routed", p.as_str()),
                        );
                    }
                    ui.end_row();

                    ui.label(RichText::new("Rules").strong());
                    ui.label(format!(
                        "{} rules · {} application profiles",
                        app.fw.rules.len(),
                        app.fw.apps.len()
                    ));
                    ui.end_row();
                });

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("Enable firewall").clicked() {
                    app.run_exec("Enable firewall", "ufw --force enable".into());
                }
                if ui.button("Disable firewall").clicked() {
                    app.run_exec("Disable firewall", "ufw --force disable".into());
                }
                if ui.button("Reload firewall").clicked() {
                    app.run_exec("Reload firewall", "ufw reload".into());
                }
            });

            ui.add_space(10.0);
            egui::CollapsingHeader::new("Raw status output")
                .default_open(false)
                .show(ui, |ui| {
                    ui.add(egui::Label::new(RichText::new(&app.fw.raw_verbose).monospace()).wrap());
                });
        });
}

fn policy_row(ui: &mut egui::Ui, id: &str, current: Policy, extra: &[Policy]) -> Option<Policy> {
    let mut picked = None;
    let mut chosen = current;
    egui::ComboBox::from_id_salt(id)
        .selected_text(current.as_str())
        .width(120.0)
        .show_ui(ui, |ui| {
            let mut opts = vec![Policy::Allow, Policy::Deny, Policy::Reject];
            for e in extra {
                if !opts.contains(e) {
                    opts.push(*e);
                }
            }
            for p in opts {
                if ui.selectable_value(&mut chosen, p, p.as_str()).clicked() {
                    picked = Some(p);
                }
            }
        });
    picked
}

// --- Rules ----------------------------------------------------------------

fn rule_matches(rule: &Rule, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    let mut hay = format!(
        "{} {} {} {} {}",
        rule.number,
        rule.action.label(),
        rule.to,
        rule.from,
        rule.interface.clone().unwrap_or_default()
    );
    if let Some(c) = &rule.comment {
        hay.push(' ');
        hay.push_str(c);
    }
    hay.to_lowercase().contains(filter)
}

pub fn ui_rules(app: &mut App, ui: &mut egui::Ui) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.add(
            egui::TextEdit::singleline(&mut app.rule_filter)
                .hint_text("port, address, action…")
                .desired_width(200.0),
        );
        if ui.button("Add rule…").clicked() {
            app.rule_draft = RuleDraft::default();
            app.rule_error = None;
            app.add_rule_open = true;
        }
        let can_delete = app.selected_rule.is_some();
        if ui
            .add_enabled(can_delete, egui::Button::new("Delete"))
            .clicked()
            && let Some(n) = app.selected_rule
            && let Some(rule) = app.fw.rules.iter().find(|r| r.number == n)
        {
            let desc = format!("{} {} from {}", rule.action.label(), rule.to, rule.from);
            app.confirm = Some(Confirm::DeleteRule { number: n, desc });
        }
        if ui.button("Refresh").clicked() {
            app.dispatch(JobKind::Refresh);
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(format!(
                "{} of {} rules",
                app.fw
                    .rules
                    .iter()
                    .filter(|r| rule_matches(r, &app.rule_filter.to_lowercase()))
                    .count(),
                app.fw.rules.len()
            ));
        });
    });
    ui.separator();

    let filter = app.rule_filter.to_lowercase();
    let rows: Vec<Rule> = app
        .fw
        .rules
        .iter()
        .filter(|r| rule_matches(r, &filter))
        .cloned()
        .collect();

    if rows.is_empty() {
        ui.add_space(20.0);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new("No rules match.").weak());
        });
        return;
    }

    egui_extras::TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(egui_extras::Column::auto().at_least(50.0))
        .column(egui_extras::Column::auto().at_least(70.0))
        .column(egui_extras::Column::auto().at_least(60.0))
        .column(egui_extras::Column::auto().at_least(120.0))
        .column(egui_extras::Column::auto().at_least(120.0))
        .column(egui_extras::Column::auto().at_least(80.0))
        .column(egui_extras::Column::remainder().at_least(80.0))
        .header(24.0, |mut header| {
            header.col(|ui| {
                ui.strong("Rule");
            });
            header.col(|ui| {
                ui.strong("Action");
            });
            header.col(|ui| {
                ui.strong("Dir");
            });
            header.col(|ui| {
                ui.strong("To");
            });
            header.col(|ui| {
                ui.strong("From");
            });
            header.col(|ui| {
                ui.strong("Iface");
            });
            header.col(|ui| {
                ui.strong("Comment");
            });
        })
        .body(|body| {
            body.rows(24.0, rows.len(), |mut row| {
                let i = row.index();
                let rule = &rows[i];
                let selected = app.selected_rule == Some(rule.number);
                row.set_selected(selected);

                row.col(|ui| {
                    let label = if rule.ipv6 {
                        format!("{} (v6)", rule.number)
                    } else {
                        rule.number.to_string()
                    };
                    if ui.selectable_label(selected, label).clicked() {
                        app.selected_rule = Some(rule.number);
                    }
                });
                row.col(|ui| {
                    ui.colored_label(action_color(rule.action), rule.action.label());
                });
                row.col(|ui| {
                    ui.label(rule.direction.label());
                });
                row.col(|ui| {
                    ui.label(&rule.to);
                });
                row.col(|ui| {
                    ui.label(&rule.from);
                });
                row.col(|ui| {
                    if let Some(iface) = &rule.interface {
                        ui.label(iface);
                    }
                });
                row.col(|ui| {
                    if let Some(c) = &rule.comment {
                        ui.label(c);
                    }
                });
            });
        });
}

// --- Applications ---------------------------------------------------------

pub fn ui_apps(app: &mut App, ui: &mut egui::Ui) {
    if app.fw.apps.is_empty() {
        ui.add_space(20.0);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new("No application profiles found.").weak());
            ui.label(RichText::new("Profiles live in /etc/ufw/applications.d.").weak());
            if ui.button("Refresh").clicked() {
                app.dispatch(JobKind::Refresh);
            }
        });
        return;
    }

    let apps = app.fw.apps.clone();
    ui.add_space(6.0);
    ui.columns(2, |cols| {
        egui::ScrollArea::vertical()
            .id_salt("app_list")
            .auto_shrink([false, false])
            .show(&mut cols[0], |ui| {
                ui.label(RichText::new("Profiles").strong());
                ui.separator();
                for name in &apps {
                    let selected = app.selected_app.as_deref() == Some(name.as_str());
                    if ui.selectable_label(selected, name).clicked() && !selected {
                        app.selected_app = Some(name.clone());
                        app.app_info = None;
                        let label = format!("App info: {name}");
                        let cmd = format!("ufw app info {}", ufw::sh_quote(name));
                        let id = app.run_query(&label, cmd);
                        app.app_info_job = Some((id, name.clone()));
                    }
                }
            });

        egui::ScrollArea::vertical()
            .id_salt("app_detail")
            .auto_shrink([false, false])
            .show(&mut cols[1], |ui| {
                let selected_name = app.selected_app.clone();
                match selected_name {
                    None => {
                        ui.label(RichText::new("Select an application profile.").weak());
                    }
                    Some(name) => {
                        ui.label(RichText::new(name.as_str()).strong().size(16.0));
                        ui.add_space(6.0);

                        ui.horizontal(|ui| {
                            ui.label("Direction:");
                            for d in [Direction::In, Direction::Out] {
                                ui.selectable_value(&mut app.app_direction, d, d.as_str());
                            }
                        });
                        ui.horizontal(|ui| {
                            let dir = app.app_direction;
                            if ui.button("Allow").clicked() {
                                let cmd = ufw::build_app_command(&name, dir, true);
                                app.run_exec(&format!("Allow {name}"), cmd);
                            }
                            if ui.button("Deny").clicked() {
                                let cmd = ufw::build_app_command(&name, dir, false);
                                app.run_exec(&format!("Deny {name}"), cmd);
                            }
                        });
                        ui.separator();

                        match &app.app_info {
                            Some((info_name, output)) if info_name == &name => {
                                if output.trim().is_empty() {
                                    ui.label(RichText::new("(no output)").weak());
                                } else {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(output.as_str()).monospace(),
                                        )
                                        .wrap(),
                                    );
                                }
                            }
                            _ => {
                                ui.spinner();
                                ui.label("Loading profile details…");
                            }
                        }
                    }
                }
            });
    });
}

// --- Servers --------------------------------------------------------------

pub fn ui_servers(app: &mut App, ui: &mut egui::Ui) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        if ui.button("Add server…").clicked() {
            app.server_draft = Some(ServerDraft {
                profile: crate::model::ServerProfile::new(String::new(), String::new()),
                is_new: true,
                port_str: "22".into(),
                error: None,
            });
        }
        if ui.button("Export…").clicked() {
            let mut dlg = IoDialog::export();
            dlg.include_servers = true;
            app.io_dialog = Some(dlg);
        }
        if ui.button("Import…").clicked() {
            app.io_dialog = Some(IoDialog::import());
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(RichText::new("Passwords and passphrases are never written to disk.").weak());
        });
    });
    ui.separator();

    if app.servers.is_empty() {
        ui.add_space(20.0);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new("No saved servers yet.").weak());
            ui.label(RichText::new("Add one to manage its firewall over SSH.").weak());
        });
        return;
    }

    let servers = app.servers.clone();
    egui_extras::TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(egui_extras::Column::auto().at_least(120.0))
        .column(egui_extras::Column::auto().at_least(160.0))
        .column(egui_extras::Column::auto().at_least(70.0))
        .column(egui_extras::Column::auto().at_least(60.0))
        .column(egui_extras::Column::auto().at_least(90.0))
        .column(egui_extras::Column::remainder().at_least(220.0))
        .header(24.0, |mut header| {
            header.col(|ui| {
                ui.strong("Label");
            });
            header.col(|ui| {
                ui.strong("Target");
            });
            header.col(|ui| {
                ui.strong("Auth");
            });
            header.col(|ui| {
                ui.strong("Sudo");
            });
            header.col(|ui| {
                ui.strong("State");
            });
            header.col(|ui| {
                ui.strong("Actions");
            });
        })
        .body(|body| {
            body.rows(28.0, servers.len(), |mut row| {
                let i = row.index();
                let s = &servers[i];
                let is_selected = app.endpoint_key == s.id;
                let connected = app.is_connected(&s.id);

                row.col(|ui| {
                    if ui.selectable_label(is_selected, &s.label).clicked() {
                        app.endpoint_key = s.id.clone();
                    }
                });
                row.col(|ui| {
                    ui.monospace(s.target());
                });
                row.col(|ui| {
                    ui.label(match s.auth_method {
                        AuthMethod::Key => "key",
                        AuthMethod::Password => "password",
                    });
                });
                row.col(|ui| {
                    ui.label(if s.use_sudo { "yes" } else { "no" });
                });
                row.col(|ui| {
                    let color = if connected {
                        allow_color()
                    } else {
                        Color32::GRAY
                    };
                    ui.colored_label(
                        color,
                        if connected {
                            "● connected"
                        } else {
                            "○ offline"
                        },
                    );
                });
                row.col(|ui| {
                    ui.horizontal(|ui| {
                        let ep = Endpoint::Server(s.id.clone());
                        if connected {
                            if ui.button("Disconnect").clicked() {
                                app.dispatch_at(ep, JobKind::Disconnect);
                            }
                        } else if ui.button("Connect").clicked() {
                            app.status_msg = "Connecting…".into();
                            app.dispatch_at(ep, JobKind::Connect);
                        }
                        if ui.button("Edit").clicked() {
                            app.server_draft = Some(ServerDraft {
                                profile: s.clone(),
                                is_new: false,
                                port_str: s.port.to_string(),
                                error: None,
                            });
                        }
                        if ui.button("Delete").clicked() {
                            app.confirm = Some(Confirm::DeleteServer {
                                id: s.id.clone(),
                                label: s.label.clone(),
                            });
                        }
                    });
                });
            });
        });
}

// --- Log ------------------------------------------------------------------

pub fn ui_log(app: &mut App, ui: &mut egui::Ui) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        if ui.button("Clear").clicked() {
            app.log.clear();
        }
        ui.label(RichText::new(format!("{} entries", app.log.len())).weak());
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Refresh firewall").clicked() {
                app.dispatch(JobKind::Refresh);
            }
        });
    });
    ui.separator();

    egui::ScrollArea::vertical()
        .stick_to_bottom(true)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if app.log.is_empty() {
                ui.add_space(16.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("No commands run yet.").weak());
                });
            }
            for entry in &app.log {
                let color = if entry.ok {
                    allow_color()
                } else {
                    deny_color()
                };
                ui.label(
                    RichText::new(format!("» {}", entry.label))
                        .strong()
                        .color(color),
                );
                if !entry.output.trim().is_empty() {
                    ui.add(
                        egui::Label::new(RichText::new(entry.output.as_str()).monospace()).wrap(),
                    );
                }
                ui.separator();
            }
        });
}
