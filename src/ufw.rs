use serde::{Deserialize, Serialize};

use crate::model::Policy;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    In,
    Out,
    Routed,
}

impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
            Direction::Routed => "route",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Direction::In => "IN",
            Direction::Out => "OUT",
            Direction::Routed => "ROUTED",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Allow,
    Deny,
    Reject,
}

impl Action {
    pub fn as_ufw(&self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Reject => "reject",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Action::Allow => "ALLOW",
            Action::Deny => "DENY",
            Action::Reject => "REJECT",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub number: usize,
    pub action: Action,
    pub direction: Direction,
    pub to: String,
    pub from: String,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub ipv6: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Defaults {
    pub incoming: Policy,
    pub outgoing: Policy,
    pub routed: Policy,
}

impl Default for Defaults {
    fn default() -> Self {
        Defaults {
            incoming: Policy::Deny,
            outgoing: Policy::Allow,
            routed: Policy::Disabled,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FirewallState {
    pub loaded: bool,
    pub active: bool,
    pub logging: String,
    pub defaults: Defaults,
    pub rules: Vec<Rule>,
    pub added_commands: Vec<String>,
    pub apps: Vec<String>,
    pub raw_verbose: String,
}

impl Default for FirewallState {
    fn default() -> Self {
        FirewallState {
            loaded: false,
            active: false,
            logging: "off".into(),
            defaults: Defaults::default(),
            rules: Vec::new(),
            added_commands: Vec::new(),
            apps: Vec::new(),
            raw_verbose: String::new(),
        }
    }
}

/// Parse `ufw status verbose`.
pub fn parse_verbose(text: &str) -> (bool, String, Defaults) {
    let mut active = false;
    let mut logging = "off".to_string();
    let mut defaults = Defaults::default();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Status:") {
            active = rest.trim().eq_ignore_ascii_case("active");
        } else if let Some(rest) = line.strip_prefix("Logging:") {
            let rest = rest.trim();
            logging = if let Some(open) = rest.find('(') {
                if let Some(close) = rest[open..].find(')') {
                    rest[open + 1..open + close].trim().to_string()
                } else if rest.to_ascii_lowercase().starts_with("off") {
                    "off".to_string()
                } else {
                    "on".to_string()
                }
            } else if rest.to_ascii_lowercase().starts_with("off") {
                "off".to_string()
            } else {
                "on".to_string()
            };
        } else if let Some(rest) = line.strip_prefix("Default:") {
            for part in rest.split(',') {
                let part = part.trim();
                let mut words = part.split_whitespace();
                let (Some(policy), Some(kind)) = (words.next(), words.next()) else {
                    continue;
                };
                let Some(policy) = Policy::from_ufw(policy) else {
                    continue;
                };
                let kind = kind.trim_matches(|c| c == '(' || c == ')');
                match kind {
                    "incoming" => defaults.incoming = policy,
                    "outgoing" => defaults.outgoing = policy,
                    "routed" => defaults.routed = policy,
                    _ => {}
                }
            }
        }
    }
    (active, logging, defaults)
}

/// Split a status row into columns separated by runs of two or more spaces.
fn extract_interface(col: &str) -> (String, Option<String>) {
    if let Some(idx) = col.rfind(" on ") {
        let iface = col[idx + 4..].trim();
        if !iface.is_empty() && !iface.contains(' ') {
            return (col[..idx].trim().to_string(), Some(iface.to_string()));
        }
    }
    (col.to_string(), None)
}

/// Parse `ufw status numbered`.
///
/// Rows are formatted by ufw as `[N] <to> <ACTION> <DIR> <from> [# comment]`
/// where `<to>`/`<from>` may carry ` on <iface>` and ` (v6)` markers.
pub fn parse_numbered(text: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim_end();
        if !line.starts_with('[') {
            continue;
        }
        let Some(close) = line.find(']') else {
            continue;
        };
        let Ok(number) = line[1..close].trim().parse::<usize>() else {
            continue;
        };
        let mut rest_owned = line[close + 1..].trim_start().to_string();

        // Trailing comment: ufw prints it as " # <text>".
        let mut comment = None;
        if let Some(idx) = rest_owned.find(" # ") {
            let c = rest_owned[idx + 3..].trim().to_string();
            if !c.is_empty() {
                comment = Some(c);
            }
            rest_owned.truncate(idx);
            let trimmed = rest_owned.trim_end().to_string();
            rest_owned = trimmed;
        }

        // The (v6) marker lives inside the To/From columns.
        let mut ipv6 = false;
        while let Some(idx) = rest_owned.find(" (v6)") {
            ipv6 = true;
            rest_owned.replace_range(idx..idx + 5, "");
        }
        let rest = rest_owned.as_str();

        // Locate the action verb (uppercase, always its own column).
        let mut found: Option<(usize, Action, usize)> = None;
        for (verb, action) in [
            (" ALLOW", Action::Allow),
            (" DENY", Action::Deny),
            (" REJECT", Action::Reject),
        ] {
            if let Some(i) = rest.find(verb)
                && found.is_none_or(|(pi, _, _)| i < pi)
            {
                found = Some((i, action, verb.len()));
            }
        }
        let Some((idx, action, verb_len)) = found else {
            continue;
        };

        let to = rest[..idx].trim_end().to_string();
        let mut remaining = rest[idx + verb_len..].trim_start();

        // Direction word: IN / OUT / FWD.
        let mut direction = Direction::In;
        for (w, d) in [
            ("IN", Direction::In),
            ("OUT", Direction::Out),
            ("FWD", Direction::Routed),
        ] {
            if let Some(tail) = remaining.strip_prefix(w)
                && (tail.is_empty() || tail.starts_with(' '))
            {
                direction = d;
                remaining = tail.trim_start();
                break;
            }
        }
        let from = remaining.trim_end().to_string();

        // Collapse the fixed-width padding into single spaces.
        let collapse = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        let (to, iface_from_to) = extract_interface(&collapse(&to));
        let (from, iface_from_from) = extract_interface(&collapse(&from));
        let interface = iface_from_to.or(iface_from_from);

        rules.push(Rule {
            number,
            action,
            direction,
            to,
            from,
            interface,
            comment,
            ipv6,
        });
    }
    rules
}

/// Parse `ufw show added` into ufw command strings.
pub fn parse_show_added(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| l.starts_with("ufw "))
        .map(|l| l.to_string())
        .collect()
}

/// Parse `ufw app list`.
pub fn parse_app_list(text: &str) -> Vec<String> {
    let mut apps = Vec::new();
    let mut in_list = false;
    for line in text.lines() {
        if line.trim_start().starts_with("Available applications") {
            in_list = true;
            continue;
        }
        if in_list {
            let name = line.trim();
            if !name.is_empty() {
                apps.push(name.to_string());
            }
        }
    }
    apps
}

pub(crate) fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

/// The fields of the "add rule" dialog.
#[derive(Clone, Debug)]
pub struct RuleDraft {
    pub action: Action,
    pub direction: Direction,
    pub proto: String,
    pub port: String,
    pub from_addr: String,
    pub to_addr: String,
    pub interface: String,
    pub comment: String,
    pub dry_run: bool,
}

impl Default for RuleDraft {
    fn default() -> Self {
        RuleDraft {
            action: Action::Allow,
            direction: Direction::In,
            proto: "tcp".into(),
            port: String::new(),
            from_addr: String::new(),
            to_addr: String::new(),
            interface: String::new(),
            comment: String::new(),
            dry_run: false,
        }
    }
}

/// Build a `ufw` rule command from the dialog fields.
pub fn build_rule_command(d: &RuleDraft) -> Result<String, String> {
    let proto = match d.proto.trim().to_ascii_lowercase().as_str() {
        "" | "any" => String::new(),
        p @ ("tcp" | "udp") => p.to_string(),
        other => return Err(format!("Unsupported protocol: {other}")),
    };

    let port = d.port.trim().to_string();
    if !port.is_empty() && !port.chars().all(|c| c.is_ascii_digit() || c == ':') {
        return Err(format!("Invalid port: {port}"));
    }

    if port.is_empty()
        && d.from_addr.trim().is_empty()
        && d.to_addr.trim().is_empty()
        && d.interface.trim().is_empty()
    {
        return Err("Rule needs a port, source, destination or interface".into());
    }

    let mut cmd = String::from("ufw");
    if d.dry_run {
        cmd.push_str(" --dry-run");
    }
    if d.direction == Direction::Routed {
        cmd.push_str(" route");
    }
    cmd.push(' ');
    cmd.push_str(d.action.as_ufw());
    if d.direction != Direction::Routed {
        cmd.push(' ');
        cmd.push_str(d.direction.as_str());
    }
    if !d.interface.trim().is_empty() {
        cmd.push_str(&format!(" on {}", sh_quote(d.interface.trim())));
    }

    let from = d.from_addr.trim();
    let to = d.to_addr.trim();

    if !port.is_empty() && from.is_empty() && to.is_empty() {
        let spec = if proto.is_empty() {
            port.clone()
        } else {
            format!("{port}/{proto}")
        };
        cmd.push(' ');
        cmd.push_str(&sh_quote(&spec));
    } else {
        if !proto.is_empty() {
            cmd.push_str(" proto ");
            cmd.push_str(&proto);
        }
        if !from.is_empty() {
            cmd.push_str(" from ");
            cmd.push_str(&sh_quote(from));
        }
        if !to.is_empty() {
            cmd.push_str(" to ");
            cmd.push_str(&sh_quote(to));
        }
        if !port.is_empty() {
            if !to.is_empty() || from.is_empty() {
                cmd.push_str(" port ");
                cmd.push_str(&port);
            } else {
                // source given, destination implied any
                cmd.push_str(" to any port ");
                cmd.push_str(&port);
            }
        }
    }

    if !d.comment.trim().is_empty() {
        cmd.push_str(&format!(" comment {}", sh_quote(d.comment.trim())));
    }
    Ok(cmd)
}

/// Build an app-profile rule command, e.g. `ufw allow in 'OpenSSH'`.
pub fn build_app_command(app: &str, direction: Direction, allow: bool) -> String {
    let verb = if allow { "allow" } else { "deny" };
    match direction {
        Direction::Routed => format!("ufw route {verb} {}", sh_quote(app)),
        d => format!("ufw {verb} {} {}", d.as_str(), sh_quote(app)),
    }
}

pub fn build_delete_command(number: usize) -> String {
    format!("ufw --force delete {number}")
}

/// The multi-command script used to reload all firewall state in one round trip.
pub fn refresh_script() -> String {
    const S1: &str = "__UFWM_S1__";
    const S2: &str = "__UFWM_S2__";
    const S3: &str = "__UFWM_S3__";
    format!(
        "ufw status verbose; echo {S1}; ufw status numbered; echo {S2}; \
         ufw show added; echo {S3}; ufw app list"
    )
}

#[derive(Debug)]
pub struct RefreshSections {
    pub verbose: String,
    pub numbered: String,
    pub added: String,
    pub apps: String,
}

pub fn split_refresh(output: &str) -> Option<RefreshSections> {
    const S1: &str = "__UFWM_S1__";
    const S2: &str = "__UFWM_S2__";
    const S3: &str = "__UFWM_S3__";
    if !output.contains(S1) || !output.contains(S2) || !output.contains(S3) {
        return None;
    }
    let mut parts = output.split(S1);
    let verbose = parts.next()?.to_string();
    let mut parts = parts.next()?.split(S2);
    let numbered = parts.next()?.to_string();
    let mut parts = parts.next()?.split(S3);
    let added = parts.next()?.to_string();
    let apps = parts.next()?.to_string();
    Some(RefreshSections {
        verbose: verbose.trim().to_string(),
        numbered: numbered.trim().to_string(),
        added: added.trim().to_string(),
        apps: apps.trim().to_string(),
    })
}

pub fn looks_like_sudo_needed(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains("need to be root")
        || l.contains("a password is required")
        || l.contains("no tty present")
        || l.contains("a terminal is required")
        || l.contains("may not run sudo")
        || l.contains("is not in the sudoers")
}

pub fn looks_like_auth_error(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains("authentication failed")
        || l.contains("permission denied (publickey")
        || l.contains("permission denied (password")
        || l.contains("permission denied,")
        || l.contains("too many authentication failures")
        || l.contains("incorrect password attempts")
        || l.contains("sorry, try again")
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERBOSE: &str = "Status: active\n\
Logging: on (low)\n\
Default: deny (incoming), allow (outgoing), disabled (routed)\n\
New profiles: skip\n";

    const NUMBERED: &str = "\
Status: active\n\
\n\
     To                         Action      From\n\
     --                         ------      ----\n\
[ 1] 22/tcp                     ALLOW IN    Anywhere\n\
[ 2] 80,443/tcp                 ALLOW IN    192.168.1.0/24\n\
[ 3] Anywhere                   DENY OUT    192.168.1.100\n\
[ 4] Anywhere on eth1           ALLOW IN    Anywhere\n\
[ 5] 514/udp                    ALLOW IN    Anywhere                   # syslog\n\
[ 6] 443/tcp (v6)               ALLOW IN    Anywhere                   # https\n\
[ 7] Anywhere                   DENY OUT    Anywhere                   (log)\n";

    #[test]
    fn parses_verbose() {
        let (active, logging, defaults) = parse_verbose(VERBOSE);
        assert!(active);
        assert_eq!(logging, "low");
        assert_eq!(defaults.incoming, Policy::Deny);
        assert_eq!(defaults.outgoing, Policy::Allow);
        assert_eq!(defaults.routed, Policy::Disabled);
    }

    #[test]
    fn parses_verbose_inactive() {
        let (active, logging, _) = parse_verbose("Status: inactive\n");
        assert!(!active);
        assert_eq!(logging, "off");
    }

    #[test]
    fn parses_numbered() {
        let rules = parse_numbered(NUMBERED);
        assert_eq!(rules.len(), 7);

        assert_eq!(rules[0].number, 1);
        assert_eq!(rules[0].action, Action::Allow);
        assert_eq!(rules[0].direction, Direction::In);
        assert_eq!(rules[0].to, "22/tcp");
        assert_eq!(rules[0].from, "Anywhere");
        assert_eq!(rules[0].interface, None);

        assert_eq!(rules[1].to, "80,443/tcp");
        assert_eq!(rules[1].from, "192.168.1.0/24");

        assert_eq!(rules[2].action, Action::Deny);
        assert_eq!(rules[2].direction, Direction::Out);
        assert_eq!(rules[2].from, "192.168.1.100");

        assert_eq!(rules[3].to, "Anywhere");
        assert_eq!(rules[3].interface.as_deref(), Some("eth1"));

        assert_eq!(rules[4].comment.as_deref(), Some("syslog"));

        assert_eq!(rules[5].to, "443/tcp");
        assert!(rules[5].ipv6);
        assert_eq!(rules[5].comment.as_deref(), Some("https"));

        assert_eq!(rules[6].from, "Anywhere (log)");
    }

    #[test]
    fn parses_numbered_empty() {
        assert!(parse_numbered("Status: inactive\n").is_empty());
    }

    #[test]
    fn parses_show_added() {
        let text = "Added user rules (see 'ufw status' for running firewall):\n\
                    ufw allow 22/tcp\n\
                    ufw deny 80/tcp\n\
                    (None)\n";
        let cmds = parse_show_added(text);
        assert_eq!(cmds, vec!["ufw allow 22/tcp", "ufw deny 80/tcp"]);
    }

    #[test]
    fn parses_app_list() {
        let text = "Available applications:\n  CUPS\n  OpenSSH\n  Web Server\n";
        assert_eq!(parse_app_list(text), vec!["CUPS", "OpenSSH", "Web Server"]);
    }

    #[test]
    fn builds_simple_rule() {
        let d = RuleDraft {
            port: "22".into(),
            proto: "tcp".into(),
            ..Default::default()
        };
        assert_eq!(build_rule_command(&d).unwrap(), "ufw allow in '22/tcp'");
    }

    #[test]
    fn builds_source_rule() {
        let d = RuleDraft {
            action: Action::Deny,
            port: "3306".into(),
            proto: "tcp".into(),
            from_addr: "10.0.0.0/8".into(),
            ..Default::default()
        };
        assert_eq!(
            build_rule_command(&d).unwrap(),
            "ufw deny in proto tcp from '10.0.0.0/8' to any port 3306"
        );
    }

    #[test]
    fn builds_interface_comment_rule() {
        let d = RuleDraft {
            interface: "eth1".into(),
            port: "53".into(),
            proto: "udp".into(),
            comment: "dns".into(),
            direction: Direction::Out,
            ..Default::default()
        };
        assert_eq!(
            build_rule_command(&d).unwrap(),
            "ufw allow out on 'eth1' '53/udp' comment 'dns'"
        );
    }

    #[test]
    fn builds_routed_rule() {
        let d = RuleDraft {
            direction: Direction::Routed,
            port: "8080".into(),
            proto: "tcp".into(),
            ..Default::default()
        };
        assert_eq!(
            build_rule_command(&d).unwrap(),
            "ufw route allow '8080/tcp'"
        );
    }

    #[test]
    fn rejects_empty_rule() {
        let d = RuleDraft::default();
        assert!(build_rule_command(&d).is_err());
    }

    #[test]
    fn rejects_bad_port() {
        let d = RuleDraft {
            port: "80;rm -rf".into(),
            ..Default::default()
        };
        assert!(build_rule_command(&d).is_err());
    }

    #[test]
    fn quotes_shell_metachars_in_addresses() {
        let d = RuleDraft {
            from_addr: "1.2.3.4; touch /tmp/x".into(),
            port: "80".into(),
            proto: "tcp".into(),
            ..Default::default()
        };
        let cmd = build_rule_command(&d).unwrap();
        assert!(cmd.contains("'1.2.3.4; touch /tmp/x'"));
        assert!(!cmd.ends_with("/tmp/x"));
    }

    #[test]
    fn splits_refresh_output() {
        let out = "Status: active\n\n__UFWM_S1__\n[ 1] 22/tcp ALLOW IN Anywhere\n__UFWM_S2__\nufw allow 22/tcp\n__UFWM_S3__\nAvailable applications:\n  OpenSSH\n";
        let s = split_refresh(out).unwrap();
        assert!(s.verbose.starts_with("Status: active"));
        assert!(s.numbered.contains("[ 1]"));
        assert_eq!(s.added, "ufw allow 22/tcp");
        assert!(s.apps.contains("OpenSSH"));
    }

    #[test]
    fn split_refresh_missing_markers() {
        assert!(split_refresh("ERROR: You need to be root").is_none());
    }

    #[test]
    fn detects_sudo_needed() {
        assert!(looks_like_sudo_needed(
            "ERROR: You need to be root to run this script"
        ));
        assert!(looks_like_sudo_needed("sudo: a password is required"));
        assert!(!looks_like_sudo_needed("some other error"));
    }
}
