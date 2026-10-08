use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use eframe::egui;

use crate::model::{Endpoint, EndpointCreds, ServerProfile};
use crate::ssh::{self, ExecRaw, SshFail, SshFailKind, SshSession};
use crate::ufw;

#[derive(Clone, Debug)]
pub enum JobKind {
    Connect,
    Disconnect,
    Refresh,
    Exec {
        script: String,
        label: String,
        privileged: bool,
        mutating: bool,
    },
}

#[derive(Clone, Debug)]
pub struct Job {
    pub id: u64,
    pub endpoint: Endpoint,
    pub profile: Option<ServerProfile>,
    pub creds: EndpointCreds,
    pub kind: JobKind,
}

#[derive(Clone, Debug)]
pub enum FailHint {
    None,
    SudoPassword,
    SshPassword,
    KeyPassphrase,
}

#[derive(Clone, Debug)]
pub struct Fail {
    pub message: String,
    pub hint: FailHint,
    pub transport: bool,
}

#[derive(Clone, Debug)]
pub struct ExecOk {
    pub stdout: String,
    pub stderr: String,
    pub status: Option<i32>,
}

#[derive(Clone, Debug)]
pub struct RefreshData {
    pub verbose: String,
    pub numbered: String,
    pub added: String,
    pub apps: String,
}

#[derive(Clone, Debug)]
pub enum Outcome {
    Connect(Result<String, Fail>),
    Disconnect,
    Refresh(Result<RefreshData, Fail>),
    Exec {
        label: String,
        result: Result<ExecOk, Fail>,
    },
}

#[derive(Clone, Debug)]
pub struct JobDone {
    pub id: u64,
    pub endpoint: Endpoint,
    pub outcome: Outcome,
}

pub fn spawn(ctx: egui::Context) -> (mpsc::Sender<Job>, mpsc::Receiver<JobDone>) {
    let (jobs_tx, jobs_rx) = mpsc::channel::<Job>();
    let (done_tx, done_rx) = mpsc::channel::<JobDone>();

    std::thread::Builder::new()
        .name("ufw-worker".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime");
            let mut sessions: HashMap<String, SshSession> = HashMap::new();

            while let Ok(job) = jobs_rx.recv() {
                let id = job.id;
                let endpoint = job.endpoint.clone();
                let outcome = match &job.kind {
                    JobKind::Disconnect => {
                        if let Some(sess) = sessions.remove(endpoint.key()) {
                            rt.block_on(ssh::disconnect(&sess));
                        }
                        Outcome::Disconnect
                    }
                    _ => rt.block_on(async { run_job(&mut sessions, job).await }),
                };
                let _ = done_tx.send(JobDone {
                    id,
                    endpoint,
                    outcome,
                });
                ctx.request_repaint();
            }
        })
        .expect("failed to spawn worker thread");

    (jobs_tx, done_rx)
}

async fn run_job(sessions: &mut HashMap<String, SshSession>, job: Job) -> Outcome {
    match &job.kind {
        JobKind::Connect => match ensure_session(sessions, &job).await {
            Ok(_) => Outcome::Connect(Ok(format!(
                "Connected to {}",
                job.profile
                    .as_ref()
                    .map(|p| p.target())
                    .unwrap_or_else(|| job.endpoint.key().to_string())
            ))),
            Err(f) => Outcome::Connect(Err(f)),
        },
        JobKind::Disconnect => Outcome::Disconnect,
        JobKind::Refresh => {
            let script = ufw::refresh_script();
            match exec_script(sessions, &job, &script, true).await {
                Ok(raw) => match validate_refresh(&raw) {
                    Ok(data) => Outcome::Refresh(Ok(data)),
                    Err(f) => Outcome::Refresh(Err(f)),
                },
                Err(f) => Outcome::Refresh(Err(f)),
            }
        }
        JobKind::Exec {
            script,
            label,
            privileged,
            ..
        } => {
            let result = match exec_script(sessions, &job, script, *privileged).await {
                Ok(raw) => {
                    if ufw::looks_like_sudo_needed(&raw.stderr)
                        || ufw::looks_like_sudo_needed(&raw.stdout)
                    {
                        Err(sudo_fail(&raw))
                    } else {
                        Ok(ExecOk {
                            stdout: raw.stdout,
                            stderr: raw.stderr,
                            status: if raw.status < 0 {
                                None
                            } else {
                                Some(raw.status)
                            },
                        })
                    }
                }
                Err(f) => Err(f),
            };
            Outcome::Exec {
                label: label.clone(),
                result,
            }
        }
    }
}

fn sudo_fail(raw: &ExecRaw) -> Fail {
    let msg = if raw.stderr.trim().is_empty() {
        raw.stdout.trim().to_string()
    } else {
        raw.stderr.trim().to_string()
    };
    Fail {
        message: msg,
        hint: FailHint::SudoPassword,
        transport: false,
    }
}

fn validate_refresh(raw: &ExecRaw) -> Result<RefreshData, Fail> {
    let sections = ufw::split_refresh(&raw.stdout);
    let Some(s) = sections else {
        let msg = format!(
            "{}{}",
            raw.stdout.trim(),
            if raw.stderr.trim().is_empty() {
                String::new()
            } else {
                format!("\n{}", raw.stderr.trim())
            }
        );
        let msg = if msg.trim().is_empty() {
            format!("Firewall query failed (exit status {})", raw.status)
        } else {
            msg
        };
        if ufw::looks_like_sudo_needed(&msg) {
            return Err(sudo_fail(raw));
        }
        return Err(Fail {
            message: msg,
            hint: FailHint::None,
            transport: false,
        });
    };

    if s.verbose.trim().starts_with("ERROR") {
        return Err(if ufw::looks_like_sudo_needed(&s.verbose) {
            sudo_fail(raw)
        } else {
            Fail {
                message: s.verbose.trim().to_string(),
                hint: FailHint::None,
                transport: false,
            }
        });
    }

    Ok(RefreshData {
        verbose: s.verbose,
        numbered: s.numbered,
        added: s.added,
        apps: s.apps,
    })
}

async fn ensure_session<'a>(
    sessions: &'a mut HashMap<String, SshSession>,
    job: &Job,
) -> Result<&'a SshSession, Fail> {
    let profile = job.profile.clone().ok_or_else(|| Fail {
        message: "No server profile selected".into(),
        hint: FailHint::None,
        transport: false,
    })?;

    let fingerprint = ssh::fingerprint(&profile);
    let stale = match sessions.get(&profile.id) {
        Some(sess) => sess.fingerprint != fingerprint,
        None => true,
    };
    if !stale {
        return Ok(sessions.get(&profile.id).expect("checked above"));
    }
    sessions.remove(&profile.id);

    let mut sess = ssh::connect(&profile, &job.creds)
        .await
        .map_err(ssh_fail_to_fail)?;
    sess.fingerprint = fingerprint;
    sessions.insert(profile.id.clone(), sess);
    Ok(sessions.get(&profile.id).expect("just inserted"))
}

fn ssh_fail_to_fail(e: SshFail) -> Fail {
    let hint = match e.kind {
        SshFailKind::EncryptedKey => FailHint::KeyPassphrase,
        SshFailKind::Auth => FailHint::SshPassword,
        _ => FailHint::None,
    };
    let transport = matches!(e.kind, SshFailKind::Network | SshFailKind::Timeout);
    Fail {
        message: e.message,
        hint,
        transport,
    }
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn compose(
    script: &str,
    privileged: bool,
    use_sudo: bool,
    creds: &EndpointCreds,
) -> (String, Option<String>, bool) {
    let root = is_root();
    if !privileged || root || !use_sudo {
        return (script.to_string(), None, false);
    }
    match &creds.sudo_password {
        Some(pw) => (
            format!("sudo -S -p '' sh -c {}", sh_quote(script)),
            Some(pw.clone()),
            true,
        ),
        None => (format!("sudo -n sh -c {}", sh_quote(script)), None, true),
    }
}

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .map(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .map(|uid| uid == "0")
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

fn run_local(full: &str, stdin_pw: Option<&str>) -> std::io::Result<ExecRaw> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(full)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    if let (Some(pw), Some(stdin)) = (stdin_pw, child.stdin.as_mut()) {
        let _ = stdin.write_all(pw.as_bytes());
        let _ = stdin.write_all(b"\n");
        let _ = stdin.flush();
    }
    drop(child.stdin.take());
    let out = child.wait_with_output()?;
    Ok(ExecRaw {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        status: out.status.code().unwrap_or(-1),
    })
}

const SUDO_MISSING: [&str; 3] = [
    "sudo: not found",
    "sudo: command not found",
    "sh: 1: sudo: not found",
];

fn sudo_missing(raw: &ExecRaw) -> bool {
    let combined = format!("{}{}", raw.stdout, raw.stderr);
    SUDO_MISSING.iter().any(|m| combined.contains(m))
}

/// A supplied sudo password was wrong (sudo retried and gave up).
fn sudo_password_rejected(raw: &ExecRaw) -> bool {
    if raw.status == 0 {
        return false;
    }
    let combined = format!("{}{}", raw.stdout, raw.stderr);
    ufw::looks_like_auth_error(&combined)
}

async fn exec_script(
    sessions: &mut HashMap<String, SshSession>,
    job: &Job,
    script: &str,
    privileged: bool,
) -> Result<ExecRaw, Fail> {
    match &job.endpoint {
        Endpoint::Local => {
            let (full, pw, used_sudo) = compose(script, privileged, true, &job.creds);

            let raw = run_local(&full, pw.as_deref()).map_err(|e| Fail {
                message: format!("Failed to run command: {e}"),
                hint: FailHint::None,
                transport: false,
            })?;

            if used_sudo && sudo_missing(&raw) {
                // No sudo available (e.g. running as root in a container).
                return run_local(script, None).map_err(|e| Fail {
                    message: format!("Failed to run command: {e}"),
                    hint: FailHint::None,
                    transport: false,
                });
            }

            if raw.status == 1 && used_sudo && job.creds.sudo_password.is_none() {
                let combined = format!("{}{}", raw.stdout, raw.stderr);
                if ufw::looks_like_sudo_needed(&combined) {
                    return Err(sudo_fail(&raw));
                }
            }
            if used_sudo && job.creds.sudo_password.is_some() && sudo_password_rejected(&raw) {
                return Err(Fail {
                    message: "The sudo password was rejected.".into(),
                    hint: FailHint::SudoPassword,
                    transport: false,
                });
            }
            Ok(raw)
        }
        Endpoint::Server(_) => {
            let profile = job.profile.clone().ok_or_else(|| Fail {
                message: "No server profile selected".into(),
                hint: FailHint::None,
                transport: false,
            })?;
            let use_sudo = profile.use_sudo || job.creds.sudo_password.is_some();
            let (full, pw, used_sudo) = compose(script, privileged, use_sudo, &job.creds);

            let result = {
                let sess = ensure_session(sessions, job).await?;
                ssh::exec(sess, &full, pw.as_deref(), Duration::from_secs(120)).await
            };

            match result {
                Ok(raw) => {
                    if used_sudo && sudo_missing(&raw) {
                        let sess = ensure_session(sessions, job).await?;
                        let plain = ssh::exec(sess, script, None, Duration::from_secs(120)).await;
                        match plain {
                            Ok(raw) => return Ok(raw),
                            Err(e) => return Err(ssh_fail_to_fail(e)),
                        }
                    }
                    if used_sudo && job.creds.sudo_password.is_none() {
                        let combined = format!("{}{}", raw.stdout, raw.stderr);
                        if ufw::looks_like_sudo_needed(&combined) {
                            return Err(sudo_fail(&raw));
                        }
                    }
                    if used_sudo
                        && job.creds.sudo_password.is_some()
                        && sudo_password_rejected(&raw)
                    {
                        return Err(Fail {
                            message: "The sudo password was rejected.".into(),
                            hint: FailHint::SudoPassword,
                            transport: false,
                        });
                    }
                    Ok(raw)
                }
                Err(e) => {
                    let fail = ssh_fail_to_fail(e);
                    if fail.transport {
                        sessions.remove(&profile.id);
                    }
                    Err(fail)
                }
            }
        }
    }
}
