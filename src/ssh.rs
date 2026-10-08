use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use russh::client;
use russh::keys::{self, PrivateKeyWithHashAlg, PublicKeyOrCertificate, known_hosts};

use crate::model::{AuthMethod, EndpointCreds, ServerProfile};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshFailKind {
    EncryptedKey,
    Auth,
    HostKey,
    Timeout,
    Network,
    Other,
}

#[derive(Clone, Debug)]
pub struct SshFail {
    pub message: String,
    pub kind: SshFailKind,
}

impl SshFail {
    fn other(message: impl Into<String>) -> Self {
        SshFail {
            message: message.into(),
            kind: SshFailKind::Other,
        }
    }
}

/// Client-side handler that implements accept-new known_hosts policy.
pub struct KeyChecker {
    host: String,
    port: u16,
    accept_new: bool,
}

impl client::Handler for KeyChecker {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = server_key else {
            // Certificate-based host keys: accept (signature already verified by KEX).
            return Ok(true);
        };
        match known_hosts::check_known_hosts(&self.host, self.port, key) {
            Ok(true) => Ok(true),
            Ok(false) => {
                if self.accept_new {
                    let _ = known_hosts::learn_known_hosts(&self.host, self.port, key);
                }
                Ok(self.accept_new)
            }
            // The key changed: possible MITM. Never accept silently.
            Err(keys::Error::KeyChanged { .. }) => Ok(false),
            // known_hosts missing/unreadable: behave like an unknown host.
            Err(_) => {
                if self.accept_new {
                    let _ = known_hosts::learn_known_hosts(&self.host, self.port, key);
                }
                Ok(self.accept_new)
            }
        }
    }
}

pub struct SshSession {
    pub handle: client::Handle<KeyChecker>,
    /// Identifies the connection parameters; used to detect profile changes.
    pub fingerprint: String,
}

pub fn fingerprint(profile: &ServerProfile) -> String {
    format!(
        "{}|{}|{}|{:?}",
        profile.host, profile.port, profile.user, profile.auth_method
    )
}

fn default_key_paths() -> Vec<PathBuf> {
    let Some(home) = dirs::home_dir() else {
        return Vec::new();
    };
    ["id_ed25519", "id_ecdsa", "id_rsa"]
        .iter()
        .map(|n| home.join(".ssh").join(n))
        .collect()
}

pub async fn connect(
    profile: &ServerProfile,
    creds: &EndpointCreds,
) -> Result<SshSession, SshFail> {
    let config = Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    });

    let handler = KeyChecker {
        host: profile.host.clone(),
        port: profile.port,
        accept_new: profile.accept_new_host_keys,
    };

    let addr = (profile.host.as_str(), profile.port);
    let mut handle = tokio::time::timeout(
        Duration::from_secs(15),
        client::connect(config, addr, handler),
    )
    .await
    .map_err(|_| SshFail {
        message: format!("Timed out connecting to {}", profile.target()),
        kind: SshFailKind::Timeout,
    })?
    .map_err(|e| match e {
        russh::Error::UnknownKey => SshFail {
            message: format!(
                "Host key for {} was rejected (unknown or changed). Check known_hosts, \
                 or enable \"Automatically accept new host keys\" for this server.",
                profile.target()
            ),
            kind: SshFailKind::HostKey,
        },
        e => SshFail {
            message: format!("Connection failed: {e}"),
            kind: SshFailKind::Network,
        },
    })?;

    authenticate(&mut handle, profile, creds).await?;

    Ok(SshSession {
        handle,
        fingerprint: fingerprint(profile),
    })
}

async fn authenticate(
    handle: &mut client::Handle<KeyChecker>,
    profile: &ServerProfile,
    creds: &EndpointCreds,
) -> Result<(), SshFail> {
    let user = profile.user.clone();

    let try_keys = match profile.auth_method {
        AuthMethod::Key => true,
        AuthMethod::Password => false,
    };

    if try_keys {
        let key_paths: Vec<PathBuf> = match &profile.key_path {
            Some(p) if !p.trim().is_empty() => vec![PathBuf::from(p)],
            _ => default_key_paths(),
        };

        for path in key_paths {
            if !path.exists() {
                continue;
            }
            let key = match keys::load_secret_key(&path, creds.key_passphrase.as_deref()) {
                Ok(k) => k,
                Err(keys::Error::KeyIsEncrypted) => {
                    return Err(SshFail {
                        message: format!("Key {} is encrypted", path.display()),
                        kind: SshFailKind::EncryptedKey,
                    });
                }
                Err(e) => {
                    return Err(SshFail::other(format!(
                        "Could not load key {}: {e}",
                        path.display()
                    )));
                }
            };
            let hash = handle
                .best_supported_rsa_hash()
                .await
                .ok()
                .flatten()
                .flatten();
            let result = handle
                .authenticate_publickey(
                    user.clone(),
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                )
                .await
                .map_err(|e| SshFail {
                    message: format!("SSH error: {e}"),
                    kind: SshFailKind::Network,
                })?;
            if result.success() {
                return Ok(());
            }
        }

        // Fall back to password if one was supplied.
        if creds.ssh_password.is_none() {
            return Err(SshFail {
                message: "No usable SSH key and no password supplied".into(),
                kind: SshFailKind::Auth,
            });
        }
    }

    let password = creds.ssh_password.clone().ok_or_else(|| SshFail {
        message: "Password authentication required but no password supplied".into(),
        kind: SshFailKind::Auth,
    })?;

    let result = handle
        .authenticate_password(user, password)
        .await
        .map_err(|e| SshFail {
            message: format!("SSH error: {e}"),
            kind: SshFailKind::Network,
        })?;
    if result.success() {
        Ok(())
    } else {
        Err(SshFail {
            message: format!(
                "Authentication failed for {} ({:?})",
                profile.target(),
                profile.auth_method
            ),
            kind: SshFailKind::Auth,
        })
    }
}

pub struct ExecRaw {
    pub stdout: String,
    pub stderr: String,
    pub status: i32,
}

pub async fn exec(
    session: &SshSession,
    command: &str,
    stdin_data: Option<&str>,
    timeout: Duration,
) -> Result<ExecRaw, SshFail> {
    let fut = async {
        let mut channel = session
            .handle
            .channel_open_session()
            .await
            .map_err(|e| SshFail {
                message: format!("Could not open SSH channel: {e}"),
                kind: SshFailKind::Network,
            })?;
        channel.exec(true, command).await.map_err(|e| SshFail {
            message: format!("Exec failed: {e}"),
            kind: SshFailKind::Network,
        })?;
        if let Some(data) = stdin_data {
            let mut buf = data.as_bytes().to_vec();
            buf.push(b'\n');
            channel.data_bytes(buf).await.map_err(|e| SshFail {
                message: format!("stdin write failed: {e}"),
                kind: SshFailKind::Network,
            })?;
        }
        channel.eof().await.map_err(|e| SshFail {
            message: format!("eof failed: {e}"),
            kind: SshFailKind::Network,
        })?;

        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();
        let mut status: i32 = -1;
        loop {
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                russh::ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                russh::ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
                russh::ChannelMsg::ExitStatus { exit_status } => status = exit_status as i32,
                russh::ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok(ExecRaw {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            status,
        })
    };

    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| SshFail {
            message: "Remote command timed out".into(),
            kind: SshFailKind::Timeout,
        })?
}

pub async fn disconnect(session: &SshSession) {
    let _ = session
        .handle
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;
}
