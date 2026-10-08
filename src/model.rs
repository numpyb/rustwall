use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AuthMethod {
    #[default]
    Key,
    Password,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerProfile {
    #[serde(default)]
    pub id: String,
    pub label: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub auth_method: AuthMethod,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default = "default_true")]
    pub use_sudo: bool,
    #[serde(default = "default_true")]
    pub accept_new_host_keys: bool,
}

fn default_port() -> u16 {
    22
}

fn default_true() -> bool {
    true
}

impl ServerProfile {
    pub fn new(host: String, user: String) -> Self {
        ServerProfile {
            id: new_id(),
            label: host.clone(),
            host,
            port: 22,
            user,
            auth_method: AuthMethod::Key,
            key_path: None,
            use_sudo: true,
            accept_new_host_keys: true,
        }
    }

    pub fn target(&self) -> String {
        format!("{}@{}:{}", self.user, self.host, self.port)
    }
}

pub fn new_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("srv-{nanos:x}")
}

/// Identifies where commands run: the local machine or a saved server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    Local,
    Server(String),
}

impl Endpoint {
    pub fn key(&self) -> &str {
        match self {
            Endpoint::Local => "local",
            Endpoint::Server(id) => id,
        }
    }

    pub fn from_key(key: &str) -> Endpoint {
        if key == "local" {
            Endpoint::Local
        } else {
            Endpoint::Server(key.to_string())
        }
    }
}

/// In-memory credentials for one endpoint. Never written to disk.
#[derive(Clone, Debug, Default)]
pub struct EndpointCreds {
    pub sudo_password: Option<String>,
    pub ssh_password: Option<String>,
    pub key_passphrase: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    Allow,
    Deny,
    Reject,
    Disabled,
}

impl Policy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Policy::Allow => "allow",
            Policy::Deny => "deny",
            Policy::Reject => "reject",
            Policy::Disabled => "disabled",
        }
    }

    pub fn from_ufw(s: &str) -> Option<Policy> {
        match s.trim().to_ascii_lowercase().as_str() {
            "allow" => Some(Policy::Allow),
            "deny" => Some(Policy::Deny),
            "reject" => Some(Policy::Reject),
            "disabled" => Some(Policy::Disabled),
            _ => None,
        }
    }
}
