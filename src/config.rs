use crate::transport;
use anyhow::Context;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::fs::{self, File};
use std::io::Read;

#[derive(Debug, Deserialize)]
struct Config {
    pub servers: ServerConfigList,
    pub clients: ClientConfigList,
}

pub type ServerConfigList = Vec<ServerConfig>;
pub type ClientConfigList = Vec<ClientConfig>;

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub listen: transport::Address,
    pub private_key: String,
    pub public_key: String,
    pub client_public_key: String,
    pub services: Vec<Service>,
}

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    pub private_key: String,
    pub public_key: String,
    pub server_public_key: String,
    pub services: Vec<Service>,
}

#[derive(Debug, Deserialize)]
pub struct Service {
    pub listen_to: transport::Address,
    pub connect_to: transport::Address,
}

impl ServerConfig {
    pub fn from_file(path: &str) -> anyhow::Result<ServerConfigList> {
        let cfg = from_file::<Config>(path)?;
        if cfg.servers.is_empty() {
            return Err(anyhow::Error::msg("No server found"));
        }
        Ok(cfg.servers)
    }
}

impl ClientConfig {
    pub fn from_file(path: &str) -> anyhow::Result<ClientConfigList> {
        let cfg = from_file::<Config>(path)?;
        if cfg.clients.is_empty() {
            return Err(anyhow::Error::msg("No client found"));
        }
        Ok(cfg.clients)
    }
}

fn from_file<T: DeserializeOwned>(path: &str) -> anyhow::Result<T> {
    check_config_perm(path).with_context(|| format!("Failed to get file permissions {}", path))?;
    let mut file = File::open(path).with_context(|| format!("Failed to open {}", path))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .with_context(|| format!("Failed to read {}", path))?;
    let config: T =
        toml::from_str(&contents).with_context(|| format!("Failed to parse {}", path))?;
    Ok(config)
}

// Check if the file is readable and writable only by the owner(0600).
fn check_config_perm(path: &str) -> anyhow::Result<()> {
    let metadata =
        fs::metadata(path).with_context(|| format!("Failed to get file permission: {}", path,))?;
    let permissions = metadata.permissions();

    // On Unix systems, we can check the mode directly
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = permissions.mode() & 0o777;
        if perm != 0o600 {
            return Err(anyhow::Error::msg(format!(
                "Config file permission should be 0600, current is 0{:o}",
                perm,
            )));
        }
        return Ok(());
    }

    // On Windows, we check if the file is readable and writable only by the owner
    #[cfg(windows)]
    {
        use std::os::windows::fs::PermissionsExt;
        // On Windows, we check if the file is readable and writable
        // and not executable (which is closest to 0600)
        let mode = permissions.mode();
        let ok = (mode & 0o600) == 0o600 && (mode & 0o177) == 0;
        if !ok {
            return Err(anyhow::Error::msg(
                "Config file permission should be not executed, and can only read/write by owner.",
            ));
        }
        return Ok(());
    }

    #[cfg(not(any(unix, windows)))]
    {
        OK(());
    }
}
