use crate::transport;
use anyhow::Context;
use anyhow::anyhow;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::fs::{self, File};
use std::io::Read;

#[derive(Deserialize)]
struct Config {
    pub servers: Option<ServerConfigList>,
    pub clients: Option<ClientConfigList>,
}

pub type ServerConfigList = Vec<ServerConfig>;
pub type ClientConfigList = Vec<ClientConfig>;

#[derive(Deserialize)]
pub struct ServerConfig {
    pub listen: transport::Address,
    pub private_key: String,
    pub client_public_key: String,
    pub services: Vec<Service>,
}

#[derive(Deserialize)]
pub struct ClientConfig {
    pub private_key: String,
    pub server_public_key: String,
    pub server_address: transport::Address,
    pub services: Vec<Service>,
    #[serde(default)]
    pub max_connections: i32,
    #[serde(default)]
    pub idle_connections: i32,
}

#[derive(Deserialize)]
pub struct Service {
    pub bind_to: transport::Address,
    pub connect_to: transport::Address,
}

impl ServerConfig {
    pub fn from_file(path: &str) -> anyhow::Result<ServerConfigList> {
        let cfg = from_file::<Config>(path)?;
        let servers = cfg.servers.ok_or(anyhow!("No server config found"))?;
        if servers.is_empty() {
            return Err(anyhow::Error::msg("No server found"));
        }
        Ok(servers)
    }
}

impl ClientConfig {
    pub fn from_file(path: &str) -> anyhow::Result<ClientConfigList> {
        let cfg = from_file::<Config>(path)?;
        let mut clients = cfg.clients.ok_or(anyhow!("No client config found"))?;
        if clients.is_empty() {
            return Err(anyhow::Error::msg("No client found"));
        }
        for client in clients.iter_mut() {
            if client.max_connections <= 0 {
                client.max_connections = 2048;
            }
            if client.idle_connections <= 0 {
                client.idle_connections = 8;
            }
        }
        Ok(clients)
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
        Ok(())
    }

    #[cfg(not(any(unix)))]
    {
        OK(());
    }
}
