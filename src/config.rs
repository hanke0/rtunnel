use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::net::{SocketAddr, ToSocketAddrs};
use std::string::String;

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::errors::{Error, Result, ResultExt as _};
use crate::whatever;

/// Root configuration structure that can contain both server and client configurations.
///
/// This is the top-level configuration structure that is deserialized from TOML files.
/// It may contain either server configurations, client configurations, or both.
#[derive(Deserialize)]
pub struct Config {
    pub servers: Option<ServerConfigList>,
    pub clients: Option<ClientConfigList>,
}

pub type ServerConfigList = Vec<ServerConfig>;
pub type ClientConfigList = Vec<ClientConfig>;

/// Server configuration for rtunnel.
///
/// This struct contains all the settings needed to run a tunnel server,
/// including the listening address, cryptographic keys, and service definitions.
#[derive(Deserialize)]
pub struct ServerConfig {
    pub private_key: String,
    pub client_public_key: String,
    pub services: Vec<Service>,
    pub listen_to: ListenTo,
}

/// Client configuration for rtunnel.
///
/// This struct contains all the settings needed to run a tunnel client,
/// including the server address, cryptographic keys, and connection limits.
#[derive(Deserialize)]
pub struct ClientConfig {
    pub private_key: String,
    pub server_public_key: String,
    #[serde(default)]
    pub idle_connections: i32,
    pub connect_to: ConnectTo,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
pub enum ConnectTo {
    #[serde(rename = "tcp")]
    Tcp { addr: SocketAddr },
    #[serde(rename = "tls")]
    Tls {
        client_cert: String,
        client_key: String,
        server_ca: String,
        subject: String,
        addr: SocketAddr,
    },
}

#[derive(Deserialize)]
#[serde(tag = "type")]
pub enum ListenTo {
    #[serde(rename = "tcp")]
    Tcp { addr: SocketAddr },
    #[serde(rename = "tls")]
    Tls {
        server_cert: String,
        server_key: String,
        client_ca: String,
        subject: String,
        addr: SocketAddr,
    },
}

/// Service definition for a tunnel server.
///
/// A service maps an external listening address to an internal destination address,
/// allowing the server to forward traffic from the public interface to backend services.
#[derive(Deserialize)]
pub struct Service {
    pub listen_to: String,
    pub connect_to: String,
}

impl ServerConfig {
    /// Loads server configurations from a TOML file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the configuration file
    ///
    /// # Returns
    ///
    /// Returns a list of server configurations parsed from the file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, parsed, or if no server
    /// configurations are found in the file.
    pub fn from_file(path: &str) -> Result<ServerConfigList> {
        let content = read_config_file(path)?;
        Self::from_string(&content)
    }
    /// Parses server configurations from a TOML string.
    ///
    /// # Arguments
    ///
    /// * `contents` - The TOML configuration string
    ///
    /// # Returns
    ///
    /// Returns a list of server configurations parsed from the string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string cannot be parsed or if no server
    /// configurations are found.
    pub fn from_string(contents: &str) -> Result<ServerConfigList> {
        let cfg = from_string::<Config>(contents)?;
        let servers = cfg.servers.ok_or(whatever!("No server config found"))?;
        if servers.is_empty() {
            return Err(whatever!("No server found"));
        }
        Ok(servers)
    }
}

impl ClientConfig {
    /// Loads client configurations from a TOML file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the configuration file
    ///
    /// # Returns
    ///
    /// Returns a list of client configurations parsed from the file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, parsed, or if no client
    /// configurations are found in the file.
    pub fn from_file(path: &str) -> Result<ClientConfigList> {
        let content = read_config_file(path)?;
        Self::from_string(&content)
    }
    /// Parses client configurations from a TOML string.
    ///
    /// # Arguments
    ///
    /// * `contents` - The TOML configuration string
    ///
    /// # Returns
    ///
    /// Returns a list of client configurations parsed from the string.
    /// Default values are applied for `max_connections` (2048) and
    /// `idle_connections` (8) if not specified.
    ///
    /// # Errors
    ///
    /// Returns an error if the string cannot be parsed or if no client
    /// configurations are found.
    pub fn from_string(contents: &str) -> Result<ClientConfigList> {
        let cfg = from_string::<Config>(contents)?;
        let mut clients = cfg.clients.ok_or(whatever!("No client config found"))?;
        if clients.is_empty() {
            return Err(whatever!("No client found"));
        }
        for client in clients.iter_mut() {
            if client.idle_connections <= 0 {
                client.idle_connections = 8;
            }
        }
        Ok(clients)
    }
}

fn read_config_file(path: &str) -> Result<String> {
    check_config_perm(path).with_context(|| format!("Failed to get file permissions {}", path))?;
    let mut file = File::open(path).with_context(|| format!("Failed to open {}", path))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .with_context(|| format!("Failed to read {}", path))?;
    Ok(contents)
}

fn from_string<T: DeserializeOwned>(contents: &str) -> Result<T> {
    toml::from_str(contents).context("Failed to parse config")
}

// Check if the file is readable and writable only by the owner(0600).
fn check_config_perm(path: &str) -> Result<()> {
    let metadata =
        fs::metadata(path).with_context(|| format!("Failed to get file permission: {}", path,))?;
    let permissions = metadata.permissions();

    // On Unix systems, we can check the mode directly
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = permissions.mode() & 0o777;

        if perm > 0o600 {
            return Err(whatever!(
                "Config file permission should be less or equal than 0o600, current is 0o{:o}, try `chmod 600 {path}` to fix it",
                perm,
            ));
        }
        Ok(())
    }

    #[cfg(windows)]
    {
        _ = permissions;
        Ok(())
    }
}
