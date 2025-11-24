use std::collections::HashSet;
use std::fmt::{self, Display};
use std::fs::{self, File};
use std::io::Read;
use std::net::SocketAddr;
use std::str::FromStr;
use std::string::String;

use rcgen::generate_simple_self_signed;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::errors::{Result, ResultExt as _};
use crate::transport::{
    PlainTcpConnectorConfig, PlainTcpListenerConfig, TlsConnectorConfig, TlsListenerConfig,
    Transport,
};
use crate::whatever;

/// Root configuration structure that can contain both server and client configurations.
///
/// This is the top-level configuration structure that is deserialized from TOML files.
/// It may contain either server configurations, client configurations, or both.
#[derive(Deserialize, Serialize)]
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
#[derive(Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    pub listen_to: ListenTo,
    pub services: Vec<Service>,
}

/// Client configuration for rtunnel.
///
/// This struct contains all the settings needed to run a tunnel client,
/// including the server address, cryptographic keys, and connection limits.
#[derive(Deserialize, Serialize, Clone)]
pub struct ClientConfig {
    pub connect_to: ConnectTo,
    pub allowed_addresses: HashSet<String>,
    #[serde(default)]
    pub idle_connections: usize,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(tag = "type")]
pub enum ConnectTo {
    #[serde(rename = "tcp")]
    PlainTcp(PlainTcpConnectorConfig),
    #[serde(rename = "tls")]
    TcpWithTls(TlsConnectorConfig),
}

impl Display for ConnectTo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlainTcp(config) => write!(f, "tcp://{}", config.addr),
            Self::TcpWithTls(config) => write!(f, "tls://{}", config.addr),
        }
    }
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(tag = "type")]
pub enum ListenTo {
    #[serde(rename = "tcp")]
    Tcp(PlainTcpListenerConfig),
    #[serde(rename = "tls")]
    Tls(TlsListenerConfig),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SelfSignedCert {
    pub server_cert: String,
    pub server_key: String,
    pub client_cert: String,
    pub client_key: String,
    pub subject: String,
}

impl SelfSignedCert {
    pub fn new(subject: &str) -> Self {
        let server_key = generate_simple_self_signed(vec![subject.to_string()]).unwrap();
        let client_key = generate_simple_self_signed(vec![subject.to_string()]).unwrap();
        Self {
            server_cert: server_key.cert.pem(),
            server_key: server_key.signing_key.serialize_pem(),
            client_cert: client_key.cert.pem(),
            client_key: client_key.signing_key.serialize_pem(),
            subject: subject.to_string(),
        }
    }
}

impl Display for ListenTo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(config) => write!(f, "tcp://{}", config.addr),
            Self::Tls(config) => write!(f, "tls://{}", config.addr),
        }
    }
}

/// Service definition for a tunnel server.
///
/// A service maps an external listening address to an internal destination address,
/// allowing the server to forward traffic from the public interface to backend services.
#[derive(Deserialize, Serialize, Clone)]
pub struct Service {
    pub listen_to: String,
    pub connect_to: String,
}

impl ServerConfig {
    /// Loads server configurations from a TOML file.
    pub fn from_file(path: &str) -> Result<ServerConfigList> {
        let content = read_config_file(path)?;
        Self::parse(&content)
    }
    /// Parses server configurations from a TOML string.
    pub fn parse(contents: &str) -> Result<ServerConfigList> {
        let cfg = from_string::<Config>(contents)?;
        let mut servers = cfg.servers.ok_or(whatever!("No server config found"))?;
        if servers.is_empty() {
            return Err(whatever!("No server found"));
        }
        for server in servers.iter_mut() {
            for service in server.services.iter_mut() {
                let transport = Transport::parse(&service.connect_to)
                    .context("Failed to parse connect_to address")?;
                service.connect_to = transport.as_string();
            }
        }
        Ok(servers)
    }
}

impl ClientConfig {
    /// Loads client configurations from a TOML file.
    pub fn from_file(path: &str) -> Result<ClientConfigList> {
        let content = read_config_file(path)?;
        Self::parse(&content)
    }
    /// Parses client configurations from a TOML string.
    pub fn parse(contents: &str) -> Result<ClientConfigList> {
        let cfg = from_string::<Config>(contents)?;
        let mut clients = cfg.clients.ok_or(whatever!("No client config found"))?;
        if clients.is_empty() {
            return Err(whatever!("No client found"));
        }
        for client in clients.iter_mut() {
            if client.idle_connections == 0 {
                client.idle_connections = 20;
            }
            let mut allowed_addresses = HashSet::new();
            for allowed_address in client.allowed_addresses.iter() {
                let transport =
                    Transport::parse(allowed_address).context("Failed to parse allowed address")?;
                allowed_addresses.insert(transport.as_string());
            }
            client.allowed_addresses = allowed_addresses;
        }
        Ok(clients)
    }
}

pub fn build_tls_example(subject: &str) -> String {
    let cert = SelfSignedCert::new(subject);

    let config = Config {
        servers: Some(vec![ServerConfig {
            listen_to: ListenTo::Tls(TlsListenerConfig {
                server_cert: cert.server_cert.clone(),
                server_key: cert.server_key,
                client_cert: cert.client_cert.clone(),
                subject: subject.to_string(),
                addr: SocketAddr::from_str("127.0.0.1:2333").unwrap(),
            }),
            services: vec![Service {
                listen_to: "tcp://0.0.0.0:2334".to_string(),
                connect_to: "tcp://127.0.0.1:2335".to_string(),
            }],
        }]),
        clients: Some(vec![ClientConfig {
            connect_to: ConnectTo::TcpWithTls(TlsConnectorConfig {
                client_cert: cert.client_cert,
                client_key: cert.client_key,
                server_cert: cert.server_cert,
                subject: subject.to_string(),
                addr: SocketAddr::from_str("127.0.0.1:2333").unwrap(),
            }),
            idle_connections: 20,
            allowed_addresses: HashSet::from_iter(vec!["tcp://127.0.0.1:2335".to_string()]),
        }]),
    };
    toml::to_string(&config).unwrap()
}

pub fn build_tcp_example() -> String {
    let config = Config {
        servers: Some(vec![ServerConfig {
            listen_to: ListenTo::Tcp(PlainTcpListenerConfig {
                addr: SocketAddr::from_str("127.0.0.1:2333").unwrap(),
            }),
            services: vec![Service {
                listen_to: "tcp://0.0.0.0:2334".to_string(),
                connect_to: "tcp://127.0.0.1:2335".to_string(),
            }],
        }]),
        clients: Some(vec![ClientConfig {
            connect_to: ConnectTo::PlainTcp(PlainTcpConnectorConfig {
                addr: SocketAddr::from_str("127.0.0.1:2333").unwrap(),
            }),
            idle_connections: 20,
            allowed_addresses: HashSet::from(["tcp://127.0.0.1:2335".to_string()]),
        }]),
    };
    toml::to_string(&config).unwrap()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_tls_config() {
        let cfg = build_tls_example("example.com");
        assert!(!cfg.is_empty());
        ServerConfig::parse(&cfg).unwrap();
        ClientConfig::parse(&cfg).unwrap();
    }
    #[test]
    fn example_tcp_config() {
        let cfg = build_tcp_example();
        assert!(!cfg.is_empty());
        ServerConfig::parse(&cfg).unwrap();
        ClientConfig::parse(&cfg).unwrap();
    }
}
