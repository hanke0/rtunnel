use std::collections::HashSet;
use std::fmt::{self, Display};
use std::fs::{self, File};
use std::io::Read;
use std::net::SocketAddr;
use std::str::FromStr;
use std::string::String;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::errors::{Error, Result, ResultExt as _};
use crate::transport::{
    PlainTcpConnectorConfig, PlainTcpListenerConfig, QuicConnectorConfig, QuicListenerConfig,
    TlsTcpConnectorConfig, TlsTcpListenerConfig, Transport,
};
use crate::whatever;

/// Root configuration structure that can contain both server and client configurations.
///
/// This is the top-level configuration structure that is deserialized from TOML files.
/// It may contain either server configurations, client configurations, or both.
#[derive(Deserialize, Serialize)]
pub struct Config {
    pub servers: Vec<ServerConfig>,
    pub clients: Vec<ClientConfig>,
    pub admin: Option<AdminConfig>,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self> {
        let contents = read_config_file(path).context("Failed to read config file")?;
        Self::parse(&contents)
    }

    pub fn parse(contents: &str) -> Result<Self> {
        let mut cfg = from_string::<Config>(contents)?;
        Self::fix_servers(&mut cfg.servers)?;
        Self::fix_clients(&mut cfg.clients)?;
        Ok(cfg)
    }

    fn fix_servers(servers: &mut [ServerConfig]) -> Result<()> {
        for server in servers.iter_mut() {
            for service in server.services.iter_mut() {
                let transport = Transport::parse(&service.connect_to)
                    .context("Failed to parse connect_to address")?;
                service.connect_to = transport.as_string();
            }
        }
        Ok(())
    }

    fn fix_clients(clients: &mut [ClientConfig]) -> Result<()> {
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
        Ok(())
    }
}

impl FromStr for Config {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

/// Server configuration for rtunnel.
///
/// This struct contains all the settings needed to run a tunnel server,
/// including the listening address, cryptographic keys, and service definitions.
#[derive(Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    pub name: Option<String>,
    pub listen_to: ListenTo,
    pub listen_to2: Option<ListenTo>,
    pub services: Vec<Service>,
}

impl ServerConfig {
    pub fn get_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| self.listen_to.to_string())
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
    pub reuse_port: Option<bool>,
}

/// Client configuration for rtunnel.
///
/// This struct contains all the settings needed to run a tunnel client,
/// including the server address, cryptographic keys, and connection limits.
#[derive(Deserialize, Serialize, Clone)]
pub struct ClientConfig {
    pub name: Option<String>,
    pub connect_to: ConnectTo,
    pub allowed_addresses: HashSet<String>,
    #[serde(default)]
    pub idle_connections: usize,
}

impl ClientConfig {
    pub fn get_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| self.connect_to.to_string())
    }
}

#[derive(Deserialize, Serialize)]
pub struct AdminConfig {
    pub listen_to: SocketAddr,
    pub http_path: Option<String>,
}

impl AdminConfig {
    pub fn get_http_path(&self) -> String {
        self.http_path
            .clone()
            .unwrap_or_else(|| "/rtunnel/admin/status".to_string())
    }
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConnectTo {
    PlainTcp(PlainTcpConnectorConfig),
    TlsTcp(TlsTcpConnectorConfig),
    Quic(QuicConnectorConfig),
}

impl Display for ConnectTo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlainTcp(config) => write!(f, "tcp://{}", config.addr),
            Self::TlsTcp(config) => write!(f, "tls://{}", config.addr),
            Self::Quic(config) => write!(f, "quic://{}", config.addr),
        }
    }
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ListenTo {
    PlainTcp(PlainTcpListenerConfig),
    TlsTcp(TlsTcpListenerConfig),
    Quic(QuicListenerConfig),
}

impl Display for ListenTo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlainTcp(config) => write!(f, "tcp://{}", config.addr),
            Self::TlsTcp(config) => write!(f, "tls://{}", config.addr),
            Self::Quic(config) => write!(f, "quic://{}", config.addr),
        }
    }
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
    fn generate(subject: &str) -> rcgen::CertifiedKey<rcgen::KeyPair> {
        let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = rcgen::CertificateParams::new(vec![subject.to_string()])
            .unwrap()
            .self_signed(&signing_key)
            .unwrap();
        rcgen::CertifiedKey { cert, signing_key }
    }

    pub fn new(subject: &str) -> Self {
        let server_key = Self::generate(subject);
        let client_key = Self::generate(subject);
        Self {
            server_cert: server_key.cert.pem(),
            server_key: server_key.signing_key.serialize_pem(),
            client_cert: client_key.cert.pem(),
            client_key: client_key.signing_key.serialize_pem(),
            subject: subject.to_string(),
        }
    }
}

pub fn build_tls_example(subject: &str) -> String {
    let cert = SelfSignedCert::new(subject);

    let config = Config {
        admin: None,
        servers: vec![ServerConfig {
            name: None,
            listen_to: ListenTo::TlsTcp(TlsTcpListenerConfig {
                server_cert: cert.server_cert.clone(),
                server_key: cert.server_key,
                client_cert: cert.client_cert.clone(),
                subject: subject.to_string(),
                addr: SocketAddr::from_str("127.0.0.1:2333").unwrap(),
                reuse_port: None,
            }),
            listen_to2: None,
            services: vec![Service {
                listen_to: "tcp://0.0.0.0:2334".to_string(),
                connect_to: "tcp://127.0.0.1:2335".to_string(),
                reuse_port: None,
            }],
        }],
        clients: vec![ClientConfig {
            name: None,
            connect_to: ConnectTo::TlsTcp(TlsTcpConnectorConfig {
                client_cert: cert.client_cert,
                client_key: cert.client_key,
                server_cert: cert.server_cert,
                subject: subject.to_string(),
                addr: "127.0.0.1:2333".to_string(),
            }),
            idle_connections: 20,
            allowed_addresses: HashSet::from_iter(vec!["tcp://127.0.0.1:2335".to_string()]),
        }],
    };
    toml::to_string(&config).unwrap()
}

pub fn build_tcp_example() -> String {
    let config = Config {
        admin: None,
        servers: vec![ServerConfig {
            name: None,
            listen_to: ListenTo::PlainTcp(PlainTcpListenerConfig {
                addr: SocketAddr::from_str("127.0.0.1:2333").unwrap(),
                reuse_port: None,
            }),
            listen_to2: None,
            services: vec![Service {
                listen_to: "tcp://0.0.0.0:2334".to_string(),
                connect_to: "tcp://127.0.0.1:2335".to_string(),
                reuse_port: None,
            }],
        }],
        clients: vec![ClientConfig {
            name: None,
            connect_to: ConnectTo::PlainTcp(PlainTcpConnectorConfig {
                addr: "127.0.0.1:2333".to_string(),
            }),
            idle_connections: 20,
            allowed_addresses: HashSet::from(["tcp://127.0.0.1:2335".to_string()]),
        }],
    };
    toml::to_string(&config).unwrap()
}

pub fn build_quic_example(subject: &str) -> String {
    let cert = SelfSignedCert::new(subject);

    let config = Config {
        admin: None,
        servers: vec![ServerConfig {
            name: None,
            listen_to: ListenTo::Quic(QuicListenerConfig {
                server_cert: cert.server_cert.clone(),
                server_key: cert.server_key,
                client_cert: cert.client_cert.clone(),
                subject: subject.to_string(),
                addr: SocketAddr::from_str("127.0.0.1:2333").unwrap(),
            }),
            listen_to2: None,
            services: vec![Service {
                listen_to: "tcp://0.0.0.0:2334".to_string(),
                connect_to: "tcp://127.0.0.1:2335".to_string(),
                reuse_port: None,
            }],
        }],
        clients: vec![ClientConfig {
            name: None,
            connect_to: ConnectTo::Quic(QuicConnectorConfig {
                client_cert: cert.client_cert,
                client_key: cert.client_key,
                server_cert: cert.server_cert,
                subject: subject.to_string(),
                addr: "127.0.0.1:2333".to_string(),
            }),
            idle_connections: 20,
            allowed_addresses: HashSet::from_iter(vec!["tcp://127.0.0.1:2335".to_string()]),
        }],
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
        Config::parse(&cfg).unwrap();
    }
    #[test]
    fn example_tcp_config() {
        let cfg = build_tcp_example();
        assert!(!cfg.is_empty());
        Config::parse(&cfg).unwrap();
    }
}
