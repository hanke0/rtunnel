use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub endpoint: String,
    pub private_key: String,
    pub public_key: String,
    pub encryption: Option<String>,
    pub clients: Vec<ServerClient>,
    pub services: Vec<ServerService>,
}

#[derive(Debug, Deserialize)]
pub struct ServerClient {
    pub name: String,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    pub name: String,
    pub private_key: String,
    pub public_key: String,
    pub encryption: Option<String>,
    pub servers: Vec<ClientServer>,
    pub services: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClientServer {
    pub endpoint: String,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerService {
    pub name: String,
    pub allowed_clients: Vec<String>,
    pub bind: String,
}

#[derive(Debug, Deserialize)]
pub struct ClientService {
    pub name: String,
    pub connect: String,
}

pub fn from_file<T: DeserializeOwned>(path: &str) -> Result<T, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let config: T = toml::from_str(&contents)?;
    Ok(config)
}
