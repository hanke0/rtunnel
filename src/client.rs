use crate::config::ClientConfig;
use crate::encryption::SessionHalf;
use crate::encryption::client_handshake;
use crate::encryption::copy_bidirectional;
use crate::transport::{Address, Controller};
use anyhow::{Result, anyhow};
use ed25519_dalek::{SigningKey, VerifyingKey};
use log::{error, info};
use std::cmp;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::fmt;

pub async fn start_client(cfg: ClientConfig, controller: &Controller) -> Result<()> {
    let verifier = VerifyingKey::try_from(cfg.server_public_key.as_bytes())?;
    let signer = SigningKey::try_from(cfg.private_key.as_bytes())?;
    let mut allows = HashSet::new();

    for service in cfg.services {
        allows.insert(service.connect_to);
    }
    start_service(controller, &cfg.server_address, &verifier, &signer, &allows).await
}

struct ActiveStream {
    pub read_half: SessionHalf,
    pub write_half: SessionHalf,
}

impl fmt::Display for ActiveStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.read_half)
    }
}

async fn connect_to_server(
    server_address: &Address,
    signer: &SigningKey,
    verifier: &VerifyingKey,
) -> Result<ActiveStream> {
    let mut conn = server_address.connect_to().await?;
    let (read_half, write_half) = client_handshake(&mut conn, signer, verifier).await?;
    Ok(ActiveStream {
        read_half,
        write_half,
    })
}

async fn start_service(
    controller: &Controller,
    server_address: &Address,
    verifier: &VerifyingKey,
    signer: &SigningKey,
    allows: &HashSet<Address>,
) -> Result<()> {
    let mut active_stream = connect_to_server(server_address, signer, verifier).await?;
    let _guard = controller.drop_guard();
    handle_stream_silent(controller, &mut active_stream, allows).await;
    Ok(())
}

async fn handle_stream_silent(
    controller: &Controller,
    stream: &mut ActiveStream,
    allows: &HashSet<Address>,
) {
    match handle_stream(controller, stream, allows).await {
        Ok((read, write)) => {
            info!("stream has read {} bytes and wrote {}", read, write);
        }
        Err(e) => {
            error!("stream transfer error: {}, {}", e, stream);
        }
    };
}

async fn handle_stream(
    controller: &Controller,
    stream: &mut ActiveStream,
    allows: &HashSet<Address>,
) -> Result<(usize, usize)> {
    let _guard = controller.drop_guard();
    let addr = stream.read_half.read_connect_msg().await?;
    let mut conn = addr.connect_to().await?;
    if !allows.contains(&addr) {
        return Err(anyhow!("Address not allowed: {}", &addr));
    }
    Ok(copy_bidirectional(
        controller,
        &mut stream.read_half,
        &mut stream.write_half,
        &mut conn,
    )
    .await)
}
