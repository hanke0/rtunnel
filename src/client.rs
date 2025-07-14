use crate::config::ClientConfig;
use crate::encryption::client_handshake;
use log::{error, info};

pub async fn start_client(cfg: ClientConfig) -> Result<()> {
    let verifier = VerifyingKey::try_from(cfg.server_public_key.as_bytes())?;
    let singer = SigningKey::try_from(cfg.private_key.as_bytes())?;
    loop {
        let (stream, addr) = listener.accept().await?;
        info!("Accepted connection from {}", addr);
        tokio::spawn(handle_client_connection(stream, &verifier, &singer);
    }
    Ok(())
}

async fn handle_client_connection(
    stream: Stream,
    verifier: &VerifyingKey,
    singer: &SigningKey,
    addr: &Address,
) {
    let (mut reader, mut writer) = stream.split();
    let (mut read_half, mut write_half) =
        match client_handshake(&mut reader, &mut writer, &singer, &verifier).await {
            Ok(v) => v,
            Err(e) => {
                error!("Handshake failed: {}", e);
                return;
            }
        };
    let mut raw_stream = match addr.connect_to().await {
        Ok(v) => v,
        Err(e) => {
            error!("Connect to {} fail: {}", addr, e);
            return;
        }
    };

    let (read, write) = copy_bidirectional(
        &mut reader,
        &mut writer,
        &mut raw_reader,
        &mut raw_writer,
        &mut read_half,
        &mut write_half,
    )
    .await;
}
