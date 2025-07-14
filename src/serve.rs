pub async fn start_serve(cfg: ServerConfig) -> Result<()> {
    let verifier = VerifyingKey::try_from(cfg.client_public_key.as_bytes())?;
    let singer = SigningKey::try_from(cfg.private_key.as_bytes())?;
    let mut listener = cfg.listen.listen_to().await?;
    loop {
        let (stream, addr) = listener.accept().await?;
        info!("Accepted connection from {}", addr);
        tokio::spawn(handle_sever_connection(stream, &verifier, &singer));
    }
    Ok(())
}

async fn handle_sever_connection(stream: Stream, verifier: &VerifyingKey, singer: &SigningKey) {
    let (mut reader, mut writer) = stream.split();
    let (mut read_session, mut write_session) =
        server_handshake(&mut reader, &mut writer, &singer, &verifier)
            .await
            .unwrap_err();

    copy_bidirectional(
        encrypted_reader,
        encrypted_writer,
        raw_reader,
        raw_writer,
        read_half,
        write_half,
    )
    .await?;
}
