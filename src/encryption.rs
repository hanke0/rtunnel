use crate::transport::Transport;

pub async fn client_handshake(stream: &mut impl Transport) -> Result<(), std::io::Error> {
    Ok(())
}

pub async fn server_handshake(stream: &mut impl Transport) -> Result<(), std::io::Error> {
    Ok(())
}
