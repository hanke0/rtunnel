use crate::transport::Transport;
use anyhow;

pub struct Session {
    raw: Box<dyn Transport>,
}

impl Session {
    pub async fn client_handshake<'a>(stream: Box<dyn Transport>) -> anyhow::Result<Self> {
        Ok(Session { raw: stream })
    }
    pub async fn server_handshake(stream: Box<dyn Transport>) -> anyhow::Result<Self> {
        Ok(Session { raw: stream })
    }
}
