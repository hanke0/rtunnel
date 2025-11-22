use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[allow(unused)]
pub async fn run_echo_server(addr: &str, wait: bool) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(addr).await?;
    eprintln!("Listening on: {addr}");
    let handle = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                if let Err(e) = handle_server_stream(socket).await {
                    eprintln!("server task failed: {:#}", e)
                }
            });
        }
    });
    if wait { Ok(handle.await?) } else { Ok(()) }
}

async fn handle_server_stream(mut socket: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut buf = vec![0; 1024];
    loop {
        let n = socket.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        socket.write_all(&buf[0..n]).await?;
    }
}
