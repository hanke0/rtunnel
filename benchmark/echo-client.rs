use std::env;
use std::error::Error;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::io::{stdin, stdout};
use tokio::net::TcpStream;

mod common;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let stream = TcpStream::connect(env::args().nth(1).unwrap()).await?;
    let mut stdin = stdin();
    let mut stdout = stdout();
    let (mut reader, mut writer) = stream.into_split();
    let (a, b) = tokio::join!(
        async move {
            let mut buffer = [0; 1024];
            loop {
                let n = stdin.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                writer.write_all(&buffer[0..n]).await?;
            }
            Result::<(), Box<dyn Error>>::Ok(())
        },
        async move {
            let mut buffer = [0; 1024];
            loop {
                let n = reader.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                stdout.write_all(&buffer[0..n]).await?;
            }
            Result::<(), Box<dyn Error>>::Ok(())
        },
    );
    a?;
    b?;
    Ok(())
}
