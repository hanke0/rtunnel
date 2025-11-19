use std::env;
use std::error::Error;
use std::result::Result;
use std::sync::Arc;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::Ordering;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = env::args().nth(1).unwrap();
    let listen_addr = env::args().nth(2).unwrap();
    let concurrent = env::args().nth(3).unwrap().parse::<usize>().unwrap();
    let times = env::args().nth(4).unwrap().parse::<usize>().unwrap();
    let bytes = env::args().nth(5).unwrap().parse::<usize>().unwrap();
    let loops = env::args().nth(6).unwrap().parse::<usize>().unwrap();
    run_server(&listen_addr).await?;

    let success = Arc::new(AtomicI64::new(0));
    let failed = Arc::new(AtomicI64::new(0));
    let spend = Arc::new(AtomicI64::new(0));
    let mut set = JoinSet::new();
    for _ in 0..concurrent {
        set.spawn(client_task(
            addr.clone(),
            times,
            bytes,
            loops,
            success.clone(),
            failed.clone(),
            spend.clone(),
        ));
    }
    set.join_all().await;
    eprintln!("addr: {addr}");
    println!("concurrent: {concurrent}");
    println!("times: {times}");
    println!("bytes: {bytes}");
    println!("loops: {loops}");
    println!("Success: {}", success.load(Ordering::Acquire));
    println!("Failed: {}", failed.load(Ordering::Acquire));
    println!("Spend: {}ms", spend.load(Ordering::Acquire));
    let throughout = times as f64 * bytes as f64 * success.load(Ordering::Acquire) as f64
        / (spend.load(Ordering::Acquire) as f64 / 1000.)
        / 1024.;
    println!("Throughput: {:.3}KB/s", throughout);
    Ok(())
}

async fn client_task(
    addr: String,
    times: usize,
    bytes: usize,
    loops: usize,
    success: Arc<AtomicI64>,
    failed: Arc<AtomicI64>,
    spend: Arc<AtomicI64>,
) {
    for _ in 0..times {
        let start = Instant::now();
        let result = run_client(&addr, loops, bytes).await;
        let end = Instant::now();
        match result {
            Err(e) => {
                eprintln!("client task failed: {:#}", e);
                failed.fetch_add(1, Ordering::Release);
            }
            Ok(_) => {
                success.fetch_add(1, Ordering::Release);
                spend.fetch_add(
                    end.duration_since(start).as_millis() as i64,
                    Ordering::Release,
                );
            }
        }
    }
}

async fn run_server(addr: &str) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(addr).await?;
    eprintln!("Listening on: {addr}");
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                if let Err(e) = handle_server_stream(socket).await {
                    eprintln!("server task failed: {:#}", e)
                }
            });
        }
    });
    Ok(())
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

async fn run_client(addr: &str, loops: usize, bytes: usize) -> Result<(), Box<dyn Error>> {
    let stream = TcpStream::connect(addr).await?;
    if bytes == 0 {
        return Ok(());
    }
    let (mut reader, mut writer) = stream.into_split();
    let mut buf = vec![0; bytes];
    for _ in 0..loops {
        writer.write_all(&buf).await?;
        reader.read_exact(&mut buf).await?;
    }
    Ok(())
}
