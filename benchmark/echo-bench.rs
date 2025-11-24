use std::env;
use std::error::Error;
use std::result::Result;
use std::sync::Arc;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

mod common;

use crate::common::run_echo_server;

#[derive(Default)]
struct Metrics {
    bytes: AtomicI64,
    spend_ns: AtomicI64,
    failed: AtomicI64,
}

type MetricsRef = Arc<Metrics>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = env::args().nth(1).unwrap();
    let listen_addr = env::args().nth(2).unwrap();
    let concurrent = env::args().nth(3).unwrap().parse::<usize>().unwrap();
    let times = env::args().nth(4).unwrap().parse::<usize>().unwrap();
    let bytes = env::args().nth(5).unwrap().parse::<usize>().unwrap();
    let loops = env::args().nth(6).unwrap().parse::<usize>().unwrap();
    run_echo_server(&listen_addr, false).await?;

    // warm up
    client_task(addr.clone(), 3, 8192, 8, Arc::new(Metrics::default())).await;

    let metrics = Arc::new(Metrics::default());
    let mut set = JoinSet::new();
    for _ in 0..concurrent {
        set.spawn(client_task(
            addr.clone(),
            times,
            bytes,
            loops,
            metrics.clone(),
        ));
    }
    set.join_all().await;
    eprintln!("addr: {addr}");
    println!("concurrent: {concurrent}");
    println!("times: {times}");
    println!("bytes: {bytes}");
    println!("loops: {loops}");
    println!("failed: {}", metrics.failed.load(Ordering::SeqCst));
    println!(
        "total_spend: {:?}",
        Duration::from_nanos(metrics.spend_ns.load(Ordering::SeqCst) as u64)
    );
    println!("total_bytes: {}", metrics.bytes.load(Ordering::SeqCst));
    let throughout = metrics.bytes.load(Ordering::SeqCst) as f64
        / (metrics.spend_ns.load(Ordering::SeqCst) as f64)
        * 1_000_000_000.
        / 1024.;

    println!("throughput: {:.3}KB/s", throughout);
    Ok(())
}

async fn client_task(addr: String, times: usize, bytes: usize, loops: usize, metrics: MetricsRef) {
    for _ in 0..times {
        let mut start = Instant::now();
        let mut stream = match TcpStream::connect(&addr).await {
            Ok(s) => s,
            Err(err) => {
                metrics.failed.fetch_add(1, Ordering::SeqCst);
                eprintln!("connect failed: {:#}", err);
                return;
            }
        };
        let mut buf = vec![0; bytes];
        for _ in 0..loops {
            match stream.write_all(&buf).await {
                Ok(_) => {}
                Err(err) => {
                    metrics.failed.fetch_add(1, Ordering::SeqCst);
                    eprintln!("write when transfer failed: {:#}", err);
                    return;
                }
            };
            match stream.read_exact(&mut buf).await {
                Ok(_) => {
                    let spend = Instant::now().duration_since(start).as_nanos();
                    metrics.spend_ns.fetch_add(spend as i64, Ordering::SeqCst);
                    metrics.bytes.fetch_add(bytes as i64, Ordering::SeqCst);
                }
                Err(err) => {
                    metrics.failed.fetch_add(1, Ordering::SeqCst);
                    eprintln!("read when transfer failed: {:#}", err);
                    return;
                }
            };
            start = Instant::now();
        }
    }
}
