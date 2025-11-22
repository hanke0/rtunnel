use std::env;
use std::error::Error;
use std::result::Result;
use std::sync::Arc;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::Ordering;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

mod common;

use crate::common::run_echo_server;

#[derive(Default)]
struct Metrics {
    connect_success: AtomicI64,
    connect_failed: AtomicI64,
    connect_spend_ns: AtomicI64,
    transfer_bytes: AtomicI64,
    transfer_spend_ns: AtomicI64,
    transfer_success: AtomicI64,
    transfer_failed: AtomicI64,
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
    println!(
        "connect_success: {}",
        metrics.connect_success.load(Ordering::SeqCst)
    );
    println!(
        "connect_failed: {}",
        metrics.connect_failed.load(Ordering::SeqCst)
    );
    println!(
        "connect_spend_ns: {}",
        metrics.connect_spend_ns.load(Ordering::SeqCst)
            / metrics.connect_success.load(Ordering::SeqCst).max(1)
    );
    println!(
        "transfer_success: {}",
        metrics.transfer_success.load(Ordering::SeqCst)
    );
    println!(
        "transfer_failed: {}",
        metrics.transfer_failed.load(Ordering::SeqCst)
    );
    println!(
        "transfer_spend_ns: {}",
        metrics.transfer_spend_ns.load(Ordering::SeqCst)
    );
    println!(
        "transfer_bytes: {}",
        metrics.transfer_bytes.load(Ordering::SeqCst)
    );
    let throughout = metrics.transfer_bytes.load(Ordering::SeqCst) as f64
        / (metrics.transfer_spend_ns.load(Ordering::SeqCst) as f64)
        * 1_000_000_000.
        / 1024.;

    println!("Throughput: {:.3}KB/s", throughout);
    Ok(())
}

async fn client_task(addr: String, times: usize, bytes: usize, loops: usize, metrics: MetricsRef) {
    for _ in 0..times {
        let start = Instant::now();
        let mut stream = match TcpStream::connect(&addr).await {
            Ok(s) => s,
            Err(err) => {
                metrics.connect_failed.fetch_add(1, Ordering::SeqCst);
                eprintln!("connect failed: {:#}", err);
                return;
            }
        };
        match stream.write_i8(1).await {
            Ok(_) => {}
            Err(err) => {
                metrics.connect_failed.fetch_add(1, Ordering::SeqCst);
                eprintln!("write when connect failed: {:#}", err);
                return;
            }
        };
        match stream.read_i8().await {
            Ok(_) => {}
            Err(err) => {
                metrics.connect_failed.fetch_add(1, Ordering::SeqCst);
                eprintln!("read when connect failed: {:#}", err);
                return;
            }
        };
        metrics.connect_success.fetch_add(1, Ordering::SeqCst);
        let spend = Instant::now().duration_since(start).as_nanos();
        metrics
            .connect_spend_ns
            .fetch_add(spend as i64, Ordering::SeqCst);

        if bytes == 0 {
            return;
        }
        let (mut reader, mut writer) = stream.into_split();
        let mut buf = vec![0; bytes];
        for _ in 0..loops {
            let start = Instant::now();
            match writer.write_all(&buf).await {
                Ok(_) => {}
                Err(err) => {
                    metrics.transfer_failed.fetch_add(1, Ordering::SeqCst);
                    eprintln!("write when transfer failed: {:#}", err);
                    return;
                }
            };
            match reader.read_exact(&mut buf).await {
                Ok(_) => {
                    metrics.transfer_success.fetch_add(1, Ordering::SeqCst);
                    let spend = Instant::now().duration_since(start).as_nanos();
                    metrics
                        .transfer_spend_ns
                        .fetch_add(spend as i64, Ordering::SeqCst);
                    metrics
                        .transfer_bytes
                        .fetch_add(bytes as i64, Ordering::SeqCst);
                }
                Err(err) => {
                    metrics.transfer_failed.fetch_add(1, Ordering::SeqCst);
                    eprintln!("read when transfer failed: {:#}", err);
                    return;
                }
            };
        }
    }
}
