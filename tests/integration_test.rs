use core::panic;
use std::string::String;
use std::time::Duration;

use clap::Parser;
use tokio::io;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::task::{JoinSet, spawn};
use tokio::time::sleep;

use rtunnel::generate_random_bytes;
use rtunnel::{Cli, Controller, run};

#[tokio::test]
async fn test_integration() {
    let _ = env_logger::builder().is_test(true).try_init();

    let controller = Controller::new();
    let server_controller = controller.clone();
    let server_handle = spawn(async move {
        let args: Vec<String> = vec![
            "rtunnel".into(),
            "server".into(),
            "--config".into(),
            "rtunnel.toml".into(),
        ];
        let options = Cli::parse_from(args);
        run(&server_controller, options).await
    });

    sleep(Duration::from_secs(10)).await;
    let client_controller = controller.clone();
    let client_handle = spawn(async move {
        let args: Vec<String> = vec![
            "rtunnel".into(),
            "client".into(),
            "--config".into(),
            "rtunnel.toml".into(),
        ];
        let options = Cli::parse_from(args);
        run(&client_controller, options).await
    });

    let listener = TcpListener::bind("127.0.0.1:2335").await.unwrap();
    let listen_controller = controller.clone();
    let listen_handle = spawn(async move {
        loop {
            tokio::select! {
                r = listener.accept() => {
                    match r {
                        Ok((stream, _)) => {
                            spawn(async move {
                                let (mut reader, mut writer) = stream.into_split();
                                let amount = io::copy(&mut reader, &mut writer).await;
                                match amount {
                                    Ok(amount) => println!("Copied {amount} bytes"),
                                    Err(e) => println!("Failed to copy: {e}"),
                                }
                            });
                        }
                        Err(e) => println!("Failed to accept: {e}"),
                    };
                },
                _ = listen_controller.wait_cancel() => return
            }
        }
    });

    sleep(Duration::from_secs(10)).await;

    let mut set = JoinSet::new();
    for _ in 0..10 {
        set.spawn(connect_to_echo());
    }
    set.join_all().await;
    controller.cancel();
    listen_handle.await.unwrap();
    server_handle.await.unwrap();
    client_handle.await.unwrap();
    controller.wait().await;
}

async fn connect_to_echo() {
    let mut stream = TcpStream::connect("127.0.0.1:2334").await.unwrap();
    let expect = generate_random_bytes::<65535>().unwrap();
    stream.write_all(expect.as_ref()).await.unwrap();
    let mut got = [0u8; 65535];
    stream.read_exact(&mut got).await.unwrap();
    if expect != got {
        panic!(
            "echo server test failed, got != expect, expect-length={}, got-length={}",
            expect.len(),
            got.len()
        )
    }
}
