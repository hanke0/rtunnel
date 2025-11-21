use core::panic;
use std::fs;
use std::io::Write;
use std::string::String;
use std::time::Duration;

use clap::Parser;
use log::LevelFilter;
use log::{error, info};
use rtunnel::errors::ResultExt;
use tempfile::NamedTempFile;
use tokio::io;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::task::{JoinSet, spawn};
use tokio::time::sleep;

use rtunnel::{Arguments, Context, build_example_config, run, setup_logger};

#[tokio::test]
async fn test_integration() {
    setup_logger(LevelFilter::Trace, true);
    let config = build_example_config("example.com");
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(config.as_bytes()).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = fs::Permissions::from_mode(0o600);
        fs::set_permissions(file.path().display().to_string(), perm).unwrap();
    }

    let context = Context::new();
    let server_context = context.children();
    let file_path = file.path().display().to_string();
    let server_handle = spawn(async move {
        let args: Vec<String> = vec![
            "rtunnel".into(),
            "server".into(),
            "--config".into(),
            file_path,
        ];
        let options = Arguments::parse_from(args);
        let code = run(&server_context, options).await;
        assert_eq!(code, 0);
    });

    sleep(Duration::from_secs(1)).await;
    let client_context = context.children();
    let file_path = file.path().display().to_string();
    let client_handle = spawn(async move {
        let args: Vec<String> = vec![
            "rtunnel".into(),
            "client".into(),
            "--config".into(),
            file_path,
        ];
        let options = Arguments::parse_from(args);
        let code = run(&client_context, options).await;
        assert_eq!(code, 0);
    });

    sleep(Duration::from_secs(1)).await;

    let listener = TcpListener::bind("127.0.0.1:2335").await.unwrap();
    let listen_context = context.children();
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
                                    Ok(amount) => info!("Copied {amount} bytes"),
                                    Err(e) => error!("Failed to copy: {e}"),
                                }
                            });
                        }
                        Err(e) => error!("Failed to accept: {e}"),
                    };
                },
                _ = listen_context.wait_cancel() => return
            }
        }
    });

    sleep(Duration::from_secs(1)).await;

    let concurrent_test = async |context: Context, n: usize| {
        let mut set = JoinSet::new();
        for _ in 0..n {
            set.spawn(connect_to_echo(context.clone()));
        }
        set.join_all().await;
        info!("It's OK for {n} concurrent connections");
    };
    concurrent_test(context.clone(), 1).await;
    concurrent_test(context.clone(), 8).await;
    // TODO: no more tunnel available. Should we support create tunnel from server side?
    // concurrent_test(context.clone(), 100).await;

    context.cancel();
    listen_handle.await.unwrap();
    server_handle.await.unwrap();
    client_handle.await.unwrap();
    context.wait().await;

    let _ = file.path();
}

async fn connect_to_echo(context: Context) {
    let stream = TcpStream::connect("127.0.0.1:2334").await.unwrap();
    let expect = [1u8; 65535];
    let mut got = [0u8; 65535];
    let mut_got = &mut got;
    let addr = format!(
        "{}-{}",
        stream.peer_addr().unwrap(),
        stream.local_addr().unwrap()
    );
    let (mut reader, mut writer) = stream.into_split();
    const TIMEOUT: Duration = Duration::from_secs(100);
    context
        .timeout(
            TIMEOUT,
            async move { writer.write_all(expect.as_ref()).await },
        )
        .await
        .with_context(|| format!("fail to write: {}", addr))
        .unwrap();
    info!("echo client {} write {} bytes", addr, expect.len());
    context
        .timeout(TIMEOUT, async move { reader.read_exact(mut_got).await })
        .await
        .with_context(|| format!("fail to read: {}", addr))
        .unwrap();
    info!("echo client {} read {} bytes", addr, got.len());
    assert_eq!(expect.len(), got.len());
    assert_eq!(expect, got);
}
