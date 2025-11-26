use core::panic;
use std::io::Write;
use std::string::String;
use std::time::Duration;

use clap::Parser;
use serial_test::serial;
use tempfile::NamedTempFile;
use tokio::io;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::task::{JoinSet, spawn};
use tokio::time::sleep;
use tracing::{error, info};

use rtunnel::errors::ResultExt;
use rtunnel::observe;
use rtunnel::{
    Arguments, Context, config::build_quic_example, config::build_tcp_example,
    config::build_tls_example, run,
};

#[tokio::test]
#[serial]
async fn test_tls() {
    let config = build_tls_example("example.com");
    test_integration(&config).await;
}

#[tokio::test]
#[serial]
async fn test_tcp() {
    let config = build_tcp_example();
    test_integration(&config).await;
}

#[tokio::test]
#[serial]
async fn test_quic() {
    let config = build_quic_example("example.com");
    test_integration(&config).await;
}

async fn start_test(context: &Context, config: &str) -> impl Future<Output = ()> {
    observe::setup_testing();
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(config.as_bytes()).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        use std::fs;
        let perm = fs::Permissions::from_mode(0o600);
        fs::set_permissions(file.path().display().to_string(), perm).unwrap();
    }

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

    async move {
        context.cancel();
        listen_handle.await.unwrap();
        server_handle.await.unwrap();
        client_handle.await.unwrap();
        context.wait().await;
        let _ = file.path();
    }
}

async fn test_integration(config: &str) {
    let context = Context::new();
    let finish = start_test(&context, config).await;
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

    // wait for keep alive ping to be sent
    sleep(Duration::from_secs(10)).await;
    concurrent_test(context.clone(), 1).await;

    for _ in 0..1000 {
        connect_to_echo(context.clone()).await;
    }
    finish.await;
}

async fn connect_to_echo(context: Context) {
    let stream = TcpStream::connect("127.0.0.1:2334").await.unwrap();
    let expect = [1u8; 1024];
    let mut got = [0u8; 1024];
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
