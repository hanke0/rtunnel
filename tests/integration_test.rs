use core::panic;
use std::collections::HashSet;
use std::io::Write;
use std::net::SocketAddr;
use std::str::FromStr;
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

use rtunnel::config;
use rtunnel::errors::ResultExt;
use rtunnel::observe;
use rtunnel::server;
use rtunnel::transport;
use rtunnel::{
    Arguments, Context, config::build_quic_example, config::build_tcp_example,
    config::build_tls_example, run,
};

#[tokio::test]
#[serial]
async fn test_tls() {
    let config = build_tls_example("example.com");
    test_integration(&config, &config, false).await;
}

#[tokio::test]
#[serial]
async fn test_tcp() {
    let config = build_tcp_example();
    test_integration(&config, &config, false).await;
}

#[tokio::test]
#[serial]
async fn test_quic() {
    let config = build_quic_example("example.com");
    test_integration(&config, &config, false).await;
}

#[tokio::test]
#[serial]
async fn test_tcp_backup() {
    let config = build_tcp_example();
    let cfg = &mut config::Config::parse(&config).unwrap();
    for server in cfg.servers.iter_mut() {
        server.listen_to2 = Some(config::ListenTo::PlainTcp(
            transport::PlainTcpListenerConfig {
                addr: SocketAddr::from_str("127.0.0.1:2336").unwrap(),
                reuse_port: None,
            },
        ));
    }
    for client in cfg.clients.iter_mut() {
        client.connect_to = config::ConnectTo::PlainTcp(transport::PlainTcpConnectorConfig {
            addr: "127.0.0.1:2336".to_string(),
        });
    }
    cfg.admin = Some(config::AdminConfig {
        listen_to: SocketAddr::from_str("127.0.0.1:2337").unwrap(),
        http_path: Some("/status".to_string()),
    });
    let sever_config = cfg.to_string();
    cfg.admin = Some(config::AdminConfig {
        listen_to: SocketAddr::from_str("127.0.0.1:2338").unwrap(),
        http_path: Some("/status".to_string()),
    });
    let client_config = cfg.to_string();
    test_integration(&sever_config, &client_config, true).await;
}

#[tokio::test]
#[serial]
async fn test_client_works_fine_when_one_tunnel_is_not_available() {
    observe::setup_testing();
    let config = build_tcp_example();
    let cfg = &mut config::Config::parse(&config).unwrap();
    cfg.clients.push(config::ClientConfig {
        name: None,
        connect_to: config::ConnectTo::PlainTcp(transport::PlainTcpConnectorConfig {
            addr: "127.0.0.1:2336".to_string(),
        }),
        allowed_addresses: HashSet::new(),
        idle_connections: 20,
    });
    let config = toml::to_string(cfg).unwrap();
    let server_context = Context::new();
    let watch = observe::Watcher::new();
    server::start_server(
        &server_context,
        config::ServerConfig {
            name: None,
            listen_to: config::ListenTo::PlainTcp(transport::PlainTcpListenerConfig {
                addr: SocketAddr::from_str("127.0.0.1:2336").unwrap(),
                reuse_port: None,
            }),
            listen_to2: None,
            services: vec![],
        },
        &watch,
    )
    .await
    .unwrap();
    let context = Context::new();
    let finish = start_test(&context, &config, &config).await;
    sleep(Duration::from_secs(1)).await;
    server_context.cancel();
    server_context.wait_finish().await;
    concurrent_test(&context).await;
    finish.await;
}

async fn start_test(
    context: &Context,
    server_config: &str,
    client_config: &str,
) -> impl Future<Output = ()> {
    observe::setup_testing();
    let server_file = write_config(server_config).await;
    let client_file = write_config(client_config).await;

    let server_context = context.children();
    let file_path = server_file.path().display().to_string();
    let server_handle = spawn(async move {
        let args: Vec<String> = vec![
            "rtunnel".into(),
            "server".into(),
            "--config".into(),
            file_path,
        ];
        let options = Arguments::parse_from(args);
        run(&server_context, options).await.expect("server failed");
    });

    sleep(Duration::from_secs(1)).await;
    let client_context = context.children();
    let file_path = client_file.path().display().to_string();
    let client_handle = spawn(async move {
        let args: Vec<String> = vec![
            "rtunnel".into(),
            "client".into(),
            "--config".into(),
            file_path,
        ];
        let options = Arguments::parse_from(args);
        run(&client_context, options).await.expect("client failed");
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
        context.wait_cancel_and_finish().await;
        let _server = server_file;
        let _client = client_file;
    }
}

async fn test_integration(sever_config: &str, client_config: &str, admin_check: bool) {
    let context = Context::new();
    let finish = start_test(&context, sever_config, client_config).await;
    concurrent_test(&context).await;
    if admin_check {
        check_admin("127.0.0.1:2337").await;
        check_admin("127.0.0.1:2338").await;
    };
    finish.await;
}

async fn check_admin(addr: &str) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).await.unwrap();
    let response: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&buffer[0..n]);
    assert!(response.contains("\"alive_tunnel\":"), "{}", response)
}

async fn concurrent_test(context: &Context) {
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

async fn write_config(config: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(config.as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        let perm = fs::Permissions::from_mode(0o600);
        fs::set_permissions(file.path().display().to_string(), perm.clone()).unwrap();
    }
    file
}

#[tokio::test]
#[serial]
async fn test_client_exit_normal() {
    observe::setup_testing();
    let config = build_tcp_example();
    let file = write_config(&config).await;
    let server_context = Context::new();
    let server_context1 = server_context.clone();
    let file_path = file.path().display().to_string();
    let join = tokio::spawn(async move {
        let args: Vec<String> = vec![
            "rtunnel".into(),
            "server".into(),
            "--config".into(),
            file_path,
        ];
        let options = Arguments::parse_from(args);
        run(&server_context, options).await.expect("server failed");
    });

    let client_context = Context::new();
    let file_path = file.path().display().to_string();
    let join2 = tokio::spawn(async move {
        let args: Vec<String> = vec![
            "rtunnel".into(),
            "client".into(),
            "--config".into(),
            file_path,
        ];
        let options = Arguments::parse_from(args);
        run(&client_context, options).await.expect("client failed");
    });
    sleep(Duration::from_secs(1)).await;
    server_context1.cancel();
    info!("server is cancel, wait finish");
    join.await.unwrap();
    info!("server finished");
    join2.await.unwrap();
    info!("client finished");
}
