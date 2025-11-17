use core::panic;
use std::fs;
use std::string::String;
use std::time::Duration;

use clap::Parser;
use log::LevelFilter;
use tokio::io;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::task::{JoinSet, spawn};
use tokio::time::sleep;

use rtunnel::errors::from_io_error;
use rtunnel::generate_random_bytes;
use rtunnel::{Arguments, Context, run};

#[tokio::test]
async fn test_integration() {
    let _ = env_logger::builder()
        .filter_level(LevelFilter::Trace)
        .is_test(true)
        .try_init();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = fs::Permissions::from_mode(0o600);
        fs::set_permissions("rtunnel.toml", perm).unwrap();
    }

    let controller = Context::new();
    let server_controller = controller.children();
    let server_handle = spawn(async move {
        let args: Vec<String> = vec![
            "rtunnel".into(),
            "server".into(),
            "--config".into(),
            "rtunnel.toml".into(),
        ];
        let options = Arguments::parse_from(args);
        let code = run(&server_controller, options).await;
        assert_eq!(code, 0);
    });

    sleep(Duration::from_secs(1)).await;
    let client_controller = controller.children();
    let client_handle = spawn(async move {
        let args: Vec<String> = vec![
            "rtunnel".into(),
            "client".into(),
            "--config".into(),
            "rtunnel.toml".into(),
        ];
        let options = Arguments::parse_from(args);
        let code = run(&client_controller, options).await;
        assert_eq!(code, 0);
    });

    sleep(Duration::from_secs(1)).await;

    let listener = TcpListener::bind("127.0.0.1:2335").await.unwrap();
    let listen_controller = controller.children();
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

    sleep(Duration::from_secs(1)).await;

    let mut set = JoinSet::new();
    for _ in 0..1 {
        set.spawn(connect_to_echo(controller.clone()));
    }
    set.join_all().await;
    controller.cancel();
    listen_handle.await.unwrap();
    server_handle.await.unwrap();
    client_handle.await.unwrap();
    controller.wait().await;
}

async fn connect_to_echo(controller: Context) {
    let stream = TcpStream::connect("127.0.0.1:2334").await.unwrap();
    let expect = generate_random_bytes::<65535>().unwrap();
    let mut got = [0u8; 65535];
    let mut_got = &mut got;
    let (mut reader, mut writer) = stream.into_split();

    controller
        .timeout_default(async move {
            writer
                .write_all(expect.as_ref())
                .await
                .map_err(from_io_error)
        })
        .await
        .unwrap();

    controller
        .timeout_default(async move { reader.read_exact(mut_got).await.map_err(from_io_error) })
        .await
        .unwrap();
    assert_eq!(expect.len(), got.len());
    assert_eq!(expect, got);
}
