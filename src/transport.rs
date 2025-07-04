use std::io;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct Reader(Arc<Mutex<Stream>>);

impl Reader {
    pub async fn read(self: &mut Self, buf: &mut [u8]) -> io::Result<usize> {
        let guard = self.0.lock();
        guard.unwrap().read(buf).await
    }
    pub async fn read_exact(self: &mut Self, buf: &mut [u8]) -> io::Result<usize> {
        let guard = self.0.lock();
        guard.unwrap().read_exact(buf).await
    }
}

pub struct Writer(Arc<Mutex<Stream>>);

impl Writer {
    pub async fn write_all(self: &mut Self, data: &[u8]) -> io::Result<()> {
        let guard = self.0.lock();
        guard.unwrap().write_all(data).await
    }
}

pub enum Stream {
    TCP(TcpStream),
}

impl Stream {
    pub async fn write_all(self: &mut Self, data: &[u8]) -> io::Result<()> {
        match self {
            Stream::TCP(s) => s.write_all(data).await,
        }
    }
    pub async fn read(self: &mut Self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::TCP(s) => s.read(buf).await,
        }
    }
    pub async fn read_exact(self: &mut Self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::TCP(s) => s.read_exact(buf).await,
        }
    }
    pub fn test(self) {
        let _a = Arc::new(self);
    }

    pub fn split(self) -> (Reader, Writer) {
        let a = Arc::new(Mutex::new(self));
        let b = a.clone();
        (Reader(a), Writer(b))
    }
}
