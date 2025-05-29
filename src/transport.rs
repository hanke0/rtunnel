use tokio::io::{AsyncRead, AsyncWrite};

pub trait Transport: AsyncRead + AsyncWrite {}

impl<T: ?Sized> Transport for T where T: AsyncRead + AsyncWrite {}
