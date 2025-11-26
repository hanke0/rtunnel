use std::error::Error as StdError;
use std::fmt::{Debug, Display};
use std::ops::Deref;
use std::result::Result as StdResult;
use std::string::String;
use std::time::Duration;

pub type Result<T> = StdResult<T, Error>;

pub trait ResultExt<T> {
    /// Wrap the error value with additional context.
    fn context<C>(self, context: C) -> Result<T>
    where
        C: Display + Send + Sync + 'static;

    /// Wrap the error value with additional context that is evaluated lazily
    /// only once an error does occur.
    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C;

    fn suppress<F: FnOnce(Error)>(self, f: F);
}

pub trait AnyContext<T> {
    fn any_context<C>(self, context: C) -> Result<T>
    where
        C: Display + Send + Sync + 'static;
}

impl<T, E: Display> AnyContext<T> for StdResult<T, E> {
    fn any_context<C>(self, context: C) -> Result<T>
    where
        C: Display + Send + Sync + 'static,
    {
        match self {
            Ok(t) => Ok(t),
            Err(e) => Err(Error::from_any(e).context(context)),
        }
    }
}

impl<T> ResultExt<T> for Result<T> {
    fn context<C>(self, context: C) -> Result<T>
    where
        C: Display + Send + Sync + 'static,
    {
        match self {
            Ok(t) => Ok(t),
            Err(e) => Err(e.context(context)),
        }
    }

    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        match self {
            Ok(t) => Ok(t),
            Err(e) => Err(e.context(f())),
        }
    }

    fn suppress<F: FnOnce(Error)>(self, f: F) {
        match self {
            Ok(_) => {}
            Err(e) => f(e),
        };
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ErrorKind {
    BadIo,
    Eof,
    IoRetryAble,
    Timeout,
    Canceled,
    Tls,
    Other,
}

pub struct Error {
    inner: Box<Inner>,
}

impl Error {
    pub fn new<T: Display>(kind: ErrorKind, message: T) -> Self {
        Self::from_string(kind, message.to_string())
    }

    pub fn from_string(kind: ErrorKind, message: String) -> Self {
        Self {
            inner: Box::new(Inner { kind, message }),
        }
    }

    pub fn from_tls<T: Display>(message: T) -> Self {
        Self::from_string(ErrorKind::Tls, message.to_string())
    }

    pub fn from_any<T: Display>(e: T) -> Self {
        Self::whatever(e.to_string())
    }

    pub fn whatever(message: String) -> Self {
        Self::from_string(ErrorKind::Other, message)
    }

    pub fn cancel() -> Self {
        Self::from_string(ErrorKind::Canceled, "context cancelled".to_string())
    }

    pub fn eof<T: Display>(msg: T) -> Self {
        Self::from_string(ErrorKind::Eof, msg.to_string())
    }

    pub fn from_io(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::UnexpectedEof => Self::new(ErrorKind::Eof, error.to_string()),
            std::io::ErrorKind::WouldBlock => Self::new(ErrorKind::IoRetryAble, error.to_string()),
            std::io::ErrorKind::Interrupted => Self::new(ErrorKind::IoRetryAble, error.to_string()),
            std::io::ErrorKind::TimedOut => Self::new(ErrorKind::Timeout, error.to_string()),
            _ => Self::new(ErrorKind::BadIo, error.to_string()),
        }
    }

    pub fn from_timeout(duration: Duration) -> Self {
        Self::from_string(ErrorKind::Timeout, format!("timeout after {duration:?}"))
    }

    pub fn is_accept_critical(&self) -> bool {
        !matches!(self.inner.kind, ErrorKind::IoRetryAble | ErrorKind::Tls)
    }

    pub fn is_relay_critical(&self) -> bool {
        !matches!(
            self.inner.kind,
            ErrorKind::IoRetryAble | ErrorKind::Eof | ErrorKind::Canceled
        )
    }

    pub fn is_connect_critical(&self) -> bool {
        !matches!(
            self.inner.kind,
            ErrorKind::IoRetryAble | ErrorKind::Canceled
        )
    }

    pub fn is_timeout(&self) -> bool {
        matches!(self.inner.kind, ErrorKind::Timeout)
    }

    pub fn is_cancel(&self) -> bool {
        matches!(self.inner.kind, ErrorKind::Canceled)
    }

    pub fn is_eof(&self) -> bool {
        matches!(self.inner.kind, ErrorKind::Eof)
    }

    pub fn context<T: Display>(mut self, context: T) -> Self {
        self.inner.extend_message(context.to_string().as_str());
        self
    }

    pub fn kind(&self) -> ErrorKind {
        self.inner.kind
    }
}

impl From<Inner> for Error {
    fn from(inner: Inner) -> Self {
        Self {
            inner: Box::new(inner),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self, f)
    }
}

impl AsRef<str> for Error {
    fn as_ref(&self) -> &str {
        &self.inner.message
    }
}

impl AsRef<dyn StdError> for Error {
    fn as_ref(&self) -> &(dyn StdError + 'static) {
        &self.inner
    }
}

impl Deref for Error {
    type Target = dyn StdError;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

struct Inner {
    kind: ErrorKind,
    message: String,
}

impl Inner {
    const DELIMITER: &'static str = ": ";
    fn extend_message(&mut self, message: &str) {
        let mut msg =
            String::with_capacity(self.message.len() + message.len() + Self::DELIMITER.len());
        msg.push_str(message);
        msg.push_str(Self::DELIMITER);
        msg.push_str(&self.message);
        self.message = msg;
    }
}

impl From<Error> for Inner {
    fn from(error: Error) -> Self {
        *error.inner
    }
}

impl StdError for Inner {}

impl Display for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self, f)
    }
}

#[macro_export]
macro_rules! whatever {
    ($msg:literal $(,)?) => {
        $crate::errors::__private::must_use(
            $crate::errors::Error::whatever($msg.to_string())
        )
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::errors::__private::must_use(
            $crate::errors::Error::whatever($crate::errors::__private::format!($fmt, $($arg)*))
        )
    };
}

use tokio_rustls::rustls;
pub use whatever;

macro_rules! generate_from_any {
    ($typ:ty, $from:ident) => {
        impl From<$typ> for $crate::errors::Error {
            fn from(error: $typ) -> Self {
                Error::$from(error)
            }
        }

        impl<T> $crate::errors::ResultExt<T> for std::result::Result<T, $typ> {
            fn context<C>(self, context: C) -> Result<T>
            where
                C: Display + Send + Sync + 'static,
            {
                match self {
                    Ok(t) => Ok(t),
                    Err(e) => Err(Error::from(e).context(context)),
                }
            }

            fn with_context<C, F>(self, f: F) -> Result<T>
            where
                C: Display + Send + Sync + 'static,
                F: FnOnce() -> C,
            {
                match self {
                    Ok(t) => Ok(t),
                    Err(e) => Err(Error::from(e).context(f())),
                }
            }
            fn suppress<F: FnOnce(Error)>(self, f: F) {
                match self {
                    Ok(_) => {}
                    Err(e) => f(e.into()),
                };
            }
        }
    };
    ($typ:ty) => {
        generate_from_any!($typ, from_any);
    };
}

generate_from_any!(std::io::Error, from_io);
generate_from_any!(std::fmt::Error);
generate_from_any!(std::string::FromUtf8Error);
generate_from_any!(toml::de::Error);
generate_from_any!(rustls::Error);
generate_from_any!(tokio_rustls::rustls::pki_types::InvalidDnsNameError);
generate_from_any!(tokio_rustls::rustls::pki_types::pem::Error);
generate_from_any!(rustls::server::VerifierBuilderError);
generate_from_any!(std::array::TryFromSliceError);
generate_from_any!(quinn::ConnectError);
generate_from_any!(quinn::ConnectionError);

// Not public API. Referenced by macro-generated code.
#[doc(hidden)]
pub mod __private {
    #[doc(hidden)]
    pub use std::format;

    #[doc(hidden)]
    #[inline(always)]
    pub const fn must_use<T>(value: T) -> T {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Read};

    #[test]
    fn test_map_and_context() {
        let mut w = io::empty();
        let mut buf = [0u8; 1];
        let r = w.read_exact(&mut buf).context("foo").unwrap_err();
        assert_eq!(r.kind(), ErrorKind::Eof);
        assert_eq!(r.to_string(), "foo: failed to fill whole buffer");
    }
}
