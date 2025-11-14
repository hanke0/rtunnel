use std::fmt::Debug;
use std::fmt::Display;
use std::time::Duration;

pub use anyhow::Context;
pub use anyhow::Error;
pub use anyhow::Result;

pub enum ErrorKind {
    BadIo(std::io::Error),
    Eof(std::io::Error),
    IoRetryAble(std::io::Error),
    Timeout(std::io::Error),
    Canceled(),
    Other(Error),
}

#[inline]
pub fn cancel_error() -> Error {
    Error::new(ErrorKind::Canceled())
}

#[inline]
pub fn from_msg<S: Display + Debug + Send + Sync + 'static>(msg: S) -> Error {
    Error::new(ErrorKind::Other(Error::msg(msg)))
}

#[inline]
pub fn from_io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::from_io_error(error))
}

#[inline]
pub fn from_timeout(spend: Duration) -> Error {
    Error::new(ErrorKind::Timeout(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("timeout after {:?}", spend),
    )))
}

#[inline]
pub fn from_error<E: std::error::Error + Send + Sync + 'static>(e: E) -> Error {
    Error::new(ErrorKind::Other(Error::new(e)))
}

#[inline]
pub fn is_relay_critical_error(error: &Error) -> bool {
    kind_of(error).is_relay_critical()
}

#[inline]
pub fn is_accept_critical_error(error: &Error) -> bool {
    kind_of(error).is_accept_critical()
}

impl ErrorKind {
    pub fn from_io_error(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::UnexpectedEof => Self::Eof(error),
            std::io::ErrorKind::WouldBlock => Self::IoRetryAble(error),
            std::io::ErrorKind::Interrupted => Self::IoRetryAble(error),
            std::io::ErrorKind::TimedOut => Self::Timeout(error),
            _ => Self::BadIo(error),
        }
    }

    pub fn is_accept_critical(&self) -> bool {
        !matches!(self, ErrorKind::IoRetryAble(_))
    }

    pub fn is_relay_critical(&self) -> bool {
        !matches!(
            self,
            ErrorKind::IoRetryAble(_) | ErrorKind::Eof(_) | ErrorKind::Canceled()
        )
    }

    pub fn is_eof(&self) -> bool {
        matches!(self, ErrorKind::Eof(_))
    }
    pub fn is_timeout(&self) -> bool {
        matches!(self, ErrorKind::Timeout(_))
    }
    pub fn is_canceled(&self) -> bool {
        matches!(self, ErrorKind::Canceled())
    }
}

impl std::error::Error for ErrorKind {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BadIo(e) => Some(e),
            Self::Eof(e) => Some(e),
            Self::IoRetryAble(e) => Some(e),
            Self::Other(e) => Some(e.as_ref()),
            Self::Canceled() => None,
            Self::Timeout(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for ErrorKind {
    fn from(error: std::io::Error) -> Self {
        ErrorKind::from_io_error(error)
    }
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadIo(_) => write!(f, "bad io"),
            Self::Eof(_) => write!(f, "end of file"),
            Self::IoRetryAble(_) => write!(f, "io is unusable currently"),
            Self::Canceled() => write!(f, "controller cancelled"),
            Self::Other(_) => write!(f, "other error"),
            Self::Timeout(_) => write!(f, "timeout"),
        }
    }
}

impl std::fmt::Debug for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

pub fn kind_of(e: &Error) -> &ErrorKind {
    if let Some(kind) = e.downcast_ref::<ErrorKind>() {
        return kind;
    }
    for cause in e.chain() {
        if let Some(kind) = cause.downcast_ref::<ErrorKind>() {
            return kind;
        }
    }
    unreachable!()
}

#[macro_export]
macro_rules! format_err {
    ($msg:literal $(,)?) => {
        $crate::errors::__private::must_use(
            $crate::errors::from_msg($msg)
        )
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::errors::__private::must_use(
            $crate::errors::from_msg($crate::errors::__private::format!($fmt, $($arg)*))
        )
    };
}

pub use format_err;

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
