use std::time::Duration;

pub type Result<T, E = anyhow::Error> = anyhow::Result<T, E>;

pub type Error = anyhow::Error;

pub enum ErrorKind {
    BadIo(std::io::Error),
    EOF(std::io::Error),
    IoRetrable(std::io::Error),
    Timeout(std::time::Duration),
    Canceled(),
    Other(String),
    Unknown(),
}

pub fn cancel_error() -> Error {
    Error::new(ErrorKind::Canceled())
}

pub fn other_error(msg: String) -> Error {
    Error::new(ErrorKind::Other(msg)
}

pub fn from_io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::from_io_error(error))
}

const UNKNOWN: ErrorKind = ErrorKind::Unknown();

impl ErrorKind {
    pub fn from_io_error(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::UnexpectedEof => Self::EOF(error),
            std::io::ErrorKind::WouldBlock => Self::IoRetrable(error),
            std::io::ErrorKind::Interrupted => Self::IoRetrable(error),
            std::io::ErrorKind::TimedOut => Self::Timeout(Duration::default()),
            _ => Self::BadIo(error),
        }
    }
    pub fn from_timeout(duration: std::time::Duration) -> Self {
        Self::Timeout(duration)
    }
}

impl std::error::Error for ErrorKind {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BadIo(e) => Some(e),
            Self::EOF(e) => Some(e),
            Self::IoRetrable(e) => Some(e),
            Self::Other(e) => Some(e.as_ref()),
            Self::Canceled() => None,
            Self::Timeout(_) => None,
            Self::Unknown() => None,
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
            Self::BadIo(e) => write!(f, "bad io result: {}", e),
            Self::EOF(e) => write!(f, "end of file: {}", e),
            Self::IoRetrable(e) => write!(f, "io is unusable currently: {}", e),
            Self::Canceled() => write!(f, "controller cancelled"),
            Self::Other(e) => write!(f, "{}", e),
            Self::Timeout(e) => write!(f, "timeout after {:?}", e),
            Self::Unknown() => write!(f, "unknown error"),
        }
    }
}

impl std::fmt::Debug for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

pub fn kind_of(e: &Error) -> &ErrorKind {
    for cause in e.chain() {
        if let Some(kind) = cause.downcast_ref::<ErrorKind>() {
            return kind;
        }
    }
    &UNKNOWN
}

#[macro_export]
macro_rules! anyerror {
    ($msg:literal $(,)?) => {
        $crate::__private::ErrorKind::Other($crate::__private::anyhow::anyhow!($msg))
    };
    ($err:expr $(,)?) => {
        $crate::__private::ErrorKind::Other($crate::__private::anyhow::anyhow!($err))
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::__private::ErrorKind::Other($crate::__private::anyhow::anyhow!($fmt, $($arg)*))
    };
}
