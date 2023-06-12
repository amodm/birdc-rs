use std::{fmt, num::ParseIntError, str::Utf8Error};

use super::Message;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// Simple wrapper over all I/O related errors
    IoError(std::io::Error),
    /// We received an error [Message] from the server
    ProtocolError(Message),
    /// If a new request is made on a connection before the
    /// response of the previous one has been fully read.
    OperationInProgress,
    /// If we received a token which was not what we were
    /// supposed to get
    InvalidToken(String),
    /// We were unable to semantically parse the message,
    /// and the contained value represents the list of
    /// messages we'd received
    ParseError(Vec<Message>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IoError(_) => write!(f, "IO operation failed"),
            Error::ProtocolError(msg) => {
                write!(f, "received an error message from server")?;
                match msg {
                    Message::ReplyTooLong(_) => write!(f, ": reply too long"),
                    Message::RouteNotFound(_) => write!(f, ": route not found"),
                    Message::ConfigurationFileError(_) => write!(f, ": configuration file error"),
                    Message::NoProtocolsMatch(_) => write!(f, ": no protocols match"),
                    Message::StoppedDueToReconfiguration(_) => {
                        write!(f, ": stopped due to reconfiguration")
                    }
                    Message::ProtocolDown(_) => write!(f, ": protocol is down => connot dump"),
                    Message::ReloadFailed(_) => write!(f, ": reload failed"),
                    Message::AccessDenied(_) => write!(f, ": access denied"),
                    Message::RuntimeError(..) => write!(f, ": evaluation runtime error"),
                    _ => Ok(()),
                }
            }
            Error::OperationInProgress => write!(f, "another request is already in progress"),
            Error::InvalidToken(_) => write!(f, "received invalid token"),
            Error::ParseError(_) => write!(f, "failed to parse server response"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(err) => Some(err),
            _ => None,
        }
    }
}

impl Error {
    pub fn eof(err: &str) -> Self {
        Self::IoError(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, err))
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err)
    }
}

impl From<Message> for Error {
    fn from(message: Message) -> Self {
        Error::ProtocolError(message)
    }
}

impl From<Utf8Error> for Error {
    fn from(_: Utf8Error) -> Self {
        Error::InvalidToken("failed to parse as utf8".into())
    }
}

impl From<ParseIntError> for Error {
    fn from(_: ParseIntError) -> Self {
        Error::InvalidToken("failed to parse as integer".into())
    }
}
