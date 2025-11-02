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
    /// supposed to get [String]
    InvalidToken(InvalidTokenError),
    /// We were unable to semantically parse the message,
    /// and the contained value represents the list of
    /// messages we'd received
    ParseError(Vec<Message>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IoError(text) => write!(f, "IO operation failed: {}", text),
            Error::ProtocolError(msg) => {
                write!(f, "received an error message from server")?;
                match msg {
                    Message::ReplyTooLong(text) => write!(f, ": reply too long: {}", text),
                    Message::RouteNotFound(text) => write!(f, ": route not found: {}", text),
                    Message::ConfigurationFileError(text) => {
                        write!(f, ": configuration file error: {}", text)
                    }
                    Message::NoProtocolsMatch(text) => write!(f, ": no protocols match: {}", text),
                    Message::StoppedDueToReconfiguration(text) => {
                        write!(f, ": stopped due to reconfiguration: {}", text)
                    }
                    Message::ProtocolDown(text) => {
                        write!(f, ": protocol is down => connot dump: {}", text)
                    }
                    Message::ReloadFailed(text) => write!(f, ": reload failed: {}", text),
                    Message::AccessDenied(text) => write!(f, ": access denied: {}", text),
                    Message::RuntimeError(code, text) => {
                        write!(f, ": evaluation runtime error: {} {}", code, text)
                    }
                    _ => Ok(()),
                }
            }
            Error::OperationInProgress => write!(f, "another request is already in progress"),
            Error::InvalidToken(error) => write!(f, "received invalid token: {}", error),
            Error::ParseError(messages) => {
                write!(f, "failed to parse server response {:?}", messages)
            }
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
    fn from(cause: Utf8Error) -> Self {
        Error::InvalidToken(InvalidTokenError::NotUtf8(cause))
    }
}

impl From<ParseIntError> for Error {
    fn from(cause: ParseIntError) -> Self {
        Error::InvalidToken(InvalidTokenError::NotAnInt(cause))
    }
}

#[derive(Debug)]
pub enum InvalidTokenError {
    NotUtf8(Utf8Error),
    NotAnInt(ParseIntError),
    Other(String),
}

impl fmt::Display for InvalidTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUtf8(err) => err.fmt(f),
            Self::NotAnInt(err) => err.fmt(f),
            Self::Other(text) => text.fmt(f),
        }
    }
}
