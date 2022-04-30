use std::{num::ParseIntError, str::Utf8Error};

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
