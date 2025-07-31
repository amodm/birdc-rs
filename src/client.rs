use std::{ffi::OsString, path::Path};

use crate::{Connection, Result, SyncConnection};

/// A bird client instance. You need to create a [Connection] from this
/// client, using [Client::connect], to make requests.
///
/// You can create multiple [Connection]s from the same client, each
/// with their own independent workflows.
pub struct Client {
    unix_socket: OsString,
}

impl Client {
    /// Creates a new [Client] using `unix_socket` file.
    ///
    /// This doesn't establish a new connection, so is guaranteed to
    /// succeed. New connections are created by [Client::connect],
    /// which can fail if `unix_socket` does not exist, or permissions
    /// prevent access.
    pub fn for_unix_socket<P: AsRef<Path>>(unix_socket: P) -> Self {
        Client {
            unix_socket: unix_socket.as_ref().as_os_str().to_owned(),
        }
    }

    /// Open a new [Connection] to this client. You can open multiple
    /// connections to the same client.
    ///
    /// Note that this can fail if the unix socket is closed, or if the
    /// initial hello negotiation with the server fails.
    pub async fn connect(&self) -> Result<Connection> {
        Connection::new(&self.unix_socket).await
    }

    /// Open a new [SyncConnection] to this client. You can open multiple
    /// connections to the same client.
    ///
    /// Note that this can fail if the unix socket is closed, or if the
    /// initial hello negotiation with the server fails.
    pub fn connect_sync(&self) -> Result<SyncConnection> {
        SyncConnection::new(&self.unix_socket)
    }
}
