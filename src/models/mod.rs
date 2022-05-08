//! All structured models of the Bird client protocol

mod interface;
pub use interface::*;

mod protocol;
pub use protocol::*;

mod status;
pub use status::*;

/// A composite entry in the `show interfaces` command
#[derive(Debug)]
pub struct ShowInterfacesMessage {
    pub interface: Interface,
    pub properties: InterfaceProperties,
    pub addresses: Vec<InterfaceAddress>,
}

/// A composite entry in the `show protocols all` command. Represents
/// the details of a protocol instance.
#[derive(Debug)]
pub struct ShowProtocolDetailsMessage {
    pub protocol: Protocol,
    pub detail: Option<ProtocolDetail>,
}
