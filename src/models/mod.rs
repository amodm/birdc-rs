//! All structured models of the Bird client protocol

mod interface;
pub use interface::*;

/// A composite entry in the `show interfaces` command
#[derive(Debug)]
pub struct ShowInterfacesMessage {
    pub interface: Interface,
    pub properties: InterfaceProperties,
    pub addresses: Vec<InterfaceAddress>,
}
