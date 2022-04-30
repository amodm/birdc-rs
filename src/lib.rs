//! Library for async communication with the Bird BGP server.
//!
//! ## Examples
//! ```no_run
//! use birdc::*;
//!
//! // create the client
//! let client = Client::for_unix_socket("/run/bird/bird.ctl");
//!
//! // we can either use raw protocol
//! async fn show_interfaces_raw(client: &Client) -> Result<()> {
//!     let mut connection = client.connect().await?;
//!
//!     // we can either use raw protocol
//!     let messages = connection.send_request("show interfaces").await?;
//!     for message in &messages {
//!         println!("received message: {:?}", message);
//!     }
//!     Ok(())
//! }
//!
//! // or we can use structured exchange
//! todo!("to be done");
//! ```
//!
//! ## Compatibility
//! This library has been tested only against Bird2

mod client;
pub use client::*;

mod connection;
pub use connection::*;

mod error;
pub use error::*;

mod message;
pub use message::*;
