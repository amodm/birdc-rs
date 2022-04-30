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
//! async fn show_interfaces(client: &Client) -> Result<()> {
//!     let mut connection = client.connect().await?;
//!
//!     // let's make a semantic call now
//!     match connection.show_interfaces().await {
//!         Ok(entries) => {
//!             for e in &entries {
//!                 println!("received entry: {:?}", e);
//!             }
//!         }
//!         Err(Error::ParseError(messages)) => {
//!             // we can still go through the raw response
//!             // even though semantic parsing failed
//!             for msg in &messages {
//!                 println!("raw message: {:?}", msg);
//!             }
//!         }
//!         Err(e) => {
//!             return Err(e);
//!         }
//!     }
//!     Ok(())
//! }
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

mod models;
pub use models::*;
