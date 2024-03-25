use std::io::{Read, Result, Write};

use crate::at_server_addr::AtServerAddr;

/// Represents a TLS connection to a server for sending and receiving data.
///
/// This trait is used to abstract the underlying TLS library used to connect to the server.
/// The super trait `Read` and `Write` are used to read and write data to the server.
pub trait TlsConnection: Read + Write {
    /// Creates a new TLS connection to the specified server address.
    fn connect(address: &AtServerAddr) -> Result<Self>
    where
        Self: Sized;
}
