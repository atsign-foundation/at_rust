//! A library for interacting with the atProtocol from a client device.
//!
//! This library is only a thin-wrapper around the atProtocol and does not provide any additional functionality.

pub mod at_chops;
pub mod at_client;
pub mod at_error;
pub mod at_secrets;
pub mod at_server_addr;
pub mod at_sign;
pub mod tls;
pub mod verbs;
