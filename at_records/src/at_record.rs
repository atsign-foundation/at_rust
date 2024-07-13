#![allow(unused_variables)]
#![allow(dead_code)]

use at_chops::AtChops;

use crate::{at_key::AtKey, record_metadata::RecordMetadata};

//? There should probably be a way to build these records (e.g. builder method) which provides sane defaults

/// atRecords are the data records that are stored by the atServers. We use the common key-value pair format.
/// By this, we mean non-cryptographic key, so we instead call them "identifier-value pairs" to prevent confusion.
#[derive(Debug)]
pub struct AtRecord {
    at_id: AtKey,
    value: AtValue,
    metadata: RecordMetadata,
}

impl AtRecord {
    pub fn new(at_id: AtKey, value: AtValue, metadata: RecordMetadata) -> Self {
        Self {
            at_id,
            value,
            metadata,
        }
    }

    // pub fn builder() -> AtRecordBuilder {
    //     AtRecordBuilder::new()
    // }
}

/// The data that can be stored in an atRecord.
#[derive(Debug)]
pub enum AtValue {
    Text(String),
    Binary(Vec<u8>),
}

impl AtValue {
    /// Create a new AtValue from a base64 encoded and encrypted string.
    // Should probably only pass in functions instead of the whole AtChops
    pub fn from_server(encoded_encrypted_data: &str, at_chops: &AtChops) -> Self {
        todo!()
    }
}
