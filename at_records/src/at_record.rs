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
