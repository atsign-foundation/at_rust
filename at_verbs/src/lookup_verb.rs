use at_records::{
    at_key::AtKey,
    at_record::{AtRecord, AtValue},
    record_metadata::RecordMetadata,
};

use super::prelude::*;

pub struct LookupVerbInputs<'a> {
    /// The atId of the key-value pair to be looked up.
    at_id: &'a AtKey,

    /// The type of data to request from the server.
    return_type: LookupReturnType,
}

impl<'a> LookupVerbInputs<'a> {
    pub fn new(at_id: &'a AtKey, return_type: LookupReturnType) -> Self {
        Self { at_id, return_type }
    }
}

pub enum LookupReturnType {
    /// Just the data.
    Data,
    /// Just the metadata.
    Meta,
    /// Both the data and the metadata.
    All,
}

pub enum LookupVerbOutput {
    Data(AtValue),
    Meta(RecordMetadata),
    All(AtRecord),
}

/// The lookup verb should be used to fetch the value of the key shared by another atSign user.
/// If there is a public and user key with the same name then the result should be based on whether the user is trying to lookup is authenticated or not.
/// If the user is authenticated then the user key has to be returned, otherwise the public key has to be returned.
pub struct LookupVerb;

impl<'a> Verb<'a> for LookupVerb {
    type Inputs = LookupVerbInputs<'a>;
    type Output = LookupVerbOutput;

    fn execute(tls_client: &mut TlsClient, input: Self::Inputs) -> Result<Self::Output> {
        let mut string_buf = String::from("lookup:");
        match input.return_type {
            LookupReturnType::Data => {}
            LookupReturnType::Meta => string_buf.push_str("meta:"),
            LookupReturnType::All => string_buf.push_str("all:"),
        }

        string_buf.push_str(&input.at_id.to_string());
        // TODO: Might need to push a newline here.

        tls_client.send_data(string_buf)?;

        let response_data = tls_client.read_data()?;
        let response_string = Self::parse_server_response(&response_data, "data")?;

        // TODO: Parse the response_string into the appropriate type.

        todo!();
    }
}
