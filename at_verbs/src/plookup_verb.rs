use at_records::{
    at_key::AtKey,
    at_record::{AtRecord, AtValue},
    record_metadata::RecordMetadata,
};

use super::prelude::*;

pub struct PlookupVerbInputs<'a> {
    /// The AtKey of the key-value pair to be looked up.
    at_key: &'a AtKey,

    /// The type of data to request from the server.
    return_type: PlookupReturnType,
}

impl<'a> PlookupVerbInputs<'a> {
    pub fn new(at_key: &'a AtKey, return_type: PlookupReturnType) -> Self {
        Self {
            at_key,
            return_type,
        }
    }
}

pub enum PlookupReturnType {
    /// Just the data.
    Data,
    /// Just the metadata.
    Meta,
    /// Both the data and the metadata.
    All,
}

#[derive(Debug)]
pub enum PlookupVerbOutput {
    Data(AtValue),
    Meta(RecordMetadata),
    All(AtRecord),
}

/// The plookup verb should be used to fetch the value of the public key shared by another atSign user.
pub struct PlookupVerb;

impl<'a> Verb<'a> for PlookupVerb {
    type Inputs = PlookupVerbInputs<'a>;
    type Output = PlookupVerbOutput;

    fn execute(tls_client: &mut TlsClient, input: Self::Inputs) -> Result<Self::Output> {
        // TODO: Implement bypassCache

        let mut string_buf = String::from("lookup:");
        match input.return_type {
            PlookupReturnType::Data => {}
            PlookupReturnType::Meta => string_buf.push_str("meta:"),
            PlookupReturnType::All => string_buf.push_str("all:"),
        }

        let formatted_at_key = format!(
            "{record_id}.{namespace}{owner}",
            record_id = &input.at_key.record_id,
            namespace = input.at_key.namespace.as_ref().unwrap_or(&String::from("")),
            owner = &input.at_key.owner.get_at_sign_with_prefix()
        );
        string_buf.push_str(formatted_at_key.as_str());

        tls_client.send_data(string_buf)?;

        let response_data = tls_client.read_data()?;
        let response_string = Self::parse_server_response(&response_data, "data")?;

        // TODO: Parse the response_string into the appropriate type.
        match input.return_type {
            PlookupReturnType::Data => Ok(PlookupVerbOutput::Data(AtValue::Text(response_string))),
            PlookupReturnType::Meta => todo!(),
            PlookupReturnType::All => todo!(),
        }
    }
}
