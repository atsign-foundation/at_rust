use at_records::{
    at_key::AtKey,
    at_record::{AtRecord, AtValue},
    record_metadata::RecordMetadata,
};

use super::prelude::*;

pub struct LookupVerbInputs<'a> {
    /// The atId of the key-value pair to be looked up.
    at_key: &'a AtKey,

    /// The type of data to request from the server.
    return_type: LookupReturnType,
}

impl<'a> LookupVerbInputs<'a> {
    pub fn new(at_key: &'a AtKey, return_type: LookupReturnType) -> Self {
        Self {
            at_key,
            return_type,
        }
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

#[derive(Debug)]
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

        let formatted_at_key = format!(
            "{}.{}{}",
            &input.at_key.record_id,
            input.at_key.namespace.as_ref().unwrap_or(&String::from("")),
            &input.at_key.owner.get_at_sign_with_prefix()
        );
        string_buf.push_str(formatted_at_key.as_str());

        tls_client.send_data(string_buf)?;

        let response_data = tls_client.read_data()?;
        let response_string = Self::parse_server_response(&response_data, "data")?;

        // TODO: Parse the response_string into the appropriate type.
        match input.return_type {
            LookupReturnType::Data => Ok(LookupVerbOutput::Data(AtValue::Text(response_string))),
            LookupReturnType::Meta => todo!(),
            LookupReturnType::All => todo!(),
        }
    }
}
