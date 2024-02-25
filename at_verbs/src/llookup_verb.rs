use at_records::{
    at_key::AtKey,
    at_record::{AtRecord, AtValue},
    record_metadata::RecordMetadata,
};

use super::prelude::*;

pub struct LlookupVerbInputs<'a> {
    /// The AtKey of the key-value pair to be looked up.
    at_key: &'a AtKey,

    /// The type of data to request from the server.
    return_type: LlookupReturnType,
}

impl<'a> LlookupVerbInputs<'a> {
    pub fn new(at_key: &'a AtKey, return_type: LlookupReturnType) -> Self {
        Self {
            at_key,
            return_type,
        }
    }
}

pub enum LlookupReturnType {
    /// Just the data.
    Data,
    /// Just the metadata.
    Meta,
    /// Both the data and the metadata.
    All,
}

#[derive(Debug)]
pub enum LlookupVerbOutput {
    Data(AtValue),
    Meta(RecordMetadata),
    All(AtRecord),
}

/// The llookup verb should be used to fetch the value of the key in the owners atServer store as is without resolving it.
/// For example if a key contains a reference as a value, the lookup verb should resolve it to a value whereas llookup should return the value as is.
pub struct LlookupVerb;

impl<'a> Verb<'a> for LlookupVerb {
    type Inputs = LlookupVerbInputs<'a>;
    type Output = LlookupVerbOutput;

    fn execute(tls_client: &mut TlsClient, input: Self::Inputs) -> Result<Self::Output> {
        let mut string_buf = String::from("lookup:");
        match input.return_type {
            LlookupReturnType::Data => {}
            LlookupReturnType::Meta => string_buf.push_str("meta:"),
            LlookupReturnType::All => string_buf.push_str("all:"),
        }

        let is_cached = if input.at_key.is_cached {
            "cached:"
        } else {
            ""
        };

        // Private and internal are not supported
        let visibility = match &input.at_key.visibility_scope {
            at_records::at_key::Visibility::Private => String::from(""),
            at_records::at_key::Visibility::Internal => String::from(""),
            at_records::at_key::Visibility::Public => String::from("public:"),
            at_records::at_key::Visibility::Shared(shared_with) => {
                format!("{}:", shared_with.get_at_sign_with_prefix())
            }
        };

        let formatted_at_key = format!(
            "{is_cached}{visibility}{record_id}.{namespace}{owner}",
            is_cached = &is_cached,
            visibility = visibility,
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
            LlookupReturnType::Data => Ok(LlookupVerbOutput::Data(AtValue::Text(response_string))),
            LlookupReturnType::Meta => todo!(),
            LlookupReturnType::All => todo!(),
        }
    }
}
