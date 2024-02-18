use at_records::at_id::AtId;
use serde::Deserialize;

use super::prelude::*;

pub struct ScanVerbInputs {
    pub show_hidden: bool,
    pub regex: Option<String>,
}

impl ScanVerbInputs {
    pub fn new(show_hidden: bool, regex: Option<String>) -> Self {
        Self { show_hidden, regex }
    }
}

#[derive(Debug, Deserialize)]
struct AtIdListJson(Vec<String>);

/// The scan verb is used to see the AtId's (old: keys) in an atSign’s atServer.
pub struct ScanVerb;

impl<'a> Verb<'a> for ScanVerb {
    type Inputs = ScanVerbInputs;
    type Output = Vec<AtId>;

    fn execute(tls_client: &mut TlsClient, input: Self::Inputs) -> Result<Self::Output> {
        let mut string_buf = String::from("scan");
        if input.show_hidden {
            string_buf.push_str(":showhidden:true");
        }
        if let Some(regex) = input.regex {
            string_buf.push_str(&format!(" {}", regex));
        }
        tls_client.send_data(string_buf)?;
        let response_data = tls_client.read_data()?;
        let response_string = Self::parse_server_response(&response_data, "data")?;
        // Example response: ["at_id_1", "at_id_2", "at_id_3"]
        let at_ids_json: AtIdListJson = serde_json::from_str(&response_string)
            .map_err(|e| AtError::UnknownAtClientException(e.to_string()))?;
        let at_ids: Vec<AtId> = at_ids_json.0.iter().map(|at_id| AtId::new(at_id)).collect();
        Ok(at_ids)
    }
}
