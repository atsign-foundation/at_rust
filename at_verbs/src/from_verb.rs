use at_sign::AtSign;

use super::prelude::*;

pub struct FromVerbInputs<'a> {
    /// The atSign of the client device.
    pub at_sign: &'a AtSign,
}

impl<'a> FromVerbInputs<'a> {
    pub fn new(at_sign: &'a AtSign) -> Self {
        Self { at_sign }
    }
}

/// The from verb is used to tell the atServer what atSign you claim to be.
/// With the from verb, one can connect to one’s own atServer or someone else’s atServer.
/// In both cases, the atServer responds back with a challenge to prove that you are who you claim to be.
/// This is part of the authentication mechanism of the atProtocol.
/// This authentication mechanism varies based on whether you are connecting to your own atServer (cram/pkam) or someone else’s atServer (pol).
pub struct FromVerb {}

impl<'a> Verb<'a> for FromVerb {
    type Inputs = FromVerbInputs<'a>;
    type Output = String;

    fn execute(tls_client: &mut TlsClient, input: Self::Inputs) -> Result<Self::Output> {
        info!("Starting PKAM authentication");
        // AtSign can be with or without the "@"
        let data_to_send = format!("from:{}\n", input.at_sign.get_at_sign());
        tls_client.send_data(data_to_send)?;
        let response_data = tls_client.read_data()?;
        let response_string = Self::parse_server_response(&response_data, "pkam")?;
        info!("Challenge: {}", response_string);
        Ok(response_string.to_owned())
    }
}
