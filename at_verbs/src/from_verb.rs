use at_chops::AtChops;
use at_sign::AtSign;

use super::prelude::*;

pub struct FromVerbInputs<'a> {
    pub at_sign: &'a AtSign,
    pub at_chops: &'a AtChops,
}

impl<'a> FromVerbInputs<'a> {
    pub fn new(at_sign: &'a AtSign, at_chops: &'a AtChops) -> Self {
        Self { at_sign, at_chops }
    }
}

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
        let response_string = Self::parse_server_response(&response_data)?;

        let (_, data) = response_string.split_at(6);
        info!("Challenge: {}", data);

        // let signed_challenge = sign_challenge(data, input.priv_pkam);

        // tls_client.send(format!("pkam:{}\n", signed_challenge))?;
        // let response = tls_client.read_line()?;

        // Ok(response)
        Ok(String::from("test"))
    }
}
