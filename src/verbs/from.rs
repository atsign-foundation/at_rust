use log::info;

use crate::at_chops::at_chops::sign_challenge;

use super::{prelude::*, Verb};

pub struct FromVerbInputs<'a> {
    pub at_sign: &'a AtSign,
    pub priv_pkam: &'a str,
}

impl<'a> FromVerbInputs<'a> {
    pub fn new(at_sign: &'a AtSign, priv_pkam: &'a str) -> Self {
        Self { at_sign, priv_pkam }
    }
}

pub struct FromVerb {}

impl<'a> Verb<'a> for FromVerb {
    type Inputs = FromVerbInputs<'a>;
    type Result = String;

    fn execute(tls_client: &mut TlsClient, input: Self::Inputs) -> Result<Self::Result> {
        info!("Starting PKAM authentication");
        tls_client.send(format!("from:{}\n", input.at_sign.get_at_sign()))?;
        let response = tls_client.read_line()?;

        let (_, data) = response.split_at(6);
        info!("Challenge: {}", data);

        let signed_challenge = sign_challenge(&data, input.priv_pkam);

        tls_client.send(format!("pkam:{}\n", signed_challenge))?;
        let response = tls_client.read_line()?;

        Ok(response)
    }
}
