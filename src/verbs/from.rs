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

    fn execute(tls_client: &mut TLSClient, input: Self::Inputs) -> Result<Self::Result> {
        println!("Starting PKAM authentication");
        tls_client.send(format!("from:{}\n", input.at_sign.get_at_sign()))?;
        let response = tls_client.read_line()?;
        println!("challenge response: {:?}", response);

        let (_, data) = response.split_at(6);

        let signed_challenge = sign_challenge(&data, input.priv_pkam);

        println!("Sending signed challenge: {}", signed_challenge);

        tls_client.send(format!("pkam:{}\n", signed_challenge))?;
        let response = tls_client.read_line()?;

        println!("response: {}", response);

        Ok(response)
    }
}
