use der::Encode;
use std::{format, println};

use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey};

use crate::utils::encoding::decode_base64_text;

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
        tls_client.send(format!("from:{}\n", input.at_sign.get_at_sign()))?;
        let res = tls_client.read_line()?;
        println!("res: {:?}", res);
        let decoded_priv_key = decode_base64_text(&input.priv_pkam);
        let rsa_key = RsaPrivateKey::from_pkcs8_der(&decoded_priv_key)
            .expect("Unable to create RSA Private Key");
        println!("rsa_key: {:?}", rsa_key);
        Ok(res)
    }
}
