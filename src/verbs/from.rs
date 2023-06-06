use rsa::pkcs8::DecodePrivateKey;
use std::{format, println};

use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::sha2::{Digest, Sha256};
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use rsa::RsaPrivateKey;

use crate::utils::encoding::{construct_rsa_key, decode_base64_text, encode_base64_text};

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

        // Prepare data
        let (_, data) = res.split_at(6);

        // Construct key
        let decoded_priv_key = decode_base64_text(&input.priv_pkam);
        let rsa_key = construct_rsa_key(&decoded_priv_key);
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::<Sha256>::new(rsa_key);
        let verifying_key = signing_key.verifying_key();

        // Sign
        let signature = signing_key.sign_with_rng(&mut rng, &data.as_bytes());
        verifying_key
            .verify(&data.as_bytes(), &signature)
            .expect("failed to verify");
        let binding = signature.to_bytes();
        let signature_bytes = binding.as_ref();
        println!("signature bytes: {:?}", signature_bytes);

        // Encode signature
        let sha256_signature_encoded = encode_base64_text(&signature_bytes);
        println!("signature encoded: {:?}", sha256_signature_encoded);

        // Send signature
        tls_client.send(format!("pkam:{}\n", sha256_signature_encoded))?;
        let res = tls_client.read_line()?;
        // println!("res: {:?}", res);

        Ok(res)
    }
}
