use at_chops::AtChops;

use super::prelude::*;

pub struct PkamVerbInputs<'a> {
    /// The challenge text received from the server.
    pub challenge: &'a str,

    /// The AtChops instance to use for signing the challenge.
    pub at_chops: &'a AtChops,
}

impl<'a> PkamVerbInputs<'a> {
    pub fn new(challenge: &'a str, at_chops: &'a AtChops) -> Self {
        Self {
            challenge,
            at_chops,
        }
    }
}

/// The pkam verb follows the from verb.
/// As an owner of the atServer, you should be able to take the challenge thrown by the from verb and
/// encrypt using the private key of the RSA key pair with what the server has been bound with.
/// Upon receiving the cram verb along with the digest, the server decrypts the digest using the public key and matches it with the challenge.
/// If they are the same then the atServer lets you connect and changes the prompt to your atSign.
pub struct PkamVerb {}

impl<'a> Verb<'a> for PkamVerb {
    type Inputs = PkamVerbInputs<'a>;
    type Output = ();

    fn execute(tls_client: &mut TlsClient, input: Self::Inputs) -> Result<Self::Output> {
        info!("Signing challenge");

        let signed_challenge = input
            .at_chops
            .sign_challenge(input.challenge)
            .map_err(|e| AtError::UnknownAtClientException(e.to_string()))?;

        let data_to_send = format!("pkam:{}\n", signed_challenge);
        tls_client.send_data(data_to_send)?;

        let response_data = tls_client.read_data()?;
        let response_string = Self::parse_server_response(&response_data, "data")?;

        if response_string.contains("success") {
            Ok(())
        } else {
            Err(AtError::UnknownAtClientException(String::from(
                "Server did not respond with success message after pkam verb.",
            )))
        }
    }
}
