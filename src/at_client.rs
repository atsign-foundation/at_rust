use anyhow::Result;
use at_chops::{default_crypto_functions::DefaultCryptoFunctions, AtChops};
use at_secrets::AtSecrets;
use at_sign::AtSign;
use at_tls::{at_server_addr::AtServerAddr, rustls_connection::RustlsConnection, TlsClient};
use at_verbs::{
    from_verb::{FromVerb, FromVerbInputs},
    pkam_verb::{PkamVerb, PkamVerbInputs},
    verb_trait::Verb,
};
use log::{debug, info};

pub struct AtClient {
    tls_client: TlsClient,
    client_at_sign: AtSign,
    at_chops: AtChops,
}

impl AtClient {
    /// Initialises a new `AtClient` with the specified secrets and at_sign.
    ///
    /// This will lookup the address of the given at_sign's server then connect and authenticate with it.
    pub fn init(at_secrets: AtSecrets, at_sign: AtSign) -> Result<Self> {
        // TODO: Pass in the server address
        debug!("Initialising at_client");
        let at_sign_server_address = Self::get_server_addr_for_at_sign(&at_sign)?;
        debug!("Connecting to at_sign server");
        let mut tls_client = TlsClient::connect::<RustlsConnection>(&at_sign_server_address)?;
        debug!("Initialised at_sign server connection successfully");
        let crypto_service = Box::new(DefaultCryptoFunctions::new());
        debug!("Initialising at_chops");
        let at_chops = AtChops::new(
            crypto_service,
            &at_secrets.encoded_self_encryption_key,
            &at_secrets.encoded_and_encrypted_encrypt_private_key,
            &at_secrets.encoded_and_encrypted_pkam_private_key,
        )?;
        debug!("Initialised at_chops successfully");
        Self::authenticate_with_server(&mut tls_client, &at_chops, &at_sign)?;
        info!("Initialised at_client successfully");
        Ok(AtClient {
            tls_client,
            client_at_sign: at_sign,
            at_chops,
        })
    }

    /// Authenticates with the at_sign's server which requires an active tls connection.
    /// Also requires at_chops to be initialised and the at_sign.
    fn authenticate_with_server(
        tls_client: &mut TlsClient,
        at_chops: &AtChops,
        at_sign: &AtSign,
    ) -> Result<()> {
        let from_verb_args = FromVerbInputs::new(at_sign);
        let challenge = FromVerb::execute(tls_client, from_verb_args)?;
        let pkam_verb_args = PkamVerbInputs::new(&challenge, at_chops);
        PkamVerb::execute(tls_client, pkam_verb_args)?;
        Ok(())
    }

    fn get_server_addr_for_at_sign(at_sign: &AtSign) -> Result<AtServerAddr> {
        debug!("Getting {} server address", at_sign);
        let address = AtServerAddr::new(String::from("root.atsign.org"), 64);
        let mut client = TlsClient::connect::<RustlsConnection>(&address)?;
        client.send_data(at_sign.get_at_sign_without_prefix())?;
        let response = String::from_utf8(client.read_data()?)?;
        let addr = response[1..].to_string();
        debug!("Got {}'s server address: {}", at_sign, &addr);
        // Trimming to remove the newline character
        let addr = addr.trim().split(':').collect::<Vec<_>>();
        let host = addr[0].to_string();
        let port = addr[1].parse::<u16>()?;
        Ok(AtServerAddr::new(host, port))
    }
}
