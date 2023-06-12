use crate::at_chops::at_chops::{
    create_new_shared_symmetric_key, encrypt_data_with_public_key, encrypt_symmetric_key,
};
use crate::at_error::{AtError, Result};
use crate::at_secrets::AtSecrets;
use crate::at_server_addr::AtServerAddr;
use crate::at_sign::AtSign;
use crate::at_tls_client::TLSClient;
use crate::verbs::llookup::{LlookupVerb, LlookupVerbInputs};
use crate::verbs::plookup::{PlookupVerb, PlookupVerbInputs};
use crate::verbs::update::{UpdateVerb, UpdateVerbInputs};
use crate::verbs::{from::FromVerb, from::FromVerbInputs, Verb};

pub struct AtClient {
    secrets: AtSecrets,
    at_sign: AtSign,
    tls_client: TLSClient,
}

impl AtClient {
    pub fn init(secrets: AtSecrets, at_sign: AtSign) -> Result<AtClient> {
        let server = get_at_sign_server_addr(&at_sign.get_at_sign())?;
        let tls_client = match TLSClient::new(&server) {
            Ok(res) => res,
            Err(err) => return Err(AtError::new(err.to_string())),
        };
        Ok(AtClient {
            secrets,
            at_sign,
            tls_client,
        })
    }

    pub fn send_data(&mut self, data: &str, receiver: AtSign) -> Result<()> {
        self.authenticate_with_at_server()?;
        let response = LlookupVerb::execute(
            &mut self.tls_client,
            LlookupVerbInputs::new(
                &self.at_sign,
                &receiver,
                "shared_key",
                &self.secrets.aes_encrypt_public_key,
            ),
        )?;
        if response.contains("error:AT0015-key not found") {
            println!("Creating new symmetric key");
            // Create symm key
            let new_key = create_new_shared_symmetric_key();
            let encrypted_encoded_sym_key =
                encrypt_symmetric_key(&new_key, &self.secrets.aes_encrypt_public_key);
            // Save for our use
            let _ = UpdateVerb::execute(
                &mut self.tls_client,
                UpdateVerbInputs::new(
                    &self.at_sign,
                    "shared_key",
                    &encrypted_encoded_sym_key,
                    Some(&receiver.get_at_sign()),
                    None,
                    None,
                ),
            )?;
            // and share with recipient
            let recipient_public_key_encoded = PlookupVerb::execute(
                &mut self.tls_client,
                PlookupVerbInputs::new(&receiver, "publickey"),
            )?;
            let symm_key_encrypted_with_recipient_public_key =
                encrypt_data_with_public_key(&recipient_public_key_encoded, &new_key);
            println!(
                "Encrypted symm key: {}",
                symm_key_encrypted_with_recipient_public_key
            );
            // Send data
            let _ = UpdateVerb::execute(
                &mut self.tls_client,
                UpdateVerbInputs::new(
                    &self.at_sign,
                    "shared_key",
                    &symm_key_encrypted_with_recipient_public_key,
                    None,
                    Some(86400),
                    Some(&receiver),
                ),
            )?;
        } else if response.contains("data") {
            println!("Already have a copy of the key");
            // Decrypt symm key
        } else {
            return Err(AtError::new(String::from("Unknown response from server")));
        }
        Ok(())
    }

    pub fn authenticate_with_at_server(&mut self) -> Result<()> {
        let _ = FromVerb::execute(
            &mut self.tls_client,
            FromVerbInputs::new(&self.at_sign, &self.secrets.aes_pkam_private_key),
        )
        .expect("Failed to authenticate with at server");
        println!("Successfully authenticated with at server");
        Ok(())
    }
}

/// function to get the at sign server address
fn get_at_sign_server_addr(at_sign: &str) -> Result<AtServerAddr> {
    println!("Getting at sign server address");

    let at_server_addr = AtServerAddr::new(String::from("root.atsign.org"), 64);
    let mut tls_client = match TLSClient::new(&at_server_addr) {
        Ok(res) => res,
        Err(_) => return Err(AtError::new(String::from("Unable to connect to at server"))),
    };

    tls_client.send(format!("{}\n", at_sign))?;
    let res = tls_client.read_line()?;
    tls_client.close()?;

    if res == "@null" {
        return Err(AtError::new(String::from("Unable to find at sign")));
    }

    // Removing the first letter from the response as it contains "@"
    let addr = res[1..].to_string();
    println!("At server address: {}", &addr);

    // Trimming to remove the newline character
    let addr = addr.trim();
    let addr = addr.split(":").collect::<Vec<_>>();
    let host = addr[0].to_string();
    let port = addr[1]
        .parse::<u16>()
        .expect("Unable to parse port to a u16");
    Ok(AtServerAddr::new(host, port))
}

// NOTE: Maybe each verb should know how to encode/decode/format itself?
// This could be good because each verb is likely to expect a different format.
// It would be the responsibility of the TLSClient to send and receive information but really do
// anything with it. Maybe just trim and turn into a String?
// Internal requirements:
// - Get the at sign server address
// - Connect to the at sign server
// - Authenticate with at sign
// External requirements:
// - Get data
// - Delete data
// - Update data
