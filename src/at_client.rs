use log::info;

use crate::at_chops::chops::{
    create_new_shared_symmetric_key, decrypt_data_with_shared_symmetric_key, decrypt_symmetric_key,
    encrypt_data_with_public_key, encrypt_data_with_shared_symmetric_key,
};
use crate::at_error::{AtError, Result};
use crate::at_secrets::AtSecrets;
use crate::at_server_addr::AtServerAddr;
use crate::at_sign::AtSign;
use crate::tls::tls_client::{ReadWrite, TlsClient};
use crate::verbs::llookup::{LlookupVerb, LlookupVerbInputs};
use crate::verbs::lookup::{LookupVerb, LookupVerbInputs};
use crate::verbs::plookup::{PlookupVerb, PlookupVerbInputs};
use crate::verbs::update::{UpdateVerb, UpdateVerbInputs};
use crate::verbs::{from::FromVerb, from::FromVerbInputs, Verb};

pub struct AtClient {
    secrets: AtSecrets,
    at_sign: AtSign,
    tls_client: TlsClient,
    namespace: String,
}

impl AtClient {
    pub fn init(
        secrets: AtSecrets,
        at_sign: AtSign,
        connect: &dyn Fn(&AtServerAddr) -> Box<dyn ReadWrite>,
        namespace: &str,
    ) -> Result<AtClient> {
        let server = get_at_sign_server_addr(&at_sign.get_at_sign(), connect)?;
        let tls_client = TlsClient::new(&|| connect(&server))?;
        Ok(AtClient {
            secrets,
            at_sign,
            tls_client,
            namespace: namespace.to_string(),
        })
    }

    pub fn send_data(&mut self, data: &str, receiver: AtSign, record_id: &str) -> Result<()> {
        self.authenticate_with_at_server()?;
        let response = LlookupVerb::execute(
            &mut self.tls_client,
            LlookupVerbInputs::new(
                &self.at_sign,
                &receiver,
                "shared_key",
                &self.secrets.encrypt_public_key,
            ),
        )?;
        let symm_key: String;
        if response.contains("error:AT0015-key not found") {
            info!("Creating new symmetric key");
            // Create symm key
            let new_key = create_new_shared_symmetric_key();
            symm_key = new_key.clone();
            // Save for our use
            let encrypted_encoded_sym_key =
                encrypt_data_with_public_key(&self.secrets.encrypt_public_key, &new_key);
            UpdateVerb::execute(
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
            info!(
                "Encrypted symm key: {}",
                symm_key_encrypted_with_recipient_public_key
            );
            // Send data
            UpdateVerb::execute(
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
            info!("Already have a copy of the key");
            // Decrypt symm key
            let encrypted_symmetric_key = response.split(':').collect::<Vec<_>>()[1];
            symm_key =
                decrypt_symmetric_key(encrypted_symmetric_key, &self.secrets.encrypt_private_key);
            info!("Decrypted symmetric key: {}", symm_key);
        } else {
            return Err(AtError::new(String::from("Unknown response from server")));
        }
        // Send data encrypted with symm key
        let encrypted_data_to_send = encrypt_data_with_shared_symmetric_key(&symm_key, data);
        let _ = UpdateVerb::execute(
            &mut self.tls_client,
            UpdateVerbInputs::new(
                &self.at_sign,
                // TODO: Pass this in as an option somewhere
                record_id,
                &encrypted_data_to_send,
                Some(&self.namespace),
                None,
                Some(&receiver),
            ),
        );
        Ok(())
    }

    pub fn read_data(&mut self, from: AtSign, record_id: &str) -> Result<()> {
        self.authenticate_with_at_server()?;
        info!("Fetching data");
        // Fetch data
        let response = LookupVerb::execute(
            &mut self.tls_client,
            LookupVerbInputs::new(&from, record_id, Some(&self.namespace)),
        )?;
        let encrypted_and_encoded_data = response.split(':').collect::<Vec<_>>()[1];
        info!("Fetching symmetric key");
        // Fetch symm key
        let response = LookupVerb::execute(
            &mut self.tls_client,
            LookupVerbInputs::new(&from, "shared_key", None),
        )?;
        info!("Decrypting symmetric key");
        let encrypted_and_encoded_symm_key = response.split(':').collect::<Vec<_>>()[1];
        let symm_key = decrypt_symmetric_key(
            encrypted_and_encoded_symm_key,
            &self.secrets.encrypt_private_key,
        );
        info!("Decrypted symmetric key: {}", symm_key);
        info!("Decrypting data");
        let encoded_data =
            decrypt_data_with_shared_symmetric_key(&symm_key, encrypted_and_encoded_data);
        info!("Decrypted data: {}", encoded_data);

        Ok(())
    }

    fn authenticate_with_at_server(&mut self) -> Result<()> {
        let _ = FromVerb::execute(
            &mut self.tls_client,
            FromVerbInputs::new(&self.at_sign, &self.secrets.pkam_private_key),
        )
        .expect("Failed to authenticate with at server");
        info!("Successfully authenticated with at server");
        Ok(())
    }
}

/// function to get the at sign server address
fn get_at_sign_server_addr(
    at_sign: &str,
    connect: &dyn Fn(&AtServerAddr) -> Box<dyn ReadWrite>,
) -> Result<AtServerAddr> {
    info!("Getting at sign server address");

    let at_server_addr = AtServerAddr::new(String::from("root.atsign.org"), 64);
    let mut tls_client = TlsClient::new(&|| connect(&at_server_addr))?;
    tls_client.send(format!("{}\n", at_sign))?;
    let res = tls_client.read_line()?;

    if res == "@null" {
        return Err(AtError::new(String::from("Unable to find at sign")));
    }

    // Removing the first letter from the response as it contains "@"
    let addr = res[1..].to_string();
    info!("At server address: {}", &addr);

    // Trimming to remove the newline character
    let addr = addr.trim();
    let addr = addr.split(':').collect::<Vec<_>>();
    let host = addr[0].to_string();
    let port = addr[1]
        .parse::<u16>()
        .expect("Unable to parse port to a u16");
    Ok(AtServerAddr::new(host, port))
}
