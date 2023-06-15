use crate::at_chops::at_chops::{
    create_new_shared_symmetric_key, decrypt_data_with_shared_symmetric_key, decrypt_symmetric_key,
    decrypt_symmetric_key_2, encrypt_data_with_public_key, encrypt_data_with_shared_symmetric_key,
};
use crate::at_error::{AtError, Result};
use crate::at_secrets::AtSecrets;
use crate::at_server_addr::AtServerAddr;
use crate::at_sign::AtSign;
use crate::at_tls_client::TLSClient;
use crate::verbs::llookup::{LlookupVerb, LlookupVerbInputs};
use crate::verbs::lookup::{LookupVerb, LookupVerbInputs};
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
        let symm_key: String;
        if response.contains("error:AT0015-key not found") {
            println!("Creating new symmetric key");
            // Create symm key
            let new_key = create_new_shared_symmetric_key();
            symm_key = new_key.clone();
            // Save for our use
            let encrypted_encoded_sym_key =
                encrypt_data_with_public_key(&self.secrets.aes_encrypt_public_key, &new_key);
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
            let encrypted_symmetric_key = response.split(":").collect::<Vec<_>>()[1];
            symm_key = decrypt_symmetric_key(
                &encrypted_symmetric_key,
                &self.secrets.aes_encrypt_private_key,
            );
            println!("Decrypted symmetric key: {}", symm_key);
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
                "data_doug",
                &encrypted_data_to_send,
                Some("doug"),
                None,
                Some(&receiver),
            ),
        );
        Ok(())
    }

    pub fn read_data(&mut self, from: AtSign) -> Result<()> {
        self.authenticate_with_at_server()?;
        // Fetch data
        let response = LookupVerb::execute(
            &mut self.tls_client,
            LookupVerbInputs::new(&from, "data_doug", Some("doug")),
        )?;
        let encrypted_and_encoded_data = response.split(":").collect::<Vec<_>>()[1];
        // Fetch symm key
        let response = LookupVerb::execute(
            &mut self.tls_client,
            LookupVerbInputs::new(&from, "shared_key", None),
        )?;
        let encrypted_and_encoded_symm_key = response.split(":").collect::<Vec<_>>()[1];
        let symm_key = decrypt_symmetric_key_2(
            &encrypted_and_encoded_symm_key,
            &self.secrets.aes_encrypt_private_key,
        );
        println!("Decrypted symmetric key: {}", symm_key);
        let encoded_data =
            decrypt_data_with_shared_symmetric_key(&symm_key, &encrypted_and_encoded_data);
        println!("Decrypted data: {}", encoded_data);

        Ok(())
    }

    fn authenticate_with_at_server(&mut self) -> Result<()> {
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
