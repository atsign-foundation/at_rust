use anyhow::Result;
use at_chops::{default_crypto_functions::DefaultCryptoFunctions, AtChops};
use at_errors::AtError;
use at_records::{
    at_key::{AtKey, Visibility},
    at_record::{AtRecord, AtValue},
    record_metadata::RecordMetadata,
};
use at_secrets::AtSecrets;
use at_sign::AtSign;
use at_tls::{at_server_addr::AtServerAddr, rustls_connection::RustlsConnection, TlsClient};
use at_verbs::{
    from_verb::{FromVerb, FromVerbInputs},
    llookup_verb::{LlookupReturnType, LlookupVerb, LlookupVerbInputs, LlookupVerbOutput},
    lookup_verb::{LookupReturnType, LookupVerb, LookupVerbInputs, LookupVerbOutput},
    pkam_verb::{PkamVerb, PkamVerbInputs},
    plookup_verb::{PlookupReturnType, PlookupVerb, PlookupVerbInputs, PlookupVerbOutput},
    scan_verb::{ScanVerb, ScanVerbInputs},
    update_verb::{UpdateOptions, UpdateVerb, UpdateVerbInputs},
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

    /// Connects to the atsign "DNS" server to get the server address of the given at_sign.
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

    /// Execute the scan verb to fetch all at_ids.
    pub fn scan(&mut self, show_hidden: bool) -> Result<Vec<AtKey>> {
        debug!("Fetching all at_ids");
        let scan_verb_args = ScanVerbInputs::new(show_hidden, None, None);
        let scan_results = ScanVerb::execute(&mut self.tls_client, scan_verb_args)?;
        debug!("Fetched at_ids successfully: {:?}", scan_results);
        Ok(scan_results)
    }

    // TODO: Create a private method for each verb and then create a public method that abstracts away the complexity of which verb is suitable for the given AtKey.

    /// Lookup the value of the given at_key.
    fn lookup(
        &mut self,
        at_key: &AtKey,
        return_type: LookupReturnType,
    ) -> Result<LookupVerbOutput> {
        debug!("Looking up at_key");
        let lookup_verb_args = LookupVerbInputs::new(at_key, return_type);
        let lookup_result = LookupVerb::execute(&mut self.tls_client, lookup_verb_args)?;
        debug!("Lookup ran successfully: {:?}", lookup_result);
        Ok(lookup_result)
    }

    /// Get the data for the given AtKey.
    pub fn get_record(
        &mut self,
        request_type: GetRequestType,
        at_key: &AtKey,
    ) -> Result<GetResponseType> {
        match &at_key.visibility_scope {
            Visibility::Public => todo!(),
            Visibility::Private => todo!(),
            Visibility::Internal => todo!(),
            Visibility::Shared(_) => {
                // This is symmetric key that is created by the client and shared with server.
                // Unlike most at_keys, the client is not the owner of this key.
                let symm_key_at_key = AtKey {
                    record_id: String::from("shared_key"),
                    namespace: None,
                    is_cached: false,
                    owner: at_key.owner.clone(),
                    visibility_scope: Visibility::Shared(self.client_at_sign.clone()),
                };
                debug!("Created at_key for getting shared_key: {}", symm_key_at_key);

                let symm_key_lookup_result =
                    match self.lookup(&symm_key_at_key, LookupReturnType::Data)? {
                        LookupVerbOutput::Data(data) => data,
                        LookupVerbOutput::Metadata(_) => todo!(),
                        LookupVerbOutput::All(_) => todo!(),
                    };
                let data_lookup_result = self.lookup(at_key, request_type.into())?;
                match data_lookup_result {
                    LookupVerbOutput::Data(data) => {
                        let decrypted_symm_key = self
                            .at_chops
                            .decrypt_symmetric_key(&symm_key_lookup_result)?;
                        let data = self
                            .at_chops
                            .decrypt_data_with_shared_symmetric_key(&decrypted_symm_key, &data)?;
                        Ok(GetResponseType::Data(AtValue::Text(
                            data.trim().to_string(),
                        )))
                    }
                    LookupVerbOutput::Metadata(_) => todo!(),
                    LookupVerbOutput::All(_) => todo!(),
                }
            }
        }
    }

    /// Put or update the data for the given AtKey.
    pub fn put_record(&mut self, at_key: &AtKey, data: &AtValue) -> Result<String> {
        // 1. See if the we have already shared our symmetric key with the recipient of the data.
        let symm_key_at_key = AtKey::new_private_key(
            String::from("shared_key"),
            match &at_key.visibility_scope {
                Visibility::Shared(shared_with) => Some(shared_with.get_at_sign_without_prefix()),
                _ => panic!("This should not happen"),
            },
            at_key.owner.clone(),
        );

        debug!(
            "Created at_key for fetching potentially already created symm key: {}",
            symm_key_at_key
        );

        let llookup_verb_args = LlookupVerbInputs::new(&symm_key_at_key, LlookupReturnType::Data);
        let llokup_verb_result = LlookupVerb::execute(&mut self.tls_client, llookup_verb_args);

        match llokup_verb_result {
            Err(AtError::KeyNotFound) => {
                info!("No shared key found. Creating a new one.");
                // 2. If we have not shared the symmetric key, then we need to create it
                let new_symm_key = self.at_chops.create_new_shared_symmetric_key()?;
                // 3. If we have just created a new symmetric key, we should encrypt with "our" public key and save it for use later
                info!("Encrypting and saving the new shared key.");
                let encrypted_new_symm_key = self
                    .at_chops
                    .encrypt_data_with_our_public_key(&new_symm_key)?;
                let encrypted_new_symm_key_value = AtValue::Text(encrypted_new_symm_key);
                let update_verb_args =
                    UpdateVerbInputs::new(&symm_key_at_key, &encrypted_new_symm_key_value);
                let _ = UpdateVerb::execute(&mut self.tls_client, update_verb_args)?;
                // 4. If we have just created a new symmetric key, we should encrypt with "their" public key and send it to them
                info!("Looking up recipient's public key.");
                let public_key_at_key = AtKey {
                    record_id: String::from("publickey"),
                    namespace: None,
                    is_cached: false,
                    owner: match &at_key.visibility_scope {
                        Visibility::Shared(shared_with) => shared_with.clone(),
                        _ => panic!("This should not happen."),
                    },
                    visibility_scope: Visibility::Public,
                };
                let plookup_verb_args =
                    PlookupVerbInputs::new(&public_key_at_key, PlookupReturnType::Data);
                let plookup_verb_result =
                    PlookupVerb::execute(&mut self.tls_client, plookup_verb_args)?;
                info!("Encrypting and sending the new shared key.");
                let their_public_key = match plookup_verb_result {
                    PlookupVerbOutput::Data(data) => match data {
                        AtValue::Text(text) => text,
                        _ => panic!("This should not happen."),
                    },
                    PlookupVerbOutput::Meta(_) => panic!("This should not happen."),
                    PlookupVerbOutput::All(_) => panic!("This should not happen."),
                };
                let encrypted_new_symm_key = self
                    .at_chops
                    .encrypt_data_with_public_key(&their_public_key, &new_symm_key)?;
                let encrypted_new_symm_key_value = AtValue::Text(encrypted_new_symm_key);
                let shared_key_at_key = AtKey {
                    record_id: String::from("shared_key"),
                    namespace: None,
                    is_cached: false,
                    owner: at_key.owner.clone(),
                    visibility_scope: Visibility::Shared(self.client_at_sign.clone()),
                };
                let update_verb_args = UpdateVerbInputs::new_with_options(
                    &shared_key_at_key,
                    &encrypted_new_symm_key_value,
                    UpdateOptions::new(None, None, Some(86400), None),
                );
                let _ = UpdateVerb::execute(&mut self.tls_client, update_verb_args)?;
                // 5. Encrypt the data with the symmetric key and send it to the server
                match data {
                    AtValue::Text(text) => {
                        let encrypted_data = self
                            .at_chops
                            .encrypt_data_with_shared_symmetric_key(&new_symm_key, text)?;
                        let encrypted_data = AtValue::Text(encrypted_data);
                        let update_verb_args = UpdateVerbInputs::new(at_key, &encrypted_data);
                        let result = UpdateVerb::execute(&mut self.tls_client, update_verb_args)?;
                        Ok(result)
                    }
                    AtValue::Binary(_) => todo!(),
                }
            }
            Ok(LlookupVerbOutput::Data(symm_key)) => {
                // 5. Encrypt the data with the symmetric key and send it to the server
                info!("Already have symm key");
                let encrypted_symm_key = match symm_key {
                    AtValue::Text(text) => text,
                    _ => panic!("Unexpected variant"),
                };
                let symm_key = self.at_chops.decrypt_symmetric_key(&encrypted_symm_key)?;
                match data {
                    AtValue::Text(text) => {
                        let encrypted_data = self
                            .at_chops
                            .encrypt_data_with_shared_symmetric_key(&symm_key, text)?;
                        let encrypted_data = AtValue::Text(encrypted_data);
                        let update_verb_args = UpdateVerbInputs::new(at_key, &encrypted_data);
                        let result = UpdateVerb::execute(&mut self.tls_client, update_verb_args)?;
                        Ok(result)
                    }
                    AtValue::Binary(_) => todo!(),
                }
            }
            Ok(LlookupVerbOutput::All(_) | LlookupVerbOutput::Meta(_)) => {
                panic!("Unexpected LlookupVerbOutput variant")
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn put_metadata(&mut self, _at_key: &AtKey, _metadata: &RecordMetadata) -> Result<String> {
        // let update_verb_args = UpdateVerbInputs::new(at_key, &AtValue::Metadata(metadata.clone()));
        // let result = UpdateVerb::execute(&mut self.tls_client, update_verb_args)?;
        // Ok(result)
        todo!()
    }
}

#[derive(Debug)]
pub enum GetRequestType {
    Data,
    MetaData,
    All,
}

impl From<GetRequestType> for LookupReturnType {
    fn from(request_type: GetRequestType) -> Self {
        match request_type {
            GetRequestType::Data => LookupReturnType::Data,
            GetRequestType::MetaData => LookupReturnType::Metadata,
            GetRequestType::All => LookupReturnType::All,
        }
    }
}

#[derive(Debug)]
pub enum GetResponseType {
    Data(AtValue),
    Meta(RecordMetadata),
    All(AtRecord),
}
