use crate::{
    at_chops::at_chops::{
        create_new_shared_symmetric_key, encrypt_data_with_public_key, encrypt_symmetric_key,
    },
    verbs::{
        plookup::{PlookupVerb, PlookupVerbInputs},
        update::{UpdateVerb, UpdateVerbInputs},
    },
};

use super::{prelude::*, Verb};

pub struct LlookupVerbInputs<'a> {
    /// The AtSign of the person who is looking up the key-value pair.
    pub from_at_sign: &'a AtSign,
    /// The AtSign of the person who owns the key-value pair.
    pub to_at_sign: &'a AtSign,
    /// The identifier of the key-value pair to be looked up.
    pub at_id: &'a str,
    /// The decrypted public key.
    pub public_key: &'a str,
}

impl<'a> LlookupVerbInputs<'a> {
    pub fn new(
        from_at_sign: &'a AtSign,
        to_at_sign: &'a AtSign,
        at_id: &'a str,
        public_key: &'a str,
    ) -> Self {
        Self {
            from_at_sign,
            to_at_sign,
            at_id,
            public_key,
        }
    }
}

pub struct LlookupVerb {}

impl<'a> Verb<'a> for LlookupVerb {
    type Inputs = LlookupVerbInputs<'a>;
    type Result = String;

    fn execute(tls_client: &mut TLSClient, input: Self::Inputs) -> Result<Self::Result> {
        println!(
            "Looking up local copy of {:?} {:?}",
            &input.to_at_sign, &input.at_id
        );
        tls_client.send(format!(
            "llookup:{}.{}@{}\n",
            input.at_id,
            input.to_at_sign.get_at_sign(),
            input.from_at_sign.get_at_sign()
        ))?;
        let response = tls_client.read_line()?;
        println!("llookup response: {:?}", response);
        // TODO: Send this response back from this method and have the caller handle what to do
        // next
        if response.contains("error:AT0015-key not found") {
            println!("Creating new symmetric key");
            // Create symm key
            let new_key = create_new_shared_symmetric_key();
            let encrypted_encoded_sym_key = encrypt_symmetric_key(&new_key, &input.public_key);
            // Save for our use
            let _ = UpdateVerb::execute(
                tls_client,
                UpdateVerbInputs::new(
                    input.from_at_sign,
                    input.to_at_sign,
                    input.at_id,
                    &encrypted_encoded_sym_key,
                ),
            )?;
            // and share with recipient
            let recipient_public_key_encoded = PlookupVerb::execute(
                tls_client,
                PlookupVerbInputs::new(input.to_at_sign, "publickey"),
            )?;
            let recipient_public_key =
                encrypt_data_with_public_key(&recipient_public_key_encoded, &new_key);
            // Send data
        } else if response.contains("data") {
            println!("Already have a copy of the key");
            // Decrypt symm key
        } else {
            return Err(AtError::new(String::from("Unknown response from server")));
        }
        Ok(String::from("llookup"))
    }
}
