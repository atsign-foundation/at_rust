use crate::at_chops::at_chops::{decode_self_encryption_key, decrypt_private_key};
use crate::at_error::Result;
use log::info;
use serde_json::{from_str, from_value, Value};

/// Struct to store all the secrets associated with an AtSign account.
#[derive(Debug)]
pub struct AtSecrets {
    pub pkam_public_key: String,
    pub pkam_private_key: String,
    pub encrypt_public_key: String,
    pub encrypt_private_key: String,
    pub self_encryption_key: String,
}

impl AtSecrets {
    fn new(
        pkam_public_key: String,
        pkam_private_key: String,
        encrypt_public_key: String,
        encrypt_private_key: String,
        self_encryption_key: String,
    ) -> AtSecrets {
        AtSecrets {
            pkam_public_key,
            pkam_private_key,
            encrypt_public_key,
            encrypt_private_key,
            self_encryption_key,
        }
    }

    /// Create AtSecrets from a JSON string which is found inside the `.atKeys` file associated
    /// with all atSign accounts.
    pub fn from_file(input: &str) -> Result<AtSecrets> {
        // Get the info from the file
        let v: Value = from_str(input).unwrap();

        info!("Extracting keys from file");

        // Get the keys
        let aes_pkam_public_key = v["aesPkamPublicKey"].as_str().unwrap().to_owned();
        let aes_pkam_private_key = v["aesPkamPrivateKey"].as_str().unwrap().to_owned();
        let aes_encrypt_public_key = v["aesEncryptPublicKey"].as_str().unwrap().to_owned();
        let aes_encrypt_private_key = v["aesEncryptPrivateKey"].as_str().unwrap().to_owned();
        let aes_self_encrypt_key = v["selfEncryptionKey"].as_str().unwrap().to_owned();

        AtSecrets::from_values(
            &aes_pkam_public_key,
            &aes_pkam_private_key,
            &aes_encrypt_public_key,
            &aes_encrypt_private_key,
            &aes_self_encrypt_key,
        )
    }

    /// Create AtSecrets from the values of the keys found inside the `.ateys` file.
    pub fn from_values(
        aes_pkam_public_key: &str,
        aes_pkam_private_key: &str,
        aes_encrypt_public_key: &str,
        aes_encrypt_private_key: &str,
        aes_self_encrypt_key: &str,
    ) -> Result<AtSecrets> {
        info!("Decoding keys");
        // Decode the self encrypt key from base64
        let decoded_self_encrypted_key = decode_self_encryption_key(&aes_self_encrypt_key);

        // Use the key to decrypt all the other private keys
        let pkam_public_key =
            decrypt_private_key(&aes_pkam_public_key, &decoded_self_encrypted_key);
        let pkam_private_key =
            decrypt_private_key(&aes_pkam_private_key, &decoded_self_encrypted_key);
        let encrypt_public_key =
            decrypt_private_key(&aes_encrypt_public_key, &decoded_self_encrypted_key);
        let encrypt_private_key =
            decrypt_private_key(&aes_encrypt_private_key, &decoded_self_encrypted_key);

        info!("Keys decoded and decrypted");

        Ok(AtSecrets::new(
            pkam_public_key,
            pkam_private_key,
            encrypt_public_key,
            encrypt_private_key,
            aes_self_encrypt_key.to_owned(),
        ))
    }
}
