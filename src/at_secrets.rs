use crate::at_chops::at_chops::{decode_self_encryption_key, decrypt_private_key};
use serde_json::{from_str, Value};

/// Struct to store all the secrets associated with an AtSign account.
#[derive(Debug)]
pub struct AtSecrets {
    pub aes_pkam_public_key: String,
    pub aes_pkam_private_key: String,
    pub aes_encrypt_public_key: String,
    pub aes_encrypt_private_key: String,
    pub self_encryption_key: String,
}

impl AtSecrets {
    pub fn new(
        aes_pkam_public_key: String,
        aes_pkam_private_key: String,
        aes_encrypt_public_key: String,
        aes_encrypt_private_key: String,
        aes_self_encrypt_key: String,
    ) -> AtSecrets {
        AtSecrets {
            aes_pkam_public_key,
            aes_pkam_private_key,
            aes_encrypt_public_key,
            aes_encrypt_private_key,
            self_encryption_key: aes_self_encrypt_key,
        }
    }

    /// Create AtSecrets from a JSON string which is found inside the `.atKeys` file associated
    /// with all AtSign accounts.
    // TODO: This should really return a Result<AtSecrets, Error> instead of panicking.
    pub fn from_file(input: &str) -> AtSecrets {
        // Get the info from the file
        let v: Value = from_str(input).unwrap();

        println!("Extracting keys from file");

        // Get the keys
        let aes_pkam_public_key = v["aesPkamPublicKey"].as_str().unwrap().to_owned();
        let aes_pkam_private_key = v["aesPkamPrivateKey"].as_str().unwrap().to_owned();
        let aes_encrypt_public_key = v["aesEncryptPublicKey"].as_str().unwrap().to_owned();
        let aes_encrypt_private_key = v["aesEncryptPrivateKey"].as_str().unwrap().to_owned();
        let aes_self_encrypt_key = v["selfEncryptionKey"].as_str().unwrap().to_owned();

        println!("Decoding keys");
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

        println!("Keys decoded and decrypted");

        AtSecrets::new(
            pkam_public_key,
            pkam_private_key,
            encrypt_public_key,
            encrypt_private_key,
            aes_self_encrypt_key,
        )
    }
}
