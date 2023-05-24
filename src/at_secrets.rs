use serde_json::{from_str, Value};

/// Struct to store all the secrets associated with an AtSign account.
#[derive(Debug)]
pub struct AtSecrets {
    /// info
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
    pub fn from_data(input: &str) -> AtSecrets {
        let v: Value = from_str(input).unwrap();

        let aes_pkam_public_key = v["aesPkamPublicKey"].as_str().unwrap().to_owned();
        let aes_pkam_private_key = v["aesPkamPrivateKey"].as_str().unwrap().to_owned();
        let aes_encrypt_public_key = v["aesEncryptPublicKey"].as_str().unwrap().to_owned();
        let aes_encrypt_private_key = v["aesEncryptPrivateKey"].as_str().unwrap().to_owned();
        let aes_self_encrypt_key = v["selfEncryptionKey"].as_str().unwrap().to_owned();

        AtSecrets::new(
            aes_pkam_public_key,
            aes_pkam_private_key,
            aes_encrypt_public_key,
            aes_encrypt_private_key,
            aes_self_encrypt_key,
        )
    }
}
