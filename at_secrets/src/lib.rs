use log::debug;
use serde_json::{from_str, Value};

/// Struct to store all the secrets associated with an AtSign account.
#[derive(Debug)]
pub struct AtSecrets {
    pub encoded_and_encrypted_pkam_public_key: String,
    pub encoded_and_encrypted_pkam_private_key: String,
    pub encoded_and_encrypted_encrypt_public_key: String,
    pub encoded_and_encrypted_encrypt_private_key: String,
    pub encoded_self_encryption_key: String,
}

impl AtSecrets {
    pub fn new(
        encoded_and_encrypted_pkam_public_key: String,
        encoded_and_encrypted_pkam_private_key: String,
        encoded_and_encrypted_encrypt_public_key: String,
        encoded_and_encrypted_encrypt_private_key: String,
        encoded_self_encryption_key: String,
    ) -> Self {
        Self {
            encoded_and_encrypted_pkam_public_key,
            encoded_and_encrypted_pkam_private_key,
            encoded_and_encrypted_encrypt_public_key,
            encoded_and_encrypted_encrypt_private_key,
            encoded_self_encryption_key,
        }
    }

    /// Create AtSecrets from a JSON string which is found inside the `.atKeys` file associated
    /// with all atSign accounts.
    pub fn from_file(input: &str) -> Result<AtSecrets, &'static str> {
        // Get the info from the file
        let v: Value = from_str(input).map_err(|_| "Failed to read file")?;

        debug!("Extracting keys from file");

        // Get the keys
        let aes_pkam_public_key = v["aesPkamPublicKey"]
            .as_str()
            .ok_or("Unable to find aesPkamPublicKey")?
            .to_owned();
        let aes_pkam_private_key = v["aesPkamPrivateKey"]
            .as_str()
            .ok_or("Unable to find aesPkamPrivateKey")?
            .to_owned();
        let aes_encrypt_public_key = v["aesEncryptPublicKey"]
            .as_str()
            .ok_or("Unable to find aesEncryptPublicKey")?
            .to_owned();
        let aes_encrypt_private_key = v["aesEncryptPrivateKey"]
            .as_str()
            .ok_or("Unable to find aesEncryptPrivateKey")?
            .to_owned();
        let aes_self_encrypt_key = v["selfEncryptionKey"]
            .as_str()
            .ok_or("Unable to find selfEncryptionKey")?
            .to_owned();

        Ok(AtSecrets::new(
            aes_pkam_public_key,
            aes_pkam_private_key,
            aes_encrypt_public_key,
            aes_encrypt_private_key,
            aes_self_encrypt_key,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_file() {
        let input = r#"{
            "aesPkamPublicKey": "pkam_public_key",
            "aesPkamPrivateKey": "pkam_private",
            "aesEncryptPublicKey": "encrypt_public",
            "aesEncryptPrivateKey": "encrypt_private",
            "selfEncryptionKey": "self_encrypt"
        }"#;
        assert!(AtSecrets::from_file(input).is_ok());
    }

    #[test]
    fn test_fail_from_file() {
        let input = r#"{
            "aesPkamPublicKey": "pkam_public_key",
            "aesPkamPrivateKey": "pkam_private",
            "aesEncryptPublicKey": "encrypt_public",
            "aesEncryptPrivateKey": "encrypt_private"
        }"#;
        let at_secrets = AtSecrets::from_file(input);
        assert!(at_secrets.is_err());
        assert_eq!(at_secrets.unwrap_err(), "Unable to find selfEncryptionKey");
    }
}
