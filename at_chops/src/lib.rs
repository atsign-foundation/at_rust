pub mod crypto_functions_trait;
pub mod default_crypto_functions;

use anyhow::Result;
pub use crypto_functions_trait::CryptoFunctions;
use rsa::{RsaPrivateKey, RsaPublicKey};

/// AtChops is a library that provides a set of high-level cryptographic functions needed within the Atsign protocol.
pub struct AtChops {
    crypto_service: Box<dyn CryptoFunctions>,
    /// Used for decrypting messages (currently just AES keys).
    rsa_private_key: RsaPrivateKey,
    /// Unused at the moment.
    rsa_public_key: RsaPublicKey,
    /// Used for authenticating with AtServer by signing challenges.
    pkam_private_key: RsaPrivateKey,
    /// Pretty sure this is never used.
    pkam_public_key: RsaPublicKey,
    //? Need to check that some of the functions should return String::from_utf8() instead of String created from base64encode
    //? In the future it probably makes sense to get rid of public keys entirely as the private keys are enough to derive them
}

impl AtChops {
    pub fn new(
        crypto_service: Box<dyn CryptoFunctions>,
        encoded_self_encryption_key: &str,
        encoded_and_encrypted_private_key: &str,
        encoded_and_encrypted_pkam_private_key: &str,
    ) -> Result<Self> {
        let decrypted_private_key = Self::decrypt_private_key(
            &crypto_service,
            encoded_and_encrypted_private_key,
            encoded_self_encryption_key,
        )?;
        let rsa_private_key = crypto_service.construct_rsa_private_key(&decrypted_private_key)?;
        let rsa_public_key = rsa_private_key.to_public_key();
        let decrypted_pkam_private_key = Self::decrypt_private_key(
            &crypto_service,
            encoded_and_encrypted_pkam_private_key,
            encoded_self_encryption_key,
        )?;
        let pkam_private_key =
            crypto_service.construct_rsa_private_key(&decrypted_pkam_private_key)?;
        let pkam_public_key = pkam_private_key.to_public_key();
        Ok(Self {
            crypto_service,
            rsa_private_key,
            rsa_public_key,
            pkam_private_key,
            pkam_public_key,
        })
    }

    // Note: Anything that is a `String` or `&str` is base64 encoded. Anything that is a `Vec<u8>` is byte data.

    /// Helper method to decrypt the private key using the self encryption key.
    fn decrypt_private_key(
        crypto_service: &Box<dyn CryptoFunctions>,
        encoded_and_encrypted_private_key: &str,
        encoded_self_encryption_key: &str,
    ) -> Result<Vec<u8>> {
        let decoded_self_encryption_key =
            crypto_service.base64_decode(encoded_self_encryption_key.as_bytes())?;
        let iv: [u8; 16] = [0x00; 16];
        let mut cipher = crypto_service.construct_aes_cipher(&decoded_self_encryption_key, &iv)?;
        let decoded_private_key =
            crypto_service.base64_decode(encoded_and_encrypted_private_key.as_bytes())?;
        let mut output = crypto_service.aes_decrypt(&mut *cipher, &decoded_private_key)?;

        // NOTE: Due to the PKCS#7 type of encryption used (on the keys), the output will have padding

        // NOTE: Might be worth converting to a char type then using .is_ascii_hexdigit() (or similar)

        // Get the last byte, which is the number of padding bytes
        let last = output.last().unwrap();
        output.truncate(output.len() - usize::from(*last));
        //? The key was originally a string?
        let string_result = String::from_utf8(output)?;
        let result = crypto_service.base64_decode(&string_result.as_bytes())?;
        Ok(result)
    }

    /// Sign a given challenge with the decrypted private key.
    pub fn sign_challenge(&self, challenge: &str) -> Result<String> {
        let sign_result = self
            .crypto_service
            .rsa_sign(challenge.as_bytes(), &self.pkam_private_key)?;
        let result = &self.crypto_service.base64_encode(&sign_result);
        Ok(result.to_owned())
    }

    /// Cut a new symmetric key to be used when interacting with a new atSign.
    pub fn create_new_shared_symmetric_key(&self) -> Result<String> {
        let key = self.crypto_service.create_new_aes_key()?;
        Ok(self.crypto_service.base64_encode(&key))
    }

    /// Decrypt "their" symmetric key with "our" private key.
    pub fn decrypt_symmetric_key(
        &self,
        encoded_and_encrypted_symmetric_key: &str,
    ) -> Result<String> {
        let decoded_symmetric_key = self
            .crypto_service
            .base64_decode(encoded_and_encrypted_symmetric_key.as_bytes())?;
        let decrypted_symm_key = self
            .crypto_service
            .rsa_decrypt(&decoded_symmetric_key, &self.rsa_private_key)?;
        Ok(String::from_utf8(decrypted_symm_key)?)
    }

    /// Encrypt data with "their" RSA public key.
    pub fn encrypt_data_with_public_key(
        &self,
        encoded_public_key: &str,
        data: &str,
    ) -> Result<String> {
        let decoded_public_key = self
            .crypto_service
            .base64_decode(encoded_public_key.as_bytes())?;
        let rsa_public_key = self
            .crypto_service
            .construct_rsa_public_key(&decoded_public_key)?;
        let encrypted_data = self
            .crypto_service
            .rsa_encrypt(data.as_bytes(), &rsa_public_key)?;
        Ok(String::from_utf8(encrypted_data)?)
    }

    /// Encrypt data with AES symm key.
    pub fn encrypt_data_with_shared_symmetric_key(
        &self,
        encoded_symmetric_key: &str,
        data: &str,
    ) -> Result<String> {
        let decoded_symmetric_key = self
            .crypto_service
            .base64_decode(encoded_symmetric_key.as_bytes())?;
        let iv: [u8; 16] = [0x00; 16];
        let mut cipher = self
            .crypto_service
            .construct_aes_cipher(&decoded_symmetric_key, &iv)?;
        let encrypted_data = self
            .crypto_service
            .aes_encrypt(&mut *cipher, data.as_bytes())?;
        Ok(self.crypto_service.base64_encode(&encrypted_data))
    }

    /// Decrypt data with an encoded AES symm key.
    pub fn decrypt_data_with_shared_symmetric_key(
        &self,
        encoded_symmetric_key: &str,
        data: &str,
    ) -> Result<String> {
        let decoded_symmetric_key = self
            .crypto_service
            .base64_decode(encoded_symmetric_key.as_bytes())?;
        let iv: [u8; 16] = [0x00; 16];
        let mut cipher = self
            .crypto_service
            .construct_aes_cipher(&decoded_symmetric_key, &iv)?;
        let encrypted_data = self
            .crypto_service
            .aes_decrypt(&mut *cipher, data.as_bytes())?;
        Ok(self.crypto_service.base64_encode(&encrypted_data))
    }
}

#[cfg(test)]
mod test {

    use self::default_crypto_functions::DefaultCryptoFunctions;

    use super::*;

    const SELF_ENCRYPTION_KEY_ENCODED: &str = "LXgXrG4oWQQTa1EpDvkTs3EE83qsyICgrpoWLVYEwbo=";
    // Pkam key base64 encoded with self encryption key (input)
    const PKAM_KEY_ENCRYPTED_AND_ENCODED: &str = "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";
    // Challenge text
    const CHALLENGE_TEXT: &str =
        "_6e27e164-e45b-4ae1-8714-7545d36b6ed4@aliens12:9ef2ec2c-39d4-4e25-825e-0da05f6e0bb9";
    // Expected result of signing the challenge text
    const CHALLENGE_RESULT: &str = "aTY5Pxod1hzv/9uL9FSqxbmmCT73vFEBRv4qA+k+d6U5hcglzYvAl1MJNY2eQLTFLoFIkx/3pgm0YkjI4aS1hBAyBmMIinGrPGbOuR3PebPqITLhNWdeWZamHrlKY8tjvARtb4k0gb2LgauzhNq3zzm5aS7EU7OYaRy22/fR5fCWXw+ZyFdRYhA9qlFcA7ksct3pJwHSvSlQb2R7YuzN210Xfii43yAgtncz4CUZRcxPL7AD4mUg7dSMu0RMVKIQKsecwhNfh7bgy1zFDGMpOP8DQJ8tJfQiut5u+0yAGM4O31FJ+F7/1pvR0pgr7/O0/4K+BdhdRWNVine335u6lg==";

    fn create_subject() -> Result<AtChops> {
        let crypto_service = Box::new(DefaultCryptoFunctions::new());
        Ok(AtChops::new(
            crypto_service,
            SELF_ENCRYPTION_KEY_ENCODED,
            // Using PKAM key just for testing
            PKAM_KEY_ENCRYPTED_AND_ENCODED,
            PKAM_KEY_ENCRYPTED_AND_ENCODED,
        )?)
    }

    #[test]
    fn test_new() {
        let subject = create_subject();
        let subject = subject.map_err(|e| println!("Error: {}", e));
        assert!(subject.is_ok());
    }

    #[test]
    fn test_sign_challenge() {
        let subject = create_subject().unwrap();
        let result = subject.sign_challenge(CHALLENGE_TEXT);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CHALLENGE_RESULT);
    }

    #[test]
    fn test_create_new_shared_symmetric_key() {
        let subject = create_subject().unwrap();
        let result = subject.create_new_shared_symmetric_key();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 44)
    }
}
