use anyhow::Result;
use crypto_functions_trait::CryptoFunctions;

pub mod crypto_functions_trait;

/// AtChops is a library that provides a set of high-level cryptographic functions needed within the Atsign protocol.
pub struct AtChops<T: CryptoFunctions> {
    crypto_service: T,
    //? It might make sense to store the self encryption key here
    //? Probably worth passing in AtSecrets to the constructor then storing the secrets here
    //? Need to check that some of the functions should return String::from_utf8() instead of String created from base64encode
}

impl<T: CryptoFunctions> AtChops<T> {
    pub fn new(crypto_service: T) -> Self {
        Self { crypto_service }
    }

    // Note: Anything that is a `String` or `&str` is base64 encoded. Anything that is a `Vec<u8>` is byte data.

    /// Base64 decode the self encryption key.
    pub fn decode_self_encryption_key(&self, self_encryption_key: &str) -> Result<Vec<u8>> {
        self.crypto_service.base64_decode(self_encryption_key)
    }

    /// Decrypt the private key using the self encryption key.
    pub fn decrypt_private_key(
        &self,
        encrypted_private_key: &str,
        decoded_self_encryption_key: &[u8],
    ) -> Result<String> {
        let iv: [u8; 16] = [0x00; 16];
        let mut cipher = self
            .crypto_service
            .construct_aes_cipher(decoded_self_encryption_key, &iv)?;
        let decoded_private_key = self.crypto_service.base64_decode(encrypted_private_key)?;

        let mut output = self
            .crypto_service
            .aes_decrypt(&mut *cipher, &decoded_private_key)?;

        // NOTE: Due to the PKCS#7 type of encryption used (on the keys), the output will have padding

        // NOTE: Might be worth converting to a char type then using .is_ascii_hexdigit() (or similar)

        // Get the last byte, which is the number of padding bytes
        let last = output.last().unwrap();
        output.truncate(output.len() - usize::from(*last));
        Ok(String::from_utf8(output)?)
    }

    /// Sign a given challenge with the decrypted private key.
    pub fn sign_challenge(&self, challenge: &str, decrypted_private_key: &str) -> Result<String> {
        let decoded_private_key = self.crypto_service.base64_decode(decrypted_private_key)?;
        let rsa_private_key = self
            .crypto_service
            .construct_rsa_private_key(&decoded_private_key)?;
        let sign_result = self
            .crypto_service
            .rsa_sign(challenge.as_bytes(), &rsa_private_key)?;
        Ok(String::from_utf8(sign_result)?)
    }

    /// Cut a new symmetric key to be used when interacting with a new atSign.
    pub fn create_new_shared_symmetric_key(&self) -> Result<String> {
        let key = self.crypto_service.create_new_aes_key()?;
        Ok(self.crypto_service.base64_encode(&key))
    }

    /// Decrypt "their" symmetric key with "our" private key.
    pub fn decrypt_symmetric_key(
        &self,
        encrypted_symmetric_key: &str,
        decrypted_private_key: &str,
    ) -> Result<String> {
        let decoded_private_key = self.crypto_service.base64_decode(decrypted_private_key)?;
        let rsa_private_key = self
            .crypto_service
            .construct_rsa_private_key(&decoded_private_key)?;
        let decoded_symmetric_key = self.crypto_service.base64_decode(encrypted_symmetric_key)?;
        let decrypted_symm_key = self
            .crypto_service
            .rsa_decrypt(decoded_symmetric_key, &rsa_private_key)?;
        Ok(String::from_utf8(decrypted_symm_key)?)
    }

    /// Encrypt data with our RSA public key.
    pub fn encrypt_data_with_public_key(
        &self,
        encoded_public_key: &str,
        data: &str,
    ) -> Result<String> {
        let decoded_public_key = self.crypto_service.base64_decode(encoded_public_key)?;
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
        let decoded_symmetric_key = self.crypto_service.base64_decode(encoded_symmetric_key)?;
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
        let decoded_symmetric_key = self.crypto_service.base64_decode(encoded_symmetric_key)?;
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
