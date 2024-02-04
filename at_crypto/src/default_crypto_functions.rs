use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::sha2::Sha256;
use rsa::signature::Keypair;
use rsa::signature::RandomizedSigner;
use rsa::signature::SignatureEncoding;
use rsa::signature::Verifier;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

use crate::crypto_functions_trait::CryptoFunctions;

struct DefaultCryptoFunctions {}

impl DefaultCryptoFunctions {
    pub fn new() -> Self {
        Self {}
    }
}

impl CryptoFunctions for DefaultCryptoFunctions {
    fn base64_decode<T: AsRef<[u8]>>(&self, data: T) -> Result<Vec<u8>> {
        Ok(general_purpose::STANDARD.decode(data)?)
    }

    fn base64_encode<T: AsRef<[u8]>>(&self, data: T) -> String {
        general_purpose::STANDARD.encode(data)
    }

    fn construct_aes_key<T: AsRef<[u8]>, U: aes::cipher::StreamCipher>(
        &self,
        key: T,
        iv: &[u8; 16],
    ) -> anyhow::Result<U> {
        todo!()
    }

    fn construct_rsa_private_key<T: AsRef<[u8]>>(&self, key: T) -> Result<RsaPrivateKey> {
        let rsa_private_key = RsaPrivateKey::from_pkcs8_der(key.as_ref())?;
        rsa_private_key.validate()?;
        Ok(rsa_private_key)
    }

    fn construct_rsa_public_key<T: AsRef<[u8]>>(&self, key: T) -> Result<RsaPublicKey> {
        let rsa_public_key = RsaPublicKey::from_public_key_der(key.as_ref())?;
        Ok(rsa_public_key)
    }

    fn rsa_sign<T: AsRef<[u8]>>(&self, data: T, key: &RsaPrivateKey) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::<Sha256>::new(key.clone());
        let verifying_key = signing_key.verifying_key();
        let signature = signing_key.sign_with_rng(&mut rng, data.as_ref());
        verifying_key.verify(data.as_ref(), &signature)?;
        Ok(Vec::from(signature.to_bytes().as_ref()))
    }

    fn create_new_aes_key(&self) -> anyhow::Result<[u8; 32]> {
        todo!()
    }

    fn rsa_encrypt<T: AsRef<[u8]>>(&self, data: T, key: &RsaPublicKey) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let enc_data = key.encrypt(&mut rng, Pkcs1v15Encrypt, data.as_ref())?;
        Ok(enc_data)
    }

    fn rsa_decrypt<T: AsRef<[u8]>>(&self, data: T, key: &RsaPrivateKey) -> Result<Vec<u8>> {
        let dec_data = key.decrypt(Pkcs1v15Encrypt, data.as_ref())?;
        Ok(dec_data)
    }

    fn aes_encrypt<T: AsRef<[u8]>, U: aes::cipher::StreamCipher>(
        &self,
        key: &mut U,
        data: T,
    ) -> anyhow::Result<U> {
        todo!()
    }

    fn aes_decrypt<T: AsRef<[u8]>, U: aes::cipher::StreamCipher>(
        &self,
        key: &mut U,
        data: T,
    ) -> anyhow::Result<U> {
        todo!()
    }
}

#[cfg(test)]
mod test {

    use super::*;

    // Create subject to be tested
    fn create_default_crypto_functions() -> DefaultCryptoFunctions {
        DefaultCryptoFunctions::new()
    }

    const DER_ENCODED_PRIVATE_KEY: &[u8] = include_bytes!("../test_data/test_rsa_private_key.der");
    const DER_ENCODED_PUBLIC_KEY: &[u8] = include_bytes!("../test_data/test_rsa_public_key.der");

    // ----- Tests ------
    #[test]
    fn test_decode_base64_text() {
        let subject = create_default_crypto_functions();
        let result = subject.base64_decode("SGVsbG8sIHdvcmxkIQ==").unwrap();
        assert_eq!(result, b"Hello, world!");
    }

    #[test]
    fn test_decode_base64_error() {
        let subject = create_default_crypto_functions();
        let result = subject.base64_decode("SGVsbG8sIHd@}{/**&(mxkIQ==");
        assert!(result.is_err())
    }

    #[test]
    fn test_encode_base64_text() {
        let subject = create_default_crypto_functions();
        let result = subject.base64_encode(b"Hello, world!");
        assert_eq!(result, String::from("SGVsbG8sIHdvcmxkIQ=="));
    }

    #[test]
    fn test_construct_rsa_private_key() {
        let subject = create_default_crypto_functions();
        let result = subject.construct_rsa_private_key(DER_ENCODED_PRIVATE_KEY);
        assert!(result.is_ok())
    }

    #[test]
    fn test_construct_rsa_public_key() {
        let subject = create_default_crypto_functions();
        let result = subject.construct_rsa_public_key(DER_ENCODED_PUBLIC_KEY);
        assert!(result.is_ok())
    }

    #[test]
    fn test_rsa_sign() {
        let subject = create_default_crypto_functions();
        let rsa_private_key = subject
            .construct_rsa_private_key(DER_ENCODED_PRIVATE_KEY)
            .unwrap();
        let data = b"Hello, world!";
        let result = subject.rsa_sign(data, &rsa_private_key);
        assert!(result.is_ok());
        // Ensure the signature is different from the original data
        assert_ne!(result.unwrap(), data);
    }

    #[test]
    fn test_rsa_encrypt_decrypt() {
        let subject = create_default_crypto_functions();
        let rsa_private_key = subject
            .construct_rsa_private_key(DER_ENCODED_PRIVATE_KEY)
            .unwrap();
        let rsa_public_key = subject
            .construct_rsa_public_key(DER_ENCODED_PUBLIC_KEY)
            .unwrap();
        let data = b"Hello, world!";
        let encrypt_result = subject.rsa_encrypt(data, &rsa_public_key).unwrap();
        assert_ne!(encrypt_result, data);
        let decrypt_result = subject
            .rsa_decrypt(encrypt_result, &rsa_private_key)
            .unwrap();
        assert_eq!(&data[..], &decrypt_result[..]);
    }
}
