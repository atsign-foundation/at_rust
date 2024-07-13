use aes::{cipher::StreamCipher, Aes256};
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use cipher::generic_array::GenericArray;
use cipher::KeyIvInit;
use ctr::Ctr128BE;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::sha2::Digest;
use rsa::sha2::Sha256;
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};

use crate::CryptoFunctions;

pub struct DefaultCryptoFunctions {}

impl DefaultCryptoFunctions {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for DefaultCryptoFunctions {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoFunctions for DefaultCryptoFunctions {
    // ----- Base64 -----
    fn base64_encode(&self, data: &[u8]) -> String {
        general_purpose::STANDARD.encode(data)
    }

    fn base64_decode(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(general_purpose::STANDARD.decode(data)?)
    }

    // ----- RSA -----
    fn construct_rsa_private_key(&self, key: &[u8]) -> Result<RsaPrivateKey> {
        let rsa_private_key = RsaPrivateKey::from_pkcs8_der(key)?;
        rsa_private_key.validate()?;
        Ok(rsa_private_key)
    }

    fn construct_rsa_public_key(&self, key: &[u8]) -> Result<RsaPublicKey> {
        let rsa_public_key = RsaPublicKey::from_public_key_der(key)?;
        Ok(rsa_public_key)
    }

    fn generate_rsa_key_pair(&self) -> Result<(RsaPrivateKey, RsaPublicKey)> {
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits)?;
        let public_key = RsaPublicKey::from(&private_key);
        Ok((private_key, public_key))
    }

    fn rsa_verify(&self, data: &[u8], signature: &[u8], key: &RsaPublicKey) -> Result<bool> {
        let hash = Sha256::digest(data);
        let padding = Pkcs1v15Sign::new::<Sha256>();
        let result = key.verify(padding, &hash, signature.as_ref()).is_ok();
        Ok(result)
    }

    fn rsa_sign(&self, data: &[u8], key: &RsaPrivateKey) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::<Sha256>::new(key.clone());
        let verifying_key = signing_key.verifying_key();
        let signature = signing_key.sign_with_rng(&mut rng, data.as_ref());
        verifying_key.verify(data.as_ref(), &signature)?;
        Ok(Vec::from(signature.to_bytes().as_ref()))
    }

    fn rsa_encrypt(&self, plaintext: &[u8], key: &RsaPublicKey) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let enc_data = key.encrypt(&mut rng, Pkcs1v15Encrypt, plaintext.as_ref())?;
        Ok(enc_data)
    }

    fn rsa_decrypt(&self, ciphertext: &[u8], key: &RsaPrivateKey) -> Result<Vec<u8>> {
        let dec_data = key.decrypt(Pkcs1v15Encrypt, ciphertext.as_ref())?;
        Ok(dec_data)
    }

    // ----- AES -----
    fn construct_aes_cipher(&self, key: &[u8], iv: &[u8; 16]) -> Result<Box<dyn StreamCipher>> {
        let key = GenericArray::from_slice(key);
        let nonce = GenericArray::from_slice(iv);
        let cipher = Ctr128BE::<Aes256>::new(key, nonce);
        Ok(Box::new(cipher))
    }

    fn create_new_aes_key(&self) -> Result<[u8; 32]> {
        let key: [u8; 32] = rand::random();
        Ok(key)
    }

    fn aes_encrypt(&self, cipher: &mut dyn StreamCipher, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = plaintext.as_ref().to_vec();
        cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }

    fn aes_decrypt(&self, cipher: &mut dyn StreamCipher, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = ciphertext.as_ref().to_vec();
        cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }
}

#[cfg(test)]
mod test {

    use super::*;

    fn create_default_crypto_functions() -> DefaultCryptoFunctions {
        DefaultCryptoFunctions::new()
    }

    const DER_ENCODED_PRIVATE_KEY: &[u8] = include_bytes!("../test_data/test_rsa_private_key.der");
    const DER_ENCODED_PUBLIC_KEY: &[u8] = include_bytes!("../test_data/test_rsa_public_key.der");

    // ----- Tests ------
    #[test]
    fn test_decode_base64_text() {
        let subject = create_default_crypto_functions();
        let result = subject.base64_decode(b"SGVsbG8sIHdvcmxkIQ==").unwrap();
        assert_eq!(result, b"Hello, world!");
    }

    #[test]
    fn test_decode_base64_error() {
        let subject = create_default_crypto_functions();
        let result = subject.base64_decode(b"SGVsbG8sIHd@}{/**&(mxkIQ==");
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
    fn test_generate_rsa_key_pair() {
        let subject = create_default_crypto_functions();
        let result = subject.generate_rsa_key_pair();
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
    fn test_rsa_verify() {
        let subject = create_default_crypto_functions();
        let (rsa_private_key, rsa_public_key) = subject.generate_rsa_key_pair().unwrap();
        let data = b"Hello, world!";
        let signature = subject.rsa_sign(data, &rsa_private_key).unwrap();
        let result = subject.rsa_verify(data, &signature, &rsa_public_key);
        assert!(result.is_ok());
        assert!(result.unwrap() == true); // Just being explicit
    }

    #[test]
    fn test_rsa_verify_fail_with_different_key_pairs() {
        let subject = create_default_crypto_functions();
        let (rsa_private_key, _) = subject.generate_rsa_key_pair().unwrap();
        let (_, rsa_public_key) = subject.generate_rsa_key_pair().unwrap();
        let data = b"Hello, world!";
        let signature = subject.rsa_sign(data, &rsa_private_key).unwrap();
        let result = subject.rsa_verify(data, &signature, &rsa_public_key);
        assert!(result.is_ok());
        assert!(result.unwrap() == false); // Just being explicit
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
            .rsa_decrypt(&encrypt_result, &rsa_private_key)
            .unwrap();
        assert_eq!(&data[..], &decrypt_result[..]);
    }

    #[test]
    fn test_construct_aes_cipher() {
        let subject = create_default_crypto_functions();
        let key = subject.create_new_aes_key().unwrap();
        let iv = [0u8; 16];
        let result = subject.construct_aes_cipher(&key, &iv);
        assert!(result.is_ok());
    }

    #[test]
    fn test_aes_encrypt_decrypt() {
        let subject = create_default_crypto_functions();
        let key = subject.create_new_aes_key().unwrap();
        let iv = [0u8; 16];
        let mut cipher = subject.construct_aes_cipher(&key, &iv).unwrap();
        let data = b"Hello, world!";
        let encrypt_result = subject.aes_encrypt(&mut *cipher, data).unwrap();
        assert_ne!(encrypt_result, data);
        let mut cipher = subject.construct_aes_cipher(&key, &iv).unwrap();
        let decrypt_result = subject.aes_decrypt(&mut *cipher, &encrypt_result).unwrap();
        assert_eq!(&data[..], &decrypt_result[..]);
    }
}
