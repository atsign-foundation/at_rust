use aes::cipher::StreamCipher;
use anyhow::Result;
use rsa::{RsaPrivateKey, RsaPublicKey};

/// A trait for cryptographic functions needed within the atSign library.
pub trait CryptoFunctions {
    // ----- Base64 -----
    /// Encode a byte array to base64 String.
    fn base64_encode<T: AsRef<[u8]>>(&self, data: T) -> String;

    /// Decode a base64 encoded string.
    fn base64_decode<T: AsRef<[u8]>>(&self, data: T) -> Result<Vec<u8>>;

    // ----- RSA -----
    /// Construct an RSA private key from a byte array.
    fn construct_rsa_private_key<T: AsRef<[u8]>>(&self, key: T) -> Result<RsaPrivateKey>;

    /// Construct an RSA public key from a byte array.
    fn construct_rsa_public_key<T: AsRef<[u8]>>(&self, key: T) -> Result<RsaPublicKey>;

    /// Generate a new RSA key pair.
    fn generate_rsa_key_pair(&self) -> Result<(RsaPrivateKey, RsaPublicKey)>;

    /// Verify a signature using an RSA public key.
    fn rsa_verify<T: AsRef<[u8]>, U: AsRef<[u8]>>(
        &self,
        data: T,
        signature: U,
        key: &RsaPublicKey,
    ) -> Result<bool>;

    /// Sign data (given as a byte array) using an RSA private key.
    /// The signature is returned as a byte array.
    fn rsa_sign<T: AsRef<[u8]>>(&self, data: T, key: &RsaPrivateKey) -> Result<Vec<u8>>;

    /// Encrypt some data using an RSA public key.
    fn rsa_encrypt<T: AsRef<[u8]>>(&self, plaintext: T, key: &RsaPublicKey) -> Result<Vec<u8>>;

    /// Decrypt some data using an RSA private key.
    fn rsa_decrypt<T: AsRef<[u8]>>(&self, ciphertext: T, key: &RsaPrivateKey) -> Result<Vec<u8>>;

    // ----- AES -----
    /// Construct an AES-256 cipher from a byte array and IV.
    fn construct_aes_cipher<T: AsRef<[u8]>>(
        &self,
        key: T,
        iv: &[u8; 16],
    ) -> Result<Box<dyn StreamCipher>>;

    /// Create a new AES-256 key from scratch.
    fn create_new_aes_key(&self) -> Result<[u8; 32]>;

    /// Encrypt some data using an AES key.
    fn aes_encrypt<T: AsRef<[u8]>>(
        &self,
        cipher: &mut dyn StreamCipher,
        plaintext: T,
    ) -> Result<Vec<u8>>;

    /// Decrypt some data using an AES key.
    fn aes_decrypt<T: AsRef<[u8]>>(
        &self,
        cipher: &mut dyn StreamCipher,
        ciphertext: T,
    ) -> Result<Vec<u8>>;
}
