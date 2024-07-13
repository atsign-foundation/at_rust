use aes::cipher::StreamCipher;
use anyhow::Result;
use rsa::{RsaPrivateKey, RsaPublicKey};

/// A trait for cryptographic functions needed within the atSign library.
pub trait CryptoFunctions {
    // ----- Base64 -----
    /// Encode a byte array to base64 String.
    fn base64_encode(&self, data: &[u8]) -> String;

    /// Decode a base64 encoded string.
    fn base64_decode(&self, data: &[u8]) -> Result<Vec<u8>>;

    // ----- RSA -----
    /// Construct an RSA private key from a byte array.
    fn construct_rsa_private_key(&self, key: &[u8]) -> Result<RsaPrivateKey>;

    /// Construct an RSA public key from a byte array.
    fn construct_rsa_public_key(&self, key: &[u8]) -> Result<RsaPublicKey>;

    /// Generate a new RSA key pair.
    fn generate_rsa_key_pair(&self) -> Result<(RsaPrivateKey, RsaPublicKey)>;

    /// Verify a signature using an RSA public key.
    fn rsa_verify(&self, data: &[u8], signature: &[u8], key: &RsaPublicKey) -> Result<bool>;

    /// Sign data (given as a byte array) using an RSA private key.
    /// The signature is returned as a byte array.
    fn rsa_sign(&self, data: &[u8], key: &RsaPrivateKey) -> Result<Vec<u8>>;

    /// Encrypt some data using an RSA public key.
    fn rsa_encrypt(&self, plaintext: &[u8], key: &RsaPublicKey) -> Result<Vec<u8>>;

    /// Decrypt some data using an RSA private key.
    fn rsa_decrypt(&self, ciphertext: &[u8], key: &RsaPrivateKey) -> Result<Vec<u8>>;

    // ----- AES -----
    /// Construct an AES-256 cipher from a byte array and IV.
    fn construct_aes_cipher(&self, key: &[u8], iv: &[u8; 16]) -> Result<Box<dyn StreamCipher>>;

    /// Create a new AES-256 key from scratch.
    fn create_new_aes_key(&self) -> Result<[u8; 32]>;

    /// Encrypt some data using an AES key.
    fn aes_encrypt(&self, cipher: &mut dyn StreamCipher, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt some data using an AES key.
    fn aes_decrypt(&self, cipher: &mut dyn StreamCipher, ciphertext: &[u8]) -> Result<Vec<u8>>;
}
