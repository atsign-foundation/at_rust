//use std::iter::repeat;

use crypto::{aes::KeySize, symmetriccipher::SynchronousStreamCipher};

use base64::{engine::general_purpose, Engine as _};
use log::info;
use rsa::{
    pkcs1v15::SigningKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    sha2::Sha256,
    signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};

/// Convert a base64 encoded string to a vector of bytes.
/// Although this just calls another function, the naming is clearer.
pub fn base64_decode(data: &str) -> Vec<u8> {
    general_purpose::STANDARD
        .decode(data)
        .expect("Failed to decode base64 text")
}

/// Convert a slice of bytes to a base64 encoded string.
/// Although this just calls another function, the naming is clearer.
pub fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Construct an AES key from a key.
pub fn construct_aes_key(data: &[u8], iv: &[u8; 16]) -> Box<dyn SynchronousStreamCipher> {
    crypto::aes::ctr(KeySize::KeySize256, data, iv)
}

/// Construct an RSA private key from a decoded key.
pub fn construct_rsa_private_key(data: &[u8]) -> RsaPrivateKey {
    let rsa_key = RsaPrivateKey::from_pkcs8_der(&data).expect("Unable to create RSA Private Key");
    rsa_key.validate().expect("Invalid RSA Private Key");
    rsa_key
}

/// Construct an RSA public key from a decoded key.
pub fn construct_rsa_public_key(data: &[u8]) -> RsaPublicKey {
    let rsa_key =
        RsaPublicKey::from_public_key_der(&data).expect("Unable to create RSA Public Key");
    rsa_key
}

/// Sign data using an RSA private key.
/// This returns a base64 encoded string.
pub fn rsa_sign(key: RsaPrivateKey, data: &[u8]) -> String {
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::<Sha256>::new(key);
    let verifying_key = signing_key.verifying_key();

    // Sign
    let signature = signing_key.sign_with_rng(&mut rng, &data);
    verifying_key
        .verify(&data, &signature)
        .expect("failed to verify");
    let binding = signature.to_bytes();
    let signature_bytes = binding.as_ref();

    // Encode signature
    let sha256_signature_encoded = base64_encode(&signature_bytes);
    sha256_signature_encoded
}

/// Create a new AES-256 key from scratch.
pub fn create_new_aes_key() -> [u8; 32] {
    let key: [u8; 32] = rand::random();
    key
}

/// Encrypt some data using an RSA public key.
pub fn encrypt_with_public_key(public_key: &RsaPublicKey, data: &[u8]) -> String {
    let mut rng = rand::thread_rng();
    let encrypted_symmetric_key = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, data)
        .expect("Failed to encrypt symmetric key");
    base64_encode(&encrypted_symmetric_key)
}

/// Decrypt an AES key using an RSA private key.
pub fn decrypt_symm_key_with_private_key(private_key: &RsaPrivateKey, symm_key: &[u8]) -> String {
    let decrypted_symmetric_key = private_key
        .decrypt(Pkcs1v15Encrypt, symm_key)
        .expect("Failed to decrypt symmetric key");
    String::from_utf8(decrypted_symmetric_key).expect("Failed to convert decrypted key to string")
}

/// Encrypt some data using an AES key.
pub fn encrypt_data_with_aes_key(
    aes_key: &mut Box<dyn SynchronousStreamCipher>,
    data: &[u8],
) -> Vec<u8> {
    let data_len = data.len();
    let mut padding_len = 16 - (data_len % 16);
    if padding_len == 0 {
        // There is always at least 1 byte of padding - https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method
        padding_len = 16;
    }
    // Construct padding
    let padding: Vec<u8> = vec![padding_len as u8; padding_len];
    // Collect data into a mut vec so the padding can be appended
    let mut new_data = data.to_vec();
    new_data.extend(padding);
    // Process
    let mut output: Vec<u8> = vec![0; new_data.len()];
    aes_key.process(&new_data, &mut output);
    output
}

/// Decrypt some data using an AES key.
pub fn decrypt_data_with_aes_key(
    aes_key: &mut Box<dyn SynchronousStreamCipher>,
    data: &[u8],
) -> Vec<u8> {
    let mut output: Vec<u8> = vec![0; data.len()];
    aes_key.process(&data, &mut output);
    // Remove padding due to PkCS#7 padding used by other SDKs
    let last = output.last().unwrap();
    output.truncate(output.len() - usize::from(*last));
    output
}

#[cfg(test)]
mod test {

    use super::*;

    // ----- Test data ------
    // "Hello World!" in base64
    const TEST_KEY_ENCODED: &str = "SGVsbG8gV29ybGQh";
    // "Hello World!" in bytes
    const TEST_KEY_DECODED: [u8; 12] = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33];
    // Self encryption key base64 encoded
    const SELF_ENCRYPTION_KEY_ENCODED: &str = "LXgXrG4oWQQTa1EpDvkTs3EE83qsyICgrpoWLVYEwbo=";
    // Expected result of decoding "Hello World!" with the self encryption key
    const SELF_ENCRYPTION_DECRYPT_RESULT: [u8; 12] = [
        0x5e, 0xbf, 0xba, 0x9b, 0x8e, 0xa0, 0xfe, 0xee, 0x66, 0xd, 0xd9, 0x6c,
    ];
    // Pkam key decoded and converted to utf-8 from bytes (expected output)
    const PKAM_KEY_DECRYPTED_AND_ENCODED: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZw9RGU0SnB7hJz5D38SkZjT2mEYt3LTT7NexdzGnX+qkuSwuS7iqICS8cLb0KW2yNaRbWrG2w5wCBFcQ6LPyyiQWAmod2F3LH3c3k06+yC/hw/EhiJqdYOW1Up3WjG4JRzC3G+dIpwMXtScu9AVFJqARPc0j/w8xTYsTTPfsf5A7gFpPRJd/NBZJEpQxZjW5fCRFP+zKFhVEkPHE5rtyVM5Vz4pK6D2ziFoNJdIbme1gWVC4beS4qqbKpLyzfHkfWGSWy/4gEEJZflnWsKVs+wPjNIljsUMAlEMqNzqmuDW0GFc7KNWAK3cKs8CEEGQuqik0xuTROD4JyMPP6nNGvAgMBAAECggEAFA2hCobjhjEQjLfAPUW7SXTNHHJfUOyZY0W2DMmS6DLti3cIDGJ5M4KXHUKty8L+ljalXtvf9lk6DJutGrUxQ4txJ0N/9Ru7wWsg5f3hhQPgo8OTIRHPc0cSBh9MzTfSOB67vZ5pFT7p0Td1lbGtS0DZRw9O7uQ3KozQBIipzo+4y3SaWsPshohSSMjeyKXfEQcy4RwDC+/bX8+pR7jLzkIqqILUs3vuRNAcPLxs5+FK3S/LJmnkhXV+7+tUuHIpl6mDgfhWDUKaOFzq+0cbzS15EJXW6YYdlPdbrj24JYbkUQHxYSEvxnR2+OOtj5HVQnIaNEPf9s0KW8IMLys7aQKBgQDJTnpdVqtN4M2Zuj8bN8ew1x6LkrqLV8EtlxQbn+kLgzmqqj56v6NVXHaxZh3OaIBoHpAQGPR26UAOBcXT5k1PhQ92RAqXh8/dbV+iBrnBjubQawZ3TK2yjclZMuFCW+/tyB6dOwDi+cO/IfBAh5P+mWHOZOa9y+dL2KjVSzL1TQKBgQDDiq3rjrAlPjtcZcMit4r7p4mZtUI0tCJEzt8J/YK9AC+A+g8Lxz7IKCH1vscFhQNU5E65omatCAYpGo17AQ59hLtbC0f3PJXNQTGLfGYiFHPsmOTf4B9w0c6ge1LPPzbfAG+1fvQ+iaa+4d7yNek3OyuH7KiknUN3AKyiFAo06wKBgAP0BZUlqZGK856sOKcJLmO7pb7p773iyElj6SItvr7aIdzHIRj6AHQhr7cGIVm3VaY1y3B1fP+Ezxw3Ys4pfKUuIMKazXZyVVOs3S7qYOV7L+8x2tum5tZV0Hlu9Vt/QLPztR4zVW4fp4duXDB4OSDL1E7gTmO1yGIF7DLcGjEVAoGBAJFiDEk0v3YRPOVHq7umJylPuRiVEXJJ86ig/mdZGtkWyDrmsEUbkGwUmpsxiptp974oOPf/7ML9UkdBPKuVb4aXJw1b59fELcR7kjCY/v6bokzoqFJjOj0RYMUkq772yv8mPef9Se8tPNJy8OW4e3ra/VSD+ibZ3g0ebTvcFnKdAoGAIGHTlkKJmP8nyRNSDceBnwRvqLPt7AC32kSxTl9mqVgYn8Slz+L33dixiMOL8/T/+JY5XxX/iQepBL/wmuxy6O+QoLxoJBIux7qoyYHyoKuOTaXbVs79dREIh/GHf0uQKGQ2MB6FJAuKgzBKyJYjkCf9t/KA2Ja3gxlYnwHBpcw=";
    // Challenge text
    const CHALLENGE_TEXT: &str =
        "_6e27e164-e45b-4ae1-8714-7545d36b6ed4@aliens12:9ef2ec2c-39d4-4e25-825e-0da05f6e0bb9";
    // Expected result of signing the challenge text
    const CHALLENGE_RESULT: &str = "aTY5Pxod1hzv/9uL9FSqxbmmCT73vFEBRv4qA+k+d6U5hcglzYvAl1MJNY2eQLTFLoFIkx/3pgm0YkjI4aS1hBAyBmMIinGrPGbOuR3PebPqITLhNWdeWZamHrlKY8tjvARtb4k0gb2LgauzhNq3zzm5aS7EU7OYaRy22/fR5fCWXw+ZyFdRYhA9qlFcA7ksct3pJwHSvSlQb2R7YuzN210Xfii43yAgtncz4CUZRcxPL7AD4mUg7dSMu0RMVKIQKsecwhNfh7bgy1zFDGMpOP8DQJ8tJfQiut5u+0yAGM4O31FJ+F7/1pvR0pgr7/O0/4K+BdhdRWNVine335u6lg==";
    // Public encryption key base64 encoded and decrypted with self encryption key
    const PUBLIC_ENCRYPTION_KEY: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgcEdJDDvEzAC92N0dKIvgGIh9ddJ4xccDm5QqdsdnaYXygzygjfWUzdKrEkrisQIQBRJwEQd50jths5Rg46f0fowOT2gg3OTpMo0GaQLQagZoYuMiUcsuho6ig3ahsdPq21vz1tTT92rbI+l7477tsG7y+w5jDbDF6kvKfLYs8Ga73Jbwm55yg3ibNJjsiLGa6bg+5Y9pxXxzggURKn+m5h77PDCgCiTd7zLb4L9vsRm6ijdpnuekVGIgqGZO6xUOEYOonmqDjlw8BQagu31Z5NlvhWoCQv1UUPaDOm34R2uUeWt1PWe/AUih02c3GdtIcUyqK8E1GkCHfhFD27CtwIDAQAB";

    // ----- Tests ------
    #[test]
    fn decode_base64_text_test() {
        let actual = base64_decode(TEST_KEY_ENCODED);
        assert_eq!(actual, TEST_KEY_DECODED);
    }

    #[test]
    fn encode_base64_text_test() {
        let actual = base64_encode(&TEST_KEY_DECODED);
        assert_eq!(actual, TEST_KEY_ENCODED);
    }

    #[test]
    fn construct_aes_key_test() {
        // Arrange
        let binding = String::from("Hello World!");
        let input = binding.as_bytes();
        let decoded_key = base64_decode(SELF_ENCRYPTION_KEY_ENCODED);

        // Act
        let iv: [u8; 16] = [0x00; 16];
        let mut cipher = construct_aes_key(&decoded_key, &iv);
        let mut output: Vec<u8> = vec![0; input.len()];
        cipher.process(input, &mut output);

        // Assert
        assert_eq!(output, SELF_ENCRYPTION_DECRYPT_RESULT);
    }

    #[test]
    fn construct_rsa_private_key_test() {
        // Arrange
        let private_key = base64_decode(&PKAM_KEY_DECRYPTED_AND_ENCODED);
        // Act
        let _ = construct_rsa_private_key(&private_key);
        // Assert it doesn't panic
    }

    #[test]
    fn construct_rsa_public_key_test() {
        // Arrange
        let public_key = base64_decode(&PUBLIC_ENCRYPTION_KEY);
        // Act
        let _ = construct_rsa_public_key(&public_key);
        // Assert it doesn't panic
    }

    #[test]
    fn rsa_sign_test() {
        // Arrange
        let private_key = base64_decode(&PKAM_KEY_DECRYPTED_AND_ENCODED);
        let rsa_key = construct_rsa_private_key(&private_key);
        // Act
        let decrypted = rsa_sign(rsa_key, CHALLENGE_TEXT.as_bytes());
        // Assert
        assert_eq!(decrypted, CHALLENGE_RESULT);
    }

    #[test]
    fn create_new_aes_key_test() {
        let key = create_new_aes_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn encrypt_with_public_key_test() {
        let public_key = base64_decode(&PUBLIC_ENCRYPTION_KEY);
        let public_key = construct_rsa_public_key(&public_key);
        let _ = encrypt_with_public_key(&public_key, &TEST_KEY_DECODED);
        // Assert it doesn't panic.
    }
}
