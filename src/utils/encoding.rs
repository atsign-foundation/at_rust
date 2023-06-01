use std::println;

use crypto::{aes::KeySize, symmetriccipher::SynchronousStreamCipher};

use base64::{engine::general_purpose, Engine as _};
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};

/// Convert a base64 string to a vector of bytes.
/// Although this just calls another function, the naming is clearer.
pub fn decode_base64_text(text: &str) -> Vec<u8> {
    general_purpose::STANDARD
        .decode(&text)
        .expect("Failed to decode base64 text")
}

/// Convert a vector of bytes to a base64 string.
/// Although this just calls another function, the naming is clearer.
pub fn encode_base64_text(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Generate an AES key from a decoded key.
pub fn generate_aes_key(decoded_key: &Vec<u8>) -> Box<dyn SynchronousStreamCipher> {
    // The IV is all zeroes. This is how it is done at AtSign.
    let iv: [u8; 16] = [0x00; 16];
    crypto::aes::ctr(KeySize::KeySize256, decoded_key, &iv)
}

/// Decrypt a private key using an AES key.
pub fn decrypt_private_key(
    cypher: &mut Box<dyn SynchronousStreamCipher>,
    encrypted_key: &str,
) -> String {
    let decoded_key = decode_base64_text(encrypted_key);
    // Input size == output size
    let mut output: Vec<u8> = vec![0; decoded_key.len()];
    cypher.process(&decoded_key, &mut output);
    let last = output.last().unwrap();
    output.truncate(output.len() - usize::from(*last));
    encode_base64_text(&output)
}

pub fn create_aes_key(encoded_key: &str) {
    let decoded_key = decode_base64_text(encoded_key);
    let rsa_key =
        RsaPrivateKey::from_pkcs8_der(&decoded_key).expect("Unable to create RSA Private Key");
    rsa_key.validate().expect("Invalid RSA Private Key");
}

#[cfg(test)]
mod test {

    use std::print;

    use super::*;

    // ----- Test data ------
    // "Hello World!" in base64
    const TEST_KEY_ENCODED: &str = "SGVsbG8gV29ybGQh";
    // "Hello World!" in bytes
    const TEST_KEY_DECODED: [u8; 12] = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33];
    // Self encryption key base64 encoded
    const SELF_ENCRYPTION_KEY_ENCODED: &str = "LXgXrG4oWQQTa1EpDvkTs3EE83qsyICgrpoWLVYEwbo=";
    // const SELF_ENCRYPTION_KEY_ENCODED: &str = "0sjAm3Qd/KS0QyVjFuSWymITKCgkOmpg7RD3afo0UuA=";
    // Expected result of decoding "Hello World!" with the self encryption key
    const SELF_ENCRYPTION_DECRYPT_RESULT: [u8; 12] = [
        0x5e, 0xbf, 0xba, 0x9b, 0x8e, 0xa0, 0xfe, 0xee, 0x66, 0xd, 0xd9, 0x6c,
    ];
    // Pkam key base64 encoded with self encryption key (input)
    const PKAM_KEY_ENCRYPTED_AND_ENCODED: &str = "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";
    // const PKAM_KEY_ENCODED: &str = "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";
    // Pkam key decoded and converted to utf-8/ASCII (expected output)
    const PKAM_KEY_DECRYPTED_AND_ENCODED: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZw9RGU0SnB7hJz5D38SkZjT2mEYt3LTT7NexdzGnX+qkuSwuS7iqICS8cLb0KW2yNaRbWrG2w5wCBFcQ6LPyyiQWAmod2F3LH3c3k06+yC/hw/EhiJqdYOW1Up3WjG4JRzC3G+dIpwMXtScu9AVFJqARPc0j/w8xTYsTTPfsf5A7gFpPRJd/NBZJEpQxZjW5fCRFP+zKFhVEkPHE5rtyVM5Vz4pK6D2ziFoNJdIbme1gWVC4beS4qqbKpLyzfHkfWGSWy/4gEEJZflnWsKVs+wPjNIljsUMAlEMqNzqmuDW0GFc7KNWAK3cKs8CEEGQuqik0xuTROD4JyMPP6nNGvAgMBAAECggEAFA2hCobjhjEQjLfAPUW7SXTNHHJfUOyZY0W2DMmS6DLti3cIDGJ5M4KXHUKty8L+ljalXtvf9lk6DJutGrUxQ4txJ0N/9Ru7wWsg5f3hhQPgo8OTIRHPc0cSBh9MzTfSOB67vZ5pFT7p0Td1lbGtS0DZRw9O7uQ3KozQBIipzo+4y3SaWsPshohSSMjeyKXfEQcy4RwDC+/bX8+pR7jLzkIqqILUs3vuRNAcPLxs5+FK3S/LJmnkhXV+7+tUuHIpl6mDgfhWDUKaOFzq+0cbzS15EJXW6YYdlPdbrj24JYbkUQHxYSEvxnR2+OOtj5HVQnIaNEPf9s0KW8IMLys7aQKBgQDJTnpdVqtN4M2Zuj8bN8ew1x6LkrqLV8EtlxQbn+kLgzmqqj56v6NVXHaxZh3OaIBoHpAQGPR26UAOBcXT5k1PhQ92RAqXh8/dbV+iBrnBjubQawZ3TK2yjclZMuFCW+/tyB6dOwDi+cO/IfBAh5P+mWHOZOa9y+dL2KjVSzL1TQKBgQDDiq3rjrAlPjtcZcMit4r7p4mZtUI0tCJEzt8J/YK9AC+A+g8Lxz7IKCH1vscFhQNU5E65omatCAYpGo17AQ59hLtbC0f3PJXNQTGLfGYiFHPsmOTf4B9w0c6ge1LPPzbfAG+1fvQ+iaa+4d7yNek3OyuH7KiknUN3AKyiFAo06wKBgAP0BZUlqZGK856sOKcJLmO7pb7p773iyElj6SItvr7aIdzHIRj6AHQhr7cGIVm3VaY1y3B1fP+Ezxw3Ys4pfKUuIMKazXZyVVOs3S7qYOV7L+8x2tum5tZV0Hlu9Vt/QLPztR4zVW4fp4duXDB4OSDL1E7gTmO1yGIF7DLcGjEVAoGBAJFiDEk0v3YRPOVHq7umJylPuRiVEXJJ86ig/mdZGtkWyDrmsEUbkGwUmpsxiptp974oOPf/7ML9UkdBPKuVb4aXJw1b59fELcR7kjCY/v6bokzoqFJjOj0RYMUkq772yv8mPef9Se8tPNJy8OW4e3ra/VSD+ibZ3g0ebTvcFnKdAoGAIGHTlkKJmP8nyRNSDceBnwRvqLPt7AC32kSxTl9mqVgYn8Slz+L33dixiMOL8/T/+JY5XxX/iQepBL/wmuxy6O+QoLxoJBIux7qoyYHyoKuOTaXbVs79dREIh/GHf0uQKGQ2MB6FJAuKgzBKyJYjkCf9t/KA2Ja3gxlYnwHBpcw=";

    // ----- Tests ------
    #[test]
    fn decode_base64_text_test() {
        let actual = decode_base64_text(TEST_KEY_ENCODED);
        assert_eq!(actual, TEST_KEY_DECODED);
    }

    #[test]
    fn encode_base64_text_test() {
        let actual = encode_base64_text(&TEST_KEY_DECODED);
        assert_eq!(actual, TEST_KEY_ENCODED);
    }

    #[test]
    fn generate_aes_key_test() {
        let binding = String::from("Hello World!");
        let input = binding.as_bytes();

        let decoded_key = decode_base64_text(SELF_ENCRYPTION_KEY_ENCODED);

        let mut cipher = generate_aes_key(&decoded_key);
        let mut output: Vec<u8> = vec![0; input.len()];

        cipher.process(input, &mut output);

        assert_eq!(output, SELF_ENCRYPTION_DECRYPT_RESULT);
    }

    #[test]
    fn decrypt_private_key_test() {
        let mut cipher = generate_aes_key(&decode_base64_text(SELF_ENCRYPTION_KEY_ENCODED));
        let output = decrypt_private_key(&mut cipher, PKAM_KEY_ENCRYPTED_AND_ENCODED);
        let output_decoded = String::from_utf8(decode_base64_text(&output)).unwrap();
        // println!("output_decoded: {:x?}", output_decoded.as_bytes());
        // println!("expected: {:x?}", PKAM_KEY_DECODED.as_bytes());
        assert_eq!(output_decoded, PKAM_KEY_DECRYPTED_AND_ENCODED);
    }

    #[test]
    fn create_aes_key_test() {
        let mut cipher = generate_aes_key(&decode_base64_text(SELF_ENCRYPTION_KEY_ENCODED));
        let output = decrypt_private_key(&mut cipher, PKAM_KEY_ENCRYPTED_AND_ENCODED);
        create_aes_key(&String::from_utf8(decode_base64_text(&output)).unwrap());
    }
}
