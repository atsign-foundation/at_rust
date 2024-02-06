//use log::{info, warn};

use super::utils::{
    base64_decode, base64_encode, construct_aes_key, construct_rsa_private_key,
    construct_rsa_public_key, create_new_aes_key, decrypt_data_with_aes_key,
    decrypt_symm_key_with_private_key, encrypt_data_with_aes_key, encrypt_with_public_key,
    rsa_sign,
};

/// Base64 decode the self encryption key.
pub fn decode_self_encryption_key(self_encryption_key: &str) -> Vec<u8> {
    base64_decode(self_encryption_key)
}

/// Decrypt the private key using the self encryption key.
pub fn decrypt_private_key(
    encrypted_private_key: &str,
    decoded_self_encryption_key: &[u8],
) -> String {
    let iv: [u8; 16] = [0x00; 16];
    let mut cypher = construct_aes_key(decoded_self_encryption_key, &iv);
    let decoded_private_key = base64_decode(encrypted_private_key);

    let mut output: Vec<u8> = vec![0; decoded_private_key.len()];
    cypher.process(&decoded_private_key, &mut output);

    // NOTE: Due to the PKCS#7 type of encryption used (on the keys), the output will have padding

    // NOTE: Might be worth converting to a char type then using .is_ascii_hexdigit() (or similar)

    // Get the last byte, which is the number of padding bytes
    let last = output.last().unwrap();
    output.truncate(output.len() - usize::from(*last));
    String::from_utf8(output).expect("Unable to convert to UTF-8")
}

/// Sign a given challenge with the decrypted private key.
pub fn sign_challenge(challenge: &str, decrypted_private_key: &str) -> String {
    let decoded_private_key = base64_decode(decrypted_private_key);
    let rsa_private_key = construct_rsa_private_key(&decoded_private_key);
    rsa_sign(rsa_private_key, challenge.as_bytes())
}

/// Cut a new symmetric key to be used when interacting with a new atSign.
pub fn create_new_shared_symmetric_key() -> String {
    let key = create_new_aes_key();
    base64_encode(&key)
}

/// Decrypt the symmetric key with "our" private key.
pub fn decrypt_symmetric_key(encrypted_symmetric_key: &str, decrypted_private_key: &str) -> String {
    let decoded_private_key = base64_decode(decrypted_private_key);
    let rsa_private_key = construct_rsa_private_key(&decoded_private_key);
    let decoded_symmetric_key = base64_decode(encrypted_symmetric_key);
    decrypt_symm_key_with_private_key(&rsa_private_key, &decoded_symmetric_key)
}

/// Encrypt data with our RSA public key.
pub fn encrypt_data_with_public_key(encoded_public_key: &str, data: &str) -> String {
    let decoded_public_key = base64_decode(encoded_public_key);
    let rsa_public_key = construct_rsa_public_key(&decoded_public_key);
    let encrypted_data = encrypt_with_public_key(&rsa_public_key, data.as_bytes());
    encrypted_data
}

/// Encrypt data with AES symm key.
pub fn encrypt_data_with_shared_symmetric_key(encoded_symmetric_key: &str, data: &str) -> String {
    let decoded_symmetric_key = base64_decode(encoded_symmetric_key);
    let iv: [u8; 16] = [0x00; 16];
    let mut cypher = construct_aes_key(&decoded_symmetric_key, &iv);
    let encrypted_data = encrypt_data_with_aes_key(&mut cypher, data.as_bytes());
    base64_encode(&encrypted_data)
}

/// Decrypt data with an encoded AES symm key.
pub fn decrypt_data_with_shared_symmetric_key(encoded_symmetric_key: &str, data: &str) -> String {
    let decoded_symmetric_key = base64_decode(encoded_symmetric_key);
    let iv: [u8; 16] = [0x00; 16];
    let mut cypher = construct_aes_key(&decoded_symmetric_key, &iv);
    let decoded_data = base64_decode(data);
    let decrypted_data = decrypt_data_with_aes_key(&mut cypher, &decoded_data);
    String::from_utf8(decrypted_data).expect("Unable to convert to UTF-8")
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
    // Pkam key base64 encoded with self encryption key (input)
    const PKAM_KEY_ENCRYPTED_AND_ENCODED: &str = "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";
    // Pkam key decoded and converted to utf-8 from bytes (expected output)
    const PKAM_KEY_DECRYPTED_AND_ENCODED: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZw9RGU0SnB7hJz5D38SkZjT2mEYt3LTT7NexdzGnX+qkuSwuS7iqICS8cLb0KW2yNaRbWrG2w5wCBFcQ6LPyyiQWAmod2F3LH3c3k06+yC/hw/EhiJqdYOW1Up3WjG4JRzC3G+dIpwMXtScu9AVFJqARPc0j/w8xTYsTTPfsf5A7gFpPRJd/NBZJEpQxZjW5fCRFP+zKFhVEkPHE5rtyVM5Vz4pK6D2ziFoNJdIbme1gWVC4beS4qqbKpLyzfHkfWGSWy/4gEEJZflnWsKVs+wPjNIljsUMAlEMqNzqmuDW0GFc7KNWAK3cKs8CEEGQuqik0xuTROD4JyMPP6nNGvAgMBAAECggEAFA2hCobjhjEQjLfAPUW7SXTNHHJfUOyZY0W2DMmS6DLti3cIDGJ5M4KXHUKty8L+ljalXtvf9lk6DJutGrUxQ4txJ0N/9Ru7wWsg5f3hhQPgo8OTIRHPc0cSBh9MzTfSOB67vZ5pFT7p0Td1lbGtS0DZRw9O7uQ3KozQBIipzo+4y3SaWsPshohSSMjeyKXfEQcy4RwDC+/bX8+pR7jLzkIqqILUs3vuRNAcPLxs5+FK3S/LJmnkhXV+7+tUuHIpl6mDgfhWDUKaOFzq+0cbzS15EJXW6YYdlPdbrj24JYbkUQHxYSEvxnR2+OOtj5HVQnIaNEPf9s0KW8IMLys7aQKBgQDJTnpdVqtN4M2Zuj8bN8ew1x6LkrqLV8EtlxQbn+kLgzmqqj56v6NVXHaxZh3OaIBoHpAQGPR26UAOBcXT5k1PhQ92RAqXh8/dbV+iBrnBjubQawZ3TK2yjclZMuFCW+/tyB6dOwDi+cO/IfBAh5P+mWHOZOa9y+dL2KjVSzL1TQKBgQDDiq3rjrAlPjtcZcMit4r7p4mZtUI0tCJEzt8J/YK9AC+A+g8Lxz7IKCH1vscFhQNU5E65omatCAYpGo17AQ59hLtbC0f3PJXNQTGLfGYiFHPsmOTf4B9w0c6ge1LPPzbfAG+1fvQ+iaa+4d7yNek3OyuH7KiknUN3AKyiFAo06wKBgAP0BZUlqZGK856sOKcJLmO7pb7p773iyElj6SItvr7aIdzHIRj6AHQhr7cGIVm3VaY1y3B1fP+Ezxw3Ys4pfKUuIMKazXZyVVOs3S7qYOV7L+8x2tum5tZV0Hlu9Vt/QLPztR4zVW4fp4duXDB4OSDL1E7gTmO1yGIF7DLcGjEVAoGBAJFiDEk0v3YRPOVHq7umJylPuRiVEXJJ86ig/mdZGtkWyDrmsEUbkGwUmpsxiptp974oOPf/7ML9UkdBPKuVb4aXJw1b59fELcR7kjCY/v6bokzoqFJjOj0RYMUkq772yv8mPef9Se8tPNJy8OW4e3ra/VSD+ibZ3g0ebTvcFnKdAoGAIGHTlkKJmP8nyRNSDceBnwRvqLPt7AC32kSxTl9mqVgYn8Slz+L33dixiMOL8/T/+JY5XxX/iQepBL/wmuxy6O+QoLxoJBIux7qoyYHyoKuOTaXbVs79dREIh/GHf0uQKGQ2MB6FJAuKgzBKyJYjkCf9t/KA2Ja3gxlYnwHBpcw=";
    // Challenge text
    const CHALLENGE_TEXT: &str =
        "_6e27e164-e45b-4ae1-8714-7545d36b6ed4@aliens12:9ef2ec2c-39d4-4e25-825e-0da05f6e0bb9";
    // Expected result of signing the challenge text
    const CHALLENGE_RESULT: &str = "aTY5Pxod1hzv/9uL9FSqxbmmCT73vFEBRv4qA+k+d6U5hcglzYvAl1MJNY2eQLTFLoFIkx/3pgm0YkjI4aS1hBAyBmMIinGrPGbOuR3PebPqITLhNWdeWZamHrlKY8tjvARtb4k0gb2LgauzhNq3zzm5aS7EU7OYaRy22/fR5fCWXw+ZyFdRYhA9qlFcA7ksct3pJwHSvSlQb2R7YuzN210Xfii43yAgtncz4CUZRcxPL7AD4mUg7dSMu0RMVKIQKsecwhNfh7bgy1zFDGMpOP8DQJ8tJfQiut5u+0yAGM4O31FJ+F7/1pvR0pgr7/O0/4K+BdhdRWNVine335u6lg==";

    #[test]
    fn decode_self_encryption_key_test() {
        let result = decode_self_encryption_key(TEST_KEY_ENCODED);
        assert_eq!(result, TEST_KEY_DECODED);
    }

    #[test]
    fn decrypt_private_key_test() {
        let self_encryption_key = decode_self_encryption_key(SELF_ENCRYPTION_KEY_ENCODED);
        let result = decrypt_private_key(PKAM_KEY_ENCRYPTED_AND_ENCODED, &self_encryption_key);
        assert_eq!(result, PKAM_KEY_DECRYPTED_AND_ENCODED);
    }

    #[test]
    fn sign_challenge_test() {
        let result = sign_challenge(CHALLENGE_TEXT, PKAM_KEY_DECRYPTED_AND_ENCODED);
        assert_eq!(result, CHALLENGE_RESULT);
    }

    #[test]
    fn create_new_shared_symmetric_key_test() {
        let result = create_new_shared_symmetric_key();
        assert_eq!(result.len(), 44);
    }
}
