use crypto_functions_trait::CryptoFunctions;

pub mod crypto_functions_trait;

/// AtChops is a library that provides a set of high-level cryptographic functions needed within the Atsign protocol.
struct AtChops<T: CryptoFunctions> {
    crypto_service: T,
}

impl<T: CryptoFunctions> AtChops<T> {
    pub fn new(crypto_service: T) -> Self {
        Self { crypto_service }
    }
}
