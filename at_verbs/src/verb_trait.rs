use super::prelude::*;

/// The Verb trait is the base trait for all verbs.
///
/// As each verb is a command that can be executed on an atServer,
/// they all have a similar interface but different implementations.
pub trait Verb<'a> {
    type Inputs: 'a;
    type Output;

    /// Execute the verb with the given inputs and tls_client.
    fn execute(tls_client: &mut TlsClient, input: Self::Inputs) -> Result<Self::Output>;

    /// Parse the response from the atServer into a string checking for exception codes.
    fn parse_server_response(response: &[u8]) -> Result<String> {
        // Parse the response into a string
        let response = std::str::from_utf8(response).map_err(|_| {
            error!("Failed to parse server response. Not valid UTF-8");
            AtError::UnknownAtClientException
        })?;

        // Check that it doesn't contain error codes
        if response.starts_with("AT") {
            let (code, _) = response.split_at(6);
            return Err(AtError::from_code(code));
        }

        Ok(response.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVerb;

    impl<'a> Verb<'a> for TestVerb {
        type Inputs = ();
        type Output = ();

        fn execute(_tls_client: &mut TlsClient, _input: Self::Inputs) -> Result<Self::Output> {
            unimplemented!() // Not needed for this test
        }
    }

    #[test]
    fn test_parse_server_response_success() {
        let response = b"OK";
        let result = TestVerb::parse_server_response(response);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "OK");
    }

    #[test]
    fn test_parse_server_response_invalid_utf8() {
        let response = &[0xff, 0xfe, 0xfd]; // Invalid UTF-8 sequence
        let result = TestVerb::parse_server_response(response);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), AtError::UnknownAtClientException);
    }

    #[test]
    fn test_parse_server_response_with_error_code() {
        let response = b"AT0001: Error Message";
        let result = TestVerb::parse_server_response(response);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), AtError::ServerException); // Assuming AT0001 maps to ServerException
    }
}
