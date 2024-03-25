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
    /// Also trims the prefix from the response.
    /// This is a default implementation that can be overridden if the verb needs to parse the response differently.
    fn parse_server_response(response: &[u8], prefix: &str) -> Result<String> {
        // Parse the response into a string
        let response = std::str::from_utf8(response).map_err(|e| {
            error!("Failed to parse server response. Not valid UTF-8");
            AtError::UnknownAtClientException(e.to_string())
        })?;

        // Check that it doesn't contain error codes
        if response.starts_with("error") {
            let code = response
                .split_once(':')
                .ok_or(AtError::UnknownAtClientException(String::from(
                    "Unexpected formatting of error message from server",
                )))?
                .1
                .split_at(6)
                .0;
            return Err(AtError::from_code(code));
        }

        // Check that it starts with the expected prefix
        if !response.starts_with(prefix) {
            return Err(AtError::UnknownAtClientException(format!(
                "Unexpected response from server: {}",
                response
            )));
        }

        // Trim the prefix and ":" from the response
        let (_, response) = response.split_at(prefix.len() + 1);

        Ok(response.trim().to_string())
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
        let response = b"data:OK";
        let result = TestVerb::parse_server_response(response, "data");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "OK");
    }

    #[test]
    fn test_parse_server_response_invalid_utf8() {
        let response = &[0xf0, 0x28, 0x8c, 0xbc]; // Invalid UTF-8 sequence
        let result = TestVerb::parse_server_response(response, "data");
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            AtError::UnknownAtClientException(String::from(
                "invalid utf-8 sequence of 1 bytes from index 0",
            ))
        );
    }

    #[test]
    fn test_parse_server_response_with_error_code() {
        let response = b"error:AT0001: Error Message";
        let result = TestVerb::parse_server_response(response, "data");
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), AtError::ServerException); // Assuming AT0001 maps to ServerException
    }
}
