use std::error::Error;
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum AtError {
    ServerException,
    DatastoreException,
    InvalidSyntax,
    SocketError,
    BufferLimitExceeded,
    HandshakeFailure,
    UnauthorizedClient,
    InternalServerError,
    InternalServerException,
    InboundConnectionLimitExceeded,
    ClientAuthenticationFailed,
    ConnectionException,
    UnknownAtClientException,
    KeyNotFound,
    UnableToConnectToSecondary,
}

impl AtError {
    pub fn from_code(code: &str) -> AtError {
        match code {
            "AT0001" => AtError::ServerException,
            "AT0002" => AtError::DatastoreException,
            "AT0003" => AtError::InvalidSyntax,
            "AT0004" => AtError::SocketError,
            "AT0005" => AtError::BufferLimitExceeded,
            "AT0008" => AtError::HandshakeFailure,
            "AT0009" => AtError::UnauthorizedClient,
            "AT0010" => AtError::InternalServerError,
            "AT0011" => AtError::InternalServerException,
            "AT0012" => AtError::InboundConnectionLimitExceeded,
            "AT0401" => AtError::ClientAuthenticationFailed,
            "AT0013" => AtError::ConnectionException,
            "AT0014" => AtError::UnknownAtClientException,
            "AT0015" => AtError::KeyNotFound,
            "AT0021" => AtError::UnableToConnectToSecondary,
            _ => AtError::UnknownAtClientException,
        }
    }
}

impl fmt::Display for AtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AtError::ServerException => write!(f, "AT0001: Server exception"),
            AtError::DatastoreException => write!(f, "AT0002: Datastore exception"),
            AtError::InvalidSyntax => write!(f, "AT0003: Invalid syntax"),
            AtError::SocketError => write!(f, "AT0004: Socket error"),
            AtError::BufferLimitExceeded => write!(f, "AT0005: Buffer limit exceeded"),
            AtError::HandshakeFailure => write!(f, "AT0008: Handshake failure"),
            AtError::UnauthorizedClient => write!(f, "AT0009: Unauthorized client in the request"),
            AtError::InternalServerError => write!(f, "AT0010: Internal server error"),
            AtError::InternalServerException => write!(f, "AT0011: Internal server exception"),
            AtError::InboundConnectionLimitExceeded => {
                write!(f, "AT0012: Inbound connection limit exceeded")
            }
            AtError::ClientAuthenticationFailed => {
                write!(f, "AT0401: Client authentication failed")
            }
            AtError::ConnectionException => write!(f, "AT0013: Connection exception"),
            AtError::UnknownAtClientException => write!(f, "AT0014: Unknown AtClient exception"),
            AtError::KeyNotFound => write!(f, "AT0015: Key not found"),
            AtError::UnableToConnectToSecondary => {
                write!(f, "AT0021: Unable to connect to secondary")
            } // Match additional error codes here
        }
    }
}

impl Error for AtError {}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_error_from_code() {
        let error = AtError::from_code("AT0001");
        assert_eq!(error, AtError::ServerException);
    }

    #[test]
    fn test_error_display() {
        let error = AtError::from_code("AT0001");
        assert_eq!(error.to_string(), "AT0001: Server exception");
    }
}
