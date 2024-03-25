use rustls::{ClientConfig, ClientConnection, StreamOwned};
use std::io::{Read, Result, Write};
use std::net::TcpStream;
use std::sync::Arc;

use crate::at_server_addr::AtServerAddr;
use crate::tls_connection_trait::TlsConnection;

pub struct RustlsConnection {
    stream: StreamOwned<ClientConnection, TcpStream>,
}

impl RustlsConnection {
    fn new(stream: StreamOwned<ClientConnection, TcpStream>) -> Self {
        RustlsConnection { stream }
    }
}

impl TlsConnection for RustlsConnection {
    fn connect(address: &AtServerAddr) -> Result<Self> {
        // TODO: Allow custom root certificates
        // Create the config with default root certificates
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let rc_config = Arc::new(config);
        // Create a DNS name from the at sign server address (i.e. the host)
        let dns_name = address.host.to_owned().try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid DNS name")
        })?;
        let session = ClientConnection::new(rc_config, dns_name)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e))?;

        // Create a standard TCP stream and wrap it with the TLS session
        let tcp_stream = TcpStream::connect(address)?;

        // StreamOwned is a wrapper around a stream that implements Read and Write
        let tls_stream = StreamOwned::new(session, tcp_stream);

        Ok(RustlsConnection::new(tls_stream))
    }
}

impl Read for RustlsConnection {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for RustlsConnection {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.stream.flush()
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_connect() {
        fn create_subject() -> Result<RustlsConnection> {
            let address = AtServerAddr::new(String::from("google.com"), 80);
            RustlsConnection::connect(&address)
        }

        let subject = create_subject();
        assert!(subject.is_ok())
    }

    #[test]
    fn test_fail_connect() {
        fn create_subject() -> Result<RustlsConnection> {
            let address = AtServerAddr::new(String::from("google12345.co"), 8080);
            RustlsConnection::connect(&address)
        }

        let subject = create_subject();
        assert!(subject.is_err())
    }
}
