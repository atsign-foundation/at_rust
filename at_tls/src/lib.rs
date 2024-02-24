use std::io::{BufRead, BufReader};

use at_server_addr::AtServerAddr;
use log::debug;
use tls_connection_trait::TlsConnection;

pub mod at_server_addr;
pub mod rustls_connection;
pub mod tls_connection_trait;

pub struct TlsClient {
    tls_connection: Box<dyn TlsConnection>,
}

impl TlsClient {
    /// Create a new client. Only for testing.
    pub fn new(tls_connection: Box<dyn TlsConnection>) -> Self {
        Self { tls_connection }
    }

    /// Connects to the specified server address using TLS.
    ///
    /// Returns a new `TlsClient` if the connection is successful.
    pub fn connect<T: TlsConnection + 'static>(address: &AtServerAddr) -> std::io::Result<Self> {
        // TODO: Add a retry mechanism
        let tls_connection = T::connect(address)?;
        Ok(Self {
            tls_connection: Box::new(tls_connection),
        })
    }

    /// Sends data to the server.
    pub fn send_data<U: AsRef<[u8]>>(&mut self, data: U) -> std::io::Result<()> {
        let data_slice = data.as_ref();
        let mut data_with_newline = Vec::with_capacity(data_slice.len() + 1);
        data_with_newline.extend_from_slice(data_slice);
        data_with_newline.push(b'\n');
        debug!(
            "Sending data: {:?}",
            String::from_utf8_lossy(&data_with_newline)
        );
        self.tls_connection.write_all(&data_with_newline)
    }

    /// Reads a line from the stream and returns the bytes.
    pub fn read_data(&mut self) -> std::io::Result<Vec<u8>> {
        let mut res = vec![];
        let mut reader = BufReader::new(&mut self.tls_connection);
        // Newline is the delimiter in the protocol
        let _ = reader.read_until(b'\n', &mut res)?;
        debug!("Reading data: {:?}", String::from_utf8_lossy(&res));
        Ok(res)
    }
}

#[cfg(test)]
mod test {

    use self::rustls_connection::RustlsConnection;

    use super::*;

    fn create_subject() -> std::io::Result<TlsClient> {
        let address = AtServerAddr::new(String::from("root.atsign.org"), 64);
        TlsClient::connect::<RustlsConnection>(&address)
    }

    #[test]
    fn test_connect() {
        let subject = create_subject();
        assert!(subject.is_ok());
    }

    #[test]
    fn test_send_data() {
        let mut subject = create_subject().unwrap();
        let res = subject.send_data(format!("{}\n", String::from("Hello, World!")));
        assert!(res.is_ok());
    }

    #[test]
    fn test_read_data() {
        let mut subject = create_subject().unwrap();
        subject
            .send_data(format!("{}\n", String::from("Hello, World!")))
            .unwrap();
        let res = subject.read_data();
        assert!(res.is_ok());
        assert_eq!(
            String::from_utf8_lossy(&res.unwrap()).trim(),
            String::from("@null")
        );
    }
}
