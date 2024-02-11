use std::io::{BufRead, BufReader};

use at_server_addr::AtServerAddr;
use tls_connection_trait::TlsConnection;

pub mod at_server_addr;
mod rustls_connection;
pub mod tls_connection_trait;

pub struct TlsClient<T: TlsConnection> {
    tls_connection: T,
}

impl<T: TlsConnection> TlsClient<T> {
    fn new(tls_connection: T) -> Self {
        TlsClient { tls_connection }
    }

    /// Connects to the specified server address using TLS.
    ///
    /// Returns a new `TlsClient` if the connection is successful.
    pub fn connect(address: &AtServerAddr) -> std::io::Result<Self> {
        let tls_connection = T::connect(address)?;
        Ok(TlsClient::new(tls_connection))
    }

    /// Sends data to the server.
    pub fn send_data<U: AsRef<[u8]>>(&mut self, data: U) -> std::io::Result<()> {
        self.tls_connection.write_all(data.as_ref())
    }

    /// Reads a line from the stream and converts it to a String which is trimmed.
    pub fn read_data(&mut self) -> std::io::Result<String> {
        let mut res = vec![];
        let mut reader = BufReader::new(&mut self.tls_connection);
        let _ = reader.read_until(b'\n', &mut res)?;
        let data = String::from_utf8_lossy(&res).trim().to_owned();
        Ok(data)
    }
}

#[cfg(test)]
mod test {

    use self::rustls_connection::RustlsConnection;

    use super::*;

    fn create_subject() -> std::io::Result<TlsClient<RustlsConnection>> {
        let address = AtServerAddr::new(String::from("root.atsign.org"), 64);
        TlsClient::connect(&address)
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
        assert_eq!(res.unwrap(), String::from("@null"));
    }
}
