// What does the API for this look like?
// I probably want to include the traits for reader, writer, buff reader, buff writer
// I also probably want to include a trait as for the API itself

use std::net::TcpStream;

use native_tls::{TlsConnector, TlsStream};

use crate::at_server_addr::AtServerAddr;

pub struct TLSClient {
    stream: TlsStream<TcpStream>,
}

impl TLSClient {
    pub fn new(at_server_addr: &AtServerAddr) -> Self {
        let connector = TlsConnector::new().unwrap();

        let stream = TcpStream::connect(&at_server_addr).unwrap();
        let stream = connector.connect(&at_server_addr.host, stream).unwrap();
        TLSClient { stream }
    }
}
