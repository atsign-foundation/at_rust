use std::{
    error::Error,
    io::{BufRead, BufReader, Write},
    net::TcpStream,
};

use log::info;
use native_tls::{TlsConnector, TlsStream};

use crate::at_server_addr::AtServerAddr;

pub struct TLSClient {
    stream: TlsStream<TcpStream>,
}

impl TLSClient {
    pub fn new(at_server_addr: &AtServerAddr) -> Result<TLSClient, Box<dyn Error>> {
        let connector = TlsConnector::new()?;
        let stream = TcpStream::connect(&at_server_addr)?;
        let stream = connector.connect(&at_server_addr.host, stream)?;
        info!("Connected to {:?}", &at_server_addr);
        Ok(TLSClient { stream })
    }

    pub fn send(&mut self, data: String) -> std::io::Result<()> {
        info!("Sending: {}", data.trim());
        self.stream.write_all(data.as_bytes())
    }

    /// Reads a line for the stream and converts it to a String which is trimmed.
    pub fn read_line(&mut self) -> std::io::Result<String> {
        let mut res = vec![];
        let mut reader = BufReader::new(&mut self.stream);
        reader.read_until(b'\n', &mut res)?;
        let data = String::from_utf8_lossy(&res).trim().to_owned();
        info!("Received: {}", data);
        Ok(data)
    }

    pub fn close(&mut self) -> std::io::Result<()> {
        info!("Closing connection");
        self.stream.shutdown()
    }
}
