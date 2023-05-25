// What does the API for this look like?
// I probably want to include the traits for reader, writer, buff reader, buff writer
// I also probably want to include a trait as for the API itself

use std::{
    error::Error,
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    println,
};

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
        Ok(TLSClient { stream })
    }

    pub fn send(&mut self, data: String) -> std::io::Result<()> {
        self.stream.write_all(data.as_bytes())
    }

    /// Reads a line for the stream and converts it to a String which is trimmed.
    // NOTE: All unauthenticated responses start with "@" and all authenticated responses start
    // with @user@
    pub fn read_line(&mut self) -> std::io::Result<String> {
        let mut res = vec![];
        let mut reader = BufReader::new(&mut self.stream);
        reader.read_until(b'\n', &mut res)?;
        Ok(String::from_utf8_lossy(&res).trim().to_owned())
    }

    pub fn close(&mut self) -> std::io::Result<()> {
        println!("Closing connection");
        self.stream.shutdown()
    }
}
