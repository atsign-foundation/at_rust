use std::io::{BufRead, BufReader, Read, Write};

use log::info;

pub trait ReadWrite: Write + Read {}
impl<T: Write + Read> ReadWrite for T {}

pub struct TlsClient {
    stream: Box<dyn ReadWrite>,
}

impl TlsClient {
    pub fn new(connect: &dyn Fn() -> Box<dyn ReadWrite>) -> std::io::Result<TlsClient> {
        Ok(TlsClient { stream: connect() })
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
}
