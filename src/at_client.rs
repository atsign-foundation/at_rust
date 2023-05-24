use crate::at_secrets::AtSecrets;
use crate::at_server_addr::AtServerAddr;
use native_tls::TlsConnector;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

pub struct AtClient {
    secrets: AtSecrets,
    at_sign: String,
    at_sign_server: AtServerAddr,
}

impl AtClient {
    pub fn init(secrets: AtSecrets, at_sign: String) -> Self {
        let server = get_at_sign_server_addr(&at_sign);
        AtClient {
            secrets,
            at_sign,
            at_sign_server: server,
        }
    }

    pub fn lookup(&self) {
        println!("Connecting to at server");
        let connector = TlsConnector::new().unwrap();
        let stream = TcpStream::connect(&self.at_sign_server).unwrap();
        let mut stream = connector
            .connect(&self.at_sign_server.host, stream)
            .unwrap();
        stream
            .write_all(format!("from:@{}\n", self.at_sign).as_bytes())
            .unwrap();
        let mut res = vec![];
        let mut reader = BufReader::new(&mut stream);
        reader.read_until(b'\n', &mut res).unwrap();
        println!("Response: {}", String::from_utf8_lossy(&res));
    }

    fn authenticate_with_at_server(&self) {}
}

/// function to get the at sign server address
fn get_at_sign_server_addr(at_sign: &str) -> AtServerAddr {
    println!("Getting at sign server address");

    let connector = TlsConnector::new().unwrap();

    let stream = TcpStream::connect("root.atsign.org:64").unwrap();
    let mut stream = connector.connect("root.atsign.org", stream).unwrap();

    stream
        .write_all(format!("{}\n", at_sign).as_bytes())
        .unwrap();
    let mut res = vec![];
    let mut reader = BufReader::new(&mut stream);
    reader.read_until(b'\n', &mut res).unwrap();
    // Removing the first byte from the response as it contains "@"
    let addr_u8 = &res[1..res.len()];
    let addr = String::from_utf8_lossy(&addr_u8).to_string();
    println!("At server address: {}", &addr);
    // Trimming to remove the newline character
    let addr = addr.trim();
    let addr = addr.split(":").collect::<Vec<_>>();
    let host = addr[0].to_string();
    let port = addr[1]
        .parse::<u16>()
        .expect("Unable to parse port to a u16");
    AtServerAddr::new(host, port)
}
