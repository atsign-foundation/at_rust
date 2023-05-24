// use std::io::{self, BufRead, Write};
// use std::io::{BufReader, Read};
// use std::net::TcpStream;
// use std::println;
// use std::sync::Arc;
//
// use rustls::ClientConnection;
//
// pub struct TLSClient {
//     socket: TcpStream,
//     tls_conn: ClientConnection,
// }
//
// impl TLSClient {
//     /// Creates a new TLS connection.
//     pub fn new(host: &str, port: u16) -> Self {
//         let mut root_store = rustls::RootCertStore::empty();
//         root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
//             rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
//                 ta.subject,
//                 ta.spki,
//                 ta.name_constraints,
//             )
//         }));
//         let config = rustls::ClientConfig::builder()
//             .with_safe_defaults()
//             .with_root_certificates(root_store)
//             .with_no_client_auth();
//         let rc_config = Arc::new(config);
//
//         // Create a TLS client.
//         let root_domain = host.try_into().unwrap();
//         let client = rustls::ClientConnection::new(rc_config, root_domain).unwrap();
//         let socket = match TcpStream::connect(format!("{}:{}", host, port.to_string())) {
//             Ok(s) => {
//                 println!("Connected to root server");
//                 s
//             }
//             Err(_) => panic!("Could not connect to root server"),
//         };
//         // let tls = rustls::Stream::new(&mut client, &mut socket);
//
//         TLSClient {
//             socket,
//             tls_conn: client,
//         }
//     }
//
//     pub fn read(&mut self) {
//         println!("Reading from socket");
//         let can_read = self.tls_conn.wants_read();
//         println!("Can read: {}", can_read);
//         let can_write = self.tls_conn.wants_write();
//         println!("Can write: {}", can_write);
//         // let mut buf_reader = BufReader::new(self.tls_conn.reader());
//         // match self.tls_conn.read_tls(&mut self.socket) {
//         //     Err(_) => panic!("Could not read from socket"),
//         //     Ok(0) => panic!("Socket closed"),
//         //     Ok(_) => {
//         //         println!("Read from socket");
//         //     }
//         // }
//
//         println!("Processing new packets");
//         let io_state = match self.tls_conn.process_new_packets() {
//             Err(_) => panic!("Could not process new packets"),
//             Ok(data) => data,
//         };
//
//         println!("Reading plaintext");
//         if io_state.plaintext_bytes_to_read() > 0 {
//             let mut plaintext = Vec::new();
//             plaintext.resize(io_state.plaintext_bytes_to_read(), 0u8);
//             self.tls_conn.reader().read_exact(&mut plaintext).unwrap();
//             io::stdout().write_all(&plaintext).unwrap();
//         } else {
//             println!("No plaintext to read");
//         }
//     }
//
//     // TODO: Pass data into this function
//     pub fn write(&mut self) {
//         let result = self.tls_conn.writer().write_all(b"aliens12\n").unwrap();
//         println!("Wrote to socket successfully");
//     }
// }
//
// fn get_at_sign_address(host: &str, port: u16) {
//     // Initialise the TLS config.
//     let mut root_store = rustls::RootCertStore::empty();
//     root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
//         rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
//             ta.subject,
//             ta.spki,
//             ta.name_constraints,
//         )
//     }));
//     let config = rustls::ClientConfig::builder()
//         .with_safe_defaults()
//         .with_root_certificates(root_store)
//         .with_no_client_auth();
//     let rc_config = Arc::new(config);
//
//     // Create a TLS client.
//     let root_domain = "root.atsign.org".try_into().unwrap();
//     let mut client = rustls::ClientConnection::new(rc_config, root_domain).unwrap();
//     let mut socket = match TcpStream::connect("root.atsign.org:64") {
//         Ok(s) => {
//             println!("Connected to root server");
//             s
//         }
//         Err(_) => panic!("Could not connect to root server"),
//     };
//     let mut tls = rustls::Stream::new(&mut client, &mut socket);
//     tls.write_all("aliens12\n".as_bytes()).unwrap();
//     let mut challenge = String::new();
//     let mut reader = BufReader::new(&mut tls);
//     reader.read_line(&mut challenge).unwrap();
//     println!("Challenge: {}", challenge);
// }
