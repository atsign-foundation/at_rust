use at_rust::at_client::AtClient;
use at_rust::at_secrets::AtSecrets;
use at_rust::at_sign::AtSign;
use at_rust::tls::tls_client::ReadWrite;
use native_tls::TlsConnector;
use std::env;
use std::fs::File;
use std::io::Read;
use std::net::TcpStream;

extern crate env_logger;
extern crate native_tls;

fn main() {
    env_logger::init();
    // Parse the arguments
    let args: Vec<String> = env::args().collect();
    // The location of the file containing the secrets
    let file_path = args[1].clone();
    // The atSign of the client device
    let host = args[2].clone();
    // The atSign of the sender of the data
    let contact = args[3].clone();

    // Read the contents of the file into a string.
    let mut file = File::open(file_path).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    // Create the secrets object from the file
    let secrets = AtSecrets::from_file(&contents).expect("Failed to create secrets");

    // Create the atSign object for the sender
    let contact = AtSign::new(contact);

    fn create_tls_connection(addr: &str) -> Box<dyn ReadWrite> {
        let stream = TcpStream::connect(addr).unwrap();
        let connector = TlsConnector::new().unwrap();
        let host = addr.split(':').collect::<Vec<&str>>()[0];
        let stream = connector.connect(&host, stream).unwrap();
        Box::new(stream)
    }

    // Create the AtClient object
    let mut at_client = AtClient::init(secrets, AtSign::new(host), &create_tls_connection, "test")
        .expect("Failed to init");

    // Read the data using the AtClient
    at_client
        .read_data(contact, "demo")
        .expect("Failed to send data");
}
