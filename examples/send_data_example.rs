use at_rust::at_client::AtClient;
use at_rust::at_secrets::AtSecrets;
use at_rust::at_sign::AtSign;
use std::env;
use std::fs::File;
use std::io::Read;
extern crate env_logger;

fn main() {
    env_logger::init();
    // Parse the arguments
    let args: Vec<String> = env::args().collect();
    // The location of the file containing the secrets
    let file_path = args[1].clone();
    // The data to send to another atSign
    let data = args[2].clone();
    // The atSign of the client device
    let host = args[3].clone();
    // The atSign of the recipient of the data
    let contact = args[4].clone();

    // Read the contents of the file into a string.
    let mut file = File::open(file_path).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    // Create the secrets object from the file
    let secrets = AtSecrets::from_file(&contents).expect("Failed to create secrets");

    // Create the atSign object for the contact
    let contact = AtSign::new(contact);

    // Create the AtClient object
    let mut at_client = AtClient::init(secrets, AtSign::new(host), "test").expect("Failed to init");

    // Send the data using the AtClient
    at_client
        .send_data(&data, contact, "demo")
        .expect("Failed to send data");
}