use at_rust::at_client::AtClient;
use at_rust::at_secrets::AtSecrets;
use at_rust::at_sign::AtSign;
use std::fs::File;
use std::io::Read;
use std::{env, println};

fn main() {
    // Read the contents of the file into a string.
    let args: Vec<String> = env::args().collect();
    let filename = args[1].clone();
    let app_type = args[2].clone();
    let host = args[3].clone();
    let contact = args[4].clone();

    println!("Reading file");
    let mut file = File::open(filename).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    println!("Creating AtSecrets");
    let secrets = AtSecrets::from_file(&contents);

    let contact = AtSign::new(contact);

    let mut at_client = AtClient::init(secrets, AtSign::new(host)).expect("Failed to init");

    if app_type == "client" {
        at_client
            .send_data("Hello World", contact)
            .expect("Failed to authenticate with at server");
    } else if app_type == "server" {
        let data = at_client
            .read_data(contact)
            .expect("Failed to authenticate with at server");
        println!("Received data: {:?}", data);
    }
}
