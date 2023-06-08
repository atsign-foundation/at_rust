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

    println!("Reading file");
    let mut file = File::open(filename).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    println!("Creating AtSecrets");
    let secrets = AtSecrets::from_file(&contents);

    let contact = AtSign::new(String::from("42territorial"));

    let mut at_client =
        AtClient::init(secrets, AtSign::new("aliens12".to_owned())).expect("Failed to init");
    at_client
        .send_data("Hello World", contact)
        .expect("Failed to authenticate with at server");
}
