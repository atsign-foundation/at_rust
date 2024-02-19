extern crate env_logger;

use std::{fs::File, io::Read};

use at_rust::at_client::AtClient;
use at_secrets::AtSecrets;
use at_sign::AtSign;
use clap::Parser;

#[derive(Parser, Debug)]
#[command()]
struct Cli {
    /// The file path to process
    #[arg(short, long)]
    file: String,

    /// The string argument to use
    #[arg(short, long)]
    at_sign: String,
}

fn main() {
    env_logger::init();

    let cli = Cli::parse();

    // Read the contents of the file into a string.
    let mut file = File::open(cli.file).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    // Create the secrets object from the file
    let secrets = AtSecrets::from_file(&contents).expect("Failed to create secrets");

    // Create the atSign of the client
    let at_sign = AtSign::new(cli.at_sign);

    let mut at_client = AtClient::init(secrets, at_sign).expect("Failed to create AtClient");
}
