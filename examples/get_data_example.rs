extern crate env_logger;

use std::{fs::File, io::Read, str::FromStr};

use at_records::at_key::AtKey;
use at_rust::at_client::{AtClient, GetRequestType};
use at_secrets::AtSecrets;
use at_sign::AtSign;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(about = "Get data from the @sign's server.")]
struct Cli {
    /// The relative or absolute path to the file containing the AtSign's secrets.
    #[arg(short, long)]
    file: String,

    /// The name of the atSign to use (without the @ symbol).
    #[arg(short, long)]
    at_sign: String,

    /// String representation of the AtKey e.g. @<shared_with>:<record_id>.<namespace>@<owner>.
    #[arg(long)]
    at_key: String,
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
    let at_key = AtKey::from_str(&cli.at_key).expect("Invalid at_key");
    let result = at_client
        .get_record(GetRequestType::Data, &at_key)
        .expect("Failed to get data");
    println!("{:?}", result);
}
