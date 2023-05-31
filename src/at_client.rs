use crate::at_error::{AtError, Result};
use crate::at_secrets::AtSecrets;
use crate::at_server_addr::AtServerAddr;
use crate::at_sign::AtSign;
use crate::at_tls_client::TLSClient;
use crate::verbs::{from::FromVerb, from::FromVerbInputs, Verb};

pub struct AtClient {
    secrets: AtSecrets,
    at_sign: AtSign,
    tls_client: TLSClient,
}

impl AtClient {
    pub fn init(secrets: AtSecrets, at_sign: AtSign) -> Result<AtClient> {
        let server = get_at_sign_server_addr(&at_sign.get_at_sign())?;
        let tls_client = match TLSClient::new(&server) {
            Ok(res) => res,
            Err(err) => return Err(AtError::new(err.to_string())),
        };
        Ok(AtClient {
            secrets,
            at_sign,
            tls_client,
        })
    }

    pub fn lookup(&mut self) {
        println!("Connecting to at server");
    }

    pub fn authenticate_with_at_server(&mut self) -> Result<()> {
        let res = FromVerb::execute(
            &mut self.tls_client,
            FromVerbInputs::new(&self.at_sign, &self.secrets.aes_pkam_private_key),
        )
        .unwrap();
        println!("Challenge: {}", res);
        Ok(())
    }
}

/// function to get the at sign server address
fn get_at_sign_server_addr(at_sign: &str) -> Result<AtServerAddr> {
    println!("Getting at sign server address");

    let at_server_addr = AtServerAddr::new(String::from("root.atsign.org"), 64);
    let mut tls_client = match TLSClient::new(&at_server_addr) {
        Ok(res) => res,
        Err(_) => return Err(AtError::new(String::from("Unable to connect to at server"))),
    };

    tls_client.send(format!("{}\n", at_sign))?;
    let res = tls_client.read_line()?;
    tls_client.close()?;

    if res == "@null" {
        return Err(AtError::new(String::from("Unable to find at sign")));
    }

    // Removing the first letter from the response as it contains "@"
    let addr = res[1..].to_string();
    println!("At server address: {}", &addr);

    // Trimming to remove the newline character
    let addr = addr.trim();
    let addr = addr.split(":").collect::<Vec<_>>();
    let host = addr[0].to_string();
    let port = addr[1]
        .parse::<u16>()
        .expect("Unable to parse port to a u16");
    Ok(AtServerAddr::new(host, port))
}

// NOTE: Maybe each verb should know how to encode/decode/format itself?
// This could be good because each verb is likely to expect a different format.
// It would be the responsibility of the TLSClient to send and receive information but really do
// anything with it. Maybe just trim and turn into a String?
// Internal requirements:
// - Get the at sign server address
// - Connect to the at sign server
// - Authenticate with at sign
// External requirements:
// - Get data
// - Delete data
// - Update data
