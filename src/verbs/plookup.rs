use super::{prelude::*, Verb};

pub struct PlookupVerbInputs<'a> {
    /// The AtSign of the person who owns the key-value pair.
    pub to_at_sign: &'a AtSign,
    /// The identifier of the key-value pair to be looked up.
    pub at_id: &'a str,
}

impl<'a> PlookupVerbInputs<'a> {
    pub fn new(to_at_sign: &'a AtSign, at_id: &'a str) -> Self {
        Self { to_at_sign, at_id }
    }
}

pub struct PlookupVerb {}

impl<'a> Verb<'a> for PlookupVerb {
    type Inputs = PlookupVerbInputs<'a>;
    type Result = String;

    fn execute(tls_client: &mut TLSClient, input: Self::Inputs) -> Result<Self::Result> {
        println!(
            "Starting public lookup of {} for {}",
            input.at_id, input.to_at_sign
        );
        let send_data = format!(
            "plookup:{}@{}\n",
            input.at_id,
            input.to_at_sign.get_at_sign()
        );
        tls_client.send(send_data)?;
        let response = tls_client.read_line()?;
        println!("plookup response: {:?}", response);
        let (_, data) = response.split_at(5);

        Ok(data.to_owned())
    }
}
