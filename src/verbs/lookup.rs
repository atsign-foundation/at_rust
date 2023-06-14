use super::{prelude::*, Verb};

pub struct LookupVerbInputs<'a> {
    /// The AtSign of the person who owns the key-value pair.
    pub to_at_sign: &'a AtSign,
    /// The identifier of the key-value pair to be looked up.
    pub at_id: &'a str,
    /// The namespace of the data
    pub namespace: Option<&'a str>,
}

impl<'a> LookupVerbInputs<'a> {
    pub fn new(to_at_sign: &'a AtSign, at_id: &'a str, namespace: Option<&'a str>) -> Self {
        Self {
            to_at_sign,
            at_id,
            namespace,
        }
    }
}

pub struct LookupVerb {}

impl<'a> Verb<'a> for LookupVerb {
    type Inputs = LookupVerbInputs<'a>;
    type Result = String;

    fn execute(tls_client: &mut TLSClient, input: Self::Inputs) -> Result<Self::Result> {
        let mut send_string = String::from("lookup");
        send_string.push_str(&format!(":{}", input.at_id));
        if let Some(namespace) = input.namespace {
            send_string.push_str(&format!(".{}", namespace));
        }
        send_string.push_str(&format!("@{}", input.to_at_sign.get_at_sign()));
        send_string.push_str(&format!("\n"));
        println!("lookup string: {}", send_string);
        tls_client.send(send_string)?;
        let response = tls_client.read_line()?;
        println!("lookup response: {:?}", response);
        Ok(response)
    }
}
