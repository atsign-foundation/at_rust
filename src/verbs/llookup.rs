use super::{prelude::*, Verb};

pub struct LlookupVerbInputs<'a> {
    /// The AtSign of the person who is looking up the key-value pair.
    pub from_at_sign: &'a AtSign,
    /// The AtSign of the person who owns the key-value pair.
    pub to_at_sign: &'a AtSign,
    /// The identifier of the key-value pair to be looked up.
    pub at_id: &'a str,
    /// The decrypted public key.
    pub public_key: &'a str,
}

impl<'a> LlookupVerbInputs<'a> {
    pub fn new(
        from_at_sign: &'a AtSign,
        to_at_sign: &'a AtSign,
        at_id: &'a str,
        public_key: &'a str,
    ) -> Self {
        Self {
            from_at_sign,
            to_at_sign,
            at_id,
            public_key,
        }
    }
}

pub struct LlookupVerb {}

impl<'a> Verb<'a> for LlookupVerb {
    type Inputs = LlookupVerbInputs<'a>;
    type Result = String;

    fn execute(tls_client: &mut TLSClient, input: Self::Inputs) -> Result<Self::Result> {
        println!(
            "Looking up local copy of {} {}",
            &input.to_at_sign.get_at_sign(),
            &input.at_id
        );
        tls_client.send(format!(
            "llookup:{}.{}@{}\n",
            input.at_id,
            input.to_at_sign.get_at_sign(),
            input.from_at_sign.get_at_sign()
        ))?;
        let response = tls_client.read_line()?;
        println!("llookup response: {:?}", response);
        Ok(response)
    }
}
