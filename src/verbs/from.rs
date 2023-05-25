use super::{prelude::*, Verb};

pub struct FromVerbInputs<'a> {
    pub at_sign: &'a AtSign,
}

impl<'a> FromVerbInputs<'a> {
    pub fn new(at_sign: &'a AtSign) -> Self {
        Self { at_sign }
    }
}

pub struct FromVerb {}

impl<'a> Verb<'a> for FromVerb {
    type Inputs = FromVerbInputs<'a>;
    type Result = String;

    fn execute(tls_client: &mut TLSClient, input: Self::Inputs) -> Result<Self::Result> {
        tls_client.send(format!("from:{}\n", input.at_sign.get_at_sign()))?;
        let res = tls_client.read_line()?;
        Ok(res)
    }
}
