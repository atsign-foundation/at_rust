use super::{prelude::*, Verb};

pub struct UpdateVerbInputs<'a> {
    /// The AtSign of the person who is looking up the key-value pair.
    pub from_at_sign: &'a AtSign,
    /// The AtSign of the person who owns the key-value pair.
    pub to_at_sign: &'a AtSign,
    /// The identifier of the key-value pair to be looked up.
    pub at_id: &'a str,
    /// Data that is base64 encoded.
    pub data: &'a str,
}

impl<'a> UpdateVerbInputs<'a> {
    pub fn new(
        from_at_sign: &'a AtSign,
        to_at_sign: &'a AtSign,
        at_id: &'a str,
        data: &'a str,
    ) -> Self {
        Self {
            from_at_sign,
            to_at_sign,
            at_id,
            data,
        }
    }
}

pub struct UpdateVerb {}

impl<'a> Verb<'a> for UpdateVerb {
    type Inputs = UpdateVerbInputs<'a>;
    type Result = ();

    fn execute(tls_client: &mut TLSClient, input: Self::Inputs) -> Result<Self::Result> {
        println!("Updating {} for {}", &input.at_id, &input.to_at_sign);
        println!("Update data: {}", &input.data);
        tls_client.send(format!(
            "update:{}.{}@{} {}\n",
            input.at_id,
            input.to_at_sign.get_at_sign(),
            input.from_at_sign.get_at_sign(),
            input.data,
        ))?;
        let response = tls_client.read_line()?;
        println!("update response: {:?}", response);
        Ok(())
    }
}
