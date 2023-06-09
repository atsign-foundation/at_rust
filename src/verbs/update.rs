use super::{prelude::*, Verb};

pub struct UpdateVerbInputs<'a> {
    /// The atSign of the person who is looking up the key-value pair.
    pub from_at_sign: &'a AtSign,
    /// The identifier of the key-value pair to be looked up.
    pub at_id: &'a str,
    /// Data that is base64 encoded.
    pub data: &'a str,
    /// Namespace
    pub namespace: Option<&'a str>,
    /// Time to refresh
    pub ttr: Option<usize>,
    /// Recipient's atSign
    pub to_at_sign: Option<&'a AtSign>,
}

impl<'a> UpdateVerbInputs<'a> {
    pub fn new(
        from_at_sign: &'a AtSign,
        at_id: &'a str,
        data: &'a str,
        namespace: Option<&'a str>,
        ttr: Option<usize>,
        to_at_sign: Option<&'a AtSign>,
    ) -> Self {
        Self {
            from_at_sign,
            at_id,
            data,
            namespace,
            ttr,
            to_at_sign,
        }
    }
}

pub struct UpdateVerb {}

impl<'a> Verb<'a> for UpdateVerb {
    type Inputs = UpdateVerbInputs<'a>;
    type Result = ();

    fn execute(tls_client: &mut TlsClient, input: Self::Inputs) -> Result<Self::Result> {
        let mut send_string = String::from("update");
        if let Some(ttr) = input.ttr {
            send_string.push_str(&format!(":ttr:{}", ttr));
        }
        if let Some(recipient) = input.to_at_sign {
            send_string.push_str(&format!(":@{}", recipient.get_at_sign()));
        }
        send_string.push_str(&format!(":{}", input.at_id));
        if let Some(namespace) = input.namespace {
            send_string.push_str(&format!(".{}", namespace));
        }
        send_string.push_str(&format!("@{}", input.from_at_sign.get_at_sign()));
        send_string.push_str(&format!(" {}\n", input.data));
        tls_client.send(send_string)?;
        let _ = tls_client.read_line()?;
        // TODO: Check response is formatted like "data: <data>" and return Error if not.
        Ok(())
    }
}
