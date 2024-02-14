use at_errors::Result;
use at_tls::TlsClient;

pub trait Verb<'a> {
    type Inputs: 'a;
    type Result;

    fn execute(tls_client: &mut TlsClient, input: Self::Inputs) -> Result<Self::Result>;
}
