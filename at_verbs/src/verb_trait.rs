use at_errors::Result;
use at_tls::{tls_connection_trait::TlsConnection, TlsClient};

pub trait Verb<'a> {
    type Inputs: 'a;
    type Result;

    fn execute<T: TlsConnection>(
        tls_client: &mut TlsClient<T>,
        input: Self::Inputs,
    ) -> Result<Self::Result>;
}
