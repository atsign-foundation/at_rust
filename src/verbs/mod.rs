pub mod from;
pub mod llookup;
pub mod lookup;
pub mod plookup;
pub mod update;

mod prelude {
    pub use crate::at_error::{AtError, Error, Result};
    pub use crate::at_sign::AtSign;
    pub use crate::tls::tls_client::TlsClient;
    pub use rsa::{RsaPrivateKey, RsaPublicKey};
}

use prelude::*;

pub trait Verb<'a> {
    type Inputs: 'a;
    type Result;

    fn execute(tls_client: &mut TlsClient, input: Self::Inputs) -> Result<Self::Result>;
}
