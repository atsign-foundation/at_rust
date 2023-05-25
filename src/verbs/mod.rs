pub mod from;

mod prelude {
    pub use crate::at_error::Result;
    pub use crate::at_sign::AtSign;
    pub use crate::at_tls_client::TLSClient;
}

use prelude::*;

pub trait Verb<'a> {
    type Inputs: 'a;
    type Result;

    fn execute(tls_client: &mut TLSClient, input: Self::Inputs) -> Result<Self::Result>;
}
