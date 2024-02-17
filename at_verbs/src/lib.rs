//! Verbs are commands you can execute on an atServer.
//! Each verb interacts with the atServer in a different way.
//! Some are for authentication, some are for data retrieval and some are for data manipulation.

pub mod from_verb;
pub mod verb_trait;

mod prelude {
    pub use crate::verb_trait::Verb;
    pub use at_errors::{AtError, Result};
    pub use at_tls::TlsClient;
    pub use log::{error, info, warn};
}
