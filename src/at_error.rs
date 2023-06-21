use std::fmt;
use std::io;
use std::result;

pub type Result<T> = result::Result<T, Error>;
pub type Error = AtError;

#[derive(Debug)]
pub struct AtError {
    pub message: String,
}

impl AtError {
    pub fn new(message: String) -> AtError {
        AtError { message }
    }
}

impl fmt::Display for AtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AtError: {}", self.message)
    }
}

impl std::error::Error for AtError {}

impl From<io::Error> for AtError {
    fn from(error: io::Error) -> Self {
        AtError {
            message: error.to_string(),
        }
    }
}
