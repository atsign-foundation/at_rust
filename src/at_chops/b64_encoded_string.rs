use std::fmt::{Display, Formatter};

use base64::{engine::general_purpose, Engine as _};

#[derive(Debug)]
pub struct Base64EncodedString<'a> {
    pub value: &'a str,
}

impl<'a> Base64EncodedString<'a> {
    pub fn decode(self) -> Vec<u8> {
        general_purpose::STANDARD
            .decode(self.value)
            .expect("Failed to decode base64 text")
    }
}

impl<'a> Display for Base64EncodedString<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl<'a> From<&'a str> for Base64EncodedString<'a> {
    fn from(value: &'a str) -> Self {
        Self { value }
    }
}

impl<'a> From<&'a String> for Base64EncodedString<'a> {
    fn from(value: &'a String) -> Self {
        Self { value }
    }
}

impl<'a> Into<&'a str> for Base64EncodedString<'a> {
    fn into(self) -> &'a str {
        self.value
    }
}

// Probably not required.
pub trait ToBase64 {
    fn to_base64(&self) -> String;
}

impl ToBase64 for &[u8] {
    fn to_base64(&self) -> String {
        general_purpose::STANDARD.encode(self)
    }
}

pub trait FromBase64 {
    fn from_base64(&self) -> Vec<u8>;
}

impl FromBase64 for str {
    fn from_base64(&self) -> Vec<u8> {
        general_purpose::STANDARD
            .decode(self)
            .expect("Failed to decode base64 text")
    }
}
