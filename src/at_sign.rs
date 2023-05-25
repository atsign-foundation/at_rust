use std::fmt::Display;

#[derive(Debug)]
pub struct AtSign {
    at_sign: String,
}

impl AtSign {
    pub fn new(at_sign: String) -> AtSign {
        AtSign { at_sign }
    }

    pub fn get_at_sign(&self) -> String {
        self.at_sign.to_owned()
    }

    pub fn get_at_sign_with_prefix(&self) -> String {
        format!("@{}", self.at_sign)
    }
}

impl Display for AtSign {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "@{}", self.at_sign)
    }
}
