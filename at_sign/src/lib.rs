use std::fmt::Display;

#[derive(Debug)]
pub struct AtSign {
    /// The atSign of the client device. Without the `@` prefix.
    at_sign: String,
}

impl AtSign {
    /// Create a new atSign. `at_sign` should be a string without the `@` prefix.
    pub fn new(at_sign: String) -> AtSign {
        assert!(
            at_sign.len() < 55,
            "at_sign must be less than 55 characters"
        );
        AtSign { at_sign }
    }

    /// Get the name of the atSign without the `@` prefix.
    pub fn get_at_sign_without_prefix(&self) -> String {
        self.at_sign.to_owned()
    }

    /// Get the name of the atSign with the `@` prefix.
    pub fn get_at_sign_with_prefix(&self) -> String {
        format!("@{}", self.at_sign)
    }
}

impl Display for AtSign {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "@{}", self.at_sign)
    }
}
