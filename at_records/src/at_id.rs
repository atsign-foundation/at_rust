use std::str::FromStr;

/// An atID is the identifier half of the "identifier-value" pair.
/// Similar to the primary key of a tabular database, the atID must be a unique string which represents the data.
/// Structure: `[cached:]<visibility scope>:<record ID>.<namespace><owner’s atSign>`
pub struct AtId {
    at_id: String,
}

impl AtId {
    pub fn new<T: AsRef<str>>(at_id: T) -> Self {
        assert!(
            at_id.as_ref().len() < 240,
            "at_id must be less than 240 characters"
        );
        Self {
            at_id: at_id.as_ref().to_string(),
        }
    }

    // pub fn builder() -> AtIdBuilder {
    //     AtIdBuilder::new()
    // }

    pub fn is_cached(&self) -> bool {
        todo!()
    }

    pub fn get_visibility_scope(&self) -> String {
        todo!()
    }

    pub fn get_record_id(&self) -> String {
        todo!()
    }

    pub fn get_namespace(&self) -> Option<String> {
        todo!()
    }

    pub fn get_owner_at_sign(&self) -> String {
        todo!()
    }
}

impl FromStr for AtId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: Split the string into the parts to make sure it actually is an atID
        Ok(AtId {
            at_id: s.to_string(),
        })
    }
}

pub enum RecordType {
    /// Store and share public data which can be seen by anyone.
    Public,
    /// Store data which can only be seen by the owner.
    Self_,
    /// Store and share private data which can only be seen by the owner and intended recipient.
    Shared,
    /// Store data which can only be seen by the owner, hidden by default.
    Private,
    /// Cache shared data from other atSigns for performance and offline mode.
    CachedShared,
}
