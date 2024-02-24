use std::{fmt::Display, str::FromStr};

use at_sign::AtSign;
use log::{error, trace};
use regex::Regex;

/**
An AtKey is the identifier half of the "identifier-value" pair.
Similar to the primary key of a tabular database, the AtKey must be a unique string which represents the data.
atId and atKey are used interchangeably.
[Docs](https://docs.atsign.com/atprotocol#key).

Structure: `[cached:]<visibility scope>:<record ID>.<namespace><owner’s atSign>`

## Examples:
### Public Key
Example: `public:record1.namespace1@alice` -> Public data that belongs to @alice
- A public key is a key which can be looked up by any atSign owner.
- A public key should be part of the scan verb result.
- Format of the public key should be `public::<@sign>`.
### Private Key
Example: `privatekey:pk1@bob` -> Private data that belongs to @bob
- A private key is a key which cannot be looked up any atSign user other than the one created it.
- A private key should not be returned in a scan verb result.
- Format of the private key should be `privatekey::<@sign>`.
### User Key
Example: `@bob:record1.namespace1@alice` -> Data that belongs to @alice and is shared with @bob
- A user key can only be looked up by an atSign owner with whom the data has been shared.
- A user key should be part of the scan verb result only for the user who created it and the specific user it has been shared with.
- Format of the key shared with someone else should be `<Shared with @sign>::<Created by @sign>`.
### Internal Key
Example: `_latestnotificationid.at_skeleton_app@alice`
- Internal keys start with an underscore(_) and are not displayed in scan results. Internal keys can be looked up only by the owner of the atServer.
### Cached Key
Example: `cached:@bob:record1.namespace1@alice` -> Cached data that belongs to @alice and is shared with @bob
- A cached key is a key that was originally created by another atSign user but is now cached on the atServer of another user's atSign as he/she was given permission to cache it.
- A cached key should be listed in the scan verb result for the atSign user who cached it.
- Format of the key shared with someone else should be `cached:<Shared with @sign>::<Created by @sign>`.
- The user who has cached the key should not be allowed to update the cached key. An atSign owner who has created and shared the key should be allowed to update a cached key, and if the "autoNotify" config parameters is set to true, the updated value should be notified (please refer to the notify verb) and the cached key updated with the new value. If the user who originally shared the keys set the CCD (Cascade delete) to true, the cached key will be deleted when the original key is deleted.
*/
#[derive(Debug)]
pub struct AtKey {
    pub record_id: String,
    pub namespace: Option<String>,
    pub owner: AtSign,
    pub is_cached: bool,
    pub visibility_scope: Visibility,
}

#[derive(Debug)]
pub enum Visibility {
    Public,
    Private,
    Internal,
    Shared(AtSign),
}

impl AtKey {
    pub fn new_public_key<T: AsRef<str>>(record_id: T, namespace: T, owner: AtSign) -> Self {
        assert!(
            record_id.as_ref().len() + namespace.as_ref().len() + owner.to_string().len() <= 240,
            "AtKey must be less than or equal to 240 characters"
        );
        AtKey {
            record_id: record_id.as_ref().to_string(),
            namespace: Some(namespace.as_ref().to_string()),
            owner,
            is_cached: false,
            visibility_scope: Visibility::Public,
        }
    }

    pub fn new_private_key<T: AsRef<str>>(
        record_id: T,
        namespace: Option<T>,
        owner: AtSign,
    ) -> Self {
        assert!(
            record_id.as_ref().len()
                + namespace
                    .as_ref()
                    .map_or_else(|| "", |ns| ns.as_ref())
                    .len()
                + owner.to_string().len()
                <= 240,
            "AtKey must be less than or equal to 240 characters"
        );
        AtKey {
            record_id: record_id.as_ref().to_string(),
            namespace: namespace.map(|ns| ns.as_ref().to_string()),
            owner,
            is_cached: false,
            visibility_scope: Visibility::Private,
        }
    }

    pub fn new_user_key<T: AsRef<str>>(
        record_id: T,
        namespace: T,
        owner: AtSign,
        shared_with: AtSign,
    ) -> Self {
        assert!(
            record_id.as_ref().len() + namespace.as_ref().len() + owner.to_string().len() <= 240,
            "AtKey must be less than or equal to 240 characters"
        );
        AtKey {
            record_id: record_id.as_ref().to_string(),
            namespace: Some(namespace.as_ref().to_string()),
            owner,
            is_cached: false,
            visibility_scope: Visibility::Shared(shared_with),
        }
    }

    pub fn new_internal_key<T: AsRef<str>>(record_id: T, namespace: T, owner: AtSign) -> Self {
        assert!(
            record_id.as_ref().len() + namespace.as_ref().len() + owner.to_string().len() <= 240,
            "AtKey must be less than or equal to 240 characters"
        );
        AtKey {
            record_id: record_id.as_ref().to_string(),
            namespace: Some(namespace.as_ref().to_string()),
            owner,
            is_cached: false,
            visibility_scope: Visibility::Internal,
        }
    }

    pub fn new_cached_key<T: AsRef<str>>(
        record_id: T,
        namespace: T,
        owner: AtSign,
        cached_by: AtSign,
    ) -> Self {
        assert!(
            record_id.as_ref().len() + namespace.as_ref().len() + owner.to_string().len() <= 240,
            "AtKey must be less than or equal to 240 characters"
        );
        AtKey {
            record_id: record_id.as_ref().to_string(),
            namespace: Some(namespace.as_ref().to_string()),
            owner,
            is_cached: true,
            visibility_scope: Visibility::Shared(cached_by),
        }
    }
}

impl Display for AtKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut buffer = String::from("");
        if self.is_cached {
            buffer.push_str("cached:");
        };
        match &self.visibility_scope {
            Visibility::Public => {
                buffer.push_str("public:");
            }
            Visibility::Private => {
                buffer.push_str("private:");
            }
            Visibility::Internal => {
                buffer.push_str("_");
            }
            Visibility::Shared(shared_with) => {
                buffer.push_str(&format!("{}:", shared_with.get_at_sign_with_prefix()));
            }
        };
        buffer.push_str(&self.record_id);
        if let Some(namespace) = &self.namespace {
            buffer.push_str(&format!(".{}", namespace));
        }
        buffer.push_str(&self.owner.get_at_sign_with_prefix());
        write!(f, "{}", buffer)
    }
}

impl FromStr for AtKey {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: Improve performance by only creating regex if the previous one doesn't match
        // TODO: Improve performance by putting most common case first

        // TODO: Check that it works with namespaces with multiple periods
        trace!("Constructing at_key from_str");

        // Regex patterns for each key type
        let public_re =
            Regex::new(r"^public:(?P<record_id>[^.]+)\.(?P<namespace>[^@]+)@(?P<owner>.+)$")
                .unwrap();
        let private_re =
            Regex::new(r"^private:(?P<record_id>[^.]+)(?:\.(?P<namespace>[^@]+))?@(?P<owner>.+)$")
                .unwrap();
        let user_re = Regex::new(
            r"^@(?P<shared_with>[^:]+):(?P<record_id>[^.]+)\.(?P<namespace>[^@]+)@(?P<owner>.+)$",
        )
        .unwrap();
        let internal_re =
            Regex::new(r"^_(?P<record_id>[^.]+)\.(?P<namespace>[^@]+)@(?P<owner>.+)$").unwrap();
        let cached_re = Regex::new(r"^cached:@(?P<cached_by>[^:]+):(?P<record_id>[^.]+)\.(?P<namespace>[^@]+)@(?P<owner>.+)$").unwrap();

        // Attempt to match each pattern and extract components
        if let Some(caps) = public_re.captures(s) {
            trace!("Matched public key pattern");
            Ok(AtKey::new_public_key(
                caps["record_id"].to_string(),
                caps["namespace"].to_string(),
                AtSign::new(caps["owner"].to_string()),
            ))
        } else if let Some(caps) = private_re.captures(s) {
            trace!("Matched private key pattern");
            Ok(AtKey::new_private_key(
                caps["record_id"].to_string(),
                caps.name("namespace").map(|m| m.as_str().to_string()), // Converts Option<Match> to Option<String>
                AtSign::new(caps["owner"].to_string()),
            ))
        } else if let Some(caps) = user_re.captures(s) {
            trace!("Matched user key pattern");
            Ok(AtKey::new_user_key(
                caps["record_id"].to_string(),
                caps["namespace"].to_string(),
                AtSign::new(caps["owner"].to_string()),
                AtSign::new(caps["shared_with"].to_string()),
            ))
        } else if let Some(caps) = internal_re.captures(s) {
            trace!("Matched internal key pattern");
            Ok(AtKey::new_internal_key(
                caps["record_id"].to_string(),
                caps["namespace"].to_string(),
                AtSign::new(caps["owner"].to_string()),
            ))
        } else if let Some(caps) = cached_re.captures(s) {
            trace!("Matched cached key pattern");
            Ok(AtKey::new_cached_key(
                caps["record_id"].to_string(),
                caps["namespace"].to_string(),
                AtSign::new(caps["owner"].to_string()),
                AtSign::new(caps["cached_by"].to_string()),
            ))
        } else {
            error!("Input didn't match any expected key format.");
            Err("Input does not match any expected key format. Expected format: [cached:]<visibility scope>:<record ID>.<namespace><owner’s atSign>")
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_public_key() {
        let at_key =
            AtKey::new_public_key("record1", "namespace1", AtSign::new(String::from("alice")));
        assert_eq!(at_key.to_string(), "public:record1.namespace1@alice");
    }

    #[test]
    fn test_new_private_key() {
        let at_key = AtKey::new_private_key(
            "record1",
            Some("namespace1"),
            AtSign::new(String::from("alice")),
        );
        assert_eq!(at_key.to_string(), "private:record1.namespace1@alice");
        let at_key = AtKey::new_private_key("record1", None, AtSign::new(String::from("alice")));
        assert_eq!(at_key.to_string(), "private:record1@alice");
    }

    #[test]
    fn test_new_user_key() {
        let at_key = AtKey::new_user_key(
            "record1",
            "namespace1",
            AtSign::new(String::from("alice")),
            AtSign::new(String::from("bob")),
        );
        assert_eq!(at_key.to_string(), "@bob:record1.namespace1@alice");
    }

    #[test]
    fn test_new_internal_key() {
        let at_key =
            AtKey::new_internal_key("record1", "namespace1", AtSign::new(String::from("alice")));
        assert_eq!(at_key.to_string(), "_record1.namespace1@alice");
    }

    #[test]
    fn test_new_cached_key() {
        let at_key = AtKey::new_cached_key(
            "record1",
            "namespace1",
            AtSign::new(String::from("alice")),
            AtSign::new(String::from("bob")),
        );
        assert_eq!(at_key.to_string(), "cached:@bob:record1.namespace1@alice");
    }

    #[test]
    #[should_panic]
    fn test_key_too_long() {
        let record_id = "a".repeat(200);
        let namespace = "b".repeat(200);
        let owner = AtSign::new(String::from("alice"));
        AtKey::new_private_key(record_id, Some(namespace), owner);
    }

    #[test]
    fn test_public_at_key_from_str() {
        let at_key = AtKey::from_str("public:record1.namespace1@alice").unwrap();
        assert_eq!(at_key.to_string(), "public:record1.namespace1@alice");
    }

    #[test]
    fn test_private_at_key_from_str() {
        let at_key = AtKey::from_str("private:record1.namespace1@alice").unwrap();
        assert_eq!(at_key.to_string(), "private:record1.namespace1@alice");
        let at_key = AtKey::from_str("private:record1@alice").unwrap();
        assert_eq!(at_key.to_string(), "private:record1@alice");
    }

    #[test]
    fn test_user_at_key_from_str() {
        let at_key = AtKey::from_str("@bob:record1.namespace1@alice").unwrap();
        assert_eq!(at_key.to_string(), "@bob:record1.namespace1@alice");
    }

    #[test]
    fn test_internal_at_key_from_str() {
        let at_key = AtKey::from_str("_record1.namespace1@alice").unwrap();
        assert_eq!(at_key.to_string(), "_record1.namespace1@alice");
    }

    #[test]
    fn test_cached_at_key_from_str() {
        let at_key = AtKey::from_str("cached:@bob:record1.namespace1@alice").unwrap();
        assert_eq!(at_key.to_string(), "cached:@bob:record1.namespace1@alice");
    }

    #[test]
    fn test_at_key_from_str_invalid() {
        let at_key = AtKey::from_str("invalid");
        assert!(at_key.is_err());
    }
}
