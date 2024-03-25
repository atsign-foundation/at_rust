#![allow(unused_variables)]
#![allow(dead_code)]

#[derive(Debug)]
pub struct RecordMetadata {
    /// A Date and Time derived from the ttb (now + ttb). A Key should be only available after availableFrom.
    available_from: usize,
    /// Indicates if a cached key needs to be deleted when the atSign user who has originally shared it deletes it.
    ccd: Option<bool>,
    /// atSign that has created the key
    created_by: String,
    /// Date and time when the key has been created.
    created_on: usize,
    /// A Date and Time derived from the ttl (now + ttl). A Key should be auto deleted once it expires.
    expires_on: usize,
    /// True if the value is a binary value.
    is_binary: bool,
    /// True if the key is cached.
    is_cached: bool,
    /// True if the value is encrypted.
    is_encrypted: bool,
    /// A Date and Time derived from the ttr. The time at which the key gets refreshed.
    refresh_at: Option<usize>,
    /// atSign of the user with whom the key has been shared. Can be null if not shared with anyone.
    shared_with: Option<String>,
    /// Date and time when the key has been last updated.
    updated_on: usize,
    /// Time to birth in milliseconds.
    ttb: Option<usize>,
    /// Time to live in milliseconds.
    ttl: Option<usize>,
    /// Time in milliseconds after which the cached key needs to be refreshed. A ttr of -1 indicates that the key can be cached forever. ttr of 0 indicates do not refresh. ttr of > 0 will refresh the key. ttr of null indicates the key is impossible to cache, hence, refreshing does not make sense (which has the same effect as a ttr of 0).
    ttr: Option<usize>,
}
