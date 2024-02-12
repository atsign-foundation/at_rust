enum KeyType {
    Public,
    Private,
    User,
    Internal,
    Cached,
}

struct KeyMetadata {
    created_on: usize,
    created_by: String,
    updated_on: usize,
    shared_with: Option<String>,
    ttl: Option<usize>,
    expires_on: usize,
    ttb: Option<usize>,
    available_from: usize,
    is_cached: bool,
    ttr: Option<usize>,
    refresh_at: Option<usize>,
    ccd: Option<bool>,
    is_binary: bool,
    is_encrypted: bool,
}

struct AtKey {
    key: String,
    key_type: KeyType,
    metadata: KeyMetadata,
    value: Vec<u8>,
}
