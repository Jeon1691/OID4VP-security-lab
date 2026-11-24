//! In-process key table: the private-key handles that never go to Redis.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use protocol_model::SessionId;
use session_core::{StoreUnavailable, Timestamp};

/// Random bytes in a key reference: 128 bits, so references minted independently by several
/// workers never collide in practice (birthday bound near 2^64 sessions) and need no
/// coordination through Redis.
const KEY_REF_BYTES: usize = 16;

/// Length of a hex-encoded key reference (two digits per byte).
pub(crate) const KEY_REF_HEX_LEN: usize = KEY_REF_BYTES * 2;

/// Keys a [`KeyTable`] may hold beyond the registry's `max_pending`: twice the largest lab
/// scenario (128 concurrent sessions).
///
/// Redis caps pending sessions at `max_pending`, but the local table also holds keys Redis
/// cannot vouch for: inserts whose outcome is unknown (timed out or cancelled after they were
/// sent, so they may have committed) and sessions another registry consumed or expired. Those
/// stay until their TTL passes. The slack absorbs them; beyond it, inserts fail closed instead
/// of growing the table while Redis is unreachable.
pub const KEY_TABLE_SLACK: usize = 256;

/// A fresh random key reference, hex-encoded. Not a secret: it only names an entry in a
/// [`KeyTable`], and knowing it gives no access to the key.
pub(crate) fn new_key_ref() -> Result<String, StoreUnavailable> {
    let mut bytes = [0u8; KEY_REF_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| StoreUnavailable)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

struct Entry<K> {
    /// The session the key was registered for; a Redis record naming this reference for any
    /// other session is refused (a swapped reference must not hand out another session's key).
    session: SessionId,
    expires_at: Timestamp,
    key: Arc<K>,
}

/// Private-key handles of the sessions a [`RedisRegistry`](crate::RedisRegistry) inserted,
/// by key reference. Redis stores only the reference.
///
/// Cloning shares the table. Registries in one process that should resolve each other's
/// sessions (the two-worker tests) share one table; registries in different processes would
/// need a shared key service instead, which is out of scope. A registry that finds a pending
/// session whose key is not in its table fails closed ([`StoreUnavailable`]).
///
/// Entries are removed when their session is consumed or expired, when Redis refused the
/// insert or the connection was refused before it was sent, and by `purge` / `expire_due`
/// (before they contact Redis, so also during an outage) once their `expires_at` has passed.
/// A registry's inserts are refused once the table holds `max_pending` +
/// [`KEY_TABLE_SLACK`] keys.
pub struct KeyTable<K> {
    entries: Arc<Mutex<HashMap<String, Entry<K>>>>,
}

impl<K> KeyTable<K> {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Number of keys held.
    ///
    /// # Errors
    /// [`StoreUnavailable`] if the table lock is poisoned.
    pub fn len(&self) -> Result<usize, StoreUnavailable> {
        Ok(self.entries.lock().map_err(|_| StoreUnavailable)?.len())
    }

    /// `true` if no key is held.
    ///
    /// # Errors
    /// [`StoreUnavailable`] if the table lock is poisoned.
    pub fn is_empty(&self) -> Result<bool, StoreUnavailable> {
        Ok(self.len()? == 0)
    }

    /// Registers `key` under `key_ref`, before the Redis insert that names it. A table holding
    /// `cap` keys first drops those past their TTL at `now`; if it is still full the key is
    /// refused ([`StoreUnavailable`]), so the table stays bounded even while Redis is
    /// unreachable and unacknowledged inserts keep their keys.
    pub(crate) fn insert(
        &self,
        key_ref: String,
        entry: (SessionId, Timestamp, K),
        cap: usize,
        now: Timestamp,
    ) -> Result<(), StoreUnavailable> {
        let (session, expires_at, key) = entry;
        let entry = Entry {
            session,
            expires_at,
            key: Arc::new(key),
        };
        let mut entries = self.entries.lock().map_err(|_| StoreUnavailable)?;
        let mut removed = Vec::new();
        if entries.len() >= cap {
            removed = take_due(&mut entries, now);
        }
        let outcome = if entries.len() >= cap {
            Err(entry)
        } else {
            entries.insert(key_ref, entry);
            Ok(())
        };
        // Keys (removed or refused) are dropped after the lock is released.
        drop(entries);
        drop(removed);
        outcome.map_err(|_| StoreUnavailable)
    }

    /// The key registered under `key_ref` for `session`.
    pub(crate) fn get(
        &self,
        key_ref: &str,
        session: &SessionId,
    ) -> Result<Arc<K>, StoreUnavailable> {
        let entries = self.entries.lock().map_err(|_| StoreUnavailable)?;
        entries
            .get(key_ref)
            .filter(|e| e.session == *session)
            .map(|e| Arc::clone(&e.key))
            .ok_or(StoreUnavailable)
    }

    /// Forgets the listed references. Keys are dropped after the lock is released.
    pub(crate) fn remove<'a>(&self, key_refs: impl IntoIterator<Item = &'a str>) {
        let removed: Vec<Entry<K>> = match self.entries.lock() {
            Ok(mut entries) => key_refs
                .into_iter()
                .filter_map(|r| entries.remove(r))
                .collect(),
            // Poisoned: nothing can be read from the table any more, so nothing to clean up.
            Err(_) => Vec::new(),
        };
        drop(removed);
    }

    /// Forgets every key whose session is past its TTL at `now`.
    pub(crate) fn remove_due(&self, now: Timestamp) -> Result<(), StoreUnavailable> {
        let mut entries = self.entries.lock().map_err(|_| StoreUnavailable)?;
        let removed = take_due(&mut entries, now);
        drop(entries);
        drop(removed);
        Ok(())
    }
}

/// Removes and returns the entries past their TTL at `now`, for dropping outside the lock.
fn take_due<K>(entries: &mut HashMap<String, Entry<K>>, now: Timestamp) -> Vec<Entry<K>> {
    let due: Vec<String> = entries
        .iter()
        .filter(|(_, e)| now >= e.expires_at)
        .map(|(r, _)| r.clone())
        .collect();
    due.iter().filter_map(|r| entries.remove(r)).collect()
}

impl<K> Default for KeyTable<K> {
    fn default() -> Self {
        Self::new()
    }
}

// Manual impl: sharing the table needs no `K: Clone`.
impl<K> Clone for KeyTable<K> {
    fn clone(&self) -> Self {
        Self {
            entries: Arc::clone(&self.entries),
        }
    }
}
