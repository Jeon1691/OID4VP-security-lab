//! In-process key table: the private-key handles that never go to Redis.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use protocol_model::SessionId;
use session_core::{StoreUnavailable, Timestamp};

/// Random bytes in a key reference: 128 bits, so references minted independently by several
/// workers never collide in practice (birthday bound near 2^64 sessions) and need no
/// coordination through Redis.
const KEY_REF_BYTES: usize = 16;

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
/// Entries are removed when their session is consumed or expired, and by `purge` /
/// `expire_due` once their `expires_at` has passed (also for sessions another registry moved
/// on), so the table holds at most the sessions that are still live.
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

    /// Registers `key` under `key_ref`, before the Redis insert that names it.
    pub(crate) fn insert(
        &self,
        key_ref: String,
        session: SessionId,
        expires_at: Timestamp,
        key: K,
    ) -> Result<(), StoreUnavailable> {
        let entry = Entry {
            session,
            expires_at,
            key: Arc::new(key),
        };
        self.entries
            .lock()
            .map_err(|_| StoreUnavailable)?
            .insert(key_ref, entry);
        Ok(())
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
        let due: Vec<String> = entries
            .iter()
            .filter(|(_, e)| now >= e.expires_at)
            .map(|(r, _)| r.clone())
            .collect();
        let removed: Vec<Entry<K>> = due.iter().filter_map(|r| entries.remove(r)).collect();
        drop(entries);
        drop(removed);
        Ok(())
    }
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
