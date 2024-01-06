use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use tokio::sync::Mutex;

use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
struct AuthCacheKey(Secret<[u8; 32]>);

impl PartialEq for AuthCacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl From<[u8; 32]> for AuthCacheKey {
    fn from(value: [u8; 32]) -> Self {
        Self(Secret::new(value))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AuthCache {
    known: Arc<Mutex<Vec<(AuthCacheKey, u64)>>>,
}

static AUTH_CACHE_EVICTION_TIMEOUT: Duration = Duration::from_secs(600);

/// checks if an entry last used at `entry_time` is still valid to be used at `now`,
/// where both `entry_time` and `now` are assumed to unix timestamps (in seconds).
fn entry_timed_out(entry_time: u64, now: u64) -> bool {
    entry_time + AUTH_CACHE_EVICTION_TIMEOUT.as_secs() < now
}

impl AuthCache {
    pub(crate) fn new() -> Self {
        AuthCache {
            known: Arc::new(Mutex::default()),
        }
    }

    /// checks if an the auth data is contained in the cache.
    /// If it is, its timestamp of last use is updated, and true is returned, meaning
    /// we can assume a password validation with these parameters would succeed.
    pub(crate) async fn contains(&self, hash: &str, pw: &str, nonce: &str) -> bool {
        let key = Self::build_hash(hash, pw, nonce);

        let now = Self::now();

        let list_of_entries = &mut self.known.lock().await;
        if let Some((_, time)) = list_of_entries
            .iter_mut()
            .find(|(ekey, time)| ekey == &key && !entry_timed_out(*time, now))
        {
            *time = now;
            true
        } else {
            false
        }
    }

    pub(crate) async fn insert(&self, hash: &str, pw: &str, nonce: &str) {
        let key = Self::build_hash(hash, pw, nonce);

        let now = Self::now();

        let list_of_entries = &mut self.known.lock().await;
        if let Some((_, time)) = list_of_entries.iter_mut().find(|(ekey, _)| ekey == &key) {
            *time = now;
        } else {
            list_of_entries.push((key, now));
        }
    }

    /// starts a background process that periodically checks the cache for old entries to drop them.
    /// This is not (just) done to keep the cache size limited, but instead to make sure unused authentication
    /// data is not part of the process memory, which increases security (a bit).
    pub(crate) fn start_eviction_process(&self) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                this.evict_stale_records().await;
                tokio::time::sleep(tokio::time::Duration::new(300, 0)).await;
            }
        })
    }

    async fn evict_stale_records(&self) {
        let now = Self::now();

        self.known
            .lock()
            .await
            .retain(|(_, time)| !entry_timed_out(*time, now));
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn build_hash(hash: &str, pw: &str, nonce: &str) -> AuthCacheKey {
        let mut hasher = Sha256::new();

        hasher.update(hash.as_bytes());
        hasher.update(pw.as_bytes());
        hasher.update(nonce.as_bytes());

        let res = hasher.finalize();

        AuthCacheKey::from(<[u8; 32]>::from(res))
    }
}
