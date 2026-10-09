//! Memory-only broker response cache. Never persist this alongside the PRT cache.
//!
//! Callers MUST authorize before lookup and again after waiting. Keys contain the
//! peer uid, stable account identity and the exact issuance request. No secret or
//! cache struct derives Debug; metrics deliberately contain only aggregate counts.
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::watch;
use zeroize::Zeroizing;

// Conservative daemon-wide fencing: credential/account changes invalidate all
// broker entries, including in-flight acquisitions. This is intentionally not a
// persisted counter, nor an unbounded per-account generation registry.
static GENERATION: LazyLock<Arc<AtomicU64>> = LazyLock::new(|| Arc::new(AtomicU64::new(0)));
pub fn invalidate_access_tokens() {
    GENERATION.fetch_add(1, Ordering::SeqCst);
}
pub fn access_token_generation() -> u64 {
    GENERATION.load(Ordering::SeqCst)
}

/// Fence both ends of async authorization mutations, including cancellation.
/// The second fence prevents work started during the mutation from surviving it.
pub(crate) struct Invalidation;
impl Invalidation {
    pub(crate) fn new() -> Self {
        invalidate_access_tokens();
        Self
    }
}
impl Drop for Invalidation {
    fn drop(&mut self) {
        invalidate_access_tokens();
    }
}

const CAPACITY: usize = 128;
const MAX_RESPONSE: usize = 64 * 1024;
const MAX_KEY: usize = 16 * 1024;
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(40);
const FAILURE_BACKOFF: Duration = Duration::from_secs(2);
const EXPIRY_MARGIN: Duration = Duration::from_secs(60);

pub type SecretResponse = Arc<Zeroizing<String>>;
type ResultToken = Result<SecretResponse, CacheError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheError {
    Acquisition,
    Timeout,
    Invalidated,
    Busy,
}
impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Acquisition => "Failed to authenticate user",
            Self::Timeout => "Access token acquisition deadline exceeded",
            Self::Invalidated => "Access token authorization context changed",
            Self::Busy => "Access token cache busy",
        })
    }
}
impl std::error::Error for CacheError {}

/// Both bounds are computed before issuance, never extended on a hit. The
/// monotonic expires_in bound prevents a wall-clock rollback extending reuse.
pub struct IssuedToken {
    pub response: Zeroizing<String>,
    pub expires_at: Option<(SystemTime, Instant)>,
}
struct Entry {
    generation: u64,
    touched: u64,
    state: State,
}
enum State {
    Pending(watch::Sender<Option<ResultToken>>),
    Ready(SecretResponse, (SystemTime, Instant)),
    Failed(CacheError, Instant),
}
#[derive(Default)]
struct Inner {
    entries: HashMap<String, Entry>,
    sequence: u64,
}
#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    hits: AtomicU64,
    waits: AtomicU64,
    acquisitions: AtomicU64,
    failures: AtomicU64,
}
#[derive(Debug, PartialEq, Eq)]
pub struct CacheStats {
    pub requests: u64,
    pub hits: u64,
    pub waits: u64,
    pub acquisitions: u64,
    pub failures: u64,
}
pub struct AccessTokenCache {
    inner: Mutex<Inner>,
    generation: Arc<AtomicU64>,
    clock: Arc<dyn Fn() -> (SystemTime, Instant) + Send + Sync>,
    counters: Counters,
    timeout: Duration,
}
impl Default for AccessTokenCache {
    fn default() -> Self {
        Self::new(
            GENERATION.clone(),
            Arc::new(|| (SystemTime::now(), Instant::now())),
        )
    }
}
impl AccessTokenCache {
    fn new(
        generation: Arc<AtomicU64>,
        clock: Arc<dyn Fn() -> (SystemTime, Instant) + Send + Sync>,
    ) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            generation,
            clock,
            counters: Counters::default(),
            timeout: ACQUIRE_TIMEOUT,
        }
    }
    pub fn stats(&self) -> CacheStats {
        let c = &self.counters;
        CacheStats {
            requests: c.requests.load(Ordering::Relaxed),
            hits: c.hits.load(Ordering::Relaxed),
            waits: c.waits.load(Ordering::Relaxed),
            acquisitions: c.acquisitions.load(Ordering::Relaxed),
            failures: c.failures.load(Ordering::Relaxed),
        }
    }
    /// No lock spans an await. A cancelled leader publishes a bounded failure;
    /// waiters never independently retry or start interactive authentication.
    pub async fn get_or_acquire<F, Fut>(&self, key: String, acquire: F) -> ResultToken
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<IssuedToken, CacheError>>,
    {
        self.counters.requests.fetch_add(1, Ordering::Relaxed);
        if key.len() > MAX_KEY {
            return Err(CacheError::Busy);
        }
        let generation = self.generation.load(Ordering::SeqCst);
        let now = (self.clock)();
        let (mut receiver, leader) = {
            let mut inner = self.inner.lock().map_err(|_| CacheError::Busy)?;
            inner.entries.retain(|_, entry| match &entry.state {
                // Do not evict a live acquisition, even after invalidation. A
                // forced refresh cannot start a replacement request storm.
                State::Pending(_) => true,
                State::Ready(_, expiry) => entry.generation == generation && usable(*expiry, now),
                State::Failed(_, until) => entry.generation == generation && *until > now.1,
            });
            inner.sequence = inner.sequence.wrapping_add(1);
            let touched = inner.sequence;
            if let Some(entry) = inner.entries.get_mut(&key) {
                if entry.generation != generation {
                    return Err(CacheError::Invalidated);
                }
                entry.touched = touched;
                match &entry.state {
                    State::Ready(token, _) => {
                        self.counters.hits.fetch_add(1, Ordering::Relaxed);
                        return self.fence(generation, token.clone());
                    }
                    State::Failed(error, _) => return Err(*error),
                    State::Pending(sender) => {
                        self.counters.waits.fetch_add(1, Ordering::Relaxed);
                        (sender.subscribe(), false)
                    }
                }
            } else {
                if inner.entries.len() >= CAPACITY {
                    let oldest = inner
                        .entries
                        .iter()
                        .filter(|(_, e)| !matches!(e.state, State::Pending(_)))
                        .min_by_key(|(_, e)| e.touched)
                        .map(|(k, _)| k.clone());
                    if let Some(oldest) = oldest {
                        inner.entries.remove(&oldest);
                    } else {
                        return Err(CacheError::Busy);
                    }
                }
                let (sender, receiver) = watch::channel(None);
                inner.entries.insert(
                    key.clone(),
                    Entry {
                        generation,
                        touched,
                        state: State::Pending(sender),
                    },
                );
                (receiver, true)
            }
        };
        if !leader {
            let result = tokio::time::timeout(self.timeout, async {
                loop {
                    if let Some(result) = receiver.borrow_and_update().clone() {
                        break result;
                    }
                    if receiver.changed().await.is_err() {
                        break Err(CacheError::Acquisition);
                    }
                }
            })
            .await
            .map_err(|_| CacheError::Timeout)??;
            return self.fence(generation, result);
        }
        let mut guard = Flight {
            cache: self,
            key,
            generation,
            complete: false,
        };
        self.counters.acquisitions.fetch_add(1, Ordering::Relaxed);
        let result = tokio::time::timeout(self.timeout, acquire())
            .await
            .unwrap_or(Err(CacheError::Timeout));
        let now = (self.clock)();
        let (result, expiry) = match result {
            Ok(issued) => {
                let expiry = issued
                    .expires_at
                    .filter(|expiry| usable(*expiry, now))
                    .filter(|_| issued.response.len() <= MAX_RESPONSE);
                (self.fence(generation, Arc::new(issued.response)), expiry)
            }
            Err(error) => (Err(error), None),
        };
        guard.finish(result.clone(), expiry);
        result
    }
    fn fence(&self, generation: u64, token: SecretResponse) -> ResultToken {
        if generation == self.generation.load(Ordering::SeqCst) {
            Ok(token)
        } else {
            Err(CacheError::Invalidated)
        }
    }
}
fn usable(expiry: (SystemTime, Instant), now: (SystemTime, Instant)) -> bool {
    expiry
        .0
        .duration_since(now.0)
        .is_ok_and(|remaining| remaining > EXPIRY_MARGIN)
        && expiry
            .1
            .checked_duration_since(now.1)
            .is_some_and(|remaining| remaining > EXPIRY_MARGIN)
}
struct Flight<'a> {
    cache: &'a AccessTokenCache,
    key: String,
    generation: u64,
    complete: bool,
}
impl Flight<'_> {
    fn finish(&mut self, result: ResultToken, expiry: Option<(SystemTime, Instant)>) {
        if result.is_err() {
            self.cache.counters.failures.fetch_add(1, Ordering::Relaxed);
        }
        tracing::debug!(stats = ?self.cache.stats(), "broker access-token flight completed");
        if let Ok(mut inner) = self.cache.inner.lock() {
            if let Some(entry) = inner.entries.get_mut(&self.key) {
                if entry.generation == self.generation {
                    if let State::Pending(sender) = &entry.state {
                        sender.send_replace(Some(result.clone()));
                    }
                    entry.state = match (result, expiry) {
                        (Ok(token), Some(expiry)) => State::Ready(token, expiry),
                        (Err(error), _) => {
                            State::Failed(error, (self.cache.clock)().1 + FAILURE_BACKOFF)
                        }
                        // Unknown/near expiry and oversized responses may be
                        // returned to this flight, but never reused later.
                        (Ok(_), None) => {
                            inner.entries.remove(&self.key);
                            self.complete = true;
                            return;
                        }
                    };
                }
            }
        }
        self.complete = true;
    }
}
impl Drop for Flight<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.finish(Err(CacheError::Acquisition), None);
        }
    }
}

#[cfg(test)]
mod tests;
