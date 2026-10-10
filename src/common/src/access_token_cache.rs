//! Bounded memory-only broker cache. Authorize before lookup AND before releasing
//! a result. Forced refresh replaces only the matching entry; actual credential
//! changes fence all entries conservatively. No lock spans an await.
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::watch;
use zeroize::Zeroizing;

pub mod diagnostics;
use diagnostics::{event, Event, Reason};

static GENERATION: LazyLock<Arc<AtomicU64>> = LazyLock::new(|| Arc::new(AtomicU64::new(0)));
pub fn access_token_generation() -> u64 {
    GENERATION.load(Ordering::SeqCst)
}
pub fn invalidate_access_tokens(reason: Reason) {
    GENERATION.fetch_add(1, Ordering::SeqCst);
    event(Event::InvalidationStart, reason, 0, None);
}
/// Fence both ends of real async authorization mutations, including cancellation.
pub(crate) struct Invalidation(Reason);
impl Invalidation {
    pub(crate) fn new(reason: Reason) -> Self {
        invalidate_access_tokens(reason);
        Self(reason)
    }
}
impl Drop for Invalidation {
    fn drop(&mut self) {
        GENERATION.fetch_add(1, Ordering::SeqCst);
        event(Event::InvalidationEnd, self.0, 0, None);
    }
}
const CAPACITY: usize = 128;
const MAX_RESPONSE: usize = 64 * 1024;
const MAX_KEY: usize = 16 * 1024;
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(40);
const FAILURE_BACKOFF: Duration = Duration::from_secs(2);
const EXPIRY_MARGIN: Duration = Duration::from_secs(60);
type Expiry = (SystemTime, Instant);
type ResultToken = Result<CachedResponse, CacheError>;

/// A lease, not just a token string: callers revalidate it after async caller
/// authorization. This closes key-local invalidation races after a cache hit.
#[derive(Clone)]
pub struct CachedResponse {
    response: Arc<Zeroizing<String>>,
    valid: Arc<AtomicBool>,
    generation: u64,
    current_generation: Arc<AtomicU64>,
}
impl CachedResponse {
    pub fn uncached(response: Zeroizing<String>) -> Self {
        Self {
            response: Arc::new(response),
            valid: Arc::new(AtomicBool::new(true)),
            generation: access_token_generation(),
            current_generation: GENERATION.clone(),
        }
    }
    pub fn validate(&self) -> Result<(), CacheError> {
        if self.valid.load(Ordering::SeqCst)
            && self.generation == self.current_generation.load(Ordering::SeqCst)
        {
            Ok(())
        } else {
            Err(CacheError::Invalidated)
        }
    }
    pub fn as_str(&self) -> &str {
        self.response.as_str()
    }
}
impl std::ops::Deref for CachedResponse {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}
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
impl CacheError {
    fn reason(self) -> Reason {
        match self {
            Self::Acquisition => Reason::BackendFailure,
            Self::Timeout => Reason::AcquisitionTimeout,
            Self::Invalidated => Reason::Invalidated,
            Self::Busy => Reason::Capacity,
        }
    }
}
/// Both bounds are computed before issuance. A wall-clock rollback cannot extend
/// retention. Missing/unsafe expiry is returned to the caller but never stored.
pub struct IssuedToken {
    pub response: Zeroizing<String>,
    pub expires_at: Option<Expiry>,
}
struct Entry {
    id: u64,
    generation: u64,
    valid: Arc<AtomicBool>,
    touched: u64,
    state: State,
}
enum State {
    Pending {
        sender: watch::Sender<Option<ResultToken>>,
        forced: bool,
    },
    Ready(CachedResponse, Expiry),
    Failed(CacheError, Instant),
}
#[derive(Default)]
struct Inner {
    entries: HashMap<String, Entry>,
    // Keep a bounded weak index of live leases even after expiry/LRU eviction
    // or a non-cacheable result. A later force/challenge must still fence them.
    leases: HashMap<String, Weak<AtomicBool>>,
    sequence: u64,
}
#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    hits: AtomicU64,
    waits: AtomicU64,
    acquisitions: AtomicU64,
    failures: AtomicU64,
    stores: AtomicU64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheStats {
    pub requests: u64,
    pub hits: u64,
    pub waits: u64,
    pub acquisitions: u64,
    pub failures: u64,
    pub stores: u64,
}
pub struct AccessTokenCache {
    inner: Mutex<Inner>,
    generation: Arc<AtomicU64>,
    clock: Arc<dyn Fn() -> Expiry + Send + Sync>,
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
    fn new(generation: Arc<AtomicU64>, clock: Arc<dyn Fn() -> Expiry + Send + Sync>) -> Self {
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
            stores: c.stores.load(Ordering::Relaxed),
        }
    }
    /// Unsupported claims cannot be fulfilled, but must fence the matching plain
    /// request. Keep pending entries until completion, so invalidation cannot
    /// start an unbounded number of replacement exchanges.
    pub fn invalidate_key(&self, key: &str, reason: Reason) -> Result<(), CacheError> {
        let mut inner = self.inner.lock().map_err(|_| CacheError::Busy)?;
        if let Some(valid) = inner.leases.get(key).and_then(Weak::upgrade) {
            valid.store(false, Ordering::SeqCst);
        }
        if let Some(entry) = inner.entries.get_mut(key) {
            entry.valid.store(false, Ordering::SeqCst);
            event(Event::InvalidateKey, reason, entry.id, Some(self.stats()));
            if !matches!(entry.state, State::Pending { .. }) {
                inner.entries.remove(key);
            }
        } else {
            event(Event::InvalidateKey, reason, 0, Some(self.stats()));
        }
        Ok(())
    }
    pub async fn get_or_acquire<F, Fut>(&self, key: String, acquire: F) -> ResultToken
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<IssuedToken, CacheError>>,
    {
        self.get_or_acquire_with_policy(key, false, acquire).await
    }
    pub async fn get_or_acquire_with_policy<F, Fut>(
        &self,
        key: String,
        force_refresh: bool,
        acquire: F,
    ) -> ResultToken
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<IssuedToken, CacheError>>,
    {
        self.counters.requests.fetch_add(1, Ordering::Relaxed);
        if key.len() > MAX_KEY {
            event(Event::Failure, Reason::KeyTooLarge, 0, Some(self.stats()));
            return Err(CacheError::Busy);
        }
        let generation = self.generation.load(Ordering::SeqCst);
        let now = (self.clock)();
        let (mut receiver, leader, valid, entry_id) = {
            let mut inner = self.inner.lock().map_err(|_| CacheError::Busy)?;
            let mut miss_reason = Reason::Cold;
            inner.entries.retain(|k, entry| {
                let reason = if entry.generation != generation
                    || (!entry.valid.load(Ordering::SeqCst)
                        && !matches!(entry.state, State::Failed(_, _)))
                {
                    Some(Reason::GenerationChanged)
                } else {
                    match entry.state {
                        State::Failed(CacheError::Invalidated, _) => {
                            Some(Reason::GenerationChanged)
                        }
                        State::Ready(_, expiry) if !usable(expiry, now) => Some(Reason::Expired),
                        State::Failed(_, until) if until <= now.1 => Some(Reason::FailureBackoff),
                        _ => None,
                    }
                };
                if let Some(reason) = reason {
                    if k == &key {
                        miss_reason = reason;
                    }
                    if !matches!(entry.state, State::Pending { .. }) {
                        event(Event::Evicted, reason, entry.id, None);
                        return false;
                    }
                }
                true
            });
            // MSAL force_refresh bypasses this AT, not unrelated client/resource
            // entries. Concurrent fresh acquisitions join each other, but an old
            // ordinary flight is fenced and cannot repopulate or return a token.
            if force_refresh {
                let join_fresh = inner.entries.get(&key).is_some_and(|entry| {
                    matches!(entry.state, State::Pending { forced: true, .. })
                });
                if !join_fresh {
                    if let Some(valid) = inner.leases.get(&key).and_then(Weak::upgrade) {
                        valid.store(false, Ordering::SeqCst);
                        if !inner.entries.contains_key(&key) {
                            event(
                                Event::InvalidateKey,
                                Reason::ForcedRefresh,
                                0,
                                Some(self.stats()),
                            );
                        }
                    }
                }
                if let Some(entry) = inner.entries.get_mut(&key) {
                    match entry.state {
                        State::Pending { forced: true, .. } | State::Failed(_, _) => {}
                        State::Pending { forced: false, .. } => {
                            entry.valid.store(false, Ordering::SeqCst);
                            event(
                                Event::InvalidateKey,
                                Reason::ForcedRefresh,
                                entry.id,
                                Some(self.stats()),
                            );
                            return Err(CacheError::Invalidated);
                        }
                        _ => {
                            entry.valid.store(false, Ordering::SeqCst);
                            event(
                                Event::InvalidateKey,
                                Reason::ForcedRefresh,
                                entry.id,
                                Some(self.stats()),
                            );
                            inner.entries.remove(&key);
                        }
                    }
                }
                miss_reason = Reason::ForcedRefresh;
            }
            inner.sequence = inner.sequence.wrapping_add(1);
            let touched = inner.sequence;
            if let Some(entry) = inner.entries.get_mut(&key) {
                if let State::Failed(error, _) = entry.state {
                    event(
                        Event::Failure,
                        Reason::FailureBackoff,
                        entry.id,
                        Some(self.stats()),
                    );
                    return Err(error);
                }
                if entry.generation != generation || !entry.valid.load(Ordering::SeqCst) {
                    event(
                        Event::Failure,
                        Reason::Invalidated,
                        entry.id,
                        Some(self.stats()),
                    );
                    return Err(CacheError::Invalidated);
                }
                entry.touched = touched;
                match &entry.state {
                    State::Ready(token, _) => {
                        token.validate()?;
                        self.counters.hits.fetch_add(1, Ordering::Relaxed);
                        event(Event::Hit, Reason::Eligible, entry.id, Some(self.stats()));
                        return Ok(token.clone());
                    }
                    State::Failed(error, _) => {
                        event(
                            Event::Failure,
                            Reason::FailureBackoff,
                            entry.id,
                            Some(self.stats()),
                        );
                        return Err(*error);
                    }
                    State::Pending { sender, .. } => {
                        self.counters.waits.fetch_add(1, Ordering::Relaxed);
                        event(Event::Wait, Reason::Pending, entry.id, Some(self.stats()));
                        (sender.subscribe(), false, entry.valid.clone(), entry.id)
                    }
                }
            } else {
                if inner.entries.len() >= CAPACITY {
                    let oldest = inner
                        .entries
                        .iter()
                        .filter(|(_, e)| !matches!(e.state, State::Pending { .. }))
                        .min_by_key(|(_, e)| e.touched)
                        .map(|(k, _)| k.clone());
                    if let Some(oldest) = oldest {
                        if let Some(entry) = inner.entries.remove(&oldest) {
                            event(Event::Evicted, Reason::Capacity, entry.id, None);
                        }
                    } else {
                        event(Event::Failure, Reason::Capacity, 0, Some(self.stats()));
                        return Err(CacheError::Busy);
                    }
                }
                inner.leases.retain(|_, weak| {
                    weak.upgrade()
                        .is_some_and(|valid| valid.load(Ordering::SeqCst))
                });
                if !inner.leases.contains_key(&key) && inner.leases.len() >= CAPACITY {
                    event(Event::Failure, Reason::Capacity, 0, Some(self.stats()));
                    return Err(CacheError::Busy);
                }
                let valid = inner
                    .leases
                    .get(&key)
                    .and_then(Weak::upgrade)
                    .filter(|valid| valid.load(Ordering::SeqCst))
                    .unwrap_or_else(|| Arc::new(AtomicBool::new(true)));
                inner.leases.insert(key.clone(), Arc::downgrade(&valid));
                let (sender, receiver) = watch::channel(None);
                inner.entries.insert(
                    key.clone(),
                    Entry {
                        id: touched,
                        generation,
                        valid: valid.clone(),
                        touched,
                        state: State::Pending {
                            sender,
                            forced: force_refresh,
                        },
                    },
                );
                event(Event::Miss, miss_reason, touched, Some(self.stats()));
                (receiver, true, valid, touched)
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
            .unwrap_or(Err(CacheError::Timeout));
            let result = result.and_then(|token| {
                token.validate()?;
                Ok(token)
            });
            if let Err(error) = result {
                event(Event::Failure, error.reason(), entry_id, Some(self.stats()));
            }
            return result;
        }
        let mut guard = Flight {
            cache: self,
            key,
            entry_id,
            generation,
            valid,
            complete: false,
        };
        self.counters.acquisitions.fetch_add(1, Ordering::Relaxed);
        let issued = tokio::time::timeout(self.timeout, acquire())
            .await
            .unwrap_or(Err(CacheError::Timeout));
        let now = (self.clock)();
        let (result, expiry, reason) = match issued {
            Ok(issued) => {
                let reason = match issued.expires_at {
                    None => Reason::UnknownExpiry,
                    Some(expiry) if !usable(expiry, now) => Reason::NearExpiry,
                    _ if issued.response.len() > MAX_RESPONSE => Reason::ResponseTooLarge,
                    _ => Reason::Eligible,
                };
                let expiry = issued.expires_at.filter(|_| reason == Reason::Eligible);
                let token = CachedResponse {
                    response: Arc::new(issued.response),
                    valid: guard.valid.clone(),
                    generation,
                    current_generation: self.generation.clone(),
                };
                let result = token.validate().map(|()| token);
                (result, expiry, reason)
            }
            Err(error) => (Err(error), None, error.reason()),
        };
        guard.finish(result.clone(), expiry, reason);
        result.and_then(|token| {
            token.validate()?;
            Ok(token)
        })
    }
}
fn usable(expiry: Expiry, now: Expiry) -> bool {
    expiry
        .0
        .duration_since(now.0)
        .is_ok_and(|d| d > EXPIRY_MARGIN)
        && expiry
            .1
            .checked_duration_since(now.1)
            .is_some_and(|d| d > EXPIRY_MARGIN)
}
struct Flight<'a> {
    cache: &'a AccessTokenCache,
    key: String,
    entry_id: u64,
    generation: u64,
    valid: Arc<AtomicBool>,
    complete: bool,
}
impl Flight<'_> {
    fn finish(&mut self, mut result: ResultToken, expiry: Option<Expiry>, reason: Reason) {
        if let Ok(mut inner) = self.cache.inner.lock() {
            if let Some(entry) = inner.entries.get_mut(&self.key) {
                if entry.id == self.entry_id {
                    if self.generation != self.cache.generation.load(Ordering::SeqCst)
                        || !self.valid.load(Ordering::SeqCst)
                    {
                        result = Err(CacheError::Invalidated);
                    }
                    if result.is_err() {
                        self.cache.counters.failures.fetch_add(1, Ordering::Relaxed);
                    }
                    if let State::Pending { sender, .. } = &entry.state {
                        sender.send_replace(Some(result.clone()));
                    }
                    entry.state = match (result, expiry) {
                        (Ok(token), Some(expiry)) => {
                            self.cache.counters.stores.fetch_add(1, Ordering::Relaxed);
                            event(Event::Stored, reason, entry.id, Some(self.cache.stats()));
                            State::Ready(token, expiry)
                        }
                        (Err(error), _) => {
                            let reason = if reason == Reason::LeaderCancelled {
                                reason
                            } else {
                                error.reason()
                            };
                            event(Event::Failure, reason, entry.id, Some(self.cache.stats()));
                            State::Failed(error, (self.cache.clock)().1 + FAILURE_BACKOFF)
                        }
                        (Ok(_), None) => {
                            event(Event::NotStored, reason, entry.id, Some(self.cache.stats()));
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
            self.finish(Err(CacheError::Acquisition), None, Reason::LeaderCancelled);
        }
    }
}
#[cfg(test)]
mod regression_tests;
#[cfg(test)]
mod tests;
