//! Allowlisted INFO telemetry. Never attach caller strings, errors, keys or token
//! material. `parent: None` also excludes fields on upstream auth tracing spans.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub const TARGET: &str = "himmelblau::token_cache";
tokio::task_local! { pub static REQUEST_ID: u64; }
static REQUESTS: AtomicU64 = AtomicU64::new(0);
static EXCHANGES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Eligible,
    MalformedRequest,
    AuthorizationDenied,
    InvalidRedirect,
    InvalidForceRefresh,
    RequestCancelled,
    Cold,
    Expired,
    GenerationChanged,
    ForcedRefresh,
    ClaimsChallenge,
    Pending,
    FailureBackoff,
    Capacity,
    KeyTooLarge,
    NearExpiry,
    ResponseTooLarge,
    UnknownParameter,
    AccountUnusable,
    AccountMetadataMismatch,
    AuthorityMismatch,
    PopUnsupported,
    ClaimsUnsupported,
    NonBearer,
    IdIdentityMissing,
    IdIdentityMismatch,
    IdTenantMissing,
    IdTenantMismatch,
    AccessIdentityMissing,
    AccessIdentityMismatch,
    AccessTenantMissing,
    AccessTenantMismatch,
    ClientMissing,
    JwtExpiryMissing,
    AccessClaimsUnreadable,
    ClientMismatch,
    UnknownExpiry,
    AccessTokenMissing,
    GrantedScopesMissing,
    RawIdTokenMissing,
    BackendFailure,
    AcquisitionTimeout,
    Invalidated,
    LeaderCancelled,
    Completed,
    CredentialReplaced,
    PrtRemoved,
    RefreshTokenRemoved,
    PrtExpired,
    RefreshTokenExpired,
    PrtImport,
    AccountChanged,
    AccountRemoved,
    PasswordChanged,
    ExclusionsChanged,
    ResolverClear,
    ResolverInvalidate,
}
#[derive(Clone, Copy, Debug)]
pub enum Event {
    Hit,
    Miss,
    Wait,
    Bypass,
    Stored,
    NotStored,
    ResponseRejected,
    Failure,
    Evicted,
    InvalidationStart,
    InvalidationEnd,
    InvalidateKey,
}
#[derive(Clone, Copy, Debug)]
pub enum Exchange {
    Prt,
    RefreshToken,
}

pub fn event(event: Event, reason: Reason, entry_id: u64, stats: Option<super::CacheStats>) {
    let request_id = REQUEST_ID.try_with(|id| *id).unwrap_or(0);
    let generation = super::access_token_generation();
    tracing::info!(target: "himmelblau::token_cache", parent: None,
        schema_version = 1u32, request_id, entry_id, ?event, ?reason, generation, ?stats, "entra_cache_decision");
}
pub fn exchange(kind: Exchange) {
    let request_id = REQUEST_ID.try_with(|id| *id).unwrap_or(0);
    let exchanges = EXCHANGES.fetch_add(1, Ordering::Relaxed) + 1;
    // Invocations of the provider exchange, NOT a count of library HTTP requests.
    tracing::info!(target: "himmelblau::token_cache", parent: None,
        schema_version = 1u32, request_id, ?kind, exchanges, "entra_cache_exchange");
}
#[derive(Clone, Copy, Debug)]
pub enum Stage {
    Parse,
    AuthorizeBefore,
    Admission,
    Acquire,
    AuthorizeAfter,
    Complete,
}
#[derive(Clone, Copy, Debug)]
pub enum Outcome {
    Aborted,
    Success,
    Rejected,
    Timeout,
    Invalidated,
}
pub struct RequestLog {
    pub id: u64,
    pub stage: Stage,
    pub reason: Reason,
    outcome: Outcome,
    started: Instant,
}
impl Default for RequestLog {
    fn default() -> Self {
        Self {
            id: REQUESTS.fetch_add(1, Ordering::Relaxed) + 1,
            stage: Stage::Parse,
            reason: Reason::MalformedRequest,
            outcome: Outcome::Aborted,
            started: Instant::now(),
        }
    }
}
impl RequestLog {
    pub fn finish(&mut self, outcome: Outcome) {
        self.outcome = outcome;
        self.reason = match outcome {
            Outcome::Success => Reason::Completed,
            Outcome::Timeout => Reason::AcquisitionTimeout,
            Outcome::Invalidated => Reason::Invalidated,
            Outcome::Aborted => Reason::RequestCancelled,
            Outcome::Rejected => self.reason,
        };
    }
}
impl Drop for RequestLog {
    fn drop(&mut self) {
        if matches!(self.outcome, Outcome::Aborted) {
            self.reason = Reason::RequestCancelled;
        }
        tracing::info!(target: "himmelblau::token_cache", parent: None,
            schema_version = 1u32, request_id = self.id, stage = ?self.stage, outcome = ?self.outcome, reason = ?self.reason,
            elapsed_ms = self.started.elapsed().as_millis() as u64,
            "entra_cache_request");
    }
}
