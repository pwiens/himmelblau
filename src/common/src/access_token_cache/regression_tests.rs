#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::tests::{fixture, issued};
use super::*;
use tokio::sync::Notify;

#[tokio::test]
async fn forced_refresh_replaces_only_matching_token_and_invalidates_old_lease() {
    let (cache, _, generation) = fixture();
    let old = cache
        .get_or_acquire("ado".into(), || async { issued(Some(2000)) })
        .await
        .unwrap();
    let other = cache
        .get_or_acquire("graph".into(), || async { issued(Some(2000)) })
        .await
        .unwrap();
    let fresh = cache
        .get_or_acquire_with_policy("ado".into(), true, || async { issued(Some(2000)) })
        .await
        .unwrap();
    assert!(old.validate().is_err());
    assert!(other.validate().is_ok());
    assert!(fresh.validate().is_ok());
    assert!(cache
        .get_or_acquire("ado".into(), || async {
            panic!("fresh result was keyed by policy")
        })
        .await
        .is_ok());
    assert!(cache
        .get_or_acquire("graph".into(), || async {
            panic!("unrelated token flushed")
        })
        .await
        .is_ok());
    assert_eq!(cache.stats().acquisitions, 3);
    assert_eq!(generation.load(Ordering::SeqCst), 0);
    // Actual credential replacement still fences ALL leases, including a hit
    // whose caller is performing asynchronous post-hit authorization.
    generation.fetch_add(1, Ordering::SeqCst);
    assert!(fresh.validate().is_err());
    assert!(other.validate().is_err());
}
#[tokio::test]
async fn noncacheable_and_evicted_leases_are_still_fenced_during_reauthorization() {
    let (cache, _, _) = fixture();
    let transient = cache
        .get_or_acquire("opaque".into(), || async { issued(None) })
        .await
        .unwrap();
    cache
        .invalidate_key("opaque", Reason::ClaimsChallenge)
        .unwrap();
    assert!(transient.validate().is_err());
    let old = cache
        .get_or_acquire("ado".into(), || async { issued(Some(2000)) })
        .await
        .unwrap();
    for i in 0..CAPACITY - 1 {
        assert!(cache
            .get_or_acquire(format!("other-{i}"), || async { issued(Some(2000)) })
            .await
            .is_ok());
    }
    // Force an LRU eviction of the entry, while the authorization caller holds
    // its lease. The weak lease index must not evict an outstanding fence.
    assert!(cache
        .get_or_acquire("over-capacity".into(), || async { issued(Some(2000)) })
        .await
        .is_err());
    cache
        .invalidate_key("ado", Reason::ClaimsChallenge)
        .unwrap();
    assert!(old.validate().is_err());
}

#[tokio::test]
async fn forced_or_challenged_old_flight_cannot_repopulate_or_return() {
    for forced in [true, false] {
        let (cache, _, _) = fixture();
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let first = {
            let c = cache.clone();
            let s = started.clone();
            let r = release.clone();
            tokio::spawn(async move {
                c.get_or_acquire("ado".into(), || async {
                    s.notify_one();
                    r.notified().await;
                    issued(Some(2000))
                })
                .await
            })
        };
        started.notified().await;
        let waiter = {
            let c = cache.clone();
            tokio::spawn(async move {
                c.get_or_acquire("ado".into(), || async { panic!("duplicate issuer") })
                    .await
            })
        };
        tokio::task::yield_now().await;
        if forced {
            assert!(matches!(
                cache
                    .get_or_acquire_with_policy("ado".into(), true, || async {
                        panic!("replacement storm")
                    })
                    .await,
                Err(CacheError::Invalidated)
            ));
        } else {
            cache
                .invalidate_key("ado", Reason::ClaimsChallenge)
                .unwrap();
        }
        release.notify_one();
        assert!(matches!(first.await.unwrap(), Err(CacheError::Invalidated)));
        assert!(matches!(
            waiter.await.unwrap(),
            Err(CacheError::Invalidated)
        ));
        assert!(cache
            .get_or_acquire("ado".into(), || async { issued(Some(2000)) })
            .await
            .is_ok());
        assert_eq!(cache.stats().acquisitions, 2);
    }
}
#[tokio::test]
async fn forced_callers_coalesce_and_cannot_bypass_failure_backoff() {
    let (cache, _, _) = fixture();
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let first = {
        let c = cache.clone();
        let s = started.clone();
        let r = release.clone();
        tokio::spawn(async move {
            c.get_or_acquire_with_policy("key".into(), true, || async {
                s.notify_one();
                r.notified().await;
                Err(CacheError::Acquisition)
            })
            .await
        })
    };
    started.notified().await;
    let waiter = {
        let c = cache.clone();
        tokio::spawn(async move {
            c.get_or_acquire_with_policy("key".into(), true, || async {
                panic!("duplicate forced acquisition")
            })
            .await
        })
    };
    tokio::task::yield_now().await;
    release.notify_one();
    assert!(first.await.unwrap().is_err());
    assert!(waiter.await.unwrap().is_err());
    assert!(cache
        .get_or_acquire_with_policy("key".into(), true, || async {
            panic!("force defeated backoff")
        })
        .await
        .is_err());
    assert_eq!(cache.stats().acquisitions, 1);
    assert_eq!(cache.stats().waits, 1);
}
#[tokio::test]
async fn normal_level_diagnostics_explain_outcomes_without_secret_fields_or_parent_spans() {
    // Other upstream tests replace scoped dispatchers/interest filters in
    // parallel. Exercise one stable INFO subscriber in an isolated process,
    // like the actual daemon, rather than depending on those test filters.
    if std::env::var_os("HIMMELBLAU_DIAGNOSTICS_TEST_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "access_token_cache::regression_tests::normal_level_diagnostics_explain_outcomes_without_secret_fields_or_parent_spans", "--nocapture"])
            .env("HIMMELBLAU_DIAGNOSTICS_TEST_CHILD", "1").output().unwrap();
        assert!(
            output.status.success(),
            "isolated diagnostics test failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    use tracing::field::{Field, Visit};
    use tracing::instrument::WithSubscriber;
    use tracing::{Event as TraceEvent, Subscriber};
    use tracing_subscriber::{
        layer::{Context, SubscriberExt},
        Layer,
    };
    #[derive(Default)]
    struct Fields(String);
    impl Visit for Fields {
        fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
            self.0 += &format!("{}={:?};", f.name(), v);
        }
    }
    struct Capture(Arc<Mutex<Vec<String>>>);
    impl<S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>> Layer<S> for Capture {
        fn on_event(&self, e: &TraceEvent<'_>, ctx: Context<'_, S>) {
            if e.metadata().target() != diagnostics::TARGET {
                return;
            }
            assert!(
                ctx.event_scope(e).is_none(),
                "cache event inherited auth span fields"
            );
            let mut fields = Fields::default();
            e.record(&mut fields);
            self.0.lock().unwrap().push(fields.0);
        }
    }
    let logs = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry()
        .with(Capture(logs.clone()))
        .with(tracing_subscriber::filter::LevelFilter::INFO);
    async {
        tracing::info_span!("untrusted_parent", account = "SECRET_PARENT").in_scope(|| {
            diagnostics::event(Event::Bypass, Reason::UnknownParameter, 0, None);
        });
        let mut log = diagnostics::RequestLog::default();
        diagnostics::REQUEST_ID
            .scope(log.id, async {
                let (cache, clock, _) = fixture();
                assert!(cache
                    .get_or_acquire("SECRET_UPN_and_SCOPES".into(), || async {
                        diagnostics::exchange(diagnostics::Exchange::Prt);
                        Ok(IssuedToken {
                            response: "SECRET_TOKEN".to_string().into(),
                            expires_at: issued(Some(2000)).unwrap().expires_at,
                        })
                    })
                    .await
                    .is_ok());
                assert!(cache
                    .get_or_acquire("SECRET_UPN_and_SCOPES".into(), || async {
                        panic!("cache miss")
                    })
                    .await
                    .is_ok());
                cache
                    .invalidate_key("SECRET_UPN_and_SCOPES", Reason::ClaimsChallenge)
                    .unwrap();
                assert!(cache
                    .get_or_acquire("unknown".into(), || async { issued(None) })
                    .await
                    .is_ok());
                assert!(cache
                    .get_or_acquire("expired".into(), || async { issued(Some(2000)) })
                    .await
                    .is_ok());
                clock.store(1940, Ordering::SeqCst);
                assert!(cache
                    .get_or_acquire("expired".into(), || async { Err(CacheError::Acquisition) })
                    .await
                    .is_err());
            })
            .await;
        log.stage = diagnostics::Stage::Complete;
        log.finish(diagnostics::Outcome::Success);
    }
    .with_subscriber(subscriber)
    .await;
    let text = logs.lock().unwrap().join("\n");
    assert!(
        !text.contains("SECRET"),
        "diagnostics exposed synthetic secret data"
    );
    for expected in [
        "Hit",
        "Miss",
        "Stored",
        "NotStored",
        "Failure",
        "Expired",
        "UnknownExpiry",
        "InvalidateKey",
        "ClaimsChallenge",
        "UnknownParameter",
        "entra_cache_exchange",
        "entra_cache_request",
        "schema_version=1",
        "elapsed_ms=",
        "request_id=",
        "entry_id=",
    ] {
        assert!(
            text.contains(expected),
            "missing diagnostic {expected}; redacted events: {text}"
        );
    }
}
