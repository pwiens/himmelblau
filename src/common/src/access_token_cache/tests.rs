#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use std::sync::atomic::AtomicBool;
use tokio::sync::Notify;

static ORIGIN: LazyLock<Instant> = LazyLock::new(Instant::now);
fn moment(seconds: u64) -> (SystemTime, Instant) {
    (
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds),
        *ORIGIN + Duration::from_secs(seconds),
    )
}

pub(super) fn fixture() -> (Arc<AccessTokenCache>, Arc<AtomicU64>, Arc<AtomicU64>) {
    let clock = Arc::new(AtomicU64::new(1000));
    let generation = Arc::new(AtomicU64::new(0));
    let now = clock.clone();
    (
        Arc::new(AccessTokenCache::new(
            generation.clone(),
            Arc::new(move || moment(now.load(Ordering::SeqCst))),
        )),
        clock,
        generation,
    )
}
pub(super) fn issued(expiry: Option<u64>) -> Result<IssuedToken, CacheError> {
    Ok(IssuedToken {
        response: "synthetic-fixture".to_string().into(),
        expires_at: expiry.map(moment),
    })
}
#[tokio::test]
async fn reuse_expiry_and_unknown_expiry() {
    let (cache, clock, _) = fixture();
    for _ in 0..4 {
        assert!(cache
            .get_or_acquire("same".into(), || async { issued(Some(2000)) })
            .await
            .is_ok());
    }
    assert_eq!(cache.stats().acquisitions, 1);
    clock.store(1940, Ordering::SeqCst);
    assert!(cache
        .get_or_acquire("same".into(), || async { issued(Some(2000)) })
        .await
        .is_ok());
    assert!(cache
        .get_or_acquire("same".into(), || async { issued(None) })
        .await
        .is_ok());
    assert!(cache
        .get_or_acquire("same".into(), || async { issued(Some(1900)) })
        .await
        .is_ok());
    assert_eq!(cache.stats().acquisitions, 4);
}
#[tokio::test]
async fn wall_clock_jumps_cannot_extend_tokens_or_change_backoff() {
    let (mut cache, wall, _) = fixture();
    let mono = Arc::new(AtomicU64::new(1000));
    let (w, m) = (wall.clone(), mono.clone());
    Arc::get_mut(&mut cache).unwrap().clock = Arc::new(move || {
        (
            moment(w.load(Ordering::SeqCst)).0,
            moment(m.load(Ordering::SeqCst)).1,
        )
    });
    assert!(cache
        .get_or_acquire("token".into(), || async { issued(Some(2000)) })
        .await
        .is_ok());
    wall.store(500, Ordering::SeqCst);
    mono.store(1940, Ordering::SeqCst);
    assert!(cache
        .get_or_acquire("token".into(), || async { issued(Some(3000)) })
        .await
        .is_ok());
    assert_eq!(cache.stats().acquisitions, 2);
    assert!(cache
        .get_or_acquire("failure".into(), || async { Err(CacheError::Acquisition) })
        .await
        .is_err());
    wall.store(100_000, Ordering::SeqCst);
    assert!(cache
        .get_or_acquire("failure".into(), || async {
            panic!("wall jump bypassed backoff")
        })
        .await
        .is_err());
    mono.store(1943, Ordering::SeqCst);
    assert!(cache
        .get_or_acquire("failure".into(), || async { issued(None) })
        .await
        .is_ok());
    assert_eq!(cache.stats().acquisitions, 4);
}

#[tokio::test]
async fn concurrent_singleflight_and_different_keys_progress() {
    let (cache, _, _) = fixture();
    let release = Arc::new(Notify::new());
    let started = Arc::new(Notify::new());
    let first = {
        let c = cache.clone();
        let r = release.clone();
        let s = started.clone();
        tokio::spawn(async move {
            c.get_or_acquire("same".into(), || async {
                s.notify_one();
                r.notified().await;
                issued(Some(2000))
            })
            .await
        })
    };
    started.notified().await;
    let mut waiters = vec![];
    for _ in 0..10 {
        let c = cache.clone();
        waiters.push(tokio::spawn(async move {
            c.get_or_acquire("same".into(), || async {
                panic!("waiter acquired upstream")
            })
            .await
        }));
    }
    for dimension in [
        "uid",
        "account-id",
        "tenant-corp",
        "tenant-tme",
        "client",
        "scope-case",
        "claims",
        "authority",
        "pop",
        "redirect",
    ] {
        assert!(cache
            .get_or_acquire(dimension.into(), || async { issued(Some(2000)) })
            .await
            .is_ok());
    }
    tokio::task::yield_now().await;
    release.notify_one();
    assert!(first.await.unwrap().is_ok());
    for task in waiters {
        assert!(task.await.unwrap().is_ok());
    }
    assert_eq!(cache.stats().acquisitions, 11);
    assert_eq!(cache.stats().waits, 10);
}
#[tokio::test]
async fn invalidation_fences_inflight_and_does_not_start_replacements() {
    let (cache, _, generation) = fixture();
    let release = Arc::new(Notify::new());
    let started = Arc::new(Notify::new());
    let first = {
        let c = cache.clone();
        let r = release.clone();
        let s = started.clone();
        tokio::spawn(async move {
            c.get_or_acquire("key".into(), || async {
                s.notify_one();
                r.notified().await;
                issued(Some(2000))
            })
            .await
        })
    };
    started.notified().await;
    generation.fetch_add(1, Ordering::SeqCst);
    assert!(matches!(
        cache
            .get_or_acquire("key".into(), || async { issued(Some(2000)) })
            .await,
        Err(CacheError::Invalidated)
    ));
    release.notify_one();
    assert!(matches!(first.await.unwrap(), Err(CacheError::Invalidated)));
    assert!(cache
        .get_or_acquire("key".into(), || async { issued(Some(2000)) })
        .await
        .is_ok());
    assert_eq!(cache.stats().acquisitions, 2);
}
#[tokio::test]
async fn cancellation_releases_waiters_and_failure_backoff_never_retries() {
    let (cache, clock, _) = fixture();
    let started = Arc::new(Notify::new());
    let first = {
        let c = cache.clone();
        let s = started.clone();
        tokio::spawn(async move {
            c.get_or_acquire("key".into(), || async {
                s.notify_one();
                std::future::pending().await
            })
            .await
        })
    };
    started.notified().await;
    let waiter = {
        let c = cache.clone();
        tokio::spawn(async move {
            c.get_or_acquire("key".into(), || async { panic!("waiter retried") })
                .await
        })
    };
    tokio::task::yield_now().await;
    first.abort();
    let _ = first.await;
    assert!(matches!(
        waiter.await.unwrap(),
        Err(CacheError::Acquisition)
    ));
    for _ in 0..20 {
        assert!(matches!(
            cache
                .get_or_acquire("key".into(), || async { panic!("backoff retried") })
                .await,
            Err(CacheError::Acquisition)
        ));
    }
    clock.store(1003, Ordering::SeqCst);
    assert!(cache
        .get_or_acquire("key".into(), || async { issued(Some(2000)) })
        .await
        .is_ok());
    assert_eq!(cache.stats().acquisitions, 2);
}
#[tokio::test]
async fn acquisition_timeout_is_bounded_and_failed_not_cached_as_success() {
    let (mut cache, _, _) = fixture();
    Arc::get_mut(&mut cache).unwrap().timeout = Duration::from_millis(10);
    assert!(matches!(
        cache
            .get_or_acquire("timeout".into(), || async { std::future::pending().await })
            .await,
        Err(CacheError::Timeout)
    ));
    assert!(matches!(
        cache
            .get_or_acquire("timeout".into(), || async {
                panic!("timeout caused replacement storm")
            })
            .await,
        Err(CacheError::Timeout)
    ));
    assert_eq!(cache.stats().acquisitions, 1);
}

#[tokio::test]
async fn authorization_is_required_even_on_a_warm_entry() {
    let (cache, _, _) = fixture();
    let authorized = AtomicBool::new(true);
    async fn request(cache: &AccessTokenCache, allowed: &AtomicBool) -> ResultToken {
        if !allowed.load(Ordering::SeqCst) {
            return Err(CacheError::Invalidated);
        }
        let token = cache
            .get_or_acquire("uid/account".into(), || async { issued(Some(2000)) })
            .await?;
        if !allowed.load(Ordering::SeqCst) {
            return Err(CacheError::Invalidated);
        }
        Ok(token)
    }
    assert!(request(&cache, &authorized).await.is_ok());
    authorized.store(false, Ordering::SeqCst);
    assert!(request(&cache, &authorized).await.is_err());
    assert_eq!(cache.stats().requests, 1);
}
#[tokio::test]
async fn capacity_and_oversized_values_are_bounded() {
    let (cache, _, _) = fixture();
    for i in 0..CAPACITY + 10 {
        assert!(cache
            .get_or_acquire(i.to_string(), || async { issued(Some(2000)) })
            .await
            .is_ok());
    }
    assert_eq!(cache.inner.lock().unwrap().entries.len(), CAPACITY);
    for _ in 0..2 {
        assert!(cache
            .get_or_acquire("large".into(), || async {
                Ok(IssuedToken {
                    response: "x".repeat(MAX_RESPONSE + 1).into(),
                    expires_at: Some(moment(2000)),
                })
            })
            .await
            .is_ok());
    }
    assert!(!cache.inner.lock().unwrap().entries.contains_key("large"));
}

// Real separate OS client processes, isolated ephemeral loopback listener and a
// fake issuer. This is NOT a live broker/Entra smoke test. No bearer is logged.
#[test]
fn subprocess_cache_client() {
    use std::io::{Read, Write};
    let Ok(address) = std::env::var("HIMMELBLAU_TEST_CACHE_ADDRESS") else {
        return;
    };
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream.write_all(b"authorized-fixture\n").unwrap();
    let mut result = String::new();
    stream.read_to_string(&mut result).unwrap();
    assert!(result == "synthetic-fixture");
}
#[tokio::test]
async fn separate_processes_two_passes_and_restart() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Before: 11 PRs * 2 passes * 3 acquisitions. After: one per observation,
    // and a shared issuer result. Last case is a restarted, cold service.
    for (shared, requests, expected_issuances, expected_hits) in
        [(false, 66, 66, 0), (true, 22, 1, 21), (true, 1, 1, 0)]
    {
        let (cache, clock, _) = fixture();
        let issuances = AtomicU64::new(0);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let clients = tokio::task::spawn_blocking(move || {
            for _ in 0..requests {
                let status = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "access_token_cache::tests::subprocess_cache_client",
                    ])
                    .env("HIMMELBLAU_TEST_CACHE_ADDRESS", addr.to_string())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .unwrap();
                assert!(status.success());
            }
        });
        for index in 0..requests {
            if index == requests / 2 {
                clock.store(1120, Ordering::SeqCst);
            }
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 19];
            stream.read_exact(&mut request).await.unwrap();
            assert!(&request == b"authorized-fixture\n");
            if shared {
                // A different resource's fresh PRT-readiness acquisition on
                // every client request must not evict this ADO token.
                assert!(cache
                    .get_or_acquire_with_policy(
                        "uid/account/ARM-readiness".into(),
                        true,
                        || async { issued(Some(2000)) }
                    )
                    .await
                    .is_ok());
            }
            let acquire = || async {
                issuances.fetch_add(1, Ordering::SeqCst);
                issued(Some(2000))
            };
            let token = if shared {
                cache
                    .get_or_acquire("uid/account/tenant/client/scope".into(), acquire)
                    .await
                    .unwrap()
            } else {
                CachedResponse::uncached(acquire().await.unwrap().response)
            };
            stream.write_all(token.as_bytes()).await.unwrap();
        }
        clients.await.unwrap();
        assert_eq!(issuances.load(Ordering::SeqCst), expected_issuances);
        assert_eq!(cache.stats().hits, expected_hits);
        if shared {
            assert_eq!(cache.stats().acquisitions, requests + 1);
        }
        eprintln!("offline process simulation: requests={requests}, upstream_issuance={expected_issuances}, hits={expected_hits}");
    }
}
