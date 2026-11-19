use dashmap::DashMap;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

const MAX_DNS_ENTRIES: usize = 512;
const DNS_TTL: Duration = Duration::from_secs(120);
const DNS_STALE_WINDOW: Duration = Duration::from_secs(300);
const DNS_NEG_TTL: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
struct DnsEntry {
    addrs: Vec<IpAddr>,
    expires_at: Instant,
    stale_until: Instant,
    negative: bool,
}

/// Low-footprint async DNS cache with:
/// - Singleflight deduplication (concurrent lookups for same host share one resolution)
/// - Stale-while-revalidate (zero-latency return on recently expired entries while refreshing in background)
/// - Negative caching (protects resolver when upstream host is down)
/// - Strict entry cap (512 entries, ~64 KB RAM max)
#[derive(Clone)]
pub struct DnsCache {
    cache: Arc<DashMap<String, DnsEntry>>,
    inflight: Arc<DashMap<String, broadcast::Sender<Result<Vec<IpAddr>, String>>>>,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(DashMap::with_capacity(64)),
            inflight: Arc::new(DashMap::with_capacity(16)),
        }
    }

    pub async fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        if host.eq_ignore_ascii_case("localhost") {
            return Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let key = host.to_ascii_lowercase();
        let now = Instant::now();

        if let Some(entry) = self.cache.get(&key) {
            if now < entry.expires_at {
                if entry.negative {
                    return Err("DNS lookup failed (cached)".to_string());
                }
                return Ok(entry.addrs.clone());
            }
            if !entry.negative && now < entry.stale_until {
                // Stale-while-revalidate: serve immediately and refresh in background
                let addrs = entry.addrs.clone();
                drop(entry);
                let this = self.clone();
                let bg_key = key.clone();
                tokio::spawn(async move {
                    let _ = this.do_lookup(&bg_key).await;
                });
                return Ok(addrs);
            }
        }

        self.do_lookup(&key).await
    }

    async fn do_lookup(&self, key: &str) -> Result<Vec<IpAddr>, String> {
        use dashmap::mapref::entry::Entry;

        // Cancellation-safe singleflight:
        // If another task is already resolving `key`, subscribe and await with a hard timeout.
        // If we are the leader, spawn the lookup in an independent Tokio task with an RAII Drop
        // guard so cancelling the caller (e.g. a 3s or 4.5s HTTP timeout) can NEVER leave a
        // stale sender wedged inside `self.inflight`.
        let mut rx = match self.inflight.entry(key.to_string()) {
            Entry::Occupied(occ) => occ.get().subscribe(),
            Entry::Vacant(vac) => {
                let (tx, rx) = broadcast::channel(1);
                vac.insert(tx.clone());
                let this = self.clone();
                let owned_key = key.to_string();
                tokio::spawn(async move {
                    struct InflightGuard {
                        inflight: Arc<DashMap<String, broadcast::Sender<Result<Vec<IpAddr>, String>>>>,
                        key: String,
                    }
                    impl Drop for InflightGuard {
                        fn drop(&mut self) {
                            self.inflight.remove(&self.key);
                        }
                    }
                    let _guard = InflightGuard {
                        inflight: Arc::clone(&this.inflight),
                        key: owned_key.clone(),
                    };

                    let lookup_res = tokio::time::timeout(
                        Duration::from_secs(6),
                        tokio::net::lookup_host((owned_key.as_str(), 0u16)),
                    )
                    .await;

                    let res: Result<Vec<IpAddr>, String> = match lookup_res {
                        Ok(Ok(iter)) => {
                            let mut v4 = Vec::new();
                            let mut v6 = Vec::new();
                            for sa in iter {
                                let ip = sa.ip();
                                match ip {
                                    IpAddr::V4(_) => {
                                        if !v4.contains(&ip) {
                                            v4.push(ip);
                                        }
                                    }
                                    IpAddr::V6(_) => {
                                        if !v6.contains(&ip) {
                                            v6.push(ip);
                                        }
                                    }
                                }
                            }
                            v4.extend(v6);
                            if v4.is_empty() {
                                Err("DNS returned no addresses".to_string())
                            } else {
                                Ok(v4)
                            }
                        }
                        Ok(Err(e)) => Err(format!("DNS lookup failed: {}", e)),
                        Err(_) => Err("DNS lookup timeout".to_string()),
                    };

                    let now = Instant::now();
                    this.evict_if_needed(now);

                    match &res {
                        Ok(addrs) => {
                            this.cache.insert(
                                owned_key.clone(),
                                DnsEntry {
                                    addrs: addrs.clone(),
                                    expires_at: now + DNS_TTL,
                                    stale_until: now + DNS_TTL + DNS_STALE_WINDOW,
                                    negative: false,
                                },
                            );
                        }
                        Err(_) => {
                            // Keep stale positive entry if present; otherwise store short negative cache
                            let keep_stale = this
                                .cache
                                .get(&owned_key)
                                .map(|e| !e.negative && now < e.stale_until)
                                .unwrap_or(false);
                            if !keep_stale {
                                this.cache.insert(
                                    owned_key.clone(),
                                    DnsEntry {
                                        addrs: Vec::new(),
                                        expires_at: now + DNS_NEG_TTL,
                                        stale_until: now + DNS_NEG_TTL,
                                        negative: true,
                                    },
                                );
                            }
                        }
                    }

                    // Remove before notifying waiters so any immediate retry starts cleanly
                    drop(_guard);
                    let _ = tx.send(res);
                });
                rx
            }
        };

        match tokio::time::timeout(Duration::from_secs(7), rx.recv()).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => {
                // Sender dropped (e.g. task completed between subscribe and recv): check cache
                if let Some(entry) = self.cache.get(key) {
                    if !entry.negative && Instant::now() < entry.stale_until {
                        return Ok(entry.addrs.clone());
                    }
                }
                Err("DNS lookup interrupted".to_string())
            }
            Err(_) => Err("DNS lookup timeout".to_string()),
        }
    }

    fn evict_if_needed(&self, now: Instant) {
        if self.cache.len() < MAX_DNS_ENTRIES {
            return;
        }
        // First prune expired entries
        self.cache.retain(|_, v| now < v.stale_until);
        // If still over cap, drop oldest quarter
        if self.cache.len() >= MAX_DNS_ENTRIES {
            let mut to_remove = Vec::with_capacity(MAX_DNS_ENTRIES / 4);
            for r in self.cache.iter() {
                to_remove.push(r.key().clone());
                if to_remove.len() >= MAX_DNS_ENTRIES / 4 {
                    break;
                }
            }
            for k in to_remove {
                self.cache.remove(&k);
            }
        }
    }

    #[cfg(test)]
    fn insert_test_entry(&self, host: &str, addrs: Vec<IpAddr>, ttl: Duration, stale: Duration) {
        let now = Instant::now();
        self.cache.insert(
            host.to_ascii_lowercase(),
            DnsEntry {
                addrs,
                expires_at: now + ttl,
                stale_until: now + stale,
                negative: false,
            },
        );
    }
}

impl Resolve for DnsCache {
    fn resolve(&self, name: Name) -> Resolving {
        let this = self.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = this
                .resolve_host(&host)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            let iter: Addrs = Box::new(addrs.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(iter)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_ip_literals_and_localhost_fast() {
        let dns = DnsCache::new();
        let r1 = dns.resolve_host("127.0.0.1").await.unwrap();
        assert_eq!(r1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        let r2 = dns.resolve_host("localhost").await.unwrap();
        assert_eq!(r2, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        let r3 = dns.resolve_host("192.168.1.50").await.unwrap();
        assert_eq!(r3, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))]);
    }

    #[tokio::test]
    async fn serves_cached_entry_and_respects_cap() {
        let dns = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40));
        dns.insert_test_entry(
            "cdn.example.invalid",
            vec![ip],
            Duration::from_secs(60),
            Duration::from_secs(120),
        );
        let got = dns.resolve_host("CDN.EXAMPLE.INVALID").await.unwrap();
        assert_eq!(got, vec![ip]);

        for i in 0..600 {
            dns.insert_test_entry(
                &format!("h{}.invalid", i),
                vec![ip],
                Duration::from_secs(60),
                Duration::from_secs(120),
            );
        }
        dns.evict_if_needed(Instant::now());
        assert!(dns.cache.len() <= MAX_DNS_ENTRIES);
    }

    #[tokio::test]
    async fn cancelled_lookup_never_poisons_inflight_singleflight() {
        let dns = DnsCache::new();
        // Cancel immediately via 1ms timeout while a lookup is in flight
        let _ = tokio::time::timeout(
            Duration::from_millis(1),
            dns.resolve_host("nonexistent.invalid"),
        )
        .await;
        // Wait briefly for the detached singleflight task to finish and clean up via Drop guard
        for _ in 0..40 {
            if dns.inflight.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            dns.inflight.is_empty(),
            "inflight map must never retain wedged entries after caller cancellation"
        );
        // Subsequent lookup must NOT hang for 7s (resolves or returns negative cache immediately)
        let t0 = Instant::now();
        let _ = dns.resolve_host("nonexistent.invalid").await;
        assert!(t0.elapsed() < Duration::from_secs(2));
    }
}
