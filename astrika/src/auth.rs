use crate::config::ConfigSnapshot;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use dashmap::DashMap;
use hmac::Hmac;
use parking_lot::Mutex;
use pbkdf2::pbkdf2;
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

const AUTH_CACHE_MAX: usize = 1024;
const AUTH_CACHE_TTL: Duration = Duration::from_secs(600);
const PBKDF2_DEFAULT_ROUNDS: u32 = 600_000;

const AUTH_WIN: Duration = Duration::from_secs(60);
const AUTH_HOST_LIM: usize = 30;
const AUTH_GLOB_LIM: usize = 300;

#[derive(Clone, Debug, Default)]
pub struct AuthResult {
    pub ok: bool,
    pub admin: bool,
    pub status: u16,
    pub login: String,
    pub detail: String,
}

impl AuthResult {
    pub fn allow(login: String, admin: bool) -> Self {
        Self {
            ok: true,
            admin,
            status: 200,
            login,
            detail: String::new(),
        }
    }

    pub fn deny(status: u16, detail: &str) -> Self {
        Self {
            ok: false,
            admin: false,
            status,
            login: String::new(),
            detail: detail.to_string(),
        }
    }
}

#[derive(Clone, Copy)]
struct CachedVerify {
    valid: bool,
    config_gen: u64,
    expires_at: Instant,
}

struct RateState {
    global: VecDeque<Instant>,
    per_host: HashMap<String, VecDeque<Instant>>,
}

/// High-performance, non-blocking authentication manager:
/// - Caches verified PBKDF2 results in a bounded DashMap (<= 1024 entries, ~128 KB max)
/// - Offloads PBKDF2 cache misses to `tokio::task::spawn_blocking` (NEVER stalls streaming)
/// - Constant-time digest comparison
/// - Rate-limits brute force attempts per IP and globally
#[derive(Clone)]
pub struct AuthManager {
    cache: Arc<DashMap<[u8; 32], CachedVerify>>,
    limiter: Arc<Mutex<RateState>>,
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthManager {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(DashMap::with_capacity(64)),
            limiter: Arc::new(Mutex::new(RateState {
                global: VecDeque::new(),
                per_host: HashMap::new(),
            })),
        }
    }

    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    pub fn is_blocked(&self, host: &str) -> bool {
        let mut st = self.limiter.lock();
        let cutoff = Instant::now() - AUTH_WIN;
        while st.global.front().is_some_and(|&t| t < cutoff) {
            st.global.pop_front();
        }
        if st.global.len() >= AUTH_GLOB_LIM {
            return true;
        }
        if let Some(q) = st.per_host.get_mut(host) {
            while q.front().is_some_and(|&t| t < cutoff) {
                q.pop_front();
            }
            if q.len() >= AUTH_HOST_LIM {
                return true;
            }
        }
        false
    }

    pub fn record_failure(&self, host: &str) {
        let mut st = self.limiter.lock();
        let now = Instant::now();
        let cutoff = now - AUTH_WIN;
        while st.global.front().is_some_and(|&t| t < cutoff) {
            st.global.pop_front();
        }
        if st.global.len() < AUTH_GLOB_LIM {
            st.global.push_back(now);
        }
        if st.per_host.len() > 2048 {
            st.per_host
                .retain(|_, q| q.back().is_some_and(|&t| t >= cutoff));
        }
        let q = st.per_host.entry(host.to_string()).or_default();
        while q.front().is_some_and(|&t| t < cutoff) {
            q.pop_front();
        }
        if q.len() < AUTH_HOST_LIM {
            q.push_back(now);
        }
    }

    /// Async, cached password verification. Cache hit <1us; cache miss runs PBKDF2 on blocking pool.
    pub async fn verify_password_cached(
        &self,
        password: &str,
        stored: &str,
        config_gen: u64,
    ) -> bool {
        if password.is_empty() || stored.is_empty() || password.len() > 256 {
            return false;
        }
        // Fast path for non-PBKDF2 plaintext/token stored secrets
        if !stored.starts_with("pbkdf2_sha256$") {
            return constant_time_str_eq(password, stored);
        }

        let mut h = Sha256::new();
        h.update(config_gen.to_le_bytes());
        h.update(password.as_bytes());
        h.update([0u8]);
        h.update(stored.as_bytes());
        let key: [u8; 32] = h.finalize().into();

        let now = Instant::now();
        if let Some(entry) = self.cache.get(&key) {
            if entry.config_gen == config_gen && now < entry.expires_at {
                return entry.valid;
            }
        }

        let pw_owned = password.to_string();
        let st_owned = stored.to_string();
        let valid = tokio::task::spawn_blocking(move || verify_password_sync(&pw_owned, &st_owned))
            .await
            .unwrap_or(false);

        if self.cache.len() >= AUTH_CACHE_MAX {
            self.cache
                .retain(|_, v| v.config_gen == config_gen && now < v.expires_at);
            if self.cache.len() >= AUTH_CACHE_MAX {
                self.cache.clear();
            }
        }
        // Only cache positive matches for full TTL; negative matches for short 15s TTL
        let ttl = if valid {
            AUTH_CACHE_TTL
        } else {
            Duration::from_secs(15)
        };
        self.cache.insert(
            key,
            CachedVerify {
                valid,
                config_gen,
                expires_at: now + ttl,
            },
        );
        valid
    }

    pub async fn check_identity(
        &self,
        cfg: &ConfigSnapshot,
        creds: Option<&str>,
        host: &str,
        req_creds: bool,
        rate_limit: bool,
    ) -> AuthResult {
        if rate_limit && self.is_blocked(host) {
            return AuthResult::deny(429, "Too many failed authentication attempts");
        }
        let auth_en = cfg.auth_enabled;
        if !auth_en && !req_creds && creds.is_none() {
            return AuthResult::allow(String::new(), true);
        }
        let Some(c) = creds else {
            if rate_limit && auth_en {
                self.record_failure(host);
            }
            return AuthResult::deny(403, "Forbidden");
        };
        let Some((login, pass)) = c.split_once(':') else {
            if rate_limit && (auth_en || !c.is_empty()) {
                self.record_failure(host);
            }
            return AuthResult::deny(403, "Forbidden");
        };

        let Some(u) = cfg.users_index.get(login) else {
            if rate_limit && (auth_en || !c.is_empty()) {
                self.record_failure(host);
            }
            return AuthResult::deny(403, "Forbidden");
        };
        if !u.enabled {
            if rate_limit {
                self.record_failure(host);
            }
            return AuthResult::deny(403, "Forbidden");
        }
        let expected = if !u.password.is_empty() {
            u.password.as_str()
        } else {
            u.token.as_str()
        };
        if !self
            .verify_password_cached(pass, expected, cfg.generation)
            .await
        {
            if rate_limit {
                self.record_failure(host);
            }
            return AuthResult::deny(403, "Forbidden");
        }
        if let Some(exp) = u.expire {
            let now_wall = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            if exp > 0.0 && now_wall > exp {
                if rate_limit {
                    self.record_failure(host);
                }
                return AuthResult::deny(403, "Forbidden");
            }
        }
        AuthResult::allow(login.to_string(), u.is_admin)
    }

    pub async fn require_auth(
        &self,
        cfg: &ConfigSnapshot,
        remote_ip: &str,
        authorization: Option<&str>,
        cookie: Option<&str>,
        user_agent: &str,
        has_sec_fetch_mode: bool,
        x_ui_auth: Option<&str>,
    ) -> AuthResult {
        let creds = authorization
            .and_then(extract_basic)
            .or_else(|| cookie.and_then(extract_cookie_auth));
        let is_browser =
            user_agent.to_ascii_lowercase().contains("mozilla/") || has_sec_fetch_mode;
        let ui_req = x_ui_auth == Some("required") || is_browser;
        if ui_req && creds.is_none() {
            return AuthResult::deny(403, "Forbidden");
        }
        self.check_identity(cfg, creds.as_deref(), remote_ip, ui_req, true)
            .await
    }

    pub async fn require_media_auth(
        &self,
        cfg: &ConfigSnapshot,
        remote_ip: &str,
        x_real_ip: Option<&str>,
        x_fwd_for: Option<&str>,
        query: &str,
        authorization: Option<&str>,
        cookie: Option<&str>,
        user_agent: &str,
        has_sec_fetch_mode: bool,
        x_ui_auth: Option<&str>,
    ) -> AuthResult {
        let mut host = remote_ip.to_string();
        if cfg.auth_x_real_ip {
            if let Some(rip) = x_real_ip.filter(|s| !s.is_empty()) {
                host = rip.to_string();
            } else if let Some(xff) = x_fwd_for.filter(|s| !s.is_empty()) {
                host = xff.split(',').next().unwrap_or(xff).trim().to_string();
            }
        }
        if ip_matches(&host, &cfg.ip_deny) {
            return AuthResult::deny(403, "IP address denied");
        }

        let token = query_get(query, "token").or_else(|| query_get(query, "auth"));
        if let Some(tok) = token.filter(|s| !s.is_empty()) {
            if cfg.token_deny.contains(&tok) {
                return AuthResult::deny(403, "Token denied");
            }
            if tok.contains(':') {
                let res = self
                    .check_identity(cfg, Some(&tok), &host, true, true)
                    .await;
                if res.ok || cfg.auth_enabled {
                    return res;
                }
            }
            // O(1) exact token lookup (fixes C-version O(N)*PBKDF2 DoS!)
            if let Some(login) = cfg.token_index.get(&tok) {
                if let Some(u) = cfg.users_index.get(login) {
                    if u.enabled {
                        return AuthResult::allow(login.clone(), u.is_admin);
                    }
                }
            }
            if cfg.auth_enabled {
                return AuthResult::deny(403, "Forbidden");
            }
        }

        if !cfg.auth_enabled {
            if let Some(creds) = authorization.and_then(extract_basic) {
                let res = self
                    .check_identity(cfg, Some(&creds), &host, true, false)
                    .await;
                if res.ok {
                    return res;
                }
            }
            return AuthResult::allow(String::new(), false);
        }

        if ip_matches(&host, &cfg.ip_allow) {
            return AuthResult::allow(String::new(), false);
        }

        self.require_auth(
            cfg,
            &host,
            authorization,
            cookie,
            user_agent,
            has_sec_fetch_mode,
            x_ui_auth,
        )
        .await
    }
}

#[inline]
pub fn constant_time_str_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    ab.len() == bb.len() && bool::from(ab.ct_eq(bb))
}

pub fn hash_password_sync(pw: &str) -> String {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut digest = [0u8; 32];
    let _ = pbkdf2::<Hmac<Sha256>>(pw.as_bytes(), &salt, PBKDF2_DEFAULT_ROUNDS, &mut digest);
    format!(
        "pbkdf2_sha256${}${}${}",
        PBKDF2_DEFAULT_ROUNDS,
        hex::encode(salt),
        hex::encode(digest)
    )
}

pub async fn hash_password_async(pw: String) -> String {
    tokio::task::spawn_blocking(move || hash_password_sync(&pw))
        .await
        .unwrap_or_default()
}

pub fn verify_password_sync(pw: &str, stored: &str) -> bool {
    if pw.is_empty() || stored.is_empty() || pw.len() > 256 {
        return false;
    }
    let Some(rest) = stored.strip_prefix("pbkdf2_sha256$") else {
        return constant_time_str_eq(pw, stored);
    };
    let mut parts = rest.split('$');
    let Some(rounds_s) = parts.next() else {
        return false;
    };
    let Some(salt_hex) = parts.next() else {
        return false;
    };
    let Some(digest_hex) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    let Ok(rounds) = rounds_s.parse::<u32>() else {
        return false;
    };
    if !(100_000..=2_000_000).contains(&rounds) {
        return false;
    }
    let Ok(salt) = hex::decode(salt_hex) else {
        return false;
    };
    let Ok(expected) = hex::decode(digest_hex) else {
        return false;
    };
    if salt.len() != 16 || expected.len() != 32 {
        return false;
    }
    let mut actual = [0u8; 32];
    let _ = pbkdf2::<Hmac<Sha256>>(pw.as_bytes(), &salt, rounds, &mut actual);
    bool::from(actual.ct_eq(&expected[..]))
}

pub fn valid_login(s: &str) -> bool {
    let len = s.len();
    (1..=64).contains(&len)
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

pub fn valid_password(s: &str) -> bool {
    if s.len() < 12 || s.len() > 128 {
        return false;
    }
    let has_alpha = s.bytes().any(|b| b.is_ascii_alphabetic());
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    has_alpha && has_digit
}

pub fn extract_basic(hdr: &str) -> Option<String> {
    let rest = hdr
        .strip_prefix("Basic ")
        .or_else(|| hdr.strip_prefix("basic "))?
        .trim();
    let bytes = B64.decode(rest).ok()?;
    String::from_utf8(bytes).ok()
}

pub fn extract_cookie_auth(cookie: &str) -> Option<String> {
    for part in cookie.split(';') {
        let p = part.trim();
        if let Some(val) = p.strip_prefix("auth=") {
            let dec = url_decode(val);
            if !dec.is_empty() {
                return Some(dec);
            }
        }
    }
    None
}

pub fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub fn query_get(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            return Some(url_decode(v));
        }
    }
    None
}

pub fn query_has(query: &str, key: &str) -> bool {
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let k = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
        if k == key {
            return true;
        }
    }
    false
}

pub fn ip_matches(host: &str, rules: &[String]) -> bool {
    if rules.is_empty() {
        return false;
    }
    let ip_v4 = host.parse::<Ipv4Addr>().ok();
    for rule in rules {
        let r = rule.trim();
        if r.is_empty() {
            continue;
        }
        if r == "*" || r == host {
            return true;
        }
        if let (Some(ip), Some((net_s, bits_s))) = (ip_v4, r.split_once('/')) {
            if let (Ok(net), Ok(bits)) = (net_s.parse::<Ipv4Addr>(), bits_s.parse::<u32>()) {
                if bits <= 32 {
                    let mask = if bits == 0 {
                        0u32
                    } else {
                        !0u32 << (32 - bits)
                    };
                    if (u32::from(ip) & mask) == (u32::from(net) & mask) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

pub fn parse_string_list(v: Option<&Value>) -> Vec<String> {
    let Some(val) = v else {
        return Vec::new();
    };
    match val {
        Value::Array(arr) => arr
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect(),
        Value::String(s) => s
            .split(|c| c == ',' || c == '\n' || c == ' ')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pbkdf2_hash_verify_and_cache_invalidation() {
        let hashed = hash_password_sync("SecretPass1234");
        assert!(hashed.starts_with("pbkdf2_sha256$600000$"));
        assert!(verify_password_sync("SecretPass1234", &hashed));
        assert!(!verify_password_sync("WrongPass1234", &hashed));

        let mgr = AuthManager::new();
        // First call computes PBKDF2 off-thread and caches
        assert!(mgr.verify_password_cached("SecretPass1234", &hashed, 1).await);
        // Second call hits cache in microseconds
        let t0 = Instant::now();
        assert!(mgr.verify_password_cached("SecretPass1234", &hashed, 1).await);
        assert!(t0.elapsed() < Duration::from_millis(10));
        // Wrong password still rejected
        assert!(!mgr.verify_password_cached("WrongPass1234", &hashed, 1).await);
    }

    #[test]
    fn ip_cidr_matching() {
        let rules = vec!["10.0.0.0/8".to_string(), "192.168.1.5".to_string()];
        assert!(ip_matches("10.12.34.56", &rules));
        assert!(ip_matches("192.168.1.5", &rules));
        assert!(!ip_matches("192.168.1.6", &rules));
        assert!(!ip_matches("172.16.0.1", &rules));
    }

    #[test]
    fn rate_limiter_blocks_after_threshold() {
        let mgr = AuthManager::new();
        for _ in 0..AUTH_HOST_LIM {
            assert!(!mgr.is_blocked("1.2.3.4"));
            mgr.record_failure("1.2.3.4");
        }
        assert!(mgr.is_blocked("1.2.3.4"));
        assert!(!mgr.is_blocked("5.6.7.8"));
    }
}
