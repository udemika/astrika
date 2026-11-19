use crate::auth::{
    hash_password_async, query_get, query_has, valid_login, valid_password, AuthManager,
};
use crate::channel::{
    hls_out_activate, next_session_id, now_unix_secs, ActiveSession, Channel, ChannelMap,
    InputMode, SessionMap,
};
use crate::config::{
    atomic_save_config_async, get_bool_field, get_u16, load_disk_config, redact_val,
    stream_keep_active, validate_config, ConfigSnapshot,
};
use crate::dns::DnsCache;
use crate::embed;
use crate::hls_in::AesKeyCache;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::Bytes;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_ENCODING, CONTENT_TYPE, ETAG,
    SEC_WEBSOCKET_ACCEPT, UPGRADE, USER_AGENT,
};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use parking_lot::{Mutex, RwLock};
use rand::RngCore;
use reqwest::Client;
use serde_json::{json, Value};
use sha1::{Digest as Sha1Digest, Sha1};
use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, Notify};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::protocol::{Message, Role};
use tokio_tungstenite::WebSocketStream;

pub const ASTRIKA_VERSION: &str = "Astrika 2.1";
pub const ASTRIKA_CLI_VERSION: &str = "2.1.0";

const MAX_LOGS: usize = 300;

#[derive(Clone)]
struct LogEntry {
    level: String,
    ts: i64,
    text: String,
}

#[derive(Clone)]
#[allow(dead_code)]
struct ScanEntry {
    id: String,
    stream_id: String,
    cluster_host: String,
}

#[derive(Clone)]
struct WsBroadcastMsg {
    target_cluster_host: Option<String>,
    revoke_login: Option<String>,
    text: Arc<String>,
}

#[derive(Clone)]
#[allow(dead_code)]
struct ClusterStream {
    eff_id: String,
    orig_id: String,
    host_port: String,
    auth_header: Option<String>,
    auth_query: Option<String>,
    remote_hls_enabled: bool,
    cfg: Value,
}

pub struct AppState {
    pub config_path: PathBuf,
    pub cfg: RwLock<Arc<ConfigSnapshot>>,
    pub cfg_gen: AtomicU64,
    pub auth: AuthManager,
    pub channels: ChannelMap,
    pub sessions: SessionMap,
    pub http_client: Client,
    pub key_cache: AesKeyCache,
    pub epoch: Instant,
    pub started_wall: i64,

    // Logs & active stream analyzer scans
    logs: Mutex<VecDeque<LogEntry>>,
    scans: DashMap<String, ScanEntry>,

    // Cluster state (O(1) maps instead of C O(N) linear arrays)
    cluster_streams: RwLock<HashMap<String, ClusterStream>>,
    cluster_aliases: RwLock<HashMap<(String, String), String>>,
    cluster_plain_aliases: RwLock<HashMap<String, String>>,
    cluster_gen: AtomicU64,

    // Cached global M3U/XSPF playlist bodies keyed by (cfg_gen, cluster_gen, variant_key)
    playlist_cache: DashMap<String, (u64, u64, Bytes)>,

    // WebSocket broadcast hub (0 CPU overhead when ws_count == 0)
    ws_tx: broadcast::Sender<WsBroadcastMsg>,
    ws_count: AtomicUsize,

    // Extra port listeners (port -> task handle)
    extra_listeners: Mutex<HashMap<u16, JoinHandle<()>>>,

    // Global shutdown & immediate cluster sync trigger
    pub shutdown: Arc<Notify>,
    pub cluster_sync_notify: Arc<Notify>,
    pub stopping: AtomicBool,
}

impl AppState {
    pub fn new(config_path: PathBuf, initial_cfg: Value) -> Arc<Self> {
        let dns = Arc::new(DnsCache::new());
        let verify_tls = std::env::var("ASTRIKA_VERIFY_TLS").ok().as_deref() == Some("1");
        let http_client = Client::builder()
            .dns_resolver(dns)
            .danger_accept_invalid_certs(!verify_tls)
            .connect_timeout(Duration::from_secs(6))
            .pool_max_idle_per_host(16)
            .pool_idle_timeout(Duration::from_secs(45))
            .tcp_nodelay(true)
            .tcp_keepalive(Duration::from_secs(30))
            .gzip(true)
            .redirect(reqwest::redirect::Policy::limited(8))
            .build()
            .expect("failed to build reqwest client");

        let snap = Arc::new(ConfigSnapshot::from_value(initial_cfg, 1));
        let (ws_tx, _) = broadcast::channel(512);

        let state = Arc::new(Self {
            config_path,
            cfg: RwLock::new(snap),
            cfg_gen: AtomicU64::new(1),
            auth: AuthManager::new(),
            channels: Arc::new(DashMap::with_capacity(64)),
            sessions: Arc::new(DashMap::with_capacity(64)),
            http_client,
            key_cache: AesKeyCache::new(),
            epoch: Instant::now(),
            started_wall: now_unix_secs(),
            logs: Mutex::new(VecDeque::with_capacity(MAX_LOGS)),
            scans: DashMap::new(),
            cluster_streams: RwLock::new(HashMap::new()),
            cluster_aliases: RwLock::new(HashMap::new()),
            cluster_plain_aliases: RwLock::new(HashMap::new()),
            cluster_gen: AtomicU64::new(1),
            playlist_cache: DashMap::new(),
            ws_tx,
            ws_count: AtomicUsize::new(0),
            extra_listeners: Mutex::new(HashMap::new()),
            shutdown: Arc::new(Notify::new()),
            cluster_sync_notify: Arc::new(Notify::new()),
            stopping: AtomicBool::new(false),
        });

        state.sync_local_engines(false);
        state.add_log("info", format!("{} started", ASTRIKA_VERSION));
        state
    }

    pub fn config(&self) -> Arc<ConfigSnapshot> {
        Arc::clone(&self.cfg.read())
    }

    pub fn add_log(&self, level: &str, text: String) {
        let mut logs = self.logs.lock();
        if logs.len() >= MAX_LOGS {
            logs.pop_front();
        }
        logs.push_back(LogEntry {
            level: level.to_string(),
            ts: now_unix_secs(),
            text,
        });
    }

    pub fn broadcast_ws(&self, scope: &str, payload: &Value) {
        if self.ws_count.load(Ordering::Relaxed) == 0 {
            return;
        }
        let mut msg = payload.clone();
        if let Some(o) = msg.as_object_mut() {
            o.insert("scope".to_string(), json!(scope));
        }
        if let Ok(s) = serde_json::to_string(&msg) {
            let _ = self.ws_tx.send(WsBroadcastMsg {
                target_cluster_host: None,
                revoke_login: None,
                text: Arc::new(s),
            });
        }
    }

    pub fn broadcast_cluster_ws(&self, host_port: &str, scope: &str, payload: &Value) {
        if self.ws_count.load(Ordering::Relaxed) == 0 {
            return;
        }
        let mut msg = payload.clone();
        if let Some(o) = msg.as_object_mut() {
            o.insert("scope".to_string(), json!(scope));
        }
        if let Ok(s) = serde_json::to_string(&msg) {
            let _ = self.ws_tx.send(WsBroadcastMsg {
                target_cluster_host: Some(host_port.to_string()),
                revoke_login: None,
                text: Arc::new(s),
            });
        }
    }

    pub fn revoke_account_sockets(&self, login: &str) {
        let _ = self.ws_tx.send(WsBroadcastMsg {
            target_cluster_host: None,
            revoke_login: Some(login.to_string()),
            text: Arc::new(String::new()),
        });
    }

    pub fn sync_local_engines(&self, rebuild: bool) {
        let snap = self.config();
        let mut wanted: HashSet<String> = HashSet::new();

        if let Some(ms) = snap.raw.get("make_stream").and_then(|v| v.as_array()) {
            for s in ms {
                let sid = s.get("id").and_then(|v| v.as_str()).unwrap_or("");
                if sid.is_empty()
                    || !get_bool_field(Some(s), "enable", true)
                    || !get_bool_field(Some(s), "active", true)
                {
                    continue;
                }
                let urls: Vec<String> = s
                    .get("input")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|u| u.trim().to_string()))
                            .filter(|u| !u.is_empty())
                            .collect()
                    })
                    .unwrap_or_default();
                if urls.is_empty() {
                    continue;
                }
                let udp_outs: Vec<String> = s
                    .get("output")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|u| u.trim().to_string()))
                            .filter(|u| {
                                let l = u.to_ascii_lowercase();
                                l.starts_with("udp://") || l.starts_with("rtp://")
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let name = s.get("name").and_then(|v| v.as_str()).unwrap_or(sid);
                let (ka, idle_delay) = stream_keep_active(s);
                wanted.insert(sid.to_string());

                if !rebuild {
                    if let Some(existing) = self.channels.get(sid) {
                        if !existing.is_cluster
                            && existing.matches_spec(name, &urls, ka, idle_delay, &udp_outs)
                        {
                            continue;
                        }
                    }
                }
                if let Some((_, old)) = self.channels.remove(sid) {
                    old.shutdown();
                }
                let ch = Channel::new(
                    sid.to_string(),
                    name.to_string(),
                    urls,
                    udp_outs,
                    snap.hls_seg_dur,
                    snap.hls_seg_keep,
                    ka,
                    idle_delay,
                    false,
                    String::new(),
                    String::new(),
                    None,
                    self.http_client.clone(),
                    self.key_cache.clone(),
                    self.epoch,
                );
                self.channels.insert(sid.to_string(), ch);
            }
        }

        // Remove local channels no longer in config
        let to_drop: Vec<String> = self
            .channels
            .iter()
            .filter(|e| !e.value().is_cluster && !wanted.contains(e.key()))
            .map(|e| e.key().clone())
            .collect();
        for sid in to_drop {
            if let Some((_, ch)) = self.channels.remove(&sid) {
                ch.shutdown();
            }
        }
    }

    pub fn sync_extra_ports(self: &Arc<Self>) {
        if std::env::var("ASTRA_DISABLE_EXTRA_PORTS").ok().as_deref() == Some("1")
            || std::env::var("ASTRIKA_DISABLE_EXTRA_PORTS").ok().as_deref() == Some("1")
        {
            return;
        }
        let snap = self.config();
        let wanted: HashSet<u16> = snap.extra_ports.iter().copied().collect();
        let mut map = self.extra_listeners.lock();

        // Stop removed ports
        let drop_ports: Vec<u16> = map
            .keys()
            .copied()
            .filter(|p| !wanted.contains(p))
            .collect();
        for p in drop_ports {
            if let Some(h) = map.remove(&p) {
                h.abort();
            }
        }

        // Spawn newly added extra ports
        for p in wanted {
            if p == snap.port || map.contains_key(&p) {
                continue;
            }
            let st = Arc::clone(self);
            let host = snap.host.clone();
            let h = tokio::spawn(async move {
                let _ = serve_http_port(st, &host, p).await;
            });
            map.insert(p, h);
        }
    }

    pub async fn apply_config(
        self: &Arc<Self>,
        candidate: Value,
        persist: bool,
        rebuild: bool,
    ) -> Result<(), String> {
        let validated = validate_config(&candidate)?;
        let new_gen = self.cfg_gen.fetch_add(1, Ordering::AcqRel) + 1;
        let snap = Arc::new(ConfigSnapshot::from_value(validated.clone(), new_gen));
        *self.cfg.write() = snap;
        self.auth.clear_cache();
        self.playlist_cache.clear();
        self.sync_local_engines(rebuild);
        self.sync_extra_ports();
        self.cluster_sync_notify.notify_one();

        if persist {
            atomic_save_config_async(self.config_path.clone(), validated).await?;
        }
        Ok(())
    }

    pub fn resolve_stream_id(&self, stream_id: &str, host_hint: Option<&str>) -> Option<String> {
        if stream_id.is_empty() {
            return None;
        }
        let snap = self.config();
        if host_hint.is_none_or(|h| h.is_empty())
            && snap.streams_index.contains_key(stream_id)
            && self.channels.contains_key(stream_id)
        {
            return Some(stream_id.to_string());
        }
        if let Some(hh) = host_hint.filter(|s| !s.is_empty()) {
            if let Some(eff) = self
                .cluster_aliases
                .read()
                .get(&(hh.to_string(), stream_id.to_string()))
            {
                return Some(eff.clone());
            }
        }
        if self.cluster_streams.read().contains_key(stream_id)
            && self.channels.contains_key(stream_id)
        {
            return Some(stream_id.to_string());
        }
        if let Some(eff) = self.cluster_plain_aliases.read().get(stream_id) {
            return Some(eff.clone());
        }
        if host_hint.is_none_or(|h| h.is_empty()) && snap.streams_index.contains_key(stream_id) {
            return Some(stream_id.to_string());
        }
        if let Some(clean) = stream_id.strip_suffix(".ts") {
            return self.resolve_stream_id(clean, host_hint);
        }
        None
    }

    pub fn ensure_channel_started(&self, sid: &str) -> Option<Arc<Channel>> {
        if let Some(ch) = self.channels.get(sid) {
            return Some(Arc::clone(ch.value()));
        }
        let snap = self.config();
        let s = snap
            .streams_index
            .get(sid)
            .cloned()
            .or_else(|| self.cluster_streams.read().get(sid).map(|c| c.cfg.clone()))?;
        if !get_bool_field(Some(&s), "enable", true) || !get_bool_field(Some(&s), "active", true) {
            return None;
        }
        let urls: Vec<String> = s
            .get("input")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|u| u.trim().to_string()))
                    .filter(|u| !u.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        if urls.is_empty() {
            return None;
        }
        let name = s.get("name").and_then(|v| v.as_str()).unwrap_or(sid);
        let (ka, idle_delay) = stream_keep_active(&s);
        let ch = Channel::new(
            sid.to_string(),
            name.to_string(),
            urls,
            vec![],
            snap.hls_seg_dur,
            snap.hls_seg_keep,
            ka,
            idle_delay,
            false,
            String::new(),
            String::new(),
            None,
            self.http_client.clone(),
            self.key_cache.clone(),
            self.epoch,
        );
        self.channels.insert(sid.to_string(), Arc::clone(&ch));
        Some(ch)
    }

    pub fn shutdown_all(&self) {
        self.stopping.store(true, Ordering::Release);
        for e in self.channels.iter() {
            e.value().shutdown();
        }
        for e in self.sessions.iter() {
            e.value().cancel.notify_waiters();
        }
        let mut map = self.extra_listeners.lock();
        for (_, h) in map.drain() {
            h.abort();
        }
        self.shutdown.notify_waiters();
    }
}

/* ----------------------------------------------------------- HTTP Server */

type RespBody = BoxBody<Bytes, Infallible>;

fn full_body(b: impl Into<Bytes>) -> RespBody {
    Full::new(b.into()).boxed()
}

fn empty_body() -> RespBody {
    Full::new(Bytes::new()).boxed()
}

fn json_resp(status: StatusCode, val: &Value) -> Response<RespBody> {
    let body = serde_json::to_vec(val).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(full_body(body))
        .unwrap()
}

fn detail_resp(status: StatusCode, detail: &str, retry_after: Option<&str>) -> Response<RespBody> {
    let body = serde_json::to_vec(&json!({ "detail": detail })).unwrap_or_default();
    let mut b = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*");
    if let Some(ra) = retry_after {
        b = b.header("Retry-After", ra);
    }
    b.body(full_body(body)).unwrap()
}

fn hdr_str<'a>(req: &'a Request<Incoming>, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

pub async fn serve_http_port(state: Arc<AppState>, host: &str, port: u16) -> Result<(), String> {
    let addr = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("cannot listen on {}: {}", addr, e))?;

    loop {
        tokio::select! {
            _ = state.shutdown.notified() => break,
            accept_res = listener.accept() => {
                let Ok((stream, peer)) = accept_res else {
                    continue;
                };
                let _ = stream.set_nodelay(true);
                let io = TokioIo::new(stream);
                let st = Arc::clone(&state);
                let remote_ip = normalize_ip(peer);
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let st_inner = Arc::clone(&st);
                        let ip = remote_ip.clone();
                        async move {
                            Ok::<_, Infallible>(handle_request(st_inner, req, ip, port).await)
                        }
                    });
                    // HTTP/1.1 with Keep-Alive enabled + WebSocket upgrade support!
                    let _ = http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(io, svc)
                        .with_upgrades()
                        .await;
                });
            }
        }
    }
    Ok(())
}

fn normalize_ip(peer: SocketAddr) -> String {
    match peer.ip() {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                v4.to_string()
            } else {
                v6.to_string()
            }
        }
    }
}

async fn handle_request(
    state: Arc<AppState>,
    req: Request<Incoming>,
    remote_ip: String,
    listen_port: u16,
) -> Response<RespBody> {
    if req.method() == Method::OPTIONS {
        return Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .header(ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS, HEAD")
            .header(ACCESS_CONTROL_ALLOW_HEADERS, "*")
            .body(empty_body())
            .unwrap();
    }

    // WebSocket Upgrade
    if hdr_str(&req, "upgrade").is_some_and(|u| u.eq_ignore_ascii_case("websocket")) {
        if let Some(ws_key) = hdr_str(&req, "sec-websocket-key").map(|s| s.to_string()) {
            let path = req.uri().path().to_string();
            let query = req.uri().query().unwrap_or("").to_string();
            let is_cluster = path == "/api/cluster-ws";
            let is_main = path == "/control/event/" || path == "/control/event";
            if is_main || is_cluster {
                let cluster_host = if is_cluster {
                    query_get(&query, "host").unwrap_or_default()
                } else {
                    String::new()
                };
                let accept = compute_ws_accept(&ws_key);
                let st_ws = Arc::clone(&state);
                let ip_ws = remote_ip.clone();
                let on_upgrade = hyper::upgrade::on(req);
                tokio::spawn(async move {
                    if let Ok(upgraded) = on_upgrade.await {
                        run_ws_session(st_ws, upgraded, ip_ws, is_cluster, cluster_host).await;
                    }
                });
                return Response::builder()
                    .status(StatusCode::SWITCHING_PROTOCOLS)
                    .header(UPGRADE, "websocket")
                    .header(CONNECTION, "Upgrade")
                    .header(SEC_WEBSOCKET_ACCEPT, accept)
                    .body(empty_body())
                    .unwrap();
            }
            return detail_resp(StatusCode::NOT_FOUND, "WebSocket endpoint not found", None);
        }
    }

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let head_only = method == Method::HEAD;

    // Extract common headers
    let auth_hdr = hdr_str(&req, "authorization").map(|s| s.to_string());
    let cookie_hdr = hdr_str(&req, "cookie").map(|s| s.to_string());
    let ua_hdr = hdr_str(&req, "user-agent").unwrap_or("").to_string();
    let host_hdr = hdr_str(&req, "host").unwrap_or("").to_string();
    let origin_hdr = hdr_str(&req, "origin").map(|s| s.to_string());
    let x_real_ip = hdr_str(&req, "x-real-ip").map(|s| s.to_string());
    let x_fwd_for = hdr_str(&req, "x-forwarded-for").map(|s| s.to_string());
    let x_fwd_proto = hdr_str(&req, "x-forwarded-proto").map(|s| s.to_string());
    let x_ui_auth = hdr_str(&req, "x-ui-auth").map(|s| s.to_string());
    let x_cluster_target = hdr_str(&req, "x-cluster-target").map(|s| s.to_string());
    let x_cluster_auth = hdr_str(&req, "x-cluster-auth").map(|s| s.to_string());
    let has_sec_fetch = req.headers().contains_key("sec-fetch-mode");
    let accept_gz = hdr_str(&req, "accept-encoding")
        .is_some_and(|ae| ae.to_ascii_lowercase().contains("gzip"));
    let if_none_match = hdr_str(&req, "if-none-match").map(|s| s.to_string());

    let is_get = method == Method::GET || head_only;
    let is_post = method == Method::POST;

    // Health
    if is_get && path == "/__health" {
        return json_resp(
            StatusCode::OK,
            &json!({ "status": "ok", "version": ASTRIKA_VERSION }),
        );
    }

    // POST API routes
    if is_post {
        let body_bytes = match read_bounded_body(req, 16 * 1024 * 1024).await {
            Ok(b) => b,
            Err(status) => return detail_resp(status, "Payload too large or read error", None),
        };
        if path == "/control/" || path == "/control" {
            return handle_control_api(
                &state,
                &remote_ip,
                auth_hdr.as_deref(),
                cookie_hdr.as_deref(),
                &ua_hdr,
                has_sec_fetch,
                x_ui_auth.as_deref(),
                &body_bytes,
            )
            .await;
        }
        if path == "/control/account/" || path == "/control/account" {
            return handle_account_change(
                &state,
                &remote_ip,
                &host_hdr,
                origin_hdr.as_deref(),
                auth_hdr.as_deref(),
                cookie_hdr.as_deref(),
                &ua_hdr,
                has_sec_fetch,
                x_ui_auth.as_deref(),
                &body_bytes,
            )
            .await;
        }
        if path == "/control/reset-password/" || path == "/control/reset-password" {
            return handle_reset_password(
                &state,
                &remote_ip,
                auth_hdr.as_deref(),
                cookie_hdr.as_deref(),
                &ua_hdr,
                has_sec_fetch,
                x_ui_auth.as_deref(),
                &body_bytes,
            )
            .await;
        }
        if path == "/api/cluster-control" {
            return handle_cluster_control(
                &state,
                &remote_ip,
                auth_hdr.as_deref(),
                cookie_hdr.as_deref(),
                &ua_hdr,
                has_sec_fetch,
                x_ui_auth.as_deref(),
                x_cluster_target.as_deref(),
                x_cluster_auth.as_deref(),
                &query,
                &body_bytes,
            )
            .await;
        }
        return detail_resp(StatusCode::NOT_FOUND, "Not Found", None);
    }

    if !is_get {
        return detail_resp(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed", None);
    }

    // Embedded UI static assets with ETag + 304 Not Modified
    if path == "/" || path == "/index.html" {
        return serve_static_gz(
            embed::INDEX_HTML_GZ,
            embed::index_plain,
            embed::index_etag(),
            "text/html; charset=utf-8",
            "no-cache",
            &[],
            accept_gz,
            if_none_match.as_deref(),
            head_only,
        );
    }
    if path == "/mod.js" {
        return serve_static_gz(
            embed::MOD_JS_GZ,
            embed::mod_plain,
            embed::mod_etag(),
            "application/javascript; charset=utf-8",
            "no-store",
            &[],
            accept_gz,
            if_none_match.as_deref(),
            head_only,
        );
    }
    if path == "/account/" || path == "/account" || path == "/account/index.html" {
        return serve_static_gz(
            embed::ACCOUNT_HTML_GZ,
            embed::account_plain,
            embed::account_etag(),
            "text/html; charset=utf-8",
            "no-store",
            &[
                ("Referrer-Policy", "no-referrer"),
                ("X-Content-Type-Options", "nosniff"),
                (
                    "Content-Security-Policy",
                    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; base-uri 'none'",
                ),
            ],
            accept_gz,
            if_none_match.as_deref(),
            head_only,
        );
    }
    if path == "/favicon.png" || path == "/favicon.ico" {
        let etag = embed::favicon_etag();
        if if_none_match.as_deref() == Some(etag) {
            return Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header(ETAG, etag)
                .body(empty_body())
                .unwrap();
        }
        return Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "image/png")
            .header(CACHE_CONTROL, "public, max-age=86400")
            .header(ETAG, etag)
            .body(if head_only {
                empty_body()
            } else {
                full_body(Bytes::from_static(embed::FAVICON_PNG))
            })
            .unwrap();
    }

    // Auth helper context for media routes
    let media_ctx = MediaReqCtx {
        remote_ip: &remote_ip,
        x_real_ip: x_real_ip.as_deref(),
        x_fwd_for: x_fwd_for.as_deref(),
        x_fwd_proto: x_fwd_proto.as_deref(),
        host_hdr: &host_hdr,
        query: &query,
        auth_hdr: auth_hdr.as_deref(),
        cookie_hdr: cookie_hdr.as_deref(),
        ua_hdr: &ua_hdr,
        has_sec_fetch,
        x_ui_auth: x_ui_auth.as_deref(),
        if_none_match: if_none_match.as_deref(),
        head_only,
    };

    // Global playlists
    if path == "/playlist.m3u8" || path == "/playlist.m3u" {
        return serve_m3u_playlist(&state, &media_ctx).await;
    }
    if path == "/playlist.xspf" {
        return serve_xspf_playlist(&state, &media_ctx).await;
    }

    // /play/cluster/{srv}/{id}...
    if let Some(rest) = path.strip_prefix("/play/cluster/") {
        if let Some((skey, tail)) = rest.split_once('/') {
            if !skey.is_empty() {
                return dispatch_media_tail(&state, &media_ctx, tail, Some(skey)).await;
            }
        }
    }

    // /play/{id}...
    if let Some(tail) = path.strip_prefix("/play/") {
        return dispatch_media_tail(&state, &media_ctx, tail, None).await;
    }

    // /live/{id}...
    if let Some(tail) = path.strip_prefix("/live/") {
        if let Some((osid, omode, oseg)) = resolve_http_output(&state, &path, listen_port) {
            return match omode {
                1 => handle_media_play_hls(&state, &media_ctx, &osid, None).await,
                2 => handle_media_play_seg(&state, &media_ctx, &osid, &oseg, None).await,
                _ => handle_media_play_ts(&state, &media_ctx, &osid, None).await,
            };
        }
        return dispatch_media_tail(&state, &media_ctx, tail, None).await;
    }

    // Custom playlist name /{custom}.m3u8|.m3u|.xspf
    if let Some(file) = path.strip_prefix('/') {
        if !file.contains('/') {
            let snap = state.config();
            let pname = &snap.playlist_name;
            if file == format!("{}.m3u8", pname) || file == format!("{}.m3u", pname) {
                return serve_m3u_playlist(&state, &media_ctx).await;
            }
            if file == format!("{}.xspf", pname) {
                return serve_xspf_playlist(&state, &media_ctx).await;
            }
        }
    }

    // Custom HTTP outputs
    if let Some((osid, omode, oseg)) = resolve_http_output(&state, &path, listen_port) {
        return match omode {
            1 => handle_media_play_hls(&state, &media_ctx, &osid, None).await,
            2 => handle_media_play_seg(&state, &media_ctx, &osid, &oseg, None).await,
            _ => handle_media_play_ts(&state, &media_ctx, &osid, None).await,
        };
    }

    // Direct /{id}.m3u8, /{id}/index.m3u8, /{id}.ts
    if let Some(rest) = path.strip_prefix('/') {
        let snap = state.config();
        if let Some(id) = rest.strip_suffix(".m3u8") {
            if !id.contains('/') && snap.streams_index.contains_key(id) {
                return handle_media_play_hls(&state, &media_ctx, id, None).await;
            }
        }
        if let Some(id) = rest.strip_suffix("/index.m3u8") {
            if !id.contains('/') && snap.streams_index.contains_key(id) {
                return handle_media_play_hls(&state, &media_ctx, id, None).await;
            }
        }
        if let Some(id) = rest.strip_suffix(".ts") {
            if !id.contains('/') && snap.streams_index.contains_key(id) {
                return handle_media_play_ts(&state, &media_ctx, id, None).await;
            }
        }
    }

    detail_resp(StatusCode::NOT_FOUND, "Not Found", None)
}

#[allow(clippy::too_many_arguments)]
fn serve_static_gz(
    gz_bytes: &'static [u8],
    plain_fn: fn() -> &'static [u8],
    etag: &'static str,
    ctype: &'static str,
    cache_ctrl: &'static str,
    extra_hdrs: &[(&'static str, &'static str)],
    accept_gz: bool,
    if_none_match: Option<&str>,
    head_only: bool,
) -> Response<RespBody> {
    if if_none_match == Some(etag) {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(ETAG, etag)
            .body(empty_body())
            .unwrap();
    }
    let mut b = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, ctype)
        .header(CACHE_CONTROL, cache_ctrl)
        .header(ETAG, etag)
        .header("Vary", "Accept-Encoding");
    for (k, v) in extra_hdrs {
        b = b.header(*k, *v);
    }
    if accept_gz {
        b = b.header(CONTENT_ENCODING, "gzip");
        b.body(if head_only {
            empty_body()
        } else {
            full_body(Bytes::from_static(gz_bytes))
        })
        .unwrap()
    } else {
        b.body(if head_only {
            empty_body()
        } else {
            full_body(Bytes::from_static(plain_fn()))
        })
        .unwrap()
    }
}

struct MediaReqCtx<'a> {
    remote_ip: &'a str,
    x_real_ip: Option<&'a str>,
    x_fwd_for: Option<&'a str>,
    x_fwd_proto: Option<&'a str>,
    host_hdr: &'a str,
    query: &'a str,
    auth_hdr: Option<&'a str>,
    cookie_hdr: Option<&'a str>,
    ua_hdr: &'a str,
    has_sec_fetch: bool,
    x_ui_auth: Option<&'a str>,
    if_none_match: Option<&'a str>,
    head_only: bool,
}

async fn check_media_auth(
    state: &AppState,
    ctx: &MediaReqCtx<'_>,
) -> crate::auth::AuthResult {
    let snap = state.config();
    state
        .auth
        .require_media_auth(
            &snap,
            ctx.remote_ip,
            ctx.x_real_ip,
            ctx.x_fwd_for,
            ctx.query,
            ctx.auth_hdr,
            ctx.cookie_hdr,
            ctx.ua_hdr,
            ctx.has_sec_fetch,
            ctx.x_ui_auth,
        )
        .await
}

async fn dispatch_media_tail(
    state: &Arc<AppState>,
    ctx: &MediaReqCtx<'_>,
    tail: &str,
    host_hint: Option<&str>,
) -> Response<RespBody> {
    if let Some((sid, seg_name)) = tail.split_once("/segment/") {
        if !seg_name.is_empty() {
            return handle_media_play_seg(state, ctx, sid, seg_name, host_hint).await;
        }
    }
    if let Some(sid) = tail.strip_suffix("/index.m3u8") {
        return handle_media_play_hls(state, ctx, sid, host_hint).await;
    }
    if let Some(sid) = tail.strip_suffix(".m3u8") {
        return handle_media_play_hls(state, ctx, sid, host_hint).await;
    }
    let sid = tail.strip_suffix(".ts").unwrap_or(tail);
    handle_media_play_ts(state, ctx, sid, host_hint).await
}

fn strip_m3u8_output_suffix(path: &str) -> Option<&str> {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with("/index.m3u8") {
        let base = &path[..path.len() - "/index.m3u8".len()];
        Some(base.trim_end_matches('/'))
    } else if lower.ends_with(".m3u8") {
        let base = &path[..path.len() - ".m3u8".len()];
        Some(base.trim_end_matches('/'))
    } else {
        None
    }
}

fn match_http_output_routes(
    routes: &[crate::config::HttpOutputRoute],
    path: &str,
    req_port: u16,
) -> Option<(String, u8, String)> {
    for route in routes {
        if route.port != req_port {
            continue;
        }
        if let Some(base_rp) = strip_m3u8_output_suffix(&route.path) {
            if path == route.path
                || (!base_rp.is_empty()
                    && (path == format!("{}.m3u8", base_rp)
                        || path == format!("{}/index.m3u8", base_rp)))
            {
                return Some((route.stream_id.clone(), 1, String::new()));
            }
            if !base_rp.is_empty() {
                if let Some(seg) = path.strip_prefix(&format!("{}/segment/", base_rp)) {
                    if !seg.is_empty() {
                        return Some((route.stream_id.clone(), 2, seg.to_string()));
                    }
                }
                if path == base_rp {
                    return Some((route.stream_id.clone(), 0, String::new()));
                }
            }
        } else {
            let rp = route.path.trim_end_matches('/');
            if path == route.path || path == rp {
                return Some((route.stream_id.clone(), 0, String::new()));
            }
            if path == format!("{}.m3u8", rp) || path == format!("{}/index.m3u8", rp) {
                return Some((route.stream_id.clone(), 1, String::new()));
            }
            if let Some(seg) = path.strip_prefix(&format!("{}/segment/", rp)) {
                if !seg.is_empty() {
                    return Some((route.stream_id.clone(), 2, seg.to_string()));
                }
            }
        }
    }
    None
}

fn resolve_http_output(state: &AppState, path: &str, req_port: u16) -> Option<(String, u8, String)> {
    let snap = state.config();
    match_http_output_routes(&snap.http_outputs, path, req_port)
}

async fn handle_media_play_ts(
    state: &Arc<AppState>,
    ctx: &MediaReqCtx<'_>,
    sid: &str,
    host_hint: Option<&str>,
) -> Response<RespBody> {
    let ar = check_media_auth(state, ctx).await;
    if !ar.ok {
        return detail_resp(
            StatusCode::from_u16(ar.status).unwrap_or(StatusCode::FORBIDDEN),
            &ar.detail,
            None,
        );
    }
    let Some(rsid) = state.resolve_stream_id(sid, host_hint) else {
        return detail_resp(StatusCode::NOT_FOUND, "Stream not found", None);
    };
    let Some(ch) = state.ensure_channel_started(&rsid) else {
        return detail_resp(StatusCode::CONFLICT, "Stream disabled or has no input", None);
    };
    if ctx.head_only {
        return Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "video/mp2t")
            .header(CACHE_CONTROL, "no-store")
            .header("Accept-Ranges", "none")
            .body(empty_body())
            .unwrap();
    }

    ch.wake();
    let sess_id = next_session_id();
    let cancel = Arc::new(Notify::new());
    let now_wall = now_unix_secs();
    state.sessions.insert(
        sess_id,
        ActiveSession {
            id: sess_id,
            channel_id: ch.id.clone(),
            channel_name: ch.name.clone(),
            addr: ctx.remote_ip.to_string(),
            login: ar.login.clone(),
            ua: ctx.ua_hdr.to_string(),
            start_wall: now_wall,
            sdate_ms: now_wall * 1000,
            cancel: Arc::clone(&cancel),
        },
    );
    ch.nclients.fetch_add(1, Ordering::Relaxed);

    let (tx, mut rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
    let ch_task = Arc::clone(&ch);
    let st_task = Arc::clone(state);

    tokio::spawn(async move {
        struct SessGuard {
            ch: Arc<Channel>,
            st: Arc<AppState>,
            id: u64,
        }
        impl Drop for SessGuard {
            fn drop(&mut self) {
                self.ch.nclients.fetch_sub(1, Ordering::Relaxed);
                self.ch.inner.lock().last_client_act = self.ch.now_s();
                self.st.sessions.remove(&self.id);
            }
        }
        let _guard = SessGuard {
            ch: Arc::clone(&ch_task),
            st: st_task,
            id: sess_id,
        };

        // 1. Wait for first keyframe + PAT/PMT (waking IMMEDIATELY on Notify!)
        // For cluster channels, the remote server already aligned its stream on PAT+PMT+Keyframe,
        // so avoid double-buffering/double-GOP stalls!
        let wait_start = Instant::now();
        let kf_deadline = wait_start
            + Duration::from_millis(if ch_task.is_cluster { 2000 } else { 3500 });
        loop {
            let ready = {
                let st = ch_task.inner.lock();
                if st.ts.kf_cnt > 0 && st.ts.has_psi() {
                    true
                } else if ch_task.is_cluster {
                    let el = wait_start.elapsed();
                    (st.ts.has_psi() && st.ts.wpos > 0 && el >= Duration::from_millis(150))
                        || (st.ts.wpos >= (crate::ts::TS * 8) as u64
                            && el >= Duration::from_millis(350))
                } else {
                    false
                }
            };
            if ready || Instant::now() >= kf_deadline || !ch_task.alive.load(Ordering::Acquire) {
                break;
            }
            let rem = kf_deadline.saturating_duration_since(Instant::now());
            tokio::select! {
                _ = ch_task.data_notify.notified() => {},
                _ = cancel.notified() => return,
                _ = tokio::time::sleep(rem.min(Duration::from_millis(120))) => {},
            }
        }

        // 2. Pick start position & emit PAT/PMT prefix
        let mut pos: u64;
        let prefix: Vec<u8>;
        {
            let st = ch_task.inner.lock();
            if ch_task.is_cluster && st.ts.wpos > 0 && st.ts.wpos - st.ts.ring_low() <= 256 * 1024 {
                pos = st.ts.ring_low();
            } else {
                pos = st.ts.pick_start(ch_task.now_s());
            }
            prefix = st.ts.client_prefix(pos);
        }
        if !prefix.is_empty() && tx.send(Ok(Frame::data(Bytes::from(prefix)))).await.is_err() {
            return;
        }

        // 3. Stream TS bytes continuously with instant Notify wake-ups & 30s backpressure timeout
        loop {
            if !ch_task.alive.load(Ordering::Acquire) {
                return;
            }
            let (chunk, jump_prefix) = {
                let st = ch_task.inner.lock();
                if st.mode == InputMode::Idle || st.ts.rcap() == 0 {
                    return;
                }
                let lo = st.ts.ring_low();
                let mut jp = None;
                if pos < lo {
                    pos = st.ts.pick_start(ch_task.now_s());
                    jp = Some(st.ts.client_prefix(pos));
                }
                let c = st.ts.ring_read_chunk(pos, 512 * 1024);
                pos += c.len() as u64;
                (c, jp)
            };

            if let Some(pre) = jump_prefix {
                if !pre.is_empty()
                    && tokio::time::timeout(
                        Duration::from_secs(30),
                        tx.send(Ok(Frame::data(Bytes::from(pre)))),
                    )
                    .await
                    .is_err()
                {
                    return;
                }
            }

            if !chunk.is_empty() {
                match tokio::time::timeout(
                    Duration::from_secs(30),
                    tx.send(Ok(Frame::data(Bytes::from(chunk)))),
                )
                .await
                {
                    Ok(Ok(())) => continue,
                    _ => return,
                }
            }

            tokio::select! {
                _ = ch_task.data_notify.notified() => {},
                _ = cancel.notified() => return,
                _ = tokio::time::sleep(Duration::from_millis(100)) => {},
            }
        }
    });

    let stream = futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx));
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "video/mp2t")
        .header(CACHE_CONTROL, "no-store, no-cache, must-revalidate")
        .header("Pragma", "no-cache")
        .header("Accept-Ranges", "none")
        .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header("X-Content-Type-Options", "nosniff")
        .body(BodyExt::boxed(StreamBody::new(stream)))
        .unwrap()
}

async fn handle_media_play_hls(
    state: &Arc<AppState>,
    ctx: &MediaReqCtx<'_>,
    sid: &str,
    host_hint: Option<&str>,
) -> Response<RespBody> {
    let ar = check_media_auth(state, ctx).await;
    if !ar.ok {
        return detail_resp(
            StatusCode::from_u16(ar.status).unwrap_or(StatusCode::FORBIDDEN),
            &ar.detail,
            None,
        );
    }
    let Some(rsid) = state.resolve_stream_id(sid, host_hint) else {
        return detail_resp(StatusCode::NOT_FOUND, "Stream not found", None);
    };
    if query_has(ctx.query, "udp") {
        return detail_resp(
            StatusCode::NOT_IMPLEMENTED,
            "UDP playlist discovery is not supported",
            None,
        );
    }

    let tqs = query_get(ctx.query, "token")
        .filter(|t| !t.is_empty())
        .map(|t| format!("?token={}", t))
        .unwrap_or_default();

    if query_has(ctx.query, "ts") {
        let body = format!("#EXTM3U\n/play/{}{}\n", rsid, tqs);
        return Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "audio/x-mpegurl")
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .body(full_body(body))
            .unwrap();
    }

    // Fast-path for cluster channels: proxy HLS playlist directly from remote cluster node!
    // Eliminates double-buffering and 2-6s local re-segmentation delay (0 extra local RAM).
    let cluster_info = state.cluster_streams.read().get(&rsid).cloned();
    if let Some(cs) = cluster_info {
        if cs.remote_hls_enabled {
            if let Some(resp) = proxy_cluster_hls_playlist(state, &cs, &rsid, ctx, &tqs).await {
                return resp;
            }
        }
    }

    let Some(ch) = state.ensure_channel_started(&rsid) else {
        return detail_resp(StatusCode::CONFLICT, "Stream disabled or has no input", None);
    };

    let was_idle = ch.wake();
    let now_s = ch.now_s();
    {
        let mut st = ch.inner.lock();
        st.hls_last_req = now_s;
        if !st.hls_on {
            hls_out_activate(&mut st, ch.seg_target, ch.seg_keep, now_s);
        }
    }

    // Require 2 segments before serving the initial HLS playlist so UHD / high-bitrate players
    // have a buffered follow-up segment and never stall right after segment 1 (RFC 8216 live edge).
    // Fallback to 1 segment only if a single long GOP (>= 3.5s) is already ready and waited > 2.5s.
    let target_segs = 2usize;
    let wait_secs = if was_idle {
        (ch.seg_target * 3.5 + 7.0).max(15.0)
    } else {
        ch.seg_target * 2.5 + 3.0
    };
    let wait_start = Instant::now();
    let deadline = wait_start + Duration::from_secs_f64(wait_secs);

    ch.nwaiters.fetch_add(1, Ordering::Relaxed);
    loop {
        let (nsegs, first_dur) = {
            let st = ch.inner.lock();
            (st.segs.len(), st.segs.front().map(|s| s.dur).unwrap_or(0.0))
        };
        let now = Instant::now();
        if nsegs >= target_segs
            || (nsegs >= 1 && first_dur >= 3.5 && wait_start.elapsed() >= Duration::from_millis(2500))
            || (nsegs >= 1 && now + Duration::from_millis(1500) >= deadline)
        {
            break;
        }
        if now >= deadline || !ch.alive.load(Ordering::Acquire) {
            break;
        }
        let rem = deadline.saturating_duration_since(now);
        tokio::select! {
            _ = ch.seg_notify.notified() => {},
            _ = tokio::time::sleep(rem.min(Duration::from_millis(250))) => {},
        }
    }
    ch.nwaiters.fetch_sub(1, Ordering::Relaxed);

    let pre = format!("/play/{}/segment/", rsid);
    let Some((body, etag)) = ch.render_hls_playlist(&pre, &tqs) else {
        return detail_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "HLS segments not yet available",
            Some("1"),
        );
    };

    // Conditional GET 304 Not Modified for polling HLS clients!
    if !etag.is_empty() && ctx.if_none_match == Some(etag.as_str()) {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(ETAG, etag)
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .body(empty_body())
            .unwrap();
    }

    let mut b = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/vnd.apple.mpegurl")
        .header(CACHE_CONTROL, "no-store, no-cache, must-revalidate")
        .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*");
    if !etag.is_empty() {
        b = b.header(ETAG, etag);
    }
    b.body(if ctx.head_only {
        empty_body()
    } else {
        full_body(body)
    })
    .unwrap()
}

async fn handle_media_play_seg(
    state: &Arc<AppState>,
    ctx: &MediaReqCtx<'_>,
    sid: &str,
    seg_name: &str,
    host_hint: Option<&str>,
) -> Response<RespBody> {
    let ar = check_media_auth(state, ctx).await;
    if !ar.ok {
        return detail_resp(
            StatusCode::from_u16(ar.status).unwrap_or(StatusCode::FORBIDDEN),
            &ar.detail,
            None,
        );
    }
    let Some(rsid) = state.resolve_stream_id(sid, host_hint) else {
        return detail_resp(StatusCode::NOT_FOUND, "Stream not found", None);
    };

    // Fast-path for cluster HLS segments: proxy directly over warm Keep-Alive pool (0 local RAM)
    let cluster_info = state.cluster_streams.read().get(&rsid).cloned();
    if let Some(cs) = cluster_info {
        if cs.remote_hls_enabled {
            if let Some(resp) = proxy_cluster_hls_segment(state, &cs, seg_name, ctx).await {
                return resp;
            }
        }
    }

    let Some(ch) = state.ensure_channel_started(&rsid) else {
        return detail_resp(StatusCode::CONFLICT, "Stream disabled or has no input", None);
    };
    ch.wake();
    let Some(seg_bytes) = ch.get_segment(seg_name) else {
        return detail_resp(StatusCode::NOT_FOUND, "Segment not found or expired", None);
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "video/mp2t")
        .header(CACHE_CONTROL, "public, max-age=60")
        .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(if ctx.head_only {
            empty_body()
        } else {
            // Zero-copy Bytes clone (atomic refcount bump only)
            full_body((*seg_bytes).clone())
        })
        .unwrap()
}

fn rewrite_cluster_hls_playlist(raw: &str, rsid: &str, tqs: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 256);
    for line in raw.lines() {
        let tr = line.trim();
        if tr.is_empty() || tr.starts_with('#') {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let no_q = tr.split('?').next().unwrap_or(tr);
        let seg_name = no_q.rsplit('/').next().unwrap_or(no_q);
        if !seg_name.is_empty() && seg_name.ends_with(".ts") {
            out.push_str("/play/");
            out.push_str(rsid);
            out.push_str("/segment/");
            out.push_str(seg_name);
            out.push_str(tqs);
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

async fn proxy_cluster_hls_playlist(
    state: &AppState,
    cs: &ClusterStream,
    rsid: &str,
    ctx: &MediaReqCtx<'_>,
    tqs: &str,
) -> Option<Response<RespBody>> {
    let qs = cs.auth_query.as_deref().unwrap_or("");
    let url = format!("http://{}/play/{}.m3u8{}", cs.host_port, cs.orig_id, qs);
    let mut req = state
        .http_client
        .get(&url)
        .header(USER_AGENT, "Astrika/2.1");
    if let Some(ref ah) = cs.auth_header {
        req = req.header(AUTHORIZATION, ah.as_str());
    }
    if let Some(inm) = ctx.if_none_match {
        req = req.header("If-None-Match", inm);
    }

    let resp = tokio::time::timeout(Duration::from_secs(10), req.send())
        .await
        .ok()?
        .ok()?;
    let st_code = resp.status().as_u16();
    if st_code == 304 {
        let mut b = Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        if let Some(et) = resp.headers().get(ETAG).and_then(|v| v.to_str().ok()) {
            b = b.header(ETAG, et);
        }
        return Some(b.body(empty_body()).unwrap());
    }
    if st_code == 503 {
        return Some(detail_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "HLS segments not yet available",
            Some("1"),
        ));
    }
    if st_code != 200 {
        return None;
    }

    let etag = resp
        .headers()
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let text = resp.text().await.ok()?;
    if !text.contains("#EXTM3U") {
        return None;
    }
    let rewritten = rewrite_cluster_hls_playlist(&text, rsid, tqs);
    let mut b = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/vnd.apple.mpegurl")
        .header(CACHE_CONTROL, "no-store, no-cache, must-revalidate")
        .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*");
    if let Some(et) = etag {
        b = b.header(ETAG, et);
    }
    Some(
        b.body(if ctx.head_only {
            empty_body()
        } else {
            full_body(rewritten)
        })
        .unwrap(),
    )
}

async fn proxy_cluster_hls_segment(
    state: &AppState,
    cs: &ClusterStream,
    seg_name: &str,
    ctx: &MediaReqCtx<'_>,
) -> Option<Response<RespBody>> {
    let qs = cs.auth_query.as_deref().unwrap_or("");
    let url = format!(
        "http://{}/play/{}/segment/{}{}",
        cs.host_port, cs.orig_id, seg_name, qs
    );
    let mut req = state
        .http_client
        .get(&url)
        .header(USER_AGENT, "Astrika/2.1")
        .header("Accept-Encoding", "identity");
    if let Some(ref ah) = cs.auth_header {
        req = req.header(AUTHORIZATION, ah.as_str());
    }

    let resp = tokio::time::timeout(Duration::from_secs(8), req.send())
        .await
        .ok()?
        .ok()?;
    if resp.status().as_u16() != 200 {
        return None;
    }
    let bytes = tokio::time::timeout(Duration::from_secs(15), resp.bytes())
        .await
        .ok()?
        .ok()?;
    Some(
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "video/mp2t")
            .header(CACHE_CONTROL, "public, max-age=60")
            .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .body(if ctx.head_only {
                empty_body()
            } else {
                full_body(bytes)
            })
            .unwrap(),
    )
}

fn playlist_base_url(ctx: &MediaReqCtx<'_>, default_port: u16) -> String {
    let proto = ctx
        .x_fwd_proto
        .and_then(|p| p.split(',').next())
        .map(|s| s.trim())
        .filter(|s| *s == "http" || *s == "https")
        .unwrap_or("http");
    let host = if !ctx.host_hdr.is_empty() {
        ctx.host_hdr.to_string()
    } else {
        format!("127.0.0.1:{}", default_port)
    };
    format!("{}://{}", proto, host)
}

async fn serve_m3u_playlist(state: &AppState, ctx: &MediaReqCtx<'_>) -> Response<RespBody> {
    let ar = check_media_auth(state, ctx).await;
    if !ar.ok {
        return detail_resp(
            StatusCode::from_u16(ar.status).unwrap_or(StatusCode::FORBIDDEN),
            &ar.detail,
            None,
        );
    }
    if query_has(ctx.query, "udp") {
        return detail_resp(
            StatusCode::NOT_IMPLEMENTED,
            "UDP playlist discovery is not supported",
            None,
        );
    }
    let snap = state.config();
    let use_hls = query_has(ctx.query, "hls")
        || (!query_has(ctx.query, "ts") && snap.http_play_hls && !snap.http_play_stream);
    let use_ts = query_has(ctx.query, "ts");
    let token = query_get(ctx.query, "token").unwrap_or_default();
    let tqs = if token.is_empty() {
        String::new()
    } else {
        format!("?token={}", token)
    };
    let base = playlist_base_url(ctx, snap.port);
    let suffix = if use_hls {
        ".m3u8"
    } else if use_ts {
        ".ts"
    } else {
        ""
    };

    let cgen = state.cluster_gen.load(Ordering::Relaxed);
    let cache_key = format!("m3u|{}|{}|{}", base, suffix, tqs);
    if let Some(entry) = state.playlist_cache.get(&cache_key) {
        if entry.0 == snap.generation && entry.1 == cgen {
            return Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "audio/x-mpegurl")
                .header(CACHE_CONTROL, "no-store")
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(if ctx.head_only {
                    empty_body()
                } else {
                    full_body(entry.2.clone())
                })
                .unwrap();
        }
    }

    let mut out = String::with_capacity(4096);
    if snap.m3u_header.is_empty() {
        out.push_str("#EXTM3U\n");
    } else {
        out.push_str(&format!("#EXTM3U {}\n", snap.m3u_header));
    }

    let mut items: Vec<Value> = Vec::new();
    if let Some(ms) = snap.raw.get("make_stream").and_then(|v| v.as_array()) {
        items.extend(ms.iter().cloned());
    }
    for cs in state.cluster_streams.read().values() {
        items.push(cs.cfg.clone());
    }

    for s in &items {
        if !s.is_object() || !get_bool_field(Some(s), "enable", true) {
            continue;
        }
        let sid = s.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if sid.is_empty() {
            continue;
        }
        let name = s
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|n| !n.is_empty())
            .unwrap_or(sid);
        let tvg = s.get("xmltv_id").and_then(|v| v.as_str()).unwrap_or(sid);
        let mut grp = "";
        if let Some(groups) = s.get("groups").and_then(|v| v.as_object()) {
            if !snap.playlist_arrange.is_empty() {
                if let Some(g) = groups.get(&snap.playlist_arrange).and_then(|v| v.as_str()) {
                    grp = g;
                }
            }
            if grp.is_empty() {
                if let Some(g) = groups.values().next().and_then(|v| v.as_str()) {
                    grp = g;
                }
            }
        }
        if !grp.is_empty() {
            out.push_str(&format!(
                "#EXTINF:-1 tvg-id=\"{}\" group-title=\"{}\",{}\n",
                tvg, grp, name
            ));
        } else {
            out.push_str(&format!("#EXTINF:-1 tvg-id=\"{}\",{}\n", tvg, name));
        }
        out.push_str(&format!("{}/play/{}{}{}\n", base, sid, suffix, tqs));
    }

    let bytes = Bytes::from(out);
    if state.playlist_cache.len() > 32 {
        state.playlist_cache.clear();
    }
    state
        .playlist_cache
        .insert(cache_key, (snap.generation, cgen, bytes.clone()));

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "audio/x-mpegurl")
        .header(CACHE_CONTROL, "no-store")
        .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(if ctx.head_only {
            empty_body()
        } else {
            full_body(bytes)
        })
        .unwrap()
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

async fn serve_xspf_playlist(state: &AppState, ctx: &MediaReqCtx<'_>) -> Response<RespBody> {
    let ar = check_media_auth(state, ctx).await;
    if !ar.ok {
        return detail_resp(
            StatusCode::from_u16(ar.status).unwrap_or(StatusCode::FORBIDDEN),
            &ar.detail,
            None,
        );
    }
    let snap = state.config();
    let token = query_get(ctx.query, "token").unwrap_or_default();
    let tqs = if token.is_empty() {
        String::new()
    } else {
        format!("?token={}", token)
    };
    let base = playlist_base_url(ctx, snap.port);

    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<playlist xmlns=\"http://xspf.org/ns/0/\" version=\"1\">\n  <title>{}</title>\n  <trackList>\n",
        xml_escape(&snap.xspf_title)
    );

    let mut items: Vec<Value> = Vec::new();
    if let Some(ms) = snap.raw.get("make_stream").and_then(|v| v.as_array()) {
        items.extend(ms.iter().cloned());
    }
    for cs in state.cluster_streams.read().values() {
        items.push(cs.cfg.clone());
    }

    for s in &items {
        if !s.is_object() || !get_bool_field(Some(s), "enable", true) {
            continue;
        }
        let sid = s.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if sid.is_empty() {
            continue;
        }
        let name = s
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|n| !n.is_empty())
            .unwrap_or(sid);
        let loc = format!("{}/play/{}{}", base, sid, tqs);
        out.push_str(&format!(
            "    <track><title>{}</title><location>{}</location></track>\n",
            xml_escape(name),
            xml_escape(&loc)
        ));
    }
    out.push_str("  </trackList>\n</playlist>\n");

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/xspf+xml")
        .header(CACHE_CONTROL, "no-store")
        .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(if ctx.head_only {
            empty_body()
        } else {
            full_body(out)
        })
        .unwrap()
}

/* ----------------------------------------------------------- Control API */

async fn read_bounded_body(req: Request<Incoming>, limit: usize) -> Result<Bytes, StatusCode> {
    let mut body = req.into_body();
    let mut buf = Vec::new();
    while let Some(frame_res) = body.frame().await {
        let frame = frame_res.map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Ok(data) = frame.into_data() {
            if buf.len() + data.len() > limit {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            buf.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(buf))
}

fn gen_uuid_hex(bytes_len: usize) -> String {
    let mut buf = vec![0u8; bytes_len];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

#[allow(clippy::too_many_arguments)]
async fn handle_control_api(
    state: &Arc<AppState>,
    remote_ip: &str,
    auth_hdr: Option<&str>,
    cookie_hdr: Option<&str>,
    ua_hdr: &str,
    has_sec_fetch: bool,
    x_ui_auth: Option<&str>,
    raw_body: &[u8],
) -> Response<RespBody> {
    let snap = state.config();
    let ar = state
        .auth
        .require_auth(
            &snap,
            remote_ip,
            auth_hdr,
            cookie_hdr,
            ua_hdr,
            has_sec_fetch,
            x_ui_auth,
        )
        .await;
    if !ar.ok {
        return detail_resp(
            StatusCode::from_u16(ar.status).unwrap_or(StatusCode::FORBIDDEN),
            &ar.detail,
            if ar.status == 429 { Some("60") } else { None },
        );
    }

    let body: Value = match serde_json::from_slice::<Value>(raw_body) {
        Ok(v) if v.is_object() => v,
        Ok(v) if v.is_array() => {
            return detail_resp(StatusCode::UNPROCESSABLE_ENTITY, "Invalid JSON", None);
        }
        _ => return detail_resp(StatusCode::BAD_REQUEST, "Invalid JSON", None),
    };
    let Some(cmd) = body.get("cmd").and_then(|v| v.as_str()) else {
        return detail_resp(
            StatusCode::UNPROCESSABLE_ENTITY,
            "cmd must be a string",
            None,
        );
    };

    if cmd == "version" {
        return json_resp(
            StatusCode::OK,
            &json!({ "version": ASTRIKA_VERSION, "commit": "astrika-rust" }),
        );
    }
    if cmd == "status" {
        let scount: usize = state.sessions.len();
        return json_resp(
            StatusCode::OK,
            &json!({
                "version": ASTRIKA_VERSION,
                "commit": "astrika-rust",
                "uptime": now_unix_secs() - state.started_wall,
                "observer": !ar.admin,
                "dvb_list": [],
                "net_list": [],
                "sessions_count": scount,
                "system": {
                    "cpu_frequency_max": 0,
                    "cpu_frequency_cur": 0
                }
            }),
        );
    }
    if cmd == "load" {
        if ar.admin {
            return json_resp(StatusCode::OK, &snap.raw);
        } else {
            return json_resp(StatusCode::OK, &redact_val(&snap.raw, true));
        }
    }
    if cmd == "sessions" {
        let now_w = now_unix_secs();
        let arr: Vec<Value> = state
            .sessions
            .iter()
            .map(|e| {
                let s = e.value();
                json!({
                    "client_id": s.id,
                    "channel_id": s.channel_id,
                    "channel_name": s.channel_name,
                    "addr": s.addr,
                    "login": s.login,
                    "ua": s.ua,
                    "sdate": s.sdate_ms,
                    "uptime": (now_w - s.start_wall).max(0)
                })
            })
            .collect();
        return json_resp(StatusCode::OK, &json!({ "sessions": arr }));
    }
    if cmd == "log" {
        let arr: Vec<Value> = state
            .logs
            .lock()
            .iter()
            .map(|l| json!({ "type": l.level, "time": l.ts, "text": l.text }))
            .collect();
        return json_resp(StatusCode::OK, &json!({ "log": arr }));
    }

    if !ar.admin {
        return detail_resp(StatusCode::FORBIDDEN, "Administrator role required", None);
    }

    if cmd == "scan-init" {
        let st = body.get("scan").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(sid) = st.strip_prefix("stream://") {
            let scan_id = gen_uuid_hex(5);
            state.scans.insert(
                scan_id.clone(),
                ScanEntry {
                    id: scan_id.clone(),
                    stream_id: sid.to_string(),
                    cluster_host: String::new(),
                },
            );
            return json_resp(StatusCode::OK, &json!({ "scan-init": "ok", "id": scan_id }));
        }
        return detail_resp(
            StatusCode::NOT_IMPLEMENTED,
            "DVB hardware operations are not implemented",
            None,
        );
    }
    if cmd == "scan-kill" {
        let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
        state.scans.remove(id);
        return json_resp(
            StatusCode::OK,
            &json!({ "scan-kill": "ok", "success": true }),
        );
    }
    if cmd.starts_with("scan-") || cmd == "restart-adapter" {
        return detail_resp(
            StatusCode::NOT_IMPLEMENTED,
            "DVB hardware operations are not implemented",
            None,
        );
    }
    if cmd == "close-session" {
        let Some(target_id) = body.get("id").and_then(|v| v.as_u64()) else {
            return detail_resp(
                StatusCode::UNPROCESSABLE_ENTITY,
                "id must be an integer",
                None,
            );
        };
        if let Some((_, sess)) = state.sessions.remove(&target_id) {
            sess.cancel.notify_waiters();
            return json_resp(StatusCode::OK, &json!({ "success": true }));
        }
        return detail_resp(StatusCode::NOT_FOUND, "Session not found", None);
    }
    if cmd == "restart" {
        let loaded = match load_disk_config(&state.config_path, None, 0) {
            Ok(v) => v,
            Err(e) => return detail_resp(StatusCode::INTERNAL_SERVER_ERROR, &e, None),
        };
        if let Err(e) = state.apply_config(loaded, false, true).await {
            return detail_resp(StatusCode::INTERNAL_SERVER_ERROR, &e, None);
        }
        state.add_log("info", "Configuration and streams reloaded".to_string());
        return json_resp(
            StatusCode::OK,
            &json!({
                "success": true,
                "message": "Configuration and engines reloaded; process not restarted"
            }),
        );
    }

    // Mutating commands
    let mut config = snap.raw.clone();
    let mut event = json!({});
    let mut result = json!({ "success": true });
    let mut ws_scope = cmd.to_string();
    let mut revoke_logins: Vec<String> = Vec::new();

    match cmd {
        "upload" => {
            let Some(up) = body.get("config").filter(|v| v.is_object()) else {
                return detail_resp(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "config must be an object",
                    None,
                );
            };
            let mut uploaded = up.clone();
            if let (Some(uusers), Some(cur_users)) = (
                uploaded.get_mut("users").and_then(|v| v.as_object_mut()),
                config.get("users").and_then(|v| v.as_object()),
            ) {
                for (k, ud) in uusers.iter_mut() {
                    if let Some(udo) = ud.as_object_mut() {
                        let empty_pw = udo
                            .get("password")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .is_empty();
                        if empty_pw {
                            if let Some(old_pw) = cur_users
                                .get(k)
                                .and_then(|v| v.get("password"))
                                .and_then(|v| v.as_str())
                                .filter(|s| !s.is_empty())
                            {
                                udo.insert("password".to_string(), json!(old_pw));
                            }
                        }
                    }
                }
            }
            config = uploaded;
            event["reload"] = json!(true);
        }
        "set-stream" => {
            let Some(sp) = body.get("stream").filter(|v| v.is_object()) else {
                return detail_resp(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "stream must be an object",
                    None,
                );
            };
            let mut data = sp.clone();
            let req_id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let dat_id = data.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let is_rem = get_bool_field(Some(&data), "remove", get_bool_field(Some(&body), "remove", false));
            let chosen = if is_rem {
                if !req_id.is_empty() && req_id != "-" { req_id } else { dat_id }
            } else if !dat_id.is_empty() && dat_id != "-" {
                dat_id
            } else {
                req_id
            };
            let sid = if chosen.is_empty() || chosen == "-" {
                gen_uuid_hex(6)
            } else {
                chosen.to_string()
            };
            let old_sid = if !req_id.is_empty() && req_id != "-" {
                req_id.to_string()
            } else {
                sid.clone()
            };
            data["id"] = json!(sid);

            let mut nms = Vec::new();
            if let Some(ms) = config.get("make_stream").and_then(|v| v.as_array()) {
                for s in ms {
                    let cid = s.get("id").and_then(|v| v.as_str()).unwrap_or("");
                    if cid != sid && cid != old_sid {
                        nms.push(s.clone());
                    }
                }
            }
            if !is_rem {
                let sname = data.get("name").and_then(|v| v.as_str()).unwrap_or(&sid);
                state.add_log("info", format!("Stream '{}' ({}) saved", sname, sid));
                nms.push(data.clone());
            } else {
                data["remove"] = json!(true);
                state.add_log("warning", format!("Stream '{}' removed", sid));
            }
            config["make_stream"] = Value::Array(nms);
            event["id"] = json!(old_sid);
            event["stream"] = data;
            result["id"] = json!(sid);
        }
        "set-stream-input" => {
            let sid = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let inp_idx = body.get("input").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
            if let Some(ch) = state.channels.get(sid) {
                let mut st = ch.inner.lock();
                if !ch.urls.is_empty() {
                    st.cur_url = inp_idx.saturating_sub(1) % ch.urls.len();
                    st.cached_variant = None;
                }
            }
            event["id"] = json!(sid);
            event["input"] = json!(inp_idx);
        }
        "set-user" => {
            let Some(up) = body.get("user").filter(|v| v.is_object()) else {
                return detail_resp(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "user must be an object",
                    None,
                );
            };
            let mut data = up.clone();
            let req_id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let dat_id = data
                .get("id")
                .or_else(|| data.get("login"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let is_rem = get_bool_field(Some(&data), "remove", get_bool_field(Some(&body), "remove", false));
            let sid = if !dat_id.is_empty() && dat_id != "-" {
                dat_id.to_string()
            } else {
                req_id.to_string()
            };
            if !valid_login(&sid) {
                return detail_resp(StatusCode::UNPROCESSABLE_ENTITY, "Invalid login", None);
            }
            let old_id = if !req_id.is_empty() && req_id != "-" {
                req_id.to_string()
            } else {
                sid.clone()
            };
            if let Some(users) = config.get_mut("users").and_then(|v| v.as_object_mut()) {
                if is_rem {
                    users.remove(&sid);
                    users.remove(&old_id);
                    revoke_logins.push(sid.clone());
                    data["remove"] = json!(true);
                } else {
                    let prev = users.get(&old_id).cloned().unwrap_or_else(|| json!({}));
                    let mut merged = prev;
                    if let (Some(mo), Some(do_)) = (merged.as_object_mut(), data.as_object()) {
                        for (k, v) in do_ {
                            if k == "password" {
                                if let Some(ps) = v.as_str() {
                                    if !ps.is_empty() {
                                        let h = if ps.starts_with("pbkdf2_sha256$") {
                                            ps.to_string()
                                        } else {
                                            hash_password_async(ps.to_string()).await
                                        };
                                        mo.insert("password".to_string(), json!(h));
                                        revoke_logins.push(sid.clone());
                                    }
                                }
                            } else {
                                mo.insert(k.clone(), v.clone());
                            }
                        }
                    }
                    if old_id != sid {
                        users.remove(&old_id);
                        revoke_logins.push(old_id.clone());
                    }
                    users.insert(sid.clone(), merged.clone());
                    data = merged;
                }
            }
            event["id"] = json!(sid);
            event["user"] = data;
            if old_id != sid {
                event["old_id"] = json!(old_id);
            }
        }
        "set-settings" | "set-auth" => {
            let key = &cmd[4..];
            let p = body.get(key);
            let mut data = match p {
                Some(v) if v.is_object() => v.clone(),
                _ if key == "auth" => json!({}),
                _ => {
                    return detail_resp(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "payload must be an object",
                        None,
                    );
                }
            };
            if get_bool_field(Some(&data), "remove", false) {
                data = json!({});
            }
            config[key] = data.clone();
            event[key] = data;
        }
        "set-log" => {
            let data = body
                .get("set")
                .filter(|v| v.is_object())
                .cloned()
                .unwrap_or_else(|| json!({}));
            config["log"] = data.clone();
            event["set"] = data;
            ws_scope = "log_event".to_string();
        }
        "set-config" => {
            let key = body.get("key").and_then(|v| v.as_str()).unwrap_or("");
            if key.is_empty() {
                return detail_resp(StatusCode::UNPROCESSABLE_ENTITY, "key required", None);
            }
            let dp = body.get("data");
            let rem = get_bool_field(Some(&body), "remove", false)
                || get_bool_field(dp, "remove", false);
            if rem {
                if let Some(o) = config.as_object_mut() {
                    o.remove(key);
                }
                event["key"] = json!(key);
                event["data"] = Value::Null;
            } else {
                let d = dp.cloned().unwrap_or_else(|| json!({}));
                config[key] = d.clone();
                event["key"] = json!(key);
                event["data"] = d;
            }
        }
        "set-category" | "set-server" | "set-softcam" | "set-cas" | "set-adapter" => {
            let name = &cmd[4..];
            let ckey = match name {
                "category" => "categories",
                "server" => "servers",
                "adapter" => "dvb_tune",
                other => other,
            };
            let Some(dp) = body.get(name).filter(|v| v.is_object()) else {
                return detail_resp(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "entry must be an object",
                    None,
                );
            };
            let mut data = dp.clone();
            let is_rem = get_bool_field(Some(&data), "remove", get_bool_field(Some(&body), "remove", false));
            let values = config
                .get_mut(ckey)
                .and_then(|v| v.as_array_mut())
                .expect("validated array");

            if name == "category" || name == "server" {
                let idv = body.get("id").or_else(|| data.get("id"));
                let idx_opt = idv.and_then(|v| match v {
                    Value::Number(n) => n.as_u64().map(|x| x as usize),
                    Value::String(s) if !s.is_empty() && s != "-" => s.parse::<usize>().ok(),
                    _ => None,
                });
                if let Some(idx) = idx_opt {
                    if idx >= values.len() {
                        return detail_resp(StatusCode::NOT_FOUND, "Entry not found", None);
                    }
                    if is_rem {
                        data["remove"] = json!(true);
                        values.remove(idx);
                    } else {
                        values[idx] = data.clone();
                    }
                    event["id"] = json!(idx);
                } else if is_rem {
                    return detail_resp(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "Removal requires id",
                        None,
                    );
                } else {
                    values.push(data.clone());
                }
            } else {
                let req_id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let dat_id = data.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let chosen = if is_rem {
                    if !req_id.is_empty() && req_id != "-" { req_id } else { dat_id }
                } else if !dat_id.is_empty() && dat_id != "-" {
                    dat_id
                } else {
                    req_id
                };
                let sid = if chosen.is_empty() || chosen == "-" {
                    gen_uuid_hex(6)
                } else {
                    chosen.to_string()
                };
                let old_sid = if !req_id.is_empty() && req_id != "-" {
                    req_id.to_string()
                } else {
                    sid.clone()
                };
                data["id"] = json!(sid);
                values.retain(|el| {
                    let eid = el.get("id").and_then(|v| v.as_str()).unwrap_or("");
                    eid != sid && eid != old_sid
                });
                if is_rem {
                    data["remove"] = json!(true);
                } else {
                    values.push(data.clone());
                }
                event["id"] = json!(old_sid);
                result["configuration_only"] = json!(true);
            }
            event[name] = data;
        }
        _ => return detail_resp(StatusCode::BAD_REQUEST, "Unknown command", None),
    }

    if let Some(g) = body.get("gid").and_then(|v| v.as_i64()) {
        config["gid"] = json!(g);
        event["gid"] = json!(g);
    }
    let rebuild = get_bool_field(Some(&body), "restart", false);
    if let Err(e) = state.apply_config(config, true, rebuild).await {
        return detail_resp(StatusCode::UNPROCESSABLE_ENTITY, &e, None);
    }
    state.broadcast_ws(&ws_scope, &event);
    for login in revoke_logins {
        state.revoke_account_sockets(&login);
    }
    json_resp(StatusCode::OK, &result)
}

fn same_origin_ok(origin: Option<&str>, host: &str) -> bool {
    let Some(orig) = origin.filter(|s| !s.is_empty()) else {
        return true;
    };
    let Some((_, hp)) = orig.split_once("://") else {
        return false;
    };
    if hp.contains('@') || hp.contains('?') || hp.contains('#') {
        return false;
    }
    let ohost = match hp.split_once('/') {
        Some((h, rest)) if rest.is_empty() => h,
        Some(_) => return false,
        None => hp,
    };
    ohost.eq_ignore_ascii_case(host)
}

#[allow(clippy::too_many_arguments)]
async fn handle_account_change(
    state: &Arc<AppState>,
    remote_ip: &str,
    host_hdr: &str,
    origin_hdr: Option<&str>,
    auth_hdr: Option<&str>,
    cookie_hdr: Option<&str>,
    ua_hdr: &str,
    has_sec_fetch: bool,
    x_ui_auth: Option<&str>,
    raw_body: &[u8],
) -> Response<RespBody> {
    if !same_origin_ok(origin_hdr, host_hdr) {
        return detail_resp(StatusCode::FORBIDDEN, "Cross-origin request rejected", None);
    }
    let snap = state.config();
    let ar = state
        .auth
        .require_auth(
            &snap,
            remote_ip,
            auth_hdr,
            cookie_hdr,
            ua_hdr,
            has_sec_fetch,
            x_ui_auth,
        )
        .await;
    if !ar.ok || ar.login.is_empty() {
        return detail_resp(StatusCode::FORBIDDEN, "Authentication required", None);
    }
    let Ok(body) = serde_json::from_slice::<Value>(raw_body) else {
        return detail_resp(StatusCode::BAD_REQUEST, "Invalid JSON", None);
    };
    let cur_pass = body
        .get("current_password")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let new_login = body
        .get("new_login")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(&ar.login);
    let new_pass = body
        .get("new_password")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !valid_login(new_login) || !valid_password(new_pass) {
        return detail_resp(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid login or password (min 12 chars with letters and digits)",
            None,
        );
    }
    let Some(u) = snap.users_index.get(&ar.login) else {
        return detail_resp(StatusCode::FORBIDDEN, "User not found", None);
    };
    let expected = if !u.password.is_empty() {
        &u.password
    } else {
        &u.token
    };
    if !state
        .auth
        .verify_password_cached(cur_pass, expected, snap.generation)
        .await
    {
        state.auth.record_failure(remote_ip);
        return detail_resp(StatusCode::FORBIDDEN, "Current password is incorrect", None);
    }
    if new_login != ar.login && snap.users_index.contains_key(new_login) {
        return detail_resp(StatusCode::CONFLICT, "Login is already in use", None);
    }
    let hashed = hash_password_async(new_pass.to_string()).await;
    let mut ncfg = snap.raw.clone();
    if let Some(users) = ncfg.get_mut("users").and_then(|v| v.as_object_mut()) {
        if let Some(mut acc) = users.remove(&ar.login) {
            if let Some(ao) = acc.as_object_mut() {
                ao.remove("token");
                ao.insert("password".to_string(), json!(hashed));
            }
            users.insert(new_login.to_string(), acc);
        }
    }
    if let Err(e) = state.apply_config(ncfg, true, false).await {
        return detail_resp(StatusCode::INTERNAL_SERVER_ERROR, &e, None);
    }
    state.revoke_account_sockets(&ar.login);
    json_resp(
        StatusCode::OK,
        &json!({ "success": true, "login": new_login }),
    )
}

#[allow(clippy::too_many_arguments)]
async fn handle_reset_password(
    state: &Arc<AppState>,
    remote_ip: &str,
    auth_hdr: Option<&str>,
    cookie_hdr: Option<&str>,
    ua_hdr: &str,
    has_sec_fetch: bool,
    x_ui_auth: Option<&str>,
    raw_body: &[u8],
) -> Response<RespBody> {
    let snap = state.config();
    let ar = state
        .auth
        .require_auth(
            &snap,
            remote_ip,
            auth_hdr,
            cookie_hdr,
            ua_hdr,
            has_sec_fetch,
            x_ui_auth,
        )
        .await;
    if !ar.ok || !ar.admin {
        return detail_resp(
            StatusCode::FORBIDDEN,
            if ar.ok {
                "Administrator role required"
            } else {
                &ar.detail
            },
            None,
        );
    }
    let Ok(body) = serde_json::from_slice::<Value>(raw_body) else {
        return detail_resp(StatusCode::BAD_REQUEST, "Invalid JSON", None);
    };
    let login = body.get("login").and_then(|v| v.as_str()).unwrap_or("");
    let pw = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
    if login.is_empty() || !valid_password(pw) {
        return detail_resp(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Supply login and a password of at least 12 characters with letters and digits",
            None,
        );
    }
    if !snap.users_index.contains_key(login) {
        return detail_resp(StatusCode::NOT_FOUND, "User not found", None);
    }
    let hashed = hash_password_async(pw.to_string()).await;
    let mut ncfg = snap.raw.clone();
    if let Some(u) = ncfg
        .get_mut("users")
        .and_then(|v| v.get_mut(login))
        .and_then(|v| v.as_object_mut())
    {
        u.remove("token");
        u.insert("password".to_string(), json!(hashed));
    }
    if let Err(e) = state.apply_config(ncfg, true, false).await {
        return detail_resp(StatusCode::INTERNAL_SERVER_ERROR, &e, None);
    }
    state.revoke_account_sockets(login);
    json_resp(StatusCode::OK, &json!({ "success": true, "login": login }))
}

/// FIXED SECURITY VULNERABILITY from C version: strictly enforces admin authentication!
#[allow(clippy::too_many_arguments)]
async fn handle_cluster_control(
    state: &Arc<AppState>,
    remote_ip: &str,
    auth_hdr: Option<&str>,
    cookie_hdr: Option<&str>,
    ua_hdr: &str,
    has_sec_fetch: bool,
    x_ui_auth: Option<&str>,
    x_cluster_target: Option<&str>,
    x_cluster_auth: Option<&str>,
    query: &str,
    raw_body: &[u8],
) -> Response<RespBody> {
    let snap = state.config();
    let ar = state
        .auth
        .require_auth(
            &snap,
            remote_ip,
            auth_hdr,
            cookie_hdr,
            ua_hdr,
            has_sec_fetch,
            x_ui_auth,
        )
        .await;
    if !ar.ok || !ar.admin {
        return detail_resp(
            if ar.ok {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::from_u16(ar.status).unwrap_or(StatusCode::FORBIDDEN)
            },
            if ar.ok {
                "Administrator role required"
            } else {
                &ar.detail
            },
            if ar.status == 429 { Some("60") } else { None },
        );
    }

    let target = x_cluster_target
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| query_get(query, "target"))
        .unwrap_or_default();
    if !target.contains(':') {
        return detail_resp(
            StatusCode::BAD_REQUEST,
            "Missing X-Cluster-Target host:port",
            None,
        );
    }

    let Ok(body) = serde_json::from_slice::<Value>(raw_body) else {
        return detail_resp(StatusCode::BAD_REQUEST, "Invalid JSON", None);
    };
    let cmd = body.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
    if cmd == "scan-init" {
        let st = body.get("scan").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(sid) = st.strip_prefix("stream://") {
            let scan_id = gen_uuid_hex(5);
            state.scans.insert(
                scan_id.clone(),
                ScanEntry {
                    id: scan_id.clone(),
                    stream_id: sid.to_string(),
                    cluster_host: target,
                },
            );
            return json_resp(StatusCode::OK, &json!({ "scan-init": "ok", "id": scan_id }));
        }
    } else if cmd == "scan-kill" {
        let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
        state.scans.remove(id);
        return json_resp(
            StatusCode::OK,
            &json!({ "scan-kill": "ok", "success": true }),
        );
    }

    let mut req_b = state
        .http_client
        .post(format!("http://{}/control/", target))
        .header(USER_AGENT, "Astrika/2.1")
        .header(CONTENT_TYPE, "application/json")
        .body(raw_body.to_vec());

    if let Some(ca) = x_cluster_auth.filter(|s| !s.is_empty()) {
        req_b = req_b.header(AUTHORIZATION, ca);
    } else if let Some(srvs) = snap.raw.get("servers").and_then(|v| v.as_array()) {
        for srv in srvs {
            let h = srv.get("host").and_then(|v| v.as_str()).unwrap_or("");
            let p = get_u16(srv, "port", 8000);
            if format!("{}:{}", h, p) == target {
                let u = srv.get("user").and_then(|v| v.as_str()).unwrap_or("");
                let pw = srv.get("pass").and_then(|v| v.as_str()).unwrap_or("");
                if !u.is_empty() {
                    let cred = if pw.is_empty() {
                        u.to_string()
                    } else {
                        format!("{}:{}", u, pw)
                    };
                    req_b = req_b.header(AUTHORIZATION, format!("Basic {}", B64.encode(cred)));
                }
                break;
            }
        }
    }

    match tokio::time::timeout(Duration::from_secs(8), req_b.send()).await {
        Ok(Ok(resp)) => {
            let status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);
            let bytes = resp.bytes().await.unwrap_or_default();
            Response::builder()
                .status(status)
                .header(CONTENT_TYPE, "application/json")
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(full_body(bytes))
                .unwrap()
        }
        _ => detail_resp(StatusCode::BAD_GATEWAY, "Cluster request failed", None),
    }
}

/* ----------------------------------------------------------- WebSocket */

fn compute_ws_accept(key: &str) -> String {
    let mut sha = Sha1::new();
    sha.update(key.as_bytes());
    sha.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    B64.encode(sha.finalize())
}

async fn run_ws_session(
    state: Arc<AppState>,
    upgraded: hyper::upgrade::Upgraded,
    remote_ip: String,
    is_cluster: bool,
    cluster_host: String,
) {
    let ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;
    let (mut sink, mut stream) = ws.split();
    let mut rx = state.ws_tx.subscribe();

    struct WsCountGuard(Arc<AppState>);
    impl Drop for WsCountGuard {
        fn drop(&mut self) {
            self.0.ws_count.fetch_sub(1, Ordering::Relaxed);
        }
    }
    state.ws_count.fetch_add(1, Ordering::Relaxed);
    let _guard = WsCountGuard(Arc::clone(&state));

    let mut authed = false;
    let mut login = String::new();
    let mut ping_iv = tokio::time::interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            _ = state.shutdown.notified() => break,
            _ = ping_iv.tick() => {
                if authed && sink.send(Message::Text("{\"scope\":\"ping\"}".into())).await.is_err() {
                    break;
                }
            }
            bcast = rx.recv() => {
                match bcast {
                    Ok(msg) => {
                        if let Some(ref rev) = msg.revoke_login {
                            if !login.is_empty() && &login == rev {
                                let _ = sink.close().await;
                                break;
                            }
                            continue;
                        }
                        if !authed {
                            continue;
                        }
                        let should_send = match &msg.target_cluster_host {
                            None => !is_cluster,
                            Some(hp) => is_cluster && hp == &cluster_host,
                        };
                        if should_send && sink.send(Message::Text((*msg.text).clone())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            inbound = stream.next() => {
                let Some(Ok(msg)) = inbound else {
                    break;
                };
                match msg {
                    Message::Close(_) => break,
                    Message::Ping(d) => {
                        let _ = sink.send(Message::Pong(d)).await;
                    }
                    Message::Text(txt) => {
                        let Ok(val) = serde_json::from_str::<Value>(&txt) else {
                            let _ = sink.send(Message::Text("{\"scope\":\"error\",\"error\":\"Invalid JSON\"}".into())).await;
                            continue;
                        };
                        let scope = val.get("scope").and_then(|v| v.as_str()).unwrap_or("");
                        if scope == "ping" {
                            let _ = sink.send(Message::Text("{\"scope\":\"ping\"}".into())).await;
                            continue;
                        }
                        if is_cluster {
                            if scope == "auth" {
                                // Validate local admin auth for cluster WS as well
                                let auth_s = val.get("auth").and_then(|v| v.as_str());
                                let snap = state.config();
                                let res = state.auth.check_identity(&snap, auth_s, &remote_ip, false, true).await;
                                if !res.ok && snap.auth_enabled {
                                    let _ = sink.send(Message::Text("{\"scope\":\"auth\",\"authorized\":false}".into())).await;
                                    continue;
                                }
                                authed = true;
                                login = res.login;
                                let resp = json!({ "scope": "auth", "id": gen_uuid_hex(16), "authorized": true });
                                let _ = sink.send(Message::Text(resp.to_string())).await;
                            }
                            continue;
                        }
                        if scope != "auth" {
                            let _ = sink.send(Message::Text("{\"scope\":\"error\",\"error\":\"Authentication message required\"}".into())).await;
                            continue;
                        }
                        let auth_s = val.get("auth").and_then(|v| v.as_str());
                        let snap = state.config();
                        let res = state.auth.check_identity(&snap, auth_s, &remote_ip, false, true).await;
                        if !res.ok {
                            authed = false;
                            let _ = sink.send(Message::Text("{\"scope\":\"auth\",\"authorized\":false}".into())).await;
                        } else {
                            authed = true;
                            login = res.login;
                            let resp = json!({ "scope": "auth", "id": gen_uuid_hex(16), "authorized": true });
                            let _ = sink.send(Message::Text(resp.to_string())).await;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/* ----------------------------------------------------------- Background tasks */

pub fn spawn_background_tasks(state: Arc<AppState>) {
    // 1. 1-second maintenance & WS telemetry loop
    let st1 = Arc::clone(&state);
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = st1.shutdown.notified() => break,
                _ = iv.tick() => {
                    let has_ws = st1.ws_count.load(Ordering::Relaxed) > 0;
                    for entry in st1.channels.iter() {
                        let ch = entry.value();
                        let stats = ch.tick_1s();
                        if !has_ws || !stats.emit {
                            continue;
                        }
                        let ev = if stats.idle {
                            json!({
                                "channel_id": stats.id,
                                "input_id": stats.input_id,
                                "idle": true,
                                "onair": false,
                                "bitrate": 0,
                                "sessions": 0
                            })
                        } else {
                            json!({
                                "running": true,
                                "idle": false,
                                "bitrate": stats.bitrate_kbps,
                                "effective_bitrate": stats.bitrate_kbps,
                                "average_bitrate": stats.bitrate_kbps,
                                "continuity_errors": stats.cc_err,
                                "cc_errors": stats.cc_err,
                                "pes_errors": stats.pes_err,
                                "cc_error": stats.cc_delta,
                                "pes_error": stats.pes_delta,
                                "scrambled": stats.scrambled,
                                "input_id": stats.input_id,
                                "packets": stats.packets,
                                "bytes": stats.packets * crate::ts::TS as u64,
                                "input_errors": stats.input_errors,
                                "last_error": if stats.last_error.is_empty() { Value::Null } else { json!(stats.last_error) },
                                "elapsed": stats.elapsed,
                                "subscribers": stats.subscribers,
                                "channel_id": stats.id,
                                "onair": stats.onair,
                                "sessions": stats.subscribers
                            })
                        };
                        st1.broadcast_ws("stream_event", &ev);
                        if stats.is_cluster && !stats.cluster_host.is_empty() {
                            let mut cev = ev;
                            cev["channel_id"] = json!(stats.cluster_orig_id);
                            st1.broadcast_cluster_ws(&stats.cluster_host, "stream_event", &cev);
                        }
                    }

                    // Emit active stream scans
                    if has_ws && !st1.scans.is_empty() {
                        for sc in st1.scans.iter() {
                            emit_scan(&st1, sc.value());
                        }
                    }
                }
            }
        }
    });

    // 2. Cluster synchronization loop (immediate on config change + every 45s)
    let st2 = Arc::clone(&state);
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_secs(45));
        loop {
            tokio::select! {
                _ = st2.shutdown.notified() => break,
                _ = st2.cluster_sync_notify.notified() => {
                    sync_cluster_once(&st2).await;
                }
                _ = iv.tick() => {
                    sync_cluster_once(&st2).await;
                }
            }
        }
    });
}

fn emit_scan(state: &AppState, sc: &ScanEntry) {
    let rsid = state
        .resolve_stream_id(
            &sc.stream_id,
            if sc.cluster_host.is_empty() {
                None
            } else {
                Some(&sc.cluster_host)
            },
        )
        .unwrap_or_else(|| sc.stream_id.clone());

    let Some(ch) = state.channels.get(&rsid) else {
        return;
    };
    let (total_br, cc_err, pes_err, scrambled, npmt, pcr_pid, tsid, pmts_data, streams_arr) = {
        let st = ch.inner.lock();
        let br = if st.bitrate > 0.0 {
            (st.bitrate / 1000.0 + 0.5) as i64
        } else {
            0
        };
        let mut sarr = Vec::new();
        for pid in 0..8191usize {
            let k = st.ts.kind[pid];
            if k != 0 && k != crate::ts::K_PMT {
                let tname = match k {
                    crate::ts::K_VIDEO => "VIDEO",
                    crate::ts::K_AUDIO => "AUDIO",
                    _ => "DATA",
                };
                sarr.push(json!({
                    "pid": pid,
                    "type_id": st.ts.stype[pid],
                    "type_name": tname,
                    "descriptors": []
                }));
            }
        }
        let mut pmts = Vec::new();
        for i in 0..st.ts.npmt {
            pmts.push((st.ts.pnr[i], st.ts.pmt_pid[i]));
        }
        (
            br,
            st.ts.cc_err,
            st.ts.pes_err,
            st.ts.scrambled,
            st.ts.npmt,
            st.ts.pcr_pid,
            st.ts.tsid,
            pmts,
            sarr,
        )
    };

    if npmt > 0 {
        let progs: Vec<Value> = pmts_data
            .iter()
            .map(|(pnr, pid)| json!({ "pnr": pnr, "pid": pid }))
            .collect();
        let pat = json!({ "data": { "psi": "pat", "tsid": tsid, "programs": progs } });
        state.broadcast_ws("scan", &pat);
        if !sc.cluster_host.is_empty() {
            state.broadcast_cluster_ws(&sc.cluster_host, "scan", &pat);
        }
        for (i, (pnr, pid)) in pmts_data.iter().enumerate() {
            let pmt = json!({
                "data": {
                    "psi": "pmt",
                    "pnr": pnr,
                    "pid": pid,
                    "pcr": if pcr_pid >= 0 { pcr_pid } else { 8191 },
                    "descriptors": [],
                    "streams": if i == 0 { streams_arr.clone() } else { vec![] }
                }
            });
            state.broadcast_ws("scan", &pmt);
            if !sc.cluster_host.is_empty() {
                state.broadcast_cluster_ws(&sc.cluster_host, "scan", &pmt);
            }
        }
    }

    let tot = json!({
        "data": {
            "analyze": true,
            "total": {
                "bitrate": total_br,
                "cc_errors": cc_err,
                "pes_errors": pes_err,
                "scrambled": scrambled
            }
        }
    });
    state.broadcast_ws("scan", &tot);
    if !sc.cluster_host.is_empty() {
        state.broadcast_cluster_ws(&sc.cluster_host, "scan", &tot);
    }
}

fn encode_cluster_auth_part(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'!') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn build_cluster_auth_query(user: &str, pass: &str) -> Option<String> {
    if user.is_empty() {
        return None;
    }
    if pass.is_empty() {
        Some(format!("?auth={}", encode_cluster_auth_part(user)))
    } else {
        Some(format!(
            "?auth={}:{}",
            encode_cluster_auth_part(user),
            encode_cluster_auth_part(pass)
        ))
    }
}

fn detect_remote_hls_enabled(rcfg: &Value) -> bool {
    let Some(settings) = rcfg.get("settings").and_then(|v| v.as_object()) else {
        return true;
    };
    if settings.contains_key("http_play_hls") {
        return get_bool_field(rcfg.get("settings"), "http_play_hls", true);
    }
    // Cesbo Astra omits `http_play_hls` when only `http_play_stream: true` is enabled.
    if settings.contains_key("http_play_stream") {
        return false;
    }
    true
}

async fn sync_cluster_once(state: &Arc<AppState>) {
    let snap = state.config();
    let servers: Vec<Value> = snap
        .raw
        .get("servers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // Fetch all enabled cluster nodes concurrently so a slow/offline node never stalls others
    let mut futs = Vec::new();
    for srv in servers {
        if !srv.is_object() || !get_bool_field(Some(&srv), "enable", true) {
            continue;
        }
        let rhost = srv.get("host").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if rhost.is_empty() {
            continue;
        }
        let rport = get_u16(&srv, "port", 8000);
        let hp = format!("{}:{}", rhost, rport);
        let ruser = srv.get("user").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let rpass = srv.get("pass").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let auth_header = if !ruser.is_empty() {
            let cred = if rpass.is_empty() {
                ruser.clone()
            } else {
                format!("{}:{}", ruser, rpass)
            };
            Some(format!("Basic {}", B64.encode(cred)))
        } else {
            None
        };
        let auth_query = build_cluster_auth_query(&ruser, &rpass);
        let client = state.http_client.clone();
        futs.push(async move {
            let mut req = client
                .post(format!("http://{}/control/", hp))
                .header(USER_AGENT, "Astrika/2.1")
                .header(CONTENT_TYPE, "application/json")
                .body("{\"cmd\":\"load\"}");
            if let Some(ref ah) = auth_header {
                req = req.header(AUTHORIZATION, ah.as_str());
            }
            let Ok(Ok(resp)) = tokio::time::timeout(Duration::from_secs(4), req.send()).await else {
                return None;
            };
            if resp.status().as_u16() != 200 {
                return None;
            }
            let raw_bytes = resp.bytes().await.ok()?;
            let rcfg = serde_json::from_slice::<Value>(&raw_bytes).ok()?;
            Some((hp, auth_header, auth_query, rcfg))
        });
    }

    let results = futures_util::future::join_all(futs).await;

    let mut new_streams = HashMap::new();
    let mut new_aliases = HashMap::new();
    let mut new_plain = HashMap::new();

    for item in results.into_iter().flatten() {
        let (hp, auth_header, auth_query, rcfg) = item;
        let remote_hls_enabled = detect_remote_hls_enabled(&rcfg);
        let Some(rms) = rcfg.get("make_stream").and_then(|v| v.as_array()) else {
            continue;
        };

        for s in rms {
            if !s.is_object() || !get_bool_field(Some(s), "enable", true) {
                continue;
            }
            let orig_id = s.get("id").and_then(|v| v.as_str()).unwrap_or("");
            if orig_id.is_empty() {
                continue;
            }
            let eff_id = format!("cluster_{}_{}", hp.replace([':', '.'], "_"), orig_id);
            let mut proxied = s.clone();
            proxied["id"] = json!(eff_id);
            let display_play_url = format!("http://{}/play/{}", hp, orig_id);
            // Cesbo Astra rejects Basic auth on /play/{id} (403) and requires ?auth=user:pass;
            // passing both ?auth= and Authorization: Basic works with Cesbo Astra AND Astrika/astrag!
            let play_url = format!(
                "{}{}",
                display_play_url,
                auth_query.as_deref().unwrap_or("")
            );
            proxied["input"] = json!([display_play_url]);

            new_aliases.insert((hp.clone(), orig_id.to_string()), eff_id.clone());
            new_plain
                .entry(orig_id.to_string())
                .or_insert_with(|| eff_id.clone());

            let name = s.get("name").and_then(|v| v.as_str()).unwrap_or(orig_id);
            let needs_insert = match state.channels.get(&eff_id) {
                Some(existing) => {
                    existing.name != name
                        || existing.auth_header != auth_header
                        || existing.urls.first().map(|u| u.as_str()) != Some(play_url.as_str())
                }
                None => true,
            };
            if needs_insert {
                if let Some((_, old)) = state.channels.remove(&eff_id) {
                    old.shutdown();
                }
                let ch = Channel::new(
                    eff_id.clone(),
                    name.to_string(),
                    vec![play_url],
                    vec![],
                    snap.hls_seg_dur,
                    snap.hls_seg_keep,
                    false,
                    20.0,
                    true,
                    hp.clone(),
                    orig_id.to_string(),
                    auth_header.clone(),
                    state.http_client.clone(),
                    state.key_cache.clone(),
                    state.epoch,
                );
                state.channels.insert(eff_id.clone(), ch);
            }
            new_streams.insert(
                eff_id.clone(),
                ClusterStream {
                    eff_id,
                    orig_id: orig_id.to_string(),
                    host_port: hp.clone(),
                    auth_header: auth_header.clone(),
                    auth_query: auth_query.clone(),
                    remote_hls_enabled,
                    cfg: proxied,
                },
            );
        }
    }

    // Remove stale cluster channels
    let stale: Vec<String> = state
        .channels
        .iter()
        .filter(|e| e.value().is_cluster && !new_streams.contains_key(e.key()))
        .map(|e| e.key().clone())
        .collect();
    for sid in stale {
        if let Some((_, ch)) = state.channels.remove(&sid) {
            ch.shutdown();
        }
    }

    *state.cluster_streams.write() = new_streams;
    *state.cluster_aliases.write() = new_aliases;
    *state.cluster_plain_aliases.write() = new_plain;
    state.cluster_gen.fetch_add(1, Ordering::Relaxed);
    state.playlist_cache.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::default_cfg_obj;

    #[tokio::test]
    async fn cluster_control_blocks_unauthenticated_requests() {
        let mut cfg = default_cfg_obj(8000, "127.0.0.1");
        cfg["auth"]["enable"] = json!(true);
        let state = AppState::new(PathBuf::from("/tmp/astrika-test-unused.conf"), cfg);

        let resp = handle_cluster_control(
            &state,
            "10.0.0.5",
            None,
            None,
            "curl/8.0",
            false,
            None,
            Some("10.0.0.2:8000"),
            None,
            "",
            b"{\"cmd\":\"load\"}",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn health_and_static_etag_304() {
        let cfg = default_cfg_obj(8000, "127.0.0.1");
        let state = AppState::new(PathBuf::from("/tmp/astrika-test-unused2.conf"), cfg);
        let r1 = serve_static_gz(
            embed::INDEX_HTML_GZ,
            embed::index_plain,
            embed::index_etag(),
            "text/html",
            "no-cache",
            &[],
            true,
            None,
            false,
        );
        assert_eq!(r1.status(), StatusCode::OK);
        let r2 = serve_static_gz(
            embed::INDEX_HTML_GZ,
            embed::index_plain,
            embed::index_etag(),
            "text/html",
            "no-cache",
            &[],
            true,
            Some(embed::index_etag()),
            false,
        );
        assert_eq!(r2.status(), StatusCode::NOT_MODIFIED);
        state.shutdown_all();
    }

    #[test]
    fn http_output_routes_m3u8_and_plain_paths_correctly() {
        let routes = vec![
            crate::config::HttpOutputRoute {
                stream_id: "rferl".to_string(),
                port: 8000,
                path: "/curent/index.m3u8".to_string(),
            },
            crate::config::HttpOutputRoute {
                stream_id: "sport4".to_string(),
                port: 18000,
                path: "/sport4/index.m3u8".to_string(),
            },
            crate::config::HttpOutputRoute {
                stream_id: "ch666".to_string(),
                port: 18000,
                path: "/666/index.m3u8".to_string(),
            },
            crate::config::HttpOutputRoute {
                stream_id: "ch666".to_string(),
                port: 18000,
                path: "/666".to_string(),
            },
            crate::config::HttpOutputRoute {
                stream_id: "plain".to_string(),
                port: 8000,
                path: "/live/ch1".to_string(),
            },
        ];

        assert_eq!(
            match_http_output_routes(&routes, "/curent/index.m3u8", 8000),
            Some(("rferl".to_string(), 1, String::new()))
        );
        assert_eq!(
            match_http_output_routes(&routes, "/curent.m3u8", 8000),
            Some(("rferl".to_string(), 1, String::new()))
        );
        assert_eq!(
            match_http_output_routes(&routes, "/curent/segment/segment-3.ts", 8000),
            Some(("rferl".to_string(), 2, "segment-3.ts".to_string()))
        );
        assert_eq!(
            match_http_output_routes(&routes, "/curent", 8000),
            Some(("rferl".to_string(), 0, String::new()))
        );
        assert_eq!(
            match_http_output_routes(&routes, "/sport4/index.m3u8", 18000),
            Some(("sport4".to_string(), 1, String::new()))
        );
        assert_eq!(
            match_http_output_routes(&routes, "/666/index.m3u8", 18000),
            Some(("ch666".to_string(), 1, String::new()))
        );
        assert_eq!(
            match_http_output_routes(&routes, "/666", 18000),
            Some(("ch666".to_string(), 0, String::new()))
        );
        assert_eq!(
            match_http_output_routes(&routes, "/live/ch1", 8000),
            Some(("plain".to_string(), 0, String::new()))
        );
        assert_eq!(
            match_http_output_routes(&routes, "/live/ch1/index.m3u8", 8000),
            Some(("plain".to_string(), 1, String::new()))
        );
    }

    #[test]
    fn cluster_auth_query_and_remote_hls_detection() {
        assert_eq!(build_cluster_auth_query("", ""), None);
        assert_eq!(
            build_cluster_auth_query("admin", "pass123!"),
            Some("?auth=admin:pass123!".to_string())
        );
        assert_eq!(
            build_cluster_auth_query("admin", "p@ss#1"),
            Some("?auth=admin:p%40ss%231".to_string())
        );

        // Cesbo Astra with only http_play_stream: true
        let cesbo_ts_only = json!({"settings": {"http_play_stream": true}});
        assert!(!detect_remote_hls_enabled(&cesbo_ts_only));

        // Cesbo Astra / Astrika with http_play_hls: true
        let with_hls = json!({"settings": {"http_play_stream": true, "http_play_hls": true}});
        assert!(detect_remote_hls_enabled(&with_hls));

        // Explicit false
        let disabled_hls = json!({"settings": {"http_play_hls": false}});
        assert!(!detect_remote_hls_enabled(&disabled_hls));
    }
}
