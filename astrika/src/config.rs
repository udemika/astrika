use crate::auth::parse_string_list;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub struct UserRecord {
    pub enabled: bool,
    pub password: String,
    pub token: String,
    pub is_admin: bool,
    pub expire: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct HttpOutputRoute {
    pub stream_id: String,
    pub port: u16,
    pub path: String,
}

/// Pre-indexed immutable snapshot of the configuration for O(1) hot-path lookups.
#[derive(Clone, Debug)]
pub struct ConfigSnapshot {
    pub generation: u64,
    pub raw: Value,
    pub host: String,
    pub port: u16,
    pub auth_enabled: bool,
    pub auth_x_real_ip: bool,
    pub ip_allow: Vec<String>,
    pub ip_deny: Vec<String>,
    pub token_deny: HashSet<String>,
    pub users_index: HashMap<String, UserRecord>,
    pub token_index: HashMap<String, String>,
    pub streams_index: HashMap<String, Value>,
    pub http_outputs: Vec<HttpOutputRoute>,
    pub extra_ports: Vec<u16>,
    pub hls_seg_dur: f64,
    pub hls_seg_keep: usize,
    pub playlist_name: String,
    pub m3u_header: String,
    pub playlist_arrange: String,
    pub xspf_title: String,
    pub http_play_hls: bool,
    pub http_play_stream: bool,
}

impl ConfigSnapshot {
    pub fn from_value(raw: Value, generation: u64) -> Self {
        let host = raw
            .get("host")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("0.0.0.0")
            .to_string();
        let port = get_u16(&raw, "port", 8000);

        let auth = raw.get("auth");
        let auth_enabled = get_bool_field(auth, "enable", false);
        let auth_x_real_ip = get_bool_field(auth, "x_real_ip", false);
        let ip_allow = parse_string_list(auth.and_then(|a| a.get("http_ip_allow")));
        let ip_deny = parse_string_list(auth.and_then(|a| a.get("http_ip_deny")));
        let token_deny: HashSet<String> =
            parse_string_list(auth.and_then(|a| a.get("http_token_deny")))
                .into_iter()
                .collect();

        let mut users_index = HashMap::new();
        let mut token_index = HashMap::new();
        if let Some(users) = raw.get("users").and_then(|u| u.as_object()) {
            for (login, u) in users {
                if !u.is_object() {
                    continue;
                }
                let enabled = get_bool_field(Some(u), "enable", true);
                let password = u
                    .get("password")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let token = u
                    .get("token")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let role = u.get("role").and_then(|v| v.as_str()).unwrap_or("");
                let utype_admin = match u.get("type") {
                    Some(Value::Number(n)) => n.as_i64() == Some(1),
                    Some(Value::String(s)) => s == "1",
                    _ => false,
                };
                let is_admin = role == "admin" || utype_admin;
                let expire = u.get("expire").and_then(|v| v.as_f64());

                if enabled {
                    if !token.is_empty() {
                        token_index.entry(token.clone()).or_insert_with(|| login.clone());
                    }
                    // Plaintext password can also match token if not pbkdf2
                    if !password.is_empty() && !password.starts_with("pbkdf2_sha256$") {
                        token_index
                            .entry(password.clone())
                            .or_insert_with(|| login.clone());
                    }
                }
                users_index.insert(
                    login.clone(),
                    UserRecord {
                        enabled,
                        password,
                        token,
                        is_admin,
                        expire,
                    },
                );
            }
        }

        let mut streams_index = HashMap::new();
        let mut http_outputs = Vec::new();
        let mut extra_ports_set = HashSet::new();

        if let Some(ms) = raw.get("make_stream").and_then(|m| m.as_array()) {
            for s in ms {
                if !s.is_object() {
                    continue;
                }
                let sid = s.get("id").and_then(|v| v.as_str()).unwrap_or("");
                if sid.is_empty() {
                    continue;
                }
                streams_index.insert(sid.to_string(), s.clone());

                if get_bool_field(Some(s), "enable", true) {
                    if let Some(outs) = s.get("output").and_then(|o| o.as_array()) {
                        for o in outs {
                            if let Some(u) = o.as_str() {
                                if let Some((oport, opath)) = parse_http_output_url(u, port) {
                                    if oport != port {
                                        extra_ports_set.insert(oport);
                                    }
                                    http_outputs.push(HttpOutputRoute {
                                        stream_id: sid.to_string(),
                                        port: oport,
                                        path: opath,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        let settings = raw.get("settings");
        let hls = raw.get("hls");
        let hls_seg_dur = hls
            .and_then(|h| h.get("duration"))
            .or_else(|| settings.and_then(|s| s.get("hls_duration")))
            .and_then(val_as_f64)
            .unwrap_or(2.0)
            .clamp(1.0, 10.0);
        let hls_seg_keep = hls
            .and_then(|h| h.get("quantity"))
            .or_else(|| settings.and_then(|s| s.get("hls_quantity")))
            .and_then(val_as_f64)
            .unwrap_or(5.0)
            .clamp(2.0, 12.0) as usize;

        let playlist_name = settings
            .and_then(|s| s.get("http_play_playlist_name"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("playlist")
            .to_string();
        let m3u_header = settings
            .and_then(|s| s.get("http_play_m3u_header"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let playlist_arrange = settings
            .and_then(|s| s.get("playlist_arrange"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let xspf_title = settings
            .and_then(|s| s.get("http_play_xspf_title"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("Astrika IPTV Playlist")
            .to_string();
        let http_play_hls = get_bool_field(settings, "http_play_hls", false);
        let http_play_stream = get_bool_field(settings, "http_play_stream", true);

        let mut extra_ports: Vec<u16> = extra_ports_set.into_iter().collect();
        extra_ports.sort_unstable();

        Self {
            generation,
            raw,
            host,
            port,
            auth_enabled,
            auth_x_real_ip,
            ip_allow,
            ip_deny,
            token_deny,
            users_index,
            token_index,
            streams_index,
            http_outputs,
            extra_ports,
            hls_seg_dur,
            hls_seg_keep,
            playlist_name,
            m3u_header,
            playlist_arrange,
            xspf_title,
            http_play_hls,
            http_play_stream,
        }
    }
}

pub fn val_as_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

pub fn get_u16(v: &Value, key: &str, def: u16) -> u16 {
    match v.get(key) {
        Some(Value::Number(n)) => n
            .as_u64()
            .filter(|&p| (1..=65535).contains(&p))
            .map(|p| p as u16)
            .unwrap_or(def),
        Some(Value::String(s)) => s
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|&p| p > 0)
            .unwrap_or(def),
        _ => def,
    }
}

pub fn get_bool_field(v: Option<&Value>, key: &str, def: bool) -> bool {
    let Some(val) = v.and_then(|o| o.get(key)) else {
        return def;
    };
    match val {
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_i64().map(|x| x != 0).unwrap_or(def),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => def,
        },
        _ => def,
    }
}

pub fn parse_http_output_url(raw: &str, default_port: u16) -> Option<(u16, String)> {
    let stripped = raw.split('#').next().unwrap_or(raw).trim();
    if !stripped.starts_with("http://") && !stripped.starts_with("https://") {
        return None;
    }
    let parsed = url::Url::parse(stripped).ok()?;
    let port = parsed.port().unwrap_or(default_port);
    let mut path = parsed.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    Some((port, path))
}

pub fn default_cfg_obj(port: u16, host: &str) -> Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    json!({
        "port": port,
        "host": if host.is_empty() { "0.0.0.0" } else { host },
        "gid": 466560,
        "auth": { "enable": false },
        "users": {
            "admin": {
                "type": 1,
                "role": "admin",
                "enable": true,
                "password": "admin",
                "created": now
            }
        },
        "make_stream": [],
        "categories": [],
        "servers": [],
        "softcam": [],
        "cas": [],
        "dvb_tune": [],
        "settings": {},
        "hls": {}
    })
}

#[allow(dead_code)]
pub fn order_init_cfg(src: Option<&Value>, port: u16) -> Value {
    let mut ord = default_cfg_obj(port, "0.0.0.0");
    if let (Some(src_obj), Some(dst_obj)) = (src.and_then(|v| v.as_object()), ord.as_object_mut()) {
        for (k, v) in src_obj {
            if k == "control_port" {
                continue;
            }
            dst_obj.insert(k.clone(), v.clone());
        }
        dst_obj.insert("port".to_string(), json!(port));
    }
    ord
}

pub fn validate_url(raw: &str, is_output: bool) -> Result<String, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("URL cannot be empty".to_string());
    }
    if s.len() > 4000 {
        return Err("URL too long".to_string());
    }
    let low = s.to_ascii_lowercase();
    let allowed = if is_output {
        low.starts_with("http://")
            || low.starts_with("https://")
            || low.starts_with("udp://")
            || low.starts_with("rtp://")
    } else {
        low.starts_with("http://")
            || low.starts_with("https://")
            || low.starts_with("udp://")
            || low.starts_with("rtp://")
            || low.starts_with("hls://")
    };
    if !allowed {
        return Err(format!("Unsupported URL scheme: {}", s));
    }
    Ok(s.to_string())
}

pub fn validate_config(raw: &Value) -> Result<Value, String> {
    let Some(obj) = raw.as_object() else {
        return Err("Configuration must be a JSON object".to_string());
    };
    let mut out = obj.clone();

    let port = get_u16(raw, "port", 8000);
    out.insert("port".to_string(), json!(port));
    let host = raw
        .get("host")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("0.0.0.0")
        .to_string();
    out.insert("host".to_string(), json!(host));

    if !out.contains_key("gid") {
        out.insert("gid".to_string(), json!(466560));
    }
    if !out.get("auth").is_some_and(|v| v.is_object()) {
        out.insert("auth".to_string(), json!({ "enable": false }));
    }
    if !out.get("users").is_some_and(|v| v.is_object()) {
        let def = default_cfg_obj(port, &host);
        out.insert("users".to_string(), def["users"].clone());
    }

    for arr_key in ["make_stream", "categories", "servers", "softcam", "cas", "dvb_tune"] {
        if !out.get(arr_key).is_some_and(|v| v.is_array()) {
            out.insert(arr_key.to_string(), json!([]));
        }
    }
    for obj_key in ["settings", "hls"] {
        if !out.get(obj_key).is_some_and(|v| v.is_object()) {
            out.insert(obj_key.to_string(), json!({}));
        }
    }

    // Validate streams
    if let Some(Value::Array(streams)) = out.get_mut("make_stream") {
        for s in streams.iter_mut() {
            let Some(so) = s.as_object_mut() else {
                return Err("Each stream must be an object".to_string());
            };
            if let Some(Value::Array(ins)) = so.get_mut("input") {
                for u in ins.iter_mut() {
                    if let Some(us) = u.as_str() {
                        let clean = validate_url(us, false)?;
                        *u = Value::String(clean);
                    }
                }
            }
            if let Some(Value::Array(outs)) = so.get_mut("output") {
                for u in outs.iter_mut() {
                    if let Some(us) = u.as_str() {
                        let clean = validate_url(us, true)?;
                        *u = Value::String(clean);
                    }
                }
            }
        }
    }

    Ok(Value::Object(out))
}

fn is_secret_key(k: &str) -> bool {
    matches!(
        k.to_ascii_lowercase().as_str(),
        "password" | "pass" | "token" | "secret" | "key"
    )
}

pub fn strip_url_creds(raw: &str) -> String {
    if let Ok(mut u) = url::Url::parse(raw) {
        if !u.username().is_empty() || u.password().is_some() {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            return u.to_string();
        }
    }
    raw.to_string()
}

pub fn redact_val(v: &Value, strip_urls: bool) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, val) in map {
                if is_secret_key(k) {
                    out.insert(k.clone(), Value::String(String::new()));
                } else {
                    out.insert(k.clone(), redact_val(val, strip_urls));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => {
            Value::Array(arr.iter().map(|x| redact_val(x, strip_urls)).collect())
        }
        Value::String(s) if strip_urls && (s.contains("://") && s.contains('@')) => {
            Value::String(strip_url_creds(s))
        }
        other => other.clone(),
    }
}

pub fn resolve_default_config_path(cli_path: Option<&str>) -> PathBuf {
    if let Some(p) = cli_path.filter(|s| !s.is_empty()) {
        return PathBuf::from(p);
    }
    if let Ok(env_p) = std::env::var("ASTRIKA_CONFIG_FILE") {
        if !env_p.is_empty() {
            return PathBuf::from(env_p);
        }
    }
    if let Ok(env_p) = std::env::var("ASTRA_CONFIG_FILE") {
        if !env_p.is_empty() {
            return PathBuf::from(env_p);
        }
    }
    if Path::new("/etc/astrika/astrika.conf").exists() {
        return PathBuf::from("/etc/astrika/astrika.conf");
    }
    if Path::new("/etc/astrag/astrag.conf").exists() {
        return PathBuf::from("/etc/astrag/astrag.conf");
    }
    PathBuf::from("/etc/astrika/astrika.conf")
}

pub fn load_json_obj_or_cfg(path: &Path) -> Option<Value> {
    let raw = fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();
    if !trimmed.starts_with('{') {
        return None;
    }
    let val: Value = serde_json::from_str(trimmed).ok()?;
    if !val.is_object() {
        return None;
    }
    if let Some(sub) = val.get("config").filter(|v| v.is_object()) {
        return Some(sub.clone());
    }
    Some(val)
}

pub fn load_disk_config(path: &Path, cli_host: Option<&str>, cli_port: u16) -> Result<Value, String> {
    let loaded = load_json_obj_or_cfg(path).unwrap_or_else(|| {
        default_cfg_obj(
            if cli_port > 0 { cli_port } else { 8000 },
            cli_host.unwrap_or("0.0.0.0"),
        )
    });
    let mut cfg = validate_config(&loaded)?;
    if let Some(obj) = cfg.as_object_mut() {
        if let Some(h) = cli_host.filter(|s| !s.is_empty()) {
            obj.insert("host".to_string(), json!(h));
        }
        if cli_port > 0 {
            obj.insert("port".to_string(), json!(cli_port));
        }
    }
    Ok(cfg)
}

pub fn atomic_write_file_sync(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let tmp = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(mode));
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Non-blocking atomic config persistence via blocking thread pool (never stalls streaming I/O).
pub async fn atomic_save_config_async(path: PathBuf, cfg: Value) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let mut bytes = serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        atomic_write_file_sync(&path, &bytes, 0o640).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("save task join error: {}", e))?
}

pub fn stream_keep_active(s: &Value) -> (bool, f64) {
    let mut ka = get_bool_field(Some(s), "keep_active", false);
    let mut idle = s
        .get("idle_delay")
        .and_then(val_as_f64)
        .filter(|&d| (5.0..=3600.0).contains(&d))
        .unwrap_or(20.0);

    // UDP/RTP output forces keep_active
    if let Some(outs) = s.get("output").and_then(|o| o.as_array()) {
        for o in outs {
            if let Some(u) = o.as_str() {
                let low = u.trim().to_ascii_lowercase();
                if low.starts_with("udp://") || low.starts_with("rtp://") {
                    ka = true;
                }
            }
        }
    }
    if let Some(ins) = s.get("input").and_then(|i| i.as_array()) {
        for inp in ins {
            if let Some(u) = inp.as_str() {
                if let Some((_, frag)) = u.split_once('#') {
                    for part in frag.split('&') {
                        if part == "keep_active" {
                            ka = true;
                        } else if let Some(v) = part.strip_prefix("idle_delay=") {
                            if let Ok(d) = v.parse::<f64>() {
                                if (5.0..=3600.0).contains(&d) {
                                    idle = d;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    (ka, idle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_o1_indexes_and_redacts_secrets() {
        let cfg = json!({
            "port": 8080,
            "host": "0.0.0.0",
            "auth": { "enable": true, "http_ip_allow": ["127.0.0.1"] },
            "users": {
                "admin": { "role": "admin", "enable": true, "password": "secret", "token": "tok123" }
            },
            "make_stream": [
                {
                    "id": "ch1",
                    "name": "Channel 1",
                    "enable": true,
                    "input": ["http://user:pass@10.0.0.1/live.m3u8"],
                    "output": ["http://0.0.0.0:9000/custom/ch1"]
                }
            ]
        });
        let validated = validate_config(&cfg).unwrap();
        let snap = ConfigSnapshot::from_value(validated.clone(), 1);
        assert_eq!(snap.port, 8080);
        assert!(snap.auth_enabled);
        assert_eq!(snap.token_index.get("tok123").map(|s| s.as_str()), Some("admin"));
        assert!(snap.streams_index.contains_key("ch1"));
        assert_eq!(snap.extra_ports, vec![9000]);

        let red = redact_val(&validated, true);
        assert_eq!(red["users"]["admin"]["password"], "");
        assert!(!red["make_stream"][0]["input"][0]
            .as_str()
            .unwrap()
            .contains("user:pass"));
    }
}
