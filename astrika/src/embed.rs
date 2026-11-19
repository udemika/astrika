use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::sync::OnceLock;

pub const INDEX_HTML_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/index.html.gz"));
pub const MOD_JS_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/mod.js.gz"));
pub const ACCOUNT_HTML_GZ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/account.html.gz"));
pub const FAVICON_PNG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/favicon.png"));

static INDEX_PLAIN: OnceLock<Vec<u8>> = OnceLock::new();
static MOD_PLAIN: OnceLock<Vec<u8>> = OnceLock::new();
static ACCOUNT_PLAIN: OnceLock<Vec<u8>> = OnceLock::new();

static INDEX_ETAG: OnceLock<String> = OnceLock::new();
static MOD_ETAG: OnceLock<String> = OnceLock::new();
static ACCOUNT_ETAG: OnceLock<String> = OnceLock::new();
static FAVICON_ETAG: OnceLock<String> = OnceLock::new();

fn compute_etag(data: &[u8]) -> String {
    let h = Sha256::digest(data);
    format!("\"{}\"", hex::encode(&h[..8]))
}

fn gunzip(gz: &[u8]) -> Vec<u8> {
    let mut dec = GzDecoder::new(gz);
    let mut out = Vec::with_capacity(gz.len() * 3);
    let _ = dec.read_to_end(&mut out);
    out
}

pub fn index_plain() -> &'static [u8] {
    INDEX_PLAIN.get_or_init(|| gunzip(INDEX_HTML_GZ))
}

pub fn mod_plain() -> &'static [u8] {
    MOD_PLAIN.get_or_init(|| gunzip(MOD_JS_GZ))
}

pub fn account_plain() -> &'static [u8] {
    ACCOUNT_PLAIN.get_or_init(|| gunzip(ACCOUNT_HTML_GZ))
}

pub fn index_etag() -> &'static str {
    INDEX_ETAG.get_or_init(|| compute_etag(INDEX_HTML_GZ))
}

pub fn mod_etag() -> &'static str {
    MOD_ETAG.get_or_init(|| compute_etag(MOD_JS_GZ))
}

pub fn account_etag() -> &'static str {
    ACCOUNT_ETAG.get_or_init(|| compute_etag(ACCOUNT_HTML_GZ))
}

pub fn favicon_etag() -> &'static str {
    FAVICON_ETAG.get_or_init(|| compute_etag(FAVICON_PNG))
}
