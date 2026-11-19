use aes::Aes128;
use bytes::Bytes;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use dashmap::DashMap;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

type Aes128CbcDec = cbc::Decryptor<Aes128>;

const KEY_CACHE_MAX: usize = 256;
const KEY_CACHE_TTL: Duration = Duration::from_secs(1800);

#[derive(Clone)]
struct CachedKey {
    key: [u8; 16],
    expires_at: Instant,
}

/// Shared bounded AES-128 key cache across all channels (survives reconnects and IN_IDLE).
#[derive(Clone, Default)]
pub struct AesKeyCache {
    map: Arc<DashMap<String, CachedKey>>,
}

impl AesKeyCache {
    pub fn new() -> Self {
        Self {
            map: Arc::new(DashMap::with_capacity(32)),
        }
    }

    pub fn get(&self, url: &str) -> Option<[u8; 16]> {
        let now = Instant::now();
        if let Some(e) = self.map.get(url) {
            if now < e.expires_at {
                return Some(e.key);
            }
        }
        None
    }

    pub fn insert(&self, url: String, key: [u8; 16]) {
        let now = Instant::now();
        if self.map.len() >= KEY_CACHE_MAX {
            self.map.retain(|_, v| now < v.expires_at);
            if self.map.len() >= KEY_CACHE_MAX {
                self.map.clear();
            }
        }
        self.map.insert(
            url,
            CachedKey {
                key,
                expires_at: now + KEY_CACHE_TTL,
            },
        );
    }
}

#[derive(Clone, Debug)]
pub struct HlsSegment {
    pub url: String,
    pub dur: f64,
    pub seq: i64,
    pub key_url: Option<String>,
    pub iv: Option<[u8; 16]>,
    pub byterange: Option<(u64, u64)>,
    pub discontinuity: bool,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum ParsedPlaylist {
    Master {
        best_uri: String,
        bandwidth: u64,
    },
    Media {
        target_duration: f64,
        media_sequence: i64,
        has_media_sequence: bool,
        segments: Vec<HlsSegment>,
    },
}

/// Resolve a relative or absolute URI against a base URL.
pub fn resolve_url(base: &str, reference: &str) -> String {
    let r = reference.trim();
    if r.starts_with("http://") || r.starts_with("https://") {
        return r.to_string();
    }
    if let Ok(b) = Url::parse(base) {
        if let Ok(joined) = b.join(r) {
            return joined.into();
        }
    }
    r.to_string()
}

/// Zero-copy attribute extractor for HLS tag lines like `METHOD=AES-128,URI="https://...",IV=0x...`.
pub fn attr_get<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let bytes = line.as_bytes();
    let nlen = name.len();
    let mut i = 0usize;
    while i + nlen < bytes.len() {
        let boundary_ok = i == 0 || matches!(bytes[i - 1], b',' | b':' | b' ');
        if boundary_ok
            && bytes[i..i + nlen].eq_ignore_ascii_case(name.as_bytes())
            && bytes[i + nlen] == b'='
        {
            let rest = &line[i + nlen + 1..];
            if let Some(quoted) = rest.strip_prefix('"') {
                let end = quoted.find('"').unwrap_or(quoted.len());
                return Some(&quoted[..end]);
            } else {
                let end = rest
                    .find(|c| c == ',' || c == '\r' || c == '\n')
                    .unwrap_or(rest.len());
                return Some(rest[..end].trim());
            }
        }
        i += 1;
    }
    None
}

fn parse_hex_iv(s: &str) -> Option<[u8; 16]> {
    let hex_part = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    if hex_part.len() < 32 {
        return None;
    }
    let bytes = hex::decode(&hex_part[..32]).ok()?;
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&bytes);
    Some(iv)
}

/// Single-pass zero-copy M3U8 parser (supports Master & Media playlists, AES-128, BYTERANGE, DISCONTINUITY).
pub fn parse_m3u8(text: &str, base_url: &str) -> Result<ParsedPlaylist, String> {
    let clean = text.trim_start_matches(['\u{FEFF}', ' ', '\t', '\r', '\n']);
    if !clean.starts_with("#EXTM3U") {
        return Err("not an M3U8 playlist".to_string());
    }

    if clean.contains("#EXT-X-STREAM-INF") {
        let mut best_bw: i64 = -1;
        let mut best_uri: Option<&str> = None;
        let mut pending = false;
        let mut cur_bw: i64 = 0;

        for raw_line in clean.lines() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with("#EXT-X-STREAM-INF") {
                cur_bw = attr_get(line, "BANDWIDTH")
                    .and_then(|v| v.parse::<i64>().ok())
                    .unwrap_or(0);
                pending = true;
            } else if pending && !line.starts_with('#') {
                if cur_bw > best_bw {
                    best_bw = cur_bw;
                    best_uri = Some(line);
                }
                pending = false;
            }
        }
        let Some(uri) = best_uri else {
            return Err("master playlist without variants".to_string());
        };
        return Ok(ParsedPlaylist::Master {
            best_uri: resolve_url(base_url, uri),
            bandwidth: best_bw.max(0) as u64,
        });
    }

    let mut td = 0.0f64;
    let mut mseq = 0i64;
    let mut has_mseq = false;
    let mut cur_dur = -1.0f64;
    let mut cur_key: Option<String> = None;
    let mut cur_iv: Option<[u8; 16]> = None;
    let mut cur_br: Option<(u64, u64)> = None;
    let mut next_br_offset = 0u64;
    let mut cur_disc = false;
    let mut segments = Vec::with_capacity(16);
    let mut idx = 0i64;

    for raw_line in clean.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('#') {
            if let Some(v) = rest.strip_prefix("EXT-X-TARGETDURATION:") {
                if let Ok(d) = v.trim().parse::<f64>() {
                    td = d;
                }
            } else if let Some(v) = rest.strip_prefix("EXT-X-MEDIA-SEQUENCE:") {
                if let Ok(seq) = v.trim().parse::<i64>() {
                    mseq = seq;
                    has_mseq = true;
                }
            } else if let Some(v) = rest.strip_prefix("EXTINF:") {
                let num = v.split(',').next().unwrap_or(v).trim();
                if let Ok(d) = num.parse::<f64>() {
                    cur_dur = d;
                }
            } else if rest.starts_with("EXT-X-DISCONTINUITY") && !rest.starts_with("EXT-X-DISCONTINUITY-SEQUENCE") {
                cur_disc = true;
            } else if let Some(v) = rest.strip_prefix("EXT-X-BYTERANGE:") {
                let mut parts = v.trim().split('@');
                if let Some(len_s) = parts.next() {
                    if let Ok(len) = len_s.parse::<u64>() {
                        let off = parts
                            .next()
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(next_br_offset);
                        cur_br = Some((off, len));
                        next_br_offset = off + len;
                    }
                }
            } else if rest.starts_with("EXT-X-KEY:") {
                let method = attr_get(line, "METHOD").unwrap_or("");
                if method.eq_ignore_ascii_case("AES-128") {
                    if let Some(uri) = attr_get(line, "URI") {
                        cur_key = Some(resolve_url(base_url, uri));
                        cur_iv = attr_get(line, "IV").and_then(parse_hex_iv);
                    } else {
                        cur_key = None;
                        cur_iv = None;
                    }
                } else {
                    cur_key = None;
                    cur_iv = None;
                }
            }
            continue;
        }

        let seq = mseq + idx;
        idx += 1;
        segments.push(HlsSegment {
            url: resolve_url(base_url, line),
            dur: if cur_dur > 0.0 { cur_dur } else { td },
            seq,
            key_url: cur_key.clone(),
            iv: cur_iv,
            byterange: cur_br.take(),
            discontinuity: std::mem::take(&mut cur_disc),
        });
        cur_dur = -1.0;
    }

    Ok(ParsedPlaylist::Media {
        target_duration: td,
        media_sequence: mseq,
        has_media_sequence: has_mseq,
        segments,
    })
}

/// FNV-1a 64-bit segment deduplication key ignoring volatile auth query parameters.
pub fn seg_dedup_key(url: &str) -> u64 {
    fn fnv(bytes: &[u8]) -> u64 {
        let mut h = 14695981039346656037u64;
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(1099511628211);
        }
        h
    }
    const DROP: &[&str] = &[
        "token",
        "md5",
        "auth",
        "wmsauthsign",
        "expires",
        "vtoken",
        "signature",
        "hash",
        "key",
    ];
    let Some((base, query)) = url.split_once('?') else {
        return fnv(url.as_bytes());
    };
    if base.len() >= 3 && base[base.len() - 3..].eq_ignore_ascii_case(".ts") {
        return fnv(base.as_bytes());
    }
    let mut h = fnv(base.as_bytes());
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let k = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
        if !DROP.iter().any(|d| d.eq_ignore_ascii_case(k)) {
            h ^= fnv(pair.as_bytes()).wrapping_mul(31);
        }
    }
    h
}

/// Bounded O(1) deduplication ring set for HLS segments without MEDIA-SEQUENCE.
pub struct SeenSet {
    set: HashSet<u64>,
    order: VecDeque<u64>,
    cap: usize,
}

impl SeenSet {
    pub fn new(cap: usize) -> Self {
        Self {
            set: HashSet::with_capacity(cap),
            order: VecDeque::with_capacity(cap),
            cap,
        }
    }

    pub fn contains(&self, k: u64) -> bool {
        self.set.contains(&k)
    }

    pub fn insert(&mut self, k: u64) {
        if self.set.insert(k) {
            self.order.push_back(k);
            if self.order.len() > self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }
}

/// Decrypt AES-128-CBC HLS segment payload.
pub fn decrypt_aes128(data: &[u8], key: &[u8; 16], iv: Option<[u8; 16]>, seq: i64) -> Result<Bytes, String> {
    if data.is_empty() || data.len() % 16 != 0 {
        return Err("invalid AES-128 ciphertext length".to_string());
    }
    let iv_bytes = iv.unwrap_or_else(|| {
        let mut out = [0u8; 16];
        out[8..16].copy_from_slice(&(seq as u64).to_be_bytes());
        out
    });
    let mut buf = data.to_vec();
    let dec = Aes128CbcDec::new(key.into(), &iv_bytes.into());
    let pt_len = dec
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| "AES-128 PKCS7 decrypt failed".to_string())?
        .len();
    buf.truncate(pt_len);
    Ok(Bytes::from(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};

    #[test]
    fn parses_master_and_picks_highest_bandwidth() {
        let m3u = "#EXTM3U\n\
            #EXT-X-STREAM-INF:BANDWIDTH=800000,RESOLUTION=640x360\n\
            low/index.m3u8\n\
            #EXT-X-STREAM-INF:BANDWIDTH=3500000,RESOLUTION=1920x1080\n\
            hd/index.m3u8\n";
        let parsed = parse_m3u8(m3u, "https://cdn.example.com/live/master.m3u8").unwrap();
        match parsed {
            ParsedPlaylist::Master { best_uri, bandwidth } => {
                assert_eq!(bandwidth, 3500000);
                assert_eq!(best_uri, "https://cdn.example.com/live/hd/index.m3u8");
            }
            _ => panic!("expected master playlist"),
        }
    }

    #[test]
    fn parses_media_playlist_with_aes_key_and_byterange() {
        let m3u = "\u{FEFF}#EXTM3U\n\
            #EXT-X-TARGETDURATION:4\n\
            #EXT-X-MEDIA-SEQUENCE:100\n\
            #EXT-X-KEY:METHOD=AES-128,URI=\"key.bin\",IV=0x000102030405060708090a0b0c0d0e0f\n\
            #EXTINF:4.000,\n\
            #EXT-X-BYTERANGE:1000@0\n\
            seg100.ts\n\
            #EXT-X-DISCONTINUITY\n\
            #EXTINF:3.500,\n\
            seg101.ts\n";
        let parsed = parse_m3u8(m3u, "https://cdn.example.com/hd/index.m3u8").unwrap();
        match parsed {
            ParsedPlaylist::Media {
                target_duration,
                media_sequence,
                has_media_sequence,
                segments,
            } => {
                assert_eq!(target_duration, 4.0);
                assert_eq!(media_sequence, 100);
                assert!(has_media_sequence);
                assert_eq!(segments.len(), 2);
                assert_eq!(segments[0].url, "https://cdn.example.com/hd/seg100.ts");
                assert_eq!(
                    segments[0].key_url.as_deref(),
                    Some("https://cdn.example.com/hd/key.bin")
                );
                assert_eq!(segments[0].byterange, Some((0, 1000)));
                assert!(!segments[0].discontinuity);
                assert!(segments[1].discontinuity);
                assert_eq!(segments[1].seq, 101);
            }
            _ => panic!("expected media playlist"),
        }
    }

    #[test]
    fn aes128_cbc_roundtrip() {
        type Aes128CbcEnc = cbc::Encryptor<Aes128>;
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let plain = b"MPEG-TS payload bytes for testing AES-128 decryption!";
        let mut buf = vec![0u8; plain.len() + 16];
        buf[..plain.len()].copy_from_slice(plain);
        let ct_len = Aes128CbcEnc::new(&key.into(), &iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plain.len())
            .unwrap()
            .len();
        buf.truncate(ct_len);

        let dec = decrypt_aes128(&buf, &key, Some(iv), 0).unwrap();
        assert_eq!(&dec[..], plain);
    }

    #[test]
    fn seg_dedup_ignores_volatile_tokens() {
        let u1 = "https://cdn.test/live/seg1.ts?token=abc&expires=111";
        let u2 = "https://cdn.test/live/seg1.ts?token=xyz&expires=222";
        assert_eq!(seg_dedup_key(u1), seg_dedup_key(u2));
    }
}
