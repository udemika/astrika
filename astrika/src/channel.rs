use crate::hls_in::{
    decrypt_aes128, parse_m3u8, seg_dedup_key, AesKeyCache, HlsSegment, ParsedPlaylist, SeenSet,
};
use crate::ts::{KeyframeHit, TsEngine, PCR_HZ, PCR_WRAP, START_BURST_S, TS};
use bytes::Bytes;
use dashmap::DashMap;
use futures_util::StreamExt;
use parking_lot::Mutex;
use reqwest::header::{
    HeaderMap, HeaderValue, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, RANGE,
    USER_AGENT,
};
use reqwest::Client;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InputMode {
    Idle,
    Wait,
    Ts,
    Hls,
    Udp,
}

#[derive(Clone)]
pub struct OutSeg {
    pub seq: i64,
    pub dur: f64,
    pub disc: bool,
    pub data: Arc<Bytes>,
}

#[derive(Clone)]
pub struct ActiveSession {
    pub id: u64,
    pub channel_id: String,
    pub channel_name: String,
    pub addr: String,
    pub login: String,
    pub ua: String,
    pub start_wall: i64,
    pub sdate_ms: i64,
    pub cancel: Arc<Notify>,
}

struct UdpOut {
    sock: std::net::UdpSocket,
    addr: SocketAddrV4,
    buf: [u8; 7 * TS],
    n: usize,
}

impl UdpOut {
    fn push(&mut self, pkt: &[u8]) {
        let off = self.n * TS;
        self.buf[off..off + TS].copy_from_slice(pkt);
        self.n += 1;
        if self.n >= 7 {
            let _ = self.sock.send_to(&self.buf[..self.n * TS], self.addr);
            self.n = 0;
        }
    }

    fn flush(&mut self) {
        if self.n > 0 {
            let _ = self.sock.send_to(&self.buf[..self.n * TS], self.addr);
            self.n = 0;
        }
    }
}

pub struct ChannelInner {
    pub ts: TsEngine,
    pub mode: InputMode,
    pub cur_url: usize,
    pub fails_row: usize,
    pub in_started: f64,
    pub last_data: f64,
    pub last_client_act: f64,
    pub hls_last_req: f64,
    pub last_error: String,
    pub input_errors: u64,
    pub bitrate: f64,
    pub win_start: f64,
    pub next_resize: f64,
    pub prev_cc_stat: u64,
    pub prev_pes_stat: u64,
    pub was_active_ws: bool,
    pub idle_reported: bool,

    // Cached resolved HLS variant across IN_IDLE sleep/wake
    pub cached_variant: Option<(String, Instant)>,

    // HLS output (double-buffered Arc<Bytes> segments)
    pub hls_on: bool,
    pub cur_started: bool,
    pub cur_disc: bool,
    pub disc_pending: bool,
    pub cur_t0_wall: f64,
    pub cur_t0_pcr: i64,
    pub cseg: Vec<u8>,
    pub segs: VecDeque<OutSeg>,
    pub next_seq: i64,
    pub playlist_etag: String,

    // Reusable scratch buffers (zero heap churn per chunk)
    scratch_pkts: Vec<u8>,
    scratch_kfs: Vec<KeyframeHit>,

    // UDP outputs
    udp_outs: Vec<UdpOut>,

    // Active input task handle
    input_task: Option<JoinHandle<()>>,
}

pub struct Channel {
    pub id: String,
    pub name: String,
    pub urls: Vec<String>,
    pub udp_out_specs: Vec<String>,
    pub seg_target: f64,
    pub seg_keep: usize,
    pub keep_active: bool,
    pub idle_delay: f64,
    pub is_cluster: bool,
    pub cluster_host: String,
    pub cluster_orig_id: String,
    pub auth_header: Option<String>,

    pub nclients: AtomicUsize,
    pub nwaiters: AtomicUsize,
    pub alive: AtomicBool,
    pub data_notify: Arc<Notify>,
    pub seg_notify: Arc<Notify>,
    pub inner: Mutex<ChannelInner>,

    pub http_client: Client,
    pub key_cache: AesKeyCache,
    pub epoch: Instant,
}

#[derive(Clone, Debug)]
pub struct ChannelStatsSnapshot {
    pub id: String,
    pub is_cluster: bool,
    pub cluster_host: String,
    pub cluster_orig_id: String,
    pub idle: bool,
    pub bitrate_kbps: i64,
    pub onair: bool,
    pub cc_err: u64,
    pub pes_err: u64,
    pub cc_delta: u64,
    pub pes_delta: u64,
    pub scrambled: bool,
    pub input_id: usize,
    pub packets: u64,
    pub input_errors: u64,
    pub last_error: String,
    pub elapsed: f64,
    pub subscribers: usize,
    pub emit: bool,
}

impl Channel {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        name: String,
        urls: Vec<String>,
        udp_out_specs: Vec<String>,
        seg_target: f64,
        seg_keep: usize,
        keep_active: bool,
        idle_delay: f64,
        is_cluster: bool,
        cluster_host: String,
        cluster_orig_id: String,
        auth_header: Option<String>,
        http_client: Client,
        key_cache: AesKeyCache,
        epoch: Instant,
    ) -> Arc<Self> {
        let udp_outs = build_udp_outs(&udp_out_specs);
        let eff_keep_active = keep_active || !udp_outs.is_empty();
        let now_s = epoch.elapsed().as_secs_f64();

        let inner = ChannelInner {
            ts: TsEngine::new(),
            mode: InputMode::Idle,
            cur_url: 0,
            fails_row: 0,
            in_started: now_s,
            last_data: now_s,
            last_client_act: -1e9,
            hls_last_req: -1e9,
            last_error: "idle".to_string(),
            input_errors: 0,
            bitrate: 0.0,
            win_start: now_s,
            next_resize: now_s + 5.0,
            prev_cc_stat: 0,
            prev_pes_stat: 0,
            was_active_ws: false,
            idle_reported: false,
            cached_variant: None,
            hls_on: false,
            cur_started: false,
            cur_disc: false,
            disc_pending: false,
            cur_t0_wall: now_s,
            cur_t0_pcr: -1,
            cseg: Vec::new(),
            segs: VecDeque::with_capacity(16),
            next_seq: 0,
            playlist_etag: String::new(),
            scratch_pkts: Vec::new(),
            scratch_kfs: Vec::new(),
            udp_outs,
            input_task: None,
        };

        let ch = Arc::new(Self {
            id,
            name,
            urls,
            udp_out_specs,
            seg_target: seg_target.clamp(1.0, 10.0),
            seg_keep: seg_keep.clamp(2, 12),
            keep_active: eff_keep_active,
            idle_delay: idle_delay.clamp(5.0, 3600.0),
            is_cluster,
            cluster_host,
            cluster_orig_id,
            auth_header,
            nclients: AtomicUsize::new(0),
            nwaiters: AtomicUsize::new(0),
            alive: AtomicBool::new(true),
            data_notify: Arc::new(Notify::new()),
            seg_notify: Arc::new(Notify::new()),
            inner: Mutex::new(inner),
            http_client,
            key_cache,
            epoch,
        });

        if eff_keep_active {
            ch.wake();
        }
        ch
    }

    #[inline]
    pub fn now_s(&self) -> f64 {
        self.epoch.elapsed().as_secs_f64()
    }

    pub fn matches_spec(
        &self,
        name: &str,
        urls: &[String],
        keep_active: bool,
        idle_delay: f64,
        udp_outs: &[String],
    ) -> bool {
        let eff_ka = keep_active || !udp_outs.is_empty();
        self.name == name
            && self.urls == urls
            && self.keep_active == eff_ka
            && (self.idle_delay as i64) == (idle_delay as i64)
            && self.udp_out_specs == udp_outs
    }

    /// Wake channel from IN_IDLE (returns true if it was previously idle).
    pub fn wake(self: &Arc<Self>) -> bool {
        let now_s = self.now_s();
        let mut st = self.inner.lock();
        st.last_client_act = now_s;
        if st.mode != InputMode::Idle {
            return false;
        }
        // Leaner initial ring for cluster channels (~1.5 MB) vs direct sources (~4.2 MB)
        let init_ring = if self.is_cluster { TS * 8192 } else { TS * 22310 };
        st.ts.alloc_ring(init_ring);
        st.ts.reset_out_cc();
        st.ts.reset_psi();
        st.win_start = now_s;
        st.bitrate = 0.0;
        st.ts.pcr_bitrate = 0.0;
        st.next_resize = now_s + 5.0;
        st.hls_on = true;
        st.cur_started = false;
        st.cseg.clear();
        st.fails_row = 0;
        st.cur_url = 0;
        st.last_error.clear();
        st.idle_reported = false;
        st.in_started = now_s;
        st.last_data = now_s;
        st.mode = InputMode::Wait;

        let ch_clone = Arc::clone(self);
        st.input_task = Some(tokio::spawn(async move {
            run_channel_input(ch_clone).await;
        }));
        true
    }

    /// Put channel into zero-RAM, zero-CPU IN_IDLE state.
    pub fn sleep(&self) {
        let mut st = self.inner.lock();
        if st.mode == InputMode::Idle {
            return;
        }
        if let Some(h) = st.input_task.take() {
            h.abort();
        }
        st.segs.clear();
        st.segs.shrink_to_fit();
        st.cseg = Vec::new();
        st.cseg.shrink_to_fit();
        st.scratch_pkts = Vec::new();
        st.scratch_pkts.shrink_to_fit();
        st.scratch_kfs = Vec::new();
        st.scratch_kfs.shrink_to_fit();
        st.cur_started = false;
        st.hls_on = false;
        st.playlist_etag.clear();
        st.ts.release_ring();
        st.ts.reset_psi();
        st.bitrate = 0.0;
        st.ts.pcr_bitrate = 0.0;
        st.ts.win_bytes = 0;
        st.ts.scr_win = false;
        st.ts.scrambled = false;
        st.mode = InputMode::Idle;
        st.idle_reported = false;
        st.last_error = "idle".to_string();
        drop(st);
        self.data_notify.notify_waiters();
        self.seg_notify.notify_waiters();
    }

    pub fn shutdown(&self) {
        self.alive.store(false, Ordering::Release);
        self.sleep();
    }

    /// Feed raw TS bytes into channel, update HLS segments & UDP outs, and immediately wake clients.
    pub fn feed_ts(&self, data: &[u8], hls_in: bool) {
        if data.is_empty() {
            return;
        }
        let now_s = self.now_s();
        let mut notify_seg = false;
        let produced: usize;
        {
            let mut st = self.inner.lock();
            if st.mode == InputMode::Idle || st.ts.rcap() == 0 {
                return;
            }
            st.last_data = now_s;

            // Split borrow cleanly via temporary std::mem::take of scratch Vecs
            let mut pkts = std::mem::take(&mut st.scratch_pkts);
            let mut kfs = std::mem::take(&mut st.scratch_kfs);
            produced = st.ts.feed(data, hls_in, now_s, &mut pkts, &mut kfs);

            if produced > 0 {
                if !st.udp_outs.is_empty() {
                    for chunk in pkts.chunks_exact(TS) {
                        for uo in &mut st.udp_outs {
                            uo.push(chunk);
                        }
                    }
                    for uo in &mut st.udp_outs {
                        uo.flush();
                    }
                }
                if st.hls_on {
                    notify_seg = hls_out_feed(&mut st, self.seg_target, self.seg_keep, now_s, &pkts, &kfs);
                }
            }
            st.scratch_pkts = pkts;
            st.scratch_kfs = kfs;
        }
        if produced > 0 {
            self.data_notify.notify_waiters();
        }
        if notify_seg {
            self.seg_notify.notify_waiters();
        }
    }

    /// Render HLS media playlist from cached segments + return its ETag for 304 support.
    pub fn render_hls_playlist(&self, pre: &str, suf: &str) -> Option<(String, String)> {
        let st = self.inner.lock();
        if st.segs.is_empty() {
            return None;
        }
        let mut maxd = 1.0f64;
        for s in &st.segs {
            if s.dur > maxd {
                maxd = s.dur;
            }
        }
        let first_play = st.segs.len().saturating_sub(3);
        let mut start_off = 0.0f64;
        for s in st.segs.iter().skip(first_play) {
            start_off += s.dur;
        }
        let media_seq = st.segs.front().map(|s| s.seq).unwrap_or(0);
        let mut out = String::with_capacity(128 + st.segs.len() * (pre.len() + suf.len() + 40));
        out.push_str(&format!(
            "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:{}\n#EXT-X-MEDIA-SEQUENCE:{}\n",
            maxd.ceil() as i64,
            media_seq
        ));
        if st.segs.len() >= 2 && start_off > 0.5 {
            out.push_str(&format!("#EXT-X-START:TIME-OFFSET=-{:.3}\n", start_off));
        }
        for (i, s) in st.segs.iter().enumerate() {
            if s.disc && i > 0 {
                out.push_str("#EXT-X-DISCONTINUITY\n");
            }
            out.push_str(&format!(
                "#EXTINF:{:.3},\n{}segment-{}.ts{}\n",
                s.dur, pre, s.seq, suf
            ));
        }
        Some((out, st.playlist_etag.clone()))
    }

    pub fn get_segment(&self, seg_name: &str) -> Option<Arc<Bytes>> {
        let seq: i64 = seg_name
            .strip_prefix("segment-")
            .and_then(|s| s.strip_suffix(".ts").or(Some(s)))
            .and_then(|s| s.parse().ok())?;
        let now_s = self.now_s();
        let mut st = self.inner.lock();
        st.hls_last_req = now_s;
        st.segs.iter().find(|s| s.seq == seq).map(|s| Arc::clone(&s.data))
    }

    /// Called once per second by the engine maintenance task.
    pub fn tick_1s(&self) -> ChannelStatsSnapshot {
        let now_s = self.now_s();
        let nclients = self.nclients.load(Ordering::Relaxed);
        let nwaiters = self.nwaiters.load(Ordering::Relaxed);

        let mut st = self.inner.lock();
        if st.mode == InputMode::Idle {
            let emit = st.was_active_ws;
            st.was_active_ws = false;
            st.idle_reported = true;
            return ChannelStatsSnapshot {
                id: self.id.clone(),
                is_cluster: self.is_cluster,
                cluster_host: self.cluster_host.clone(),
                cluster_orig_id: self.cluster_orig_id.clone(),
                idle: true,
                bitrate_kbps: 0,
                onair: false,
                cc_err: 0,
                pes_err: 0,
                cc_delta: 0,
                pes_delta: 0,
                scrambled: false,
                input_id: st.cur_url + 1,
                packets: 0,
                input_errors: st.input_errors,
                last_error: st.last_error.clone(),
                elapsed: 0.0,
                subscribers: 0,
                emit,
            };
        }

        if nclients > 0 || nwaiters > 0 {
            st.last_client_act = now_s;
        } else if !self.keep_active {
            let last_act = st.last_client_act.max(st.hls_last_req);
            if now_s - last_act >= self.idle_delay {
                drop(st);
                self.sleep();
                let mut st2 = self.inner.lock();
                let emit = st2.was_active_ws;
                st2.was_active_ws = false;
                st2.idle_reported = true;
                return ChannelStatsSnapshot {
                    id: self.id.clone(),
                    is_cluster: self.is_cluster,
                    cluster_host: self.cluster_host.clone(),
                    cluster_orig_id: self.cluster_orig_id.clone(),
                    idle: true,
                    bitrate_kbps: 0,
                    onair: false,
                    cc_err: 0,
                    pes_err: 0,
                    cc_delta: 0,
                    pes_delta: 0,
                    scrambled: false,
                    input_id: st2.cur_url + 1,
                    packets: 0,
                    input_errors: st2.input_errors,
                    last_error: "idle".to_string(),
                    elapsed: 0.0,
                    subscribers: 0,
                    emit,
                };
            }
        }

        let el = now_s - st.win_start;
        if el > 0.2 {
            st.bitrate = (st.ts.win_bytes as f64) * 8.0 / el;
        }
        st.ts.win_bytes = 0;
        st.win_start = now_s;
        st.ts.scrambled = st.ts.scr_win;
        st.ts.scr_win = false;

        if now_s >= st.next_resize {
            st.next_resize = now_s + 5.0;
            let bps = st.bitrate.max(st.ts.pcr_bitrate) / 8.0;
            let secs = (st.ts.gop + START_BURST_S + 1.5).max(8.0);
            let want = (bps * secs).clamp(1.5 * 1024.0 * 1024.0, 24.0 * 1024.0 * 1024.0) as usize;
            let rcap = st.ts.rcap();
            if rcap > 0 && (want as f64 > rcap as f64 * 1.25 || (want as f64) < rcap as f64 * 0.6) {
                st.ts.ring_resize(want);
            }
        }

        let br_kbps = if st.bitrate > 0.0 {
            (st.bitrate / 1000.0 + 0.5) as i64
        } else {
            0
        };
        let onair = br_kbps > 0;
        let emit = onair || st.input_errors > 0 || st.was_active_ws;
        if emit {
            st.was_active_ws = true;
        }
        let cc_d = st.ts.cc_err.saturating_sub(st.prev_cc_stat);
        let pes_d = st.ts.pes_err.saturating_sub(st.prev_pes_stat);
        st.prev_cc_stat = st.ts.cc_err;
        st.prev_pes_stat = st.ts.pes_err;

        ChannelStatsSnapshot {
            id: self.id.clone(),
            is_cluster: self.is_cluster,
            cluster_host: self.cluster_host.clone(),
            cluster_orig_id: self.cluster_orig_id.clone(),
            idle: false,
            bitrate_kbps: br_kbps,
            onair,
            cc_err: st.ts.cc_err,
            pes_err: st.ts.pes_err,
            cc_delta: cc_d,
            pes_delta: pes_d,
            scrambled: st.ts.scrambled,
            input_id: st.cur_url + 1,
            packets: st.ts.packets,
            input_errors: st.input_errors,
            last_error: st.last_error.clone(),
            elapsed: now_s - st.in_started,
            subscribers: nclients,
            emit,
        }
    }
}

fn seg_elapsed(st: &ChannelInner, pcr: i64, now_s: f64) -> f64 {
    if pcr >= 0 && st.cur_t0_pcr >= 0 {
        let d = ((pcr - st.cur_t0_pcr + PCR_WRAP) % PCR_WRAP) as f64 / PCR_HZ;
        if (0.0..60.0).contains(&d) {
            return d;
        }
    }
    now_s - st.cur_t0_wall
}

fn seg_begin(st: &mut ChannelInner, pcr: i64, wall: f64) {
    st.cseg.clear();
    st.ts.prefix_build(&mut st.cseg);
    st.cur_t0_pcr = pcr;
    st.cur_t0_wall = wall;
    st.cur_started = true;
    st.cur_disc = st.disc_pending;
    st.disc_pending = false;
}

fn seg_finish(st: &mut ChannelInner, seg_target: f64, seg_keep: usize, now_s: f64, dur: f64) -> bool {
    if st.cseg.len() < TS * 8 {
        return false;
    }
    let seq = st.next_seq;
    st.next_seq += 1;
    let buf = std::mem::take(&mut st.cseg);
    let seg = OutSeg {
        seq,
        dur: if dur > 0.05 { dur } else { seg_target },
        disc: st.cur_disc,
        data: Arc::new(Bytes::from(buf)),
    };
    let keep = if now_s - st.hls_last_req > 60.0 {
        3
    } else {
        seg_keep
    };
    while !st.segs.is_empty() && (st.segs.len() >= 16 || st.segs.len() >= keep) {
        st.segs.pop_front();
    }
    st.segs.push_back(seg);
    let first_seq = st.segs.front().map(|s| s.seq).unwrap_or(0);
    st.playlist_etag = format!("\"s{}-{}\"", first_seq, seq);
    true
}

fn hls_out_feed(
    st: &mut ChannelInner,
    seg_target: f64,
    seg_keep: usize,
    now_s: f64,
    pkts: &[u8],
    kfs: &[KeyframeHit],
) -> bool {
    let mut finished_any = false;
    let mut run = 0usize;
    for hit in kfs {
        if !st.cur_started {
            run = hit.offset;
            seg_begin(st, hit.pcr, now_s);
            continue;
        }
        let d = seg_elapsed(st, hit.pcr, now_s);
        let target = if matches!(st.mode, InputMode::Ts | InputMode::Udp) {
            if st.segs.len() < 2 {
                1.0
            } else {
                (seg_target * 0.6).min(1.5)
            }
        } else {
            seg_target * 0.72
        };
        if d >= target {
            if hit.offset > run {
                st.cseg.extend_from_slice(&pkts[run..hit.offset]);
            }
            if seg_finish(st, seg_target, seg_keep, now_s, d) {
                finished_any = true;
            }
            run = hit.offset;
            seg_begin(st, hit.pcr, now_s);
        }
    }
    if !st.cur_started {
        return finished_any;
    }
    if pkts.len() > run {
        st.cseg.extend_from_slice(&pkts[run..]);
    }
    let d = seg_elapsed(st, st.ts.cur_pcr, now_s);
    if d >= seg_target * 3.0 || st.cseg.len() > 48 * 1024 * 1024 {
        if seg_finish(st, seg_target, seg_keep, now_s, d) {
            finished_any = true;
        }
        let cur_pcr = st.ts.cur_pcr;
        seg_begin(st, cur_pcr, now_s);
    }
    finished_any
}

pub fn hls_out_activate(st: &mut ChannelInner, seg_target: f64, seg_keep: usize, now_s: f64) {
    st.hls_on = true;
    st.cur_started = false;
    st.cseg.clear();
    let lo = st.ts.ring_low();
    let mut newest: Option<usize> = None;
    let mut oldest: Option<usize> = None;
    for i in 0..st.ts.kf_cnt {
        let idx = (st.ts.kf_head + crate::ts::KF_N - 1 - i) % crate::ts::KF_N;
        let p = st.ts.kf[idx].pos;
        if p < lo || p >= st.ts.wpos {
            break;
        }
        if newest.is_none() {
            newest = Some(idx);
        }
        oldest = Some(idx);
    }
    let Some(nidx) = newest else {
        return;
    };
    let oidx = oldest.unwrap_or(nidx);
    if oidx != nidx {
        let kf_o = st.ts.kf[oidx];
        let kf_n = st.ts.kf[nidx];
        seg_begin(st, kf_o.pcr, kf_o.wall);
        let mut tmp = Vec::new();
        st.ts.ring_copy_into(&mut tmp, kf_o.pos, kf_n.pos);
        st.cseg.extend_from_slice(&tmp);
        let mut d = -1.0f64;
        if kf_o.pcr >= 0 && kf_n.pcr >= 0 {
            d = ((kf_n.pcr - kf_o.pcr + PCR_WRAP) % PCR_WRAP) as f64 / PCR_HZ;
        }
        if d <= 0.0 || d > 60.0 {
            d = kf_n.wall - kf_o.wall;
        }
        if d >= 0.3 {
            seg_finish(st, seg_target, seg_keep, now_s, d);
        }
    }
    let kf_n = st.ts.kf[nidx];
    seg_begin(st, kf_n.pcr, kf_n.wall);
    let mut tmp = Vec::new();
    st.ts.ring_copy_into(&mut tmp, kf_n.pos, st.ts.wpos);
    st.cseg.extend_from_slice(&tmp);
}

/* ----------------------------------------------------------- UDP helpers */

fn parse_udp_spec(raw: &str) -> Option<(bool, Option<Ipv4Addr>, Ipv4Addr, u16)> {
    let stripped = raw.split('#').next().unwrap_or(raw).trim();
    let (is_rtp, rest) = if let Some(r) = stripped.strip_prefix("udp://") {
        (false, r)
    } else if let Some(r) = stripped.strip_prefix("rtp://") {
        (true, r)
    } else if stripped.len() > 6 && stripped[..6].eq_ignore_ascii_case("udp://") {
        (false, &stripped[6..])
    } else if stripped.len() > 6 && stripped[..6].eq_ignore_ascii_case("rtp://") {
        (true, &stripped[6..])
    } else {
        return None;
    };
    let host_port = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let (lip, target) = if let Some((l, t)) = host_port.split_once('@') {
        (l.parse::<Ipv4Addr>().ok(), t)
    } else {
        (None, host_port)
    };
    let (ip_s, port_s) = target.split_once(':')?;
    let gip = ip_s.parse::<Ipv4Addr>().ok()?;
    let port = port_s.parse::<u16>().ok().filter(|&p| p > 0)?;
    Some((is_rtp, lip, gip, port))
}

fn build_udp_outs(specs: &[String]) -> Vec<UdpOut> {
    let mut outs = Vec::new();
    for sp in specs {
        if outs.len() >= 8 {
            break;
        }
        let Some((_is_rtp, lip, gip, port)) = parse_udp_spec(sp) else {
            continue;
        };
        let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") else {
            continue;
        };
        let _ = sock.set_nonblocking(true);
        let _ = sock.set_multicast_ttl_v4(32);
        if let Some(la) = lip {
            let _ = socket2::SockRef::from(&sock).set_multicast_if_v4(&la);
        }
        outs.push(UdpOut {
            sock,
            addr: SocketAddrV4::new(gip, port),
            buf: [0u8; 7 * TS],
            n: 0,
        });
    }
    outs
}

fn parse_input_options(raw_url: &str) -> (String, String, bool, bool) {
    let mut ua = "Astrika/2.1".to_string();
    let mut drop_sdt = false;
    let mut drop_eit = false;
    let (base, frag) = match raw_url.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (raw_url, None),
    };
    if let Some(f) = frag {
        for opt in f.split('&') {
            if let Some(v) = opt.strip_prefix("ua=") {
                if !v.is_empty() {
                    ua = v.to_string();
                }
            } else if opt == "no_sdt" {
                drop_sdt = true;
            } else if opt == "no_eit" {
                drop_eit = true;
            }
        }
    }
    let clean = if let Some(rest) = base.strip_prefix("hls://") {
        format!("http://{}", rest)
    } else {
        base.to_string()
    };
    (clean, ua, drop_sdt, drop_eit)
}

/* ----------------------------------------------------------- Channel input loop */

async fn run_channel_input(ch: Arc<Channel>) {
    if ch.urls.is_empty() {
        return;
    }

    loop {
        if !ch.alive.load(Ordering::Acquire) {
            return;
        }
        let cur_idx = {
            let st = ch.inner.lock();
            if st.mode == InputMode::Idle {
                return;
            }
            st.cur_url % ch.urls.len()
        };

        let raw_url = ch.urls[cur_idx].clone();
        let (url, ua, drop_sdt, drop_eit) = parse_input_options(&raw_url);
        let now_s = ch.now_s();
        {
            let mut st = ch.inner.lock();
            st.in_started = now_s;
            st.last_data = now_s;
            st.ts.drop_sdt = drop_sdt;
            st.ts.drop_eit = drop_eit;
        }

        let err_msg: String = if url.to_ascii_lowercase().starts_with("udp://")
            || url.to_ascii_lowercase().starts_with("rtp://")
        {
            run_udp_input(&ch, &url).await
        } else {
            let path_part = url.split('?').next().unwrap_or(&url);
            let is_m3u_ext = path_part.len() >= 5
                && path_part[path_part.len() - 5..].eq_ignore_ascii_case(".m3u8")
                || (path_part.len() >= 4
                    && path_part[path_part.len() - 4..].eq_ignore_ascii_case(".m3u"));

            if is_m3u_ext {
                run_hls_input(&ch, &url, None, &ua).await
            } else {
                match run_http_ts_or_probe(&ch, &url, &ua).await {
                    TsOrHls::SwitchToHls { final_url, body } => {
                        run_hls_input(&ch, &url, Some((final_url, body)), &ua).await
                    }
                    TsOrHls::Failed(e) => e,
                }
            }
        };

        if !ch.alive.load(Ordering::Acquire) {
            return;
        }

        let delay = {
            let mut st = ch.inner.lock();
            if st.mode == InputMode::Idle {
                return;
            }
            st.input_errors += 1;
            st.last_error = err_msg.clone();
            st.fails_row += 1;
            let next = (st.cur_url + 1) % ch.urls.len();
            if next != st.cur_url {
                st.ts.reset_psi();
                st.ts.reset_out_cc();
                st.disc_pending = true;
                st.cached_variant = None;
            } else {
                st.ts.reset_sync();
            }
            st.cur_url = next;
            st.mode = InputMode::Wait;

            // Fast failover: switch immediately to backup URL on first failure!
            if ch.urls.len() > 1 && st.fails_row < ch.urls.len() {
                if st.fails_row == 1 {
                    Duration::from_millis(0)
                } else {
                    Duration::from_millis(400)
                }
            } else {
                Duration::from_secs(2)
            }
        };

        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
}

async fn run_udp_input(ch: &Arc<Channel>, url: &str) -> String {
    let Some((is_rtp, lip, gip, port)) = parse_udp_spec(url) else {
        return "invalid UDP/RTP URL".to_string();
    };
    let sock = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
        Ok(s) => s,
        Err(e) => return format!("UDP socket failed: {}", e),
    };
    let _ = sock.set_reuse_address(true);
    let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = sock.set_nonblocking(true);

    let is_mcast = gip.is_multicast();
    let bind_ip = if is_mcast {
        gip
    } else {
        lip.unwrap_or(Ipv4Addr::UNSPECIFIED)
    };
    if let Err(e) = sock.bind(&SocketAddrV4::new(bind_ip, port).into()) {
        return format!("UDP bind failed: {}", e);
    }
    if is_mcast {
        if let Err(e) = sock.join_multicast_v4(&gip, &lip.unwrap_or(Ipv4Addr::UNSPECIFIED)) {
            return format!("UDP multicast join failed: {}", e);
        }
    }
    let std_sock: std::net::UdpSocket = sock.into();
    let udp = match UdpSocket::from_std(std_sock) {
        Ok(u) => u,
        Err(e) => return format!("UDP tokio wrap failed: {}", e),
    };

    ch.inner.lock().mode = InputMode::Udp;
    let mut buf = vec![0u8; 65536];
    let mut got_any = false;
    loop {
        match tokio::time::timeout(Duration::from_secs(10), udp.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                if n == 0 {
                    continue;
                }
                let slice = if is_rtp && n >= 12 {
                    strip_rtp(&buf[..n])
                } else {
                    Some(&buf[..n])
                };
                if let Some(payload) = slice {
                    if !got_any {
                        got_any = true;
                        ch.inner.lock().fails_row = 0;
                    }
                    ch.feed_ts(payload, false);
                }
            }
            Ok(Err(e)) => return format!("UDP recv error: {}", e),
            Err(_) => return "UDP no data timeout".to_string(),
        }
    }
}

fn strip_rtp(d: &[u8]) -> Option<&[u8]> {
    if d.len() < 12 {
        return None;
    }
    let cc = (d[0] & 0x0F) as usize;
    let has_ext = ((d[0] >> 4) & 1) != 0;
    let has_pad = ((d[0] >> 5) & 1) != 0;
    let mut off = 12 + cc * 4;
    let mut dl = d.len();
    if has_ext && off + 4 <= dl {
        let ext_words = u16::from_be_bytes([d[off + 2], d[off + 3]]) as usize;
        off += 4 + ext_words * 4;
    }
    if has_pad && dl > off {
        let pad = d[dl - 1] as usize;
        if pad <= dl - off {
            dl -= pad;
        }
    }
    if off < dl {
        Some(&d[off..dl])
    } else {
        None
    }
}

enum TsOrHls {
    SwitchToHls { final_url: String, body: String },
    Failed(String),
}

async fn run_http_ts_or_probe(ch: &Arc<Channel>, url: &str, ua: &str) -> TsOrHls {
    ch.inner.lock().mode = InputMode::Ts;
    let conn_to = Duration::from_secs_f64(if ch.is_cluster {
        3.5
    } else if ch.urls.len() > 1 {
        4.5
    } else {
        8.0
    });
    let idle_to = Duration::from_secs_f64(if ch.urls.len() > 1 { 12.0 } else { 20.0 });

    let mut req = ch
        .http_client
        .get(url)
        .header(USER_AGENT, ua)
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Cache-Control", "no-cache");
    if let Some(ref ah) = ch.auth_header {
        req = req.header(reqwest::header::AUTHORIZATION, ah.as_str());
    }

    let resp = match tokio::time::timeout(conn_to, req.send()).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return TsOrHls::Failed(format!("connect error: {}", e)),
        Err(_) => return TsOrHls::Failed("connect timeout".to_string()),
    };

    let status = resp.status().as_u16();
    if status != 200 {
        return TsOrHls::Failed(format!("HTTP {}", status));
    }
    let final_url = resp.url().to_string();
    let is_m3u_ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.to_ascii_lowercase().contains("mpegurl"));

    let mut stream = resp.bytes_stream();
    let mut checked = false;
    let mut probe_m3u = is_m3u_ct;
    let mut probe_buf = Vec::new();
    let mut data_started = Instant::now();

    loop {
        match tokio::time::timeout(idle_to, stream.next()).await {
            Ok(Some(Ok(chunk))) => {
                if chunk.is_empty() {
                    continue;
                }
                if !checked {
                    checked = true;
                    data_started = Instant::now();
                    let trimmed = trim_leading_ws_bom(&chunk);
                    if trimmed.starts_with(b"#EXTM3U") {
                        probe_m3u = true;
                    }
                }
                if probe_m3u {
                    if probe_buf.len() + chunk.len() > 16 * 1024 * 1024 {
                        return TsOrHls::Failed("playlist too large".to_string());
                    }
                    probe_buf.extend_from_slice(&chunk);
                } else {
                    if data_started.elapsed() > Duration::from_secs(5) {
                        ch.inner.lock().fails_row = 0;
                    }
                    ch.feed_ts(&chunk, false);
                }
            }
            Ok(Some(Err(e))) => return TsOrHls::Failed(format!("stream read error: {}", e)),
            Ok(None) => {
                if probe_m3u && !probe_buf.is_empty() {
                    let body = String::from_utf8_lossy(&probe_buf).into_owned();
                    return TsOrHls::SwitchToHls { final_url, body };
                }
                return TsOrHls::Failed("stream ended".to_string());
            }
            Err(_) => return TsOrHls::Failed("read timeout".to_string()),
        }
    }
}

fn trim_leading_ws_bom(d: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < d.len()
        && matches!(
            d[i],
            b' ' | b'\r' | b'\n' | b'\t' | 0xEF | 0xBB | 0xBF
        )
    {
        i += 1;
    }
    &d[i..]
}

/* ----------------------------------------------------------- HLS input (async parallel) */

struct PendingSeg {
    seg: HlsSegment,
    handle: JoinHandle<Result<(Bytes, u16), String>>,
}

async fn fetch_key_bytes(client: &Client, url: &str, ua: &str) -> Result<[u8; 16], String> {
    let resp = tokio::time::timeout(
        Duration::from_secs(8),
        client.get(url).header(USER_AGENT, ua).send(),
    )
    .await
    .map_err(|_| "key timeout".to_string())?
    .map_err(|e| format!("key error: {}", e))?;
    if resp.status().as_u16() != 200 {
        return Err(format!("key HTTP {}", resp.status().as_u16()));
    }
    let bytes = resp.bytes().await.map_err(|e| format!("key body: {}", e))?;
    if bytes.len() != 16 {
        return Err("invalid AES key length".to_string());
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

async fn fetch_segment_task(
    client: Client,
    key_cache: AesKeyCache,
    seg: HlsSegment,
    ua: String,
    timeout: Duration,
) -> Result<(Bytes, u16), String> {
    // Launch AES-128 key fetch in parallel with segment HTTP download!
    let key_fut = if let Some(ref kurl) = seg.key_url {
        if key_cache.get(kurl).is_some() {
            None
        } else {
            let c = client.clone();
            let ku = kurl.clone();
            let u = ua.clone();
            Some(tokio::spawn(async move { fetch_key_bytes(&c, &ku, &u).await }))
        }
    } else {
        None
    };

    let mut req = client
        .get(&seg.url)
        .header(USER_AGENT, &ua)
        .header("Accept", "*/*");
    if let Some((off, len)) = seg.byterange {
        let end = off + len.saturating_sub(1);
        req = req.header(RANGE, format!("bytes={}-{}", off, end));
    }

    let resp = tokio::time::timeout(timeout, req.send())
        .await
        .map_err(|_| "segment connect timeout".to_string())?
        .map_err(|e| format!("segment fetch error: {}", e))?;

    let status = resp.status().as_u16();
    if status != 200 && status != 206 {
        return Ok((Bytes::new(), status));
    }
    let raw = tokio::time::timeout(timeout, resp.bytes())
        .await
        .map_err(|_| "segment read timeout".to_string())?
        .map_err(|e| format!("segment body error: {}", e))?;

    if raw.len() > 96 * 1024 * 1024 {
        return Err("segment too large".to_string());
    }

    let payload = if let Some(ref kurl) = seg.key_url {
        let key = if let Some(k) = key_cache.get(kurl) {
            k
        } else if let Some(kh) = key_fut {
            let k = kh
                .await
                .map_err(|_| "key join error".to_string())??;
            key_cache.insert(kurl.clone(), k);
            k
        } else {
            return Err("missing AES key".to_string());
        };
        decrypt_aes128(&raw, &key, seg.iv, seg.seq)?
    } else {
        raw
    };

    Ok((payload, status))
}

async fn run_hls_input(
    ch: &Arc<Channel>,
    master_url: &str,
    initial_body: Option<(String, String)>,
    ua: &str,
) -> String {
    ch.inner.lock().mode = InputMode::Hls;

    // Use cached variant URL if fresh (saves 1-2 RTTs on wake from IN_IDLE!)
    let mut pl_url = {
        let st = ch.inner.lock();
        if let Some((ref v, ts)) = st.cached_variant {
            if ts.elapsed() < Duration::from_secs(600) {
                v.clone()
            } else {
                master_url.to_string()
            }
        } else {
            master_url.to_string()
        }
    };

    let mut etag: Option<String> = None;
    let mut last_mod: Option<String> = None;
    let mut first = true;
    let mut td = 6.0f64;
    let mut last_seq: i64 = -1;
    let mut seen = SeenSet::new(256);
    let mut queue: VecDeque<HlsSegment> = VecDeque::with_capacity(24);
    let mut inflight: VecDeque<PendingSeg> = VecDeque::with_capacity(4);
    let mut pl_err = 0usize;
    let mut consec_seg_err = 0usize;
    let mut burst_done = false;
    let mut avg_bps = 0.0f64;

    let mut pending_initial = initial_body;
    let mut next_poll = Instant::now();
    let started_at = Instant::now();

    loop {
        if !ch.alive.load(Ordering::Acquire) {
            for p in inflight {
                p.handle.abort();
            }
            return "channel stopped".to_string();
        }

        // 1. Poll playlist if due and queue isn't already deep
        if pending_initial.is_some() || (Instant::now() >= next_poll && queue.len() < 6) {
            let fetch_res: Result<Option<(String, String)>, (String, u16)> =
                if let Some((base, body)) = pending_initial.take() {
                    Ok(Some((base, body)))
                } else {
                    let mut hdrs = HeaderMap::new();
                    if let Ok(v) = HeaderValue::from_str(ua) {
                        hdrs.insert(USER_AGENT, v);
                    }
                    if let Some(ref e) = etag {
                        if let Ok(v) = HeaderValue::from_str(e) {
                            hdrs.insert(IF_NONE_MATCH, v);
                        }
                    }
                    if let Some(ref lm) = last_mod {
                        if let Ok(v) = HeaderValue::from_str(lm) {
                            hdrs.insert(IF_MODIFIED_SINCE, v);
                        }
                    }
                    match tokio::time::timeout(
                        Duration::from_secs(8),
                        ch.http_client.get(&pl_url).headers(hdrs).send(),
                    )
                    .await
                    {
                        Ok(Ok(resp)) => {
                            let status = resp.status().as_u16();
                            if status == 304 {
                                Ok(None)
                            } else if status != 200 {
                                Err((format!("playlist HTTP {}", status), status))
                            } else {
                                if let Some(e) =
                                    resp.headers().get(ETAG).and_then(|v| v.to_str().ok())
                                {
                                    etag = Some(e.to_string());
                                }
                                if let Some(lm) = resp
                                    .headers()
                                    .get(LAST_MODIFIED)
                                    .and_then(|v| v.to_str().ok())
                                {
                                    last_mod = Some(lm.to_string());
                                }
                                let final_u = resp.url().to_string();
                                match resp.text().await {
                                    Ok(t) => Ok(Some((final_u, t))),
                                    Err(e) => Err((format!("playlist read: {}", e), 0)),
                                }
                            }
                        }
                        Ok(Err(e)) => Err((format!("playlist fetch: {}", e), 0)),
                        Err(_) => Err(("playlist timeout".to_string(), 0)),
                    }
                };

            match fetch_res {
                Ok(None) => {
                    // 304 Not Modified — zero parsing CPU!
                    pl_err = 0;
                    next_poll = Instant::now()
                        + Duration::from_secs_f64((td * 0.25).clamp(0.4, 1.2));
                }
                Ok(Some((base, text))) => match parse_m3u8(&text, &base) {
                    Ok(ParsedPlaylist::Master { best_uri, .. }) => {
                        pl_url = best_uri.clone();
                        etag = None;
                        last_mod = None;
                        ch.inner.lock().cached_variant = Some((best_uri, Instant::now()));
                        next_poll = Instant::now();
                        continue;
                    }
                    Ok(ParsedPlaylist::Media {
                        target_duration,
                        has_media_sequence,
                        segments,
                        ..
                    }) => {
                        if target_duration > 0.0 {
                            td = target_duration;
                        }
                        if pl_url != master_url {
                            ch.inner.lock().cached_variant = Some((pl_url.clone(), Instant::now()));
                        }
                        // Pre-warm AES-128 key immediately if any segment uses an uncached key
                        for s in &segments {
                            if let Some(ref ku) = s.key_url {
                                if ch.key_cache.get(ku).is_none() {
                                    let c = ch.http_client.clone();
                                    let kc = ch.key_cache.clone();
                                    let kurl = ku.clone();
                                    let u = ua.to_string();
                                    tokio::spawn(async move {
                                        if let Ok(k) = fetch_key_bytes(&c, &kurl, &u).await {
                                            kc.insert(kurl, k);
                                        }
                                    });
                                    break;
                                }
                            }
                        }

                        if has_media_sequence
                            && !segments.is_empty()
                            && last_seq >= 0
                            && segments.last().unwrap().seq < last_seq - 50
                        {
                            last_seq = -1;
                        }

                        let mut new_segs = Vec::new();
                        for s in segments {
                            let dk = seg_dedup_key(&s.url);
                            let is_new = if has_media_sequence {
                                s.seq > last_seq
                            } else {
                                !seen.contains(dk)
                            };
                            if is_new {
                                new_segs.push((s, dk));
                            }
                        }

                        let limit = if first {
                            if td <= 5.0 { 4 } else { 3 }
                        } else if td <= 6.0 {
                            3
                        } else {
                            2
                        };
                        let skip = new_segs.len().saturating_sub(limit);
                        first = false;
                        let mut added = 0usize;
                        for (idx, (s, dk)) in new_segs.into_iter().enumerate() {
                            seen.insert(dk);
                            if s.seq > last_seq {
                                last_seq = s.seq;
                            }
                            if idx < skip || queue.len() >= 24 {
                                continue;
                            }
                            queue.push_back(s);
                            added += 1;
                        }
                        pl_err = 0;
                        let td2 = if td > 0.0 { td } else { 6.0 };
                        let wait_s = if added > 0 {
                            (td2 * 0.42).clamp(0.3, 1.8)
                        } else {
                            (td2 * 0.22).clamp(0.4, 1.1)
                        };
                        next_poll = Instant::now() + Duration::from_secs_f64(wait_s);
                    }
                    Err(e) => {
                        pl_err += 1;
                        ch.inner.lock().last_error = e.clone();
                        if pl_url != master_url {
                            pl_url = master_url.to_string();
                            etag = None;
                            last_mod = None;
                            ch.inner.lock().cached_variant = None;
                        }
                        if first || pl_err >= 8 {
                            for p in inflight {
                                p.handle.abort();
                            }
                            return e;
                        }
                        next_poll = Instant::now()
                            + Duration::from_secs_f64((0.3 * pl_err as f64).min(2.0));
                    }
                },
                Err((msg, _status)) => {
                    pl_err += 1;
                    ch.inner.lock().last_error = msg.clone();
                    if pl_url != master_url {
                        pl_url = master_url.to_string();
                        etag = None;
                        last_mod = None;
                        ch.inner.lock().cached_variant = None;
                    }
                    if first || pl_err >= 8 {
                        for p in inflight {
                            p.handle.abort();
                        }
                        return msg;
                    }
                    next_poll = Instant::now()
                        + Duration::from_secs_f64((0.3 * pl_err as f64).min(2.0));
                }
            }
        }

        // 2. Adaptive parallel segment prefetch (3 during cold burst, 2 steady-state)
        let parallel_cap = if burst_done { 2 } else { 3 };
        while inflight.len() < parallel_cap {
            let Some(seg) = queue.pop_front() else {
                break;
            };
            let timeout = Duration::from_secs_f64((td * 1.5 + 2.0).clamp(5.0, 20.0));
            let c = ch.http_client.clone();
            let kc = ch.key_cache.clone();
            let u = ua.to_string();
            let seg_clone = seg.clone();
            let handle = tokio::spawn(async move {
                fetch_segment_task(c, kc, seg_clone, u, timeout).await
            });
            inflight.push_back(PendingSeg { seg, handle });
        }

        // 3. Consume front in-flight segment in strict playback order
        if let Some(front) = inflight.pop_front() {
            let seg_dur = front.seg.dur;
            let seg_disc = front.seg.discontinuity;
            match front.handle.await {
                Ok(Ok((payload, status))) => {
                    if status == 404 || status == 410 {
                        if status == 410 && pl_url != master_url {
                            pl_url = master_url.to_string();
                            etag = None;
                            last_mod = None;
                            ch.inner.lock().cached_variant = None;
                        }
                        continue;
                    }
                    if status == 401 || status == 403 {
                        if pl_url != master_url {
                            pl_url = master_url.to_string();
                            etag = None;
                            last_mod = None;
                            ch.inner.lock().cached_variant = None;
                            next_poll = Instant::now();
                        }
                        consec_seg_err += 1;
                    } else if (status == 200 || status == 206) && payload.len() >= TS {
                        consec_seg_err = 0;
                        if started_at.elapsed() > Duration::from_secs(5) {
                            ch.inner.lock().fails_row = 0;
                        }
                        if seg_dur > 0.2 {
                            let m = payload.len() as f64 / seg_dur;
                            avg_bps = if avg_bps > 0.0 {
                                0.7 * avg_bps + 0.3 * m
                            } else {
                                m
                            };
                        }
                        {
                            let mut st = ch.inner.lock();
                            st.ts.reset_in_cc();
                            if seg_disc {
                                st.disc_pending = true;
                            }
                        }

                        // Feed segment: burst immediately until 2 output segments exist, then pace smoothly
                        if !burst_done {
                            ch.feed_ts(&payload, true);
                            let nsegs = ch.inner.lock().segs.len();
                            if nsegs >= 2 {
                                burst_done = true;
                            }
                        } else {
                            let bps = if avg_bps > 50_000.0 { avg_bps } else { 500_000.0 };
                            let step_bytes = (((bps * 0.05) as usize) / TS).max(32) * TS;
                            let mut off = 0usize;
                            while off < payload.len() {
                                if !ch.alive.load(Ordering::Acquire) {
                                    break;
                                }
                                let end = (off + step_bytes).min(payload.len());
                                ch.feed_ts(&payload[off..end], true);
                                off = end;
                                if off < payload.len() {
                                    let sleep_ms = if queue.len() >= 2 { 35 } else { 48 };
                                    tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                                }
                            }
                        }
                        continue;
                    } else {
                        consec_seg_err += 1;
                        ch.inner.lock().last_error = format!("segment HTTP {}", status);
                    }
                }
                Ok(Err(e)) => {
                    consec_seg_err += 1;
                    ch.inner.lock().last_error = e;
                }
                Err(_) => {
                    consec_seg_err += 1;
                    ch.inner.lock().last_error = "segment task cancelled".to_string();
                }
            }
            if consec_seg_err >= 8 {
                for p in inflight {
                    p.handle.abort();
                }
                return ch.inner.lock().last_error.clone();
            }
        } else {
            // Nothing in flight — wait until next playlist poll
            let now = Instant::now();
            if next_poll > now {
                tokio::time::sleep((next_poll - now).min(Duration::from_millis(250))).await;
            } else {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        // Watchdog for stalled HLS stream
        let last_data_age = ch.now_s() - ch.inner.lock().last_data;
        let max_idle = (td * 2.5).max(12.0);
        if last_data_age > max_idle {
            for p in inflight {
                p.handle.abort();
            }
            return "HLS no data timeout".to_string();
        }
    }
}

/// Global session sequence generator
static SESS_SEQ: AtomicU64 = AtomicU64::new(1);

pub fn next_session_id() -> u64 {
    SESS_SEQ.fetch_add(1, Ordering::Relaxed)
}

pub fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub type ChannelMap = Arc<DashMap<String, Arc<Channel>>>;
pub type SessionMap = Arc<DashMap<u64, ActiveSession>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_udp_and_input_options() {
        let (is_rtp, lip, gip, port) = parse_udp_spec("rtp://192.168.1.2@239.0.0.1:1234").unwrap();
        assert!(is_rtp);
        assert_eq!(lip, Some(Ipv4Addr::new(192, 168, 1, 2)));
        assert_eq!(gip, Ipv4Addr::new(239, 0, 0, 1));
        assert_eq!(port, 1234);

        let (u, ua, no_sdt, no_eit) =
            parse_input_options("http://10.0.0.1/ch.ts#ua=VLC/3.0&no_sdt&no_eit");
        assert_eq!(u, "http://10.0.0.1/ch.ts");
        assert_eq!(ua, "VLC/3.0");
        assert!(no_sdt);
        assert!(no_eit);
    }

    #[test]
    fn channel_idle_uses_zero_ring_memory() {
        let client = Client::new();
        let ch = Channel::new(
            "ch1".into(),
            "Test".into(),
            vec!["http://127.0.0.1:9999/test.ts".into()],
            vec![],
            2.0,
            5,
            false,
            20.0,
            false,
            String::new(),
            String::new(),
            None,
            client,
            AesKeyCache::new(),
            Instant::now(),
        );
        let st = ch.inner.lock();
        assert_eq!(st.mode, InputMode::Idle);
        assert_eq!(st.ts.rcap(), 0);
        assert_eq!(st.segs.len(), 0);
    }
}
