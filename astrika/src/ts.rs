use memchr::memchr;
use std::sync::OnceLock;

pub const TS: usize = 188;
pub const KF_N: usize = 48;
pub const PCR_HZ: f64 = 27_000_000.0;
pub const PCR_WRAP: i64 = 8_589_934_592 * 300;
pub const START_BURST_S: f64 = 3.5;

pub const K_NONE: u8 = 0;
pub const K_VIDEO: u8 = 1;
pub const K_AUDIO: u8 = 2;
pub const K_PMT: u8 = 3;
pub const K_OTHER: u8 = 4;

static CRC_TAB: OnceLock<[u32; 256]> = OnceLock::new();

fn crc_tab() -> &'static [u32; 256] {
    CRC_TAB.get_or_init(|| {
        let mut tab = [0u32; 256];
        for i in 0..256u32 {
            let mut c = i << 24;
            for _ in 0..8 {
                c = if (c & 0x8000_0000) != 0 {
                    (c << 1) ^ 0x04C1_1DB7
                } else {
                    c << 1
                };
            }
            tab[i as usize] = c;
        }
        tab
    })
}

#[inline]
pub fn crc32_mpeg(data: &[u8]) -> u32 {
    let tab = crc_tab();
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = (c << 8) ^ tab[(((c >> 24) as u8) ^ b) as usize];
    }
    c
}

#[inline]
fn is_video_stype(st: u8) -> bool {
    matches!(st, 0x01 | 0x02 | 0x10 | 0x1B | 0x24 | 0x42 | 0xD1 | 0xEA | 0x33)
}

#[inline]
fn is_audio_stype(st: u8) -> bool {
    matches!(
        st,
        0x03 | 0x04 | 0x0F | 0x11 | 0x1C | 0x2D | 0x81 | 0x82 | 0x83 | 0x84 | 0x87
    )
}

/// PSI section reassembler supporting up to 8 TS packets and version_number skip.
#[derive(Clone)]
pub struct PsiCap {
    pub pid: u16,
    sec: [u8; 1024],
    have: usize,
    need: usize,
    pk: [[u8; TS]; 8],
    npk: usize,
    pub done: [[u8; TS]; 8],
    pub ndone: usize,
    last_version: Option<u8>,
}

impl PsiCap {
    fn new(pid: u16) -> Self {
        Self {
            pid,
            sec: [0u8; 1024],
            have: 0,
            need: 0,
            pk: [[0u8; TS]; 8],
            npk: 0,
            done: [[0u8; TS]; 8],
            ndone: 0,
            last_version: None,
        }
    }
}

/// Keyframe index entry inside the circular ring buffer.
#[derive(Clone, Copy, Default)]
pub struct KfEntry {
    pub pos: u64,
    pub pcr: i64,
    pub wall: f64,
}

#[derive(Clone, Copy, Debug)]
pub struct KeyframeHit {
    pub offset: usize,
    pub back_bytes: usize,
    pub pos: u64,
    pub pcr: i64,
}

/// Fast SIMD-assisted NAL/MPEG2 start-code scanner.
/// Returns:
/// - `Some(true)` if a keyframe (SPS/IDR/VPS/IRAP/SequenceHeader) was found
/// - `Some(false)` if a non-keyframe slice was definitively seen
/// - `None` if no conclusive NAL was found in this slice (caller may check next TS packet)
#[inline]
pub fn scan_video_nal(buf: &[u8], stype: u8) -> Option<bool> {
    let mut i = 0usize;
    let len = buf.len();
    while i + 4 <= len {
        let rel = memchr(0x00, &buf[i..len - 3])?;
        i += rel;
        if buf[i + 1] == 0x00 && buf[i + 2] == 0x01 {
            let b = buf[i + 3];
            if stype == 0x24 {
                // HEVC
                let t = (b >> 1) & 0x3F;
                if (16..=21).contains(&t) || t == 32 || t == 33 {
                    return Some(true);
                }
                if t <= 9 {
                    return Some(false);
                }
            } else if stype == 0x01 || stype == 0x02 {
                // MPEG-1 / MPEG-2
                if b == 0xB3 {
                    return Some(true);
                }
                if b == 0x00 {
                    return Some(false);
                }
            } else {
                // H.264 / AVC (default)
                let t = b & 0x1F;
                if t == 7 || t == 5 {
                    return Some(true);
                }
                if t == 1 || t == 2 {
                    return Some(false);
                }
                // Note: t == 6 (SEI) or t == 9 (AUD) -> keep scanning!
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    None
}

#[inline]
fn pes_check_kf(pkt: &[u8; TS], off: usize, stype: u8) -> Option<bool> {
    if off + 9 > TS || pkt[off] != 0 || pkt[off + 1] != 0 || pkt[off + 2] != 1 {
        return Some(false);
    }
    let start = off + 9 + pkt[off + 8] as usize;
    if start >= TS {
        return None; // PES header spans into next packet
    }
    scan_video_nal(&pkt[start..TS], stype)
}

pub struct TsEngine {
    pub drop_sdt: bool,
    pub drop_eit: bool,

    // Stream alignment & carry
    carry: [u8; TS],
    carry_n: usize,
    pub synced: bool,

    // PID state
    pub in_cc: [i8; 8192],
    pub out_cc: [i8; 8192],
    pub kind: [u8; 8192],
    pub stype: [u8; 8192],
    // Compact multi-packet PES lookahead for UHD/HEVC keyframes (AUD + HDR SEI up to 6 TS packets)
    vid_la_pid: u16,
    vid_la_rem: u8,
    vid_la_pos: u64,
    vid_la_pcr: i64,
    vid_la_tail: [u8; 3],
    vid_la_tail_len: u8,

    // PSI
    pub caps: Vec<PsiCap>,
    pub pmt_pid: [u16; 8],
    pub pnr: [u16; 8],
    pub npmt: usize,
    pub tsid: u16,

    // PCR & bitrate
    pub pcr_pid: i32,
    pub cur_pcr: i64,
    pub br_pcr0: i64,
    pub br_pos0: u64,
    pub pcr_bitrate: f64,
    pub gop: f64,

    // Circular ring buffer (empty when channel is IN_IDLE -> 0 bytes RAM!)
    pub ring: Vec<u8>,
    pub wpos: u64,
    pub kf: [KfEntry; KF_N],
    pub kf_head: usize,
    pub kf_cnt: usize,

    // Stats
    pub win_bytes: u64,
    pub packets: u64,
    pub cc_err: u64,
    pub pes_err: u64,
    pub sync_losses: u64,
    pub scr_win: bool,
    pub scrambled: bool,
}

impl Default for TsEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TsEngine {
    pub fn new() -> Self {
        Self {
            drop_sdt: false,
            drop_eit: false,
            carry: [0u8; TS],
            carry_n: 0,
            synced: false,
            in_cc: [-1; 8192],
            out_cc: [-1; 8192],
            kind: [0; 8192],
            stype: [0; 8192],
            vid_la_pid: 0xFFFF,
            vid_la_rem: 0,
            vid_la_pos: 0,
            vid_la_pcr: -1,
            vid_la_tail: [0; 3],
            vid_la_tail_len: 0,
            caps: Vec::with_capacity(4),
            pmt_pid: [0; 8],
            pnr: [0; 8],
            npmt: 0,
            tsid: 0,
            pcr_pid: -1,
            cur_pcr: -1,
            br_pcr0: -1,
            br_pos0: 0,
            pcr_bitrate: 0.0,
            gop: 0.0,
            ring: Vec::new(),
            wpos: 0,
            kf: [KfEntry::default(); KF_N],
            kf_head: 0,
            kf_cnt: 0,
            win_bytes: 0,
            packets: 0,
            cc_err: 0,
            pes_err: 0,
            sync_losses: 0,
            scr_win: false,
            scrambled: false,
        }
    }

    pub fn alloc_ring(&mut self, cap_bytes: usize) {
        let aligned = (cap_bytes / TS).max(64) * TS;
        self.ring = vec![0u8; aligned];
        self.wpos = 0;
        self.kf_head = 0;
        self.kf_cnt = 0;
    }

    pub fn release_ring(&mut self) {
        self.ring = Vec::new();
        self.ring.shrink_to_fit();
        self.wpos = 0;
        self.kf_head = 0;
        self.kf_cnt = 0;
    }

    pub fn reset_psi(&mut self) {
        self.kind.fill(0);
        self.stype.fill(0);
        self.in_cc.fill(-1);
        self.vid_la_pid = 0xFFFF;
        self.vid_la_rem = 0;
        self.vid_la_tail_len = 0;
        self.caps.clear();
        self.npmt = 0;
        self.pcr_pid = -1;
        self.cur_pcr = -1;
        self.br_pcr0 = -1;
        self.kf_cnt = 0;
        self.synced = false;
        self.carry_n = 0;
    }

    pub fn reset_in_cc(&mut self) {
        self.in_cc.fill(-1);
    }

    pub fn reset_out_cc(&mut self) {
        self.out_cc.fill(-1);
    }

    pub fn reset_sync(&mut self) {
        self.carry_n = 0;
        self.synced = false;
        self.in_cc.fill(-1);
    }

    #[inline]
    pub fn rcap(&self) -> usize {
        self.ring.len()
    }

    #[inline]
    pub fn ring_low(&self) -> u64 {
        let rcap = self.ring.len() as u64;
        if rcap <= (64 * TS) as u64 {
            return self.wpos;
        }
        let room = rcap - (64 * TS) as u64;
        self.wpos.saturating_sub(room)
    }

    pub fn ring_resize(&mut self, new_cap: usize) {
        let old_cap = self.ring.len();
        if old_cap == 0 {
            return;
        }
        let ncap = (new_cap / TS) * TS;
        if ncap < TS * 64 || ncap == old_cap {
            return;
        }
        let mut nr = vec![0u8; ncap];
        let keep = (self.wpos.min(old_cap as u64) as usize).min(ncap);
        let keep = keep - (keep % TS);
        let mut p = self.wpos - keep as u64;
        while p < self.wpos {
            let so = (p % old_cap as u64) as usize;
            let dso = (p % ncap as u64) as usize;
            let n = (old_cap - so)
                .min(ncap - dso)
                .min((self.wpos - p) as usize);
            nr[dso..dso + n].copy_from_slice(&self.ring[so..so + n]);
            p += n as u64;
        }
        self.ring = nr;
    }

    pub fn ring_copy_into(&self, dst: &mut Vec<u8>, mut from: u64, to: u64) {
        let rcap = self.ring.len();
        if rcap == 0 || from >= to {
            return;
        }
        dst.reserve((to - from) as usize);
        while from < to {
            let o = (from % rcap as u64) as usize;
            let n = (rcap - o).min((to - from) as usize);
            dst.extend_from_slice(&self.ring[o..o + n]);
            from += n as u64;
        }
    }

    /// Zero-copy view into up to 2 contiguous slices of the ring buffer.
    pub fn ring_read_chunk(&self, pos: u64, max_bytes: usize) -> Vec<u8> {
        let rcap = self.ring.len();
        if rcap == 0 || pos >= self.wpos {
            return Vec::new();
        }
        let avail = ((self.wpos - pos) as usize).min(max_bytes);
        let mut out = Vec::with_capacity(avail);
        let a = (pos % rcap as u64) as usize;
        let first = avail.min(rcap - a);
        out.extend_from_slice(&self.ring[a..a + first]);
        if avail > first {
            out.extend_from_slice(&self.ring[0..(avail - first)]);
        }
        out
    }

    pub fn has_psi(&self) -> bool {
        self.caps.iter().any(|c| c.pid == 0 && c.ndone > 0) && self.npmt > 0
    }

    pub fn prefix_build(&self, dst: &mut Vec<u8>) {
        if let Some(pat) = self.caps.iter().find(|c| c.pid == 0 && c.ndone > 0) {
            for k in 0..pat.ndone {
                dst.extend_from_slice(&pat.done[k]);
            }
            for i in 0..self.npmt {
                let pmt_p = self.pmt_pid[i];
                if let Some(c) = self.caps.iter().find(|c| c.pid == pmt_p && c.ndone > 0) {
                    for k in 0..c.ndone {
                        dst.extend_from_slice(&c.done[k]);
                    }
                }
            }
        }
    }

    /// Build PAT/PMT prefix with continuity counters aligned to the first packet at `start`.
    pub fn client_prefix(&self, start: u64) -> Vec<u8> {
        let mut pre = Vec::with_capacity(TS * 4);
        self.prefix_build(&mut pre);
        let np = pre.len() / TS;
        if np == 0 || self.ring.is_empty() {
            return pre;
        }
        let mut pids = [0u16; 16];
        let mut ccs = [0u8; 16];
        let mut found = [false; 16];
        let mut npid = 0usize;
        for k in 0..np {
            if npid >= 16 {
                break;
            }
            let p = &pre[k * TS..(k + 1) * TS];
            let pid = (((p[1] & 0x1F) as u16) << 8) | p[2] as u16;
            if !pids[..npid].contains(&pid) {
                pids[npid] = pid;
                npid += 1;
            }
        }
        let mut left = npid;
        let rcap = self.ring.len() as u64;
        let mut p = start;
        let limit = (start + 4 * 1024 * 1024).min(self.wpos);
        while p + TS as u64 <= limit && left > 0 {
            let off = (p % rcap) as usize;
            let q = &self.ring[off..off + TS];
            let pid = (((q[1] & 0x1F) as u16) << 8) | q[2] as u16;
            if (q[3] & 0x10) != 0 {
                for j in 0..npid {
                    if !found[j] && pids[j] == pid {
                        found[j] = true;
                        ccs[j] = q[3] & 0x0F;
                        left -= 1;
                    }
                }
            }
            p += TS as u64;
        }
        for j in 0..npid {
            if !found[j] {
                continue;
            }
            let mut c = ccs[j];
            for k in (0..np).rev() {
                let pkt = &mut pre[k * TS..(k + 1) * TS];
                let pid = (((pkt[1] & 0x1F) as u16) << 8) | pkt[2] as u16;
                if pid == pids[j] {
                    c = c.wrapping_sub(1) & 0x0F;
                    pkt[3] = (pkt[3] & 0xF0) | c;
                }
            }
        }
        pre
    }

    pub fn kf_age(&self, idx: usize, now_s: f64) -> f64 {
        let e = self.kf[idx];
        if e.pcr >= 0 && self.cur_pcr >= 0 {
            let d = ((self.cur_pcr - e.pcr + PCR_WRAP) % PCR_WRAP) as f64 / PCR_HZ;
            if (0.0..60.0).contains(&d) {
                return d;
            }
        }
        now_s - e.wall
    }

    pub fn pick_start(&self, now_s: f64) -> u64 {
        let lo = self.ring_low();
        if self.wpos == 0 {
            return 0;
        }
        let mut cand: Option<u64> = None;
        for i in 0..self.kf_cnt {
            let idx = (self.kf_head + KF_N - 1 - i) % KF_N;
            let p = self.kf[idx].pos;
            if p < lo || p >= self.wpos {
                break;
            }
            cand = Some(p);
            if self.kf_age(idx, now_s) >= START_BURST_S {
                return p;
            }
        }
        if let Some(p) = cand {
            return p;
        }
        let back = ((self.wpos - lo) as usize).min(512 * 1024);
        let back = back - (back % TS);
        self.wpos - back as u64
    }

    fn cap_index(&mut self, pid: u16) -> Option<usize> {
        if let Some(idx) = self.caps.iter().position(|c| c.pid == pid) {
            return Some(idx);
        }
        if self.caps.len() >= 9 {
            return None;
        }
        self.caps.push(PsiCap::new(pid));
        Some(self.caps.len() - 1)
    }

    fn parse_pat(&mut self, sec: &[u8], sl: usize) {
        let end = (3 + sl).saturating_sub(4).min(sec.len());
        let mut npids = [0u16; 8];
        let mut npnr = [0u16; 8];
        let mut n = 0usize;
        let mut i = 8usize;
        while i + 4 <= end && n < 8 {
            let pnr = ((sec[i] as u16) << 8) | sec[i + 1] as u16;
            let pid = (((sec[i + 2] & 0x1F) as u16) << 8) | sec[i + 3] as u16;
            i += 4;
            if pnr == 0 {
                continue;
            }
            npnr[n] = pnr;
            npids[n] = pid;
            n += 1;
        }
        for k in 0..self.npmt {
            let old = self.pmt_pid[k];
            if !npids[..n].contains(&old) && self.kind[old as usize] == K_PMT {
                self.kind[old as usize] = K_NONE;
            }
        }
        if sec.len() >= 5 {
            self.tsid = ((sec[3] as u16) << 8) | sec[4] as u16;
        }
        self.npmt = n;
        for k in 0..n {
            self.pmt_pid[k] = npids[k];
            self.pnr[k] = npnr[k];
            self.kind[npids[k] as usize] = K_PMT;
        }
    }

    fn parse_pmt(&mut self, sec: &[u8], sl: usize) {
        let end = (3 + sl).saturating_sub(4).min(sec.len());
        if end < 12 {
            return;
        }
        let pcr = (((sec[8] & 0x1F) as i32) << 8) | sec[9] as i32;
        let pil = (((sec[10] & 0x0F) as usize) << 8) | sec[11] as usize;
        if pcr != 0x1FFF {
            self.pcr_pid = pcr;
        }
        let mut i = 12 + pil;
        while i + 5 <= end {
            let st = sec[i];
            let pid = (((sec[i + 1] & 0x1F) as usize) << 8) | sec[i + 2] as usize;
            let el = (((sec[i + 3] & 0x0F) as usize) << 8) | sec[i + 4] as usize;
            let mut k = K_OTHER;
            if is_video_stype(st) {
                k = K_VIDEO;
            } else if is_audio_stype(st) {
                k = K_AUDIO;
            } else if st == 0x06 {
                let mut d = i + 5;
                let dend = (i + 5 + el).min(end);
                while d + 2 <= dend {
                    let tag = sec[d];
                    let dlen = sec[d + 1] as usize;
                    if matches!(tag, 0x6A | 0x7A | 0x7C | 0x7F) {
                        k = K_AUDIO;
                    }
                    if tag == 0x05
                        && d + 6 <= dend
                        && (&sec[d + 2..d + 6] == b"AC-3" || &sec[d + 2..d + 6] == b"EAC3")
                    {
                        k = K_AUDIO;
                    }
                    d += 2 + dlen;
                }
            }
            if pid < 8191 && self.kind[pid] != K_PMT {
                self.kind[pid] = k;
                self.stype[pid] = st;
            }
            i += 5 + el;
        }
    }

    fn psi_push(&mut self, pid: u16, p: &[u8; TS], off: usize, pusi: bool) {
        let Some(ci) = self.cap_index(pid) else {
            return;
        };
        if off >= TS {
            return;
        }
        let complete = {
            let c = &mut self.caps[ci];
            if pusi {
                let s = off + 1 + p[off] as usize;
                c.need = 0;
                if s + 3 > TS {
                    return;
                }
                let sl = (((p[s + 1] & 0x0F) as usize) << 8) | p[s + 2] as usize;
                if 3 + sl > c.sec.len() || sl < 9 {
                    return;
                }
                // Fast-path version_number skip when single-packet & already captured!
                if s + 6 <= TS && c.ndone > 0 {
                    let table_id = p[s];
                    let ver_byte = p[s + 5];
                    let cur_next = ver_byte & 1;
                    let ver = (ver_byte >> 1) & 0x1F;
                    if cur_next == 1
                        && c.last_version == Some(ver)
                        && ((pid == 0 && table_id == 0x00) || (pid != 0 && table_id == 0x02))
                    {
                        return;
                    }
                }
                c.need = 3 + sl;
                let take = (TS - s).min(c.need);
                c.sec[..take].copy_from_slice(&p[s..s + take]);
                c.have = take;
                c.npk = 0;
                c.pk[c.npk].copy_from_slice(p);
                c.npk += 1;
            } else if c.need > 0 && c.have < c.need && c.npk < c.pk.len() {
                let take = (TS - off).min(c.need - c.have);
                c.sec[c.have..c.have + take].copy_from_slice(&p[off..off + take]);
                c.have += take;
                c.pk[c.npk].copy_from_slice(p);
                c.npk += 1;
            } else {
                return;
            }
            c.need > 0 && c.have >= c.need
        };

        if complete {
            let need = self.caps[ci].need;
            let sl = need - 3;
            let table_id = self.caps[ci].sec[0];
            let ver_byte = self.caps[ci].sec[5];
            let cur_next = ver_byte & 1;
            let ver = (ver_byte >> 1) & 0x1F;

            // Check version before CRC if multi-packet section already cached
            if cur_next == 1
                && self.caps[ci].ndone > 0
                && self.caps[ci].last_version == Some(ver)
                && ((pid == 0 && table_id == 0x00) || (pid != 0 && table_id == 0x02))
            {
                self.caps[ci].need = 0;
                return;
            }

            if crc32_mpeg(&self.caps[ci].sec[..need]) == 0 {
                let mut sec_copy = [0u8; 1024];
                sec_copy[..need].copy_from_slice(&self.caps[ci].sec[..need]);
                {
                    let c = &mut self.caps[ci];
                    for k in 0..c.npk {
                        c.done[k] = c.pk[k];
                    }
                    c.ndone = c.npk;
                    if cur_next == 1 {
                        c.last_version = Some(ver);
                    }
                }
                if pid == 0 && table_id == 0x00 {
                    self.parse_pat(&sec_copy[..need], sl);
                } else if table_id == 0x02 {
                    self.parse_pmt(&sec_copy[..need], sl);
                }
            }
            self.caps[ci].need = 0;
        }
    }

    /// Process a single 188-byte TS packet in place. Returns `(keep_packet, is_keyframe)`.
    #[allow(dead_code)]
    pub fn process_packet(&mut self, p: &mut [u8; TS], hls: bool) -> (bool, bool) {
        let (keep, kf) = self.process_packet_at(p, hls, self.wpos);
        (keep, kf.is_some())
    }

    /// Process a single 188-byte TS packet at stream position `pkt_wpos`.
    /// Returns `(keep_packet, Option<(kf_pusi_wpos, kf_pcr)>)`.
    pub fn process_packet_at(
        &mut self,
        p: &mut [u8; TS],
        hls: bool,
        pkt_wpos: u64,
    ) -> (bool, Option<(u64, i64)>) {
        let pid = (((p[1] & 0x1F) as usize) << 8) | p[2] as usize;
        if (pid == 0x11 && self.drop_sdt) || (pid == 0x12 && self.drop_eit) {
            return (false, None);
        }
        self.packets += 1;
        if pid == 0x1FFF {
            return (true, None);
        }

        let tei = (p[1] & 0x80) != 0;
        let pusi = (p[1] & 0x40) != 0;
        let scr = (p[3] & 0xC0) != 0;
        let afc = (p[3] >> 4) & 3;
        let cc = (p[3] & 15) as i8;
        let mut off = 4usize;
        let mut rai = false;
        let mut disc = false;

        if (afc & 2) != 0 {
            let al = p[4] as usize;
            off = 5 + al;
            if al > 0 {
                let fl = p[5];
                disc = (fl & 0x80) != 0;
                rai = (fl & 0x40) != 0;
                if (fl & 0x10) != 0 && al >= 7 {
                    let base = ((p[6] as i64) << 25)
                        | ((p[7] as i64) << 17)
                        | ((p[8] as i64) << 9)
                        | ((p[9] as i64) << 1)
                        | ((p[10] as i64) >> 7);
                    let pcr = base * 300 + ((((p[10] & 1) as i64) << 8) | p[11] as i64);
                    if self.pcr_pid < 0 {
                        self.pcr_pid = pid as i32;
                    }
                    if pid as i32 == self.pcr_pid {
                        self.cur_pcr = pcr;
                    }
                }
                if disc && hls {
                    p[5] &= 0x7F;
                    disc = false;
                }
            }
            if off > TS {
                off = TS;
            }
        }

        if tei {
            self.in_cc[pid] = -1;
            return (true, None);
        }

        if (afc & 1) != 0 {
            let prev = self.in_cc[pid];
            if prev >= 0 && !disc && cc != ((prev + 1) & 15) && cc != prev {
                self.cc_err += 1;
            }
            self.in_cc[pid] = cc;
            if hls {
                let o = if self.out_cc[pid] < 0 {
                    cc
                } else {
                    (self.out_cc[pid] + 1) & 15
                };
                self.out_cc[pid] = o;
                p[3] = (p[3] & 0xF0) | (o as u8);
            }
        } else if hls && self.out_cc[pid] >= 0 {
            p[3] = (p[3] & 0xF0) | (self.out_cc[pid] as u8);
        }

        if scr {
            self.scr_win = true;
        }

        let mut kind = self.kind[pid];
        if !scr && (afc & 1) != 0 && (pid == 0 || kind == K_PMT) {
            self.psi_push(pid as u16, p, off, pusi);
        }

        if pusi && !scr && (afc & 1) != 0 && off + 4 <= TS {
            let startcode = p[off] == 0 && p[off + 1] == 0 && p[off + 2] == 1;
            if kind == K_VIDEO || kind == K_AUDIO {
                if !startcode {
                    self.pes_err += 1;
                }
            } else if kind == K_NONE && startcode && pid > 0x1F && self.npmt == 0 {
                let sid = p[off + 3];
                if (0xE0..=0xEF).contains(&sid) {
                    kind = K_VIDEO;
                    self.kind[pid] = K_VIDEO;
                } else if (0xC0..=0xDF).contains(&sid) || sid == 0xBD {
                    kind = K_AUDIO;
                    self.kind[pid] = K_AUDIO;
                }
            }
        }

        let mut kf_hit: Option<(u64, i64)> = None;
        if kind == K_VIDEO && !scr && (afc & 1) != 0 {
            let st = self.stype[pid];
            let pid16 = pid as u16;
            if pusi {
                if self.vid_la_pid == pid16 {
                    self.vid_la_rem = 0;
                    self.vid_la_tail_len = 0;
                }
                match pes_check_kf(p, off, st) {
                    Some(true) => kf_hit = Some((pkt_wpos, self.cur_pcr)),
                    Some(false) => {
                        if rai && st == 0 {
                            kf_hit = Some((pkt_wpos, self.cur_pcr));
                        }
                    }
                    None => {
                        if rai {
                            kf_hit = Some((pkt_wpos, self.cur_pcr));
                        } else {
                            // Look ahead up to 6 TS packets (covers UHD AUD + HDR10/HLG SEI before VPS/SPS/IDR)
                            self.vid_la_pid = pid16;
                            self.vid_la_rem = 6;
                            self.vid_la_pos = pkt_wpos;
                            self.vid_la_pcr = self.cur_pcr;
                            let start = if off + 9 <= TS
                                && p[off] == 0
                                && p[off + 1] == 0
                                && p[off + 2] == 1
                            {
                                (off + 9 + p[off + 8] as usize).min(TS)
                            } else {
                                TS
                            };
                            let tlen = (TS - start).min(3);
                            if tlen > 0 {
                                self.vid_la_tail[..tlen].copy_from_slice(&p[TS - tlen..TS]);
                            }
                            self.vid_la_tail_len = tlen as u8;
                        }
                    }
                }
            } else if self.vid_la_rem > 0 && self.vid_la_pid == pid16 {
                self.vid_la_rem -= 1;
                if off < TS {
                    let payload = &p[off..TS];
                    let mut found: Option<bool> = None;
                    let tlen = self.vid_la_tail_len as usize;
                    if tlen > 0 {
                        let mut bridge = [0u8; 6];
                        let hlen = payload.len().min(3);
                        bridge[..tlen].copy_from_slice(&self.vid_la_tail[..tlen]);
                        bridge[tlen..tlen + hlen].copy_from_slice(&payload[..hlen]);
                        found = scan_video_nal(&bridge[..tlen + hlen], st);
                    }
                    if found.is_none() {
                        found = scan_video_nal(payload, st);
                    }
                    match found {
                        Some(true) => {
                            kf_hit = Some((self.vid_la_pos, self.vid_la_pcr));
                            self.vid_la_rem = 0;
                            self.vid_la_tail_len = 0;
                        }
                        Some(false) => {
                            self.vid_la_rem = 0;
                            self.vid_la_tail_len = 0;
                        }
                        None => {
                            let nt = payload.len().min(3);
                            self.vid_la_tail[..nt].copy_from_slice(&payload[payload.len() - nt..]);
                            self.vid_la_tail_len = nt as u8;
                        }
                    }
                }
            }
        }

        (true, kf_hit)
    }

    /// Feed raw MPEG-TS bytes directly into the ring buffer, returning:
    /// `(processed_bytes_for_hls_out, keyframes)` where `processed_bytes_for_hls_out` is only
    /// populated when `need_out_buf` is true (or read back directly from ring).
    pub fn feed(
        &mut self,
        data: &[u8],
        hls_in: bool,
        now_s: f64,
        out_packets: &mut Vec<u8>,
        kfs: &mut Vec<KeyframeHit>,
    ) -> usize {
        out_packets.clear();
        kfs.clear();
        if data.is_empty() || self.ring.is_empty() {
            return 0;
        }
        self.win_bytes += data.len() as u64;

        let rcap = self.ring.len();
        let base_wpos = self.wpos;
        let mut produced = 0usize;

        // Helper closure-style macro for committing one packet into ring + out_packets
        macro_rules! commit_pkt {
            ($pkt:expr) => {{
                let cur_pos = base_wpos + produced as u64;
                let (keep, kf) = self.process_packet_at($pkt, hls_in, cur_pos);
                if keep {
                    if let Some((kf_pos, kf_pcr)) = kf {
                        let (offset, back_bytes) = if kf_pos >= base_wpos {
                            ((kf_pos - base_wpos) as usize, 0)
                        } else {
                            (0, (base_wpos - kf_pos) as usize)
                        };
                        kfs.push(KeyframeHit {
                            offset,
                            back_bytes,
                            pos: kf_pos,
                            pcr: kf_pcr,
                        });
                    }
                    // Write directly into circular ring
                    let ro = (cur_pos % rcap as u64) as usize;
                    if ro + TS <= rcap {
                        self.ring[ro..ro + TS].copy_from_slice($pkt);
                    } else {
                        let first = rcap - ro;
                        self.ring[ro..rcap].copy_from_slice(&$pkt[..first]);
                        self.ring[..TS - first].copy_from_slice(&$pkt[first..]);
                    }
                    out_packets.extend_from_slice($pkt);
                    produced += TS;
                }
            }};
        }

        // Fast path: already synced, no carry, starts with 0x47 -> zero scratch allocation!
        if self.carry_n == 0 && self.synced && data.len() >= TS && data[0] == 0x47 {
            let mut i = 0usize;
            while i + TS <= data.len() {
                if data[i] != 0x47 {
                    self.sync_losses += 1;
                    self.synced = false;
                    // Fall back to resync loop from `i`
                    let rem_slice = &data[i..];
                    produced += self.feed_slow(rem_slice, hls_in, base_wpos, base_wpos + produced as u64, out_packets, kfs);
                    self.finalize_feed(base_wpos, produced, now_s, kfs);
                    return produced;
                }
                let mut pkt = [0u8; TS];
                pkt.copy_from_slice(&data[i..i + TS]);
                commit_pkt!(&mut pkt);
                i += TS;
            }
            let rem = data.len() - i;
            if rem > 0 {
                self.carry[..rem].copy_from_slice(&data[i..]);
                self.carry_n = rem;
            }
            self.finalize_feed(base_wpos, produced, now_s, kfs);
            return produced;
        }

        // General path: stitch carry + data
        let mut combined = Vec::with_capacity(self.carry_n + data.len());
        combined.extend_from_slice(&self.carry[..self.carry_n]);
        combined.extend_from_slice(data);
        self.carry_n = 0;
        produced += self.feed_slow(&combined, hls_in, base_wpos, base_wpos, out_packets, kfs);
        self.finalize_feed(base_wpos, produced, now_s, kfs);
        produced
    }

    fn feed_slow(
        &mut self,
        s: &[u8],
        hls_in: bool,
        base_wpos: u64,
        mut wpos: u64,
        out_packets: &mut Vec<u8>,
        kfs: &mut Vec<KeyframeHit>,
    ) -> usize {
        let len = s.len();
        let rcap = self.ring.len();
        let mut i = 0usize;
        let mut added = 0usize;
        while i + TS <= len {
            if s[i] != 0x47 || (!self.synced && i + 2 * TS <= len && s[i + TS] != 0x47) {
                if self.synced {
                    self.sync_losses += 1;
                }
                self.synced = false;
                i += 1;
                continue;
            }
            self.synced = true;
            let mut pkt = [0u8; TS];
            pkt.copy_from_slice(&s[i..i + TS]);
            let (keep, kf) = self.process_packet_at(&mut pkt, hls_in, wpos);
            if keep {
                if let Some((kf_pos, kf_pcr)) = kf {
                    let (offset, back_bytes) = if kf_pos >= base_wpos {
                        ((kf_pos - base_wpos) as usize, 0)
                    } else {
                        (0, (base_wpos - kf_pos) as usize)
                    };
                    kfs.push(KeyframeHit {
                        offset,
                        back_bytes,
                        pos: kf_pos,
                        pcr: kf_pcr,
                    });
                }
                let ro = (wpos % rcap as u64) as usize;
                if ro + TS <= rcap {
                    self.ring[ro..ro + TS].copy_from_slice(&pkt);
                } else {
                    let first = rcap - ro;
                    self.ring[ro..rcap].copy_from_slice(&pkt[..first]);
                    self.ring[..TS - first].copy_from_slice(&pkt[first..]);
                }
                out_packets.extend_from_slice(&pkt);
                wpos += TS as u64;
                added += TS;
            }
            i += TS;
        }
        let rem = (len - i).min(TS - 1);
        if rem > 0 {
            self.carry[..rem].copy_from_slice(&s[len - rem..]);
            self.carry_n = rem;
        }
        added
    }

    fn finalize_feed(&mut self, base_wpos: u64, produced: usize, now_s: f64, kfs: &[KeyframeHit]) {
        if produced == 0 {
            return;
        }
        for hit in kfs {
            if self.kf_cnt > 0 {
                let prev = (self.kf_head + KF_N - 1) % KF_N;
                let mut iv = -1.0f64;
                if hit.pcr >= 0 && self.kf[prev].pcr >= 0 {
                    iv = ((hit.pcr - self.kf[prev].pcr + PCR_WRAP) % PCR_WRAP) as f64 / PCR_HZ;
                }
                if !(0.0..=30.0).contains(&iv) {
                    iv = now_s - self.kf[prev].wall;
                }
                if iv > 0.2 && iv <= 30.0 {
                    self.gop = if iv > self.gop {
                        iv
                    } else {
                        0.95 * self.gop + 0.05 * iv
                    };
                }
            }
            self.kf[self.kf_head] = KfEntry {
                pos: hit.pos,
                pcr: hit.pcr,
                wall: now_s,
            };
            self.kf_head = (self.kf_head + 1) % KF_N;
            if self.kf_cnt < KF_N {
                self.kf_cnt += 1;
            }
        }
        self.wpos = base_wpos + produced as u64;
        if self.pcr_pid >= 0 && self.cur_pcr >= 0 {
            if self.br_pcr0 < 0 {
                self.br_pcr0 = self.cur_pcr;
                self.br_pos0 = self.wpos;
            } else {
                let dt = ((self.cur_pcr - self.br_pcr0 + PCR_WRAP) % PCR_WRAP) as f64 / PCR_HZ;
                if !(0.0..=30.0).contains(&dt) {
                    self.br_pcr0 = -1;
                } else if dt >= 2.0 {
                    self.pcr_bitrate = (self.wpos - self.br_pos0) as f64 * 8.0 / dt;
                    self.br_pcr0 = self.cur_pcr;
                    self.br_pos0 = self.wpos;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pat_packet(pmt_pid: u16, version: u8, cc: u8) -> [u8; TS] {
        let mut p = [0xFFu8; TS];
        p[0] = 0x47;
        p[1] = 0x40; // PUSI=1, PID=0
        p[2] = 0x00;
        p[3] = 0x10 | (cc & 0x0F);
        p[4] = 0x00; // pointer_field
        let sec = &mut p[5..];
        sec[0] = 0x00; // table_id PAT
        let sl = 13usize; // 5 hdr + 4 entry + 4 crc
        sec[1] = 0xB0 | ((sl >> 8) as u8 & 0x0F);
        sec[2] = (sl & 0xFF) as u8;
        sec[3] = 0x00;
        sec[4] = 0x01; // tsid=1
        sec[5] = 0xC1 | ((version & 0x1F) << 1);
        sec[6] = 0x00;
        sec[7] = 0x00;
        // Program 1 -> pmt_pid
        sec[8] = 0x00;
        sec[9] = 0x01;
        sec[10] = 0xE0 | ((pmt_pid >> 8) as u8 & 0x1F);
        sec[11] = (pmt_pid & 0xFF) as u8;
        let crc = crc32_mpeg(&sec[..12]);
        sec[12..16].copy_from_slice(&crc.to_be_bytes());
        p
    }

    fn make_pmt_packet(pmt_pid: u16, video_pid: u16, stype: u8, version: u8, cc: u8) -> [u8; TS] {
        let mut p = [0xFFu8; TS];
        p[0] = 0x47;
        p[1] = 0x40 | ((pmt_pid >> 8) as u8 & 0x1F);
        p[2] = (pmt_pid & 0xFF) as u8;
        p[3] = 0x10 | (cc & 0x0F);
        p[4] = 0x00;
        let sec = &mut p[5..];
        sec[0] = 0x02; // PMT
        let sl = 18usize; // 9 + 5 + 4
        sec[1] = 0xB0 | ((sl >> 8) as u8 & 0x0F);
        sec[2] = (sl & 0xFF) as u8;
        sec[3] = 0x00;
        sec[4] = 0x01; // program_number=1
        sec[5] = 0xC1 | ((version & 0x1F) << 1);
        sec[6] = 0x00;
        sec[7] = 0x00;
        sec[8] = 0xE0 | ((video_pid >> 8) as u8 & 0x1F);
        sec[9] = (video_pid & 0xFF) as u8; // PCR PID
        sec[10] = 0xF0;
        sec[11] = 0x00; // program_info_length = 0
        sec[12] = stype;
        sec[13] = 0xE0 | ((video_pid >> 8) as u8 & 0x1F);
        sec[14] = (video_pid & 0xFF) as u8;
        sec[15] = 0xF0;
        sec[16] = 0x00;
        let crc = crc32_mpeg(&sec[..17]);
        sec[17..21].copy_from_slice(&crc.to_be_bytes());
        p
    }

    #[test]
    fn parses_pat_pmt_and_skips_unchanged_version() {
        let mut ts = TsEngine::new();
        ts.alloc_ring(TS * 128);
        let mut pat = make_pat_packet(0x100, 1, 0);
        let mut pmt = make_pmt_packet(0x100, 0x101, 0x1B, 1, 0);
        let mut out = Vec::new();
        let mut kfs = Vec::new();
        let mut buf = Vec::new();
        buf.extend_from_slice(&pat);
        buf.extend_from_slice(&pmt);
        ts.feed(&buf, false, 1.0, &mut out, &mut kfs);

        assert!(ts.has_psi());
        assert_eq!(ts.pmt_pid[0], 0x100);
        assert_eq!(ts.kind[0x101], K_VIDEO);
        assert_eq!(ts.stype[0x101], 0x1B);
        assert_eq!(ts.pcr_pid, 0x101);

        // Corrupt CRC on same version -> fast-path version skip should leave parsed state intact
        pat[20] ^= 0xFF;
        pat[3] = 0x11;
        ts.process_packet(&mut pat, false);
        assert_eq!(ts.pmt_pid[0], 0x100);

        // New version updates PMT pid
        let mut pat2 = make_pat_packet(0x200, 2, 2);
        ts.process_packet(&mut pat2, false);
        assert_eq!(ts.pmt_pid[0], 0x200);
        let _ = &mut pmt;
    }

    #[test]
    fn detects_h264_keyframe_across_second_ts_packet() {
        let mut ts = TsEngine::new();
        ts.alloc_ring(TS * 128);
        ts.kind[0x101] = K_VIDEO;
        ts.stype[0x101] = 0x1B;

        // First TS packet: PES header + SEI NAL only (no IDR yet)
        let mut p1 = [0x00u8; TS];
        p1[0] = 0x47;
        p1[1] = 0x41; // PUSI=1, PID=0x101
        p1[2] = 0x01;
        p1[3] = 0x10;
        p1[4] = 0x00;
        p1[5] = 0x00;
        p1[6] = 0x01;
        p1[7] = 0xE0; // video stream
        p1[12] = 0; // PES header data len
        p1[13] = 0x00;
        p1[14] = 0x00;
        p1[15] = 0x01;
        p1[16] = 0x06; // SEI NAL (non-conclusive)
        for b in &mut p1[17..TS] {
            *b = 0xAA;
        }

        // Second TS packet: SPS NAL (type 7)
        let mut p2 = [0xAAu8; TS];
        p2[0] = 0x47;
        p2[1] = 0x01; // PUSI=0, PID=0x101
        p2[2] = 0x01;
        p2[3] = 0x11;
        p2[10] = 0x00;
        p2[11] = 0x00;
        p2[12] = 0x01;
        p2[13] = 0x67; // SPS (NAL type 7)

        let (_, kf1) = ts.process_packet(&mut p1, false);
        let (_, kf2) = ts.process_packet(&mut p2, false);
        assert!(!kf1);
        assert!(kf2);
    }

    #[test]
    fn ring_resize_preserves_recent_bytes() {
        let mut ts = TsEngine::new();
        ts.alloc_ring(TS * 64);
        let mut data = vec![0u8; TS * 80];
        for i in 0..80 {
            data[i * TS] = 0x47;
            data[i * TS + 1] = 0x1F;
            data[i * TS + 2] = 0xFF; // null packet
            data[i * TS + 3] = 0x10;
            data[i * TS + 4] = i as u8;
        }
        let mut out = Vec::new();
        let mut kfs = Vec::new();
        ts.feed(&data, false, 1.0, &mut out, &mut kfs);
        assert_eq!(ts.wpos, (TS * 80) as u64);

        ts.ring_resize(TS * 128);
        let tail = ts.ring_read_chunk(ts.wpos - TS as u64, TS);
        assert_eq!(tail.len(), TS);
        assert_eq!(tail[4], 79);
    }

    #[test]
    fn detects_hevc_uhd_keyframe_across_hdr_sei_and_split_startcode_at_pusi_offset() {
        let mut ts = TsEngine::new();
        ts.alloc_ring(TS * 128);
        ts.kind[0x101] = K_VIDEO;
        ts.stype[0x101] = 0x24; // HEVC

        // Packet 0: PUSI=1 + PES header + AUD + start of HDR10 PREFIX_SEI
        let mut p1 = [0xAAu8; TS];
        p1[0] = 0x47;
        p1[1] = 0x41; // PUSI=1, PID=0x101
        p1[2] = 0x01;
        p1[3] = 0x10;
        p1[4] = 0x00;
        p1[5] = 0x00;
        p1[6] = 0x01;
        p1[7] = 0xE0;
        p1[12] = 0; // PES header data len
        p1[13] = 0x00;
        p1[14] = 0x00;
        p1[15] = 0x01;
        p1[16] = 35 << 1; // HEVC AUD_NUT
        p1[17] = 0x01;
        p1[18] = 0x00;
        p1[19] = 0x00;
        p1[20] = 0x01;
        p1[21] = 39 << 1; // HEVC PREFIX_SEI_NUT (non-conclusive HDR metadata)

        // Packet 1: continuation of HDR10 SEI, ending with split 0x00 0x00 start code
        let mut p2 = [0xBBu8; TS];
        p2[0] = 0x47;
        p2[1] = 0x01; // PUSI=0
        p2[2] = 0x01;
        p2[3] = 0x11;
        p2[TS - 2] = 0x00;
        p2[TS - 1] = 0x00;

        // Packet 2: starts with 0x01 + HEVC VPS_NUT (32 << 1 = 0x40)
        let mut p3 = [0xCCu8; TS];
        p3[0] = 0x47;
        p3[1] = 0x01; // PUSI=0
        p3[2] = 0x01;
        p3[3] = 0x12;
        p3[4] = 0x01;
        p3[5] = 32 << 1; // HEVC VPS_NUT

        let mut buf = Vec::new();
        buf.extend_from_slice(&p1);
        buf.extend_from_slice(&p2);
        buf.extend_from_slice(&p3);

        let mut out = Vec::new();
        let mut kfs = Vec::new();
        ts.feed(&buf, false, 1.0, &mut out, &mut kfs);

        assert_eq!(kfs.len(), 1);
        // Keyframe MUST point back to Packet 0 (PUSI=1, offset 0), NOT Packet 2!
        assert_eq!(kfs[0].offset, 0);
        assert_eq!(kfs[0].back_bytes, 0);
        assert_eq!(kfs[0].pos, 0);
        assert_eq!(ts.kf[0].pos, 0);
    }
}
