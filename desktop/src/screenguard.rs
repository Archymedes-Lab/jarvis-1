//! Screen Guard's rules, before any capture exists (docs/architecture/SCREEN-GUARD.md).
//!
//! This module decides *whether* and *when* a frame may be taken, reduces a
//! frame to a fingerprint, and keeps the decisions. It never captures: the
//! capture and the model arrive in a later slice and must go through
//! `Guard::due`, which is where the privacy invariants live:
//! * nothing is taken unless the user turned Screen Guard on and has not
//!   paused it, and never while the screen is locked, on the secure desktop,
//!   or while the privacy seal is on (`Gate`);
//! * at most one frame per `MIN_GAP`, whatever the window churn, every
//!   `FAST` for `FAST_WINDOW` after a window change, every `STEADY` after
//!   that, nothing after `IDLE` without input (`Schedule`);
//! * a frame's pixels live in a `Frame`, which zeroes them when dropped;
//! * only decisions are kept, in memory, for `TTL` (`Decisions`). Nothing
//!   here touches disk.
//!
//! Times are seconds on a monotonic clock, passed in, so every rule is a pure
//! function the tests can drive.

/// The shortest gap between two frames, even when windows change faster.
pub const MIN_GAP: f64 = 2.0;
/// The interval for the first `FAST_WINDOW` seconds after a window change.
pub const FAST: f64 = 2.0;
pub const FAST_WINDOW: f64 = 60.0;
/// The interval while the same window stays in front.
pub const STEADY: f64 = 10.0;
/// No input for this long means nobody is looking: stop.
pub const IDLE: f64 = 60.0;
/// How long a warning stays for the user to review.
pub const TTL: f64 = 24.0 * 3600.0;
/// The most warnings kept, whatever their age.
pub const MAX_DECISIONS: usize = 500;
/// Fingerprints this close (bits of 64) are the same screen.
pub const SAME_SCREEN_BITS: u32 = 4;

/// Why a frame may not be taken. Every variant is a refusal; there is no
/// "allowed with conditions".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Block {
    Off,
    Paused,
    Locked,
    SecureDesktop,
    PrivacySeal,
    Idle,
    NotYet,
}

/// What the session looks like right now, read fresh before each frame.
/// Every field defaults to the refusing value, so a sensor that could not be
/// read blocks the capture instead of allowing it.
#[derive(Debug, Clone, Copy)]
pub struct Gate {
    pub enabled: bool,
    pub paused: bool,
    pub locked: bool,
    pub secure_desktop: bool,
    pub sealed: bool,
    /// Seconds since the last keyboard or mouse input; `None` when unknown.
    pub idle_for: Option<f64>,
}

impl Default for Gate {
    fn default() -> Self {
        Gate { enabled: false, paused: true, locked: true, secure_desktop: true, sealed: true, idle_for: None }
    }
}

impl Gate {
    pub fn check(&self) -> Result<(), Block> {
        if !self.enabled {
            return Err(Block::Off);
        }
        if self.paused {
            return Err(Block::Paused);
        }
        if self.locked {
            return Err(Block::Locked);
        }
        if self.secure_desktop {
            return Err(Block::SecureDesktop);
        }
        if self.sealed {
            return Err(Block::PrivacySeal);
        }
        match self.idle_for {
            Some(s) if s.is_finite() && (0.0..IDLE).contains(&s) => Ok(()),
            _ => Err(Block::Idle),
        }
    }
}

/// When the next frame is due: immediately after a window change, then every
/// `FAST`, then every `STEADY`, never closer than `MIN_GAP`.
#[derive(Debug, Default)]
pub struct Schedule {
    last_change: Option<f64>,
    last_frame: Option<f64>,
    pending_change: bool,
}

impl Schedule {
    /// The foreground window or its title changed.
    pub fn changed(&mut self, now: f64) {
        self.last_change = Some(now);
        self.pending_change = true;
    }

    fn interval(&self, now: f64) -> f64 {
        match self.last_change {
            Some(c) if now - c < FAST_WINDOW => FAST,
            _ => STEADY,
        }
    }

    fn due_at(&self, now: f64) -> bool {
        let Some(last) = self.last_frame else { return true };
        // A clock that went backwards is not "long ago": wait out MIN_GAP from now.
        let since = now - last;
        #[allow(clippy::neg_cmp_op_on_partial_ord)] // NaN must refuse too
        if !(since >= MIN_GAP) {
            return false;
        }
        self.pending_change || since >= self.interval(now)
    }

    fn taken(&mut self, now: f64) {
        self.last_frame = Some(now);
        self.pending_change = false;
    }
}

/// The gate and the schedule together: the only way to obtain permission for
/// a frame.
#[derive(Debug, Default)]
pub struct Guard {
    pub schedule: Schedule,
}

impl Guard {
    /// May a frame be taken now? On `Ok` the frame counts as taken, so a
    /// second call in the same instant is refused.
    pub fn due(&mut self, now: f64, gate: &Gate) -> Result<(), Block> {
        gate.check()?;
        if !self.schedule.due_at(now) {
            return Err(Block::NotYet);
        }
        self.schedule.taken(now);
        Ok(())
    }
}

/// Grayscale pixels that are zeroed when dropped, so a frame does not linger
/// in freed memory after the decision is made.
pub struct Frame {
    pub width: usize,
    pub height: usize,
    pixels: Vec<u8>,
}

impl Frame {
    pub fn new(width: usize, height: usize, pixels: Vec<u8>) -> Option<Frame> {
        (width > 0 && height > 0 && pixels.len() == width * height).then_some(Frame { width, height, pixels })
    }

    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    /// A 64-bit difference hash: the frame shrunk to 9 x 8 cells by
    /// averaging, each bit saying whether a cell is brighter than its right
    /// neighbour. Small changes (a clock, a cursor) move few bits; a new page
    /// moves many.
    pub fn fingerprint(&self) -> u64 {
        let (cols, rows) = (9usize, 8usize);
        let mut cells = [0u32; 72];
        for (r, row) in cells.chunks_mut(cols).enumerate() {
            let (y0, y1) = (r * self.height / rows, ((r + 1) * self.height / rows).max(r * self.height / rows + 1));
            for (c, cell) in row.iter_mut().enumerate() {
                let (x0, x1) = (c * self.width / cols, ((c + 1) * self.width / cols).max(c * self.width / cols + 1));
                let (mut sum, mut n) = (0u64, 0u64);
                for y in y0..y1.min(self.height) {
                    for x in x0..x1.min(self.width) {
                        sum += u64::from(self.pixels[y * self.width + x]);
                        n += 1;
                    }
                }
                *cell = (sum / n.max(1)) as u32;
            }
        }
        let mut hash = 0u64;
        for r in 0..rows {
            for c in 0..cols - 1 {
                hash = (hash << 1) | u64::from(cells[r * cols + c] > cells[r * cols + c + 1]);
            }
        }
        hash
    }
}

impl Frame {
    fn wipe(&mut self) {
        for b in self.pixels.iter_mut() {
            // Volatile so the compiler cannot drop the stores as dead.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub fn same_screen(a: u64, b: u64) -> bool {
    (a ^ b).count_ones() <= SAME_SCREEN_BITS
}

/// One decision: no pixels, no text from the screen.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub at: f64,
    pub label: String,
    pub confidence: f32,
    /// The foreground application's executable name, nothing more.
    pub app: String,
}

pub const BENIGN: &str = "benign";

/// Warnings kept for review for `TTL`, at most `MAX_DECISIONS`; the last
/// screen's fingerprint and label so an unchanged screen is not classified
/// again. Benign decisions are not kept.
#[derive(Debug, Default)]
pub struct Decisions {
    warnings: Vec<Decision>,
    last: Option<(u64, String)>,
}

impl Decisions {
    /// The label of the last screen if `fingerprint` is the same screen.
    pub fn reuse(&self, fingerprint: u64) -> Option<&str> {
        self.last.as_ref().filter(|(f, _)| same_screen(*f, fingerprint)).map(|(_, l)| l.as_str())
    }

    pub fn record(&mut self, fingerprint: u64, d: Decision) {
        self.last = Some((fingerprint, d.label.clone()));
        if d.label != BENIGN {
            self.warnings.push(d);
            if self.warnings.len() > MAX_DECISIONS {
                let excess = self.warnings.len() - MAX_DECISIONS;
                self.warnings.drain(..excess);
            }
        }
    }

    /// Drop warnings older than `TTL` (or from a clock that went backwards).
    pub fn expire(&mut self, now: f64) {
        self.warnings.retain(|d| d.at <= now && now - d.at < TTL);
    }

    pub fn warnings(&mut self, now: f64) -> &[Decision] {
        self.expire(now);
        &self.warnings
    }

    /// The user switched Screen Guard off or asked to forget: nothing stays.
    pub fn clear(&mut self) {
        self.warnings.clear();
        self.last = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open() -> Gate {
        Gate { enabled: true, paused: false, locked: false, secure_desktop: false, sealed: false, idle_for: Some(1.0) }
    }

    #[test]
    fn default_gate_refuses() {
        assert_eq!(Gate::default().check(), Err(Block::Off));
        let mut g = Guard::default();
        assert_eq!(g.due(0.0, &Gate::default()), Err(Block::Off));
    }

    #[test]
    fn every_refusal_blocks_alone() {
        assert_eq!(open().check(), Ok(()));
        type Set = fn(&mut Gate);
        let cases: [(Set, Block); 6] = [
            (|g| g.enabled = false, Block::Off),
            (|g| g.paused = true, Block::Paused),
            (|g| g.locked = true, Block::Locked),
            (|g| g.secure_desktop = true, Block::SecureDesktop),
            (|g| g.sealed = true, Block::PrivacySeal),
            (|g| g.idle_for = Some(IDLE), Block::Idle),
        ];
        for (set, want) in cases {
            let mut g = open();
            set(&mut g);
            assert_eq!(g.check(), Err(want));
        }
    }

    #[test]
    fn unknown_or_bad_idle_blocks() {
        for idle in [None, Some(f64::NAN), Some(f64::INFINITY), Some(-1.0)] {
            assert_eq!(Gate { idle_for: idle, ..open() }.check(), Err(Block::Idle), "{idle:?}");
        }
    }

    #[test]
    fn a_refused_gate_does_not_consume_the_schedule() {
        let mut g = Guard::default();
        assert_eq!(g.due(0.0, &Gate { locked: true, ..open() }), Err(Block::Locked));
        assert_eq!(g.due(0.0, &open()), Ok(()));
    }

    /// Frame times over `secs` with the given window-change times.
    fn run(changes: &[f64], secs: f64, step: f64) -> Vec<f64> {
        let mut g = Guard::default();
        let (mut out, mut t, mut ci) = (Vec::new(), 0.0, 0);
        while t <= secs {
            while ci < changes.len() && changes[ci] <= t {
                g.schedule.changed(changes[ci]);
                ci += 1;
            }
            if g.due(t, &open()).is_ok() {
                out.push(t);
            }
            t += step;
        }
        out
    }

    #[test]
    fn schedule_is_fast_after_a_change_then_steady() {
        let frames = run(&[0.0], 180.0, 0.5);
        let gaps: Vec<f64> = frames.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(frames.iter().filter(|t| **t < FAST_WINDOW).count() >= 29, "{frames:?}");
        assert!(gaps.iter().all(|g| *g >= MIN_GAP), "{gaps:?}");
        let late: Vec<f64> = frames.iter().copied().filter(|t| *t > FAST_WINDOW + MIN_GAP).collect();
        assert!(late.windows(2).all(|w| w[1] - w[0] >= STEADY), "{late:?}");
    }

    #[test]
    fn a_change_is_captured_at_once_but_never_closer_than_min_gap() {
        // Steady frames near 90 and 100; a change at 105.3 is captured on the
        // next tick, not at the steady 110.
        let frames = run(&[0.0, 105.3], 120.0, 0.1);
        assert!(frames.iter().any(|t| (105.3..105.5).contains(t)), "{frames:?}");
        // A change 0.3 s after a frame waits out MIN_GAP, then is captured.
        let frames = run(&[0.0, 100.3], 120.0, 0.1);
        let after: Vec<f64> = frames.iter().copied().filter(|t| *t > 100.0).collect();
        assert!(after[0] >= 100.3 && after[0] < 100.0 + MIN_GAP + 0.2, "{frames:?}");
        // Window churn every 0.1 s for 30 s: still at most one frame per MIN_GAP.
        let churn: Vec<f64> = (0..300).map(|i| f64::from(i) * 0.1).collect();
        let frames = run(&churn, 30.0, 0.1);
        assert!(frames.windows(2).all(|w| w[1] - w[0] >= MIN_GAP - 1e-9), "{frames:?}");
        assert!(frames.len() <= (30.0 / MIN_GAP) as usize + 1);
    }

    #[test]
    fn a_clock_going_backwards_waits() {
        let mut g = Guard::default();
        assert_eq!(g.due(100.0, &open()), Ok(()));
        g.schedule.changed(50.0);
        assert_eq!(g.due(50.0, &open()), Err(Block::NotYet));
        assert_eq!(g.due(f64::NAN, &open()), Err(Block::NotYet));
    }

    #[test]
    fn frame_rejects_wrong_sizes() {
        assert!(Frame::new(0, 4, vec![]).is_none());
        assert!(Frame::new(4, 4, vec![0; 15]).is_none());
        assert!(Frame::new(4, 4, vec![0; 16]).is_some());
    }

    fn gradient(w: usize, h: usize, shift: usize) -> Frame {
        let px = (0..w * h).map(|i| (((i % w) + shift) * 255 / (w + shift)) as u8).collect();
        Frame::new(w, h, px).unwrap()
    }

    #[test]
    fn fingerprint_sees_a_new_page_but_not_a_cursor() {
        let base = gradient(256, 160, 0);
        let mut px = base.pixels().to_vec();
        for p in px.iter_mut().take(6) {
            *p = 255; // a few changed pixels: cursor, clock
        }
        let cursor = Frame::new(256, 160, px).unwrap();
        assert!(same_screen(base.fingerprint(), cursor.fingerprint()));
        let reversed: Vec<u8> = base.pixels().iter().map(|p| 255 - p).collect();
        let page = Frame::new(256, 160, reversed).unwrap();
        assert!(!same_screen(base.fingerprint(), page.fingerprint()));
        // Tiny frames still produce a hash without panicking.
        let _ = Frame::new(1, 1, vec![9]).unwrap().fingerprint();
    }

    #[test]
    fn frame_is_zeroed_on_drop() {
        // Drop calls wipe(); run it on a live frame so the bytes can be read.
        let mut f = Frame::new(4, 4, vec![7; 16]).unwrap();
        f.wipe();
        assert!(f.pixels().iter().all(|b| *b == 0));
    }

    fn warn(at: f64) -> Decision {
        Decision { at, label: "fake_login".into(), confidence: 0.9, app: "chrome.exe".into() }
    }

    #[test]
    fn decisions_keep_warnings_only_and_expire_them() {
        let mut d = Decisions::default();
        d.record(1, Decision { label: BENIGN.into(), ..warn(0.0) });
        assert!(d.warnings(0.0).is_empty());
        assert_eq!(d.reuse(1), Some(BENIGN));
        d.record(0xFFFF, warn(10.0));
        assert_eq!(d.reuse(0xFFFF), Some("fake_login"));
        assert_eq!(d.reuse(1), None);
        assert_eq!(d.warnings(10.0 + TTL - 1.0).len(), 1);
        assert!(d.warnings(10.0 + TTL).is_empty());
        // A warning stamped in the future (clock stepped back) is not kept.
        d.record(2, warn(500.0));
        assert!(d.warnings(100.0).is_empty());
    }

    #[test]
    fn decisions_are_bounded_and_clearable() {
        let mut d = Decisions::default();
        for i in 0..MAX_DECISIONS + 50 {
            d.record(i as u64, warn(i as f64));
        }
        let w = d.warnings((MAX_DECISIONS + 50) as f64);
        assert_eq!(w.len(), MAX_DECISIONS);
        assert_eq!(w[0].at, 50.0);
        d.clear();
        assert!(d.warnings(0.0).is_empty());
        assert_eq!(d.reuse(0), None);
    }
}
