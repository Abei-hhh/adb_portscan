//! Threaded port scanner with two-pass timing, optional cancellation, and a structured event stream.
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::detect::{probe, AdbKind};
use crate::target::Target;
use crate::threads::{auto_threads, stack_size_for};

/// Progress reporting cadence (in scanned items).
const PROGRESS_EVERY: usize = 5_000;

// ──────────────────────────── Cancellation ────────────────────────────

/// Cooperative cancellation handle, shared across producers and the scanner.
///
/// Cloning is cheap (refcounted). Call [`CancellationToken::cancel`] from any thread
/// to signal an in-flight [`run`] / [`run_streaming`] to return as soon as possible.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

// ──────────────────────────── Events ──────────────────────────────────

#[derive(Debug, Clone)]
pub struct Hit {
    pub target: Target,
    pub port: u16,
    pub kind: AdbKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassSkipReason {
    /// Second pass skipped because an ADB hit was already found and `stop_on_first` is true.
    HitFound,
    /// Second pass skipped because the cancellation token was triggered.
    Cancelled,
}

/// Events emitted by [`run`] / [`run_streaming`] for progress reporting.
#[derive(Debug, Clone)]
pub enum ScanEvent {
    PassStarted {
        pass: u8,
        work_items: usize,
        timeout: Duration,
    },
    Progress {
        pass: u8,
        done: usize,
        total: usize,
    },
    PortHit(Hit),
    PassSkipped {
        pass: u8,
        remaining: usize,
        reason: PassSkipReason,
    },
    ThreadsSpawned {
        pass: u8,
        requested: usize,
        actual: usize,
    },
}

type EventCallback = Arc<dyn Fn(ScanEvent) + Send + Sync>;

// ──────────────────────────── Configuration ───────────────────────────

/// Configuration for a scan run. Construct via [`ScanCfg::builder`].
pub struct ScanCfg {
    pub targets: Vec<Target>,
    pub ports: Arc<Vec<u16>>,
    pub threads: usize,
    pub fast_timeout: Duration,
    pub slow_timeout: Duration,
    pub verify_timeout: Duration,
    pub verify_adb: bool,
    pub stop_on_first: bool,
    pub stack_size: usize,
    pub cancel: CancellationToken,
    pub on_event: Option<EventCallback>,
}

impl std::fmt::Debug for ScanCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanCfg")
            .field("targets", &self.targets.len())
            .field("ports", &self.ports.len())
            .field("threads", &self.threads)
            .field("fast_timeout", &self.fast_timeout)
            .field("slow_timeout", &self.slow_timeout)
            .field("verify_timeout", &self.verify_timeout)
            .field("verify_adb", &self.verify_adb)
            .field("stop_on_first", &self.stop_on_first)
            .field("stack_size", &self.stack_size)
            .field("cancel", &self.cancel)
            .field("on_event", &self.on_event.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

impl ScanCfg {
    /// Start a builder with sensible defaults; pass `targets` and `ports` upfront because
    /// they have no good default. Other fields can stay at their defaults.
    pub fn builder(targets: Vec<Target>, ports: Arc<Vec<u16>>) -> ScanCfgBuilder {
        ScanCfgBuilder {
            inner: ScanCfg {
                targets,
                ports,
                threads: 0, // 0 = pick automatically in build()
                fast_timeout: Duration::from_millis(100),
                slow_timeout: Duration::from_millis(800),
                verify_timeout: Duration::from_millis(800),
                verify_adb: true,
                stop_on_first: true,
                stack_size: 0,
                cancel: CancellationToken::new(),
                on_event: None,
            },
            threads_set: false,
            stack_set: false,
        }
    }
}

/// Builder for [`ScanCfg`].
pub struct ScanCfgBuilder {
    inner: ScanCfg,
    threads_set: bool,
    stack_set: bool,
}

impl std::fmt::Debug for ScanCfgBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanCfgBuilder").finish_non_exhaustive()
    }
}

impl ScanCfgBuilder {
    pub fn threads(mut self, n: usize) -> Self {
        self.inner.threads = n.max(1);
        if !self.stack_set {
            self.inner.stack_size = stack_size_for(self.inner.threads);
        }
        self.threads_set = true;
        self
    }
    pub fn stack_size(mut self, n: usize) -> Self {
        self.inner.stack_size = n.max(64 * 1024);
        self.stack_set = true;
        self
    }
    pub fn fast_timeout(mut self, d: Duration) -> Self {
        self.inner.fast_timeout = d;
        self
    }
    pub fn slow_timeout(mut self, d: Duration) -> Self {
        self.inner.slow_timeout = d;
        self
    }
    pub fn verify_timeout(mut self, d: Duration) -> Self {
        self.inner.verify_timeout = d;
        self
    }
    pub fn verify_adb(mut self, v: bool) -> Self {
        self.inner.verify_adb = v;
        self
    }
    pub fn stop_on_first(mut self, v: bool) -> Self {
        self.inner.stop_on_first = v;
        self
    }
    pub fn cancel(mut self, t: CancellationToken) -> Self {
        self.inner.cancel = t;
        self
    }
    pub fn on_event<F>(mut self, f: F) -> Self
    where
        F: Fn(ScanEvent) + Send + Sync + 'static,
    {
        self.inner.on_event = Some(Arc::new(f));
        self
    }

    pub fn build(mut self) -> ScanCfg {
        if !self.threads_set {
            let work_items = self
                .inner
                .targets
                .len()
                .saturating_mul(self.inner.ports.len())
                .max(1);
            let d = auto_threads(work_items);
            self.inner.threads = d.chosen;
            if !self.stack_set {
                self.inner.stack_size = d.stack_bytes;
            }
        } else if self.inner.stack_size == 0 {
            self.inner.stack_size = stack_size_for(self.inner.threads);
        }
        self.inner
    }
}

// ──────────────────────────── Internals ───────────────────────────────

#[derive(Clone)]
struct Work {
    target_idx: usize,
    port: u16,
}

#[derive(PartialEq, Eq)]
enum ConnectOutcome {
    Open,
    Closed,
    Timeout,
}

fn try_connect(addr: SocketAddr, timeout: Duration) -> ConnectOutcome {
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(stream) => {
            // Aggressively close to free the local ephemeral port; on Windows the
            // TIME_WAIT pool is small and accumulating sockets stalls later connects.
            let _ = stream.shutdown(std::net::Shutdown::Both);
            drop(stream);
            ConnectOutcome::Open
        }
        Err(e) => match e.kind() {
            ErrorKind::TimedOut | ErrorKind::WouldBlock => ConnectOutcome::Timeout,
            _ => ConnectOutcome::Closed,
        },
    }
}

fn emit(cb: &Option<EventCallback>, ev: ScanEvent) {
    if let Some(f) = cb {
        f(ev);
    }
}

fn should_stop(local: &AtomicBool, cancel: &CancellationToken) -> bool {
    local.load(Ordering::Relaxed) || cancel.is_cancelled()
}

// ──────────────────────────── Public entry points ─────────────────────

/// Run a scan to completion, returning every confirmed hit.
pub fn run(cfg: ScanCfg) -> Vec<Hit> {
    let work: Vec<Work> = cfg
        .targets
        .iter()
        .enumerate()
        .flat_map(|(ti, _)| {
            cfg.ports.iter().map(move |&p| Work {
                target_idx: ti,
                port: p,
            })
        })
        .collect();
    let total = work.len();
    if total == 0 {
        return Vec::new();
    }
    if cfg.cancel.is_cancelled() {
        return Vec::new();
    }

    emit(
        &cfg.on_event,
        ScanEvent::PassStarted {
            pass: 1,
            work_items: total,
            timeout: cfg.fast_timeout,
        },
    );

    let cfg = Arc::new(cfg);
    let work = Arc::new(work);
    let hits: Arc<Mutex<Vec<Hit>>> = Arc::new(Mutex::new(Vec::new()));
    let pending: Arc<Mutex<Vec<Work>>> = Arc::new(Mutex::new(Vec::new()));
    let local_stop: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));

    pass(
        &cfg,
        Arc::clone(&work),
        cfg.fast_timeout,
        Arc::clone(&hits),
        Some(Arc::clone(&pending)),
        Arc::clone(&local_stop),
        1,
    );

    let pending_work = std::mem::take(&mut *pending.lock().unwrap());
    let has_adb = hits
        .lock()
        .unwrap()
        .iter()
        .any(|h| matches!(h.kind, AdbKind::Plain | AdbKind::Tls));

    let cancelled = cfg.cancel.is_cancelled();
    if !pending_work.is_empty() && !cancelled && !(cfg.stop_on_first && has_adb) {
        emit(
            &cfg.on_event,
            ScanEvent::PassStarted {
                pass: 2,
                work_items: pending_work.len(),
                timeout: cfg.slow_timeout,
            },
        );
        pass(
            &cfg,
            Arc::new(pending_work),
            cfg.slow_timeout,
            Arc::clone(&hits),
            None,
            Arc::clone(&local_stop),
            2,
        );
    } else if !pending_work.is_empty() {
        let reason = if cancelled {
            PassSkipReason::Cancelled
        } else {
            PassSkipReason::HitFound
        };
        emit(
            &cfg.on_event,
            ScanEvent::PassSkipped {
                pass: 2,
                remaining: pending_work.len(),
                reason,
            },
        );
    }

    let mut out: Vec<Hit> = hits.lock().unwrap().clone();
    out.sort_by_key(|h| {
        let pri = match h.kind {
            AdbKind::Plain => 0,
            AdbKind::Tls => 1,
            AdbKind::Open => 2,
        };
        (pri, h.target.display.clone(), h.port)
    });
    out
}

/// Run a scan on a background thread, returning a join handle for the final sorted hit list
/// and a receiver that streams [`ScanEvent`]s (including [`ScanEvent::PortHit`]) as they happen.
///
/// Any preexisting `on_event` callback on `cfg` is preserved — events are forwarded to both.
pub fn run_streaming(
    cfg: ScanCfg,
) -> (thread::JoinHandle<Vec<Hit>>, mpsc::Receiver<ScanEvent>) {
    let (tx, rx) = mpsc::channel();
    let prev = cfg.on_event.clone();
    let mut new_cfg = cfg;
    new_cfg.on_event = Some(Arc::new(move |ev| {
        if let Some(p) = &prev {
            p(ev.clone());
        }
        let _ = tx.send(ev);
    }));
    let handle = thread::spawn(move || run(new_cfg));
    (handle, rx)
}

fn pass(
    cfg: &Arc<ScanCfg>,
    work: Arc<Vec<Work>>,
    connect_timeout: Duration,
    hits: Arc<Mutex<Vec<Hit>>>,
    pending: Option<Arc<Mutex<Vec<Work>>>>,
    local_stop: Arc<AtomicBool>,
    pass_label: u8,
) {
    let total = work.len();
    let next = Arc::new(AtomicUsize::new(0));
    let scanned = Arc::new(AtomicUsize::new(0));

    let threads = cfg.threads.min(total).max(1);
    let stack = if cfg.stack_size == 0 {
        stack_size_for(threads)
    } else {
        cfg.stack_size
    };
    let mut handles = Vec::with_capacity(threads);

    for _ in 0..threads {
        let next = Arc::clone(&next);
        let scanned = Arc::clone(&scanned);
        let work = Arc::clone(&work);
        let hits = Arc::clone(&hits);
        let pending = pending.clone();
        let cfg = Arc::clone(cfg);
        let local_stop = Arc::clone(&local_stop);

        let res = thread::Builder::new()
            .name(format!("scan-{pass_label}-{}", handles.len()))
            .stack_size(stack)
            .spawn(move || loop {
                if should_stop(&local_stop, &cfg.cancel) {
                    break;
                }
                let idx = next.fetch_add(1, Ordering::Relaxed);
                if idx >= total {
                    break;
                }
                let item = work[idx].clone();
                let target = &cfg.targets[item.target_idx];
                let addr = target.socket(item.port);

                match try_connect(addr, connect_timeout) {
                    ConnectOutcome::Closed => {}
                    ConnectOutcome::Timeout => {
                        if let Some(p) = &pending {
                            p.lock().unwrap().push(item);
                        }
                    }
                    ConnectOutcome::Open => {
                        if !should_stop(&local_stop, &cfg.cancel) {
                            let kind = if cfg.verify_adb {
                                probe(addr, connect_timeout, cfg.verify_timeout)
                            } else {
                                AdbKind::Open
                            };
                            if !should_stop(&local_stop, &cfg.cancel) {
                                let hit = Hit {
                                    target: target.clone(),
                                    port: item.port,
                                    kind,
                                };
                                emit(&cfg.on_event, ScanEvent::PortHit(hit.clone()));
                                hits.lock().unwrap().push(hit);
                                if cfg.stop_on_first
                                    && matches!(kind, AdbKind::Plain | AdbKind::Tls)
                                {
                                    local_stop.store(true, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }

                let done = scanned.fetch_add(1, Ordering::Relaxed) + 1;
                if done % PROGRESS_EVERY == 0 {
                    emit(
                        &cfg.on_event,
                        ScanEvent::Progress {
                            pass: pass_label,
                            done,
                            total,
                        },
                    );
                }
            });
        match res {
            Ok(h) => handles.push(h),
            Err(_) => break,
        }
    }
    if handles.len() != cfg.threads {
        emit(
            &cfg.on_event,
            ScanEvent::ThreadsSpawned {
                pass: pass_label,
                requested: cfg.threads,
                actual: handles.len(),
            },
        );
    }
    for h in handles {
        let _ = h.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::default_ports;
    use crate::target::parse_targets;

    #[test]
    fn cancellation_token_round_trip() {
        let t = CancellationToken::new();
        assert!(!t.is_cancelled());
        let t2 = t.clone();
        t2.cancel();
        assert!(t.is_cancelled());
        assert!(t2.is_cancelled());
    }

    #[test]
    fn builder_picks_auto_threads_by_default() {
        let targets = parse_targets("127.0.0.1").unwrap();
        let cfg = ScanCfg::builder(targets, Arc::new(vec![5555])).build();
        assert!(cfg.threads >= 1);
        assert!(cfg.stack_size >= 64 * 1024);
    }

    #[test]
    fn builder_threads_clamped_to_at_least_one() {
        let targets = parse_targets("127.0.0.1").unwrap();
        let cfg = ScanCfg::builder(targets, Arc::new(vec![5555]))
            .threads(0)
            .build();
        assert_eq!(cfg.threads, 1);
    }

    #[test]
    fn builder_explicit_threads_overrides_auto() {
        let targets = parse_targets("127.0.0.1").unwrap();
        let cfg = ScanCfg::builder(targets, Arc::new(vec![5555]))
            .threads(42)
            .build();
        assert_eq!(cfg.threads, 42);
    }

    #[test]
    fn builder_stack_size_overrides_default() {
        let targets = parse_targets("127.0.0.1").unwrap();
        let cfg = ScanCfg::builder(targets, Arc::new(vec![5555]))
            .threads(100)
            .stack_size(2 * 1024 * 1024)
            .build();
        assert_eq!(cfg.stack_size, 2 * 1024 * 1024);
    }

    #[test]
    fn builder_stack_size_has_minimum_floor() {
        let targets = parse_targets("127.0.0.1").unwrap();
        let cfg = ScanCfg::builder(targets, Arc::new(vec![5555]))
            .stack_size(1)
            .build();
        assert!(cfg.stack_size >= 64 * 1024);
    }

    #[test]
    fn empty_targets_returns_empty() {
        let cfg = ScanCfg::builder(vec![], Arc::new(default_ports())).build();
        let hits = run(cfg);
        assert!(hits.is_empty());
    }

    #[test]
    fn empty_ports_returns_empty() {
        let targets = parse_targets("127.0.0.1").unwrap();
        let cfg = ScanCfg::builder(targets, Arc::new(vec![])).build();
        let hits = run(cfg);
        assert!(hits.is_empty());
    }

    #[test]
    fn cancel_before_start_returns_immediately() {
        use std::time::Instant;

        let token = CancellationToken::new();
        token.cancel();
        let targets = parse_targets("127.0.0.1").unwrap();
        let ports: Vec<u16> = (40_000..45_000).map(|p| p as u16).collect();
        let cfg = ScanCfg::builder(targets, Arc::new(ports))
            .threads(8)
            .cancel(token)
            .build();

        let start = Instant::now();
        let hits = run(cfg);
        assert!(hits.is_empty());
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "pre-cancelled scan took {:?}",
            start.elapsed()
        );
    }
}
