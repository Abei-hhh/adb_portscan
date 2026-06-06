//! 工作线程池扫描器：两遍超时 + 命中即停 + 防本地端口耗尽。
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::detect::{detect, AdbKind};
use crate::elog;
use crate::platform::stop_requested;
use crate::target::Target;

/// scan 内部停止信号 + 全局 Ctrl+C 信号 任一为真都停。
fn should_stop(local: &AtomicBool) -> bool {
    local.load(Ordering::Relaxed) || stop_requested()
}

#[derive(Debug, Clone)]
pub struct Hit {
    pub target: Target,
    pub port: u16,
    pub kind: AdbKind,
}

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
}

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

/// 试连一次：成功立即 shutdown + drop，让 OS 尽快回收本地 ephemeral 端口，
/// 缓解 Windows 上 TIME_WAIT 堆积导致后续 connect 失败的问题。
fn try_connect(addr: SocketAddr, timeout: Duration) -> ConnectOutcome {
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(stream) => {
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

    elog!(
        "[Pass 1/2] {} 工作项, 快速连接超时 {}ms",
        total,
        cfg.fast_timeout.as_millis()
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

    if !pending_work.is_empty() && !stop_requested() && !(cfg.stop_on_first && has_adb) {
        elog!(
            "[Pass 2/2] 对 {} 个无响应端口用 {}ms 超时复扫",
            pending_work.len(),
            cfg.slow_timeout.as_millis()
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
        elog!(
            "[Pass 2/2] 跳过 (已命中或被中断, 剩余 {} 个未复扫)",
            pending_work.len()
        );
    }

    let mut out = Arc::try_unwrap(hits).unwrap().into_inner().unwrap();
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
    let stack = cfg.stack_size;
    let mut handles = Vec::with_capacity(threads);
    let mut spawn_failed = 0usize;

    for i in 0..threads {
        let next = Arc::clone(&next);
        let scanned = Arc::clone(&scanned);
        let work = Arc::clone(&work);
        let hits = Arc::clone(&hits);
        let pending = pending.clone();
        let cfg = Arc::clone(cfg);
        let local_stop = Arc::clone(&local_stop);

        let res = thread::Builder::new()
            .name(format!("scan-{pass_label}-{i}"))
            .stack_size(stack)
            .spawn(move || loop {
                if should_stop(&local_stop) {
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
                        if should_stop(&local_stop) {
                            // #4: 已停 → 不再探测/打印
                        } else {
                            let kind = if cfg.verify_adb {
                                detect(addr, connect_timeout, cfg.verify_timeout)
                            } else {
                                AdbKind::Open
                            };
                            if !should_stop(&local_stop) {
                                let tag = match kind {
                                    AdbKind::Plain => "[ADB-Plain]",
                                    AdbKind::Tls => "[ADB-TLS]",
                                    AdbKind::Open => "[open]",
                                };
                                elog!("  发现 {}:{} {}", target.display, item.port, tag);
                                hits.lock().unwrap().push(Hit {
                                    target: target.clone(),
                                    port: item.port,
                                    kind,
                                });
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
                if done % 5000 == 0 {
                    elog!("  进度 {}/{}", done, total);
                }
            });
        match res {
            Ok(h) => handles.push(h),
            Err(_) => {
                spawn_failed += 1;
                break;
            }
        }
    }
    if spawn_failed > 0 {
        elog!(
            "  注意: 申请 {} 线程，实际起了 {} (系统资源限制)",
            cfg.threads,
            handles.len()
        );
    }
    for h in handles {
        let _ = h.join();
    }
}
