//! Shared command-line parsing and [`ScanCfg`] construction.
//!
//! Used by both the CLI binary (`src/main.rs`) and the GUI binary
//! (`src/gui.rs`) so that timeouts, thread counts, port ranges, etc.
//! behave identically across modes.

use std::sync::Arc;
use std::time::Duration;

use crate::{
    default_ports, parse_targets, CancellationToken, ScanCfg, ScanCfgBuilder, ScanEvent, Target,
    HARD_MAX_THREADS,
};

/// How the user wants to pick the scanner thread count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadArg {
    Auto,
    Max,
    Fixed(usize),
}

impl ThreadArg {
    /// Resolve to an actual thread count given the total number of work items.
    pub fn resolve(self, work_items: usize) -> usize {
        match self {
            Self::Auto => {
                let decision = crate::auto_threads(work_items.max(1));
                decision.chosen
            }
            Self::Max => HARD_MAX_THREADS.min(work_items.max(1)),
            Self::Fixed(n) => n.min(work_items.max(1)).max(1),
        }
    }
}

/// Fully parsed CLI scan options. Everything needed to build a [`ScanCfg`].
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub targets: Vec<Target>,
    pub ports: Vec<u16>,
    pub threads_arg: ThreadArg,
    pub timeout_fast_ms: u64,
    pub timeout_slow_ms: u64,
    pub verify_adb: bool,
    pub stop_on_first: bool,
}

impl ScanOptions {
    /// Number of work items (targets × ports).
    pub fn work_items(&self) -> usize {
        self.targets.len().saturating_mul(self.ports.len())
    }

    /// Start building a [`ScanCfg`] from these options. The caller still has
    /// to attach cancellation and any event callback before calling `.build()`.
    pub fn cfg_builder(&self) -> ScanCfgBuilder {
        let ports = Arc::new(self.ports.clone());
        let threads = self.threads_arg.resolve(self.work_items().max(1));
        ScanCfg::builder(self.targets.clone(), ports)
            .threads(threads)
            .fast_timeout(Duration::from_millis(self.timeout_fast_ms))
            .slow_timeout(Duration::from_millis(self.timeout_slow_ms))
            .verify_timeout(Duration::from_millis(self.timeout_slow_ms))
            .verify_adb(self.verify_adb)
            .stop_on_first(self.stop_on_first)
    }

    /// Convenience: build a fully configured [`ScanCfg`] with cancellation
    /// and an event callback.
    pub fn build_cfg<F>(
        &self,
        cancel: CancellationToken,
        on_event: F,
    ) -> ScanCfg
    where
        F: Fn(ScanEvent) + Send + Sync + 'static,
    {
        self.cfg_builder()
            .cancel(cancel)
            .on_event(on_event)
            .build()
    }
}

/// Parsed command-line invocation.
#[derive(Debug)]
pub struct ParsedArgs {
    /// If true, the user requested the floating GUI (`--gui`).
    pub gui: bool,
    /// Scan options, present only when a target was supplied on the command line.
    pub scan: Option<ScanOptions>,
}

/// Parse the argument list exactly like the original CLI binary did.
///
/// Returns `Ok(ParsedArgs)`. If `--gui` is present, `gui` is set to true and
/// other positional scan arguments are still parsed when present.
pub fn parse_args(args: Vec<String>) -> Result<ParsedArgs, String> {
    let mut it = args.into_iter();
    let mut target_str: Option<String> = None;
    let mut custom_range: Option<(u16, u16)> = None;
    let mut threads_arg = ThreadArg::Auto;
    let mut timeout_fast: u64 = 100;
    let mut timeout_slow: u64 = 800;
    let mut verify_adb = true;
    let mut stop_on_first = true;
    let mut gui = false;

    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "--gui" => gui = true,
            "--range" => {
                let v = it.next().ok_or("--range 缺少参数")?;
                let (s, e) = v.split_once('-').ok_or("--range 格式应为 START-END")?;
                let s: u16 = s.parse().map_err(|_| "start port 非法")?;
                let e: u16 = e.parse().map_err(|_| "end port 非法")?;
                if s > e {
                    return Err("start 必须 <= end".into());
                }
                custom_range = Some((s, e));
            }
            "-t" | "--threads" => {
                let v = it.next().ok_or("--threads 缺少参数")?;
                threads_arg = match v.as_str() {
                    "auto" => ThreadArg::Auto,
                    "max" => ThreadArg::Max,
                    s => {
                        let n: usize = s.parse().map_err(|_| "threads 非法")?;
                        if n == 0 {
                            return Err("threads 必须 > 0".into());
                        }
                        if n > HARD_MAX_THREADS {
                            return Err(format!("threads 不能超过 {HARD_MAX_THREADS}"));
                        }
                        ThreadArg::Fixed(n)
                    }
                };
            }
            "--timeout-fast" => {
                timeout_fast = it
                    .next()
                    .ok_or("--timeout-fast 缺少参数")?
                    .parse()
                    .map_err(|_| "非法")?;
            }
            "--timeout-slow" => {
                timeout_slow = it
                    .next()
                    .ok_or("--timeout-slow 缺少参数")?
                    .parse()
                    .map_err(|_| "非法")?;
            }
            "--timeout" => {
                let v: u64 = it
                    .next()
                    .ok_or("--timeout 缺少参数")?
                    .parse()
                    .map_err(|_| "非法")?;
                timeout_fast = v;
                timeout_slow = v;
            }
            "--no-verify" => verify_adb = false,
            "--verify" => verify_adb = true,
            "--all" => stop_on_first = false,
            "--first" => stop_on_first = true,
            s if s.starts_with('-') => return Err(format!("未知参数 {s}")),
            s => {
                if target_str.is_some() {
                    return Err(format!("多余的位置参数 {s}"));
                }
                target_str = Some(s.to_string());
            }
        }
    }

    let scan = match target_str {
        Some(s) => {
            let targets = parse_targets(&s).map_err(|e| e.to_string())?;
            let ports: Vec<u16> = match custom_range {
                Some((s, e)) => (s..=e).collect(),
                None => default_ports(),
            };
            Some(ScanOptions {
                targets,
                ports,
                threads_arg,
                timeout_fast_ms: timeout_fast,
                timeout_slow_ms: timeout_slow,
                verify_adb,
                stop_on_first,
            })
        }
        None => {
            if custom_range.is_some() {
                return Err("--range 需要配合目标使用".into());
            }
            if !matches!(threads_arg, ThreadArg::Auto) {
                return Err("-t/--threads 需要配合目标使用".into());
            }
            None
        }
    };

    Ok(ParsedArgs { gui, scan })
}

/// Print the CLI help text to stdout.
pub fn print_usage() {
    println!(
        "用法:\n\
           adb_portScan                         启动悬浮窗 GUI (默认)\n\
           adb_portScan <目标> [选项]           启动 GUI 并预填目标\n\n\
         目标可以是:\n\
           IPv4              192.168.1.42\n\
           IPv6              fe80::1\n\
           IPv6 + zone       fe80::1%2\n\
           主机名             phone.local\n\
           CIDR 子网          192.168.1.0/24  (最大 /16)\n\n\
         默认行为:\n\
           扫 1-65535 全端口，按命中概率排序。两遍扫描 (100ms / 800ms)，\n\
           命中第一个 ADB 端口即停。\n\n\
         选项:\n\
           --range S-E         只扫指定端口范围\n\
           -t, --threads N     线程数: auto (默认) / max (65535) / 具体数字\n\
           --timeout-fast MS   第一遍超时 默认 100\n\
           --timeout-slow MS   第二遍超时 默认 800\n\
           --timeout MS        同时设置 fast/slow\n\
           --no-verify         不做 ADB/TLS 校验, 仅检测 TCP 开放\n\
           --all               扫完全部端口 (不在命中后停止)\n\
           -h, --help          显示帮助"
    );
}
