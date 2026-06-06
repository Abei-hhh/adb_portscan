mod detect;
mod mdns;
mod output;
mod platform;
mod ports;
mod scan;
mod target;
mod threads;

use std::env;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::detect::AdbKind;
use crate::platform::{install_ctrlc_handler, stop_requested, wait_any_key};
use crate::ports::default_ports;
use crate::scan::{Hit, ScanCfg};
use crate::target::{parse_targets, Target};
use crate::threads::{auto_threads, HARD_MAX_THREADS};

fn main() {
    install_ctrlc_handler();
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        interactive_mode();
    } else {
        cli_mode(args);
    }
}

// ─────────────────── 交互模式 ─────────────────────────────────────────────

fn interactive_mode() {
    println!("================================");
    println!("   ADB 无线调试端口扫描器");
    println!("================================\n");

    // mDNS 优先尝试
    try_mdns_discover();

    loop {
        if stop_requested() {
            println!("\n[Ctrl+C] 已中断。");
            break;
        }
        let targets = match prompt_target() {
            Some(t) => t,
            None => break,
        };
        run_scan(&targets);
        if stop_requested() {
            println!("\n[Ctrl+C] 已中断。");
            break;
        }
        if !ask_yes_no("\n再扫一次? (y/N): ", false) {
            break;
        }
    }

    wait_any_key("\n按任意键退出...");
}

fn try_mdns_discover() {
    println!("正在通过 mDNS 搜索同网段 ADB 服务 (1.5s) ...");
    let results = mdns::discover(Duration::from_millis(1500));
    if results.is_empty() {
        println!("mDNS 未发现 ADB 服务，可继续手动输入 IP 扫描。\n");
        return;
    }
    println!("\nmDNS 发现 {} 个 ADB 服务:", results.len());
    for s in &results {
        println!("  [{}] {}:{}  ({})", s.kind.label(), s.ip, s.port, s.instance);
    }
    let recommend = results
        .iter()
        .find(|s| matches!(s.kind, mdns::AdbServiceKind::Connect | mdns::AdbServiceKind::Legacy))
        .unwrap_or(&results[0]);
    println!(
        "\n推荐直接执行: adb connect {}:{}\n",
        recommend.ip, recommend.port
    );
}

fn prompt_target() -> Option<Vec<Target>> {
    loop {
        if stop_requested() {
            return None;
        }
        print!(
            "请输入 设备IP / 主机名 / CIDR (例 192.168.1.42 或 192.168.1.0/24，q 退出): "
        );
        std::io::stdout().flush().ok();
        let mut buf = String::new();
        let n = std::io::stdin().read_line(&mut buf).unwrap_or(0);
        if n == 0 {
            // EOF (Ctrl+Z + Enter 在 Windows)
            return None;
        }
        if stop_requested() {
            return None;
        }
        let s = buf.trim();
        if s.is_empty() {
            continue;
        }
        if matches!(s, "q" | "Q" | "quit" | "exit") {
            return None;
        }
        match parse_targets(s) {
            Ok(ts) => return Some(ts),
            Err(e) => println!("解析失败: {e}\n"),
        }
    }
}

fn ask_yes_no(prompt: &str, default_yes: bool) -> bool {
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut buf = String::new();
    if std::io::stdin().read_line(&mut buf).unwrap_or(0) == 0 {
        return default_yes;
    }
    let s = buf.trim().to_lowercase();
    if s.is_empty() {
        return default_yes;
    }
    matches!(s.as_str(), "y" | "yes")
}

fn run_scan(targets: &[Target]) {
    let ports = Arc::new(default_ports());
    let work_items = targets.len() * ports.len();
    let decision = auto_threads(work_items);

    let cfg = ScanCfg {
        targets: targets.to_vec(),
        ports: Arc::clone(&ports),
        threads: decision.chosen,
        fast_timeout: Duration::from_millis(100),
        slow_timeout: Duration::from_millis(800),
        verify_timeout: Duration::from_millis(800),
        verify_adb: true,
        stop_on_first: true,
        stack_size: decision.stack_bytes,
    };

    println!(
        "\n[资源] {} 逻辑核 | 物理内存 {} / 可用 {} MB",
        decision.cores,
        decision.total_mem_mb.map(|m| m.to_string()).unwrap_or_else(|| "?".into()),
        decision.avail_mem_mb.map(|m| m.to_string()).unwrap_or_else(|| "?".into()),
    );
    println!(
        "[线程] 选用 {} 线程 (硬上限 {}) | 栈 {}KB/线程",
        decision.chosen,
        HARD_MAX_THREADS,
        cfg.stack_size / 1024
    );
    println!(
        "[目标] {} 个 IP × {} 端口 = {} 工作项",
        targets.len(),
        ports.len(),
        work_items
    );
    println!("[策略] 两遍扫描: 100ms 快扫 → 800ms 复扫未响应端口 | 命中即停\n");

    let started = Instant::now();
    let hits = scan::run(cfg);
    let elapsed = started.elapsed();

    print_results(&hits, elapsed);
}

fn print_results(hits: &[Hit], elapsed: Duration) {
    println!("\n--------------------------------");
    println!("扫描完成 用时 {:.2}s", elapsed.as_secs_f64());

    let adb: Vec<&Hit> = hits
        .iter()
        .filter(|h| matches!(h.kind, AdbKind::Plain | AdbKind::Tls))
        .collect();
    if !adb.is_empty() {
        println!("\n>>> 找到 ADB 端口:");
        for h in &adb {
            let tag = match h.kind {
                AdbKind::Plain => "明文 ADB (adb tcpip)",
                AdbKind::Tls => "ADB over TLS (Android 11+)",
                _ => "?",
            };
            println!("    {}:{}  [{}]", h.target.display, h.port, tag);
        }
        println!("\n执行命令直接连接:");
        println!("    adb connect {}:{}", adb[0].target.display, adb[0].port);
    } else if !hits.is_empty() {
        println!("\n未识别到 ADB 协议端口，但有 TCP 开放端口:");
        for h in hits {
            println!("    {}:{}  [open]", h.target.display, h.port);
        }
    } else {
        println!("\n未发现任何开放端口。");
        println!("请确认:");
        println!("  1. 手机与电脑处于同一 Wi-Fi 网络");
        println!("  2. 「开发者选项 → 无线调试」已开启");
        println!("  3. IP 输入正确 (设置 → 关于本机 → 状态)");
    }
    println!("--------------------------------");
}

// ─────────────────── 命令行模式 ───────────────────────────────────────────

enum ThreadArg {
    Auto,
    Max,
    Fixed(usize),
}

fn cli_mode(args: Vec<String>) {
    let (targets, ports, threads_arg, timeout_fast, timeout_slow, verify_adb, stop_on_first) =
        match parse_args(args) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("参数错误: {e}\n");
                print_usage();
                std::process::exit(1);
            }
        };

    let ports = Arc::new(ports);
    let work_items = targets.len() * ports.len();
    let decision = auto_threads(work_items);
    let threads = match threads_arg {
        ThreadArg::Auto => decision.chosen,
        ThreadArg::Max => HARD_MAX_THREADS.min(work_items),
        ThreadArg::Fixed(n) => n.min(work_items),
    };

    let cfg = ScanCfg {
        targets: targets.clone(),
        ports: Arc::clone(&ports),
        threads,
        fast_timeout: Duration::from_millis(timeout_fast),
        slow_timeout: Duration::from_millis(timeout_slow),
        verify_timeout: Duration::from_millis(timeout_slow),
        verify_adb,
        stop_on_first,
        stack_size: threads::stack_size_for(threads),
    };

    println!(
        "目标 {} 个 × 端口 {} 个 | 线程 {} | 快/慢 {}/{}ms | 校验ADB {} | 命中即停 {}",
        targets.len(),
        ports.len(),
        threads,
        timeout_fast,
        timeout_slow,
        verify_adb,
        stop_on_first
    );

    let started = Instant::now();
    let hits = scan::run(cfg);
    print_results(&hits, started.elapsed());
}

#[allow(clippy::type_complexity)]
fn parse_args(
    args: Vec<String>,
) -> Result<
    (
        Vec<Target>,
        Vec<u16>,
        ThreadArg,
        u64,
        u64,
        bool,
        bool,
    ),
    String,
> {
    let mut it = args.into_iter();
    let mut target_str: Option<String> = None;
    let mut custom_range: Option<(u16, u16)> = None;
    let mut threads_arg = ThreadArg::Auto;
    let mut timeout_fast: u64 = 100;
    let mut timeout_slow: u64 = 800;
    let mut verify_adb = true;
    let mut stop_on_first = true;

    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
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
                timeout_fast = it.next().ok_or("--timeout-fast 缺少参数")?.parse().map_err(|_| "非法")?;
            }
            "--timeout-slow" => {
                timeout_slow = it.next().ok_or("--timeout-slow 缺少参数")?.parse().map_err(|_| "非法")?;
            }
            "--timeout" => {
                let v: u64 = it.next().ok_or("--timeout 缺少参数")?.parse().map_err(|_| "非法")?;
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

    let s = target_str.ok_or("缺少目标 (IP / 主机名 / CIDR)")?;
    let targets = parse_targets(&s)?;
    let ports: Vec<u16> = match custom_range {
        Some((s, e)) => (s..=e).collect(),
        None => default_ports(),
    };
    Ok((
        targets,
        ports,
        threads_arg,
        timeout_fast,
        timeout_slow,
        verify_adb,
        stop_on_first,
    ))
}

fn print_usage() {
    println!(
        "用法:\n\
           adb_portScan                         交互模式 (双击 .exe 也可)\n\
           adb_portScan <目标> [选项]           命令行模式\n\n\
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
