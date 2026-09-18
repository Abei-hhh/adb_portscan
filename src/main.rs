//! `adb_portScan` — 悬浮窗 GUI 入口（带控制台，便于排错）。
//!
//! 默认启动 GUI 模式。如需无控制台窗口的版本，请使用 `adb_portScan_gui`。
//! 若在命令行传入目标参数（IP / 主机名 / CIDR），会预填到 GUI 的手动扫描框。

#[cfg(feature = "gui")]
use std::env;

#[cfg(feature = "gui")]
use adb_portscan::{parse_cli_args, print_usage, run_gui};

fn main() {
    #[cfg(feature = "gui")]
    {
        let args: Vec<String> = env::args().skip(1).collect();
        let parsed = match parse_cli_args(args) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("参数错误: {e}\n");
                print_usage();
                std::process::exit(1);
            }
        };

        if let Err(e) = run_gui(parsed.scan) {
            eprintln!("GUI 启动失败: {e}");
            std::process::exit(1);
        }
    }

    #[cfg(not(feature = "gui"))]
    {
        eprintln!("错误: 本二进制未编译 GUI 功能。请执行: cargo build --release --features gui");
        std::process::exit(1);
    }
}
