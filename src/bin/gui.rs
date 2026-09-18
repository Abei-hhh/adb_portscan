//! `adb_portScan_gui` — 无控制台悬浮窗入口。
//!
//! 该二进制文件仅用于 Windows 等需要隐藏命令行窗口的场景。
//! 所有 UI 逻辑均位于 `adb_portscan::gui::run_gui`。

#![windows_subsystem = "windows"]

fn main() -> eframe::Result {
    adb_portscan::run_gui(None)
}
