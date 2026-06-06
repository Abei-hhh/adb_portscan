//! 平台相关 FFI 封装: 任意键退出 / Ctrl+C handler / 可用内存查询。
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

pub fn stop_requested() -> bool {
    STOP.load(Ordering::Relaxed)
}

#[allow(dead_code)]
pub fn request_stop() {
    STOP.store(true, Ordering::Relaxed);
}

#[cfg(windows)]
pub fn wait_any_key(msg: &str) {
    println!("{msg}");
    std::io::stdout().flush().ok();
    #[link(name = "msvcrt")]
    extern "C" {
        fn _getch() -> i32;
    }
    unsafe {
        let _ = _getch();
    }
}

#[cfg(not(windows))]
pub fn wait_any_key(msg: &str) {
    use std::io::Read;
    println!("{msg}");
    std::io::stdout().flush().ok();
    let mut buf = [0u8; 1];
    let _ = std::io::stdin().read(&mut buf);
}

#[cfg(windows)]
pub fn install_ctrlc_handler() {
    type Dword = u32;
    type Bool = i32;
    type PhandlerRoutine = unsafe extern "system" fn(Dword) -> Bool;

    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleCtrlHandler(handler: PhandlerRoutine, add: Bool) -> Bool;
    }

    unsafe extern "system" fn handler(ctrl_type: Dword) -> Bool {
        const CTRL_C_EVENT: Dword = 0;
        const CTRL_BREAK_EVENT: Dword = 1;
        if ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT {
            STOP.store(true, Ordering::Relaxed);
            return 1; // 标记已处理，OS 不会强杀进程
        }
        0
    }

    unsafe {
        SetConsoleCtrlHandler(handler, 1);
    }
}

#[cfg(not(windows))]
pub fn install_ctrlc_handler() {
    // 标准库无信号 API；非 Windows 平台 Ctrl+C 走默认行为
}

/// 返回 (总物理内存 MB, 可用物理内存 MB)；查询失败返回 None。
#[cfg(windows)]
pub fn memory_mb() -> Option<(u64, u64)> {
    #[repr(C)]
    #[allow(non_snake_case)]
    struct MemoryStatusEx {
        dwLength: u32,
        dwMemoryLoad: u32,
        ullTotalPhys: u64,
        ullAvailPhys: u64,
        ullTotalPageFile: u64,
        ullAvailPageFile: u64,
        ullTotalVirtual: u64,
        ullAvailVirtual: u64,
        ullAvailExtendedVirtual: u64,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalMemoryStatusEx(buf: *mut MemoryStatusEx) -> i32;
    }

    unsafe {
        let mut m: MemoryStatusEx = std::mem::zeroed();
        m.dwLength = std::mem::size_of::<MemoryStatusEx>() as u32;
        if GlobalMemoryStatusEx(&mut m) == 0 {
            return None;
        }
        Some((m.ullTotalPhys / 1024 / 1024, m.ullAvailPhys / 1024 / 1024))
    }
}

#[cfg(not(windows))]
pub fn memory_mb() -> Option<(u64, u64)> {
    // 跨平台兜底：返回 None，调用方按"未知"处理
    None
}
