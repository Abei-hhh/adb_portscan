//! Platform FFI: physical memory query.
//!
//! Ctrl+C handling and `wait_any_key` previously lived here too, but they install
//! process-wide state which is inappropriate for a library. They now live in the
//! binary (`src/ctrl_c.rs`).

/// Total / available physical memory in MB. Returns `None` if the platform doesn't expose it.
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
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn windows_returns_some() {
        let m = memory_mb().expect("Windows should return Some");
        assert!(m.0 >= m.1, "available {} should not exceed total {}", m.1, m.0);
        assert!(m.0 > 0);
    }

    #[test]
    #[cfg(not(windows))]
    fn non_windows_returns_none() {
        assert!(memory_mb().is_none());
    }
}
