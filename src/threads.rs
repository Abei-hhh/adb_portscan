//! 综合 CPU 核数和可用内存自动决定工作线程数。
use std::thread;

use crate::platform::memory_mb;

pub const HARD_MAX_THREADS: usize = 65535;

/// 线程栈大小：超过 2000 线程时缩到 256KB，避免吃光虚拟内存。
/// 工作线程只跑 TCP connect + 不超过几百字节的协议握手，256KB 完全够用。
pub fn stack_size_for(threads: usize) -> usize {
    if threads > 2000 {
        256 * 1024
    } else {
        1024 * 1024
    }
}

#[derive(Debug)]
pub struct ThreadDecision {
    pub cores: usize,
    pub total_mem_mb: Option<u64>,
    pub avail_mem_mb: Option<u64>,
    pub stack_bytes: usize,
    pub chosen: usize,
}

/// 公式:
/// 1. 基线 = cores * 100 (TCP-bound 工作可以高度超订)
/// 2. 受端口数钳制 (没必要比工作量更多线程)
/// 3. 受可用内存钳制: chosen * stack_size <= 70% 可用内存
/// 4. 最终硬上限 HARD_MAX_THREADS
pub fn auto_threads(work_items: usize) -> ThreadDecision {
    let cores = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let (total, avail) = match memory_mb() {
        Some((t, a)) => (Some(t), Some(a)),
        None => (None, None),
    };

    let base = cores.saturating_mul(100);
    let mut chosen = base.min(work_items).min(HARD_MAX_THREADS).max(1);

    if let Some(mb) = avail {
        // 按当前 chosen 估算栈大小，再回算内存上限
        let stack_bytes = stack_size_for(chosen) as u64;
        let usable_bytes = mb.saturating_mul(1024 * 1024) * 7 / 10; // 70%
        let mem_cap = (usable_bytes / stack_bytes).max(1) as usize;
        chosen = chosen.min(mem_cap);
    }

    chosen = chosen.max(1);
    let stack_bytes = stack_size_for(chosen);

    ThreadDecision {
        cores,
        total_mem_mb: total,
        avail_mem_mb: avail,
        stack_bytes,
        chosen,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_size_thresholds() {
        assert_eq!(stack_size_for(1), 1024 * 1024);
        assert_eq!(stack_size_for(2000), 1024 * 1024);
        assert_eq!(stack_size_for(2001), 256 * 1024);
        assert_eq!(stack_size_for(65535), 256 * 1024);
    }

    #[test]
    fn auto_threads_respects_work_items() {
        let d = auto_threads(10);
        assert!(d.chosen <= 10);
        assert!(d.chosen >= 1);
    }

    #[test]
    fn auto_threads_within_hard_cap() {
        let d = auto_threads(65535);
        assert!(d.chosen <= HARD_MAX_THREADS);
    }
}
