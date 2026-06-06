//! `adb_portscan` — find Android ADB wireless-debugging ports on a LAN.
//!
//! This crate is dual: it ships a CLI binary (`adb_portScan`) and a reusable library.
//! The library has zero runtime dependencies and works on stable Rust.
//!
//! # Quick start
//! ```no_run
//! use std::sync::Arc;
//! use std::time::Duration;
//! use adb_portscan::{default_ports, parse_targets, run, ScanCfg};
//!
//! let targets = parse_targets("192.168.1.42").unwrap();
//! let cfg = ScanCfg::builder(targets, Arc::new(default_ports()))
//!     .fast_timeout(Duration::from_millis(100))
//!     .build();
//! for h in run(cfg) {
//!     println!("{}:{}  {:?}", h.target.display, h.port, h.kind);
//! }
//! ```
//!
//! # Cancellation
//! ```no_run
//! use std::sync::Arc;
//! use std::thread;
//! use std::time::Duration;
//! use adb_portscan::{default_ports, parse_targets, run, CancellationToken, ScanCfg};
//!
//! let token = CancellationToken::new();
//! let t2 = token.clone();
//! thread::spawn(move || { thread::sleep(Duration::from_secs(2)); t2.cancel(); });
//!
//! let cfg = ScanCfg::builder(
//!     parse_targets("192.168.1.0/24").unwrap(),
//!     Arc::new(default_ports()),
//! ).cancel(token).build();
//! run(cfg);
//! ```
//!
//! # Streaming results
//! ```no_run
//! use std::sync::Arc;
//! use adb_portscan::{default_ports, parse_targets, run_streaming, ScanCfg, ScanEvent};
//!
//! let cfg = ScanCfg::builder(
//!     parse_targets("192.168.1.42").unwrap(),
//!     Arc::new(default_ports()),
//! ).build();
//! let (handle, rx) = run_streaming(cfg);
//! for ev in rx {
//!     if let ScanEvent::PortHit(h) = ev {
//!         println!("hit {}:{}", h.target.display, h.port);
//!     }
//! }
//! let _final_hits = handle.join().unwrap();
//! ```
//!
//! # Feature flags
//! - `mdns` (default): include the [`mdns`] module for ADB service discovery via multicast DNS.
//!   Disable with `default-features = false` if you only need the scanner.

#![warn(missing_debug_implementations)]

pub mod detect;
mod error;
pub mod ports;
pub mod scan;
pub mod target;
pub mod threads;

#[cfg(feature = "mdns")]
pub mod mdns;

mod platform;

pub use crate::detect::{probe, AdbKind};
pub use crate::error::TargetError;
pub use crate::ports::default_ports;
pub use crate::scan::{
    run, run_streaming, CancellationToken, Hit, PassSkipReason, ScanCfg, ScanCfgBuilder, ScanEvent,
};
pub use crate::target::{parse_targets, Target, CIDR_MAX_ADDRESSES};
pub use crate::threads::{auto_threads, stack_size_for, ThreadDecision, HARD_MAX_THREADS};

#[cfg(feature = "mdns")]
pub use crate::mdns::{discover, AdbService, AdbServiceKind};

/// Best-effort (total, available) physical memory in MB, if the platform exposes it.
/// Returns `None` on platforms where no implementation exists (currently anything non-Windows).
pub fn system_memory_mb() -> Option<(u64, u64)> {
    platform::memory_mb()
}
