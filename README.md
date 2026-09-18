# adb_portScan

A fast Rust scanner that finds the **ADB wireless-debugging port** on an Android device on your LAN.

Android 11+ wireless debugging picks a random port in the Linux ephemeral range (32768–60999) every time you toggle it, which makes `adb connect` a guessing game. This tool sweeps all 65535 TCP ports, verifies the **ADB protocol** (plaintext CNXN/AUTH) or **ADB-over-TLS** handshake, and tells you the exact `adb connect` command to run.

[中文文档 / Chinese README](./README.zh.md)

## Features

- **Full 1–65535 sweep**, ordered by hit probability (5555 → ephemeral 32768–60999 → other unprivileged → privileged).
- **Two-pass timing**: 100 ms fast pass, then 800 ms slow re-check of non-responders. Cuts wall-clock without missing slow stacks.
- **Real ADB verification**, not just an open-TCP check:
  - Plain ADB: sends a host-side CNXN packet and validates the 24-byte response header (magic == cmd ^ 0xFFFFFFFF).
  - ADB over TLS: sends a TLS ClientHello and checks for a TLS ServerHello.
- **mDNS discovery** on startup — finds `_adb-tls-connect._tcp` / `_adb-tls-pairing._tcp` / `_adb._tcp` and recommends a target before you even type an IP. A single device may advertise **both IPv4 and IPv6** addresses; all of them are kept and sorted by connect preference (IPv4 → global IPv6 → link-local IPv6).
- **CIDR support** (up to /16) and IPv6 (including zone IDs like `fe80::1%2`).
- **Auto-tuned threads** based on CPU cores and available memory, hard-capped at 65535.
- **Stop-on-first-hit** by default; `--all` to scan everything.
- **Floating-window GUI** (default `gui` feature): a borderless, always-on-top desktop window that auto-discovers devices via mDNS and offers one-click **re-scan**, copy-to-clipboard `adb connect` commands, one-click connect, manual IP full-port scans, a live **settings panel** (threads, timeouts, port range, ADB verification, stop-on-first), and **dark/light/system theme** switching. Command-line targets/options are applied directly to the GUI's pre-filled scan.
- **Zero-dependency core**: the scanner library itself has no runtime dependencies; `eframe`/`egui` are only pulled in by the default `gui` feature.

## Build

Requires Rust 1.70+ (edition 2021). The scanner core has zero runtime dependencies; the default build (`mdns` + `gui` features) additionally pulls in `eframe`/`egui` for the floating window.

```bash
git clone https://github.com/Abei-hhh/adb_portscan
cd adb_portscan
cargo build --release
# Binaries at: target/release/adb_portScan(.exe) and adb_portScan_gui(.exe)
```

The release profile uses `lto = true`, `codegen-units = 1`, `strip = true` for a small, fast binary.

Dependency-free build (library + no GUI):

```bash
cargo build --release --no-default-features --features mdns
```

### Binaries

Two binaries are produced when the `gui` feature is enabled (on by default):

- `adb_portScan` — GUI entry point with a console attached (handy for troubleshooting). Command-line targets/options are passed through to the GUI.
- `adb_portScan_gui` — the same GUI built with the Windows GUI subsystem, so double-clicking it never pops a console window.

### The floating window

The GUI is a borderless, always-on-top, semi-transparent floating window whose width is fixed while its height auto-fits its content (no wasted blank area). It auto-discovers ADB devices via mDNS on startup and re-scans on one click. Per device:

- **Left-click** a row to expand/collapse details (service type, instance, all addresses, port).
- **Right-click** a row for a menu: **Connect now** (runs `adb connect` in the background and shows the result), **Scan this device**, copy the connect command, or expand details.
- **×** closes, **─** minimizes, and **⚙** opens the settings panel; the title bar is draggable.
- **Settings panel**: adjust threads, fast/slow timeouts, port range, ADB verification, stop-on-first, and theme (dark/light/system).

Manual full-port scans with a live progress bar, elapsed time, and stop button are also supported.

## Use as a library

This crate is dual: the same code is available as a Rust library for other projects to embed. Add to your `Cargo.toml`:

```toml
[dependencies]
adb_portscan = { git = "https://github.com/Abei-hhh/adb_portscan" }
# Lean, dependency-free scanner (no GUI, no mDNS):
# adb_portscan = { git = "https://github.com/Abei-hhh/adb_portscan", default-features = false }
# Scanner + mDNS without the GUI:
# adb_portscan = { git = "https://github.com/Abei-hhh/adb_portscan", default-features = false, features = ["mdns"] }
```

Minimal scan:

```rust
use std::sync::Arc;
use adb_portscan::{default_ports, parse_targets, run, ScanCfg};

let targets = parse_targets("192.168.1.42")?;
let cfg = ScanCfg::builder(targets, Arc::new(default_ports())).build();
for h in run(cfg) {
    println!("{}:{} {:?}", h.target.display, h.port, h.kind);
}
```

Streaming events and cancellation:

```rust
use std::sync::Arc;
use adb_portscan::{default_ports, parse_targets, run_streaming, CancellationToken, ScanCfg, ScanEvent};

let token = CancellationToken::new();
let cfg = ScanCfg::builder(
    parse_targets("192.168.1.0/24")?,
    Arc::new(default_ports()),
).cancel(token.clone()).build();

let (handle, rx) = run_streaming(cfg);
for ev in rx {
    if let ScanEvent::PortHit(h) = ev {
        println!("hit {}:{}", h.target.display, h.port);
        token.cancel(); // stop the scan from any thread
    }
}
let _final_hits = handle.join().unwrap();
```

### Features
- `mdns` (default): includes the `mdns` module for local ADB-service discovery via multicast DNS. Disable with `default-features = false` if you only need the scanner.
- `gui` (default): the floating-window GUI module plus the `adb_portScan` / `adb_portScan_gui` binaries; pulls in `eframe`/`egui`. Disable with `default-features = false` for a lean, dependency-free scanner library.

## Usage

### Floating-window GUI

The default build starts the floating window — no subcommand needed:

```
adb_portScan                     # starts the GUI
adb_portScan 192.168.1.42        # starts the GUI with the target pre-filled
```

On Windows you can also use the no-console shortcut (double-click friendly):

```
adb_portScan_gui
```

A small always-on-top floating window (drag the title bar to move it, `✕` to close):

- On startup it runs an mDNS discovery and lists every ADB service with **all** of its IPv4/IPv6 addresses.
- **↻ 重新扫描** re-runs mDNS discovery at any time.
- Clicking a device row copies `adb connect <ip>:<port>` to the clipboard.
- **Right-click** a device row for more actions: **Connect now**, **Scan this device**, copy command, expand details.
- **📥 手动扫描** runs a full 1–65535 port scan on any IP / hostname / CIDR, with a live progress bar, elapsed/remaining time, and a ⏹ stop button.
- **⚙ 设置面板** lets you tune threads, timeouts, port range, ADB verification, stop-on-first, and switch dark/light/system themes.

### Command-line arguments

There is no headless CLI mode any more — arguments configure the GUI's pre-filled manual scan. Target can be:

| Form        | Example              |
| ----------- | -------------------- |
| IPv4        | `192.168.1.42`       |
| IPv6        | `fe80::1`            |
| IPv6 + zone | `fe80::1%2`          |
| Hostname    | `phone.local`        |
| CIDR        | `192.168.1.0/24` (up to /16) |

Options (applied to the pre-filled scan):

| Flag                 | Default     | Description                                              |
| -------------------- | ----------- | -------------------------------------------------------- |
| `--range S-E`        | `1-65535`   | Only scan ports in the given range                       |
| `-t`, `--threads N`  | `auto`      | `auto` / `max` (65535) / a specific number               |
| `--timeout-fast MS`  | `100`       | First-pass connect timeout in milliseconds               |
| `--timeout-slow MS`  | `800`       | Second-pass timeout for ports that didn't respond fast   |
| `--timeout MS`       | —           | Shortcut: set both fast and slow                         |
| `--no-verify`        | off         | Skip ADB/TLS handshake — just report open TCP            |
| `--all`              | off         | Scan every port (don't stop after the first ADB hit)     |
| `--first`            | on          | Stop after the first ADB hit (default)                   |
| `-h`, `--help`       | —           | Print help                                               |

### Examples

```bash
# Open the GUI pre-filled for a single device
adb_portScan 192.168.1.42

# Pre-fill a whole /24 sweep
adb_portScan 192.168.1.0/24

# Pre-fill only the official ephemeral range
adb_portScan 192.168.1.42 --range 32768-60999

# Slow Wi-Fi: looser timeouts, more threads (pre-filled into the scan settings)
adb_portScan 192.168.1.42 -t 4096 --timeout-fast 200 --timeout-slow 1500
```

Need the results in your terminal instead? Use the [library API](#use-as-a-library) — `run` / `run_streaming` return every hit programmatically.

## How it picks the port order

Android 11+ assigns the debugging port from the kernel's local ephemeral range, which on Linux defaults to **32768–60999**. The scanner walks ports in this order:

1. `5555` — legacy `adb tcpip` mode.
2. `32768-60999` — modern Android wireless debugging.
3. `1024-32767` + `61000-65535` — remaining unprivileged ports.
4. `1-1023` — privileged ports (essentially never used for ADB).

This way the first ADB hit usually comes back in well under a second.

## Hit classification

Every hit is protocol-verified before it is reported:

- **ADB over TLS (Android 11+)** — the port answered a TLS ServerHello to our ClientHello.
- **Plain ADB** (`adb tcpip`) — valid CNXN response header (magic == cmd ^ 0xFFFFFFFF).
- **`[open]`** — TCP open but no ADB handshake responded; reported so you can investigate.

## License

MIT. See source headers for attribution. Not affiliated with Google or the Android Open Source Project.
