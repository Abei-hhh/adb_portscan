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
- **mDNS discovery** on startup — finds `_adb-tls-connect._tcp` / `_adb-tls-pairing._tcp` / `_adb._tcp` and recommends a target before you even type an IP.
- **CIDR support** (up to /16) and IPv6 (including zone IDs like `fe80::1%2`).
- **Auto-tuned threads** based on CPU cores and available memory, hard-capped at 65535.
- **Stop-on-first-hit** by default; `--all` to scan everything.
- Single static binary, no runtime deps.

## Build

Requires Rust 1.70+ (edition 2021).

```bash
git clone https://github.com/Abei-hhh/adb_portscan
cd adb_portscan
cargo build --release
# Binary at: target/release/adb_portScan(.exe)
```

The release profile uses `lto = true`, `codegen-units = 1`, `strip = true` for a small, fast binary.

## Usage

### Interactive mode

Run with no arguments (or double-click the `.exe` on Windows):

```
adb_portScan
```

You'll see something like:

```
================================
   ADB Wireless Debug Port Scanner
================================

Searching for ADB services via mDNS (1.5s) ...

mDNS found 1 ADB service:
  [tls-connect] 192.168.1.42:43219  (adb-XXXX)

Recommended: adb connect 192.168.1.42:43219

Enter device IP / hostname / CIDR (e.g. 192.168.1.42 or 192.168.1.0/24, q to quit):
```

### CLI mode

```
adb_portScan <target> [options]
```

Target can be:

| Form        | Example              |
| ----------- | -------------------- |
| IPv4        | `192.168.1.42`       |
| IPv6        | `fe80::1`            |
| IPv6 + zone | `fe80::1%2`          |
| Hostname    | `phone.local`        |
| CIDR        | `192.168.1.0/24` (up to /16) |

Options:

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
# Scan a single device, stop on first ADB hit
adb_portScan 192.168.1.42

# Sweep the whole /24
adb_portScan 192.168.1.0/24

# Only check the official ephemeral range
adb_portScan 192.168.1.42 --range 32768-60999

# Be aggressive (more threads, looser timeouts) on a slow Wi-Fi
adb_portScan 192.168.1.42 -t 4096 --timeout-fast 200 --timeout-slow 1500
```

## How it picks the port order

Android 11+ assigns the debugging port from the kernel's local ephemeral range, which on Linux defaults to **32768–60999**. The scanner walks ports in this order:

1. `5555` — legacy `adb tcpip` mode.
2. `32768-60999` — modern Android wireless debugging.
3. `1024-32767` + `61000-65535` — remaining unprivileged ports.
4. `1-1023` — privileged ports (essentially never used for ADB).

This way the first ADB hit usually comes back in well under a second.

## Output

On a hit:

```
>>> Found ADB port:
    192.168.1.42:43219  [ADB over TLS (Android 11+)]

Run this to connect:
    adb connect 192.168.1.42:43219
```

If no ADB handshake responds but a port is open, it's reported as `[open]` so you can investigate.

## License

MIT. See source headers for attribution. Not affiliated with Google or the Android Open Source Project.
