# adb_portScan

一个用 Rust 写的小工具，用来在局域网里**快速找到 Android 无线调试的 ADB 端口**。

Android 11+ 的无线调试每次开启都会从 Linux 临时端口范围 (32768–60999) 里随机分配一个端口，导致 `adb connect` 没法直接用。这个工具会扫描全部 1–65535 端口，对每个开放端口做真实的 **ADB 协议握手** (明文 CNXN/AUTH) 或 **ADB over TLS** 探测，最后直接打印出可用的 `adb connect` 命令。

[English README](./README.md)

## 特性

- **全端口 1–65535 扫描**，按命中概率排序 (5555 → 32768–60999 临时段 → 其余非特权 → 特权)。
- **两遍扫描策略**：第一遍 100ms 快扫，未响应的端口再用 800ms 复扫一次。在保证不漏掉慢响应栈的前提下尽量缩短总耗时。
- **真正的 ADB 协议校验**，不仅仅看 TCP 是否开放：
  - 明文 ADB：发送 host 端 CNXN 包，校验返回的 24 字节包头 (magic == cmd ^ 0xFFFFFFFF)。
  - ADB over TLS：发送 TLS ClientHello，检查是否返回 TLS ServerHello。
- **mDNS 自动发现**：启动时搜索 `_adb-tls-connect._tcp` / `_adb-tls-pairing._tcp` / `_adb._tcp`，直接推荐目标。
- **支持 CIDR 子网** (最大 /16) 和 **IPv6** (含 zone ID，如 `fe80::1%2`)。
- **线程自动调优**：根据 CPU 核数和可用内存决定线程数，硬上限 65535。
- **默认命中即停**，加 `--all` 才扫完全部端口。
- 单个静态二进制，无运行时依赖。

## 编译

需要 Rust 1.70+ (edition 2021)，零运行时依赖。

```bash
git clone https://github.com/Abei-hhh/adb_portscan
cd adb_portscan
cargo build --release
# 产物路径: target/release/adb_portScan(.exe)
```

release 配置启用了 `lto = true`、`codegen-units = 1`、`strip = true`，输出体积小、运行快。

## 作为库使用

本项目同时提供库 API，可在其他 Rust 项目里直接引用。`Cargo.toml`：

```toml
[dependencies]
adb_portscan = { git = "https://github.com/Abei-hhh/adb_portscan" }
# 不需要 mDNS 时:
# adb_portscan = { git = "https://github.com/Abei-hhh/adb_portscan", default-features = false }
```

最小用法：

```rust
use std::sync::Arc;
use adb_portscan::{default_ports, parse_targets, run, ScanCfg};

let targets = parse_targets("192.168.1.42")?;
let cfg = ScanCfg::builder(targets, Arc::new(default_ports())).build();
for h in run(cfg) {
    println!("{}:{} {:?}", h.target.display, h.port, h.kind);
}
```

流式事件 + 取消：

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
        println!("命中 {}:{}", h.target.display, h.port);
        token.cancel(); // 任意线程都可触发停止
    }
}
let _final_hits = handle.join().unwrap();
```

### Feature 开关
- `mdns` (默认开): 启用 `mdns` 模块，通过组播 DNS 发现局域网内的 ADB 服务。如果只需要扫描功能，可以 `default-features = false` 关掉。

## 使用方式

### 交互模式

不带参数直接运行 (Windows 上也可以直接双击 `.exe`)：

```
adb_portScan
```

看到的输出大致如下：

```
================================
   ADB 无线调试端口扫描器
================================

正在通过 mDNS 搜索同网段 ADB 服务 (1.5s) ...

mDNS 发现 1 个 ADB 服务:
  [tls-connect] 192.168.1.42:43219  (adb-XXXX)

推荐直接执行: adb connect 192.168.1.42:43219

请输入 设备IP / 主机名 / CIDR (例 192.168.1.42 或 192.168.1.0/24，q 退出):
```

### 命令行模式

```
adb_portScan <目标> [选项]
```

目标可以是：

| 形式        | 示例                 |
| ----------- | -------------------- |
| IPv4        | `192.168.1.42`       |
| IPv6        | `fe80::1`            |
| IPv6 + zone | `fe80::1%2`          |
| 主机名      | `phone.local`        |
| CIDR 子网   | `192.168.1.0/24` (最大 /16) |

选项：

| 参数                 | 默认值      | 说明                                                  |
| -------------------- | ----------- | ----------------------------------------------------- |
| `--range S-E`        | `1-65535`   | 只扫指定端口范围                                       |
| `-t`, `--threads N`  | `auto`      | `auto` / `max` (65535) / 具体数字                      |
| `--timeout-fast MS`  | `100`       | 第一遍连接超时 (毫秒)                                  |
| `--timeout-slow MS`  | `800`       | 第二遍复扫超时 (毫秒)                                  |
| `--timeout MS`       | —           | 同时设置 fast/slow                                     |
| `--no-verify`        | 关          | 不做 ADB/TLS 校验，只检测 TCP 是否开放                 |
| `--all`              | 关          | 扫完全部端口 (不在第一个 ADB 命中后停止)              |
| `--first`            | 开          | 命中第一个 ADB 端口即停 (默认)                         |
| `-h`, `--help`       | —           | 显示帮助                                               |

### 示例

```bash
# 扫单个设备，命中即停
adb_portScan 192.168.1.42

# 扫整个 /24 子网
adb_portScan 192.168.1.0/24

# 只扫临时端口段
adb_portScan 192.168.1.42 --range 32768-60999

# Wi-Fi 慢，放宽超时、加大线程
adb_portScan 192.168.1.42 -t 4096 --timeout-fast 200 --timeout-slow 1500
```

## 端口扫描顺序的设计

Android 11+ 的调试端口由内核从本地临时端口范围分配，Linux 默认是 **32768–60999**。所以扫描顺序是：

1. `5555` —— 旧版 `adb tcpip` 模式。
2. `32768-60999` —— 现代 Android 无线调试段。
3. `1024-32767` + `61000-65535` —— 其余非特权端口。
4. `1-1023` —— 特权端口 (基本不会出现 ADB)。

正常情况下第一个 ADB 命中会在 1 秒内返回。

## 输出示例

命中时：

```
>>> 找到 ADB 端口:
    192.168.1.42:43219  [ADB over TLS (Android 11+)]

执行命令直接连接:
    adb connect 192.168.1.42:43219
```

如果端口开放但没有 ADB 握手响应，会标记为 `[open]`，方便你排查。

## 许可证

MIT。本项目与 Google / AOSP 没有任何官方关系。
