# adb_portScan

一个用 Rust 写的小工具，用来在局域网里**快速找到 Android 无线调试的 ADB 端口**。

Android 11+ 的无线调试每次开启都会从 Linux 临时端口范围 (32768–60999) 里随机分配一个端口，导致 `adb connect` 没法直接用。这个工具会扫描全部 1–65535 端口，对每个开放端口做真实的 **ADB 协议握手** (明文 CNXN/AUTH) 或 **ADB over TLS** 探测，最后直接给出可用的 `adb connect` 命令。

[English README](./README.md)

## 特性

- **全端口 1–65535 扫描**，按命中概率排序 (5555 → 32768–60999 临时段 → 其余非特权 → 特权)。
- **两遍扫描策略**：第一遍 100ms 快扫，未响应的端口再用 800ms 复扫一次。在保证不漏掉慢响应栈的前提下尽量缩短总耗时。
- **真正的 ADB 协议校验**，不仅仅看 TCP 是否开放：
  - 明文 ADB：发送 host 端 CNXN 包，校验返回的 24 字节包头 (magic == cmd ^ 0xFFFFFFFF)。
  - ADB over TLS：发送 TLS ClientHello，检查是否返回 TLS ServerHello。
- **mDNS 自动发现**：启动时搜索 `_adb-tls-connect._tcp` / `_adb-tls-pairing._tcp` / `_adb._tcp`，直接推荐目标。同一台设备可能同时通告 **IPv4 和 IPv6** 地址，全部保留并按连接优先级排序（IPv4 → 全局 IPv6 → link-local IPv6）。
- **支持 CIDR 子网** (最大 /16) 和 **IPv6** (含 zone ID，如 `fe80::1%2`)。
- **线程自动调优**：根据 CPU 核数和可用内存决定线程数，硬上限 65535。
- **默认命中即停**，加 `--all` 才扫完全部端口。
- **悬浮窗 GUI**（默认 `gui` feature）：无边框、置顶的桌面悬浮小窗，自动 mDNS 发现设备，支持一键**重新扫描**、点击复制 `adb connect` 命令、一键连接、手动 IP 全端口扫描、实时**设置面板**（线程数、超时、端口范围、ADB 校验、命中即停）以及**深色/浅色/跟随系统**主题切换。命令行传入的目标和参数会直接套用到 GUI 预填的扫描中。
- **核心零依赖**：扫描库本身无任何运行时依赖；`eframe`/`egui` 仅由默认的 `gui` feature 引入。

## 编译

需要 Rust 1.70+ (edition 2021)。扫描核心零运行时依赖；默认构建（`mdns` + `gui`）会额外引入 `eframe`/`egui` 用于悬浮窗。

```bash
git clone https://github.com/Abei-hhh/adb_portscan
cd adb_portscan
cargo build --release
# 产物路径: target/release/adb_portScan(.exe) 与 adb_portScan_gui(.exe)
```

release 配置启用了 `lto = true`、`codegen-units = 1`、`strip = true`，输出体积小、运行快。

零依赖构建（仅库 + 无 GUI）：

```bash
cargo build --release --no-default-features --features mdns
```

### 两个二进制

启用 `gui` feature（默认开启）时会产出两个二进制：

- `adb_portScan` — 带控制台的 GUI 入口（便于排错）。命令行目标/参数会透传给 GUI。
- `adb_portScan_gui` — 同一个 GUI，使用 Windows GUI 子系统构建，双击运行不会弹出命令行窗口。

### 悬浮窗

无边框、置顶、半透明的悬浮小窗（Windows GUI 子系统，启动不弹命令行窗口），**窗口尺寸贴合内容（宽度固定、高度自适应）**，无多余空白：启动即自动 mDNS 发现设备，一键重新扫描，每台设备列出全部 IPv4/IPv6 地址。设备交互：

- **左键点击**设备行 → 展开/收起详情（服务类型、实例名、全部地址、端口）
- **右键点击**设备行 → 菜单：**一键连接** / **扫描此设备** / 复制连接命令 / 展开详情
- 右上角 **×** 关闭、**─** 最小化、**⚙** 打开设置面板，标题栏可拖动
- **设置面板**：可调整线程数、快/慢超时、端口范围、是否校验 ADB、命中即停，以及切换深色/浅色/跟随系统主题

还支持手动 IP 全端口扫描（实时进度条、已用/预计剩余时间 + 停止按钮）。

## 作为库使用

本项目同时提供库 API，可在其他 Rust 项目里直接引用。`Cargo.toml`：

```toml
[dependencies]
adb_portscan = { git = "https://github.com/Abei-hhh/adb_portscan" }
# 精简零依赖版（无 GUI、无 mDNS）:
# adb_portscan = { git = "https://github.com/Abei-hhh/adb_portscan", default-features = false }
# 扫描 + mDNS、无 GUI:
# adb_portscan = { git = "https://github.com/Abei-hhh/adb_portscan", default-features = false, features = ["mdns"] }
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
- `gui` (默认开): 悬浮窗 GUI 模块及 `adb_portScan` / `adb_portScan_gui` 二进制；引入 `eframe`/`egui`。用 `default-features = false` 可得到精简零依赖的扫描库。

## 使用方式

### 悬浮窗 GUI

默认构建直接启动悬浮窗，无需子命令：

```
adb_portScan                     # 启动 GUI
adb_portScan 192.168.1.42        # 启动 GUI 并预填目标
```

Windows 上也可以使用无控制台入口（双击友好）：

```
adb_portScan_gui
```

一个置顶的悬浮小窗（拖标题栏移动位置，点 `✕` 关闭）：

- 启动即自动 mDNS 发现设备，列出每台设备的**全部 IPv4/IPv6 地址**。
- **↻ 重新扫描**：随时一键重跑 mDNS 发现。
- 点击设备行即可复制 `adb connect <ip>:<port>` 命令。
- **右键点击**设备行：一键连接 / 扫描此设备 / 复制命令 / 展开详情。
- **📥 手动扫描**：对任意 IP / 主机名 / CIDR 做全端口扫描，实时进度条、已用/预计剩余时间 + ⏹ 停止按钮。
- **⚙ 设置面板**：调整线程数、超时、端口范围、ADB 校验、命中即停，切换深色/浅色/跟随系统主题。

### 命令行参数

已不再提供无界面的命令行扫描模式 —— 参数用于配置 GUI 预填的手动扫描。目标可以是：

| 形式        | 示例                 |
| ----------- | -------------------- |
| IPv4        | `192.168.1.42`       |
| IPv6        | `fe80::1`            |
| IPv6 + zone | `fe80::1%2`          |
| 主机名      | `phone.local`        |
| CIDR 子网   | `192.168.1.0/24` (最大 /16) |

选项（套用到预填的扫描）：

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
# 打开 GUI 并预填单个设备
adb_portScan 192.168.1.42

# 预填整个 /24 子网
adb_portScan 192.168.1.0/24

# 只预填临时端口段
adb_portScan 192.168.1.42 --range 32768-60999

# Wi-Fi 慢：放宽超时、加大线程（预填到扫描设置）
adb_portScan 192.168.1.42 -t 4096 --timeout-fast 200 --timeout-slow 1500
```

需要在终端里拿结果？请使用[库 API](#作为库使用) —— `run` / `run_streaming` 会以编程方式返回全部命中。

## 端口扫描顺序的设计

Android 11+ 的调试端口由内核从本地临时端口范围分配，Linux 默认是 **32768–60999**。所以扫描顺序是：

1. `5555` —— 旧版 `adb tcpip` 模式。
2. `32768-60999` —— 现代 Android 无线调试段。
3. `1024-32767` + `61000-65535` —— 其余非特权端口。
4. `1-1023` —— 特权端口 (基本不会出现 ADB)。

正常情况下第一个 ADB 命中会在 1 秒内返回。

## 命中分类

每个命中都会先做协议校验再报告：

- **ADB over TLS (Android 11+)** —— 端口对 ClientHello 返回了 TLS ServerHello。
- **明文 ADB** (`adb tcpip`) —— CNXN 响应包头校验通过 (magic == cmd ^ 0xFFFFFFFF)。
- **`[open]`** —— TCP 开放但没有 ADB 握手响应；照常报告方便排查。

## 许可证

MIT。本项目与 Google / AOSP 没有任何官方关系。
