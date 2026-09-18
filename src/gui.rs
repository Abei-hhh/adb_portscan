//! `adb_portscan` 悬浮窗 GUI 模块。
//!
//! 通过 `gui` feature 启用，提供：
//! - 启动时自动 mDNS 发现
//! - 可展开的设备详情与一键连接 / 复制命令 / 扫描此设备
//! - 手动 IP / 主机名 / CIDR 全端口扫描
//! - 实时扫描设置（线程、超时、端口范围、是否校验 ADB、命中即停）
//! - 深色 / 浅色 / 跟随系统主题切换
//!
//! 入口统一为 [`run_gui`]。`src/bin/gui.rs` 仅保留 Windows GUI 子系统声明并委托到这里。

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText, ThemePreference};

use crate::{
    default_ports, discover, parse_targets, run_streaming, AdbKind, AdbService, AdbServiceKind,
    CancellationToken, Hit, ScanCfg, ScanEvent, ScanOptions, Target, ThreadArg, HARD_MAX_THREADS,
};

/// 后台线程 → UI 消息。
enum Msg {
    MdnsDone {
        services: Vec<AdbService>,
        elapsed: Duration,
    },
    ScanEvt(ScanEvent),
    ScanDone {
        hits: Vec<Hit>,
        elapsed: Duration,
    },
    Toast(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanStatus {
    Idle,
    MdnsBusy,
    PortBusy,
}

impl ScanStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Idle => "● 就绪",
            Self::MdnsBusy => "◐ mDNS 发现中…",
            Self::PortBusy => "◐ 端口扫描中…",
        }
    }
    fn busy(self) -> bool {
        !matches!(self, Self::Idle)
    }
}

/// 设备行上触发的交互动作。
#[derive(Debug, Clone)]
enum RowAction {
    CopyCmd(String),
    Connect(String),
    Toggle(String),
    ScanTarget(Vec<Target>),
}

/// 日志条目，带类型用于着色。
#[derive(Debug, Clone)]
struct LogEntry {
    text: String,
    kind: LogKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogKind {
    Normal,
    Hit,
    Error,
    Success,
    Status,
}

/// 用户可调扫描设置。初始化时若从命令行传入了扫描参数则直接套用。
#[derive(Debug, Clone)]
struct GuiOptions {
    target: String,
    range: String,
    threads_arg: ThreadArg,
    timeout_fast_ms: u64,
    timeout_slow_ms: u64,
    verify_adb: bool,
    stop_on_first: bool,
}

impl Default for GuiOptions {
    fn default() -> Self {
        Self {
            target: String::new(),
            range: String::from("1-65535"),
            threads_arg: ThreadArg::Auto,
            timeout_fast_ms: 100,
            timeout_slow_ms: 800,
            verify_adb: true,
            stop_on_first: true,
        }
    }
}

impl From<&ScanOptions> for GuiOptions {
    fn from(opts: &ScanOptions) -> Self {
        let range = if opts.ports.len() == default_ports().len() {
            "1-65535".to_string()
        } else {
            format!("{}-{}", opts.ports.first().copied().unwrap_or(1), opts.ports.last().copied().unwrap_or(65535))
        };
        Self {
            target: opts.targets.first().map(|t| t.display.clone()).unwrap_or_default(),
            range,
            threads_arg: opts.threads_arg,
            timeout_fast_ms: opts.timeout_fast_ms,
            timeout_slow_ms: opts.timeout_slow_ms,
            verify_adb: opts.verify_adb,
            stop_on_first: opts.stop_on_first,
        }
    }
}

struct App {
    rx: Receiver<Msg>,
    tx: Sender<Msg>,

    services: Vec<AdbService>,
    hits: Vec<Hit>,
    progress: Option<(usize, usize)>,
    scan_started: Option<Instant>,

    status: ScanStatus,
    last_mdns_elapsed: Option<Duration>,
    last_scan_elapsed: Option<Duration>,
    opts: GuiOptions,
    cancel: Option<CancellationToken>,

    toast: Option<(String, Instant)>,
    log: Vec<LogEntry>,
    expanded: HashSet<String>,
    show_settings: bool,
    last_want: Option<egui::Vec2>,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, initial: Option<ScanOptions>) -> Self {
        setup_fonts(&cc.egui_ctx);
        cc.egui_ctx.set_theme(egui::Theme::Dark);

        let (tx, rx) = channel();
        let opts = initial.as_ref().map(GuiOptions::from).unwrap_or_default();
        let mut app = Self {
            rx,
            tx,
            services: Vec::new(),
            hits: Vec::new(),
            progress: None,
            scan_started: None,
            status: ScanStatus::Idle,
            last_mdns_elapsed: None,
            last_scan_elapsed: None,
            opts,
            cancel: None,
            toast: None,
            log: Vec::new(),
            expanded: HashSet::new(),
            show_settings: false,
            last_want: None,
        };
        app.start_mdns_scan();
        app
    }

    fn log(&mut self, text: impl Into<String>, kind: LogKind) {
        self.log.push(LogEntry {
            text: text.into(),
            kind,
        });
        if self.log.len() > 300 {
            self.log.drain(..self.log.len() - 300);
        }
    }

    fn start_mdns_scan(&mut self) {
        if self.status.busy() {
            return;
        }
        self.status = ScanStatus::MdnsBusy;
        self.services.clear();
        self.expanded.clear();
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let started = Instant::now();
            let services = discover(Duration::from_millis(2000));
            let _ = tx.send(Msg::MdnsDone {
                services,
                elapsed: started.elapsed(),
            });
        });
    }

    fn parse_ports(&self) -> Result<Vec<u16>, String> {
        let s = self.opts.range.trim();
        if s.is_empty() || s == "1-65535" {
            return Ok(default_ports());
        }
        let (start, end) = s.split_once('-').ok_or("端口范围格式应为 START-END")?;
        let start: u16 = start.parse().map_err(|_| "起始端口非法")?;
        let end: u16 = end.parse().map_err(|_| "结束端口非法")?;
        if start > end {
            return Err("起始端口必须 <= 结束端口".into());
        }
        Ok((start..=end).collect())
    }

    fn start_port_scan(&mut self, targets: Vec<Target>) {
        if self.status.busy() {
            return;
        }
        let ports = match self.parse_ports() {
            Ok(p) => Arc::new(p),
            Err(e) => {
                self.toast = Some((e, Instant::now()));
                return;
            }
        };
        let token = CancellationToken::new();
        self.cancel = Some(token.clone());
        self.status = ScanStatus::PortBusy;
        self.hits.clear();
        self.progress = None;
        self.scan_started = Some(Instant::now());
        self.log(format!("开始扫描 {} 个目标, {} 个端口", targets.len(), ports.len()), LogKind::Status);

        let threads = self.opts.threads_arg.resolve(targets.len().saturating_mul(ports.len()).max(1));
        let fast = Duration::from_millis(self.opts.timeout_fast_ms);
        let slow = Duration::from_millis(self.opts.timeout_slow_ms);
        let verify = self.opts.verify_adb;
        let stop_first = self.opts.stop_on_first;
        let tx = self.tx.clone();

        std::thread::spawn(move || {
            let started = Instant::now();
            let cfg = ScanCfg::builder(targets, Arc::clone(&ports))
                .threads(threads)
                .fast_timeout(fast)
                .slow_timeout(slow)
                .verify_timeout(slow)
                .verify_adb(verify)
                .stop_on_first(stop_first)
                .cancel(token)
                .build();
            let (handle, rx) = run_streaming(cfg);
            for ev in rx {
                let _ = tx.send(Msg::ScanEvt(ev));
            }
            let hits = handle.join().unwrap_or_default();
            let _ = tx.send(Msg::ScanDone {
                hits,
                elapsed: started.elapsed(),
            });
        });
    }

    fn adb_connect(&mut self, addr: &str) {
        let tx = self.tx.clone();
        let addr = addr.to_owned();
        self.log(format!("正在连接 {addr} …"), LogKind::Status);
        std::thread::spawn(move || {
            let msg = match std::process::Command::new("adb")
                .arg("connect")
                .arg(&addr)
                .output()
            {
                Ok(o) => {
                    let text = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    if !text.is_empty() {
                        format!("adb {addr}: {text}")
                    } else {
                        let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
                        if err.is_empty() {
                            format!("adb {addr}: 无输出 (退出码 {})", o.status.code().unwrap_or(-1))
                        } else {
                            format!("adb {addr}: {err}")
                        }
                    }
                }
                Err(e) => format!("无法启动 adb: {e} — 请确认 adb 已安装并在 PATH 中"),
            };
            let _ = tx.send(Msg::Toast(msg));
        });
    }

    fn poll_messages(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::MdnsDone { services, elapsed } => {
                    self.services = services;
                    self.status = ScanStatus::Idle;
                    self.last_mdns_elapsed = Some(elapsed);
                    let n = self.services.len();
                    self.log(format!("mDNS 完成: 发现 {n} 个设备 ({:.1}s)", elapsed.as_secs_f64()), LogKind::Status);
                    if n == 0 {
                        self.log("未发现设备, 可手动输入 IP 扫描".to_string(), LogKind::Normal);
                    }
                }
                Msg::ScanEvt(ev) => match ev {
                    ScanEvent::Progress { done, total, .. } => {
                        self.progress = Some((done, total));
                    }
                    ScanEvent::PortHit(h) => {
                        let (tag, kind) = match h.kind {
                            AdbKind::Plain => ("明文ADB", LogKind::Hit),
                            AdbKind::Tls => ("TLS加密", LogKind::Hit),
                            AdbKind::Open => ("开放端口", LogKind::Normal),
                        };
                        self.log(format!("命中 {}:{} [{tag}]", h.target.display, h.port), kind);
                    }
                    ScanEvent::PassStarted { pass, work_items, timeout } => {
                        self.log(format!("[Pass {pass}/2] {work_items} 项, 超时 {}ms", timeout.as_millis()), LogKind::Status);
                    }
                    ScanEvent::PassSkipped { remaining, reason, .. } => {
                        self.log(format!("[Pass 2/2] 跳过 ({reason:?}, 剩余 {remaining})"), LogKind::Status);
                    }
                    ScanEvent::ThreadsSpawned { requested, actual, .. } => {
                        if requested != actual {
                            self.log(format!("注意: 申请 {requested} 线程, 实际起了 {actual}"), LogKind::Error);
                        }
                    }
                },
                Msg::ScanDone { hits, elapsed } => {
                    self.hits = hits;
                    self.progress = None;
                    self.cancel = None;
                    self.status = ScanStatus::Idle;
                    self.last_scan_elapsed = Some(elapsed);
                    self.scan_started = None;
                    let adb = self.hits.iter().filter(|h| matches!(h.kind, AdbKind::Plain | AdbKind::Tls)).count();
                    self.log(format!("扫描完成: {} 个命中, ADB {} 个 ({:.1}s)", self.hits.len(), adb, elapsed.as_secs_f64()), LogKind::Success);
                }
                Msg::Toast(s) => {
                    self.toast = Some((s, Instant::now()));
                }
            }
        }
    }

    fn title_bar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let (rect, drag_resp) = ui.allocate_exact_size(
            egui::vec2(ui.available_width(), 32.0),
            egui::Sense::click_and_drag(),
        );
        let mut child = ui.new_child(egui::UiBuilder::new().max_rect(rect));
        child.horizontal(|ui| {
            ui.label(RichText::new("🛰 ADB 悬浮扫描").strong().size(15.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let close = egui::Button::new(
                    RichText::new("×")
                        .size(16.0)
                        .color(Color32::from_rgb(255, 170, 170)),
                )
                .fill(Color32::from_rgba_unmultiplied(120, 36, 42, 210))
                .corner_radius(6);
                if ui.add_sized(egui::vec2(28.0, 24.0), close).clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                ui.add_space(4.0);
                let min = egui::Button::new(RichText::new("─").size(14.0))
                    .fill(Color32::from_rgba_unmultiplied(58, 66, 82, 210))
                    .corner_radius(6);
                if ui.add_sized(egui::vec2(28.0, 24.0), min).clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                }
                ui.add_space(4.0);
                let settings_btn = egui::Button::new(RichText::new("⚙").size(14.0))
                    .fill(Color32::from_rgba_unmultiplied(58, 66, 82, 210))
                    .corner_radius(6);
                if ui.add_sized(egui::vec2(28.0, 24.0), settings_btn).clicked() {
                    self.show_settings = !self.show_settings;
                }
            });
        });
        if drag_resp.drag_started() {
            ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
        }
    }

    fn settings_panel(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        egui::Frame::new()
            .inner_margin(egui::Margin::same(10))
            .corner_radius(egui::CornerRadius::same(10))
            .fill(Color32::from_rgba_unmultiplied(38, 44, 58, 255))
            .show(ui, |ui| {
                ui.label(RichText::new("扫描设置").strong().size(14.0));
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    ui.label("线程:");
                    let mut threads_text = match self.opts.threads_arg {
                        ThreadArg::Auto => "auto".to_string(),
                        ThreadArg::Max => "max".to_string(),
                        ThreadArg::Fixed(n) => n.to_string(),
                    };
                    ui.add(egui::TextEdit::singleline(&mut threads_text).desired_width(80.0));
                    self.opts.threads_arg = match threads_text.trim() {
                        "auto" => ThreadArg::Auto,
                        "max" => ThreadArg::Max,
                        s => match s.parse::<usize>() {
                            Ok(0) | Err(_) => ThreadArg::Auto,
                            Ok(n) => ThreadArg::Fixed(n.clamp(1, HARD_MAX_THREADS)),
                        },
                    };
                    ui.label(RichText::new("auto / max / 数字").weak().size(11.0));
                });

                ui.horizontal(|ui| {
                    ui.label("快超时:");
                    ui.add(egui::DragValue::new(&mut self.opts.timeout_fast_ms).speed(10).range(10..=5000).suffix("ms"));
                    ui.label("慢超时:");
                    ui.add(egui::DragValue::new(&mut self.opts.timeout_slow_ms).speed(10).range(10..=30000).suffix("ms"));
                });

                ui.horizontal(|ui| {
                    ui.label("端口范围:");
                    ui.add(egui::TextEdit::singleline(&mut self.opts.range).desired_width(140.0));
                    ui.checkbox(&mut self.opts.verify_adb, "校验 ADB/TLS");
                    ui.checkbox(&mut self.opts.stop_on_first, "命中即停");
                });

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("主题:");
                    if ui.selectable_label(ctx.theme() == egui::Theme::Dark, "深色").clicked() {
                        ctx.set_theme(egui::Theme::Dark);
                    }
                    if ui.selectable_label(ctx.theme() == egui::Theme::Light, "浅色").clicked() {
                        ctx.set_theme(egui::Theme::Light);
                    }
                    if ui.selectable_label(false, "跟随系统").clicked() {
                        ctx.set_theme(ThemePreference::System);
                    }
                });
            });
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let color = if self.status.busy() {
                Color32::from_rgb(240, 200, 90)
            } else {
                Color32::from_rgb(110, 210, 130)
            };
            ui.label(RichText::new(self.status.label()).color(color));
            if let Some(d) = self.last_mdns_elapsed {
                ui.label(RichText::new(format!("| mDNS {:.1}s", d.as_secs_f64())).weak());
            }
            if let Some(d) = self.last_scan_elapsed {
                ui.label(RichText::new(format!("| 扫描 {:.1}s", d.as_secs_f64())).weak());
            }
            if let Some(started) = self.scan_started {
                ui.label(RichText::new(format!("已用 {:.1}s", started.elapsed().as_secs_f64())).weak());
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.status.busy() {
                    if ui.button("⏹ 停止").clicked() {
                        if let Some(t) = &self.cancel {
                            t.cancel();
                        }
                    }
                } else if ui.button(RichText::new("↻ 重新扫描").strong()).clicked() {
                    self.start_mdns_scan();
                }
            });
        });

        if let Some((done, total)) = self.progress {
            let frac = if total == 0 { 0.0 } else { done as f32 / total as f32 };
            ui.add(
                egui::ProgressBar::new(frac)
                    .desired_width(ui.available_width())
                    .text(format!("{done}/{total}")),
            );
            if let Some(started) = self.scan_started {
                let elapsed = started.elapsed().as_secs_f32();
                if frac > 0.0 && elapsed > 0.5 {
                    let rate = frac / elapsed;
                    let remain = (1.0 - frac) / rate;
                    ui.label(RichText::new(format!("预计剩余 {:.1}s", remain)).weak().size(11.0));
                }
            }
        }

        if let Some((text, at)) = &self.toast {
            if at.elapsed() < Duration::from_secs(4) {
                ui.label(RichText::new(format!("✔ {text}")).color(Color32::from_rgb(110, 210, 130)));
            } else {
                self.toast = None;
            }
        }
    }

    fn device_list(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("📡 mDNS 设备 ({})", self.services.len())).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if !self.services.is_empty() && ui.button("复制全部").clicked() {
                    let cmds: Vec<String> = self.services.iter().map(|s| format!("adb connect {}:{}", s.ip, s.port)).collect();
                    ctx.copy_text(cmds.join("\n"));
                    self.toast = Some(("已复制全部连接命令".to_string(), Instant::now()));
                }
            });
        });

        if self.services.is_empty() {
            ui.label(
                RichText::new(if self.status.busy() {
                    "正在发现设备…"
                } else {
                    "未发现设备 — 点击右上角「重新扫描」或手动输入 IP"
                })
                .weak(),
            );
        } else {
            let mut actions: Vec<RowAction> = Vec::new();
            egui::ScrollArea::vertical()
                .max_height(220.0)
                .auto_shrink([true, false])
                .show(ui, |ui| {
                    for s in &self.services {
                        let key = format!("{}|{}", s.instance, s.ip);
                        let expanded = self.expanded.contains(&key);
                        device_row(ui, s, expanded, &mut actions);
                        ui.add_space(4.0);
                    }
                });
            for a in actions {
                match a {
                    RowAction::CopyCmd(cmd) => {
                        ctx.copy_text(cmd.clone());
                        self.toast = Some((format!("已复制: {cmd}"), Instant::now()));
                    }
                    RowAction::Connect(addr) => self.adb_connect(&addr),
                    RowAction::Toggle(key) => {
                        if !self.expanded.remove(&key) {
                            self.expanded.insert(key);
                        }
                    }
                    RowAction::ScanTarget(targets) => {
                        if let Some(t) = targets.first() {
                            self.opts.target = t.display.clone();
                        }
                        self.start_port_scan(targets);
                    }
                }
            }
        }
    }

    fn manual_scan(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("📥 手动扫描").strong());
            ui.add(
                egui::TextEdit::singleline(&mut self.opts.target)
                    .hint_text("IP / 主机名 / CIDR，如 192.168.1.50")
                    .desired_width(230.0),
            );
            let can_scan = !self.opts.target.trim().is_empty() && !self.status.busy();
            if ui.add_enabled(can_scan, egui::Button::new(RichText::new("▶ 扫描").strong())).clicked() {
                match parse_targets(self.opts.target.trim()) {
                    Ok(targets) => self.start_port_scan(targets),
                    Err(e) => self.toast = Some((format!("目标解析失败: {e}"), Instant::now())),
                }
            }
        });

        if !self.hits.is_empty() {
            ui.add_space(4.0);
            let adb: Vec<(String, String)> = self
                .hits
                .iter()
                .filter(|h| matches!(h.kind, AdbKind::Plain | AdbKind::Tls))
                .map(|h| {
                    let tag = match h.kind {
                        AdbKind::Plain => "明文ADB",
                        AdbKind::Tls => "TLS加密",
                        _ => "?",
                    };
                    let cmd = format!("adb connect {}:{}", h.target.display, h.port);
                    (cmd, tag.to_string())
                })
                .collect();
            if !adb.is_empty() {
                for (cmd, tag) in adb {
                    let addr = cmd.trim_start_matches("adb connect ").to_string();
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new(format!("{cmd}   [{tag}]")).size(13.0)).clicked() {
                            ctx.copy_text(cmd.clone());
                            self.toast = Some((format!("已复制: {cmd}"), Instant::now()));
                        }
                        if ui.button("连接").clicked() {
                            self.adb_connect(&addr);
                        }
                    });
                }
            } else {
                ui.label(
                    RichText::new(format!("有 {} 个 TCP 开放端口, 未识别到 ADB 协议", self.hits.len())).weak(),
                );
            }
        }
    }

    fn log_view(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("📄 事件日志").strong());
        if self.log.is_empty() {
            ui.label(RichText::new("(暂无)").weak());
        } else {
            egui::ScrollArea::vertical()
                .max_height(120.0)
                .auto_shrink([true, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for entry in &self.log {
                        let color = match entry.kind {
                            LogKind::Hit => Color32::from_rgb(110, 210, 130),
                            LogKind::Error => Color32::from_rgb(255, 120, 120),
                            LogKind::Success => Color32::from_rgb(120, 200, 255),
                            LogKind::Status => Color32::from_rgb(240, 200, 90),
                            LogKind::Normal => ui.visuals().text_color(),
                        };
                        ui.label(RichText::new(&entry.text).size(12.0).color(color));
                    }
                });
        }
    }
}

impl eframe::App for App {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        // 与外层 Frame 填充色一致的深色背景, 避免透明窗口在部分系统上出现白边。
        [28.0 / 255.0, 32.0 / 255.0, 42.0 / 255.0, 1.0]
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_messages();

        let ctx = ui.ctx().clone();
        egui::Frame::new()
            .inner_margin(egui::Margin::same(12))
            .corner_radius(egui::CornerRadius::same(16))
            .fill(Color32::from_rgba_unmultiplied(28, 32, 42, 250))
            .stroke(egui::Stroke::NONE)
            .show(ui, |ui| {
                self.title_bar(ui, &ctx);
                ui.add_space(6.0);
                self.status_bar(ui);
                if self.show_settings {
                    ui.add_space(8.0);
                    self.settings_panel(ui, &ctx);
                }
                ui.separator();
                self.device_list(ui, &ctx);
                ui.separator();
                self.manual_scan(ui, &ctx);
                ui.separator();
                self.log_view(ui);
            });

        let want = egui::vec2(
            ui.ctx().viewport_rect().width(),
            ui.min_rect().size().y + 6.0,
        );
        let changed = self
            .last_want
            .is_none_or(|w| (w.x - want.x).abs() > 4.0 || (w.y - want.y).abs() > 4.0);
        if changed {
            self.last_want = Some(want);
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(want));
        }

        ui.ctx().request_repaint_after(Duration::from_millis(250));
    }
}

/// 启动悬浮窗 GUI。`initial` 若存在，会预填充到手动扫描框并套用对应扫描设置。
pub fn run_gui(initial: Option<ScanOptions>) -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("ADB 悬浮扫描")
            .with_inner_size([480.0, 460.0])
            .with_min_inner_size([360.0, 240.0])
            .with_resizable(true)
            .with_decorations(false)
            .with_always_on_top(),
        ..Default::default()
    };
    eframe::run_native(
        "adb_portScan_gui",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc, initial)))),
    )
}

/// 服务类型的中文标签。
fn kind_cn(k: &AdbServiceKind) -> &'static str {
    match k {
        AdbServiceKind::Connect => "TLS连接",
        AdbServiceKind::Pairing => "TLS配对",
        AdbServiceKind::Legacy => "旧版ADB",
    }
}

/// 渲染单个 mDNS 设备行。
fn device_row(ui: &mut egui::Ui, s: &AdbService, expanded: bool, actions: &mut Vec<RowAction>) {
    let key = format!("{}|{}", s.instance, s.ip);
    let addr = format!("{}:{}", s.ip, s.port);
    let kind_color = match s.kind {
        AdbServiceKind::Connect | AdbServiceKind::Legacy => Color32::from_rgb(90, 190, 250),
        _ => Color32::from_rgb(170, 175, 185),
    };
    let arrow = if expanded { "▼ " } else { "▶ " };
    let text = format!(
        "{arrow}[{}] {}:{}  ({})",
        kind_cn(&s.kind),
        format_ip(&s.ip),
        s.port,
        s.instance
    );
    let resp = ui.add_sized(
        egui::vec2(ui.available_width(), 24.0),
        egui::Button::new(RichText::new(text).size(13.0).color(kind_color))
            .fill(Color32::from_rgba_unmultiplied(42, 48, 64, 255))
            .corner_radius(8),
    );
    if resp.clicked() {
        actions.push(RowAction::Toggle(key.clone()));
    }
    resp.context_menu(|ui| {
        if ui.button("🔗 连接设备").clicked() {
            actions.push(RowAction::Connect(addr.clone()));
            ui.close();
        }
        if ui.button("📋 复制连接命令").clicked() {
            actions.push(RowAction::CopyCmd(addr.clone()));
            ui.close();
        }
        if ui.button("🔍 扫描此设备").clicked() {
            let targets = s.ips.iter().map(|ip| Target {
                ip: *ip,
                zone: if let IpAddr::V6(v6) = ip { (v6.segments()[0] & 0xffc0 == 0xfe80).then_some(0) } else { None },
                display: ip.to_string(),
            }).collect();
            actions.push(RowAction::ScanTarget(targets));
            ui.close();
        }
        if ui.button(if expanded { "▲ 收起详情" } else { "▼ 展开详情" }).clicked() {
            actions.push(RowAction::Toggle(key.clone()));
            ui.close();
        }
    });

    if expanded {
        ui.add_space(2.0);
        egui::Frame::new()
            .inner_margin(egui::Margin::same(8))
            .corner_radius(egui::CornerRadius::same(8))
            .fill(Color32::from_rgba_unmultiplied(38, 44, 58, 255))
            .show(ui, |ui| {
                ui.label(RichText::new(format!("类型: {}    端口: {}", kind_cn(&s.kind), s.port)).size(12.5));
                ui.label(RichText::new(format!("实例: {}", s.instance)).size(12.5));
                ui.label(RichText::new("地址:").size(12.5));
                for ip in &s.ips {
                    ui.label(RichText::new(format!("  {}", format_ip(ip))).size(12.5).weak());
                }
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("📋 复制命令").size(12.5)).clicked() {
                        actions.push(RowAction::CopyCmd(addr.clone()));
                    }
                    if ui.button(RichText::new("🔗 连接").size(12.5)).clicked() {
                        actions.push(RowAction::Connect(addr.clone()));
                    }
                    if ui.button(RichText::new("🔍 扫描").size(12.5)).clicked() {
                        let targets = s.ips.iter().map(|ip| Target {
                            ip: *ip,
                            zone: if let IpAddr::V6(v6) = ip { (v6.segments()[0] & 0xffc0 == 0xfe80).then_some(0) } else { None },
                            display: ip.to_string(),
                        }).collect();
                        actions.push(RowAction::ScanTarget(targets));
                    }
                });
            });
        ui.add_space(4.0);
    }
}

fn format_ip(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => format!("IPv4 {v4}"),
        IpAddr::V6(v6) => {
            let mut s = format!("IPv6 {v6}");
            if v6.segments()[0] & 0xffc0 == 0xfe80 {
                s.push_str(" (链路本地)");
            }
            s
        }
    }
}

fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    for path in [
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\msyhbd.ttc",
        r"C:\Windows\Fonts\Deng.ttf",
        r"C:\Windows\Fonts\simhei.ttf",
        r"C:\Windows\Fonts\simsun.ttc",
    ] {
        if let Ok(bytes) = std::fs::read(path) {
            fonts
                .font_data
                .insert("cn".to_owned(), egui::FontData::from_owned(bytes).into());
            for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                fonts.families.entry(family).or_default().push("cn".to_owned());
            }
            break;
        }
    }
    ctx.set_fonts(fonts);
}
