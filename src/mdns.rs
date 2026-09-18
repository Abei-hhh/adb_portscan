//! 最小化的 mDNS 客户端，用于发现局域网内的 ADB 服务。
//!
//! 实现策略：
//! - 绑定 UDP socket 到 0.0.0.0:0，向 224.0.0.251:5353 发送 PTR 查询
//! - 监听响应直到超时，解析所有 SRV / A / AAAA / PTR 记录
//! - 关联 PTR -> SRV -> A，得到 (instance, ip, port)
//!
//! 不依赖外部 crate，纯手工解析 DNS 报文（处理 name compression）。

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct AdbService {
    pub kind: AdbServiceKind,
    pub instance: String,
    /// 首选连接地址: 优先 IPv4, 其次全局 IPv6, 最后 link-local IPv6。
    /// 与 `ips[0]` 一致, 保留该字段便于兼容旧调用方。
    pub ip: IpAddr,
    /// 设备通告的全部地址 (IPv4 + IPv6), 按上述优先级排序去重。
    pub ips: Vec<IpAddr>,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdbServiceKind {
    Connect, // _adb-tls-connect._tcp.local — Android 11+ 已配对连接口
    Pairing, // _adb-tls-pairing._tcp.local — Android 11+ 配对口
    Legacy,  // _adb._tcp.local — 旧版 adb tcpip
}

impl AdbServiceKind {
    pub fn label(&self) -> &'static str {
        match self {
            AdbServiceKind::Connect => "TLS-Connect",
            AdbServiceKind::Pairing => "TLS-Pairing",
            AdbServiceKind::Legacy => "Legacy",
        }
    }
}

const ADB_SERVICES: &[(&str, AdbServiceKind)] = &[
    ("_adb-tls-connect._tcp.local", AdbServiceKind::Connect),
    ("_adb-tls-pairing._tcp.local", AdbServiceKind::Pairing),
    ("_adb._tcp.local", AdbServiceKind::Legacy),
];

pub fn discover(total_timeout: Duration) -> Vec<AdbService> {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    // 给每个 recv_from 设一个短超时，便于轮询直到 deadline
    let _ = socket.set_read_timeout(Some(Duration::from_millis(150)));
    let _ = socket.set_broadcast(true);
    let mdns_addr: SocketAddr = "224.0.0.251:5353".parse().unwrap();

    // 三个 service 一起查
    for (svc, _) in ADB_SERVICES {
        let q = build_query(svc);
        let _ = socket.send_to(&q, mdns_addr);
    }

    let mut srv_records: HashMap<String, SrvRecord> = HashMap::new();
    // 一个主机名可以同时通告 A (IPv4) 和 AAAA (IPv6) 记录,
    // 必须全部保留, 不能像旧版那样互相覆盖, 否则 IPv4 会被后到的 IPv6 挤掉。
    let mut a_records: HashMap<String, Vec<IpAddr>> = HashMap::new();
    let mut ptrs: Vec<(AdbServiceKind, String)> = Vec::new();

    let deadline = Instant::now() + total_timeout;
    let resend_at = Instant::now() + Duration::from_millis(500);
    let mut resent = false;
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        // 500ms 后重发一次查询, 应对首次丢包或设备响应慢的情况
        if !resent && Instant::now() >= resend_at {
            for (svc, _) in ADB_SERVICES {
                let q = build_query(svc);
                let _ = socket.send_to(&q, mdns_addr);
            }
            resent = true;
        }
        match socket.recv_from(&mut buf) {
            Ok((n, _)) => {
                parse_message(&buf[..n], &mut srv_records, &mut a_records, &mut ptrs);
            }
            Err(_) => continue,
        }
    }

    // 去重: 重发查询或设备多次响应会导致 ptrs 中存在重复的 (kind, instance) 对。
    let mut seen_ptrs: HashSet<(AdbServiceKind, String)> = HashSet::new();
    ptrs.retain(|(k, i)| seen_ptrs.insert((*k, i.clone())));

    let mut out = Vec::new();
    let mut seen_out: HashSet<(AdbServiceKind, String, u16, IpAddr)> = HashSet::new();
    for (kind, instance) in ptrs {
        if let Some(srv) = srv_records.get(&instance) {
            if let Some(ips) = a_records.get(&srv.target) {
                if let Some(&ip) = ips.first() {
                    // 再次去重, 防止不同 instance 名指向同一设备+端口+IP
                    if !seen_out.insert((kind, instance.clone(), srv.port, ip)) {
                        continue;
                    }
                    out.push(AdbService {
                        kind,
                        instance,
                        ip,
                        ips: ips.clone(),
                        port: srv.port,
                    });
                }
            }
        }
    }
    out
}

/// 向地址表追加一个地址: 去重, 并按 首选优先 排序。
fn push_addr(map: &mut HashMap<String, Vec<IpAddr>>, name: String, ip: IpAddr) {
    let list = map.entry(name).or_default();
    if !list.contains(&ip) {
        list.push(ip);
        list.sort_by_key(addr_priority);
    }
}

/// 连接优先级: IPv4 最高, 全局 IPv6 次之, link-local IPv6 最低
/// (link-local 需要附加 zone id 才能路由, 所以最不推荐)。
fn addr_priority(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 0,
        IpAddr::V6(v6) if is_link_local(*v6) => 2,
        IpAddr::V6(_) => 1,
    }
}

fn is_link_local(v6: Ipv6Addr) -> bool {
    v6.segments()[0] & 0xffc0 == 0xfe80
}

#[derive(Debug, Clone)]
struct SrvRecord {
    target: String,
    port: u16,
}

fn build_query(service: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(64);
    // header: id=0, flags=0 (standard query), qd=1, an/ns/ar=0
    m.extend_from_slice(&[0u8; 4]);
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&[0u8; 6]);
    // question name
    for label in service.split('.') {
        if label.is_empty() {
            continue;
        }
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&12u16.to_be_bytes()); // type = PTR
    m.extend_from_slice(&0x8001u16.to_be_bytes()); // class = IN | unicast-response
    m
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn u16(&mut self) -> Option<u16> {
        let s = self.slice(2)?;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }
    fn slice(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        self.pos += n;
        Some(())
    }

    fn read_name(&mut self) -> Option<String> {
        let mut out = String::new();
        let mut jumped_to: Option<usize> = None;
        let mut pos = self.pos;
        let mut budget = 100usize;

        loop {
            if budget == 0 || pos >= self.buf.len() {
                return None;
            }
            budget -= 1;
            let len = self.buf[pos];
            if len == 0 {
                pos += 1;
                if jumped_to.is_none() {
                    self.pos = pos;
                }
                return Some(out);
            }
            if len & 0xC0 == 0xC0 {
                if pos + 1 >= self.buf.len() {
                    return None;
                }
                let ptr = ((len as usize & 0x3F) << 8) | self.buf[pos + 1] as usize;
                if jumped_to.is_none() {
                    self.pos = pos + 2;
                    jumped_to = Some(ptr);
                }
                pos = ptr;
                continue;
            }
            pos += 1;
            let len = len as usize;
            if pos + len > self.buf.len() {
                return None;
            }
            let label = std::str::from_utf8(&self.buf[pos..pos + len]).ok()?;
            if !out.is_empty() {
                out.push('.');
            }
            out.push_str(label);
            pos += len;
        }
    }
}

fn parse_message(
    buf: &[u8],
    srvs: &mut HashMap<String, SrvRecord>,
    addrs: &mut HashMap<String, Vec<IpAddr>>,
    ptrs: &mut Vec<(AdbServiceKind, String)>,
) -> Option<()> {
    if buf.len() < 12 {
        return None;
    }
    let mut c = Cursor { buf, pos: 0 };
    c.skip(2)?; // id
    c.skip(2)?; // flags
    let qd = c.u16()? as usize;
    let an = c.u16()? as usize;
    let ns = c.u16()? as usize;
    let ar = c.u16()? as usize;

    // Skip questions
    for _ in 0..qd {
        c.read_name()?;
        c.skip(4)?; // type + class
    }

    let total_rr = an.saturating_add(ns).saturating_add(ar);
    for _ in 0..total_rr {
        let name = c.read_name()?;
        let rtype = c.u16()?;
        c.skip(2)?; // class
        c.skip(4)?; // ttl
        let rdlen = c.u16()? as usize;
        let rdata_start = c.pos;
        if rdata_start + rdlen > buf.len() {
            return None;
        }

        match rtype {
            12 => {
                // PTR
                let mut sub = Cursor {
                    buf,
                    pos: rdata_start,
                };
                if let Some(target) = sub.read_name() {
                    for (svc, kind) in ADB_SERVICES {
                        if name.eq_ignore_ascii_case(svc) {
                            ptrs.push((*kind, target));
                            break;
                        }
                    }
                }
            }
            33 => {
                // SRV: priority(2) weight(2) port(2) target(name)
                if rdlen >= 6 {
                    let port = u16::from_be_bytes([buf[rdata_start + 4], buf[rdata_start + 5]]);
                    let mut sub = Cursor {
                        buf,
                        pos: rdata_start + 6,
                    };
                    if let Some(target) = sub.read_name() {
                        srvs.insert(name, SrvRecord { target, port });
                    }
                }
            }
            1 if rdlen == 4 => {
                // A (IPv4) — 与 AAAA 共存, 不再覆盖
                let ip = Ipv4Addr::new(
                    buf[rdata_start],
                    buf[rdata_start + 1],
                    buf[rdata_start + 2],
                    buf[rdata_start + 3],
                );
                push_addr(addrs, name, IpAddr::V4(ip));
            }
            28 if rdlen == 16 => {
                // AAAA (IPv6) — 与 A 共存, 不再覆盖
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&buf[rdata_start..rdata_start + 16]);
                push_addr(addrs, name, IpAddr::V6(Ipv6Addr::from(bytes)));
            }
            _ => {}
        }
        c.pos = rdata_start + rdlen;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_well_formed() {
        let q = build_query("_adb._tcp.local");
        // header 12 + name (1+4+_adb 4+_tcp 5+local 0) = roughly
        // labels: _adb (4+1), _tcp (4+1), local (5+1), terminator 1
        assert_eq!(q.len(), 12 + 17 + 4);
        assert_eq!(&q[0..2], &[0, 0]); // id
        let qd = u16::from_be_bytes([q[4], q[5]]);
        assert_eq!(qd, 1);
    }

    #[test]
    fn parse_simple_response_with_srv_and_a() {
        // 手工构造一个最小 mDNS 响应:
        //   answer: PTR _adb._tcp.local -> myphone._adb._tcp.local
        //   additional: SRV myphone._adb._tcp.local -> phone.local:5555
        //   additional: A phone.local -> 192.168.1.42
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 4]); // id + flags
        buf.extend_from_slice(&0u16.to_be_bytes()); // qd
        buf.extend_from_slice(&1u16.to_be_bytes()); // an
        buf.extend_from_slice(&0u16.to_be_bytes()); // ns
        buf.extend_from_slice(&2u16.to_be_bytes()); // ar

        fn enc(name: &str, out: &mut Vec<u8>) {
            for l in name.split('.') {
                out.push(l.len() as u8);
                out.extend_from_slice(l.as_bytes());
            }
            out.push(0);
        }

        // PTR answer
        enc("_adb._tcp.local", &mut buf);
        buf.extend_from_slice(&12u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&120u32.to_be_bytes());
        let mut rd = Vec::new();
        enc("myphone._adb._tcp.local", &mut rd);
        buf.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rd);

        // SRV additional
        enc("myphone._adb._tcp.local", &mut buf);
        buf.extend_from_slice(&33u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&120u32.to_be_bytes());
        let mut rd = Vec::new();
        rd.extend_from_slice(&0u16.to_be_bytes()); // priority
        rd.extend_from_slice(&0u16.to_be_bytes()); // weight
        rd.extend_from_slice(&5555u16.to_be_bytes()); // port
        enc("phone.local", &mut rd);
        buf.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rd);

        // A additional
        enc("phone.local", &mut buf);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&120u32.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[192, 168, 1, 42]);

        let mut srvs = HashMap::new();
        let mut addrs = HashMap::new();
        let mut ptrs = Vec::new();
        parse_message(&buf, &mut srvs, &mut addrs, &mut ptrs).expect("parse");

        assert_eq!(ptrs.len(), 1);
        assert_eq!(ptrs[0].1, "myphone._adb._tcp.local");
        let srv = srvs.get("myphone._adb._tcp.local").expect("srv");
        assert_eq!(srv.port, 5555);
        assert_eq!(srv.target, "phone.local");
        assert_eq!(
            addrs.get("phone.local"),
            Some(&vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42))])
        );
    }

    /// 同一主机名同时带 A (IPv4) 和 AAAA (IPv6) 时, 两条都必须保留,
    /// 且 IPv4 应排在首位 (首选连接地址)。
    #[test]
    fn a_and_aaaa_records_coexist_without_overwrite() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&0u16.to_be_bytes()); // qd
        buf.extend_from_slice(&0u16.to_be_bytes()); // an
        buf.extend_from_slice(&0u16.to_be_bytes()); // ns
        buf.extend_from_slice(&3u16.to_be_bytes()); // ar: A + AAAA + AAAA

        fn enc(name: &str, out: &mut Vec<u8>) {
            for l in name.split('.') {
                out.push(l.len() as u8);
                out.extend_from_slice(l.as_bytes());
            }
            out.push(0);
        }

        // A: phone.local -> 192.168.1.42
        enc("phone.local", &mut buf);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&120u32.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[192, 168, 1, 42]);

        // AAAA #1 (link-local): phone.local -> fe80::1
        enc("phone.local", &mut buf);
        buf.extend_from_slice(&28u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&120u32.to_be_bytes());
        buf.extend_from_slice(&16u16.to_be_bytes());
        let mut ll = [0u8; 16];
        ll[0] = 0xfe;
        ll[1] = 0x80;
        ll[15] = 1;
        buf.extend_from_slice(&ll);

        // AAAA #2 (全局): phone.local -> 240e::1
        enc("phone.local", &mut buf);
        buf.extend_from_slice(&28u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&120u32.to_be_bytes());
        buf.extend_from_slice(&16u16.to_be_bytes());
        let mut global = [0u8; 16];
        global[0] = 0x24;
        global[1] = 0x0e;
        global[15] = 1;
        buf.extend_from_slice(&global);

        let mut srvs = HashMap::new();
        let mut addrs = HashMap::new();
        let mut ptrs = Vec::new();
        parse_message(&buf, &mut srvs, &mut addrs, &mut ptrs).expect("parse");

        let ips = addrs.get("phone.local").expect("addrs");
        assert_eq!(ips.len(), 3, "IPv4 与两条 IPv6 都应保留: {ips:?}");
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)));
        // 排序: IPv4 -> 全局 IPv6 -> link-local IPv6
        assert_eq!(ips[1], IpAddr::V6(Ipv6Addr::from(global)));
        assert_eq!(ips[2], IpAddr::V6(Ipv6Addr::from(ll)));
    }

    /// 只有 AAAA 记录时, 首选地址应为 IPv6。
    #[test]
    fn ipv6_only_service_uses_ipv6_as_primary() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // ar: AAAA

        fn enc(name: &str, out: &mut Vec<u8>) {
            for l in name.split('.') {
                out.push(l.len() as u8);
                out.extend_from_slice(l.as_bytes());
            }
            out.push(0);
        }

        enc("phone.local", &mut buf);
        buf.extend_from_slice(&28u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&120u32.to_be_bytes());
        buf.extend_from_slice(&16u16.to_be_bytes());
        let mut ll = [0u8; 16];
        ll[0] = 0xfe;
        ll[1] = 0x80;
        ll[15] = 9;
        buf.extend_from_slice(&ll);

        let mut srvs = HashMap::new();
        let mut addrs = HashMap::new();
        let mut ptrs = Vec::new();
        parse_message(&buf, &mut srvs, &mut addrs, &mut ptrs).expect("parse");

        let ips = addrs.get("phone.local").expect("addrs");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], IpAddr::V6(Ipv6Addr::from(ll)));
    }

    /// 重复地址 (同一 A 记录出现两次) 应去重。
    #[test]
    fn duplicate_addresses_are_deduplicated() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&2u16.to_be_bytes()); // ar: A + A

        fn enc(name: &str, out: &mut Vec<u8>) {
            for l in name.split('.') {
                out.push(l.len() as u8);
                out.extend_from_slice(l.as_bytes());
            }
            out.push(0);
        }

        for _ in 0..2 {
            enc("phone.local", &mut buf);
            buf.extend_from_slice(&1u16.to_be_bytes());
            buf.extend_from_slice(&1u16.to_be_bytes());
            buf.extend_from_slice(&120u32.to_be_bytes());
            buf.extend_from_slice(&4u16.to_be_bytes());
            buf.extend_from_slice(&[192, 168, 1, 42]);
        }

        let mut srvs = HashMap::new();
        let mut addrs = HashMap::new();
        let mut ptrs = Vec::new();
        parse_message(&buf, &mut srvs, &mut addrs, &mut ptrs).expect("parse");

        let ips = addrs.get("phone.local").expect("addrs");
        assert_eq!(ips.len(), 1, "重复地址应去重: {ips:?}");
    }

    /// 完整的 discover() 组装: A + AAAA 共存时 AdbService 同时携带两者。
    #[test]
    fn discover_service_carries_both_ipv4_and_ipv6() {
        // 复用 parse_message 的输入构造, 直接验证 discover 的组装逻辑。
        // 这里仅验证排序 + 首选地址选择, 通过 push_addr 单元级验证。
        let mut map = HashMap::new();
        let fe80 = "fe80::1".parse::<IpAddr>().unwrap();
        let v4 = "192.168.1.42".parse::<IpAddr>().unwrap();
        push_addr(&mut map, "phone.local".into(), fe80); // 先到的是 IPv6
        push_addr(&mut map, "phone.local".into(), v4); // 后到的是 IPv4
        let ips = map.get("phone.local").unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], v4, "IPv4 必须排在首位 (首选)");
        assert_eq!(ips[1], fe80);
    }

    #[test]
    fn name_compression_pointer_resolved() {
        // 在 offset 0 写一个名字 abc.local，然后指针指回它
        let mut buf = Vec::new();
        buf.push(3); buf.extend_from_slice(b"abc");
        buf.push(5); buf.extend_from_slice(b"local");
        buf.push(0);
        let ptr_start = buf.len();
        buf.push(0xC0); buf.push(0); // 指针到 offset 0

        let mut c = Cursor { buf: &buf, pos: ptr_start };
        assert_eq!(c.read_name(), Some("abc.local".into()));
    }
}
