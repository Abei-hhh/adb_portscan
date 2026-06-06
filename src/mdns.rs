//! 最小化的 mDNS 客户端，用于发现局域网内的 ADB 服务。
//!
//! 实现策略：
//! - 绑定 UDP socket 到 0.0.0.0:0，向 224.0.0.251:5353 发送 PTR 查询
//! - 监听响应直到超时，解析所有 SRV / A / AAAA / PTR 记录
//! - 关联 PTR -> SRV -> A，得到 (instance, ip, port)
//!
//! 不依赖外部 crate，纯手工解析 DNS 报文（处理 name compression）。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct AdbService {
    pub kind: AdbServiceKind,
    pub instance: String,
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Copy)]
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
    let mut a_records: HashMap<String, IpAddr> = HashMap::new();
    let mut ptrs: Vec<(AdbServiceKind, String)> = Vec::new();

    let deadline = Instant::now() + total_timeout;
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((n, _)) => {
                parse_message(&buf[..n], &mut srv_records, &mut a_records, &mut ptrs);
            }
            Err(_) => continue,
        }
    }

    let mut out = Vec::new();
    for (kind, instance) in ptrs {
        if let Some(srv) = srv_records.get(&instance) {
            if let Some(ip) = a_records.get(&srv.target).copied() {
                out.push(AdbService {
                    kind,
                    instance,
                    ip,
                    port: srv.port,
                });
            }
        }
    }
    out
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
    m.extend_from_slice(&1u16.to_be_bytes()); // class = IN
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
    addrs: &mut HashMap<String, IpAddr>,
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
            1 => {
                // A
                if rdlen == 4 {
                    let ip = Ipv4Addr::new(
                        buf[rdata_start],
                        buf[rdata_start + 1],
                        buf[rdata_start + 2],
                        buf[rdata_start + 3],
                    );
                    addrs.insert(name, IpAddr::V4(ip));
                }
            }
            28 => {
                // AAAA
                if rdlen == 16 {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&buf[rdata_start..rdata_start + 16]);
                    addrs.insert(name, IpAddr::V6(Ipv6Addr::from(bytes)));
                }
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
        assert_eq!(addrs.get("phone.local"), Some(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42))));
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
