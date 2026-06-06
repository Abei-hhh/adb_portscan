//! ADB 协议握手 + TLS ClientHello 探测。
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdbKind {
    /// 明文 ADB (CNXN/AUTH 响应)，旧版 adb tcpip 模式
    Plain,
    /// ADB over TLS (Android 11+ 无线调试)
    Tls,
    /// TCP 打开但既非 ADB 明文也非 TLS
    Open,
}

pub const A_CNXN: u32 = 0x4e58_4e43; // "CNXN"
pub const A_AUTH: u32 = 0x4854_5541; // "AUTH"
const ADB_VERSION: u32 = 0x0100_0000;
const ADB_MAX_PAYLOAD: u32 = 256 * 1024;

/// 构造一个 host 端 CNXN 包 (24 字节头 + payload)。
pub fn build_cnxn_packet() -> Vec<u8> {
    let payload = b"host::adb_portScan\0";
    let crc: u32 = payload.iter().map(|&b| b as u32).sum();

    let mut pkt = Vec::with_capacity(24 + payload.len());
    pkt.extend_from_slice(&A_CNXN.to_le_bytes());
    pkt.extend_from_slice(&ADB_VERSION.to_le_bytes());
    pkt.extend_from_slice(&ADB_MAX_PAYLOAD.to_le_bytes());
    pkt.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    pkt.extend_from_slice(&crc.to_le_bytes());
    pkt.extend_from_slice(&(A_CNXN ^ 0xFFFF_FFFF).to_le_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

/// 校验完整 24 字节 ADB 包头: magic == cmd ^ 0xFFFFFFFF 且 cmd 是已知命令。
pub fn verify_adb_header(buf: &[u8; 24]) -> Option<u32> {
    let cmd = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let data_len = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    let magic = u32::from_le_bytes(buf[20..24].try_into().unwrap());
    if cmd ^ 0xFFFF_FFFF != magic {
        return None;
    }
    if cmd != A_CNXN && cmd != A_AUTH {
        return None;
    }
    // data_len 必须在合理范围
    if data_len > ADB_MAX_PAYLOAD {
        return None;
    }
    Some(cmd)
}

/// 构造一个最小可被解析的 TLS 1.2 ClientHello (不含 SNI / 不带扩展)。
pub fn build_tls_client_hello() -> Vec<u8> {
    // Handshake body
    let mut hs = Vec::new();
    hs.extend_from_slice(&[0x03, 0x03]); // client_version = TLS 1.2
    hs.extend_from_slice(&[0x55; 32]); // random (固定填充, 探测不需要随机)
    hs.push(0); // session_id length = 0
    let suites: [u8; 4] = [0x00, 0x2F, 0x00, 0x35]; // 任意两个常见 RSA 套件
    hs.extend_from_slice(&(suites.len() as u16).to_be_bytes());
    hs.extend_from_slice(&suites);
    hs.extend_from_slice(&[0x01, 0x00]); // compression methods: null

    // Handshake wrapper: type=ClientHello(1) + 3-byte length + body
    let mut msg = Vec::with_capacity(4 + hs.len());
    msg.push(0x01);
    let hs_len = hs.len() as u32;
    msg.push((hs_len >> 16) as u8);
    msg.push((hs_len >> 8) as u8);
    msg.push(hs_len as u8);
    msg.extend_from_slice(&hs);

    // TLS Record: type=Handshake(22) + version + length + payload
    let mut rec = Vec::with_capacity(5 + msg.len());
    rec.push(0x16);
    rec.extend_from_slice(&[0x03, 0x01]); // record version TLS 1.0 (兼容)
    rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    rec.extend_from_slice(&msg);
    rec
}

fn try_adb(stream: &mut TcpStream, read_timeout: Duration) -> bool {
    if stream.set_read_timeout(Some(read_timeout)).is_err() {
        return false;
    }
    if stream.set_write_timeout(Some(read_timeout)).is_err() {
        return false;
    }
    let pkt = build_cnxn_packet();
    if stream.write_all(&pkt).is_err() {
        return false;
    }
    let mut hdr = [0u8; 24];
    if stream.read_exact(&mut hdr).is_err() {
        return false;
    }
    verify_adb_header(&hdr).is_some()
}

fn try_tls(stream: &mut TcpStream, read_timeout: Duration) -> bool {
    if stream.set_read_timeout(Some(read_timeout)).is_err() {
        return false;
    }
    if stream.set_write_timeout(Some(read_timeout)).is_err() {
        return false;
    }
    let hello = build_tls_client_hello();
    if stream.write_all(&hello).is_err() {
        return false;
    }
    let mut resp = [0u8; 5];
    if stream.read_exact(&mut resp).is_err() {
        return false;
    }
    // TLS Record Layer 应以 ContentType=Handshake(0x16) 开头，
    // 版本字段在 (0x0301..=0x0304) 之间
    resp[0] == 0x16 && resp[1] == 0x03 && (0x01..=0x04).contains(&resp[2])
}

/// Probe an open TCP endpoint: try plaintext ADB first, then TLS.
/// Each probe needs a fresh TCP connection (the previous write dirties the stream).
pub fn probe(addr: SocketAddr, connect_timeout: Duration, verify_timeout: Duration) -> AdbKind {
    if let Ok(mut s) = TcpStream::connect_timeout(&addr, connect_timeout) {
        if try_adb(&mut s, verify_timeout) {
            return AdbKind::Plain;
        }
    }
    if let Ok(mut s) = TcpStream::connect_timeout(&addr, connect_timeout) {
        if try_tls(&mut s, verify_timeout) {
            return AdbKind::Tls;
        }
    }
    AdbKind::Open
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cnxn_packet_layout() {
        let p = build_cnxn_packet();
        assert!(p.len() >= 24);
        // 头部 cmd 字段 == "CNXN"
        assert_eq!(&p[0..4], b"CNXN");
        // magic == cmd XOR 0xFFFFFFFF
        let cmd = u32::from_le_bytes(p[0..4].try_into().unwrap());
        let magic = u32::from_le_bytes(p[20..24].try_into().unwrap());
        assert_eq!(cmd ^ 0xFFFF_FFFF, magic);
    }

    #[test]
    fn verify_accepts_well_formed_cnxn() {
        let p = build_cnxn_packet();
        let hdr: [u8; 24] = p[..24].try_into().unwrap();
        assert_eq!(verify_adb_header(&hdr), Some(A_CNXN));
    }

    #[test]
    fn verify_rejects_bad_magic() {
        let mut p = build_cnxn_packet();
        p[20] ^= 0xFF; // 破坏 magic
        let hdr: [u8; 24] = p[..24].try_into().unwrap();
        assert_eq!(verify_adb_header(&hdr), None);
    }

    #[test]
    fn verify_rejects_unknown_cmd() {
        let mut hdr = [0u8; 24];
        let cmd: u32 = 0x4142_4344; // 随便编一个
        hdr[0..4].copy_from_slice(&cmd.to_le_bytes());
        hdr[20..24].copy_from_slice(&(cmd ^ 0xFFFF_FFFF).to_le_bytes());
        assert_eq!(verify_adb_header(&hdr), None);
    }

    #[test]
    fn tls_client_hello_starts_with_record_header() {
        let h = build_tls_client_hello();
        assert!(h.len() >= 5);
        assert_eq!(h[0], 0x16); // Handshake
        assert_eq!(h[1], 0x03); // major
        // record length field equals remaining bytes
        let rec_len = u16::from_be_bytes([h[3], h[4]]) as usize;
        assert_eq!(h.len(), 5 + rec_len);
    }

    #[test]
    fn verify_accepts_well_formed_auth() {
        let mut hdr = [0u8; 24];
        hdr[0..4].copy_from_slice(&A_AUTH.to_le_bytes());
        hdr[20..24].copy_from_slice(&(A_AUTH ^ 0xFFFF_FFFF).to_le_bytes());
        assert_eq!(verify_adb_header(&hdr), Some(A_AUTH));
    }

    #[test]
    fn verify_rejects_oversized_payload() {
        let mut hdr = [0u8; 24];
        hdr[0..4].copy_from_slice(&A_CNXN.to_le_bytes());
        let too_big = ADB_MAX_PAYLOAD + 1;
        hdr[12..16].copy_from_slice(&too_big.to_le_bytes());
        hdr[20..24].copy_from_slice(&(A_CNXN ^ 0xFFFF_FFFF).to_le_bytes());
        assert_eq!(verify_adb_header(&hdr), None);
    }

    #[test]
    fn verify_accepts_payload_at_max() {
        let mut hdr = [0u8; 24];
        hdr[0..4].copy_from_slice(&A_CNXN.to_le_bytes());
        hdr[12..16].copy_from_slice(&ADB_MAX_PAYLOAD.to_le_bytes());
        hdr[20..24].copy_from_slice(&(A_CNXN ^ 0xFFFF_FFFF).to_le_bytes());
        assert_eq!(verify_adb_header(&hdr), Some(A_CNXN));
    }

    #[test]
    fn cnxn_payload_carries_host_banner() {
        let p = build_cnxn_packet();
        let payload = &p[24..];
        assert!(payload.starts_with(b"host::"));
    }

    #[test]
    fn cnxn_packet_data_length_matches_payload() {
        let p = build_cnxn_packet();
        let data_len = u32::from_le_bytes(p[12..16].try_into().unwrap()) as usize;
        assert_eq!(p.len(), 24 + data_len);
    }

    #[test]
    fn cnxn_packet_crc_is_byte_sum() {
        let p = build_cnxn_packet();
        let stored_crc = u32::from_le_bytes(p[16..20].try_into().unwrap());
        let calc_crc: u32 = p[24..].iter().map(|&b| b as u32).sum();
        assert_eq!(stored_crc, calc_crc);
    }
}
