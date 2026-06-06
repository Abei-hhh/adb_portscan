//! 输入目标解析：IPv4 / IPv6 (含 zone id) / 主机名 / CIDR 子网。
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

#[derive(Clone, Debug)]
pub struct Target {
    pub ip: IpAddr,
    pub zone: Option<u32>, // IPv6 link-local zone (scope_id)
    pub display: String,
}

impl Target {
    pub fn socket(&self, port: u16) -> SocketAddr {
        match self.ip {
            IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
            IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, self.zone.unwrap_or(0))),
        }
    }
}

pub fn parse_targets(input: &str) -> Result<Vec<Target>, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("空输入".into());
    }

    // CIDR (含 '/')
    if let Some((host, mask)) = s.rsplit_once('/') {
        if let Ok(mask) = mask.parse::<u8>() {
            return parse_cidr(host, mask);
        }
    }

    // IPv6 + zone id, e.g. fe80::1%2
    if let Some((addr_part, zone_part)) = s.split_once('%') {
        let v6: Ipv6Addr = addr_part
            .parse()
            .map_err(|_| format!("IPv6 地址 {addr_part} 非法"))?;
        let zone: u32 = zone_part
            .parse()
            .map_err(|_| format!("zone 必须是数字接口索引: %{zone_part}"))?;
        return Ok(vec![Target {
            ip: IpAddr::V6(v6),
            zone: Some(zone),
            display: s.to_string(),
        }]);
    }

    // IP 字面量
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(vec![Target {
            ip,
            zone: None,
            display: s.to_string(),
        }]);
    }

    // 主机名（getaddrinfo）
    let host_port = format!("{}:0", s);
    let addrs: Vec<SocketAddr> = host_port
        .to_socket_addrs()
        .map_err(|e| format!("无法解析主机名 {s}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("主机名 {s} 没有解析结果"));
    }
    Ok(addrs
        .into_iter()
        .map(|sa| Target {
            ip: sa.ip(),
            zone: None,
            display: format!("{s} ({})", sa.ip()),
        })
        .collect())
}

fn parse_cidr(host: &str, mask: u8) -> Result<Vec<Target>, String> {
    let ip: IpAddr = host.parse().map_err(|_| format!("CIDR 主机部分 {host} 非法"))?;
    match ip {
        IpAddr::V4(v4) => {
            if mask > 32 {
                return Err("IPv4 CIDR 掩码不能超过 32".into());
            }
            let host_bits = 32 - mask as u32;
            let count: u64 = 1u64 << host_bits;
            if count > 65536 {
                return Err(format!(
                    "CIDR /{mask} 包含 {count} 个 IP，过大；请使用 /16 或更小"
                ));
            }
            let base = if mask == 0 {
                0
            } else {
                u32::from(v4) & (!0u32 << host_bits)
            };
            let mut out = Vec::with_capacity(count as usize);
            for i in 0..count {
                let addr = Ipv4Addr::from(base.wrapping_add(i as u32));
                out.push(Target {
                    ip: IpAddr::V4(addr),
                    zone: None,
                    display: addr.to_string(),
                });
            }
            Ok(out)
        }
        IpAddr::V6(_) => Err("暂不支持 IPv6 CIDR".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_literal() {
        let t = parse_targets("192.168.1.1").unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn ipv6_with_zone() {
        let t = parse_targets("fe80::1%2").unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].zone, Some(2));
        assert!(matches!(t[0].ip, IpAddr::V6(_)));
    }

    #[test]
    fn ipv6_zone_non_numeric_fails() {
        assert!(parse_targets("fe80::1%eth0").is_err());
    }

    #[test]
    fn cidr_slash24() {
        let t = parse_targets("192.168.1.0/24").unwrap();
        assert_eq!(t.len(), 256);
        assert_eq!(t[0].ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(t[255].ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)));
    }

    #[test]
    fn cidr_slash32_single() {
        let t = parse_targets("10.0.0.5/32").unwrap();
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn cidr_too_large() {
        assert!(parse_targets("10.0.0.0/8").is_err());
    }

    #[test]
    fn empty_input() {
        assert!(parse_targets("   ").is_err());
    }

    #[test]
    fn socket_v6_carries_scope_id() {
        let t = &parse_targets("fe80::1%5").unwrap()[0];
        let sa = t.socket(5555);
        if let SocketAddr::V6(v6) = sa {
            assert_eq!(v6.scope_id(), 5);
        } else {
            panic!("expected v6");
        }
    }
}
