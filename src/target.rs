//! Target parsing: IPv4 / IPv6 (with zone id) / hostname / CIDR subnet.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

use crate::error::TargetError;

#[derive(Clone, Debug)]
pub struct Target {
    pub ip: IpAddr,
    /// IPv6 link-local zone (scope_id).
    pub zone: Option<u32>,
    /// Human-friendly form used by the original input or expanded from CIDR.
    pub display: String,
}

impl Target {
    pub fn socket(&self, port: u16) -> SocketAddr {
        match self.ip {
            IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
            IpAddr::V6(v6) => {
                SocketAddr::V6(SocketAddrV6::new(v6, port, 0, self.zone.unwrap_or(0)))
            }
        }
    }
}

/// Maximum number of addresses a single CIDR expansion may produce.
pub const CIDR_MAX_ADDRESSES: u64 = 65536;

/// Parse a target string into a vector of [`Target`].
///
/// Accepted forms:
/// - IPv4 literal: `192.168.1.42`
/// - IPv6 literal: `fe80::1`
/// - IPv6 with zone id (numeric only): `fe80::1%2`
/// - Hostname: `phone.local`
/// - IPv4 CIDR: `192.168.1.0/24` (up to `/16`)
pub fn parse_targets(input: &str) -> Result<Vec<Target>, TargetError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(TargetError::Empty);
    }

    // CIDR — `host/mask` where mask parses as u8.
    if let Some((host, mask)) = s.rsplit_once('/') {
        if let Ok(mask) = mask.parse::<u8>() {
            return parse_cidr(host, mask);
        }
    }

    // IPv6 + zone id, e.g. `fe80::1%2`.
    if let Some((addr_part, zone_part)) = s.split_once('%') {
        let v6: Ipv6Addr = addr_part
            .parse()
            .map_err(|_| TargetError::InvalidIp(addr_part.to_string()))?;
        let zone: u32 = zone_part
            .parse()
            .map_err(|_| TargetError::InvalidIpv6Zone(zone_part.to_string()))?;
        return Ok(vec![Target {
            ip: IpAddr::V6(v6),
            zone: Some(zone),
            display: s.to_string(),
        }]);
    }

    // Bare IP literal.
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(vec![Target {
            ip,
            zone: None,
            display: s.to_string(),
        }]);
    }

    // Hostname via getaddrinfo.
    let host_port = format!("{s}:0");
    let addrs: Vec<SocketAddr> = host_port
        .to_socket_addrs()
        .map_err(|e| TargetError::HostResolveFailed {
            host: s.to_string(),
            source: e.to_string(),
        })?
        .collect();
    if addrs.is_empty() {
        return Err(TargetError::HostNoResults(s.to_string()));
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

fn parse_cidr(host: &str, mask: u8) -> Result<Vec<Target>, TargetError> {
    let ip: IpAddr = host
        .parse()
        .map_err(|_| TargetError::InvalidCidrHost(host.to_string()))?;
    match ip {
        IpAddr::V4(v4) => {
            if mask > 32 {
                return Err(TargetError::CidrMaskOutOfRange { max: 32, got: mask });
            }
            let host_bits = 32 - mask as u32;
            let count: u64 = 1u64 << host_bits;
            if count > CIDR_MAX_ADDRESSES {
                return Err(TargetError::CidrTooLarge { count });
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
        IpAddr::V6(_) => Err(TargetError::Ipv6CidrUnsupported),
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
        assert_eq!(t[0].zone, None);
    }

    #[test]
    fn ipv4_literal_trims_whitespace() {
        let t = parse_targets("  192.168.1.1  \n").unwrap();
        assert_eq!(t[0].display, "192.168.1.1");
    }

    #[test]
    fn ipv6_literal() {
        let t = parse_targets("fe80::1").unwrap();
        assert_eq!(t.len(), 1);
        assert!(matches!(t[0].ip, IpAddr::V6(_)));
        assert_eq!(t[0].zone, None);
    }

    #[test]
    fn ipv6_with_zone() {
        let t = parse_targets("fe80::1%2").unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].zone, Some(2));
        assert!(matches!(t[0].ip, IpAddr::V6(_)));
    }

    #[test]
    fn ipv6_zone_zero_is_valid() {
        let t = parse_targets("fe80::1%0").unwrap();
        assert_eq!(t[0].zone, Some(0));
    }

    #[test]
    fn ipv6_zone_max_u32_is_valid() {
        let t = parse_targets("fe80::1%4294967295").unwrap();
        assert_eq!(t[0].zone, Some(u32::MAX));
    }

    #[test]
    fn ipv6_zone_overflow_fails() {
        let err = parse_targets("fe80::1%4294967296").unwrap_err();
        assert!(matches!(err, TargetError::InvalidIpv6Zone(_)));
    }

    #[test]
    fn ipv6_zone_non_numeric_fails() {
        let err = parse_targets("fe80::1%eth0").unwrap_err();
        assert!(matches!(err, TargetError::InvalidIpv6Zone(_)));
    }

    #[test]
    fn ipv6_bad_address_with_zone_fails() {
        let err = parse_targets("not_ipv6%2").unwrap_err();
        assert!(matches!(err, TargetError::InvalidIp(_)));
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
        assert_eq!(t[0].ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
    }

    #[test]
    fn cidr_slash16_boundary_passes() {
        let t = parse_targets("10.0.0.0/16").unwrap();
        assert_eq!(t.len(), 65536);
        assert_eq!(t[0].ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(t[65535].ip, IpAddr::V4(Ipv4Addr::new(10, 0, 255, 255)));
    }

    #[test]
    fn cidr_slash15_boundary_fails() {
        let err = parse_targets("10.0.0.0/15").unwrap_err();
        assert!(matches!(err, TargetError::CidrTooLarge { .. }));
    }

    #[test]
    fn cidr_slash0_fails() {
        let err = parse_targets("0.0.0.0/0").unwrap_err();
        assert!(matches!(err, TargetError::CidrTooLarge { .. }));
    }

    #[test]
    fn cidr_mask_over_32_fails() {
        let err = parse_targets("10.0.0.0/33").unwrap_err();
        assert!(matches!(
            err,
            TargetError::CidrMaskOutOfRange { max: 32, got: 33 }
        ));
    }

    #[test]
    fn cidr_aligns_host_bits_to_network() {
        // 5 in the host portion of /24 should round down to .0
        let t = parse_targets("192.168.1.5/24").unwrap();
        assert_eq!(t.len(), 256);
        assert_eq!(t[0].ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
    }

    #[test]
    fn cidr_empty_host_fails() {
        let err = parse_targets("/24").unwrap_err();
        assert!(matches!(err, TargetError::InvalidCidrHost(_)));
    }

    #[test]
    fn ipv6_cidr_unsupported() {
        let err = parse_targets("::1/64").unwrap_err();
        assert!(matches!(err, TargetError::Ipv6CidrUnsupported));
    }

    #[test]
    fn empty_input_fails() {
        assert!(matches!(parse_targets("").unwrap_err(), TargetError::Empty));
        assert!(matches!(
            parse_targets("   ").unwrap_err(),
            TargetError::Empty
        ));
    }

    #[test]
    fn socket_v4_constructs_correctly() {
        let t = &parse_targets("10.0.0.1").unwrap()[0];
        let sa = t.socket(5555);
        assert_eq!(sa.port(), 5555);
        assert!(sa.is_ipv4());
    }

    #[test]
    fn socket_v6_carries_scope_id() {
        let t = &parse_targets("fe80::1%5").unwrap()[0];
        let sa = t.socket(5555);
        match sa {
            SocketAddr::V6(v6) => assert_eq!(v6.scope_id(), 5),
            _ => panic!("expected v6"),
        }
    }

    #[test]
    fn socket_v6_without_zone_uses_zero() {
        let t = &parse_targets("::1").unwrap()[0];
        match t.socket(80) {
            SocketAddr::V6(v6) => assert_eq!(v6.scope_id(), 0),
            _ => panic!("expected v6"),
        }
    }

    #[test]
    fn target_error_display_contains_input() {
        let err = parse_targets("10.0.0.0/33").unwrap_err();
        assert!(err.to_string().contains("/33"));
    }

    #[test]
    fn target_error_implements_std_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        let err = TargetError::Empty;
        assert_error(&err);
    }
}
