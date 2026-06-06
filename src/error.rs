//! Public error types for the library API.
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    Empty,
    InvalidIp(String),
    InvalidCidrHost(String),
    CidrMaskOutOfRange { max: u8, got: u8 },
    CidrTooLarge { count: u64 },
    InvalidIpv6Zone(String),
    Ipv6CidrUnsupported,
    HostResolveFailed { host: String, source: String },
    HostNoResults(String),
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty input"),
            Self::InvalidIp(s) => write!(f, "invalid IP literal: {s}"),
            Self::InvalidCidrHost(s) => write!(f, "invalid CIDR host part: {s:?}"),
            Self::CidrMaskOutOfRange { max, got } => {
                write!(f, "CIDR mask /{got} out of range (max /{max})")
            }
            Self::CidrTooLarge { count } => write!(
                f,
                "CIDR contains {count} addresses, exceeds /16 limit (65536)"
            ),
            Self::InvalidIpv6Zone(s) => write!(f, "IPv6 zone id must be numeric: %{s}"),
            Self::Ipv6CidrUnsupported => write!(f, "IPv6 CIDR not supported"),
            Self::HostResolveFailed { host, source } => {
                write!(f, "hostname {host} resolve failed: {source}")
            }
            Self::HostNoResults(s) => write!(f, "hostname {s} resolved to no addresses"),
        }
    }
}

impl std::error::Error for TargetError {}
