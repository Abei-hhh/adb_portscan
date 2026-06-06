//! 端口列表构造：按命中概率排序的全量 1-65535 列表。

/// 顺序：
/// 1. 5555 (旧版 adb tcpip)
/// 2. 32768-60999 (Linux ephemeral 默认段，Android 11+ 无线调试落在这)
/// 3. 1024-32767 + 61000-65535 (其余非特权端口)
/// 4. 1-1023 (特权端口，理论上不出现)
pub fn default_ports() -> Vec<u16> {
    let mut v: Vec<u16> = Vec::with_capacity(65535);
    let mut seen = [false; 65536];
    let mut push = |v: &mut Vec<u16>, p: u16| {
        if !seen[p as usize] {
            seen[p as usize] = true;
            v.push(p);
        }
    };
    push(&mut v, 5555);
    for p in 32768u16..=60999 {
        push(&mut v, p);
    }
    for p in 1024u16..=32767 {
        push(&mut v, p);
    }
    for p in 61000u16..=65535 {
        push(&mut v, p);
    }
    for p in 1u16..=1023 {
        push(&mut v, p);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn covers_1_to_65535() {
        let v = default_ports();
        assert_eq!(v.len(), 65535);
        let set: HashSet<u16> = v.iter().copied().collect();
        assert_eq!(set.len(), 65535);
        for p in 1u16..=65535 {
            assert!(set.contains(&p), "missing port {p}");
        }
    }

    #[test]
    fn five_thousand_first() {
        let v = default_ports();
        assert_eq!(v[0], 5555);
    }

    #[test]
    fn ephemeral_segment_high_priority() {
        let v = default_ports();
        // 5555 之后紧跟 32768
        assert_eq!(v[1], 32768);
        // 60999 必须出现在 1024 之前
        let pos_60999 = v.iter().position(|&p| p == 60999).unwrap();
        let pos_1024 = v.iter().position(|&p| p == 1024).unwrap();
        assert!(pos_60999 < pos_1024);
    }
}
