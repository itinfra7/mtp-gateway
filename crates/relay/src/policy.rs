use crate::config::{Policy, UserPolicy};
use ipnet::IpNet;
use mtp_protocol::{fake_ip, normalize};
use std::net::IpAddr;

pub fn allowed(policy: &Policy, user: &UserPolicy, ip: IpAddr) -> bool {
    let ip = normalize(ip);
    if fake_ip(ip)
        || policy
            .management_addresses
            .iter()
            .any(|v| normalize(*v) == ip)
        || policy
            .deny
            .iter()
            .chain(&user.deny)
            .any(|n| n.contains(&ip))
    {
        return false;
    }
    if policy
        .allow
        .iter()
        .chain(&user.allow)
        .any(|n| n.contains(&ip))
    {
        return true;
    }
    if matches!(ip, IpAddr::V6(_))
        && !"2000::/3"
            .parse::<IpNet>()
            .expect("고정 CIDR")
            .contains(&ip)
    {
        return false;
    }
    let denied = [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/96",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ];
    !denied
        .iter()
        .any(|s| s.parse::<IpNet>().expect("고정 CIDR").contains(&ip))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn 사설_매핑_메타데이터_차단() {
        let p = Policy::default();
        let u = UserPolicy::default();
        for s in [
            "127.0.0.1",
            "10.1.1.1",
            "169.254.169.254",
            "::1",
            "::ffff:10.0.0.1",
            "fe80::1",
            "224.0.0.1",
            "198.19.1.1",
        ] {
            assert!(!allowed(&p, &u, s.parse().unwrap()), "{s}");
        }
        assert!(allowed(&p, &u, "1.1.1.1".parse().unwrap()));
        assert!(allowed(&p, &u, "2606:4700:4700::1111".parse().unwrap()));
    }
    #[test]
    fn 명시허용과_절대금지() {
        let p = Policy {
            allow: vec!["0.0.0.0/0".parse().unwrap()],
            ..Default::default()
        };
        assert!(allowed(
            &p,
            &UserPolicy::default(),
            "127.0.0.1".parse().unwrap()
        ));
        assert!(!allowed(
            &p,
            &UserPolicy::default(),
            "198.18.1.1".parse().unwrap()
        ));
    }
}
