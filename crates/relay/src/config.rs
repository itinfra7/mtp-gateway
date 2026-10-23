use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

pub fn read_limited(path: &Path, max: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() <= max as u64,
        "설정 파일 크기 또는 형식 한도"
    );
    let mut data = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut data)?;
    ensure!(data.len() <= max, "설정 읽기 한도");
    Ok(data)
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: Vec<SocketAddr>,
    pub secret_file: PathBuf,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub client_ca: PathBuf,
    pub registry_file: PathBuf,
    pub metrics_socket: PathBuf,
    pub resolver: ResolverConfig,
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub log_domains: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverConfig {
    pub address: SocketAddr,
    #[serde(default = "udp")]
    pub mode: String,
    pub server_name: Option<String>,
    pub ca_file: Option<PathBuf>,
    #[serde(default = "dns_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "cache_limit")]
    pub cache_entries: usize,
}
fn udp() -> String {
    "udp".into()
}
fn dns_timeout() -> u64 {
    3
}
fn cache_limit() -> usize {
    1024
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub allow: Vec<IpNet>,
    #[serde(default)]
    pub deny: Vec<IpNet>,
    #[serde(default)]
    pub management_addresses: Vec<IpAddr>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub connections: usize,
    pub streams: usize,
    pub handshakes: usize,
    pub handshakes_per_second: u32,
    pub handshake_seconds: u64,
    pub connect_seconds: u64,
    pub tcp_idle_seconds: u64,
    pub udp_idle_seconds: u64,
    pub drain_seconds: u64,
    pub buffer_bytes: usize,
    pub connection_buffer_bytes: usize,
    pub replay_entries: usize,
    pub tcp_per_connection: usize,
    pub udp_per_connection: usize,
    pub dns_inflight: usize,
    pub control_queue: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            connections: 64,
            streams: 512,
            handshakes: 16,
            handshakes_per_second: 16,
            handshake_seconds: 10,
            connect_seconds: 8,
            tcp_idle_seconds: 300,
            udp_idle_seconds: 120,
            drain_seconds: 15,
            buffer_bytes: 64 * 1024 * 1024,
            connection_buffer_bytes: 16 * 1024 * 1024,
            replay_entries: 4096,
            tcp_per_connection: 512,
            udp_per_connection: 512,
            dns_inflight: 32,
            control_queue: 1024,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UserPolicy {
    pub enabled: bool,
    pub connections: usize,
    pub tcp_streams: usize,
    pub udp_associations: usize,
    pub bytes_per_second: u64,
    pub udp_per_second: u32,
    pub buffer_bytes: usize,
    pub allow: Vec<IpNet>,
    pub deny: Vec<IpNet>,
}
impl Default for UserPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            connections: 32,
            tcp_streams: 512,
            udp_associations: 512,
            bytes_per_second: 128 * 1024 * 1024,
            udp_per_second: 10000,
            buffer_bytes: 64 * 1024 * 1024,
            allow: vec![],
            deny: vec![],
        }
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub id: String,
    pub owner: String,
    pub enabled: bool,
    pub issued_at: String,
    pub not_after: String,
}
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub revision: u64,
    pub enabled: bool,
    pub users: BTreeMap<String, UserPolicy>,
    pub certificates: BTreeMap<String, Device>,
}
pub fn valid_id(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let c: Self = toml::from_str(std::str::from_utf8(&read_limited(path, 131072)?)?)?;
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.listen.is_empty()
                && self.listen.len() <= 4
                && self.listen.iter().all(|a| a.port() != 0),
            "리스닝 주소 한도"
        );
        ensure!(
            self.policy.allow.len() <= 256
                && self.policy.deny.len() <= 256
                && self.policy.management_addresses.len() <= 256,
            "목적지 정책 한도"
        );
        let l = &self.limits;
        ensure!(
            (1..=1024).contains(&l.connections)
                && (1..=4096).contains(&l.streams)
                && (1..=128).contains(&l.handshakes)
                && (1..=100).contains(&l.handshakes_per_second),
            "연결/핸드셰이크 한도"
        );
        ensure!(
            (1..=60).contains(&l.handshake_seconds)
                && (1..=120).contains(&l.connect_seconds)
                && (1..=86400).contains(&l.tcp_idle_seconds)
                && (1..=86400).contains(&l.udp_idle_seconds)
                && (1..=120).contains(&l.drain_seconds),
            "시간 한도"
        );
        ensure!(
            (262144..=1024 * 1024 * 1024).contains(&l.buffer_bytes)
                && (131072..=16 * 1024 * 1024).contains(&l.connection_buffer_bytes),
            "버퍼 한도"
        );
        ensure!(
            (1..=65536).contains(&l.replay_entries)
                && (1..=1024).contains(&l.tcp_per_connection)
                && (1..=1024).contains(&l.udp_per_connection)
                && (1..=32).contains(&l.dns_inflight)
                && (16..=1024).contains(&l.control_queue),
            "세션/큐 한도"
        );
        ensure!(
            self.resolver.address.port() != 0
                && ["udp", "tcp", "tls"].contains(&self.resolver.mode.as_str())
                && (1..=30).contains(&self.resolver.timeout_seconds)
                && (1..=65536).contains(&self.resolver.cache_entries),
            "DNS 설정"
        );
        if self.resolver.mode == "tls" {
            mtp_protocol::domain(
                self.resolver
                    .server_name
                    .as_deref()
                    .context("DoT 인증 이름 필요")?,
            )?;
            ensure!(self.resolver.ca_file.is_some(), "DoT CA 경로 필요");
        }
        for path in [
            &self.secret_file,
            &self.server_cert,
            &self.server_key,
            &self.client_ca,
            &self.registry_file,
            &self.metrics_socket,
        ] {
            ensure!(path.is_absolute(), "서버 설정 경로는 절대 경로여야 합니다");
        }
        Ok(())
    }
}
impl Registry {
    pub fn load(path: &Path) -> Result<Self> {
        let r: Self = serde_json::from_slice(&read_limited(path, 8 * 1024 * 1024)?)?;
        r.validate()?;
        Ok(r)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.users.len() <= 4096 && self.certificates.len() <= 16384,
            "사용자/인증서 목록 한도"
        );
        for (id, u) in &self.users {
            ensure!(
                u.allow.len() <= 64 && u.deny.len() <= 64,
                "사용자 CIDR 한도"
            );
            ensure!(valid_id(id), "사용자 식별자");
            ensure!(
                (1..=32).contains(&u.connections)
                    && (1..=2048).contains(&u.tcp_streams)
                    && (1..=2048).contains(&u.udp_associations)
                    && (65536..=1024 * 1024 * 1024).contains(&u.bytes_per_second)
                    && (1..=10000).contains(&u.udp_per_second)
                    && (131072..=256 * 1024 * 1024).contains(&u.buffer_bytes),
                "사용자 자원 한도"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= 8 * 1024 * 1024,
            "권한 원장 파일 한도"
        );
        for (fp, d) in &self.certificates {
            ensure!(
                fp.len() == 64
                    && fp.bytes().all(|v| v.is_ascii_hexdigit())
                    && valid_id(&d.id)
                    && self.users.contains_key(&d.owner),
                "인증서 식별자/소유자"
            );
        }
        Ok(())
    }
}
