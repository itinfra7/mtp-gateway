use crate::{
    config::{Config, Registry, UserPolicy},
    dns::Resolver,
    flow::Rate,
};
use anyhow::{Result, anyhow, ensure};
use mtp_protocol::Code;
use serde_json::json;
use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub struct Metrics {
    pub accepted: AtomicU64,
    pub authentication_failed: AtomicU64,
    pub protocol_failed: AtomicU64,
    pub transport_failed: AtomicU64,
    pub active_tunnels: AtomicUsize,
    pub active_tcp: AtomicUsize,
    pub active_udp: AtomicUsize,
    pub bytes_to_destination: AtomicU64,
    pub bytes_to_client: AtomicU64,
    pub udp_dropped: AtomicU64,
    pub udp_rate_dropped: AtomicU64,
    pub udp_window_dropped: AtomicU64,
    pub udp_queue_dropped: AtomicU64,
    pub udp_truncated: AtomicU64,
    pub denied: AtomicU64,
    pub tasks: AtomicUsize,
}
impl Metrics {
    pub fn json(&self) -> serde_json::Value {
        json!({"accepted":self.accepted.load(Ordering::Relaxed),"authentication_failed":self.authentication_failed.load(Ordering::Relaxed),"protocol_failed":self.protocol_failed.load(Ordering::Relaxed),"transport_failed":self.transport_failed.load(Ordering::Relaxed),"active_tunnels":self.active_tunnels.load(Ordering::Relaxed),"active_tcp":self.active_tcp.load(Ordering::Relaxed),"active_udp":self.active_udp.load(Ordering::Relaxed),"bytes_to_destination":self.bytes_to_destination.load(Ordering::Relaxed),"bytes_to_client":self.bytes_to_client.load(Ordering::Relaxed),"udp_dropped":self.udp_dropped.load(Ordering::Relaxed),"udp_rate_dropped":self.udp_rate_dropped.load(Ordering::Relaxed),"udp_window_dropped":self.udp_window_dropped.load(Ordering::Relaxed),"udp_queue_dropped":self.udp_queue_dropped.load(Ordering::Relaxed),"udp_truncated":self.udp_truncated.load(Ordering::Relaxed),"denied":self.denied.load(Ordering::Relaxed),"active_tasks":self.tasks.load(Ordering::Relaxed)})
    }
}
pub struct UserRuntime {
    pub policy: UserPolicy,
    pub connections: Arc<Semaphore>,
    pub tcp: Arc<Semaphore>,
    pub udp: Arc<Semaphore>,
    pub buffer: Arc<Semaphore>,
    pub bytes: Rate,
    pub packets: Rate,
}
impl UserRuntime {
    fn new(policy: UserPolicy) -> Self {
        Self {
            connections: Arc::new(Semaphore::new(policy.connections)),
            tcp: Arc::new(Semaphore::new(policy.tcp_streams)),
            udp: Arc::new(Semaphore::new(policy.udp_associations)),
            buffer: Arc::new(Semaphore::new(policy.buffer_bytes)),
            bytes: Rate::new(policy.bytes_per_second),
            packets: Rate::new(policy.udp_per_second as u64),
            policy,
        }
    }
}
/// 목적지·본문·암호값을 저장하지 않는 연결별 처리 진단.
#[derive(Default)]
pub struct ConnectionDiagnostics {
    pub mux_ready: AtomicBool,
    pub frames_in: AtomicU64,
    pub open_tcp: AtomicU64,
    pub open_udp: AtomicU64,
    pub open_ok: AtomicU64,
    pub open_failed: AtomicU64,
    pub dns_requests: AtomicU64,
    pub data_frames: AtomicU64,
    pub data_bytes: AtomicU64,
    pub ping_received: AtomicU64,
    last_kind: AtomicUsize,
    last_stream: AtomicU64,
    last_failure: Mutex<Option<(u32, u16, &'static str)>>,
}
impl ConnectionDiagnostics {
    pub fn received(&self, frame: &mtp_protocol::Frame) {
        use mtp_protocol::Kind;
        self.frames_in.fetch_add(1, Ordering::Relaxed);
        self.last_kind.store(frame.kind as usize, Ordering::Relaxed);
        self.last_stream.store(frame.id as u64, Ordering::Relaxed);
        match frame.kind {
            Kind::OpenTcp => {
                self.open_tcp.fetch_add(1, Ordering::Relaxed);
            }
            Kind::OpenUdp => {
                self.open_udp.fetch_add(1, Ordering::Relaxed);
            }
            Kind::DnsRequest => {
                self.dns_requests.fetch_add(1, Ordering::Relaxed);
            }
            Kind::Ping => {
                self.ping_received.fetch_add(1, Ordering::Relaxed);
            }
            Kind::TcpData | Kind::UdpDatagram => {
                self.data_frames.fetch_add(1, Ordering::Relaxed);
                self.data_bytes
                    .fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
            }
            _ => {}
        }
    }
    pub fn failed(&self, stream: u32, code: Code, phase: &'static str) {
        if phase != "stream" {
            self.open_failed.fetch_add(1, Ordering::Relaxed);
        }
        if let Ok(mut last) = self.last_failure.lock() {
            *last = Some((stream, code as u16, phase));
        }
    }
    pub fn json(&self) -> serde_json::Value {
        let last = self
            .last_failure
            .lock()
            .ok()
            .and_then(|v| *v)
            .map(|(stream, code, phase)| json!({"stream":stream,"code":code,"phase":phase}));
        json!({"mux_ready":self.mux_ready.load(Ordering::Relaxed),"frames_in":self.frames_in.load(Ordering::Relaxed),"open_tcp":self.open_tcp.load(Ordering::Relaxed),"open_udp":self.open_udp.load(Ordering::Relaxed),"open_ok":self.open_ok.load(Ordering::Relaxed),"open_failed":self.open_failed.load(Ordering::Relaxed),"dns_requests":self.dns_requests.load(Ordering::Relaxed),"data_frames":self.data_frames.load(Ordering::Relaxed),"data_bytes":self.data_bytes.load(Ordering::Relaxed),"ping_received":self.ping_received.load(Ordering::Relaxed),"last_frame_type":self.last_kind.load(Ordering::Relaxed),"last_stream_id":self.last_stream.load(Ordering::Relaxed),"last_failure":last})
    }
}
pub struct ConnectionInfo {
    pub owner: String,
    pub fingerprint: String,
    pub diagnostics: Arc<ConnectionDiagnostics>,
    pub peer: IpAddr,
    pub cancel: CancellationToken,
}
pub struct State {
    pub config: Config,
    pub registry: RwLock<Registry>,
    pub resolver: Resolver,
    pub metrics: Arc<Metrics>,
    pub global_buffer: Arc<Semaphore>,
    pub tunnels: Arc<Semaphore>,
    pub streams: Arc<Semaphore>,
    pub handshakes: Arc<Semaphore>,
    pub shutdown: CancellationToken,
    users: Mutex<HashMap<String, Arc<UserRuntime>>>,
    pub connections: Mutex<BTreeMap<u64, ConnectionInfo>>,
    pub next: AtomicU64,
    rate: Mutex<HashMap<IpAddr, (Instant, u32)>>,
    global_rate: Rate,
    pub diagnostic_logs: Rate,
    pub registry_error: AtomicUsize,
}
impl State {
    pub fn new(config: Config) -> Result<Arc<Self>> {
        let registry = Registry::load(&config.registry_file)?;
        Ok(Arc::new(Self {
            resolver: Resolver::new(config.resolver.clone()),
            global_buffer: Arc::new(Semaphore::new(config.limits.buffer_bytes)),
            tunnels: Arc::new(Semaphore::new(config.limits.connections)),
            streams: Arc::new(Semaphore::new(config.limits.streams)),
            handshakes: Arc::new(Semaphore::new(config.limits.handshakes)),
            global_rate: Rate::new(config.limits.handshakes_per_second as u64 * 4),
            diagnostic_logs: Rate::new(1),
            config,
            registry: RwLock::new(registry),
            metrics: Arc::default(),
            shutdown: CancellationToken::new(),
            users: Mutex::new(HashMap::new()),
            connections: Mutex::new(BTreeMap::new()),
            next: AtomicU64::new(1),
            rate: Mutex::new(HashMap::new()),
            registry_error: AtomicUsize::new(0),
        }))
    }
    pub fn handshake_allowed(&self, ip: IpAddr) -> bool {
        if !self.global_rate.take(1) {
            return false;
        }
        let Ok(mut m) = self.rate.lock() else {
            return false;
        };
        let now = Instant::now();
        m.retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(2));
        if m.len() >= 4096 && !m.contains_key(&ip) {
            return false;
        }
        let e = m.entry(ip).or_insert((now, 0));
        if now.duration_since(e.0) >= Duration::from_secs(1) {
            *e = (now, 0);
        }
        if e.1 >= self.config.limits.handshakes_per_second {
            return false;
        }
        e.1 += 1;
        true
    }
    pub fn authenticate(&self, fingerprint: &str) -> Result<(String, Arc<UserRuntime>), Code> {
        if self.registry_error.load(Ordering::Relaxed) != 0 {
            return Err(Code::Resource);
        }
        let r = self.registry.read().map_err(|_| Code::Io)?;
        if !r.enabled {
            return Err(Code::Revoked);
        }
        let d = r
            .certificates
            .get(fingerprint)
            .filter(|d| d.enabled)
            .ok_or(Code::Revoked)?;
        let p = r
            .users
            .get(&d.owner)
            .filter(|p| p.enabled)
            .ok_or(Code::Revoked)?;
        let mut users = self.users.lock().map_err(|_| Code::Io)?;
        if let Some(u) = users.get(&d.owner) {
            if &u.policy == p {
                return Ok((d.owner.clone(), u.clone()));
            }
            if u.connections.available_permits() != u.policy.connections {
                return Err(Code::Resource);
            }
        }
        let u = Arc::new(UserRuntime::new(p.clone()));
        users.insert(d.owner.clone(), u.clone());
        Ok((d.owner.clone(), u))
    }
    pub fn reload(&self) -> Result<()> {
        let next = Registry::load(&self.config.registry_file)?;
        let mut old = self
            .registry
            .write()
            .map_err(|_| anyhow!("정책 잠금 실패"))?;
        self.users
            .lock()
            .map_err(|_| anyhow!("사용자 상태 잠금 실패"))?
            .retain(|id, u| {
                next.users.contains_key(id)
                    || u.connections.available_permits() != u.policy.connections
            });
        if next == *old {
            return Ok(());
        }
        ensure!(
            next.revision > old.revision,
            "정책 revision은 증가해야 합니다"
        );
        let conns = self
            .connections
            .lock()
            .map_err(|_| anyhow!("연결 목록 잠금 실패"))?;
        for c in conns.values() {
            let enabled = next.enabled
                && next
                    .certificates
                    .get(&c.fingerprint)
                    .is_some_and(|d| d.enabled && d.owner == c.owner)
                && next.users.get(&c.owner).is_some_and(|u| u.enabled);
            if !enabled || old.users.get(&c.owner) != next.users.get(&c.owner) {
                c.cancel.cancel();
            }
        }
        *old = next;
        Ok(())
    }
    pub fn status(&self) -> serde_json::Value {
        let list = self
            .connections
            .lock()
            .map(|c| {
                c.iter()
                    .map(|(id, v)| json!({"id":id,"owner":v.owner,"peer":v.peer,"diagnostics":v.diagnostics.json()}))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        json!({"state":if self.registry_error.load(Ordering::Relaxed)==0&&!self.shutdown.is_cancelled(){"ready"}else{"degraded"},"mode":"mtp_tcp_v1","protocol_version":1,"tls":"TLS1.3/mTLS","metrics":self.metrics.json(),"dns_queries":self.resolver.queries.load(Ordering::Relaxed),"dns_cache_hits":self.resolver.cache_hits.load(Ordering::Relaxed),"connections":list,"buffer_used":self.config.limits.buffer_bytes-self.global_buffer.available_permits(),"buffer_limit":self.config.limits.buffer_bytes})
    }
}
pub struct CountGuard {
    metrics: Arc<Metrics>,
    kind: u8,
}
impl CountGuard {
    pub fn new(metrics: Arc<Metrics>, kind: u8) -> Self {
        metrics.tasks.fetch_add(1, Ordering::Relaxed);
        match kind {
            1 => {
                metrics.active_tunnels.fetch_add(1, Ordering::Relaxed);
            }
            2 => {
                metrics.active_tcp.fetch_add(1, Ordering::Relaxed);
            }
            3 => {
                metrics.active_udp.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        Self { metrics, kind }
    }
}
impl Drop for CountGuard {
    fn drop(&mut self) {
        self.metrics.tasks.fetch_sub(1, Ordering::Relaxed);
        match self.kind {
            1 => {
                self.metrics.active_tunnels.fetch_sub(1, Ordering::Relaxed);
            }
            2 => {
                self.metrics.active_tcp.fetch_sub(1, Ordering::Relaxed);
            }
            3 => {
                self.metrics.active_udp.fetch_sub(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}
pub struct TunnelGuard {
    pub state: Arc<State>,
    pub id: u64,
}
impl Drop for TunnelGuard {
    fn drop(&mut self) {
        if let Ok(mut c) = self.state.connections.lock() {
            c.remove(&self.id);
        }
    }
}

#[cfg(test)]
mod diagnostics_tests {
    use super::*;
    #[test]
    fn 진단에는_요청종류와_고정오류만_보관() {
        use mtp_protocol::{Frame, Kind};
        let d = ConnectionDiagnostics::default();
        let secret = "진단에 저장하지 않을 가짜 본문".as_bytes();
        d.received(&Frame::new(Kind::TcpData, 1, secret.to_vec()));
        d.received(&Frame::new(Kind::OpenTcp, 3, vec![1, 1, 1, 1, 1, 0, 80]));
        d.received(&Frame::new(Kind::Ping, 0, vec![0; 8]));
        d.failed(3, Code::Policy, "connect");
        let v = d.json();
        assert_eq!(v["frames_in"], 3);
        assert_eq!(v["data_frames"], 1);
        assert_eq!(v["data_bytes"], secret.len());
        assert_eq!(v["open_tcp"], 1);
        assert_eq!(v["open_failed"], 1);
        assert_eq!(v["last_failure"]["code"], Code::Policy as u16);
        assert_eq!(v["ping_received"], 1);
        assert!(!v.to_string().contains(std::str::from_utf8(secret).unwrap()));
    }
}
