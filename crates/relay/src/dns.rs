//! 명시 upstream, 질문·ID 검증, TTL 캐시와 주소군별 실패 분리.
use crate::config::ResolverConfig;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use mtp_protocol::{Code, fake_ip, normalize};
use rustls::pki_types::ServerName;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::Semaphore,
};

type DnsResult<T> = Result<T, Code>;
#[derive(Clone)]
struct Entry {
    created: Instant,
    expires: Instant,
    wire: Vec<u8>,
}
pub struct Resolver {
    cfg: ResolverConfig,
    cache: Mutex<HashMap<[u8; 32], Entry>>,
    permits: Semaphore,
    pub cache_hits: AtomicU64,
    pub queries: AtomicU64,
}
impl Resolver {
    pub fn new(cfg: ResolverConfig) -> Self {
        Self {
            cfg,
            cache: Mutex::new(HashMap::new()),
            permits: Semaphore::new(32),
            cache_hits: AtomicU64::new(0),
            queries: AtomicU64::new(0),
        }
    }
    pub async fn raw(&self, wire: &[u8]) -> DnsResult<Vec<u8>> {
        if !(12..=65535).contains(&wire.len()) {
            return Err(Code::DnsMalformed);
        }
        let q = Message::from_vec(wire).map_err(|_| Code::DnsMalformed)?;
        if q.metadata.message_type != MessageType::Query
            || q.metadata.op_code != OpCode::Query
            || q.queries.len() != 1
            || !q.answers.is_empty()
        {
            return Err(Code::DnsMalformed);
        }
        let query = &q.queries[0];
        if [RecordType::AXFR, RecordType::IXFR].contains(&query.query_type()) {
            return Err(Code::Unsupported);
        }
        let key: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, &wire[2..])
            .as_ref()
            .try_into()
            .map_err(|_| Code::Io)?;
        if let Some(e) = self
            .cache
            .lock()
            .map_err(|_| Code::Io)?
            .get(&key)
            .filter(|e| e.expires > Instant::now())
            .cloned()
        {
            let mut m = Message::from_vec(&e.wire).map_err(|_| Code::DnsMalformed)?;
            m.metadata.id = q.metadata.id;
            let elapsed = e.created.elapsed().as_secs().min(u32::MAX as u64) as u32;
            for r in m
                .answers
                .iter_mut()
                .chain(m.authorities.iter_mut())
                .chain(m.additionals.iter_mut())
            {
                r.ttl = r.ttl.saturating_sub(elapsed);
            }
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return m.to_vec().map_err(|_| Code::DnsMalformed);
        }
        let _permit = self.permits.acquire().await.map_err(|_| Code::Resource)?;
        self.queries.fetch_add(1, Ordering::Relaxed);
        let response = tokio::time::timeout(
            Duration::from_secs(self.cfg.timeout_seconds),
            self.exchange(wire, &q),
        )
        .await
        .map_err(|_| Code::DnsTimeout)??;
        let m = Message::from_vec(&response).map_err(|_| Code::DnsMalformed)?;
        if m.metadata.id != q.metadata.id
            || m.metadata.message_type != MessageType::Response
            || m.metadata.op_code != q.metadata.op_code
            || m.queries != q.queries
        {
            return Err(Code::DnsMalformed);
        }
        if m.answers
            .iter()
            .chain(m.additionals.iter())
            .any(|r| match &r.data {
                RData::A(v) => fake_ip(IpAddr::V4(v.0)),
                RData::AAAA(v) => fake_ip(IpAddr::V6(v.0)),
                _ => false,
            })
        {
            return Err(Code::Policy);
        }
        let ttl = if m.metadata.response_code == ResponseCode::NXDomain || m.answers.is_empty() {
            m.authorities
                .iter()
                .filter_map(|r| {
                    if let RData::SOA(s) = &r.data {
                        Some(r.ttl.min(s.minimum))
                    } else {
                        None
                    }
                })
                .min()
                .unwrap_or(0)
                .min(60)
        } else {
            m.answers.iter().map(|r| r.ttl).min().unwrap_or(0).min(600)
        };
        if ttl > 0
            && [ResponseCode::NoError, ResponseCode::NXDomain].contains(&m.metadata.response_code)
        {
            let mut c = self.cache.lock().map_err(|_| Code::Io)?;
            c.retain(|_, e| e.expires > Instant::now());
            if c.len() >= self.cfg.cache_entries
                && let Some(k) = c.iter().min_by_key(|(_, e)| e.expires).map(|(k, _)| *k)
            {
                c.remove(&k);
            }
            while c.values().map(|e| e.wire.len()).sum::<usize>() + response.len() > 8 * 1024 * 1024
            {
                if let Some(k) = c.iter().min_by_key(|(_, e)| e.expires).map(|(k, _)| *k) {
                    c.remove(&k);
                } else {
                    break;
                }
            }
            c.insert(
                key,
                Entry {
                    created: Instant::now(),
                    expires: Instant::now() + Duration::from_secs(ttl as u64),
                    wire: response.clone(),
                },
            );
        }
        Ok(response)
    }
    async fn exchange(&self, wire: &[u8], q: &Message) -> DnsResult<Vec<u8>> {
        match self.cfg.mode.as_str() {
            "udp" => {
                let bind = if self.cfg.address.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let socket = UdpSocket::bind(bind).await.map_err(|_| Code::DnsServfail)?;
                socket
                    .connect(self.cfg.address)
                    .await
                    .map_err(|_| Code::DnsServfail)?;
                socket.send(wire).await.map_err(|_| Code::DnsServfail)?;
                let mut b = vec![0; 65535];
                loop {
                    let n = socket.recv(&mut b).await.map_err(|_| Code::DnsServfail)?;
                    let m = Message::from_vec(&b[..n]).map_err(|_| Code::DnsMalformed)?;
                    if m.metadata.id != q.metadata.id {
                        continue;
                    }
                    if m.metadata.truncation {
                        return self.tcp(wire).await;
                    }
                    return Ok(b[..n].to_vec());
                }
            }
            "tcp" => self.tcp(wire).await,
            "tls" => {
                let s = TcpStream::connect(self.cfg.address)
                    .await
                    .map_err(|_| Code::DnsServfail)?;
                let roots =
                    mtp_transport::roots(self.cfg.ca_file.as_ref().ok_or(Code::DnsServfail)?)
                        .map_err(|_| Code::DnsServfail)?;
                let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| Code::DnsServfail)?
                .with_root_certificates(roots)
                .with_no_client_auth();
                cfg.enable_early_data = false;
                let name =
                    ServerName::try_from(self.cfg.server_name.clone().ok_or(Code::DnsServfail)?)
                        .map_err(|_| Code::DnsServfail)?;
                let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
                    .connect(name, s)
                    .await
                    .map_err(|_| Code::DnsServfail)?;
                Self::tcp_wire(&mut tls, wire).await
            }
            _ => Err(Code::DnsServfail),
        }
    }
    async fn tcp(&self, wire: &[u8]) -> DnsResult<Vec<u8>> {
        let mut s = TcpStream::connect(self.cfg.address)
            .await
            .map_err(|_| Code::DnsServfail)?;
        Self::tcp_wire(&mut s, wire).await
    }
    async fn tcp_wire<S: AsyncRead + AsyncWrite + Unpin>(
        s: &mut S,
        wire: &[u8],
    ) -> DnsResult<Vec<u8>> {
        s.write_all(&(wire.len() as u16).to_be_bytes())
            .await
            .map_err(|_| Code::DnsServfail)?;
        s.write_all(wire).await.map_err(|_| Code::DnsServfail)?;
        let n = s.read_u16().await.map_err(|_| Code::DnsServfail)? as usize;
        if n < 12 {
            return Err(Code::DnsMalformed);
        }
        let mut b = vec![0; n];
        s.read_exact(&mut b).await.map_err(|_| Code::DnsServfail)?;
        Ok(b)
    }
    pub async fn family(&self, name: &str, kind: RecordType) -> DnsResult<Vec<IpAddr>> {
        let mut id = [0; 2];
        mtp_transport::random(&mut id).map_err(|_| Code::Io)?;
        let mut q = Message::new(u16::from_be_bytes(id), MessageType::Query, OpCode::Query);
        q.metadata.recursion_desired = true;
        q.add_query(Query::query(
            Name::from_ascii(format!("{name}.")).map_err(|_| Code::DnsMalformed)?,
            kind,
        ));
        let wire = q.to_vec().map_err(|_| Code::DnsMalformed)?;
        let answer = self.raw(&wire).await?;
        let m = Message::from_vec(&answer).map_err(|_| Code::DnsMalformed)?;
        match m.metadata.response_code {
            ResponseCode::NXDomain => return Err(Code::DnsNx),
            ResponseCode::ServFail => return Err(Code::DnsServfail),
            ResponseCode::NoError => {}
            _ => return Err(Code::DnsServfail),
        }
        let mut names = HashSet::new();
        names.insert(q.queries[0].name.clone());
        for _ in 0..16 {
            let before = names.len();
            for r in &m.answers {
                if names.contains(&r.name)
                    && let RData::CNAME(v) = &r.data
                {
                    names.insert(v.0.clone());
                }
            }
            if before == names.len() {
                break;
            }
        }
        let result = m
            .answers
            .iter()
            .filter(|r| names.contains(&r.name))
            .filter_map(|r| match &r.data {
                RData::A(v) if kind == RecordType::A => Some(normalize(IpAddr::V4(v.0))),
                RData::AAAA(v) if kind == RecordType::AAAA => Some(normalize(IpAddr::V6(v.0))),
                _ => None,
            })
            .collect::<Vec<_>>();
        if result.is_empty() {
            Err(Code::DnsNoData)
        } else {
            Ok(result)
        }
    }
    pub async fn addresses(&self, name: &str, port: u16) -> DnsResult<Vec<SocketAddr>> {
        let (a, b) = tokio::join!(
            self.family(name, RecordType::A),
            self.family(name, RecordType::AAAA)
        );
        let mut out = Vec::new();
        if let Ok(v) = &a {
            out.extend(v.iter().copied());
        }
        if let Ok(v) = &b {
            out.extend(v.iter().copied());
        }
        out.sort();
        out.dedup();
        if !out.is_empty() {
            return Ok(out
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect());
        }
        for code in [
            Code::DnsTimeout,
            Code::DnsServfail,
            Code::DnsNx,
            Code::Policy,
            Code::DnsMalformed,
        ] {
            if a.as_ref().err() == Some(&code) || b.as_ref().err() == Some(&code) {
                return Err(code);
            }
        }
        Err(Code::DnsNoData)
    }
}
