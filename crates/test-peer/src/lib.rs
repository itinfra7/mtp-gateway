//! Windows에서도 사용할 수 있는 실제 Fake-TLS·mTLS·다중화 참조 클라이언트.
use anyhow::{Context, Result, anyhow, bail, ensure};
use bytes::Bytes;
use hickory_proto::op::{Message, MessageType};
use mtp_protocol::{
    Code, Destination, Frame, Hello, Kind, MAX_TCP, MAX_UDP, STREAM_WINDOW,
    flow::{Acknowledgement, Budget, Queued, ReceiveWindow, Reservation, SendWindow, Sender},
    read_frame, write_frame,
};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::io::AsyncWriteExt;
use tokio::{
    net::TcpStream,
    sync::{Notify, Semaphore, mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSettings {
    pub host: String,
    pub port: u16,
    pub secret_hex: String,
    pub tls_domain: String,
    pub tunnel_mode: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecuritySettings {
    pub transport: String,
    pub server_name: String,
    pub ca_file: String,
    pub certificate_file: String,
    pub private_key_file: String,
    pub mux_version: u8,
    pub zero_rtt: bool,
}
fn relative(root: &Path, path: &str) -> Result<PathBuf> {
    let p = Path::new(path);
    ensure!(
        p.components().all(|c| matches!(c, Component::Normal(_))),
        "인증 파일은 앱 루트 상대 경로여야 합니다"
    );
    let root = root.canonicalize()?;
    let full = root.join(p).canonicalize()?;
    ensure!(full.starts_with(&root), "인증 파일이 앱 루트를 벗어납니다");
    Ok(full)
}
struct Slot {
    tx: mpsc::Sender<Received>,
    send: Arc<SendWindow>,
    receive: Arc<ReceiveWindow>,
    opened: AtomicBool,
    remote_fin: AtomicBool,
    local_fin: AtomicBool,
    cancel: CancellationToken,
    udp: bool,
    write_lock: tokio::sync::Mutex<()>,
}
struct Shared {
    sender: Sender,
    slots: Mutex<HashMap<u32, Arc<Slot>>>,
    send: Arc<SendWindow>,
    receive: Arc<ReceiveWindow>,
    cancel: CancellationToken,
    next: AtomicU32,
    accepting: AtomicBool,
    dns: Mutex<HashMap<u32, oneshot::Sender<Frame>>>,
    next_dns: AtomicU32,
    peer_window: u32,
    local_stream_window: u32,
    goaway_written: AtomicBool,
    flushed: Notify,
}
struct Life {
    cancel: CancellationToken,
}
impl Drop for Life {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
#[derive(Clone)]
pub struct Peer {
    shared: Arc<Shared>,
    life: Arc<Life>,
}
pub struct Received {
    pub frame: Frame,
    _ack: Option<Acknowledgement>,
}
impl Received {
    pub fn udp(&self) -> Result<(Destination, &[u8])> {
        ensure!(self.frame.kind == Kind::UdpDatagram, "UDP 응답이 아닙니다");
        let (d, n) = Destination::decode(&self.frame.payload)?;
        ensure!(self.frame.payload.len() - n <= MAX_UDP, "UDP 길이 상한");
        Ok((d, &self.frame.payload[n..]))
    }
}
impl Shared {
    fn slot(&self, id: u32) -> Result<Arc<Slot>> {
        self.slots
            .lock()
            .map_err(|_| anyhow!("스트림 잠금"))?
            .get(&id)
            .cloned()
            .context("종료된 스트림")
    }
    fn control(&self, f: Frame) -> Result<()> {
        self.sender.control(f).map_err(|_| anyhow!("제어 큐 한도"))
    }
    fn updates(&self) -> Result<()> {
        let n = self.receive.take_pending();
        if n > 0 {
            self.control(Frame::new(Kind::WindowUpdate, 0, n.to_be_bytes().to_vec()))?;
        }
        let slots = self.slots.lock().map_err(|_| anyhow!("스트림 잠금"))?;
        for (id, s) in slots.iter() {
            let n = s.receive.take_pending();
            if n > 0 {
                self.control(Frame::new(
                    Kind::WindowUpdate,
                    *id,
                    n.to_be_bytes().to_vec(),
                ))?;
            }
        }
        Ok(())
    }
    async fn send(&self, id: u32, data: &[u8], udp: bool) -> Result<()> {
        let s = self.slot(id)?;
        ensure!(s.udp == udp, "스트림 종류 불일치");
        ensure!(
            !s.cancel.is_cancelled() && !self.cancel.is_cancelled(),
            "종료된 스트림"
        );
        let _serial = s.write_lock.lock().await;
        ensure!(
            !s.local_fin.load(Ordering::Relaxed) && s.opened.load(Ordering::Relaxed),
            "송신 상태 오류"
        );
        if udp {
            ensure!(data.len() <= MAX_UDP, "UDP 길이 상한");
            let frame = Frame::new(Kind::UdpDatagram, id, data.to_vec());
            let cost = frame.credit();
            let credit = loop {
                let a = self.send.notify.notified();
                let b = s.send.notify.notified();
                if let Ok(c) = Reservation::immediate(self.send.clone(), s.send.clone(), cost) {
                    break c;
                }
                tokio::select! {_=self.cancel.cancelled()=>bail!("터널 종료"),_=s.cancel.cancelled()=>bail!("스트림 종료"),_=a=>{},_=b=>{}}
            };
            self.sender
                .data(frame, Some(credit))
                .await
                .map_err(|_| anyhow!("송신 큐 한도"))?;
        } else {
            let mut at = 0;
            while at < data.len() {
                let (credit, n) = tokio::select! {_=self.cancel.cancelled()=>bail!("터널 종료"),_=s.cancel.cancelled()=>bail!("스트림 종료"),r=Reservation::reserve(self.send.clone(),s.send.clone(),(data.len()-at).min(MAX_TCP))=>r.map_err(|_|anyhow!("송신 윈도"))?};
                self.sender
                    .data(
                        Frame::new(Kind::TcpData, id, data[at..at + n].to_vec()),
                        Some(credit),
                    )
                    .await
                    .map_err(|_| anyhow!("송신 큐 한도"))?;
                at += n;
            }
        }
        Ok(())
    }
    async fn finish(&self, id: u32) -> Result<()> {
        let s = self.slot(id)?;
        let _serial = s.write_lock.lock().await;
        ensure!(
            !s.udp && !s.local_fin.swap(true, Ordering::SeqCst),
            "FIN 상태 오류"
        );
        self.sender
            .data(Frame::new(Kind::TcpFin, id, Bytes::new()), None)
            .await
            .map_err(|_| anyhow!("송신 큐 한도"))
    }
    async fn incoming(self: &Arc<Self>, frame: Frame) -> Result<()> {
        match frame.kind {
            Kind::Ping => self.control(Frame::new(Kind::Pong, 0, frame.payload))?,
            Kind::Pong => {}
            Kind::Goaway => {
                self.accepting.store(false, Ordering::Relaxed);
            }
            Kind::WindowUpdate => {
                let n = u32::from_be_bytes(frame.payload[..].try_into()?);
                if frame.id == 0 {
                    self.send.update(n).map_err(|_| anyhow!("연결 윈도 오류"))?;
                } else if let Ok(s) = self.slot(frame.id) {
                    s.send.update(n).map_err(|_| anyhow!("스트림 윈도 오류"))?;
                } else {
                    ensure!(
                        frame.id < self.next.load(Ordering::Relaxed) && frame.id % 2 == 1,
                        "미지정 스트림 윈도"
                    );
                }
            }
            Kind::DnsResponse => {
                let id = u32::from_be_bytes(frame.payload[..4].try_into()?);
                if let Some(tx) = self
                    .dns
                    .lock()
                    .map_err(|_| anyhow!("DNS 잠금"))?
                    .remove(&id)
                {
                    let _ = tx.send(frame);
                } else {
                    ensure!(
                        id < self.next_dns.load(Ordering::Relaxed),
                        "알 수 없는 DNS 응답 ID"
                    );
                }
            }
            Kind::OpenOk
            | Kind::OpenError
            | Kind::TcpData
            | Kind::UdpDatagram
            | Kind::TcpFin
            | Kind::Reset => {
                let slot = match self.slot(frame.id) {
                    Ok(v) => v,
                    Err(_) => {
                        ensure!(
                            frame.id < self.next.load(Ordering::Relaxed) && frame.id % 2 == 1,
                            "알 수 없는 서버 스트림"
                        );
                        if matches!(frame.kind, Kind::TcpData | Kind::UdpDatagram) {
                            drop(
                                Acknowledgement::take(
                                    frame.credit(),
                                    self.receive.clone(),
                                    ReceiveWindow::new(STREAM_WINDOW),
                                )
                                .map_err(|_| anyhow!("늦은 데이터 연결 윈도 오류"))?,
                            );
                        }
                        return Ok(());
                    }
                };
                if frame.kind == Kind::OpenOk {
                    ensure!(!slot.opened.swap(true, Ordering::SeqCst), "중복 OPEN_OK");
                }
                if frame.kind == Kind::OpenError {
                    ensure!(!slot.opened.load(Ordering::Relaxed), "OPEN 이후 OPEN_ERROR");
                    slot.cancel.cancel();
                }
                let ack = if matches!(frame.kind, Kind::TcpData | Kind::UdpDatagram) {
                    ensure!(
                        slot.opened.load(Ordering::Relaxed)
                            && !slot.remote_fin.load(Ordering::Relaxed)
                            && slot.udp == (frame.kind == Kind::UdpDatagram),
                        "수신 DATA 상태 오류"
                    );
                    Some(
                        Acknowledgement::take(
                            frame.credit(),
                            self.receive.clone(),
                            slot.receive.clone(),
                        )
                        .map_err(|_| anyhow!("수신 윈도 초과"))?,
                    )
                } else {
                    None
                };
                if frame.kind == Kind::TcpFin {
                    ensure!(
                        !slot.udp && !slot.remote_fin.swap(true, Ordering::SeqCst),
                        "FIN 상태 오류"
                    );
                }
                if frame.kind == Kind::Reset {
                    slot.cancel.cancel();
                }
                slot.tx
                    .try_send(Received { frame, _ack: ack })
                    .map_err(|_| anyhow!("스트림 수신 큐 한도"))?;
            }
            _ => bail!("서버 프레임 방향 또는 상태 오류"),
        }
        Ok(())
    }
}
impl Peer {
    pub async fn connect(root: &Path) -> Result<Self> {
        let server: ServerSettings =
            serde_json::from_slice(&std::fs::read(root.join("config/server.json"))?)?;
        let security: SecuritySettings =
            serde_json::from_slice(&std::fs::read(root.join("config/security.json"))?)?;
        Self::connect_settings(root, &server, &security).await
    }
    pub async fn connect_settings(
        root: &Path,
        server: &ServerSettings,
        security: &SecuritySettings,
    ) -> Result<Self> {
        Self::connect_settings_with_hello(root, server, security, Hello::default()).await
    }
    /// 메모리 예산에 맞춘 수신 윈도로 같은 프로토콜을 연결한다.
    pub async fn connect_settings_with_hello(
        root: &Path,
        server: &ServerSettings,
        security: &SecuritySettings,
        advertised: Hello,
    ) -> Result<Self> {
        Hello::decode(&advertised.encode())?;
        ensure!(
            server.port != 0
                && server.tunnel_mode == "extended_socks_over_mtproto"
                && security.transport == "mtp_tcp_v1"
                && security.mux_version == 1
                && !security.zero_rtt,
            "지원하지 않는 터널/보안 설정"
        );
        let secret = mtp_transport::Secret::parse(&server.secret_hex)?;
        ensure!(
            secret.domain == mtp_protocol::domain(&server.tls_domain)?,
            "외부 SNI 설정 불일치"
        );
        let cfg = mtp_transport::client_tls(
            &relative(root, &security.certificate_file)?,
            &relative(root, &security.private_key_file)?,
            &relative(root, &security.ca_file)?,
        )?;
        let setup = async {
            let socket = TcpStream::connect((server.host.as_str(), server.port)).await?;
            socket.set_nodelay(true)?;
            let outer = mtp_transport::connect(socket, &secret).await?;
            let name = ServerName::try_from(security.server_name.clone())?;
            let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
                .connect(name, outer)
                .await?;
            ensure!(
                tls.get_ref().1.alpn_protocol() == Some(mtp_transport::ALPN),
                "ALPN 불일치"
            );
            write_frame(&mut tls, &Frame::new(Kind::Hello, 0, advertised.encode())).await?;
            let f = read_frame(&mut tls).await?.context("WELCOME EOF")?;
            ensure!(f.kind == Kind::Welcome, "WELCOME 필요");
            let hello = Hello::decode(&f.payload[..12])?;
            Ok::<_, anyhow::Error>((tls, hello))
        };
        let (tls, hello) = tokio::time::timeout(Duration::from_secs(15), setup).await??;
        let (mut read, mut write) = tokio::io::split(tls);
        let (control, mut ctrl_rx) = mpsc::channel(128);
        let (data, mut data_rx) = mpsc::channel::<Queued>(128);
        let cancel = CancellationToken::new();
        let budget = Arc::new(Semaphore::new(8 * 1024 * 1024));
        let sender = Sender {
            stream_cancel: None,
            control,
            data,
            cancel: cancel.clone(),
            budget: Budget {
                global: budget.clone(),
                user: budget.clone(),
                connection: budget,
            },
        };
        let shared = Arc::new(Shared {
            sender,
            slots: Mutex::new(HashMap::new()),
            send: SendWindow::new(hello.connection),
            receive: ReceiveWindow::new(advertised.connection),
            cancel: cancel.clone(),
            next: AtomicU32::new(1),
            accepting: AtomicBool::new(true),
            dns: Mutex::new(HashMap::new()),
            next_dns: AtomicU32::new(1),
            peer_window: hello.stream,
            local_stream_window: advertised.stream,
            goaway_written: AtomicBool::new(false),
            flushed: Notify::new(),
        });
        let s = shared.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                let frame = tokio::select! {biased;_=s.cancel.cancelled()=>break,Some(f)=ctrl_rx.recv()=>Some((f,None)),_=interval.tick()=>{if s.updates().is_err(){s.cancel.cancel();break;}None},Some(q)=data_rx.recv()=>{if q.frame.id!=0&&s.slot(q.frame.id).is_err(){continue;}
                if q.frame.id!=0&&s.slot(q.frame.id).is_ok_and(|v|v.cancel.is_cancelled()){continue;}Some((q.frame,Some((q.credit,q._charge))))}};
                if let Some((f, credit)) = frame {
                    let _charge = if let Some((credit, charge)) = credit {
                        if let Some(c) = credit {
                            c.commit();
                        }
                        Some(charge)
                    } else {
                        None
                    };
                    let r = tokio::select! {_=s.cancel.cancelled()=>break,r=write_frame(&mut write,&f)=>r};
                    if r.is_err() {
                        s.cancel.cancel();
                        break;
                    }
                    if f.kind == Kind::Goaway {
                        let _ = write.shutdown().await;
                        s.goaway_written.store(true, Ordering::Relaxed);
                        s.flushed.notify_waiters();
                        break;
                    }
                }
            }
        });
        let s = shared.clone();
        tokio::spawn(async move {
            loop {
                let f = tokio::select! {_=s.cancel.cancelled()=>break,f=read_frame(&mut read)=>f};
                match f {
                    Ok(Some(f)) => {
                        if s.incoming(f).await.is_err() {
                            s.cancel.cancel();
                            break;
                        }
                    }
                    _ => {
                        s.cancel.cancel();
                        break;
                    }
                }
            }
            if let Ok(mut slots) = s.slots.lock() {
                slots.clear();
            }
            if let Ok(mut dns) = s.dns.lock() {
                dns.clear();
            }
        });
        Ok(Self {
            shared,
            life: Arc::new(Life { cancel }),
        })
    }
    pub async fn open(&self, destination: Destination, udp: bool) -> Result<ClientStream> {
        ensure!(
            self.shared.accepting.load(Ordering::Relaxed) && !self.shared.cancel.is_cancelled(),
            "터널이 새 스트림을 받지 않습니다"
        );
        let id = self
            .shared
            .next
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                v.checked_add(2).filter(|_| v <= 0xffff_fffd)
            })
            .map_err(|_| anyhow!("스트림 ID 소진: 새 터널 필요"))?;
        let (tx, rx) = mpsc::channel(2048);
        self.shared
            .slots
            .lock()
            .map_err(|_| anyhow!("스트림 잠금"))?
            .insert(
                id,
                Arc::new(Slot {
                    tx,
                    send: SendWindow::new(self.shared.peer_window),
                    receive: ReceiveWindow::new(self.shared.local_stream_window),
                    opened: AtomicBool::new(false),
                    remote_fin: AtomicBool::new(false),
                    local_fin: AtomicBool::new(false),
                    cancel: self.shared.cancel.child_token(),
                    udp,
                    write_lock: tokio::sync::Mutex::new(()),
                }),
            );
        let mut stream = ClientStream {
            id,
            udp,
            rx,
            shared: self.shared.clone(),
            _life: self.life.clone(),
            selected: None,
            bound: None,
        };
        self.shared.control(Frame::new(
            if udp { Kind::OpenUdp } else { Kind::OpenTcp },
            id,
            destination.encode()?,
        ))?;
        let response = tokio::time::timeout(Duration::from_secs(15), stream.recv()).await??;
        if response.frame.kind == Kind::OpenError {
            let code = u16::from_be_bytes(response.frame.payload[..2].try_into()?);
            bail!("목적지 열기 거부: 코드 {code}");
        }
        ensure!(response.frame.kind == Kind::OpenOk, "OPEN_OK 필요");
        let (bound, n) = Destination::decode(&response.frame.payload)?;
        let (selected, k) = Destination::decode(&response.frame.payload[n..])?;
        ensure!(n + k == response.frame.payload.len(), "OPEN_OK 주소 길이");
        stream.bound = Some(bound);
        stream.selected = Some(selected);
        drop(response);
        Ok(stream)
    }
    pub async fn send_tcp(&self, id: u32, data: &[u8]) -> Result<()> {
        self.shared.send(id, data, false).await
    }
    pub async fn send_udp(&self, id: u32, data: &[u8]) -> Result<()> {
        self.shared.send(id, data, true).await
    }
    pub async fn finish_tcp(&self, id: u32) -> Result<()> {
        self.shared.finish(id).await
    }
    pub async fn dns(&self, wire: &[u8]) -> Result<Vec<u8>> {
        ensure!((12..=65535).contains(&wire.len()), "DNS 길이");
        let query = Message::from_vec(wire)?;
        let request = self
            .shared
            .next_dns
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .map_err(|_| anyhow!("DNS ID 소진"))?;
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.shared.dns.lock().map_err(|_| anyhow!("DNS 잠금"))?;
            ensure!(pending.len() < 4, "동시 DNS 요청 한도");
            pending.insert(request, tx);
        }
        let mut p = request.to_be_bytes().to_vec();
        p.extend_from_slice(wire);
        self.shared
            .sender
            .data(Frame::new(Kind::DnsRequest, 0, p), None)
            .await
            .map_err(|_| anyhow!("터널 종료"))?;
        let response = match tokio::time::timeout(Duration::from_secs(10), rx).await {
            Ok(Ok(v)) => v,
            _ => {
                if let Ok(mut p) = self.shared.dns.lock() {
                    p.remove(&request);
                }
                bail!("DNS 응답 시간 초과 또는 터널 종료");
            }
        };
        ensure!(
            u32::from_be_bytes(response.payload[..4].try_into()?) == request,
            "DNS 요청 ID 불일치"
        );
        let code = u16::from_be_bytes(response.payload[4..6].try_into()?);
        ensure!(code == 0, "원격 DNS 오류 코드 {code}");
        let answer = Message::from_vec(&response.payload[6..])?;
        ensure!(
            answer.metadata.id == query.metadata.id
                && answer.metadata.message_type == MessageType::Response
                && answer.queries == query.queries,
            "DNS wire ID/질문 불일치"
        );
        Ok(response.payload[6..].to_vec())
    }
    pub async fn close(&self) -> Result<()> {
        let mut p = (Code::Shutdown as u16).to_be_bytes().to_vec();
        p.extend_from_slice(
            &self
                .shared
                .next
                .load(Ordering::Relaxed)
                .saturating_sub(2)
                .to_be_bytes(),
        );
        self.shared.control(Frame::new(Kind::Goaway, 0, p))?;
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            while !self.shared.goaway_written.load(Ordering::Relaxed) {
                self.shared.flushed.notified().await;
            }
        })
        .await;
        let _ = tokio::time::timeout(Duration::from_secs(1), self.shared.cancel.cancelled()).await;
        self.shared.cancel.cancel();
        Ok(())
    }
    pub fn is_closed(&self) -> bool {
        self.shared.cancel.is_cancelled()
    }
}
pub struct ClientStream {
    pub id: u32,
    pub udp: bool,
    rx: mpsc::Receiver<Received>,
    shared: Arc<Shared>,
    _life: Arc<Life>,
    pub selected: Option<Destination>,
    pub bound: Option<Destination>,
}
impl ClientStream {
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.shared.send(self.id, data, self.udp).await
    }
    pub async fn finish(&mut self) -> Result<()> {
        self.shared.finish(self.id).await
    }
    pub async fn recv(&mut self) -> Result<Received> {
        let received = tokio::select! {_=self.shared.cancel.cancelled()=>bail!("터널 종료"),v=self.rx.recv()=>v.context("스트림 종료")?};
        if received.frame.kind == Kind::Reset {
            let code = u16::from_be_bytes(received.frame.payload[..2].try_into()?);
            bail!("스트림 RESET 코드 {code}");
        }
        if received.frame.kind == Kind::UdpDatagram {
            let (source, _) = received.udp()?;
            ensure!(
                self.selected.as_ref() == Some(&source),
                "UDP 응답 출발지 불일치"
            );
        }
        Ok(received)
    }
}
impl Drop for ClientStream {
    fn drop(&mut self) {
        if let Ok(s) = self.shared.slot(self.id) {
            if !(s.local_fin.load(Ordering::Relaxed) && s.remote_fin.load(Ordering::Relaxed)) {
                let _ = self
                    .shared
                    .control(Frame::error(Kind::Reset, self.id, Code::State));
            }
            s.cancel.cancel();
        }
        if let Ok(mut s) = self.shared.slots.lock() {
            s.remove(&self.id);
        }
    }
}
