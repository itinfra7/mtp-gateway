//! mTLS 인증 뒤에만 실제 목적지 소켓을 여는 다중화 중계기.
use crate::{
    config::Config,
    flow::{
        Acknowledgement, Budget, Charge, Queued, ReceiveWindow, Reservation, SendWindow, Sender,
    },
    policy,
    state::{ConnectionDiagnostics, ConnectionInfo, CountGuard, State, TunnelGuard, UserRuntime},
};
use anyhow::{Result, anyhow, ensure};
use bytes::Bytes;
use hickory_proto::{op::Message, rr::RData};
use mtp_protocol::{
    Address, CONNECTION_WINDOW, Code, Destination, Frame, Hello, Kind, MAX_TCP, MAX_UDP,
    STREAM_WINDOW, read_frame, write_frame,
};
use mtp_transport::{ReplayCache, Secret};
use nix::sys::socket::{MsgFlags, SockaddrStorage, recvmsg};
use std::{
    collections::{HashMap, HashSet},
    io::{self, IoSliceMut},
    net::{IpAddr, SocketAddr},
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, PermissionsExt},
    },
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket, UnixListener},
    sync::{Semaphore, mpsc},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

struct Input {
    payload: Bytes,
    _ack: Acknowledgement,
    _charge: Charge,
}
enum Command {
    Data(Input),
    Fin,
}
struct Stream {
    udp: bool,
    open: AtomicBool,
    fin: AtomicBool,
    send: Arc<SendWindow>,
    receive: Arc<ReceiveWindow>,
    input: mpsc::Sender<Command>,
    cancel: CancellationToken,
}
type Streams = Arc<Mutex<HashMap<u32, Arc<Stream>>>>;
struct StreamGuard {
    streams: Streams,
    id: u32,
}
impl Drop for StreamGuard {
    fn drop(&mut self) {
        if let Ok(mut m) = self.streams.lock() {
            m.remove(&self.id);
        }
    }
}
fn io_code(e: io::Error) -> Code {
    if e.kind() == io::ErrorKind::ConnectionRefused {
        Code::Refused
    } else {
        Code::Io
    }
}

async fn targets(
    state: &State,
    user: &UserRuntime,
    destination: &Destination,
) -> Result<Vec<SocketAddr>, Code> {
    let values = match &destination.address {
        Address::Ip(ip) => vec![SocketAddr::new(*ip, destination.port)],
        Address::Domain(name) => {
            if state.config.log_domains {
                tracing::info!(domain = name, "목적지 DNS 조회");
            }
            state.resolver.addresses(name, destination.port).await?
        }
    };
    let allowed = values
        .iter()
        .copied()
        .filter(|a| policy::allowed(&state.config.policy, &user.policy, a.ip()))
        .collect::<Vec<_>>();
    if allowed.is_empty() {
        state.metrics.denied.fetch_add(1, Ordering::Relaxed);
        if state.diagnostic_logs.take(1) {
            let address_type = match destination.address {
                Address::Ip(_) => "IP",
                Address::Domain(_) => "도메인",
            };
            let addresses = values
                .iter()
                .take(4)
                .map(|a| a.ip().to_string())
                .collect::<Vec<_>>();
            // 도메인·본문·비밀값은 기록하지 않으며 거부된 IP 표본만 유한하게 남긴다.
            tracing::warn!(address_type, port=destination.port, blocked_ips=?addresses, "목적지 정책이 주소를 거부했습니다");
        }
        Err(Code::Policy)
    } else {
        Ok(allowed)
    }
}
async fn connect_tcp(
    state: &State,
    user: &UserRuntime,
    destination: &Destination,
) -> Result<(TcpStream, SocketAddr), Code> {
    let result=tokio::time::timeout(Duration::from_secs(state.config.limits.connect_seconds),async{
  let addresses=targets(state,user,destination).await?;
  let mut v4=addresses.iter().copied().filter(SocketAddr::is_ipv4);let mut v6=addresses.iter().copied().filter(SocketAddr::is_ipv6);let mut candidates=std::collections::VecDeque::new();
  for _ in 0..16{if let Some(a)=v4.next(){candidates.push_back(a);}
if let Some(a)=v6.next(){candidates.push_back(a);}}
  let mut pending:JoinSet<Result<(TcpStream,SocketAddr),Code>>=JoinSet::new();let mut launch=tokio::time::Instant::now();let mut last=Code::Refused;
  loop{
   if pending.is_empty()&&candidates.is_empty(){return Err(last);}
   tokio::select!{
    r=pending.join_next(),if !pending.is_empty()=>{match r{Some(Ok(Ok((s,a))))=>{pending.abort_all();while pending.join_next().await.is_some(){}let _=s.set_nodelay(true);return Ok((s,a));},Some(Ok(Err(code)))=>last=code,_=>last=Code::Io}if pending.is_empty(){launch=tokio::time::Instant::now();}},
    _=tokio::time::sleep_until(launch),if !candidates.is_empty()&&pending.len()<4=>{let a=candidates.pop_front().ok_or(Code::Io)?;pending.spawn(async move{match tokio::time::timeout(Duration::from_secs(3),TcpStream::connect(a)).await{Ok(Ok(s))=>Ok((s,a)),Ok(Err(e))=>Err(io_code(e)),Err(_)=>Err(Code::ConnectTimeout)}});launch=tokio::time::Instant::now()+Duration::from_millis(250);}
   }
  }
 }).await;
    result.map_err(|_| Code::ConnectTimeout)?
}
async fn connect_udp(
    state: &State,
    user: &UserRuntime,
    destination: &Destination,
) -> Result<(UdpSocket, SocketAddr), Code> {
    let addresses = targets(state, user, destination).await?;
    for address in addresses {
        let bind = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        if let Ok(s) = UdpSocket::bind(bind).await
            && s.connect(address).await.is_ok()
        {
            return Ok((s, address));
        }
    }
    Err(Code::Io)
}
fn opened(sender: &Sender, id: u32, bound: SocketAddr, target: SocketAddr) -> Result<(), Code> {
    let mut b = Destination::socket(bound)
        .encode()
        .map_err(|_| Code::Protocol)?;
    b.extend_from_slice(
        &Destination::socket(target)
            .encode()
            .map_err(|_| Code::Protocol)?,
    );
    sender.control(Frame::new(Kind::OpenOk, id, b))
}
fn activity(mark: &Mutex<Instant>) {
    if let Ok(mut m) = mark.lock() {
        *m = Instant::now();
    }
}
async fn idle(mark: &Mutex<Instant>, seconds: u64) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let elapsed = mark
            .lock()
            .map(|v| v.elapsed().as_secs())
            .unwrap_or(seconds);
        if elapsed >= seconds {
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn tcp_worker(
    state: Arc<State>,
    user: Arc<UserRuntime>,
    sender: Sender,
    id: u32,
    stream: Arc<Stream>,
    conn_send: Arc<SendWindow>,
    mut input: mpsc::Receiver<Command>,
    socket: TcpStream,
) -> Result<(), Code> {
    let (read_half, write_half) = socket.into_split();
    let mut read_half = read_half;
    let mut write_half = write_half;
    let mark = Mutex::new(Instant::now());
    let reading = async {
        loop {
            let buffer_charge = sender.budget.charge(MAX_TCP + 64)?;
            let mut data = vec![0; MAX_TCP];
            let n = read_half.read(&mut data).await.map_err(io_code)?;
            if n == 0 {
                drop(buffer_charge);
                sender
                    .data(Frame::new(Kind::TcpFin, id, Bytes::new()), None)
                    .await?;
                return Ok::<(), Code>(());
            }
            data.truncate(n);
            user.bytes.wait(n as u64).await;
            let mut at = 0;
            while at < n {
                let (credit, size) =
                    Reservation::reserve(conn_send.clone(), stream.send.clone(), n - at).await?;
                sender
                    .data(
                        Frame::new(Kind::TcpData, id, data[at..at + size].to_vec()),
                        Some(credit),
                    )
                    .await?;
                at += size;
            }
            drop(buffer_charge);
            state
                .metrics
                .bytes_to_client
                .fetch_add(n as u64, Ordering::Relaxed);
            activity(&mark);
            tokio::task::yield_now().await;
        }
    };
    let writing = async {
        while let Some(command) = input.recv().await {
            match command {
                Command::Data(data) => {
                    user.bytes.wait(data.payload.len() as u64).await;
                    write_half.write_all(&data.payload).await.map_err(io_code)?;
                    state
                        .metrics
                        .bytes_to_destination
                        .fetch_add(data.payload.len() as u64, Ordering::Relaxed);
                    activity(&mark);
                    drop(data);
                }
                Command::Fin => {
                    write_half.shutdown().await.map_err(io_code)?;
                    return Ok::<(), Code>(());
                }
            }
        }
        Err(Code::Io)
    };
    tokio::select! {_=stream.cancel.cancelled()=>Err(Code::State),_=idle(&mark,state.config.limits.tcp_idle_seconds)=>Err(Code::Idle),r=async{tokio::try_join!(reading,writing).map(|_|())}=>r}
}
async fn recv_datagram(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, bool)> {
    socket
        .async_io(tokio::io::Interest::READABLE, || {
            let mut ios = [IoSliceMut::new(buf)];
            let msg = recvmsg::<SockaddrStorage>(
                socket.as_raw_fd(),
                &mut ios,
                None,
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
            )
            .map_err(io::Error::from)?;
            Ok((msg.bytes, msg.flags.contains(MsgFlags::MSG_TRUNC)))
        })
        .await
}
#[allow(clippy::too_many_arguments)]
async fn udp_worker(
    state: Arc<State>,
    user: Arc<UserRuntime>,
    sender: Sender,
    id: u32,
    stream: Arc<Stream>,
    conn_send: Arc<SendWindow>,
    mut input: mpsc::Receiver<Command>,
    socket: UdpSocket,
    target: SocketAddr,
) -> Result<(), Code> {
    let mark = Mutex::new(Instant::now());
    let mut buf = vec![0; MAX_UDP + 1];
    let endpoint = Destination::socket(target)
        .encode()
        .map_err(|_| Code::Protocol)?;
    let receiving = async {
        loop {
            let (n, truncated) = recv_datagram(&socket, &mut buf).await.map_err(io_code)?;
            if truncated || n > MAX_UDP {
                state.metrics.udp_truncated.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            activity(&mark);
            if !user.packets.take(1) || !user.bytes.take(n.max(1) as u64) {
                state.metrics.udp_dropped.fetch_add(1, Ordering::Relaxed);
                state
                    .metrics
                    .udp_rate_dropped
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let mut payload = endpoint.clone();
            payload.extend_from_slice(&buf[..n]);
            let frame = Frame::new(Kind::UdpDatagram, id, payload);
            // 다른 방향의 UDP 송신을 계속 처리하면서 한 데이터그램만 유한 시간 대기한다.
            let deliver = async {
                let credit =
                    Reservation::exact(conn_send.clone(), stream.send.clone(), frame.credit())
                        .await?;
                sender.data(frame, Some(credit)).await
            };
            match tokio::time::timeout(Duration::from_secs(1), deliver).await {
                Ok(Ok(())) => {
                    state
                        .metrics
                        .bytes_to_client
                        .fetch_add(n as u64, Ordering::Relaxed);
                }
                Ok(Err(_)) => {
                    state.metrics.udp_dropped.fetch_add(1, Ordering::Relaxed);
                    state
                        .metrics
                        .udp_queue_dropped
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    state.metrics.udp_dropped.fetch_add(1, Ordering::Relaxed);
                    state
                        .metrics
                        .udp_window_dropped
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    };
    let sending = async {
        while let Some(command) = input.recv().await {
            let Command::Data(data) = command else {
                return Err(Code::State);
            };
            activity(&mark);
            if !user.packets.take(1) || !user.bytes.take(data.payload.len().max(1) as u64) {
                state.metrics.udp_dropped.fetch_add(1, Ordering::Relaxed);
                state
                    .metrics
                    .udp_rate_dropped
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let n = socket.send(&data.payload).await.map_err(io_code)?;
            if n != data.payload.len() {
                return Err(Code::Io);
            }
            state
                .metrics
                .bytes_to_destination
                .fetch_add(n as u64, Ordering::Relaxed);
        }
        Err::<(), Code>(Code::State)
    };
    tokio::select! {
        _=stream.cancel.cancelled()=>Err(Code::State),
        _=idle(&mark,state.config.limits.udp_idle_seconds)=>Err(Code::Idle),
        r=receiving=>r,
        r=sending=>r,
    }
}

async fn dns_request(
    state: Arc<State>,
    user: Arc<UserRuntime>,
    sender: Sender,
    request: u32,
    wire: Bytes,
) -> Result<(), Code> {
    let result = state.resolver.raw(&wire).await.and_then(|b| {
        let m = Message::from_vec(&b).map_err(|_| Code::DnsMalformed)?;
        let denied = m
            .answers
            .iter()
            .chain(&m.additionals)
            .any(|r| match &r.data {
                RData::A(v) => {
                    !policy::allowed(&state.config.policy, &user.policy, IpAddr::V4(v.0))
                }
                RData::AAAA(v) => {
                    !policy::allowed(&state.config.policy, &user.policy, IpAddr::V6(v.0))
                }
                _ => false,
            });
        if denied { Err(Code::Policy) } else { Ok(b) }
    });
    let mut b = request.to_be_bytes().to_vec();
    match result {
        Ok(wire) => {
            b.extend_from_slice(&0u16.to_be_bytes());
            b.extend_from_slice(&wire);
        }
        Err(code) => {
            b.extend_from_slice(&(code as u16).to_be_bytes());
            b.extend_from_slice(code.message().as_bytes());
        }
    }
    sender.data(Frame::new(Kind::DnsResponse, 0, b), None).await
}

async fn tunnel(
    state: Arc<State>,
    owner: String,
    user: Arc<UserRuntime>,
    fingerprint: String,
    peer: IpAddr,
    tls: tokio_rustls::server::TlsStream<tokio::io::DuplexStream>,
) -> Result<()> {
    let _count = CountGuard::new(state.metrics.clone(), 1);
    let _user_permit = user
        .connections
        .clone()
        .try_acquire_owned()
        .map_err(|_| anyhow!("사용자 연결 한도"))?;
    let id = state.next.fetch_add(1, Ordering::Relaxed);
    let connection_id = id;
    let diagnostics = Arc::new(ConnectionDiagnostics::default());
    let cancel = CancellationToken::new();
    state
        .connections
        .lock()
        .map_err(|_| anyhow!("연결 잠금"))?
        .insert(
            id,
            ConnectionInfo {
                owner: owner.clone(),
                fingerprint,
                diagnostics: diagnostics.clone(),
                peer,
                cancel: cancel.clone(),
            },
        );
    tracing::info!(connection=id,owner=%owner,peer=%peer,"인증된 터널 연결");
    let _guard = TunnelGuard {
        state: state.clone(),
        id,
    };
    let (mut reader, mut writer) = tokio::io::split(tls);
    let first = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut reader))
        .await??
        .ok_or_else(|| anyhow!("HELLO EOF"))?;
    ensure!(first.kind == Kind::Hello, "최초 HELLO 필요");
    let hello = Hello::decode(&first.payload)?;
    let mut welcome = Hello::default().encode();
    welcome.extend_from_slice(&(state.config.limits.tcp_per_connection as u16).to_be_bytes());
    welcome.extend_from_slice(&(state.config.limits.udp_per_connection as u16).to_be_bytes());
    welcome.extend_from_slice(&(state.config.limits.udp_idle_seconds as u32).to_be_bytes());
    write_frame(&mut writer, &Frame::new(Kind::Welcome, 0, welcome)).await?;
    diagnostics.mux_ready.store(true, Ordering::Relaxed);
    let (conn_send, conn_receive) = (
        SendWindow::new(hello.connection),
        ReceiveWindow::new(CONNECTION_WINDOW),
    );
    let streams: Streams = Arc::new(Mutex::new(HashMap::new()));
    let (mut last, mut draining) = (0u32, false);
    let mut drain_deadline = tokio::time::Instant::now() + Duration::from_secs(86400);
    let (frame_tx, mut frame_rx) = mpsc::channel(8);
    let reading = tokio::spawn(async move {
        loop {
            match read_frame(&mut reader).await {
                Ok(Some(f)) => {
                    if frame_tx.send(Ok(f)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let _ = frame_tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel(state.config.limits.control_queue);
    let (data_tx, mut data_rx) = mpsc::channel::<Queued>(128);
    let sender = Sender {
        stream_cancel: None,
        control: ctrl_tx,
        data: data_tx,
        cancel: cancel.clone(),
        budget: Budget {
            global: state.global_buffer.clone(),
            user: user.buffer.clone(),
            connection: Arc::new(Semaphore::new(state.config.limits.connection_buffer_bytes)),
        },
    };
    let (goaway_sent, mut goaway_seen) = tokio::sync::watch::channel(false);
    let writer_cancel = cancel.clone();
    let writing = tokio::spawn(async move {
        loop {
            tokio::select! {biased;_=writer_cancel.cancelled()=>break,Some(frame)=ctrl_rx.recv()=>{if write_frame(&mut writer,&frame).await.is_err(){writer_cancel.cancel();break;}
            if frame.kind==Kind::Goaway{let _=goaway_sent.send(true);}},Some(q)=data_rx.recv()=>{if q.stream_cancel.as_ref().is_some_and(|v|v.is_cancelled()){continue;}
            if let Some(c)=q.credit{c.commit();}
                        if write_frame(&mut writer,&q.frame).await.is_err(){writer_cancel.cancel();break;}}}
        }
    });
    let mut jobs = JoinSet::new();
    let mut updates = tokio::time::interval(Duration::from_millis(5));
    updates.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let dns_slots = Arc::new(Semaphore::new(state.config.limits.dns_inflight));
    let requests = Arc::new(Mutex::new(HashSet::<u32>::new()));
    let controls = crate::flow::Rate::new(50000);
    let dns_rate = crate::flow::Rate::new(1000);
    let stream_controls = crate::flow::Rate::new(4096);
    let incoming_frames = crate::flow::Rate::new(
        (user.policy.udp_per_second as u64 * 8 + user.policy.bytes_per_second / 1024 + 8192)
            .max(16384),
    );
    let result:Result<()>=async{loop{tokio::select!{
  _=cancel.cancelled()=>break,
  _=state.shutdown.cancelled(),if !draining=>{draining=true;drain_deadline=tokio::time::Instant::now()+Duration::from_secs(state.config.limits.drain_seconds);let mut p=(Code::Shutdown as u16).to_be_bytes().to_vec();p.extend_from_slice(&last.to_be_bytes());sender.control(Frame::new(Kind::Goaway,0,p)).map_err(|_|anyhow!("종료 큐 한도"))?;},
  _=tokio::time::sleep_until(drain_deadline),if draining=>break,
  _=updates.tick()=>{let n=conn_receive.take_pending();if n>0{sender.control(Frame::new(Kind::WindowUpdate,0,n.to_be_bytes().to_vec())).map_err(|_|anyhow!("윈도 큐 한도"))?;}let list=streams.lock().map_err(|_|anyhow!("스트림 잠금"))?.iter().map(|(id,s)|(*id,s.clone())).collect::<Vec<_>>();for(id,s)in list{let n=s.receive.take_pending();if n>0{sender.control(Frame::new(Kind::WindowUpdate,id,n.to_be_bytes().to_vec())).map_err(|_|anyhow!("윈도 큐 한도"))?;}}},
  Some(job)=jobs.join_next()=>{if job.is_err(){return Err(anyhow!("스트림 작업이 비정상 종료됐습니다"));}},
  frame=frame_rx.recv()=>{
   let Some(frame)=frame else{break};let frame=frame?;diagnostics.received(&frame);ensure!(incoming_frames.take(1),"프레임 속도 한도");if matches!(frame.kind,Kind::OpenTcp|Kind::OpenUdp|Kind::Reset|Kind::TcpFin){ensure!(stream_controls.take(1),"스트림 제어 속도 한도");}
   match frame.kind{
    Kind::OpenTcp|Kind::OpenUdp=>{
     ensure!(frame.id>last&&frame.id%2==1&&frame.id<=0xffff_fffd,"스트림 ID 재사용/역행/짝수");last=frame.id;
     if draining{sender.control(Frame::error(Kind::OpenError,frame.id,Code::Shutdown)).map_err(|_|anyhow!("제어 큐"))?;continue;}
     let destination=match Destination::exact(&frame.payload){Ok(v)=>v,Err(_)=>{diagnostics.failed(frame.id,Code::Protocol,"destination");if state.diagnostic_logs.take(1){tracing::warn!(connection=connection_id,stream=frame.id,code=Code::Protocol as u16,phase="destination","목적지 주소 형식이 잘못돼 요청을 거부했습니다");}sender.control(Frame::error(Kind::OpenError,frame.id,Code::Protocol)).map_err(|_|anyhow!("제어 큐"))?;continue;}};
     let udp=frame.kind==Kind::OpenUdp;let count=streams.lock().map_err(|_|anyhow!("스트림 잠금"))?.values().filter(|s|s.udp==udp).count();let limit=if udp{state.config.limits.udp_per_connection}else{state.config.limits.tcp_per_connection};
     let user_permit=if udp{user.udp.clone()}else{user.tcp.clone()}.try_acquire_owned();let global_permit=state.streams.clone().try_acquire_owned();
     if count>=limit||user_permit.is_err()||global_permit.is_err(){diagnostics.failed(frame.id,Code::Resource,"resource");if state.diagnostic_logs.take(1){tracing::warn!(connection=connection_id,stream=frame.id,code=Code::Resource as u16,phase="resource","목적지 스트림 한도로 요청을 거부했습니다");}sender.control(Frame::error(Kind::OpenError,frame.id,Code::Resource)).map_err(|_|anyhow!("제어 큐"))?;continue;}
     let user_permit=user_permit.map_err(|_|anyhow!("사용자 한도"))?;let global_permit=global_permit.map_err(|_|anyhow!("전역 한도"))?;let(tx,rx)=mpsc::channel(if udp{64}else{2048});let sc=Arc::new(Stream{udp,open:AtomicBool::new(false),fin:AtomicBool::new(false),send:SendWindow::new(hello.stream),receive:ReceiveWindow::new(STREAM_WINDOW),input:tx,cancel:cancel.child_token()});streams.lock().map_err(|_|anyhow!("스트림 잠금"))?.insert(frame.id,sc.clone());
     let(st,u,mut out,list,send)=(state.clone(),user.clone(),sender.clone(),streams.clone(),conn_send.clone());out.stream_cancel=Some(sc.cancel.clone());
     let diag=diagnostics.clone();let diagnostic_state=st.clone();
     jobs.spawn(async move{let _permits=(user_permit,global_permit);let _guard=StreamGuard{streams:list,id:frame.id};let _count=CountGuard::new(st.metrics.clone(),if udp{3}else{2});let id=frame.id;
      let action=async{
       if udp{let(socket,target)=tokio::time::timeout(Duration::from_secs(st.config.limits.connect_seconds),connect_udp(&st,&u,&destination)).await.map_err(|_|Code::ConnectTimeout)??;let bound=socket.local_addr().map_err(io_code)?;sc.open.store(true,Ordering::Release);opened(&out,id,bound,target)?;diag.open_ok.fetch_add(1,Ordering::Relaxed);udp_worker(st,u,out.clone(),id,sc.clone(),send,rx,socket,target).await}
       else{let(socket,target)=connect_tcp(&st,&u,&destination).await?;let bound=socket.local_addr().map_err(io_code)?;sc.open.store(true,Ordering::Release);opened(&out,id,bound,target)?;diag.open_ok.fetch_add(1,Ordering::Relaxed);tcp_worker(st,u,out.clone(),id,sc.clone(),send,rx,socket).await}
      };
      let result=tokio::select!{_=sc.cancel.cancelled()=>Err(Code::State),r=action=>r};
      if let Err(code)=result&& !out.cancel.is_cancelled()&&code!=Code::State{let phase=if sc.open.load(Ordering::Acquire){"stream"}else{"connect"};diag.failed(id,code,phase);if diagnostic_state.diagnostic_logs.take(1){tracing::warn!(connection=connection_id,stream=id,protocol=if udp{"UDP"}else{"TCP"},code=code as u16,phase,reason=code.message(),"목적지 처리에 실패했습니다");}let kind=if sc.open.load(Ordering::Acquire){Kind::Reset}else{Kind::OpenError};let _=out.control(Frame::error(kind,id,code));}
     });
    },
    Kind::TcpData|Kind::UdpDatagram=>{
     let stream=streams.lock().map_err(|_|anyhow!("스트림 잠금"))?.get(&frame.id).cloned();let Some(stream)=stream else{ensure!(frame.id<=last&&frame.id%2==1,"알 수 없는 데이터 스트림");drop(Acknowledgement::take(frame.credit(),conn_receive.clone(),ReceiveWindow::new(STREAM_WINDOW)).map_err(|_|anyhow!("늦은 데이터 연결 윈도 초과"))?);sender.control(Frame::error(Kind::Reset,frame.id,Code::State)).map_err(|_|anyhow!("제어 큐"))?;continue;};
     if !stream.open.load(Ordering::Acquire)||stream.udp!=(frame.kind==Kind::UdpDatagram)||stream.fin.load(Ordering::Acquire){stream.cancel.cancel();sender.control(Frame::error(Kind::Reset,frame.id,Code::State)).map_err(|_|anyhow!("제어 큐"))?;continue;}
     if stream.udp&&frame.payload.len()>MAX_UDP{stream.cancel.cancel();sender.control(Frame::error(Kind::Reset,frame.id,Code::TooLarge)).map_err(|_|anyhow!("제어 큐"))?;continue;}
     let ack=Acknowledgement::take(frame.credit(),conn_receive.clone(),stream.receive.clone()).map_err(|_|anyhow!("수신 윈도 초과"))?;
     let charge=match sender.budget.charge(frame.payload.len()+64){Ok(v)=>v,Err(_)=>{drop(ack);if stream.udp{state.metrics.udp_dropped.fetch_add(1,Ordering::Relaxed);state.metrics.udp_queue_dropped.fetch_add(1,Ordering::Relaxed);}else{stream.cancel.cancel();sender.control(Frame::error(Kind::Reset,frame.id,Code::Resource)).map_err(|_|anyhow!("제어 큐"))?;}continue;}};
     let data=Input{payload:frame.payload,_ack:ack,_charge:charge};if stream.input.try_send(Command::Data(data)).is_err(){if stream.udp{state.metrics.udp_dropped.fetch_add(1,Ordering::Relaxed);state.metrics.udp_queue_dropped.fetch_add(1,Ordering::Relaxed);}else{stream.cancel.cancel();sender.control(Frame::error(Kind::Reset,frame.id,Code::Resource)).map_err(|_|anyhow!("제어 큐"))?;}}
    },
    Kind::TcpFin=>{let stream=streams.lock().map_err(|_|anyhow!("스트림 잠금"))?.get(&frame.id).cloned();if let Some(s)=stream{if s.udp||!s.open.load(Ordering::Acquire)||s.fin.swap(true,Ordering::SeqCst){s.cancel.cancel();sender.control(Frame::error(Kind::Reset,frame.id,Code::State)).map_err(|_|anyhow!("제어 큐"))?;}else if s.input.try_send(Command::Fin).is_err(){s.cancel.cancel();}}else{sender.control(Frame::error(Kind::Reset,frame.id,Code::State)).map_err(|_|anyhow!("제어 큐"))?;}},
    Kind::Reset=>{if let Some(s)=streams.lock().map_err(|_|anyhow!("스트림 잠금"))?.get(&frame.id){s.cancel.cancel();}},
    Kind::WindowUpdate=>{ensure!(controls.take(1),"제어 프레임 속도 한도");let n=u32::from_be_bytes(frame.payload[..].try_into()?);if frame.id==0{conn_send.update(n).map_err(|_|anyhow!("연결 윈도 반환 오류"))?;}else if let Some(s)=streams.lock().map_err(|_|anyhow!("스트림 잠금"))?.get(&frame.id){s.send.update(n).map_err(|_|anyhow!("스트림 윈도 반환 오류"))?;}else{ensure!(frame.id<=last&&frame.id%2==1,"알 수 없는 스트림 윈도");}},
    Kind::Ping=>{ensure!(controls.take(1),"PING 속도 한도");sender.control(Frame::new(Kind::Pong,0,frame.payload)).map_err(|_|anyhow!("제어 큐"))?;},Kind::Pong=>{ensure!(controls.take(1),"PONG 속도 한도");},
    Kind::Goaway=>{if !draining{draining=true;drain_deadline=tokio::time::Instant::now()+Duration::from_secs(state.config.limits.drain_seconds);}},
    Kind::DnsRequest=>{ensure!(dns_rate.take(1),"DNS 요청 속도 한도");let request=u32::from_be_bytes(frame.payload[..4].try_into()?);let permit=dns_slots.clone().try_acquire_owned();if permit.is_err(){let mut b=request.to_be_bytes().to_vec();b.extend_from_slice(&(Code::Resource as u16).to_be_bytes());sender.control(Frame::new(Kind::DnsResponse,0,b)).map_err(|_|anyhow!("DNS 응답 큐"))?;continue;}ensure!(requests.lock().map_err(|_|anyhow!("DNS 잠금"))?.insert(request),"DNS 요청 ID 재사용");let(st,u,out,reqs)=(state.clone(),user.clone(),sender.clone(),requests.clone());jobs.spawn(async move{let _permit=permit;let _=dns_request(st,u,out,request,frame.payload.slice(4..)).await;if let Ok(mut r)=reqs.lock(){r.remove(&request);}});},
    _=>return Err(anyhow!("프레임 송수신 방향/상태 오류")),
   }
  }
 }}Ok(())}.await;
    let protocol_failure =
        result
            .as_ref()
            .err()
            .is_some_and(|e| match e.downcast_ref::<io::Error>() {
                Some(v) => {
                    v.kind() == io::ErrorKind::InvalidData
                        || v.get_ref()
                            .is_some_and(|v| v.is::<mtp_protocol::ProtocolError>())
                }
                None => true,
            });
    if result.is_err() && !cancel.is_cancelled() {
        let mut p = ((if protocol_failure {
            Code::Protocol
        } else {
            Code::Io
        }) as u16)
            .to_be_bytes()
            .to_vec();
        p.extend_from_slice(&last.to_be_bytes());
        if sender.control(Frame::new(Kind::Goaway, 0, p)).is_ok() {
            let _ = tokio::time::timeout(Duration::from_millis(250), async {
                while !*goaway_seen.borrow_and_update() {
                    if goaway_seen.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await;
        }
    }
    cancel.cancel();
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    reading.abort();
    let _ = reading.await;
    writing.abort();
    let _ = writing.await;
    streams.lock().map_err(|_| anyhow!("스트림 잠금"))?.clear();
    if result.is_err() {
        if protocol_failure {
            state
                .metrics
                .protocol_failed
                .fetch_add(1, Ordering::Relaxed);
        } else {
            state
                .metrics
                .transport_failed
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    tracing::info!(
        connection = id,
        diagnostics = %diagnostics.json(),
        reason = if result.is_ok() {
            "closed"
        } else if protocol_failure {
            "protocol_error"
        } else {
            "transport_error"
        },
        "터널 연결 종료"
    );
    result
}

fn listener(address: SocketAddr) -> io::Result<TcpListener> {
    let s = socket2::Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    s.set_reuse_address(true)?;
    if address.is_ipv6() {
        s.set_only_v6(true)?;
    }
    s.bind(&address.into())?;
    s.listen(128)?;
    s.set_nonblocking(true)?;
    TcpListener::from_std(s.into())
}
async fn metrics(state: Arc<State>) -> Result<()> {
    let path = &state.config.metrics_socket;
    let parent = path.parent().ok_or_else(|| anyhow!("상태 소켓 경로"))?;
    std::fs::create_dir_all(parent)?;
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        ensure!(meta.file_type().is_socket(), "상태 경로가 소켓이 아닙니다");
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    let mut jobs = JoinSet::new();
    let permits = Arc::new(Semaphore::new(8));
    loop {
        tokio::select! {_=state.shutdown.cancelled()=>break,Some(_)=jobs.join_next()=>{},value=listener.accept()=>{let(mut socket,_)=value?;let Ok(p)=permits.clone().try_acquire_owned()else{continue;};let st=state.clone();jobs.spawn(async move{let _p=p;let mut b=[0;1024];let n=tokio::time::timeout(Duration::from_secs(2),socket.read(&mut b)).await.ok().and_then(Result::ok).unwrap_or(0);let request=std::str::from_utf8(&b[..n]).unwrap_or("");let(body,ct,code)=if request.starts_with("GET /status "){(st.status().to_string(),"application/json","200 OK")}else if request.starts_with("GET /metrics "){let j=st.metrics.json();let s=j.as_object().map(|o|o.iter().filter_map(|(k,v)|v.as_u64().map(|n|format!("mtp_gateway_{k} {n}\n"))).collect::<String>()).unwrap_or_default();(s,"text/plain; version=0.0.4","200 OK")}else{("{}".into(),"application/json","404 Not Found")};let response=format!("HTTP/1.1 {code}\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",body.len());let _=tokio::time::timeout(Duration::from_secs(2),socket.write_all(response.as_bytes())).await;});}}
    }
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    Ok(())
}
pub async fn serve(
    config: Config,
    ready: Option<tokio::sync::oneshot::Sender<Arc<State>>>,
) -> Result<()> {
    let state = State::new(config)?;
    let secret = Secret::parse(&std::fs::read_to_string(&state.config.secret_file)?)?;
    let tls = Arc::new(mtp_transport::server_tls(
        &state.config.server_cert,
        &state.config.server_key,
        &state.config.client_ca,
    )?);
    let replay = Arc::new(ReplayCache::new(
        state.config.limits.replay_entries,
        Duration::from_secs(610),
    ));
    let mut listeners = Vec::new();
    for a in &state.config.listen {
        listeners.push(listener(*a)?);
    }
    let mut tasks = JoinSet::new();
    let (st, sec, acceptor, rp) = (
        state.clone(),
        Arc::new(secret),
        tokio_rustls::TlsAcceptor::from(tls),
        replay,
    );
    for listener in listeners {
        let (state, secret, acceptor, replay) =
            (st.clone(), sec.clone(), acceptor.clone(), rp.clone());
        tasks.spawn(async move{let mut connections=JoinSet::new();loop{tokio::select!{_=state.shutdown.cancelled()=>break,Some(_)=connections.join_next()=>{},value=listener.accept()=>{let Ok((socket,peer))=value else{continue;};if !state.handshake_allowed(peer.ip()){continue;}let Ok(global)=state.tunnels.clone().try_acquire_owned()else{continue;};let Ok(handshake)=state.handshakes.clone().try_acquire_owned()else{continue;};let(state,secret,acceptor,replay)=(state.clone(),secret.clone(),acceptor.clone(),replay.clone());connections.spawn(async move{let _global=global;state.metrics.accepted.fetch_add(1,Ordering::Relaxed);let result=tokio::time::timeout(Duration::from_secs(state.config.limits.handshake_seconds),async{let outer=mtp_transport::accept(socket,&secret,&replay).await?;let tls=acceptor.accept(outer).await?;ensure!(tls.get_ref().1.alpn_protocol()==Some(mtp_transport::ALPN),"ALPN 불일치");let cert=tls.get_ref().1.peer_certificates().and_then(|v|v.first()).ok_or_else(||anyhow!("클라이언트 인증서 누락"))?;let fp=mtp_transport::fingerprint(cert.as_ref());tokio::task::spawn_blocking({let state=state.clone();move||state.reload()}).await??;state.registry_error.store(0,Ordering::Relaxed);let(owner,user)=state.authenticate(&fp).map_err(|_|anyhow!("사용자 인증서/권한 거부"))?;Ok::<_,anyhow::Error>((tls,fp,owner,user))}).await;drop(handshake);
 match result{Ok(Ok((tls,fp,owner,user)))=>{let st=state.clone();if let Err(e)=tunnel(state,owner,user,fp,peer.ip(),tls).await&&st.diagnostic_logs.take(1){let reason=if e.to_string()=="사용자 연결 한도"{"사용자 연결 한도"}else{"HELLO 또는 터널 처리 실패"};tracing::warn!(peer=%peer.ip(),reason,"인증 후 터널 처리를 완료하지 못했습니다");}},_=>{state.metrics.authentication_failed.fetch_add(1,Ordering::Relaxed);tracing::debug!(reason="인증 또는 핸드셰이크 실패","터널 거부");}}
 });}}}let deadline=tokio::time::sleep(Duration::from_secs(state.config.limits.drain_seconds+2));tokio::pin!(deadline);loop{tokio::select!{_= &mut deadline=>{connections.abort_all();break;},v=connections.join_next()=>if v.is_none(){break;}}}while connections.join_next().await.is_some(){}Ok::<(),anyhow::Error>(())});
    }
    let st = state.clone();
    tasks.spawn(async move { metrics(st).await });
    let st = state.clone();
    tasks.spawn(async move{let mut tick=tokio::time::interval(Duration::from_secs(1));loop{tokio::select!{_=st.shutdown.cancelled()=>break,_=tick.tick()=>{if st.reload().is_err(){st.registry_error.store(1,Ordering::Relaxed);if let Ok(c)=st.connections.lock(){for v in c.values(){v.cancel.cancel();}}}else{st.registry_error.store(0,Ordering::Relaxed);}}}}Ok(())});
    if let Some(ready) = ready {
        let _ = ready.send(state.clone());
    }
    #[cfg(unix)]
    {
        let st = state.clone();
        tasks.spawn(async move{let mut term=tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;tokio::select!{_=st.shutdown.cancelled()=>{},_=term.recv()=>{st.shutdown.cancel();},_=tokio::signal::ctrl_c()=>{st.shutdown.cancel();}}Ok(())});
    }
    while let Some(r) = tasks.join_next().await {
        if r.is_err() || r.as_ref().is_ok_and(|v| v.is_err()) {
            state.shutdown.cancel();
        }
    }
    Ok(())
}
