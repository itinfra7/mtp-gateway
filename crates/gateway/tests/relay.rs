//! 실제 소켓·독립 DNS 응답기를 사용하는 전체 계층 통합 검증.
use anyhow::{Result, ensure};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use mtp_gateway::pki::{self, Endpoint};
use mtp_protocol::{Destination, Kind};
use mtp_relay::{config::Registry, state::State};
use mtp_test_peer::Peer;
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
};
struct Fixture {
    root: PathBuf,
    client: PathBuf,
    state: Arc<State>,
    server: JoinHandle<Result<()>>,
    dns: JoinHandle<()>,
    queries: Arc<AtomicUsize>,
}
impl Fixture {
    async fn new() -> Result<Self> {
        Self::with_idle(5).await
    }
    async fn with_idle(udp_idle: u64) -> Result<Self> {
        Self::with_tuning(udp_idle, 8, 16, 100).await
    }
    async fn with_tuning(
        udp_idle: u64,
        tcp_limit: usize,
        udp_limit: usize,
        udp_rate: u32,
    ) -> Result<Self> {
        let mut b = [0; 8];
        mtp_transport::random(&mut b)?;
        let root = std::env::temp_dir().join(format!("mtp-test-{}", hex::encode(b)));
        let socket = std::net::TcpListener::bind("127.0.0.1:0")?;
        let listen = socket.local_addr()?;
        drop(socket);
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let dns_addr = udp.local_addr()?;
        let queries = Arc::new(AtomicUsize::new(0));
        let count = queries.clone();
        let dns = tokio::spawn(async move {
            let mut buf = [0; 65535];
            while let Ok((n, peer)) = udp.recv_from(&mut buf).await {
                count.fetch_add(1, Ordering::Relaxed);
                let Ok(mut m) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                m.metadata.message_type = MessageType::Response;
                let q = m.queries[0].clone();
                let name = q.name().to_ascii();
                if name.starts_with("timeout.") {
                    continue;
                }
                if name.starts_with("nx.") {
                    m.metadata.response_code = ResponseCode::NXDomain;
                } else if name.starts_with("fail.") {
                    m.metadata.response_code = ResponseCode::ServFail;
                } else if !name.starts_with("empty.")
                    && !(name.starts_with("v4.") && q.query_type() == RecordType::AAAA)
                {
                    let data = if q.query_type() == RecordType::A {
                        RData::A(A(if name.starts_with("fake.") {
                            std::net::Ipv4Addr::new(198, 18, 0, 1)
                        } else {
                            std::net::Ipv4Addr::LOCALHOST
                        }))
                    } else {
                        RData::AAAA(AAAA(std::net::Ipv6Addr::LOCALHOST))
                    };
                    m.add_answer(Record::from_rdata(
                        q.name().clone(),
                        if name.starts_with("zero.") { 0 } else { 2 },
                        data,
                    ));
                }
                if let Ok(w) = m.to_vec() {
                    let _ = udp.send_to(&w, peer).await;
                }
            }
        });
        let mut config = pki::init(
            &root,
            Endpoint {
                host: "127.0.0.1".into(),
                port: listen.port(),
                outer_sni: "www.example.com".into(),
                server_name: "gateway.example.com".into(),
            },
            vec![listen],
            dns_addr,
        )?;
        config.policy.allow = vec!["127.0.0.0/8".parse()?, "::1/128".parse()?];
        config.limits.udp_idle_seconds = udp_idle;
        config.limits.tcp_per_connection = tcp_limit;
        config.limits.udp_per_connection = udp_limit;
        config.limits.tcp_idle_seconds = 5;
        config.limits.drain_seconds = 1;
        config.limits.handshakes_per_second = 100;
        config.resolver.timeout_seconds = 1;
        pki::atomic(
            &root.join("gateway.toml"),
            toml::to_string_pretty(&config)?.as_bytes(),
        )?;
        pki::issue(&root, "first", "test-user", 2)?;
        let mut r = Registry::load(&config.registry_file)?;
        let policy = r.users.get_mut("test-user").unwrap();
        policy.connections = 2;
        policy.bytes_per_second = 64 * 1024 * 1024;
        policy.tcp_streams = tcp_limit.max(16);
        policy.udp_associations = udp_limit.max(32);
        policy.udp_per_second = udp_rate;
        r.revision += 1;
        pki::save(&config.registry_file, &r)?;
        let client = pki::export(&root, "first", &root.join("exports"))?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(mtp_relay::server::serve(config, Some(tx)));
        let state = rx.await?;
        Ok(Self {
            root,
            client,
            state,
            server,
            dns,
            queries,
        })
    }
    async fn stop(self) -> Result<()> {
        self.state.shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), self.server).await???;
        self.dns.abort();
        let _ = self.dns.await;
        std::fs::remove_dir_all(self.root)?;
        Ok(())
    }
    async fn peer(&self) -> Result<Peer> {
        Peer::connect(&self.client).await
    }
    async fn clean(&self) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                let j = self.state.metrics.json();
                if j["active_tunnels"] == 0
                    && j["active_tcp"] == 0
                    && j["active_udp"] == 0
                    && j["active_tasks"] == 0
                    && self.state.global_buffer.available_permits()
                        == self.state.config.limits.buffer_bytes
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        Ok(())
    }
}
async fn tcp_echo(ip: &str) -> Result<(SocketAddr, JoinHandle<()>)> {
    let l = TcpListener::bind(format!("{ip}:0")).await?;
    let addr = l.local_addr()?;
    let task = tokio::spawn(async move {
        let mut jobs = tokio::task::JoinSet::new();
        loop {
            tokio::select! {Some(_)=jobs.join_next()=>{},r=l.accept()=>{let Ok((mut s,_))=r else{break;};jobs.spawn(async move{let mut b=[0;16384];loop{let n=s.read(&mut b).await?;if n==0{break;}s.write_all(&b[..n]).await?;}s.shutdown().await?;Ok::<_,std::io::Error>(())});}}
        }
    });
    Ok((addr, task))
}
async fn echo_tcp(peer: &Peer, target: Destination, n: usize) -> Result<()> {
    let mut s = peer.open(target, false).await?;
    let bytes = (0..n).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let out = bytes.clone();
    let p = peer.clone();
    let id = s.id;
    let task = tokio::spawn(async move {
        p.send_tcp(id, &out).await?;
        p.finish_tcp(id).await
    });
    let mut got = Vec::new();
    loop {
        let f = s.recv().await?;
        if f.frame.kind == Kind::TcpFin {
            break;
        }
        ensure!(f.frame.kind == Kind::TcpData, "DATA 필요");
        got.extend_from_slice(&f.frame.payload);
        ensure!(got.len() <= n, "초과 응답");
    }
    task.await??;
    ensure!(bytes == got, "전체 TCP 내용 불일치");
    Ok(())
}
fn query(name: &str) -> Result<Vec<u8>> {
    let mut q = Message::new(5225, MessageType::Query, OpCode::Query);
    q.add_query(Query::query(Name::from_ascii(name)?, RecordType::A));
    Ok(q.to_vec()?)
}
#[tokio::test]
async fn 실제_tcp_udp_dns_전체계층() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(40), async {
        let f = Fixture::new().await?;
        let p = f.peer().await?;
        let (a, tcp) = tcp_echo("127.0.0.1").await?;
        echo_tcp(&p, Destination::socket(a), 2 * 1024 * 1024).await?;
        echo_tcp(&p, Destination::new("v4.test", a.port())?, 33333).await?;
        let (a6, tcp6) = tcp_echo("[::1]").await?;
        echo_tcp(&p, Destination::socket(a6), 77777).await?;
        eprintln!("TCP 완료");
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let ua = udp.local_addr()?;
        let udptask = tokio::spawn(async move {
            let mut b = [0; 65536];
            while let Ok((n, a)) = udp.recv_from(&mut b).await {
                let _ = udp.send_to(&b[..n], a).await;
            }
        });
        let mut u = p.open(Destination::socket(ua), true).await?;
        let mut u2 = p
            .open(Destination::new("v4.test", ua.port())?, true)
            .await?;
        ensure!(u.id != u2.id, "목적지별 association ID");
        for n in [0, 1, 65507] {
            eprintln!("UDP 단계 {n}");
            let b = vec![73; n];
            u.send(&b).await?;
            let received = match u.recv().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("UDP 실패 현황 {}", f.state.status());
                    return Err(e);
                }
            };
            ensure!(received.udp()?.1 == b, "UDP 경계/내용");
        }
        u2.send(b"second").await?;
        ensure!(u2.recv().await?.udp()?.1 == b"second", "두번째 association");
        ensure!(u.send(&vec![0; 65508]).await.is_err(), "과대 UDP 거부");
        drop(u);
        drop(u2);
        let q = query("v4.test.")?;
        let r = p.dns(&q).await?;
        ensure!(!Message::from_vec(&r)?.answers.is_empty(), "실제 DNS 응답");
        let before = f.queries.load(Ordering::Relaxed);
        p.dns(&q).await?;
        ensure!(f.queries.load(Ordering::Relaxed) == before, "TTL 캐시");
        ensure!(
            p.dns(&query("fake.test.")?).await.is_err(),
            "Fake-IP 응답 거부"
        );
        ensure!(
            p.open(Destination::new("nx.test", a.port())?, false)
                .await
                .err()
                .is_some_and(|e| e.to_string().contains("2")),
            "NXDOMAIN 구분"
        );
        ensure!(
            p.open(Destination::new("empty.test", a.port())?, false)
                .await
                .err()
                .is_some_and(|e| e.to_string().contains("3")),
            "NODATA 구분"
        );
        ensure!(
            p.open(Destination::new("fail.test", a.port())?, false)
                .await
                .err()
                .is_some_and(|e| e.to_string().contains("4")),
            "SERVFAIL 구분"
        );
        ensure!(
            p.open(Destination::new("timeout.test", a.port())?, false)
                .await
                .err()
                .is_some_and(|e| e.to_string().contains("5")),
            "DNS timeout 구분"
        );
        // 실제 통신 경로의 누적 요청과 실패가 구분되어야 진단을 신뢰할 수 있다.
        let status = f.state.status();
        let diagnostics = &status["connections"][0]["diagnostics"];
        ensure!(diagnostics["mux_ready"] == true, "협상 완료 진단");
        ensure!(diagnostics["open_tcp"] == 7, "TCP 요청 진단");
        ensure!(diagnostics["open_udp"] == 2, "UDP 요청 진단");
        ensure!(diagnostics["open_ok"] == 5, "연결 성공 진단");
        ensure!(diagnostics["open_failed"] == 4, "DNS 실패와 성공 분리");
        ensure!(diagnostics["dns_requests"] == 3, "DNS RPC 요청 진단");
        ensure!(
            diagnostics["data_frames"].as_u64().unwrap_or(0) > 0,
            "실제 DATA 수신 진단"
        );
        p.close().await?;
        drop(p);
        f.clean().await?;
        tcp.abort();
        tcp6.abort();
        udptask.abort();
        f.stop().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
#[tokio::test]
async fn 인증_폐기_수명_권한_정리() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let f = Fixture::with_idle(1).await?;
        let p = f.peer().await?;
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let mut u = p.open(Destination::socket(udp.local_addr()?), true).await?;
        ensure!(
            u.recv()
                .await
                .err()
                .is_some_and(|e| e.to_string().contains("11")),
            "UDP 유휴 만료 RESET"
        );
        ensure!(u.send(b"old").await.is_err(), "만료 스트림 부활 금지");
        drop(u);
        let p2 = f.peer().await?;
        ensure!(f.peer().await.is_err(), "사용자 연결 한도");
        pki::revoke(&f.root, "first")?;
        tokio::time::sleep(Duration::from_millis(1200)).await;
        ensure!(p.is_closed() && p2.is_closed(), "폐기 활성 세션 회수");
        let before = f.queries.load(Ordering::Relaxed);
        ensure!(f.peer().await.is_err(), "폐기 인증서 재접속 거부");
        ensure!(
            f.queries.load(Ordering::Relaxed) == before,
            "인증 전 DNS 금지"
        );
        drop(p);
        drop(p2);
        f.clean().await?;
        f.stop().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
#[tokio::test]
async fn 정책과_인증서_서버명_거부() -> Result<()> {
    let f = Fixture::new().await?;
    let mut c: mtp_test_peer::SecuritySettings =
        serde_json::from_slice(&std::fs::read(f.client.join("config/security.json"))?)?;
    let server: mtp_test_peer::ServerSettings =
        serde_json::from_slice(&std::fs::read(f.client.join("config/server.json"))?)?;
    c.server_name = "wrong.example.com".into();
    ensure!(
        Peer::connect_settings(&f.client, &server, &c)
            .await
            .is_err(),
        "서버 이름 검증"
    );
    c.server_name = "gateway.example.com".into();
    c.ca_file = "config/client.pem".into();
    ensure!(
        Peer::connect_settings(&f.client, &server, &c)
            .await
            .is_err(),
        "잘못된 서버 CA 거부"
    );
    let mut r = Registry::load(&f.state.config.registry_file)?;
    r.users.get_mut("test-user").unwrap().allow.clear();
    r.users.get_mut("test-user").unwrap().deny = vec!["127.0.0.0/8".parse()?];
    r.revision += 1;
    pki::save(&f.state.config.registry_file, &r)?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let p = f.peer().await?;
    ensure!(
        p.open(Destination::new("v4.test", 80)?, false)
            .await
            .is_err(),
        "사설 DNS 결과 정책 적용"
    );
    p.close().await?;
    drop(p);
    f.clean().await?;
    f.stop().await
}

#[tokio::test]
async fn 느린_스트림_격리_동시성과_큐상한() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(35), async {
        let f = Fixture::new().await?;
        let p = f.peer().await?;
        let (a, tcp) = tcp_echo("127.0.0.1").await?;
        let flood = TcpListener::bind("127.0.0.1:0").await?;
        let flood_addr = flood.local_addr()?;
        let send = tokio::spawn(async move {
            let (mut s, _) = flood.accept().await?;
            s.write_all(&vec![42; 4 * 1024 * 1024]).await?;
            Ok::<_, std::io::Error>(())
        });
        let stalled = p.open(Destination::socket(flood_addr), false).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..6 {
            let p = p.clone();
            jobs.spawn(async move { echo_tcp(&p, Destination::socket(a), 131071).await });
        }
        while let Some(v) = jobs.join_next().await {
            v??;
        }
        ensure!(!p.is_closed(), "느린 스트림의 다른 연결 차단 금지");
        drop(stalled);
        send.abort();
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let ua = udp.local_addr()?;
        let echo = tokio::spawn(async move {
            let mut b = [0; 65536];
            while let Ok((n, a)) = udp.recv_from(&mut b).await {
                let _ = udp.send_to(&b[..n], a).await;
            }
        });
        let mut u = p.open(Destination::socket(ua), true).await?;
        for _ in 0..500 {
            u.send(&[]).await?;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        ensure!(
            f.state.metrics.json()["udp_dropped"].as_u64().unwrap() > 0,
            "UDP 속도/큐 폐기 계수"
        );
        ensure!(
            f.state.global_buffer.available_permits() <= f.state.config.limits.buffer_bytes,
            "메모리 상한"
        );
        drop(u);
        drop(p);
        f.clean().await?;
        tcp.abort();
        echo.abort();
        f.stop().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn 실제_udp_패킷_관측용() -> Result<()> {
    let f = Fixture::new().await?;
    let p = f.peer().await?;
    for bind in ["127.0.0.1:55070", "[::1]:55071"] {
        let echo = UdpSocket::bind(bind).await?;
        let addr = echo.local_addr()?;
        let task = tokio::spawn(async move {
            let mut b = [0; 2048];
            let (n, a) = echo.recv_from(&mut b).await?;
            echo.send_to(&b[..n], a).await?;
            Ok::<_, std::io::Error>(())
        });
        let mut s = p.open(Destination::socket(addr), true).await?;
        s.send(b"MTP-GATEWAY-SYNTHETIC-PCAP").await?;
        ensure!(
            s.recv().await?.udp()?.1 == b"MTP-GATEWAY-SYNTHETIC-PCAP",
            "실제 UDP 응답"
        );
        task.await??;
    }
    p.close().await?;
    drop(p);
    f.clean().await?;
    f.stop().await
}

#[tokio::test]
async fn dns_ttl_만료_영_캐시_자원_보존() -> Result<()> {
    let f = Fixture::new().await?;
    let r = &f.state.resolver;
    let q = query("zero.test.")?;
    r.raw(&q).await.map_err(|c| anyhow::anyhow!("{c:?}"))?;
    let n = f.queries.load(Ordering::Relaxed);
    r.raw(&q).await.map_err(|c| anyhow::anyhow!("{c:?}"))?;
    ensure!(f.queries.load(Ordering::Relaxed) > n, "TTL0 캐시 금지");
    let q = query("ttl.test.")?;
    r.raw(&q).await.map_err(|c| anyhow::anyhow!("{c:?}"))?;
    let n = f.queries.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(2100)).await;
    r.raw(&q).await.map_err(|c| anyhow::anyhow!("{c:?}"))?;
    ensure!(f.queries.load(Ordering::Relaxed) > n, "TTL 만료 재조회");
    ensure!(
        r.addresses("v4.test", 80).await.is_ok(),
        "IPv6 NODATA와 IPv4 독립"
    );
    f.stop().await
}

#[tokio::test]
async fn 멀티클라이언트_부하와_외부소켓_작업_회수() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(35),async{let f=Fixture::new().await?;let mut clients=Vec::new();for i in 0..8{let id=format!("bench-{i}");pki::issue(&f.root,&id,&id,1)?;clients.push(pki::export(&f.root,&id,&f.root.join("exports"))?);}f.state.reload()?;let(a,echo)=tcp_echo("127.0.0.1").await?;let started=std::time::Instant::now();let mut jobs=tokio::task::JoinSet::new();for root in clients{jobs.spawn(async move{let p=Peer::connect(&root).await?;echo_tcp(&p,Destination::socket(a),2*1024*1024).await?;p.close().await?;Ok::<_,anyhow::Error>(())});}while let Some(v)=jobs.join_next().await{v??;}let elapsed=started.elapsed().as_secs_f64();println!("BENCHMARK clients=8 each_bytes=2097152 echo_bytes=16777216 elapsed_seconds={elapsed:.6} bidirectional_mib_s={:.3}",32.0/elapsed);f.clean().await?;let metrics=f.state.metrics.json();ensure!(metrics["active_tcp"]==0&&metrics["active_tunnels"]==0&&metrics["active_tasks"]==0,"작업/소켓 보존 금지");echo.abort();f.stop().await?;Ok::<_,anyhow::Error>(())}).await??;
    Ok(())
}

#[tokio::test]
async fn udp_응답_출발지_위조와_초과_잘림_차단() -> Result<()> {
    let f = Fixture::new().await?;
    let p = f.peer().await?;
    let socket = UdpSocket::bind("[::1]:0").await?;
    let mut stream = p
        .open(Destination::socket(socket.local_addr()?), true)
        .await?;
    let bound = stream.bound.clone().unwrap();
    let addr = match bound.address {
        mtp_protocol::Address::Ip(ip) => SocketAddr::new(ip, bound.port),
        _ => unreachable!(),
    };
    let attacker = UdpSocket::bind("[::1]:0").await?;
    attacker.send_to("위조".as_bytes(), addr).await?;
    stream.send(b"go").await?;
    let mut b = [0; 10];
    let (_, source) = socket.recv_from(&mut b).await?;
    socket.send_to(&vec![51; 65508], source).await?;
    tokio::time::sleep(Duration::from_millis(40)).await;
    socket.send_to(b"ok", source).await?;
    let got = tokio::time::timeout(Duration::from_secs(2), stream.recv()).await??;
    ensure!(got.udp()?.1 == b"ok", "위조·잘린 데이터 미전달");
    ensure!(
        f.state.metrics.json()["udp_truncated"] == 1,
        "과대 데이터그램 탐지 계수"
    );
    drop(got);
    drop(stream);
    p.close().await?;
    drop(p);
    f.clean().await?;
    f.stop().await
}

#[tokio::test]
async fn 만료인증서_잘못된클라이언트ca_eku_거부() -> Result<()> {
    let f = Fixture::new().await?;
    let queries = f.queries.load(Ordering::Relaxed);
    for mode in [0, 1, 2] {
        let key = rcgen::KeyPair::generate()?;
        let mut params = rcgen::CertificateParams::new(vec![])?;
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(2);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(1);
        if mode == 0 {
            params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        }
        params.extended_key_usages = vec![if mode == 2 {
            rcgen::ExtendedKeyUsagePurpose::ServerAuth
        } else {
            rcgen::ExtendedKeyUsagePurpose::ClientAuth
        }];
        let ca = if mode == 1 { "server-ca" } else { "client-ca" };
        let issuer = rcgen::Issuer::from_ca_cert_pem(
            &std::fs::read_to_string(f.root.join(format!("pki/{ca}.pem")))?,
            rcgen::KeyPair::from_pem(&std::fs::read_to_string(
                f.root.join(format!("pki/{ca}-key.pem")),
            )?)?,
        )?;
        let cert = params.signed_by(&key, &issuer)?;
        let mut registry = Registry::load(&f.state.config.registry_file)?;
        registry.certificates.insert(
            mtp_transport::fingerprint(cert.der()),
            mtp_relay::config::Device {
                id: format!("invalid-{mode}"),
                owner: "test-user".into(),
                enabled: true,
                issued_at: "합성 시험".into(),
                not_after: "합성 시험".into(),
            },
        );
        registry.revision += 1;
        pki::save(&f.state.config.registry_file, &registry)?;
        std::fs::write(f.client.join("config/client.pem"), cert.pem())?;
        std::fs::write(f.client.join("config/client-key.pem"), key.serialize_pem())?;
        ensure!(f.peer().await.is_err(), "실제 인증서 검증 거부 {mode}");
    }
    ensure!(
        f.queries.load(Ordering::Relaxed) == queries,
        "mTLS 실패 전 DNS 조회 금지"
    );
    f.stop().await
}

#[test]
fn 강한_umask_중에도_원장_권한_보존() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut b = [0; 8];
    mtp_transport::random(&mut b)?;
    let root = std::env::temp_dir().join(format!("mtp-umask-{}", hex::encode(b)));
    let cfg = pki::init(
        &root,
        Endpoint {
            host: "127.0.0.1".into(),
            port: 12345,
            outer_sni: "www.example.com".into(),
            server_name: "gateway.example.com".into(),
        },
        vec!["127.0.0.1:12345".parse()?],
        "127.0.0.1:53".parse()?,
    )?;
    std::fs::set_permissions(&cfg.registry_file, std::fs::Permissions::from_mode(0o640))?;
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg("umask 077; exec \"$@\"")
        .arg("-")
        .arg(env!("CARGO_BIN_EXE_mtp-gateway"))
        .args(["client", "issue", "--root"])
        .arg(&root)
        .args([
            "--id",
            "umask-child",
            "--owner",
            "synthetic-owner",
            "--days",
            "1",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    ensure!(status.success(), "자식 발급 명령");
    ensure!(
        std::fs::metadata(&cfg.registry_file)?.permissions().mode() & 0o777 == 0o640,
        "원장0640 보존"
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn 작은_연결윈도에서_유휴tcp가_udp를_막지_않음() -> Result<()> {
    let f = Fixture::new().await?;
    let server: mtp_test_peer::ServerSettings =
        serde_json::from_slice(&std::fs::read(f.client.join("config/server.json"))?)?;
    let security: mtp_test_peer::SecuritySettings =
        serde_json::from_slice(&std::fs::read(f.client.join("config/security.json"))?)?;
    let p = Peer::connect_settings_with_hello(
        &f.client,
        &server,
        &security,
        mtp_protocol::Hello {
            connection: 131072,
            stream: 131072,
            capabilities: 7,
        },
    )
    .await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let a = listener.local_addr()?;
    let mut streams = Vec::new();
    let mut sockets = Vec::new();
    for _ in 0..8 {
        streams.push(p.open(Destination::socket(a), false).await?);
        sockets.push(listener.accept().await?.0);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let a = udp.local_addr()?;
    let echo = tokio::spawn(async move {
        let mut b = [0; 128];
        let (n, a) = udp.recv_from(&mut b).await?;
        udp.send_to(&b[..n], a).await?;
        Ok::<_, std::io::Error>(())
    });
    let mut u = p.open(Destination::socket(a), true).await?;
    u.send(b"fair").await?;
    let reply = tokio::time::timeout(Duration::from_secs(2), u.recv()).await??;
    ensure!(
        reply.udp()?.1 == b"fair",
        "유휴 TCP의 미사용 송신 credit 점유 금지"
    );
    drop(reply);
    drop(u);
    drop(streams);
    drop(sockets);
    p.close().await?;
    drop(p);
    echo.await??;
    f.clean().await?;
    f.stop().await
}

async fn raw_tunnel(
    f: &Fixture,
) -> Result<tokio_rustls::client::TlsStream<tokio::io::DuplexStream>> {
    let secret =
        mtp_transport::Secret::parse(&std::fs::read_to_string(&f.state.config.secret_file)?)?;
    let s = tokio::net::TcpStream::connect(f.state.config.listen[0]).await?;
    let outer = mtp_transport::connect(s, &secret).await?;
    let cfg = mtp_transport::client_tls(
        &f.client.join("config/client.pem"),
        &f.client.join("config/client-key.pem"),
        &f.client.join("config/gateway-ca.pem"),
    )?;
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(
            rustls::pki_types::ServerName::try_from("gateway.example.com")?,
            outer,
        )
        .await?;
    mtp_protocol::write_frame(
        &mut tls,
        &mtp_protocol::Frame::new(Kind::Hello, 0, mtp_protocol::Hello::default().encode()),
    )
    .await?;
    ensure!(
        mtp_protocol::read_frame(&mut tls).await?.unwrap().kind == Kind::Welcome,
        "WELCOME"
    );
    Ok(tls)
}
#[tokio::test]
async fn 실제_잘못된_상태_길이_윈도와_늦은_credit_반환() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let f = Fixture::new().await?;
        for wire in [
            vec![0, 0, 0, 8, 1, 0x24, 0, 0, 0, 0, 0, 0],
            vec![0, 4, 0, 1],
            vec![0, 0, 0, 8, 2, 0x30, 0, 0, 0, 0, 0, 0],
        ] {
            let mut t = raw_tunnel(&f).await?;
            t.write_all(&wire).await?;
            t.flush().await?;
            let r = mtp_protocol::read_frame(&mut t).await?;
            ensure!(
                r.is_some_and(|r| r.kind == Kind::Goaway && r.payload[..2] == [0, 14]),
                "잘못된 형식 GOAWAY/PROTOCOL"
            );
            drop(t);
        }
        let mut t = raw_tunnel(&f).await?;
        mtp_protocol::write_frame(
            &mut t,
            &mtp_protocol::Frame::new(Kind::WindowUpdate, 0, 1u32.to_be_bytes().to_vec()),
        )
        .await?;
        ensure!(
            mtp_protocol::read_frame(&mut t).await?.unwrap().kind == Kind::Goaway,
            "미소비 윈도 반환 거부"
        );
        drop(t);
        let (a, echo) = tcp_echo("127.0.0.1").await?;
        let mut t = raw_tunnel(&f).await?;
        mtp_protocol::write_frame(
            &mut t,
            &mtp_protocol::Frame::new(Kind::OpenTcp, 1, Destination::socket(a).encode()?),
        )
        .await?;
        ensure!(
            mtp_protocol::read_frame(&mut t).await?.unwrap().kind == Kind::OpenOk,
            "OPEN"
        );
        mtp_protocol::write_frame(
            &mut t,
            &mtp_protocol::Frame::error(Kind::Reset, 1, mtp_protocol::Code::State),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(30)).await;
        mtp_protocol::write_frame(
            &mut t,
            &mtp_protocol::Frame::new(Kind::TcpData, 1, vec![0; 4096]),
        )
        .await?;
        let mut returned = 0u32;
        for _ in 0..3 {
            let r = tokio::time::timeout(Duration::from_secs(1), mtp_protocol::read_frame(&mut t))
                .await??
                .unwrap();
            if r.kind == Kind::WindowUpdate && r.id == 0 {
                returned += u32::from_be_bytes(r.payload[..].try_into()?);
                if returned >= 4160 {
                    break;
                }
            }
        }
        ensure!(returned == 4160, "RESET 경합의 늦은 연결 credit 반환");
        mtp_protocol::write_frame(
            &mut t,
            &mtp_protocol::Frame::new(Kind::OpenTcp, 1, Destination::socket(a).encode()?),
        )
        .await?;
        ensure!(
            mtp_protocol::read_frame(&mut t).await?.unwrap().kind == Kind::Goaway,
            "종료 ID 재사용 금지"
        );
        drop(t);
        f.clean().await?;
        echo.abort();
        f.stop().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn 주소군_한쪽의_syn_지연이_다른쪽을_막지_않음() -> Result<()> {
    let f = Fixture::new().await?;
    let p = f.peer().await?;
    let blocked = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    blocked.bind(&"127.0.0.1:0".parse::<SocketAddr>()?.into())?;
    blocked.listen(0)?;
    let addr = blocked.local_addr()?.as_socket().unwrap();
    let hold = tokio::net::TcpStream::connect(addr).await?;
    ensure!(
        tokio::time::timeout(
            Duration::from_millis(100),
            tokio::net::TcpStream::connect(addr)
        )
        .await
        .is_err(),
        "합성 IPv4 accept 대기열을 채워 SYN 지연 구성"
    );
    let listener = TcpListener::bind(SocketAddr::new("::1".parse()?, addr.port())).await?;
    let echo = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await?;
        let mut b = [0; 4096];
        loop {
            let n = s.read(&mut b).await?;
            if n == 0 {
                break;
            }
            s.write_all(&b[..n]).await?;
        }
        s.shutdown().await?;
        Ok::<_, std::io::Error>(())
    });
    tokio::time::timeout(
        Duration::from_secs(1),
        echo_tcp(&p, Destination::new("dual.test", addr.port())?, 1024),
    )
    .await??;
    drop(hold);
    drop(blocked);
    echo.await??;
    p.close().await?;
    drop(p);
    f.clean().await?;
    f.stop().await
}

#[tokio::test]
async fn 목적지_fin_후에도_반대_방향_쓰기_보존() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let f = Fixture::new().await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let target = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            socket.write_all(b"greeting").await?;
            socket.shutdown().await?;
            let mut received = Vec::new();
            socket.read_to_end(&mut received).await?;
            ensure!(
                received == b"after-fin",
                "FIN 이후 반대 방향 데이터 보존 필요"
            );
            Ok::<_, anyhow::Error>(())
        });
        let peer = f.peer().await?;
        let mut stream = peer.open(Destination::socket(target), false).await?;
        let mut received = Vec::new();
        loop {
            let item = stream.recv().await?;
            if item.frame.kind == Kind::TcpFin {
                break;
            }
            ensure!(item.frame.kind == Kind::TcpData, "DATA 필요");
            received.extend_from_slice(&item.frame.payload);
        }
        ensure!(received == b"greeting", "목적지 데이터 누락");
        peer.send_tcp(stream.id, b"after-fin").await?;
        peer.finish_tcp(stream.id).await?;
        server.await??;
        drop(stream);
        peer.close().await?;
        drop(peer);
        f.clean().await?;
        f.stop().await
    })
    .await?
}

#[tokio::test]
async fn 브라우저_동시연결과_연속_udp_예산() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let f = Fixture::with_tuning(10, 512, 512, 10000).await?;
        let p = f.peer().await?;
        let (addr, tcp) = tcp_echo("127.0.0.1").await?;
        let mut tcp_streams = Vec::new();
        for _ in 0..192 {
            tcp_streams.push(p.open(Destination::socket(addr), false).await?);
        }
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let target = socket.local_addr()?;
        let udp = tokio::spawn(async move {
            let mut b = [0; 2048];
            while let Ok((n, a)) = socket.recv_from(&mut b).await {
                socket.send_to(&b[..n], a).await.unwrap();
            }
        });
        let mut udp_streams = Vec::new();
        for _ in 0..192 {
            udp_streams.push(p.open(Destination::socket(target), true).await?);
        }
        // 초당 100개 양방향 공유 예산으로는 실패하던 웹 수준의 짧은 데이터그램 왕복이다.
        for n in 0..500u32 {
            let bytes = n.to_be_bytes();
            udp_streams[0].send(&bytes).await?;
            let response =
                tokio::time::timeout(Duration::from_secs(1), udp_streams[0].recv()).await??;
            ensure!(response.udp()?.1 == bytes, "연속 UDP 왕복 유실");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        ensure!(
            f.state.metrics.udp_dropped.load(Ordering::Relaxed) == 0,
            "정상 예산 내 UDP 폐기 금지"
        );
        ensure!(
            f.state.metrics.active_tcp.load(Ordering::Relaxed) == 192,
            "동시 TCP 192개 유지"
        );
        ensure!(
            f.state.metrics.active_udp.load(Ordering::Relaxed) == 192,
            "동시 UDP 192개 유지"
        );
        p.close().await?;
        drop(tcp_streams);
        drop(udp_streams);
        drop(p);
        f.clean().await?;
        tcp.abort();
        udp.abort();
        f.stop().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn udp_전송윈도_반환대기는_즉시폐기하지_않고_양방향을_유지() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let f = Fixture::with_tuning(5, 64, 64, 10000).await?;
        let p = f.peer().await?;
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let target = socket.local_addr()?;
        let echo = tokio::spawn(async move {
            let mut b = [0; 2048];
            while let Ok((n, a)) = socket.recv_from(&mut b).await {
                socket.send_to(&b[..n], a).await.unwrap();
            }
        });
        let mut stream = p.open(Destination::socket(target), true).await?;
        for n in 0..100u32 {
            let mut bytes = vec![33; 1500];
            bytes[..4].copy_from_slice(&n.to_be_bytes());
            stream.send(&bytes).await?;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        for n in 0..100u32 {
            let response = tokio::time::timeout(Duration::from_secs(2), stream.recv()).await??;
            let (_, bytes) = response.udp()?;
            ensure!(
                bytes.len() == 1500 && bytes[..4] == n.to_be_bytes(),
                "지연 수신에서도 순서·경계·내용 유지"
            );
        }
        ensure!(
            f.state.metrics.udp_dropped.load(Ordering::Relaxed) == 0,
            "클라이언트 윈도 반환 전 즉시 폐기 금지"
        );
        drop(stream);
        p.close().await?;
        drop(p);
        f.clean().await?;
        echo.abort();
        f.stop().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
