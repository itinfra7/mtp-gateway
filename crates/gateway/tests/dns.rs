//! 실제 DNS wire·TCP fallback·검증된 DoT와 자동 강등 금지를 시험한다.
use anyhow::{Result, ensure};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, SOA},
    },
};
use mtp_relay::{config::ResolverConfig, dns::Resolver};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
fn config(address: SocketAddr) -> ResolverConfig {
    ResolverConfig {
        address,
        mode: "udp".into(),
        server_name: None,
        ca_file: None,
        timeout_seconds: 1,
        cache_entries: 8,
    }
}
fn question(id: u16, name: &str) -> Result<Vec<u8>> {
    let mut m = Message::new(id, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(Name::from_ascii(name)?, RecordType::A));
    Ok(m.to_vec()?)
}
fn answer(wire: &[u8], negative: bool) -> Result<Vec<u8>> {
    let mut m = Message::from_vec(wire)?;
    m.metadata.message_type = MessageType::Response;
    if negative {
        m.metadata.response_code = ResponseCode::NXDomain;
        m.authorities.push(Record::from_rdata(
            Name::from_ascii("example.")?,
            2,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.example.")?,
                Name::from_ascii("hostmaster.example.")?,
                1,
                60,
                60,
                60,
                2,
            )),
        ));
    } else {
        m.add_answer(Record::from_rdata(
            m.queries[0].name().clone(),
            2,
            RData::A(A("1.1.1.1".parse()?)),
        ));
    }
    Ok(m.to_vec()?)
}
#[tokio::test]
async fn 잘린_udp_tcp_fallback_요청id와_부정ttl() -> Result<()> {
    let tcp = TcpListener::bind("127.0.0.1:0").await?;
    let address = tcp.local_addr()?;
    let udp = UdpSocket::bind(address).await?;
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    let u = tokio::spawn(async move {
        let mut b = [0; 4096];
        while let Ok((n, a)) = udp.recv_from(&mut b).await {
            c.fetch_add(1, Ordering::Relaxed);
            let mut q = Message::from_vec(&b[..n]).unwrap();
            if q.queries[0].name().to_ascii().starts_with("nx.") {
                let r = answer(&b[..n], true).unwrap();
                udp.send_to(&r, a).await.unwrap();
                continue;
            }
            q.metadata.message_type = MessageType::Response;
            q.metadata.truncation = true;
            let original = q.metadata.id;
            q.metadata.id ^= 1;
            udp.send_to(&q.to_vec().unwrap(), a).await.unwrap();
            q.metadata.id = original;
            udp.send_to(&q.to_vec().unwrap(), a).await.unwrap();
        }
    });
    let t = tokio::spawn(async move {
        let (mut s, _) = tcp.accept().await?;
        let n = s.read_u16().await? as usize;
        let mut b = vec![0; n];
        s.read_exact(&mut b).await?;
        let r = answer(&b, false).unwrap();
        s.write_all(&(r.len() as u16).to_be_bytes()).await?;
        s.write_all(&r).await?;
        Ok::<_, std::io::Error>(())
    });
    let r = Resolver::new(config(address));
    let response = r
        .raw(&question(123, "tcp.example.")?)
        .await
        .map_err(|c| anyhow::anyhow!("{c:?}"))?;
    ensure!(
        Message::from_vec(&response)?.answers.len() == 1,
        "TCP fallback 실제 응답"
    );
    t.await??;
    let q = question(321, "nx.example.")?;
    r.raw(&q).await.map_err(|c| anyhow::anyhow!("{c:?}"))?;
    let n = count.load(Ordering::Relaxed);
    let response = r
        .raw(&question(322, "nx.example.")?)
        .await
        .map_err(|c| anyhow::anyhow!("{c:?}"))?;
    ensure!(
        count.load(Ordering::Relaxed) == n && Message::from_vec(&response)?.metadata.id == 322,
        "SOA 부정 TTL 캐시와 새 ID 복원"
    );
    tokio::time::sleep(Duration::from_millis(2100)).await;
    r.raw(&q).await.map_err(|c| anyhow::anyhow!("{c:?}"))?;
    ensure!(count.load(Ordering::Relaxed) > n, "부정 TTL 만료");
    u.abort();
    Ok(())
}
#[tokio::test]
async fn dot_인증이름_ca_검증과_평문강등_금지() -> Result<()> {
    let mut random = [0; 8];
    mtp_transport::random(&mut random)?;
    let root = std::env::temp_dir().join(format!("mtp-dot-{}", hex::encode(random)));
    let cfg = mtp_gateway::pki::init(
        &root,
        mtp_gateway::pki::Endpoint {
            host: "127.0.0.1".into(),
            port: 12345,
            outer_sni: "www.example.com".into(),
            server_name: "gateway.example.com".into(),
        },
        vec!["127.0.0.1:12345".parse()?],
        "127.0.0.1:53".parse()?,
    )?;
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(
        mtp_transport::certificates(&cfg.server_cert)?,
        mtp_transport::private_key(&cfg.server_key)?,
    )?;
    let accept = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let udp = UdpSocket::bind(address).await?;
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    let u = tokio::spawn(async move {
        let mut b = [0; 4096];
        while udp.recv_from(&mut b).await.is_ok() {
            c.fetch_add(1, Ordering::Relaxed);
        }
    });
    let t = tokio::spawn(async move {
        let mut jobs = tokio::task::JoinSet::new();
        loop {
            tokio::select! {Some(_)=jobs.join_next()=>{},r=listener.accept()=>{let(s,_)=r.unwrap();let accept=accept.clone();jobs.spawn(async move{let Ok(mut s)=accept.accept(s).await else{return;};let Ok(n)=s.read_u16().await else{return;};let mut b=vec![0;n as usize];if s.read_exact(&mut b).await.is_err(){return;}let r=answer(&b,false).unwrap();let _=s.write_all(&(r.len()as u16).to_be_bytes()).await;let _=s.write_all(&r).await;let _=s.shutdown().await;});}}
        }
    });
    let mut c = config(address);
    c.mode = "tls".into();
    c.ca_file = Some(root.join("pki/server-ca.pem"));
    c.server_name = Some("gateway.example.com".into());
    let q = question(1290, "dot.example.")?;
    ensure!(
        Resolver::new(c.clone()).raw(&q).await.is_ok(),
        "실제 DoT 왕복"
    );
    c.server_name = Some("wrong.example.com".into());
    ensure!(
        Resolver::new(c.clone()).raw(&q).await.is_err(),
        "DoT 인증 이름 거부"
    );
    c.server_name = Some("gateway.example.com".into());
    c.ca_file = Some(root.join("pki/client-ca.pem"));
    ensure!(
        Resolver::new(c).raw(&q).await.is_err(),
        "DoT 잘못된 CA 거부"
    );
    ensure!(
        count.load(Ordering::Relaxed) == 0,
        "실패 후 평문 UDP로 강등 금지"
    );
    t.abort();
    u.abort();
    std::fs::remove_dir_all(root)?;
    Ok(())
}
