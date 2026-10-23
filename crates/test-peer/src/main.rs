//! Windows에서도 실행 가능한 인증 터널 기능 검증 도구.
use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use hickory_proto::{
    op::Query,
    op::{Message, MessageType, OpCode},
    rr::{Name, RecordType},
};
use mtp_protocol::{Destination, Kind};
use mtp_test_peer::Peer;
use std::{
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};
#[derive(Parser)]
#[command(about = "실제 Fake-TLS·mTLS 터널 검증")]
struct Cli {
    #[arg(long)]
    root: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    #[command(about = "실제 공인 HTTP·UDP DNS·서버 DNS 경로 검증")]
    Probe {
        #[arg(long)]
        http_host: String,
        #[arg(long)]
        udp_dns: SocketAddr,
    },
    #[command(about = "TCP echo·대용량·half-close 검증")]
    Tcp {
        #[arg(long)]
        destination: String,
        #[arg(long, default_value_t = 1048576)]
        bytes: usize,
    },
    #[command(about = "UDP echo 검증")]
    Udp {
        #[arg(long)]
        destination: String,
        #[arg(long, default_value_t = 1024)]
        bytes: usize,
    },
    #[command(about = "전체 DNS wire 요청·응답 검증")]
    Dns {
        #[arg(long)]
        name: String,
    },
}
fn destination(s: &str) -> Result<Destination> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        Ok(Destination::socket(a))
    } else {
        let (name, port) = s
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("도메인:포트 필요"))?;
        Ok(Destination::new(name, port.parse()?)?)
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    let start = Instant::now();
    let peer = Peer::connect(&args.root).await?;
    tokio::time::timeout(Duration::from_secs(120), async {
        match args.command {
            Command::Probe { http_host, udp_dns } => {
                let name = mtp_protocol::domain(&http_host)?;
                let mut stream = peer.open(Destination::new(&name, 80)?, false).await?;
                stream
                    .send(
                        format!("GET / HTTP/1.0\r\nHost: {name}\r\nConnection: close\r\n\r\n")
                            .as_bytes(),
                    )
                    .await?;
                let mut content = Vec::new();
                loop {
                    let f = stream.recv().await?;
                    if f.frame.kind == Kind::TcpFin {
                        break;
                    }
                    ensure!(
                        content.len() + f.frame.payload.len() <= 1024 * 1024,
                        "HTTP 응답 상한"
                    );
                    content.extend_from_slice(&f.frame.payload);
                }
                stream.finish().await?;
                ensure!(content.starts_with(b"HTTP/1."), "실제 HTTP 응답 필요");
                let mut q = Message::new(14921, MessageType::Query, OpCode::Query);
                q.metadata.recursion_desired = true;
                q.add_query(Query::query(
                    Name::from_ascii(format!("{name}."))?,
                    RecordType::A,
                ));
                let wire = q.to_vec()?;
                let mut udp = peer.open(Destination::socket(udp_dns), true).await?;
                udp.send(&wire).await?;
                let received = udp.recv().await?;
                let (_, b) = received.udp()?;
                let response = Message::from_vec(b)?;
                ensure!(
                    response.metadata.id == q.metadata.id
                        && response.metadata.message_type == MessageType::Response
                        && response.queries == q.queries
                        && !response.answers.is_empty(),
                    "실제 UDP DNS 응답 검증"
                );
                let b = peer.dns(&wire).await?;
                ensure!(
                    !Message::from_vec(&b)?.answers.is_empty(),
                    "서버 DNS 응답 필요"
                );
                println!("실제 공인 TCP HTTP·UDP DNS·서버 DNS 양방향 경로 검증 성공");
            }
            Command::Tcp {
                destination: target,
                bytes,
            } => {
                ensure!((1..=64 * 1024 * 1024).contains(&bytes), "전송 길이 한도");
                let mut stream = peer.open(destination(&target)?, false).await?;
                let payload = (0..bytes).map(|i| (i % 251) as u8).collect::<Vec<_>>();
                let send = payload.clone();
                let writer = peer.clone();
                let id = stream.id;
                let task = tokio::spawn(async move {
                    writer.send_tcp(id, &send).await?;
                    writer.finish_tcp(id).await
                });
                let mut received = Vec::new();
                loop {
                    let f = stream.recv().await?;
                    if f.frame.kind == Kind::TcpFin {
                        break;
                    }
                    ensure!(f.frame.kind == Kind::TcpData, "TCP 응답 종류");
                    received.extend_from_slice(&f.frame.payload);
                    ensure!(received.len() <= bytes, "과다 echo");
                }
                task.await??;
                ensure!(payload == received, "TCP 데이터 불일치");
                println!("TCP {}바이트 양방향·half-close 검증 성공", bytes);
            }
            Command::Udp {
                destination: target,
                bytes,
            } => {
                ensure!(bytes <= mtp_protocol::MAX_UDP, "UDP 길이 상한");
                let mut stream = peer.open(destination(&target)?, true).await?;
                let payload = (0..bytes).map(|i| (i % 251) as u8).collect::<Vec<_>>();
                stream.send(&payload).await?;
                let f = stream.recv().await?;
                let (_, data) = f.udp()?;
                ensure!(data == payload, "UDP echo 불일치");
                println!("UDP {}바이트·출발지 검증 성공", bytes);
            }
            Command::Dns { name } => {
                let mut q = Message::new(5721, MessageType::Query, OpCode::Query);
                q.metadata.recursion_desired = true;
                q.add_query(Query::query(
                    Name::from_ascii(format!("{}.", mtp_protocol::domain(&name)?))?,
                    RecordType::A,
                ));
                let r = peer.dns(&q.to_vec()?).await?;
                let answer = Message::from_vec(&r)?;
                println!(
                    "DNS ID·질문·응답 검증 성공 · 응답 {}개",
                    answer.answers.len()
                );
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    peer.close().await?;
    println!("소요 {:.3}초", start.elapsed().as_secs_f64());
    Ok(())
}
