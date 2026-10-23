//! 비밀값을 표준 출력에 노출하지 않는 운영 CLI.
use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use mtp_gateway::pki;
use std::{net::SocketAddr, path::PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[derive(Parser)]
#[command(
    name = "mtp-gateway",
    version,
    author,
    about = "인증된 TCP·UDP·DNS 전용 터널"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    #[command(about = "사용자별 권한·용량 정책 관리")]
    User {
        #[command(subcommand)]
        command: User,
    },
    #[command(about = "전체 터널 인증 허용·차단")]
    Access {
        #[arg(long)]
        root: PathBuf,
        #[arg(long, action=clap::ArgAction::Set)]
        enabled: bool,
    },
    #[command(about = "분리된 CA·서버 설정 초기 생성")]
    Init {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        host: String,
        #[arg(long, default_value_t = 8443)]
        port: u16,
        #[arg(long)]
        outer_sni: String,
        #[arg(long)]
        server_name: String,
        #[arg(long, value_delimiter = ',', default_value = "0.0.0.0:8443,[::]:8443")]
        listen: Vec<SocketAddr>,
        #[arg(long)]
        dns_server: SocketAddr,
    },
    #[command(about = "설정·인증서·권한 검증")]
    ValidateConfig {
        #[arg(long)]
        config: PathBuf,
    },
    #[command(about = "터널 서버 실행")]
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    #[command(about = "사용자별 인증서 관리")]
    Client {
        #[command(subcommand)]
        command: Client,
    },
    #[command(about = "실행 상태·DNS 응답 검증")]
    Doctor {
        #[arg(long)]
        config: PathBuf,
    },
}
#[derive(Subcommand)]
enum Client {
    #[command(about = "장치 상태 목록; 개인키는 표시하지 않음")]
    List {
        #[arg(long)]
        root: PathBuf,
    },
    #[command(about = "장치 인증서 발급")]
    Issue {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        owner: String,
        #[arg(long, default_value_t = 365)]
        days: i64,
    },
    #[command(about = "장치 인증서 폐기 및 활성 연결 회수")]
    Revoke {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        id: String,
    },
    #[command(about = "Windows 앱 루트용 인증 파일 내보내기")]
    Export {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        out: PathBuf,
    },
}
#[derive(Subcommand)]
enum User {
    #[command(about = "사용자 정책 JSON 표시")]
    Show {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        owner: String,
    },
    #[command(about = "검증한 JSON 정책 적용; 해당 사용자의 현재 터널은 재접속")]
    Set {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        policy: PathBuf,
    },
}
fn registry(root: &std::path::Path) -> Result<mtp_relay::config::Registry> {
    let config = mtp_relay::config::Config::load(&root.join("gateway.toml"))?;
    mtp_relay::config::Registry::load(&config.registry_file)
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    match Cli::parse().command {
        Command::User { command } => match command {
            User::Show { root, owner } => {
                let r = registry(&root)?;
                let policy = r
                    .users
                    .get(&owner)
                    .ok_or_else(|| anyhow::anyhow!("등록된 소유자가 아닙니다"))?;
                println!("{}", serde_json::to_string_pretty(policy)?);
            }
            User::Set {
                root,
                owner,
                policy,
            } => {
                let bytes = mtp_relay::config::read_limited(&policy, 131072)?;
                let policy = serde_json::from_slice(&bytes)?;
                pki::user_policy(&root, &owner, policy)?;
                println!("사용자 정책 적용 완료");
            }
        },
        Command::Access { root, enabled } => {
            pki::set_enabled(&root, enabled)?;
            println!("전체 인증 허용 상태: {enabled}");
        }
        Command::Init {
            root,
            host,
            port,
            outer_sni,
            server_name,
            listen,
            dns_server,
        } => {
            pki::init(
                &root,
                pki::Endpoint {
                    host,
                    port,
                    outer_sni,
                    server_name,
                },
                listen,
                dns_server,
            )?;
            println!("초기 생성 완료: {}", root.display());
        }
        Command::ValidateConfig { config } => {
            pki::validate(&config)?;
            println!("설정·인증서·권한 검증 성공");
        }
        Command::Serve { config } => {
            mtp_relay::server::serve(pki::validate(&config)?, None).await?
        }
        Command::Client { command } => match command {
            Client::List { root } => {
                let r = registry(&root)?;
                let devices = r.certificates.values().collect::<Vec<_>>();
                println!("{}", serde_json::to_string_pretty(&devices)?);
            }
            Client::Issue {
                root,
                id,
                owner,
                days,
            } => {
                let d = pki::issue(&root, &id, &owner, days)?;
                println!("장치 {} 발급 완료 · 만료 {}", d.id, d.not_after);
            }
            Client::Revoke { root, id } => {
                pki::revoke(&root, &id)?;
                println!("장치 폐기 완료");
            }
            Client::Export { root, id, out } => {
                let p = pki::export(&root, &id, &out)?;
                println!("내보내기 완료: {}", p.display());
            }
        },
        Command::Doctor { config } => {
            let c = pki::validate(&config)?;
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let mut s = tokio::net::UnixStream::connect(&c.metrics_socket).await?;
                s.write_all(b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .await?;
                let mut b = Vec::new();
                s.take(65536).read_to_end(&mut b).await?;
                let text = std::str::from_utf8(&b)?;
                let (_, body) = text
                    .split_once("\r\n\r\n")
                    .ok_or_else(|| anyhow::anyhow!("상태 응답 형식"))?;
                let status: serde_json::Value = serde_json::from_str(body)?;
                ensure!(status["state"] == "ready", "실행 상태 이상");
                let resolver = mtp_relay::dns::Resolver::new(c.resolver.clone());
                let addresses = resolver
                    .addresses("example.com", 443)
                    .await
                    .map_err(|e| anyhow::anyhow!("DNS 검증 실패: {e:?}"))?;
                ensure!(!addresses.is_empty(), "DNS 주소 없음");
                Ok::<_, anyhow::Error>(status)
            })
            .await??;
            println!("{}", serde_json::to_string_pretty(&result)?);
            println!(
                "설정·mTLS 구성·실행 상태·실 DNS 응답 정상. 중계 경로는 test-peer로 별도 검증하십시오."
            );
        }
    }
    Ok(())
}
