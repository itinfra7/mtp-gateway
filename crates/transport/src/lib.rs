//! Fake-TLS와 연속 Obfuscated2/청크 스트림. 실제 보안은 이 스트림 위의 TLS1.3이다.
use anyhow::{Context, Result, anyhow, ensure};
use bytes::{Buf, Bytes, BytesMut};
use ctr::cipher::{KeyIvInit, StreamCipher};
use ring::{
    agreement, digest, hmac,
    rand::{SecureRandom, SystemRandom},
};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use std::{
    collections::{HashMap, HashSet},
    io::{self, BufReader},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::TcpStream,
};

type AesCtr = ctr::Ctr128BE<aes::Aes256>;
pub const ALPN: &[u8] = b"mtp-gateway/1";
const RECORD_MAX: usize = 16_384;
const CHUNK_MAX: usize = 16_407;

#[derive(Clone)]
pub struct Secret {
    pub key: [u8; 16],
    pub domain: String,
}
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([비공개])")
    }
}
impl Secret {
    pub fn parse(value: &str) -> Result<Self> {
        let b = hex::decode(value.trim()).context("잘못된 ee hex")?;
        ensure!(b.len() > 17 && b[0] == 0xee, "ee 비밀 형식");
        let key = b[1..17].try_into().map_err(|_| anyhow!("키 길이"))?;
        let domain = mtp_protocol::domain(std::str::from_utf8(&b[17..]).context("도메인 UTF8")?)?;
        Ok(Self { key, domain })
    }
    pub fn expose_hex(&self) -> String {
        let mut b = vec![0xee];
        b.extend_from_slice(&self.key);
        b.extend_from_slice(self.domain.as_bytes());
        hex::encode(b)
    }
}
pub fn random(b: &mut [u8]) -> Result<()> {
    SystemRandom::new()
        .fill(b)
        .map_err(|_| anyhow!("보안 난수 생성 실패"))
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
fn mac(secret: &[u8], data: &[u8]) -> [u8; 32] {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret), data)
        .as_ref()
        .try_into()
        .expect("SHA256은32바이트")
}
fn sha(data: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, data)
        .as_ref()
        .try_into()
        .expect("SHA256은32바이트")
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "외부 전송 형식이 잘못됐습니다")
}

pub struct ReplayCache {
    entries: Mutex<HashMap<[u8; 32], Instant>>,
    capacity: usize,
    ttl: Duration,
}
impl ReplayCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity,
            ttl,
        }
    }
    pub fn check_insert(&self, key: [u8; 32]) -> Result<()> {
        let mut e = self
            .entries
            .lock()
            .map_err(|_| anyhow!("재전송 캐시 잠금 실패"))?;
        let now = Instant::now();
        e.retain(|_, t| now.duration_since(*t) < self.ttl);
        ensure!(!e.contains_key(&key), "재전송된 ClientHello");
        ensure!(e.len() < self.capacity, "재전송 캐시 한도");
        e.insert(key, now);
        Ok(())
    }
}
fn u16at(b: &[u8], n: usize) -> Result<usize> {
    let p = b.get(n..n + 2).context("잘린 16비트 필드")?;
    Ok(u16::from_be_bytes([p[0], p[1]]) as usize)
}
fn hello_fields(packet: &[u8]) -> Result<([u8; 32], Vec<u8>, String)> {
    ensure!(
        packet.len() >= 76 && packet.len() <= 4096,
        "ClientHello 크기"
    );
    ensure!(
        packet[0] == 22 && packet[1] == 3 && [1, 3].contains(&packet[2]),
        "ClientHello 레코드"
    );
    ensure!(
        u16at(packet, 3)? + 5 == packet.len(),
        "ClientHello 레코드 길이"
    );
    ensure!(packet[5] == 1, "ClientHello 유형");
    let hl = ((packet[6] as usize) << 16) | ((packet[7] as usize) << 8) | packet[8] as usize;
    ensure!(
        hl + 9 == packet.len() && packet[9..11] == [3, 3],
        "ClientHello handshake 길이/버전"
    );
    let random = packet[11..43]
        .try_into()
        .map_err(|_| anyhow!("ClientHello random"))?;
    let sl = packet[43] as usize;
    ensure!(sl == 32, "ClientHello session ID");
    let sid = packet.get(44..44 + sl).context("잘린 session ID")?.to_vec();
    let mut at = 44 + sl;
    let cl = u16at(packet, at)?;
    at += 2;
    ensure!(cl >= 2 && cl.is_multiple_of(2), "cipher vector 길이");
    let cs = packet.get(at..at + cl).context("잘린 cipher vector")?;
    ensure!(
        cs.as_chunks::<2>().0.contains(&[0x13, 1]),
        "TLS1.3 cipher 누락"
    );
    at += cl;
    ensure!(packet.get(at..at + 2) == Some(&[1, 0][..]), "압축 방식");
    at += 2;
    let el = u16at(packet, at)?;
    at += 2;
    ensure!(at + el == packet.len(), "extension 전체 길이");
    let mut seen = HashSet::new();
    let mut sni = None;
    let mut tls13 = false;
    while at < packet.len() {
        let ty = u16at(packet, at)?;
        let n = u16at(packet, at + 2)?;
        at += 4;
        let data = packet.get(at..at + n).context("잘린 extension")?;
        at += n;
        ensure!(seen.insert(ty), "중복 extension");
        match ty {
            0 => {
                ensure!(
                    data.len() >= 5 && u16at(data, 0)? + 2 == data.len() && data[2] == 0,
                    "SNI 목록"
                );
                let n = u16at(data, 3)?;
                ensure!(n + 5 == data.len(), "SNI 이름 길이");
                let name = std::str::from_utf8(&data[5..]).context("SNI UTF8")?;
                ensure!(name.is_ascii(), "SNI는 A-label이어야 합니다");
                sni = Some(mtp_protocol::domain(name)?);
            }
            10 | 13 => {
                ensure!(
                    data.len() >= 4
                        && u16at(data, 0)? + 2 == data.len()
                        && (data.len() - 2).is_multiple_of(2),
                    "확장 vector 길이"
                );
            }
            51 => {
                ensure!(
                    data.len() >= 6 && u16at(data, 0)? + 2 == data.len(),
                    "클라이언트 key_share vector"
                );
                let mut k = 2;
                while k < data.len() {
                    let n = u16at(data, k + 2)?;
                    k += 4;
                    ensure!(n > 0 && k + n <= data.len(), "클라이언트 key_share 길이");
                    k += n;
                }
            }
            43 => {
                ensure!(
                    !data.is_empty()
                        && data[0] as usize + 1 == data.len()
                        && (data.len() - 1).is_multiple_of(2),
                    "supported_versions 길이"
                );
                tls13 = data[1..].as_chunks::<2>().0.contains(&[3, 4]);
            }
            _ => {}
        }
    }
    ensure!(tls13, "TLS1.3 지원 누락");
    Ok((random, sid, sni.context("SNI 누락")?))
}
/// 서버의 외부 응답 세 레코드와 인증값을 검증한다.
pub fn authenticate_server(
    response: &[u8],
    secret: &Secret,
    client_random: &[u8; 32],
    session: &[u8],
) -> Result<()> {
    ensure!(
        response.len() <= 20491 && session.len() == 32,
        "서버 응답 상한"
    );
    let first = u16at(response, 3)?
        .checked_add(5)
        .context("서버 레코드 길이")?;
    let hello = response.get(..first).context("잘린 ServerHello")?;
    ensure!(
        hello.len() >= 81 && hello[..3] == [22, 3, 3] && hello[5] == 2,
        "ServerHello 형식"
    );
    let n = ((hello[6] as usize) << 16) | ((hello[7] as usize) << 8) | hello[8] as usize;
    ensure!(
        n + 9 == hello.len()
            && hello[9..11] == [3, 3]
            && hello[43] == 32
            && &hello[44..76] == session,
        "ServerHello 길이·버전·세션"
    );
    ensure!(
        hello[76..79] == [0x13, 1, 0] && u16at(hello, 79)? + 81 == hello.len(),
        "ServerHello cipher·extension 길이"
    );
    let (mut at, mut version, mut share) = (81, false, false);
    let mut seen = HashSet::new();
    while at < hello.len() {
        let ty = u16at(hello, at)?;
        let n = u16at(hello, at + 2)?;
        at += 4;
        let b = hello.get(at..at + n).context("잘린 서버 extension")?;
        at += n;
        ensure!(seen.insert(ty), "중복 서버 extension");
        match ty {
            43 => {
                ensure!(b == [3, 4], "서버 TLS1.3 version");
                version = true;
            }
            51 => {
                ensure!(
                    b.len() == 36 && b[..4] == [0, 29, 0, 32],
                    "서버 X25519 key_share"
                );
                share = true;
            }
            _ => {}
        }
    }
    ensure!(version && share, "서버 TLS1.3 필수 extension");
    ensure!(
        response.get(first..first + 6) == Some(&[20, 3, 3, 0, 1, 1][..]),
        "서버 CCS"
    );
    let at = first + 6;
    let h = response
        .get(at..at + 5)
        .context("서버 ApplicationData 헤더")?;
    let n = u16::from_be_bytes([h[3], h[4]]) as usize;
    ensure!(
        h[..3] == [23, 3, 3] && (1..=16384).contains(&n) && at + 5 + n == response.len(),
        "서버 ApplicationData 길이·형식"
    );
    let expected = &response[11..43];
    let mut zero = response.to_vec();
    zero[11..43].fill(0);
    let mut signed = client_random.to_vec();
    signed.extend_from_slice(&zero);
    ensure!(
        bool::from(mac(&secret.key, &signed).ct_eq(expected)),
        "ServerHello HMAC 불일치"
    );
    Ok(())
}
pub fn authenticate_hello(
    packet: &[u8],
    secret: &Secret,
    clock: u64,
    skew: u64,
) -> Result<([u8; 32], Vec<u8>)> {
    let (random, sid, sni) = hello_fields(packet)?;
    ensure!(sni == secret.domain, "외부 SNI 불일치");
    let mut zero = packet.to_vec();
    zero[11..43].fill(0);
    let check = mac(&secret.key, &zero);
    ensure!(
        bool::from(check[..28].ct_eq(&random[..28])),
        "ClientHello HMAC 불일치"
    );
    let a = u32::from_le_bytes(random[28..].try_into()?);
    let b = u32::from_le_bytes(check[28..].try_into()?);
    let stamp = (a ^ b) as u64;
    ensure!(clock.abs_diff(stamp) <= skew, "ClientHello 시각 범위 초과");
    Ok((random, sid))
}
pub fn client_hello(secret: &Secret, stamp: u64) -> Result<Vec<u8>> {
    let mut sid = [0; 32];
    random(&mut sid)?;
    let mut key = [0; 32];
    random(&mut key)?;
    let mut ext = Vec::new();
    let name = secret.domain.as_bytes();
    let mut sni = Vec::new();
    sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name);
    for (kind, b) in [
        (0u16, sni),
        (43, vec![2, 3, 4]),
        (10, vec![0, 2, 0, 29]),
        (13, vec![0, 4, 4, 3, 8, 4]),
        (51, {
            let mut b = vec![0, 36, 0, 29, 0, 32];
            b.extend_from_slice(&key);
            b
        }),
    ] {
        ext.extend_from_slice(&kind.to_be_bytes());
        ext.extend_from_slice(&(b.len() as u16).to_be_bytes());
        ext.extend_from_slice(&b);
    }
    let pad = 240usize.saturating_sub(ext.len());
    ext.extend_from_slice(&21u16.to_be_bytes());
    ext.extend_from_slice(&(pad as u16).to_be_bytes());
    ext.resize(ext.len() + pad, 0);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.push(32);
    body.extend_from_slice(&sid);
    body.extend_from_slice(&[0, 2, 0x13, 1, 1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut packet = vec![22, 3, 1];
    packet.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    packet.push(1);
    let n = body.len() as u32;
    packet.extend_from_slice(&n.to_be_bytes()[1..]);
    packet.extend_from_slice(&body);
    let mut h = mac(&secret.key, &packet);
    let t = (stamp as u32).to_le_bytes();
    for i in 0..4 {
        h[28 + i] ^= t[i];
    }
    packet[11..43].copy_from_slice(&h);
    Ok(packet)
}
fn server_hello(secret: &Secret, client_random: &[u8; 32], sid: &[u8]) -> Result<Vec<u8>> {
    let pk = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new())
        .map_err(|_| anyhow!("외부 key_share 난수 실패"))?
        .compute_public_key()
        .map_err(|_| anyhow!("외부 key_share 생성 실패"))?;
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.push(sid.len() as u8);
    body.extend_from_slice(sid);
    body.extend_from_slice(&[
        0x13, 1, 0, 0, 46, 0, 43, 0, 2, 3, 4, 0, 51, 0, 36, 0, 29, 0, 32,
    ]);
    body.extend_from_slice(pk.as_ref());
    let mut result = vec![22, 3, 3];
    result.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    result.push(2);
    result.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    result.extend_from_slice(&body);
    result.extend_from_slice(&[20, 3, 3, 0, 1, 1, 23, 3, 3, 4, 0]);
    let start = result.len();
    result.resize(start + 1024, 0);
    random(&mut result[start..])?;
    let mut signed = client_random.to_vec();
    signed.extend_from_slice(&result);
    let h = mac(&secret.key, &signed);
    result[11..43].copy_from_slice(&h);
    Ok(result)
}
async fn record<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> io::Result<Option<(u8, [u8; 2], Vec<u8>)>> {
    let mut h = [0; 5];
    if r.read(&mut h[..1]).await? == 0 {
        return Ok(None);
    }
    r.read_exact(&mut h[1..]).await?;
    let n = u16::from_be_bytes([h[3], h[4]]) as usize;
    if n == 0 || n > max {
        return Err(invalid());
    }
    let mut b = vec![0; n];
    r.read_exact(&mut b).await?;
    Ok(Some((h[0], [h[1], h[2]], b)))
}
fn packet(t: u8, v: [u8; 2], b: &[u8]) -> Vec<u8> {
    let mut r = vec![t, v[0], v[1]];
    r.extend_from_slice(&(b.len() as u16).to_be_bytes());
    r.extend_from_slice(b);
    r
}
fn good_init(b: &[u8; 64]) -> bool {
    b[0] != 0xef
        && b[4..8] != [0, 0, 0, 0]
        && ![
            [0xdd; 4],
            [0xee; 4],
            *b"POST",
            *b"GET ",
            *b"HEAD",
            *b"OPTI",
            [0x16, 3, 1, 2],
        ]
        .contains(&b[..4].try_into().expect("고정길이"))
}
fn keys(header: &[u8; 64], secret: &[u8; 16]) -> (AesCtr, AesCtr) {
    let mut both = header[8..40].to_vec();
    both.extend_from_slice(secret);
    let a = sha(&both);
    let mut rev = *header;
    rev.reverse();
    let mut both = rev[8..40].to_vec();
    both.extend_from_slice(secret);
    let b = sha(&both);
    (
        AesCtr::new_from_slices(&a, &header[40..56]).expect("고정 key/IV 길이"),
        AesCtr::new_from_slices(&b, &rev[40..56]).expect("고정 key/IV 길이"),
    )
}
pub fn client_obfuscation(secret: &[u8; 16]) -> Result<([u8; 64], CipherPair)> {
    let mut h = [0; 64];
    loop {
        random(&mut h)?;
        if good_init(&h) {
            break;
        }
    }
    h[56..60].fill(0xdd);
    h[60..62].fill(0);
    let (mut tx, rx) = keys(&h, secret);
    let mut encrypted = h;
    tx.apply_keystream(&mut encrypted);
    h[56..64].copy_from_slice(&encrypted[56..64]);
    Ok((h, CipherPair { rx, tx }))
}
pub fn server_obfuscation(h: [u8; 64], secret: &[u8; 16]) -> Result<CipherPair> {
    ensure!(good_init(&h), "잘못된 Obfuscated2 초기값");
    let (mut rx, tx) = keys(&h, secret);
    let mut decoded = h;
    rx.apply_keystream(&mut decoded);
    ensure!(
        decoded[56..60] == [0xdd; 4] && decoded[60..62] == [0, 0],
        "확장 marker 또는 DC 불일치"
    );
    Ok(CipherPair { rx, tx })
}
pub struct CipherPair {
    rx: AesCtr,
    tx: AesCtr,
}
pub fn chunk(data: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !data.is_empty() && data.len() <= RECORD_MAX,
        "청크 content 길이"
    );
    let mut one = [0];
    random(&mut one)?;
    let pad = 4 + (one[0] as usize % 12);
    let mut b = ((4 + data.len() + pad) as u32).to_le_bytes().to_vec();
    b.extend_from_slice(&(data.len() as u32).to_be_bytes());
    b.extend_from_slice(data);
    let at = b.len();
    b.resize(at + pad, 0);
    random(&mut b[at..])?;
    Ok(b)
}
#[derive(Default)]
pub struct ChunkDecoder {
    buf: BytesMut,
}
impl ChunkDecoder {
    pub fn push(&mut self, b: &[u8]) -> Result<()> {
        ensure!(
            self.buf.len().saturating_add(b.len()) <= CHUNK_MAX * 2,
            "청크 버퍼 한도"
        );
        self.buf.extend_from_slice(b);
        Ok(())
    }
    pub fn next_content(&mut self) -> Result<Option<Bytes>> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let n = u32::from_le_bytes(self.buf[..4].try_into()?) as usize;
        ensure!((9..=CHUNK_MAX - 4).contains(&n), "wire_len 범위");
        if self.buf.len() < 8 {
            return Ok(None);
        }
        let content = u32::from_be_bytes(self.buf[4..8].try_into()?) as usize;
        ensure!((1..=RECORD_MAX).contains(&content), "content_len 범위");
        let pad = n.checked_sub(4 + content).context("청크 길이 산술")?;
        ensure!((4..=15).contains(&pad), "패딩 범위");
        if self.buf.len() < n + 4 {
            return Ok(None);
        }
        let mut full = self.buf.split_to(n + 4);
        full.advance(8);
        Ok(Some(full.freeze().slice(..content)))
    }
    pub fn finish(&self) -> Result<()> {
        ensure!(self.buf.is_empty(), "잘린 청크");
        Ok(())
    }
}
async fn read_application<R: AsyncRead + Unpin>(
    r: &mut R,
    ccs: &mut bool,
) -> io::Result<Option<Vec<u8>>> {
    loop {
        let Some((t, v, b)) = record(r, RECORD_MAX).await? else {
            return Ok(None);
        };
        if v != [3, 3] {
            return Err(invalid());
        }
        if t == 20 && *ccs && b == [1] {
            *ccs = false;
            continue;
        }
        if t != 23 {
            return Err(invalid());
        }
        *ccs = false;
        return Ok(Some(b));
    }
}
fn bridge(stream: TcpStream, mut c: CipherPair, server: bool, initial: Vec<u8>) -> DuplexStream {
    let (inner, outer) = tokio::io::duplex(32768);
    tokio::spawn(async move {
        let (mut net_read, mut net_write) = stream.into_split();
        let (mut feed, mut take) = tokio::io::split(outer);
        let read = async {
            let mut decoder = ChunkDecoder::default();
            if !initial.is_empty() {
                decoder.push(&initial)?;
            }
            let mut ccs = server;
            loop {
                while let Some(content) = decoder.next_content()? {
                    take.write_all(&content).await?;
                }
                let Some(mut b) = read_application(&mut net_read, &mut ccs).await? else {
                    decoder.finish()?;
                    break;
                };
                c.rx.apply_keystream(&mut b);
                decoder.push(&b)?;
            }
            Ok::<(), anyhow::Error>(())
        };
        let write = async {
            let mut b = vec![0; RECORD_MAX];
            loop {
                let n = feed.read(&mut b).await?;
                if n == 0 {
                    break;
                }
                let mut encoded = chunk(&b[..n])?;
                c.tx.apply_keystream(&mut encoded);
                for part in encoded.chunks(RECORD_MAX) {
                    net_write.write_all(&packet(23, [3, 3], part)).await?;
                }
            }
            net_write.shutdown().await?;
            Ok::<(), anyhow::Error>(())
        };
        let outcome = tokio::select! {r=read=>r,r=write=>r};
        if outcome.is_err() {
            tracing::debug!(reason = "외부 레코드/청크 종료", "터널 전송 종료");
        }
    });
    inner
}
pub async fn accept(
    mut stream: TcpStream,
    secret: &Secret,
    replay: &ReplayCache,
) -> Result<DuplexStream> {
    stream.set_nodelay(true)?;
    let (t, v, b) = record(&mut stream, 4091)
        .await?
        .context("ClientHello EOF")?;
    ensure!(t == 22, "ClientHello 필요");
    let raw = packet(t, v, &b);
    let (cr, sid) = authenticate_hello(&raw, secret, now(), 300)?;
    replay.check_insert(cr)?;
    stream.write_all(&server_hello(secret, &cr, &sid)?).await?;
    let mut ccs = true;
    let mut h = Vec::new();
    while h.len() < 64 {
        let b = read_application(&mut stream, &mut ccs)
            .await?
            .context("Obfuscated2 EOF")?;
        h.extend_from_slice(&b);
        ensure!(h.len() <= 64 + RECORD_MAX, "초기 레코드 한도");
    }
    let header = h[..64].try_into()?;
    let mut c = server_obfuscation(header, &secret.key)?;
    let mut initial = h[64..].to_vec();
    c.rx.apply_keystream(&mut initial);
    Ok(bridge(stream, c, false, initial))
}
pub async fn connect(mut stream: TcpStream, secret: &Secret) -> Result<DuplexStream> {
    stream.set_nodelay(true)?;
    let hello = client_hello(secret, now())?;
    let cr: [u8; 32] = hello[11..43].try_into()?;
    let sid = &hello[44..76];
    stream.write_all(&hello).await?;
    let (t, v, b) = record(&mut stream, 4096)
        .await?
        .context("ServerHello EOF")?;
    ensure!(
        t == 22 && v == [3, 3] && b.len() >= 71,
        "ServerHello 레코드"
    );
    let mut whole = packet(t, v, &b);
    ensure!(
        whole[5] == 2
            && whole[9..11] == [3, 3]
            && whole[43] == 32
            && whole.get(44..76) == Some(sid),
        "ServerHello session ID"
    );
    let (t, v, b) = record(&mut stream, 1).await?.context("서버 CCS EOF")?;
    ensure!(t == 20 && v == [3, 3] && b == [1], "서버 CCS");
    whole.extend_from_slice(&packet(t, v, &b));
    let (t, v, b) = record(&mut stream, RECORD_MAX)
        .await?
        .context("서버 data EOF")?;
    ensure!(t == 23 && v == [3, 3], "서버 data 레코드");
    whole.extend_from_slice(&packet(t, v, &b));
    authenticate_server(&whole, secret, &cr, sid)?;
    let (h, c) = client_obfuscation(&secret.key)?;
    stream.write_all(&[20, 3, 3, 0, 1, 1]).await?;
    stream.write_all(&packet(23, [3, 3], &h)).await?;
    Ok(bridge(stream, c, false, Vec::new()))
}
pub fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut f = BufReader::new(std::fs::File::open(path)?);
    let c = rustls_pemfile::certs(&mut f).collect::<io::Result<Vec<_>>>()?;
    ensure!(!c.is_empty(), "인증서가 없습니다");
    Ok(c)
}
pub fn private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open(path)?))?
        .context("개인키가 없습니다")
}
pub fn roots(path: &Path) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for c in certificates(path)? {
        roots.add(c)?;
    }
    Ok(roots)
}
pub fn server_tls(cert: &Path, key: &Path, ca: &Path) -> Result<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verify = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots(ca)?),
        provider.clone(),
    )
    .build()?;
    let mut c = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verify)
        .with_single_cert(certificates(cert)?, private_key(key)?)?;
    c.max_early_data_size = 0;
    c.alpn_protocols = vec![ALPN.to_vec()];
    Ok(c)
}
pub fn client_tls(cert: &Path, key: &Path, ca: &Path) -> Result<ClientConfig> {
    let mut c =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots(ca)?)
            .with_client_auth_cert(certificates(cert)?, private_key(key)?)?;
    c.enable_early_data = false;
    c.alpn_protocols = vec![ALPN.to_vec()];
    Ok(c)
}
pub fn fingerprint(cert: &[u8]) -> String {
    hex::encode(sha(cert))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn secret() -> Secret {
        Secret {
            key: [7; 16],
            domain: "example.test".into(),
        }
    }
    #[test]
    fn 핸드셰이크_정상_인증오류_시각_재전송() {
        let s = secret();
        let mut h = client_hello(&s, 123456).unwrap();
        let (r, _) = authenticate_hello(&h, &s, 123456, 300).unwrap();
        assert!(authenticate_hello(&h, &s, 124000, 300).is_err());
        h[20] ^= 1;
        assert!(authenticate_hello(&h, &s, 123456, 300).is_err());
        let cache = ReplayCache::new(1, Duration::from_secs(610));
        cache.check_insert(r).unwrap();
        assert!(cache.check_insert(r).is_err());
        assert!(cache.check_insert([1; 32]).is_err());
    }
    #[test]
    fn 모든_잘린_hello() {
        let h = client_hello(&secret(), 123456).unwrap();
        for n in 0..h.len() {
            assert!(authenticate_hello(&h[..n], &secret(), 123456, 300).is_err());
        }
    }
    #[test]
    fn nist_aes256_ctr_정답과_연속진행() {
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .unwrap();
        let iv = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
        let mut data =
            hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
                .unwrap();
        let mut c = AesCtr::new_from_slices(&key, &iv).unwrap();
        c.apply_keystream(&mut data[..7]);
        c.apply_keystream(&mut data[7..]);
        assert_eq!(
            hex::encode(data),
            "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
        );
    }
    #[test]
    fn 방향과_64바이트_진행() {
        let (h, mut a) = client_obfuscation(&secret().key).unwrap();
        let mut b = server_obfuscation(h, &secret().key).unwrap();
        for size in [1, 20, 655] {
            let mut m = vec![3; size];
            a.tx.apply_keystream(&mut m);
            b.rx.apply_keystream(&mut m);
            assert_eq!(m, vec![3; size]);
            let mut r = vec![4; size];
            b.tx.apply_keystream(&mut r);
            a.rx.apply_keystream(&mut r);
            assert_eq!(r, vec![4; size]);
        }
    }
    #[test]
    fn 청크_분할과_길이검증() {
        let a = chunk(b"abcdef").unwrap();
        for n in 0..=a.len() {
            let mut d = ChunkDecoder::default();
            d.push(&a[..n]).unwrap();
            let first = d.next_content().unwrap();
            d.push(&a[n..]).unwrap();
            assert_eq!(
                first.or_else(|| d.next_content().unwrap()).unwrap(),
                b"abcdef"[..]
            );
            d.finish().unwrap();
        }
        for n in [0u32, 8, 16404, u32::MAX] {
            let mut d = ChunkDecoder::default();
            d.push(&n.to_le_bytes()).unwrap();
            assert!(d.next_content().is_err());
        }
    }
}

#[cfg(test)]
mod network_tests {
    use super::*;
    #[tokio::test]
    async fn 실제_tcp_외부터널_양방향() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let secret = Secret {
            key: [9; 16],
            domain: "gateway.example".into(),
        };
        let server_secret = secret.clone();
        let task = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let replay = ReplayCache::new(10, Duration::from_secs(610));
            let mut io = accept(s, &server_secret, &replay).await.unwrap();
            let mut data = vec![0; 100_000];
            io.read_exact(&mut data).await.unwrap();
            assert!(data.iter().all(|v| *v == 73));
            io.write_all(&data).await.unwrap();
        });
        let mut io = connect(TcpStream::connect(addr).await.unwrap(), &secret)
            .await
            .unwrap();
        let data = vec![73; 100_000];
        io.write_all(&data).await.unwrap();
        let mut got = vec![0; 100_000];
        io.read_exact(&mut got).await.unwrap();
        assert_eq!(data, got);
        task.await.unwrap();
    }
}

#[cfg(test)]
mod independent_vectors {
    use super::*;
    #[test]
    fn 독립_python_openssl_공식배치_벡터() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/independent.json")).unwrap();
        let b = |key: &str| hex::decode(v[key].as_str().unwrap()).unwrap();
        let secret = Secret {
            key: b("secret").try_into().unwrap(),
            domain: "www.example.com".into(),
        };
        authenticate_hello(
            &b("client_hello"),
            &secret,
            v["timestamp"].as_u64().unwrap(),
            0,
        )
        .unwrap();
        let hello = b("client_hello");
        authenticate_server(
            &b("server_hello"),
            &secret,
            &hello[11..43].try_into().unwrap(),
            &hello[44..76],
        )
        .unwrap();
        let mut cipher =
            server_obfuscation(b("obfuscated_wire").try_into().unwrap(), &secret.key).unwrap();
        let mut encrypted = b("client_after_header");
        cipher.rx.apply_keystream(&mut encrypted);
        assert_eq!(encrypted, b("chunk"));
        let mut encrypted = b("chunk");
        cipher.tx.apply_keystream(&mut encrypted);
        assert_eq!(encrypted, b("server_from_zero"));
        let mut d = ChunkDecoder::default();
        d.push(&b("chunk")).unwrap();
        assert_eq!(d.next_content().unwrap().unwrap().as_ref(), b("content"));
    }
}

#[cfg(test)]
mod server_validation {
    use super::*;
    #[test]
    fn 서버_인증_길이_시각과_잘림() {
        let s = Secret {
            key: [12; 16],
            domain: "www.example.com".into(),
        };
        let cr = [23; 32];
        let sid = [32; 32];
        let response = server_hello(&s, &cr, &sid).unwrap();
        authenticate_server(&response, &s, &cr, &sid).unwrap();
        for i in 0..response.len() {
            assert!(authenticate_server(&response[..i], &s, &cr, &sid).is_err());
        }
        let mut bad = response.clone();
        bad[11] ^= 1;
        assert!(authenticate_server(&bad, &s, &cr, &sid).is_err());
        assert!(authenticate_server(&response, &s, &[0; 32], &sid).is_err());
        let mut trailing = response.clone();
        trailing.push(0);
        assert!(authenticate_server(&trailing, &s, &cr, &sid).is_err());
    }
}
