//! 전용 다중화 v1의 길이 제한, 주소와 프레임 형식.
pub mod flow;
use bytes::{Buf, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VERSION: u8 = 1;
pub const MAX_FRAME: usize = 262_144;
pub const MAX_TCP: usize = 16_384;
pub const MAX_UDP: usize = 65_507;
pub const CONNECTION_WINDOW: u32 = 524_288;
pub const STREAM_WINDOW: u32 = 131_072;
pub const CREDIT_OVERHEAD: u32 = 64;

#[derive(Debug, thiserror::Error)]
#[error("프로토콜 오류: {0}")]
pub struct ProtocolError(pub &'static str);
fn bad(s: &'static str) -> ProtocolError {
    ProtocolError(s)
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Hello = 1,
    Welcome = 2,
    OpenTcp = 0x10,
    OpenUdp = 0x11,
    OpenOk = 0x12,
    OpenError = 0x13,
    TcpData = 0x20,
    UdpDatagram = 0x21,
    TcpFin = 0x22,
    Reset = 0x23,
    WindowUpdate = 0x24,
    Ping = 0x30,
    Pong = 0x31,
    Goaway = 0x32,
    DnsRequest = 0x40,
    DnsResponse = 0x41,
}
impl TryFrom<u8> for Kind {
    type Error = ProtocolError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Ok(match v {
            1 => Self::Hello,
            2 => Self::Welcome,
            0x10 => Self::OpenTcp,
            0x11 => Self::OpenUdp,
            0x12 => Self::OpenOk,
            0x13 => Self::OpenError,
            0x20 => Self::TcpData,
            0x21 => Self::UdpDatagram,
            0x22 => Self::TcpFin,
            0x23 => Self::Reset,
            0x24 => Self::WindowUpdate,
            0x30 => Self::Ping,
            0x31 => Self::Pong,
            0x32 => Self::Goaway,
            0x40 => Self::DnsRequest,
            0x41 => Self::DnsResponse,
            _ => return Err(bad("정의되지 않은 프레임")),
        })
    }
}
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Code {
    Policy = 1,
    DnsNx = 2,
    DnsNoData = 3,
    DnsServfail = 4,
    DnsTimeout = 5,
    Refused = 6,
    ConnectTimeout = 7,
    Resource = 8,
    Unsupported = 9,
    State = 10,
    Idle = 11,
    Io = 12,
    Revoked = 13,
    Protocol = 14,
    Shutdown = 15,
    DnsMalformed = 16,
    TooLarge = 17,
    Unauthenticated = 18,
}
impl Code {
    pub fn message(self) -> &'static str {
        match self {
            Self::Policy => "목적지 접근이 거부됐습니다",
            Self::DnsNx => "도메인이 없습니다",
            Self::DnsNoData => "사용 가능한 주소가 없습니다",
            Self::DnsServfail => "DNS 서버가 실패했습니다",
            Self::DnsTimeout => "DNS 응답 시간이 초과됐습니다",
            Self::Refused => "목적지가 연결을 거부했습니다",
            Self::ConnectTimeout => "목적지 연결 시간이 초과됐습니다",
            Self::Resource => "자원 한도를 넘었습니다",
            Self::Unsupported => "지원하지 않는 기능입니다",
            Self::State => "스트림 상태가 유효하지 않습니다",
            Self::Idle => "유휴 시간이 만료됐습니다",
            Self::Io => "소켓 통신에 실패했습니다",
            Self::Revoked => "인증서 또는 사용자 권한이 폐기됐습니다",
            Self::Protocol => "프로토콜 형식이 잘못됐습니다",
            Self::Shutdown => "서버가 종료 중입니다",
            Self::DnsMalformed => "DNS 메시지가 잘못됐습니다",
            Self::TooLarge => "허용한 길이를 넘었습니다",
            Self::Unauthenticated => "인증이 필요합니다",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: Kind,
    pub id: u32,
    pub payload: Bytes,
}
impl Frame {
    pub fn new(kind: Kind, id: u32, payload: impl Into<Bytes>) -> Self {
        Self {
            kind,
            id,
            payload: payload.into(),
        }
    }
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let n = self.payload.len();
        if n > MAX_FRAME - 8 {
            return Err(bad("프레임 크기 상한"));
        }
        let control = matches!(
            self.kind,
            Kind::Hello
                | Kind::Welcome
                | Kind::Ping
                | Kind::Pong
                | Kind::Goaway
                | Kind::DnsRequest
                | Kind::DnsResponse
        );
        if control && self.id != 0 || !control && self.id == 0 && self.kind != Kind::WindowUpdate {
            return Err(bad("잘못된 제어 스트림 ID"));
        }
        let valid = match self.kind {
            Kind::Hello => n == 12,
            Kind::Welcome => n == 20,
            Kind::OpenTcp | Kind::OpenUdp => (7..=259).contains(&n),
            Kind::OpenOk => (14..=38).contains(&n),
            Kind::OpenError => (2..=194).contains(&n),
            Kind::TcpData => (1..=MAX_TCP).contains(&n),
            Kind::UdpDatagram => n <= MAX_UDP + 19,
            Kind::TcpFin => n == 0,
            Kind::Reset => n == 2,
            Kind::WindowUpdate => n == 4,
            Kind::Ping | Kind::Pong => n == 8,
            Kind::Goaway => n == 6,
            Kind::DnsRequest => (16..=65_539).contains(&n),
            Kind::DnsResponse => (6..=65_541).contains(&n),
        };
        if !valid {
            return Err(bad("프레임 본문 길이"));
        }
        if matches!(self.kind, Kind::Reset | Kind::OpenError | Kind::Goaway) {
            let code = u16::from_be_bytes([self.payload[0], self.payload[1]]);
            if !(1..=18).contains(&code) {
                return Err(bad("미정의 오류 코드"));
            }
        }
        if self.kind == Kind::OpenOk {
            let (a, n) = Destination::decode(&self.payload)?;
            let (b, k) = Destination::decode(&self.payload[n..])?;
            if n + k != self.payload.len()
                || !matches!(a.address, Address::Ip(_))
                || !matches!(b.address, Address::Ip(_))
            {
                return Err(bad("OPEN_OK는 IP 주소 둘이어야 합니다"));
            }
        }
        if self.kind == Kind::OpenError && std::str::from_utf8(&self.payload[2..]).is_err() {
            return Err(bad("오류 설명 UTF8"));
        }
        if self.kind == Kind::DnsResponse {
            let code = u16::from_be_bytes([self.payload[4], self.payload[5]]);
            if code > 18 {
                return Err(bad("DNS 오류 코드"));
            }
            if code == 0 && n < 18 {
                return Err(bad("DNS 정상 응답 길이"));
            }
            if code != 0 && (n > 198 || std::str::from_utf8(&self.payload[6..]).is_err()) {
                return Err(bad("DNS 오류 설명 길이·UTF8"));
            }
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut b = Vec::with_capacity(self.payload.len() + 12);
        b.extend_from_slice(&((self.payload.len() + 8) as u32).to_be_bytes());
        b.extend_from_slice(&[VERSION, self.kind as u8, 0, 0]);
        b.extend_from_slice(&self.id.to_be_bytes());
        b.extend_from_slice(&self.payload);
        Ok(b)
    }
    pub fn error(kind: Kind, id: u32, code: Code) -> Self {
        let mut p = (code as u16).to_be_bytes().to_vec();
        if kind == Kind::OpenError {
            p.extend_from_slice(code.message().as_bytes());
        }
        Self::new(kind, id, p)
    }
    pub fn credit(&self) -> u32 {
        self.payload.len() as u32 + CREDIT_OVERHEAD
    }
}
#[derive(Default)]
pub struct Decoder {
    buf: BytesMut,
}
impl Decoder {
    pub fn push(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        if self.buf.len().saturating_add(data.len()) > MAX_FRAME * 2 + 8 {
            return Err(bad("증분 버퍼 상한"));
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }
    pub fn next_frame(&mut self) -> Result<Option<Frame>, ProtocolError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let n = u32::from_be_bytes(self.buf[..4].try_into().map_err(|_| bad("길이"))?) as usize;
        if !(8..=MAX_FRAME).contains(&n) {
            return Err(bad("프레임 길이"));
        }
        if self.buf.len() < n + 4 {
            return Ok(None);
        }
        let mut b = self.buf.split_to(n + 4);
        b.advance(4);
        if b[0] != VERSION || b[2..4] != [0, 0] {
            return Err(bad("버전 또는 flags"));
        }
        let kind = Kind::try_from(b[1])?;
        let id = u32::from_be_bytes(b[4..8].try_into().map_err(|_| bad("ID"))?);
        b.advance(8);
        let f = Frame::new(kind, id, b.freeze());
        f.validate()?;
        Ok(Some(f))
    }
    pub fn finish(&self) -> Result<(), ProtocolError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(bad("잘린 프레임"))
        }
    }
}
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Frame>> {
    let mut h = [0; 4];
    let n = r.read(&mut h[..1]).await?;
    if n == 0 {
        return Ok(None);
    }
    r.read_exact(&mut h[1..]).await?;
    let n = u32::from_be_bytes(h) as usize;
    if !(8..=MAX_FRAME).contains(&n) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            bad("프레임 길이"),
        ));
    }
    let mut b = vec![0; n];
    r.read_exact(&mut b).await?;
    if b[0] != VERSION || b[2..4] != [0, 0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            bad("버전 또는 flags"),
        ));
    }
    let f = Frame::new(
        Kind::try_from(b[1]).map_err(io::Error::other)?,
        u32::from_be_bytes(b[4..8].try_into().map_err(io::Error::other)?),
        b[8..].to_vec(),
    );
    f.validate().map_err(io::Error::other)?;
    Ok(Some(f))
}
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, f: &Frame) -> io::Result<()> {
    w.write_all(&f.encode().map_err(io::Error::other)?).await?;
    w.flush().await
}

pub fn domain(s: &str) -> Result<String, ProtocolError> {
    if s.is_empty() || s.contains('\0') {
        return Err(bad("빈 도메인 또는 NUL"));
    }
    let a = idna::domain_to_ascii_strict(s.trim_end_matches('.'))
        .map_err(|_| bad("잘못된 IDNA"))?
        .to_ascii_lowercase();
    if a.is_empty()
        || a.len() > 253
        || a.split('.').any(|l| {
            l.is_empty()
                || l.len() > 63
                || l.starts_with('-')
                || l.ends_with('-')
                || !l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(bad("잘못된 도메인"));
    }
    Ok(a)
}
pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}
pub fn fake_ip(ip: IpAddr) -> bool {
    match normalize(ip) {
        IpAddr::V4(v) => u32::from(v) & 0xfffe0000 == 0xc6120000,
        _ => false,
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Address {
    Ip(IpAddr),
    Domain(String),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    pub address: Address,
    pub port: u16,
}
impl Destination {
    pub fn new(host: &str, port: u16) -> Result<Self, ProtocolError> {
        if port == 0 {
            return Err(bad("포트 0"));
        }
        let address = match host.parse::<IpAddr>() {
            Ok(ip) => {
                if fake_ip(ip) {
                    return Err(bad("Fake-IP 목적지 금지"));
                }
                Address::Ip(normalize(ip))
            }
            Err(_) => Address::Domain(domain(host)?),
        };
        Ok(Self { address, port })
    }
    pub fn socket(addr: SocketAddr) -> Self {
        Self {
            address: Address::Ip(normalize(addr.ip())),
            port: addr.port(),
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.port == 0 {
            return Err(bad("포트 0"));
        }
        let mut b = Vec::new();
        match &self.address {
            Address::Ip(ip) => match normalize(*ip) {
                IpAddr::V4(v) => {
                    b.push(1);
                    b.extend_from_slice(&v.octets());
                }
                IpAddr::V6(v) => {
                    b.push(4);
                    b.extend_from_slice(&v.octets());
                }
            },
            Address::Domain(s) => {
                let a = domain(s)?;
                b.push(3);
                b.push(a.len() as u8);
                b.extend_from_slice(a.as_bytes());
            }
        }
        b.extend_from_slice(&self.port.to_be_bytes());
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<(Self, usize), ProtocolError> {
        let t = *b.first().ok_or(bad("주소 누락"))?;
        let (address, n) = match t {
            1 => {
                let a = b.get(1..5).ok_or(bad("잘린 IPv4"))?;
                (
                    Address::Ip(
                        Ipv4Addr::from(<[u8; 4]>::try_from(a).map_err(|_| bad("IPv4"))?).into(),
                    ),
                    5,
                )
            }
            4 => {
                let a = b.get(1..17).ok_or(bad("잘린 IPv6"))?;
                (
                    Address::Ip(normalize(
                        Ipv6Addr::from(<[u8; 16]>::try_from(a).map_err(|_| bad("IPv6"))?).into(),
                    )),
                    17,
                )
            }
            3 => {
                let n = *b.get(1).ok_or(bad("도메인 길이 누락"))? as usize;
                let a = b.get(2..2 + n).ok_or(bad("잘린 도메인"))?;
                let a = domain(std::str::from_utf8(a).map_err(|_| bad("UTF8"))?)?;
                (Address::Domain(a), 2 + n)
            }
            _ => return Err(bad("주소 유형")),
        };
        let p = b.get(n..n + 2).ok_or(bad("포트 누락"))?;
        let port = u16::from_be_bytes([p[0], p[1]]);
        if port == 0 || matches!(address,Address::Ip(ip) if fake_ip(ip)) {
            return Err(bad("포트 0 또는 Fake-IP"));
        }
        Ok((Self { address, port }, n + 2))
    }
    pub fn exact(b: &[u8]) -> Result<Self, ProtocolError> {
        let (d, n) = Self::decode(b)?;
        if n != b.len() {
            return Err(bad("주소 뒤 불필요 데이터"));
        }
        Ok(d)
    }
    pub fn ip_socket(&self) -> Result<SocketAddr, ProtocolError> {
        match self.address {
            Address::Ip(ip) => Ok(SocketAddr::new(ip, self.port)),
            _ => Err(bad("실제 IP 주소 필요")),
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub struct Hello {
    pub connection: u32,
    pub stream: u32,
    pub capabilities: u32,
}
impl Default for Hello {
    fn default() -> Self {
        Self {
            connection: CONNECTION_WINDOW,
            stream: STREAM_WINDOW,
            capabilities: 7,
        }
    }
}
impl Hello {
    pub fn encode(self) -> Vec<u8> {
        [
            self.connection.to_be_bytes(),
            self.stream.to_be_bytes(),
            self.capabilities.to_be_bytes(),
        ]
        .concat()
    }
    pub fn decode(b: &[u8]) -> Result<Self, ProtocolError> {
        if b.len() != 12 {
            return Err(bad("HELLO 길이"));
        }
        let a = Self {
            connection: u32::from_be_bytes(b[0..4].try_into().map_err(|_| bad("윈도"))?),
            stream: u32::from_be_bytes(b[4..8].try_into().map_err(|_| bad("윈도"))?),
            capabilities: u32::from_be_bytes(b[8..12].try_into().map_err(|_| bad("기능"))?),
        };
        if !(131072..=4194304).contains(&a.connection)
            || !(131072..=1048576).contains(&a.stream)
            || a.capabilities != 7
        {
            return Err(bad("HELLO 한도/기능"));
        }
        Ok(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn 모든_바이트_분할과_병합() {
        let a = Frame::new(Kind::TcpData, 1, vec![7; 191]).encode().unwrap();
        let b = Frame::new(Kind::Ping, 0, vec![2; 8]).encode().unwrap();
        for i in 0..=a.len() {
            let mut d = Decoder::default();
            d.push(&a[..i]).unwrap();
            let first = d.next_frame().unwrap();
            d.push(&a[i..]).unwrap();
            let f = first.or_else(|| d.next_frame().unwrap()).unwrap();
            assert_eq!(f.payload.len(), 191);
            d.push(&b).unwrap();
            assert_eq!(d.next_frame().unwrap().unwrap().kind, Kind::Ping);
            d.finish().unwrap();
        }
    }
    #[test]
    fn 독립_고정_프레임() {
        let f = Frame::new(Kind::Ping, 0, Bytes::from_static(b"12345678"));
        assert_eq!(
            f.encode().unwrap(),
            b"\0\0\0\x10\x01\x30\0\0\0\0\0\x0012345678"
        );
    }
    #[test]
    fn 길이와_버전_거부() {
        for n in [0, 7, 262145, u32::MAX] {
            let mut d = Decoder::default();
            d.push(&n.to_be_bytes()).unwrap();
            assert!(d.next_frame().is_err());
        }
        let mut b = Frame::new(Kind::Ping, 0, vec![0; 8]).encode().unwrap();
        b[6] = 1;
        let mut d = Decoder::default();
        d.push(&b).unwrap();
        assert!(d.next_frame().is_err());
    }
    #[test]
    fn 주소_보안() {
        for s in ["198.18.0.1", "198.19.255.255", "::ffff:198.18.1.2"] {
            assert!(Destination::new(s, 443).is_err());
        }
        assert!(Destination::new("a\0b", 80).is_err());
        assert!(Destination::new("", 80).is_err());
        assert!(Destination::new("valid.example", 0).is_err());
        let d = Destination::new("예시.한국", 443).unwrap();
        assert_eq!(Destination::exact(&d.encode().unwrap()).unwrap(), d);
    }
    #[test]
    fn 잘림_완료검사() {
        let mut d = Decoder::default();
        d.push(&[0, 0]).unwrap();
        assert!(d.finish().is_err());
    }
}
