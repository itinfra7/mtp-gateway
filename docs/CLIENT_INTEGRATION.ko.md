# Windows mtp-splitter 통합

`mtp-test-peer`는 protocol·transport crate를 공유하는 실제 Rust 참조 클라이언트다. `x86_64-pc-windows-gnu` 대상으로 라이브러리와 exe를 실제 교차 빌드했다. Windows에서의 실행·WinDivert 통합 시험은 별도이며 교차 빌드를 그 시험으로 대체하지 않는다.

관리 화면의 장치 설정 다운로드는 다음 ZIP을 제공한다. CA 개인키·서버 절대 경로는 포함하지 않는다.

```
client-<id>/
  config/
    server.json
    security.json
    gateway-ca.pem
    client.pem
    client-key.pem
```

server.json에는 host, port, secret_hex, tls_domain, tunnel_mode=extended_socks_over_mtproto를 둔다. host는 IP 리터럴을 지원하여 OS DNS bootstrap에 의존하지 않는다. security.json에는 transport=mtp_tcp_v1, 내부 인증 server_name, 앱 루트 기준 CA/client cert/key 상대 경로, mux_version=1, zero_rtt=false를 둔다. 기존 단순 목적지 헤더만 보내는 클라이언트는 그대로 사용할 수 없다.

Windows 클라이언트의 필수 변경은 다음과 같다.

1. ee 외부 handshake의 HMAC·시각·SNI/서버 응답 인증, Obfuscated2의 정확한 방향별 CTR 위치와 연속 진행을 구현한다.
2. MTProto 메시지 구조를 가정하지 않고 wire_len/content_len/무작위4..15패딩 청크를 구현한다. 모든 경계는 TCP read와 독립이다.
3. 전용 CA로 서버 SAN과 실제 TLS1.3을 검증하고 장치 cert/key로 상호 인증한다. 무조건 성공하는 verifier·0RTT·임의 CA 우회는 금지한다.
4. HELLO/WELCOME 이후 증가하는 홀수 stream ID, OPEN_OK/ERROR, FIN/RESET, 연결·스트림별 윈도와 제어 우선 큐를 구현한다. 정확한 바이트 형식과 오류는 PROTOCOL.ko.md를 따른다.
5. Fake-IP198.18/15를 앱의 도메인 매핑으로 되돌려 도메인이나 실제 IP를 보낸다. 서버는 Fake-IP 목적지를 항상 거부한다.
6. 원래 UDP 소켓과 목적지 조합별로 OPEN_UDP association을 분리한다. UDP_DATAGRAM 하나가 원래 데이터그램 하나이며0바이트도 보존한다. OPEN_OK의 선택 endpoint와 응답 source/stream ID를 원래 NAT 매핑에 결속한다.
7. DNS_REQUEST/RESPONSE로 전체 wire DNS를 전달하고 요청 ID·질문·응답 ID를 검증한다. A/AAAA 외 요청도 이 경로를 사용한다. 서버 내부 resolver 예외를 일반 목적지 예외로 쓰지 않는다.
8. 인증·연결 실패나 터널 종료 때 소속 앱 소켓을 정리한다. 실패한 TCP 데이터는 자동 재송신하지 않는다. 새 터널에는 새 암호 상태와 ID 공간을 사용한다.

사용 예:

```sh
mtp-test-peer --root <client-id 경로> dns --name example.com
mtp-test-peer --root <client-id 경로> tcp --destination <시험echo주소:포트> --bytes 1048576
mtp-test-peer --root <client-id 경로> udp --destination <시험echo주소:포트> --bytes 0
mtp-test-peer --root <client-id 경로> probe --http-host example.com --udp-dns 1.1.1.1:53
```

라이브러리에서는 `Peer::open`, `Peer::send_tcp/send_udp/finish_tcp`, `ClientStream::recv`를 사용한다. 큰 TCP 송신과 수신은 동시에 진행한다. 수신한 Received가 처리 후 drop될 때 윈도를 반환하므로 앱에 전달하지 않고 무제한 보관하지 않는다. 느린 목적지를 기다리는 작업은 다른 stream의 전체 reader를 막지 않게 분리한다.

UDP-over-TCP는 TCP 재전송·head-of-line blocking의 영향을 받는다. 네이티브 UDP나 QUIC와 같지 않으며 지연 민감 앱은 이 한계를 고려한다. 여러 터널 풀을 쓴다고 이 특성이 없어지지 않는다.

프로세스 식별, Windows Dnscache 귀속, 패킷 NAT와 원래 주소 복원, WinDivert 권한, watchdog 충돌 후 차단 유지는 Windows 측 책임이다. 서버 기능 구현만으로 클라이언트의 누출 방지·충돌 안전성을 보장하지 않는다.
