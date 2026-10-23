# mtp_tcp_v1 / extended_socks_over_mtproto v1 명세

2026-10-23 구현 전 확정. 외부 Fake-TLS/Obfuscated2와 본문의 자체 청크·내부TLS·다중화는 서로 다른 계층이다. 일반 MTProxy나 Telegram 애플리케이션 프로토콜과의 내부 호환성을 주장하지 않는다. 참조 원본 커밋·SHA는 references/manifest.json이다. 참조 구현 원문/라이선스는 원본을 유지하고 자체 문서·주석은 한국어다.

## 계층과 인증

TCP → Fake-TLS ee 레코드 → Obfuscated2 AES-256-CTR 연속 스트림 → 자체 청크 → 실제 TLS1.3 상호인증(ALPN mtp-gateway/1) → 다중화 v1 순서다. Fake-TLS와CTR은 보안상의 암호화 무결성/서버 인증을 제공하는 실제TLS의 대체물이 아니다. TLS0-RTT는 양쪽에서 끈다. TLS 인증서와 현재 허용 fingerprint/사용자 정책 검증을 끝내기 전에는 DNS/목적지 연결을 하지 않는다. 인증서 fingerprint를 사용자·장치에 결속하고 폐기·사용중지는 기존 터널도 종료한다.

외부 SNI는 fake_tls_domain, 내부 인증 이름은 server_name이다. client host IP 리터럴과는 별개다. ee 비밀은 ee +16바이트 키+UTF8 도메인 bytes의 hex. 관리 입력에서 도메인을IDNA A-label/소문자/길이검증하여canonical ASCII로정규화한다. 키/CA개인키/본문은로그에남기지않는다.

ClientHello는 공식클라이언트의 단일 handshake 레코드(최대4096바이트)이며 TCP상분할은제한없이증분수신한다. handshake/type/길이/legacy version/session ID32/짝수cipher vector/압축0/extension전체길이·중복/SNI목록·이름/supported_versions TLS1.3을검사한다. random은offset11의32바이트. 이32바이트를0으로바꾼원래레코드전체의HMAC-SHA256을구하고앞28바이트상수시간비교,마지막4바이트XOR를little-endian UNIX시각으로복원하여기본±300초검증한다. 유효random을replay cache에기록하며유효창안중복거부/최대4096항목·만료후회수,살아있는항목을버려재전송을허용하지않고가득차면새handshake거부한다.

ServerHello+CCS(140303000101)+임의ApplicationData를연결한응답에서서버random(offset11)을0으로두고HMAC(secret, 실제client_random||응답전체)를구하여서버random에쓴다. client session ID를echo하고TLS1.3 version/key_share를포함한다. 클라이언트는HMAC/echo/길이/CCS를검증한다. 첫클라이언트ApplicationData전에CCS1개를허용하고그후에는170303/길이1..16384의레코드만허용한다. TCP읽기와레코드·청크·실TLS경계는독립적이다. 잘린메시지/초과길이/기한초과는종료한다.

Obfuscated2는64바이트: 금지prefix/첫byte ef/두번째word0을거부한다. 원래header[8..40]||secret의SHA256과header[40..56]으로client→server key/IV를만들고,header전체를reverse한동일offset으로반대방향을만든다. AES-256-CTR의128비트big-endian counter를사용한다. client송신/server수신은header64바이트처리후위치64부터이어가고반대방향은위치0부터다. header전체암호화후56..64만원래header에덮어전송한다. 복호화marker[56..60]=dddddddd, DC[60..62]=0000(이전용확장예약값),마지막2바이트는임의값이다. 실제Telegram DC를선택하지않는다. 프레임마다CTR을초기화하지않는다.

## 자체 청크

u32LE wire_len / u32BE content_len / content / CSPRNG padding. wire_len은자신4바이트를제외하며4+content_len+padding_len, content_len1..16384, padding_len4..15. 길이를확인한뒤에만메모리확보한다. content를순서대로연결하면실제TLS바이트스트림이다. 패딩과임의애플리케이션데이터를MTProto구조로추측하지않는다.

## 공통 프레임

u32BE frame_len / u8 version=1 / u8 type / u16BE flags=0 / u32BE stream_id / payload. frame_len은자신을제외한8..262144. 미정의버전/flags/type/길이는GOAWAY(PROTOCOL)후종료한다. client가여는ID는0이아닌증가하는홀수이며반복/역행/짝수/재사용은연결오류다. 최대ID0xfffffffd 이후새터널을연결한다. stream0은제어전용이다. 아래정수는별도표기가없으면big-endian이다.

아래 코드 열은 16진수다.

|코드|이름|payload와방향/상태|
|---|---|---|
|01|HELLO|client→server, 인증후최초1회/stream0. u32 connection_receive_window +u32 stream_receive_window +u32 capabilities=7(TCP1/UDP2/DNS4). 수신윈도범위131072..4194304/131072..1048576.|
|02|WELCOME|server→client, HELLO후1회/stream0. HELLO와동일12바이트+u16 TCP한도+u16 UDP한도+u32 UDP유휴초=총20바이트.|
|10|OPEN_TCP|client→server/새홀수ID. 목적지하나. OPENING상태에서데이터금지.|
|11|OPEN_UDP|client→server/새홀수ID. 목적지하나. 클라이언트원래소켓이같아도목적지가다르면다른ID.|
|12|OPEN_OK|server→client/OPENING. 바인딩주소+실제선택목적지주소,두주소모두IP형태. 이후OPEN.|
|13|OPEN_ERROR|server→client/OPENING. u16오류코드+UTF8설명0..192바이트. ID는영구폐기.|
|20|TCP_DATA|양방향/OPEN,그방향FIN이전. payload1..16384바이트.|
|21|UDP_DATAGRAM|client→server는앱데이터0..65507. server→client는선택목적지IP주소/포트+앱데이터0..65507.|
|22|TCP_FIN|양방향/TCP OPEN, payload없음. 앞선같은방향DATA뒤에보내며해당방향만닫는다. 양방향FIN완료후스트림정리.|
|23|STREAM_RESET|양방향/해당스트림,u16오류코드. 양방향소켓/작업정리. 종료한ID의늦은DATA에는INVALID_STATE RESET,새association을묵시생성하지않는다.|
|24|WINDOW_UPDATE|양방향/u32양수credit. stream0은연결,비0은그스트림. 미사용credit보다큰반환·상한초과는프로토콜오류. 이미종료된ID의늦은스트림WU는무시하되새ID에적용하지않는다.|
|30|PING|양방향/stream0,opaque8바이트.|
|31|PONG|양방향/stream0,수신PING의동일8바이트.|
|32|GOAWAY|양방향/stream0,u16사유+u32마지막처리ID. 새OPEN거부·설정된drain후전체정리.|
|40|DNS_REQUEST|client→server/stream0,u32 request_id(동시재사용금지)+DNS wire message12..65535. QUERY/QR0/표준opcode/질문1개,길이와질문을검증.|
|41|DNS_RESPONSE|server→client/stream0,u32 request_id+u16상태(0=정상DNS응답)+DNS wire message또는오류설명. DNS헤더ID/질문/QR/길이를원요청과검증한다.|

HELLO/WELCOME/PING/PONG/GOAWAY/DNS는stream0만,나머지는위표예외외비0만가능하다. 서버가client전용OPEN/DNS_REQUEST를받는방향외반대송신은오류. client의WELCOME/OPEN_OK/OPEN_ERROR수신방향을반대로보내면연결오류다. 스트림별상태는OPENING→OPEN→각방향FIN→CLOSED 또는RESET. UDP에는FIN을허용하지않는다. payload형식오류/flow 초과는프로토콜오류,소켓실패/유휴/정책/스트림자원실패는해당스트림ERROR/RESET으로격리한다. 스트림하나의실패로다른스트림의성공을위장하거나애플리케이션데이터를재송신하지않는다.

## 주소

01+IPv4 4바이트 /03+u8도메인바이트길이+UTF8도메인 /04+IPv6 16바이트,이후u16포트. 빈도메인/잘못된UTF8/NUL/잘못된IDNA/초과label·전체길이/포트0거부. IPv4-mappedIPv6는IPv4로정규화한다. Fake-IP198.18/15는 명시적 allow가 있어도 항상 거부한다. 관리 resolver 예외는 사용자 목적지 허용과 공유하지 않는다.

## 흐름과 수명

TCP_DATA/UDP_DATAGRAM은각각해당방향연결윈도와스트림윈도를동시에소비한다. 비용은payload전체바이트수+64 credit이며빈UDP도64를소비한다. 이메타비용으로작은프레임공격의큐메모리를제한한다. 수신자가실소켓쓰기또는로컬클라이언트처리를마친후같은비용의연결/스트림WU를보낸다. 폐기·RESET정리때소비한연결credit을반환한다. 기본연결윈도524288/스트림131072. 반대방향과다른스트림의윈도는독립이다. 제어용제한큐는데이터큐와분리·우선송신하고FIN은데이터순서를따라보낸다. 큐/메모리는연결/사용자/전역한도로제한한다.

UDP는서버실UDPsocket을선택한목적지에connect한다. 예상remote이외응답은kernel에서배제된다. recvmsg/MSG_TRUNC로초과/잘림을탐지하고데이터를잘라정상전달하지않는다. 큐포화·전송량/윈도부족시새데이터그램을폐기하고계수하며대상endpoint를변경하지않는다. 기본유휴120초·만료시RESET(IDLE_TIMEOUT),예전ID재활성화없음. 응답selected endpoint와streamID를클라이언트의원래소켓/목적지/NAT맵에연결하여복원한다. 이복원과WinDivert프로세스/방화벽/충돌watchdog보장은Windows책임이다.

도메인은서버A·AAAA병행조회,각결과모두정책검사후검증한IP에직접연결한다. 사용가능한다른주소군은한주소군실패로버리지않는다. TTL0은캐시하지않고긍정/부정SOA TTL을늘리지않는다. 캐시/조회동시성/메시지크기는제한한다. UDP선택IP는association수명동안고정하고재해석은새OPEN으로만한다. NXDOMAIN/NODATA/SERVFAIL/TIMEOUT을구분한다. 명시resolver만사용하고DoT실패는평문자동강등하지않는다. 53공개리스너는없다.

터널이끊기면소속외부소켓/작업/큐를모두취소한다. TCP실패사용자데이터를자동재전송하지않고새터널은새ID영역/새TLS/새CTR이다. shutdown은새연결/OPEN을멈추고GOAWAY를보내며최대drain뒤남은작업을취소한다. 상태를디스크에서복원해이전소켓처럼속이지않는다. UDP-over-TCP는TCP재전송/HOL지연이있어네이티브UDP/QUIC와같지않다.

## 오류 코드

1 POLICY_DENIED /2 DNS_NXDOMAIN /3 DNS_NODATA /4 DNS_SERVFAIL /5 DNS_TIMEOUT /6 CONNECT_REFUSED /7 CONNECT_TIMEOUT /8 RESOURCE_LIMIT /9 UNSUPPORTED /10 INVALID_STATE /11 IDLE_TIMEOUT /12 IO_ERROR /13 REVOKED /14 PROTOCOL_ERROR /15 SHUTDOWN /16 DNS_MALFORMED /17 TOO_LARGE /18 UNAUTHENTICATED. 설명은한국어고정문구이며secret·본문·기본비활성도메인을포함하지않는다.

연결별로 스트림 OPEN/FIN/RESET 제어는 초당4096회, 윈도/PING/PONG 제어는 초당50000회, 전체 입력 프레임은 max(16384, 사용자 UDP초당한도×8+사용자 초당바이트한도÷1024+8192)회로 제한한다. 제어 속도 위반은 프로토콜 오류로 종료한다. TCP 읽기를 기다리는 동안 사용하지 않은 송신 credit을 점유하지 않으며, 제한된 실제 읽기 버퍼를 먼저 확보하고 데이터가 생긴 뒤 윈도를 예약한다.

TCP 주소 후보는 정책 검사 뒤 주소군을 교차 배치하고 최대32개·동시4개·250ms간격으로 연결을 경합한다. 성공한 IP에 직접 연결하고 나머지 소켓/작업을 취소한다. 한 주소군의 blackhole 때문에 다른 주소군을 시도하지 못하는 순차 지연을 방지하며, 전체 연결 제한시간을 별도로 유지한다.


## UDP 전송 대기 보완

외부 UDP 수신과 터널에서 외부로 보내는 UDP 송신은 별도 비동기 작업으로 진행한다. 데이터그램은 나누지 않고 크레딧 전체를 확보하며, 전송 윈도·유한 큐가 잠시 부족하면 최대1초 기다린다. 한 association에서 한 응답만 대기하므로 무제한 사용자 공간 큐를 만들지 않는다. 대기 시간 초과·큐/메모리 거부·패킷/바이트 속도 초과의 폐기는 각각 udp_window_dropped/udp_queue_dropped/udp_rate_dropped로 집계하고 전체 udp_dropped에도 더한다. 애플리케이션 본문은 기록하지 않는다. 초기 협상 수신 윈도의 값은 여전히 협상한 값을 준수한다.
