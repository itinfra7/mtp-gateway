# 검증 기록

v0.1.0 기준이다.

## 빌드·자동 시험

Rust 1.98.1, Cargo.lock의 고정 의존성을 사용했다.

- AlmaLinux 10.2 native: fmt/check/clippy(-D warnings)·release build·37개 시험 성공. 실제 비특권 systemd 실행에서 NoNewPrivileges=1/capability0·CA/장치키 접근 거부·TCP/UDP/DNS 중계·doctor 성공. SELinux Enforcing을 유지했다.
- Ubuntu 24.04: 기존에 완료한 UID65532/capability0 check·release build·37개 시험과 격리 설치/실중계 검증 결과를 유지한다.

- cargo fmt --check: 성공.
- cargo check --workspace --all-targets --locked: 성공.
- cargo clippy --workspace --all-targets --locked -- -D warnings: 성공.
- cargo test --workspace --locked: 37개 성공.
- 고정 Ubuntu 24.04 컨테이너의 UID65532/capability0에서 check·release build·같은37개 시험 성공.
- protocol/transport/참조 피어의 Windows GNU target check 성공. 실제 Windows 실행은 미검증.

시험은 Fake-TLS HMAC/시간/replay·CTR 알려진 정답/진행 위치·독립 fixture·증분 파서·실제 mTLS/인증서 거부·다중 TCP/UDP·DNS·half-close·취소·유휴/폐기·메모리/윈도·FD 회수·다중 클라이언트를 포함한다. CLI 시험은 초기화·장치 발급/목록/폐기·정책 JSON 변경·전체 인증 차단과 개인키 비출력을 확인한다.

192개 TCP와192개 UDP를 동시에 유지하며 UDP500회 왕복을 검증했다. 100개×1500바이트 UDP 응답의 수신을 늦춘 시험에서도 윈도 반환을 기다린 뒤 경계·순서·내용을 유지했다.

## 설치·실제 실행

격리된 Ubuntu 24.04 환경에서 deploy/install-systemd.py를 실행했다. 기존 설치 재실행 거부·생성 unit의 systemd-analyze verify·비특권 실제 서버 UID/capability0·CA/장치 개인키 접근 거부·실제 공인 TCP HTTP/UDP DNS/서버 DNS·doctor 성공을 확인했다.

시험 컨테이너는 systemd가 PID1이 아니므로 systemctl 호출은 시험용 대역으로 분리하고 RuntimeDirectory를 동일 소유권으로 준비했다. 실제 중계 프로세스는 실행했다. 이 검증을 전체 systemd 부팅·재부팅 시험으로 표현하지 않는다. 설치 시 umask가 실행 디렉터리 접근을 막던 문제는 명시적 권한 지정으로 수정했다.

## 퍼징과 한계

libFuzzer network_parsers: 500,000입력,16초,크래시0. 독립 fixture와 표준 암호 검증 벡터도 함께 사용했다.

UDP-over-TCP에는 재전송 지연과 head-of-line blocking이 있다. 네이티브 UDP와 같지 않다. 장기 부하·실제 Windows 패킷 포착·컨테이너 bridge IPv6·OS 재부팅은 별도 검증이 필요하다. 서비스가 정상 리슨한다는 사실만으로 앱의 전체 중계 성공을 판단하지 않는다.
