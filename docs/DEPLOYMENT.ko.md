# CLI 서버 배포

Linux x86_64와 Rust 1.98.1을 사용한다. Ubuntu 24.04에서 빌드·배포 시험한다. `README.md`의 init 명령은 관리자용 CA·서버 인증서·공유 비밀·원장을 새로 생성한다. host는 접속할 실제 서버 IP 또는 이름이며 outer-sni와 내부 server-name은 별개다. 예시 주소는 문서용이며 실제 주소로 교체한다.

`deploy/install-systemd.py`는 root로 실행하며 비특권 mtp-gateway 계정, /etc/mtp-gateway의 최소 실행 자료와 전용 systemd unit을 설치한다. 원래 CA·장치 개인키 디렉터리는 root만 접근한다. 서비스는 해당 자료를 읽지 못한다. 기존 설치를 자동 덮어쓰지 않으며 SSH·방화벽·다른 서비스를 변경하지 않는다. 선택한 포트가 8443이 아니면 unit의 SocketBindAllow도 해당 TCP 포트로 지정한다.

터널에 필요한 공개 inbound는 TCP 리슨 포트 하나다. 외부 목적지 TCP·UDP, 설정한 DNS upstream으로의 outbound도 허용해야 한다. 호스트 방화벽과 클라우드 방화벽을 각각 확인한다. 외부 TLS 종료 reverse proxy를 앞에 두지 않는다. TCP 그대로 전달하는 방식은 사용할 수 있다.

원장과 사용자 정책은 client issue/revoke, user show/set 명령으로 관리한다. 전체 인증 차단·허용은 `mtp-gateway access --root /var/lib/mtp-gateway-admin --enabled false` 또는 true다. 차단·폐기·정책 변경은 해당 활성 터널을 회수한다. init을 기존 자료 위에 다시 실행하지 않는다.

업그레이드는 서비스를 정상 종료하고 검증한 새 바이너리를 설치한 뒤 unit의 ExecStart를 교체해 시작한다. 원장·폐기 이력·공유 비밀·CA를 보존한다. 키·인증서 회전은 새 신뢰 자료와 클라이언트 배포를 준비하고 점검 시간에 수행한다. 실패한 TCP 애플리케이션 데이터를 자동 재전송하지 않는다.

백업에는 관리자 루트·/etc/mtp-gateway·정확한 바이너리·unit을 포함하고 암호화한다. 백업 자료와 장치 export를 저장소·Release에 올리지 않는다. 복구 시 최신 폐기 원장을 과거 자료로 덮지 않는다. 제거는 해당 unit을 stop/disable한 뒤 설치 파일·계정만 선택 정리한다.

Docker는 Dockerfile과 Compose의 host 네트워크를 사용한다. root 관리자 자료에서 `deploy/container-bundle.py --root <관리자루트> --out /etc/mtp-gateway-container`로 CA 개인키 없는 실행 묶음을 만든다. 원장·서버 키를 변경하면 이 명령으로 실행 묶음을 갱신하고 필요시 컨테이너를 재시작한다. 별도 bridge IPv6 환경은 검증 범위가 아니다.
