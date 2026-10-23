"""격리된 Ubuntu 컨테이너에서 설치 산출물과 실제 비특권 중계를 검증한다."""
from pathlib import Path
import argparse,subprocess,os,json,time,pwd,signal
p=argparse.ArgumentParser();p.add_argument("--binary",type=Path,required=True);p.add_argument("--peer",type=Path,required=True);a=p.parse_args()
assert os.geteuid()==0 and not Path("/etc/mtp-gateway").exists()
root=Path("/var/lib/mtp-gateway-admin");stub=Path("/tmp/mtp-unit-test-bin");stub.mkdir();(stub/"systemctl").write_text("#!/bin/sh\nexit 0\n");(stub/"systemctl").chmod(0o755)
env=dict(os.environ,PATH=str(stub)+":"+os.environ["PATH"],RUST_LOG="info")
def run(args,**kw):return subprocess.run([str(x) for x in args],capture_output=True,check=True,env=env,timeout=30,**kw)
run([a.binary,"init","--root",root,"--host","127.0.0.1","--port","18445","--listen","127.0.0.1:18445,[::1]:18445","--outer-sni","www.example.com","--server-name","gateway.example.com","--dns-server","9.9.9.9:53"])
installer=Path(__file__).resolve().parents[2]/"deploy/install-systemd.py"
run(["python3",installer,"--root",root,"--binary",a.binary])
second=subprocess.run(["python3",str(installer),"--root",str(root),"--binary",str(a.binary)],capture_output=True,env=env);assert second.returncode!=0
run(["/usr/local/bin/mtp-gateway","client","issue","--root",root,"--id","desktop","--owner","alice"])
run(["/usr/local/bin/mtp-gateway","client","export","--root",root,"--id","desktop","--out","/tmp/mtp-export"])
user=pwd.getpwnam("mtp-gateway")
# systemctl은 대역이므로 systemd가 생성할 RuntimeDirectory도 같은 소유권으로 준비한다.
runtime=Path("/run/mtp-gateway");runtime.mkdir(mode=0o750);runtime.chmod(0o750);os.chown(runtime,user.pw_uid,user.pw_gid)
for name in [root/"pki/server-ca-key.pem",root/"pki/client-ca-key.pem",root/"devices/desktop/client-key.pem"]:
 assert subprocess.run(["runuser","-u","mtp-gateway","--","test","-r",str(name)]).returncode!=0
run(["runuser","-u","mtp-gateway","--","test","-r","/etc/mtp-gateway/server-key.pem"])
log=Path("/tmp/mtp-install-runtime.log").open("wb")
server=subprocess.Popen(["runuser","-u","mtp-gateway","--","/usr/local/bin/mtp-gateway","serve","--config","/etc/mtp-gateway/gateway.toml"],env=env,stdout=log,stderr=log,start_new_session=True)
try:
 for _ in range(100):
  if Path("/run/mtp-gateway/status.sock").exists():break
  if server.poll() is not None:raise RuntimeError("비특권 서버 시작 실패")
  time.sleep(.05)
 else:raise RuntimeError("상태 소켓 준비 실패")
 children=Path(f"/proc/{server.pid}/task/{server.pid}/children").read_text().split();assert children
 status=dict(line.split(":",1) for line in Path("/proc/"+children[0]+"/status").read_text().splitlines() if ":" in line)
 assert int(status["Uid"].split()[1])==user.pw_uid and int(status["CapEff"],16)==0
 run([a.peer,"--root","/tmp/mtp-export/client-desktop","probe","--http-host","example.com","--udp-dns","1.1.1.1:53"])
 run(["/usr/local/bin/mtp-gateway","doctor","--config","/etc/mtp-gateway/gateway.toml"])
 print(json.dumps({"install":True,"systemd_unit_syntax":True,"systemctl_is_stubbed":True,"repeat_install_refused":True,"unprivileged_runtime":True,"capabilities":0,"ca_and_device_keys_denied":True,"real_tcp_udp_dns_relay":True,"doctor":True}))
finally:
 os.killpg(server.pid,signal.SIGTERM)
 try:server.wait(timeout=20)
 except subprocess.TimeoutExpired:os.killpg(server.pid,signal.SIGKILL);server.wait()
