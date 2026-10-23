#!/usr/bin/env python3
"""초기화한 자료를 비특권 CLI 서버용으로 설치한다. 기존 서비스·방화벽은 변경하지 않는다."""
from pathlib import Path
import argparse,grp,hashlib,json,os,pwd,re,shutil,subprocess,tomllib
os.umask(0o077)
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);a=p.parse_args()
if os.geteuid()!=0:raise SystemExit('root 권한이 필요합니다.')
root=a.root.resolve();binary=a.binary.resolve();etc=Path('/etc/mtp-gateway');unit=Path('/etc/systemd/system/mtp-gateway.service')
if etc.exists() or unit.exists() or Path('/usr/local/bin/mtp-gateway').exists() or Path('/usr/local/bin/mtp-gateway').is_symlink():raise SystemExit('기존 설치는 자동 덮어쓰지 않습니다.')
if any(c.isspace() for c in str(root)):raise SystemExit('설치 경로에는 공백을 넣지 마십시오.')
if root==Path('/root') or Path('/root') in root.parents:raise SystemExit('서비스 관리자 자료는 /var/lib 같은 경로에 두십시오.')
subprocess.run([str(binary),'validate-config','--config',str(root/'gateway.toml')],check=True)
try:user=pwd.getpwnam('mtp-gateway')
except KeyError:
 subprocess.run(['useradd','--system','--user-group','--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin','mtp-gateway'],check=True);user=pwd.getpwnam('mtp-gateway')
if user.pw_uid>=1000 or user.pw_shell not in ['/usr/sbin/nologin','/sbin/nologin']:raise SystemExit('동일 이름의 기존 일반 계정은 사용하지 않습니다.')
gid=user.pw_gid
original=(root/'gateway.toml').read_text();cfg=tomllib.loads(original)
for path in [root,root/'state']:
 os.chown(path,0,gid);path.chmod(0o750)
registry=Path(cfg['registry_file']);os.chown(registry,0,gid);registry.chmod(0o640)
etc.mkdir(mode=0o750);os.chown(etc,0,gid);etc.chmod(0o750)
rewrite={}
for key,name in [('secret_file','secret.ee'),('server_cert','server.pem'),('server_key','server-key.pem'),('client_ca','client-ca.pem')]:
 target=etc/name;shutil.copyfile(cfg[key],target);os.chown(target,0,gid);target.chmod(0o640);rewrite[key]=str(target)
rewrite['metrics_socket']='/run/mtp-gateway/status.sock'
for key,value in rewrite.items():original=original.replace(key+' = '+json.dumps(cfg[key]),key+' = '+json.dumps(value))
addresses=json.loads(subprocess.check_output(['ip','-j','address'],text=True))
self_ips=sorted({v['local'] for x in addresses for v in x.get('addr_info',[]) if v.get('family') in ['inet','inet6']})
blocked=list(dict.fromkeys(cfg.get('policy',{}).get('management_addresses',[])+self_ips))
original,count=re.subn(r'^management_addresses\s*=.*$', 'management_addresses = '+json.dumps(blocked),original,flags=re.M)
if count!=1:raise SystemExit('관리 주소 정책 항목이 없거나 중복됐습니다.')
(etc/'gateway.toml').write_text(original);os.chown(etc/'gateway.toml',0,gid);(etc/'gateway.toml').chmod(0o640)
sha=hashlib.sha256(binary.read_bytes()).hexdigest();release_root=Path('/opt/mtp-gateway');release_root.mkdir(exist_ok=True,mode=0o755);release_root.chmod(0o755);release=release_root/sha[:12];release.mkdir(mode=0o755)
release.chmod(0o755);target=release/'mtp-gateway';shutil.copyfile(binary,target);target.chmod(0o755)
link=Path('/usr/local/bin/mtp-gateway')
if link.exists() or link.is_symlink():raise SystemExit('기존 /usr/local/bin/mtp-gateway는 자동 덮어쓰지 않습니다.')
link.symlink_to(target)
ports=sorted({str(x.rsplit(':',1)[1]) for x in cfg['listen']})
body=(Path(__file__).parent/'mtp-gateway.service').read_text().replace('@@BINARY@@',str(target)).replace('@@ADMIN_ROOT@@',str(root)).replace('@@PORTS@@','\n'.join('SocketBindAllow=tcp:'+x for x in ports))
unit.write_text(body);unit.chmod(0o644)
subprocess.run(['systemd-analyze','verify',str(unit)],check=True)
subprocess.run(['systemctl','daemon-reload'],check=True);subprocess.run(['systemctl','enable','--now','mtp-gateway.service'],check=True)
print(json.dumps({'installed':True,'binary_sha256':sha,'service':'mtp-gateway.service','ports':ports}))
