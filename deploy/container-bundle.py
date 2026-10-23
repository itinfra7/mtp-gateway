#!/usr/bin/python3
"""CA 개인키 없이 비특권 컨테이너용 읽기 전용 자료만 준비한다."""
from pathlib import Path
import argparse,tomllib,json,os,shutil,fcntl
os.umask(0o077)
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--gid',type=int,default=65532);a=p.parse_args();assert os.geteuid()==0 and 0<a.gid<2**31
with (a.root/'registry.lock').open('a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 original=(a.root/'gateway.toml').read_text();config=tomllib.loads(original)
 for directory in [a.out,a.out/'etc',a.out/'state']:
  directory.mkdir(parents=True,exist_ok=True);os.chown(directory,0,a.gid);directory.chmod(0o750)
 rewrite={}
 for field,name in [('secret_file','secret.ee'),('server_cert','server.pem'),('server_key','server-key.pem'),('client_ca','client-ca.pem')]:
  source=Path(config[field]);target=a.out/'etc'/name;shutil.copyfile(source,target);os.chown(target,0,a.gid);target.chmod(0o640);rewrite[field]='/etc/mtp-gateway/'+name
 target=a.out/'state/registry.json';temp=target.with_suffix('.new');shutil.copyfile(config['registry_file'],temp);os.chown(temp,0,a.gid);temp.chmod(0o640);os.replace(temp,target)
 rewrite['registry_file']='/var/lib/mtp-gateway/registry.json';rewrite['metrics_socket']='/run/mtp-gateway/status.sock'
 for field,value in rewrite.items():original=original.replace(field+' = '+json.dumps(config[field],ensure_ascii=False),field+' = '+json.dumps(value,ensure_ascii=False))
 target=a.out/'etc/gateway.toml';target.write_text(original);os.chown(target,0,a.gid);target.chmod(0o640)
print('비특권 컨테이너용 공개 인증서·서버 키·원장 자료 준비 완료. CA 개인키는 제외했습니다.')
