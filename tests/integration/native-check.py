"""원래 서비스를 바꾸지 않고 임시 systemd unit에서 비특권 실제 중계를 검증한다."""
from pathlib import Path
import argparse,subprocess,json,os,pwd,grp,re,shutil,socket,time,uuid
p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--peer',type=Path,required=True);a=p.parse_args();assert os.geteuid()==0
nonce=uuid.uuid4().hex[:12];unit='mtp-native-check-'+nonce;root=Path('/var/lib')/unit;root.mkdir(mode=0o755);root.chmod(0o755)
account=pwd.getpwnam('nobody');group=grp.getgrgid(account.pw_gid).gr_name
material=root/'admin';runtime=root/'runtime';runtime.mkdir(mode=0o750);os.chown(runtime,0,account.pw_gid);runtime.chmod(0o750)
binary=root/'mtp-gateway';shutil.copyfile(a.binary,binary);binary.chmod(0o755)
def run(args,**kw):return subprocess.run([str(x) for x in args],capture_output=True,check=True,timeout=30,**kw)
probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
started=False
try:
 if shutil.which('getenforce') and run(['getenforce']).stdout.strip()==b'Enforcing':run(['chcon','-t','bin_t',binary])
 run([binary,'init','--root',material,'--host','127.0.0.1','--port',port,'--listen',f'127.0.0.1:{port},[::1]:{port}','--outer-sni','www.example.com','--server-name','gateway.example.com','--dns-server','9.9.9.9:53'])
 for d in [material,material/'state']:
  os.chown(d,0,account.pw_gid);d.chmod(0o750)
 state=material/'state/registry.json';os.chown(state,0,account.pw_gid);state.chmod(0o640)
 config=(material/'gateway.toml').read_text()
 for key,name in [('secret_file','secret.ee'),('server_cert','server.pem'),('server_key','server-key.pem'),('client_ca','client-ca.pem')]:
  source=material/name if name=='secret.ee' else material/'pki'/name;target=runtime/name;shutil.copyfile(source,target);os.chown(target,0,account.pw_gid);target.chmod(0o640)
  config=re.sub('^'+key+r'\s*=.*$',key+' = '+json.dumps(str(target)),config,flags=re.M)
 config=re.sub(r'^metrics_socket\s*=.*$','metrics_socket = '+json.dumps('/run/'+unit+'/status.sock'),config,flags=re.M)
 cfg=runtime/'gateway.toml';cfg.write_text(config);os.chown(cfg,0,account.pw_gid);cfg.chmod(0o640)
 run([binary,'client','issue','--root',material,'--id','desktop','--owner','alice'])
 run([binary,'client','export','--root',material,'--id','desktop','--out',root/'exports'])
 for path in [material/'pki/server-ca-key.pem',material/'pki/client-ca-key.pem',material/'devices/desktop/client-key.pem']:
  assert subprocess.run(['runuser','-u','nobody','--','test','-r',str(path)],capture_output=True).returncode!=0
 command=['systemd-run','--quiet','--collect','--unit',unit,'--property=User=nobody','--property=Group='+group,'--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=RuntimeDirectory='+unit,'--property=RuntimeDirectoryMode=0750','--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=ReadWritePaths=/run/'+unit,'--property=InaccessiblePaths='+str(material/'pki')+' '+str(material/'devices'),'--property=PrivateTmp=yes','--property=MemoryMax=384M','--property=LimitNOFILE=8192',str(binary),'serve','--config',str(cfg)]
 started=True;run(command)
 for _ in range(100):
  if Path('/run/'+unit+'/status.sock').exists():break
  time.sleep(.05)
 else:raise RuntimeError('비특권 상태 소켓 준비 실패')
 pid=int(run(['systemctl','show',unit,'-p','MainPID','--value']).stdout)
 status=dict(x.split(':',1) for x in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in x)
 assert int(status['Uid'].split()[1])==account.pw_uid and int(status['CapEff'],16)==0 and int(status['NoNewPrivs'])==1
 run([a.peer,'--root',root/'exports/client-desktop','probe','--http-host','example.com','--udp-dns','1.1.1.1:53'])
 run([binary,'doctor','--config',cfg])
 print(json.dumps({'native_systemd_runtime':True,'unprivileged':True,'no_new_privileges':1,'capabilities':0,'ca_and_device_keys_denied':True,'tcp_udp_dns_relay':True,'doctor':True,'selinux_enforcing':bool(shutil.which('getenforce') and run(['getenforce']).stdout.strip()==b'Enforcing')}))
finally:
 if started:
  subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=25)
  subprocess.run(['systemctl','reset-failed',unit],capture_output=True)
 shutil.rmtree(root)
