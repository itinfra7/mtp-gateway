#!/usr/bin/python3
"""공식 TDesktop 고정 참조의 배치 규칙을 별도 Python/OpenSSL로 계산한다."""
from pathlib import Path
import hashlib,hmac,json,struct,subprocess
root=Path(__file__).resolve().parents[2]
secret=bytes(range(16));stamp=1792730000;domain=b'www.example.com'
def ext(t,b):return struct.pack('>HH',t,len(b))+b
sni=struct.pack('>HBH',len(domain)+3,0,len(domain))+domain
extensions=ext(0x2a2a,b'')+ext(43,b'\x04\x0a\x0a\x03\x04')+ext(0,sni)+ext(51,b'\x00\x24\x00\x1d\x00\x20'+bytes(range(32)))+ext(21,bytes(61))
body=b'\x03\x03'+bytes(32)+b'\x20'+bytes(range(32,64))+b'\x00\x06\x0a\x0a\x13\x01\x13\x02\x01\x00'+struct.pack('>H',len(extensions))+extensions
hello=bytearray(b'\x16\x03\x01'+struct.pack('>H',len(body)+4)+b'\x01'+len(body).to_bytes(3,'big')+body)
auth=bytearray(hmac.digest(secret,hello,'sha256'))
for i,b in enumerate(struct.pack('<I',stamp)):auth[28+i]^=b
hello[11:43]=auth
plain=bytearray(range(1,65));plain[56:60]=b'\xdd'*4;plain[60:62]=bytes(2)
def aes(data,key,iv):return subprocess.run(['openssl','enc','-aes-256-ctr','-K',key.hex(),'-iv',iv.hex()],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True).stdout
key=hashlib.sha256(plain[8:40]+secret).digest();iv=plain[40:56];reverse=plain[::-1];rkey=hashlib.sha256(reverse[8:40]+secret).digest();riv=reverse[40:56]
wire=bytearray(plain);wire[56:64]=aes(plain,key,iv)[56:64]
content=b'\x00\x00\x00\x08\x01\x22\x00\x00\x00\x00\x00\x01'
chunk=struct.pack('<I',4+len(content)+7)+struct.pack('>I',len(content))+content+bytes(range(7))
server_extensions=ext(43,b'\x03\x04')+ext(51,b'\x00\x1d\x00\x20'+bytes(range(32)))
server_body=b'\x03\x03'+bytes(32)+b'\x20'+bytes(hello[44:76])+b'\x13\x01\x00'+struct.pack('>H',len(server_extensions))+server_extensions
server=bytearray(b'\x16\x03\x03'+struct.pack('>H',len(server_body)+4)+b'\x02'+len(server_body).to_bytes(3,'big')+server_body+b'\x14\x03\x03\x00\x01\x01'+b'\x17\x03\x03\x02\x00'+bytes(range(256))*2)
server[11:43]=hmac.digest(secret,bytes(hello[11:43])+server,'sha256')
result={'reference_commit':'a7f453612f4896ac04d0007a36ab0d377e5bcbcf','generator':'Python hashlib/hmac + OpenSSL AES-256-CTR; 운영 비밀값 아님','secret':secret.hex(),'timestamp':stamp,'client_hello':hello.hex(),'server_hello':server.hex(),'obfuscated_wire':wire.hex(),'client_after_header':aes(bytes(64)+chunk,key,iv)[64:].hex(),'server_from_zero':aes(chunk,rkey,riv).hex(),'chunk':chunk.hex(),'content':content.hex(),'sha256_key':key.hex(),'sha256_reverse_key':rkey.hex()}
(root/'tests/fixtures/independent.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
print('독립 fixture 생성 완료')
