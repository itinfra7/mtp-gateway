#![no_main]
//! 외부·내부 파서의 길이·분할·상태 입력을 같은 실행에서 변이한다.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data:&[u8]|{
 if data.len()>32768{return;}
 let secret=mtp_transport::Secret{key:[0;16],domain:"www.example.com".into()};
 let _=mtp_transport::authenticate_hello(data,&secret,1792730000,300);
 let _=mtp_transport::authenticate_server(data,&secret,&[0;32],&[0;32]);
 if data.len()>=64{let mut h=[0;64];h.copy_from_slice(&data[..64]);let _=mtp_transport::server_obfuscation(h,&[0;16]);}
 let mut chunk=mtp_transport::ChunkDecoder::default();
 for b in data.chunks(31){if chunk.push(b).is_err(){break;}loop{match chunk.next_content(){Ok(Some(_))=>{},_=>break}}}let _=chunk.finish();
 let mut frame=mtp_protocol::Decoder::default();
 for b in data.chunks(17){if frame.push(b).is_err(){break;}loop{match frame.next_frame(){Ok(Some(_))=>{},_=>break}}}let _=frame.finish();
 let _=mtp_protocol::Destination::exact(data);
});
