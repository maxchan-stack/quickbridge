const $=id=>document.getElementById(id);
let ws,pc,dc,room,relayMode=false,confirmed=false,remoteReady=false,verified=false,incoming=null,pending=[];
const chunk=16384;
const fileLimit=()=> (relayMode?5:20)*1024*1024;
const status=s=>$('status').textContent=s;
const send=(type,data={})=>{if(ws?.readyState===1)ws.send(JSON.stringify({type,...data}))};
const random=(bytes=16)=>Array.from(crypto.getRandomValues(new Uint8Array(bytes)),x=>x.toString(16).padStart(2,'0')).join('');
const reset=()=>{dc?.close();pc?.close();ws?.close();dc=pc=ws=null;confirmed=remoteReady=verified=false;incoming=null;pending=[];$('setup').hidden=false;$('room').hidden=true;$('transfer').hidden=true;$('confirm').hidden=true;$('reject').hidden=true;$('sas').hidden=true;$('qr').replaceChildren()};
$('leave').onclick=()=>{reset();history.replaceState({},'',location.pathname)};
$('create').onclick=()=>join(random(),true);
const createRelay=$('createRelay');
if(createRelay)createRelay.onclick=()=>join(random(),true,random(32));
function join(id,host,secret=''){
 if(!/^[a-f0-9]{32}$/.test(id))return alert('房間連結無效');
 const origin=window.QUICKBRIDGE_SIGNAL_ORIGIN;
 if(!origin||origin.includes('REPLACE-ME'))return alert('配對服務尚未部署，請先設定 config.js');
 if(secret&&!/^[a-f0-9]{64}$/.test(secret))return alert('中繼房間金鑰無效');
 reset();room=id;relayMode=Boolean(secret);status('連線中…');$('setup').hidden=true;$('room').hidden=false;
 const link=new URL(location.href);link.searchParams.set('room',id);if(secret){link.searchParams.set('relay','1');link.hash=secret;}$('invite').href=link.href;$('invite').textContent=link.href;
 if(host&&window.QRCode)new QRCode($('qr'),{text:link.href,width:200,height:200});
 const url=new URL(origin);url.protocol=url.protocol==='https:'?'wss:':'ws:';url.pathname=(secret?'/relay/':'/room/')+id;
 const socket=new WebSocket(url.href);
 ws=socket;
 let socketError=false;
 socket.onopen=()=>status('等待另一台裝置加入');
 socket.onerror=()=>{socketError=true};
 socket.onclose=event=>{
  if(ws!==socket||$('room').hidden)return;
  if(secret){verified=false;incoming=null;for(const name of ['transfer','confirm','reject','sas'])$(name).hidden=true;}
  const rtc=secret?'小檔中繼':pc?'WebRTC '+pc.connectionState+'／ICE '+pc.iceConnectionState:'WebRTC 尚未啟動';
  const before=$('status').textContent;
  status(`配對連線已關閉（代碼 ${event.code}，${rtc}${socketError?'，WebSocket 發生錯誤':''}）｜關閉前：${before}`);
 };
 if(secret){openRelay(socket,secret,id);return;}
 socket.onmessage=async e=>{if(ws!==socket)return;let m;try{m=JSON.parse(e.data)}catch{return}
  if(m.type==='peer-joined'){status('裝置加入，正在建立連線');await prepare(true)}
  if(m.type==='signal')await signal(m.data);
  if(m.type==='ready'){remoteReady=true;activate()}
  if(m.type==='reject'){status('對方拒絕配對');reset()}
  if(m.type==='peer-left'){status('對方已離線');pc?.close();$('transfer').hidden=true}
 };
}

function openRelay(socket,secret,id){
 const encoder=new TextEncoder(),decoder=new TextDecoder();
 const raw=Uint8Array.from(secret.match(/../g),byte=>parseInt(byte,16));
 const key=crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt']);
 let role,outgoing=0,received=0,active=false,queue=Promise.resolve();
 const aad=(sender,sequence)=>encoder.encode(id+'|'+sender+'|'+sequence);
 const sendEncrypted=async data=>{
  if(!active||ws!==socket||socket.readyState!==WebSocket.OPEN)throw Error('中繼連線已關閉');
  const text=typeof data==='string', body=text?encoder.encode(data):new Uint8Array(data);
  const plain=new Uint8Array(body.length+1);
  plain[0]=text?1:0;
  plain.set(body,1);
  const sequence=outgoing++;
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const encrypted=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(role,sequence)},await key,plain);
  if(!active||ws!==socket||socket.readyState!==WebSocket.OPEN)throw Error('中繼連線已關閉');
  const packet=new Uint8Array(iv.length+encrypted.byteLength);
  packet.set(iv);
  packet.set(new Uint8Array(encrypted),iv.length);
  socket.send(packet);
 };
 let writes=Promise.resolve();
 const transport={
  get readyState(){return active&&socket.readyState===WebSocket.OPEN?'open':'closed'},
  get bufferedAmount(){return socket.bufferedAmount},
  send(data){
   const task=writes.then(()=>sendEncrypted(data));
   writes=task.catch(()=>{});
   return task;
  },
  close(){active=false}
 };
 socket.binaryType='arraybuffer';
 socket.onmessage=event=>{
  queue=queue.then(async()=>{
   if(ws!==socket)return;
   if(typeof event.data==='string'){
    const m=JSON.parse(event.data);
    if(m.type==='role'){role=m.role;return}
    if(m.type==='peer-left'){
     active=false;
     verified=false;
     incoming=null;
     for(const name of ['transfer','confirm','reject','sas'])$(name).hidden=true;
     status('對方已離線，請建立新的中繼房間');
     return;
    }
    if(m.type==='peer-joined'&&role&&!active){
     active=true;
     channel(transport);
     const digest=await crypto.subtle.digest('SHA-256',encoder.encode('QuickBridge relay verification|'+id+'|'+secret));
     if(ws!==socket||!active)return;
     const code=Array.from(new Uint8Array(digest,0,4),x=>x.toString(16).padStart(2,'0')).join('').toUpperCase();
     $('sas').textContent='請確認兩端驗證碼相同：'+code;
     for(const name of ['sas','confirm','reject'])$(name).hidden=false;
     status('中繼已連線，等待配對確認');
    }
    return;
   }
   if(!active)return;
   const packet=new Uint8Array(event.data);
   const plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:packet.subarray(0,12),additionalData:aad(role==='host'?'guest':'host',received++)},await key,packet.subarray(12)));
   if(ws!==socket||!active)return;
   if(plain[0]===1){
    const data=decoder.decode(plain.subarray(1)),message=JSON.parse(data);
    if(message.type==='ready'){remoteReady=true;activate();return}
    if(message.type==='reject'){reset();return}
    await transport.onmessage({data});
   }else if(plain[0]===0)await transport.onmessage({data:plain.slice(1).buffer});
  }).catch(()=>{
   if(ws!==socket)return;
   active=false;
   verified=false;
   incoming=null;
   $('transfer').hidden=true;
   status('中繼驗證失敗，請建立新的房間');
   socket.close();
  });
 };
}

async function prepare(initiator){
 if(pc)return;
 pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
 pc.onicecandidate=e=>{if(e.candidate)send('signal',{data:{candidate:e.candidate}})};
 pc.onconnectionstatechange=()=>{if(ws?.readyState!==WebSocket.CLOSED&&pc.connectionState==='failed')status('P2P 連線失敗，請結束房間並建立小檔中繼房間')};
 pc.ondatachannel=e=>channel(e.channel);
 if(initiator){channel(pc.createDataChannel('quickbridge'));const offer=await pc.createOffer();await pc.setLocalDescription(offer);send('signal',{data:{description:pc.localDescription}})}
}
async function signal(data){
 if(!data||typeof data!=='object')return;
 if(!pc)await prepare(false);
 try{
  if(data.description){await pc.setRemoteDescription(data.description);for(const c of pending)await pc.addIceCandidate(c);pending=[];if(data.description.type==='offer'){const a=await pc.createAnswer();await pc.setLocalDescription(a);send('signal',{data:{description:pc.localDescription}})}}
  if(data.candidate){if(pc.remoteDescription)await pc.addIceCandidate(data.candidate);else pending.push(data.candidate)}
 }catch(e){status('連線協商失敗：'+e.message)}
}
async function sas(){
 const fingerprint=sdp=>(sdp.match(/^a=fingerprint:sha-256 (.+)$/m)||[])[1]||'';
 const values=[fingerprint(pc.localDescription?.sdp||''),fingerprint(pc.remoteDescription?.sdp||'')].sort().join('|');
 const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(room+'|'+values));
 return Array.from(new Uint8Array(digest).slice(0,4),x=>x.toString(16).padStart(2,'0')).join('').toUpperCase();
}
function channel(c){
 dc=c;dc.binaryType='arraybuffer';
 c.onopen=async()=>{$('sas').textContent='請確認兩端驗證碼相同：'+await sas();$('sas').hidden=false;$('confirm').hidden=false;$('reject').hidden=false;status('等待配對確認')};
 c.onclose=()=>{verified=false;$('transfer').hidden=true;if(ws?.readyState!==WebSocket.CLOSED)status('傳輸連線已關閉')};
 c.onmessage=async e=>{
  if(typeof e.data==='string'){
   let m;try{m=JSON.parse(e.data)}catch{return}
   if(!verified)return;
   if(m.type==='text'&&typeof m.text==='string'){const div=document.createElement('div');div.textContent=m.text;$('received').prepend(div)}
   if(m.type==='file-start'&&Number.isInteger(m.size)&&m.size>=0&&m.size<=fileLimit()&&typeof m.name==='string'){incoming={name:m.name,size:m.size,parts:[],bytes:0};status('正在接收：'+m.name)}
   if(m.type==='file-end'&&incoming){const f=incoming;incoming=null;if(f.bytes!==f.size)return status('檔案大小不符，已取消');const blob=new Blob(f.parts),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=f.name;a.textContent='下載 '+f.name;const div=document.createElement('div');div.append(a);$('received').prepend(div);status('檔案已接收，請點選下載');setTimeout(()=>URL.revokeObjectURL(a.href),600000)}
  }else if(verified&&incoming){const b=e.data instanceof ArrayBuffer?e.data:await e.data.arrayBuffer();incoming.bytes+=b.byteLength;if(incoming.bytes>incoming.size){incoming=null;return status('檔案超出預期大小')}incoming.parts.push(b)}
 };
}
function activate(){if(confirmed&&remoteReady&&dc?.readyState==='open'){verified=true;$('transfer').hidden=false;$('reject').hidden=true;status(relayMode?'配對完成，可中繼傳送小檔（單檔 5 MB）':'配對完成，可以傳送')}}
$('confirm').onclick=async()=>{
 const channel=dc;
 $('confirm').hidden=true;
 try{
  if(relayMode)await channel.send(JSON.stringify({type:'ready'}));else send('ready');
  if(dc===channel){confirmed=true;activate()}
 }catch(e){if(dc===channel)status('確認失敗：'+e.message)}
};
$('reject').onclick=async()=>{try{if(relayMode)await dc.send(JSON.stringify({type:'reject'}));else send('reject')}finally{reset()}};
$('sendText').onclick=async()=>{if(!verified)return;const value=$('text').value;if(value.length>(relayMode?4000:10000))return alert(relayMode?'中繼文字不可超過 4,000 字':'文字不可超過 10,000 字');try{await dc.send(JSON.stringify({type:'text',text:value}));$('text').value=''}catch(e){status('傳送失敗：'+e.message)}};
const drain=async channel=>{while(dc===channel&&channel.readyState==='open'&&channel.bufferedAmount>512*1024)await new Promise(r=>setTimeout(r,50));if(dc!==channel||channel.readyState!=='open')throw Error('連線中斷')};
$('sendFile').onclick=async()=>{
 const f=$('file').files[0];if(!f||!verified)return;if(f.size>fileLimit())return alert(relayMode?'中繼單檔上限 5 MB':'單檔上限 20 MB');
 const channel=dc;
 $('sendFile').disabled=true;
 try{await channel.send(JSON.stringify({type:'file-start',name:f.name,size:f.size}));let offset=0;while(offset<f.size){await drain(channel);const b=await f.slice(offset,offset+chunk).arrayBuffer();await channel.send(b);offset+=b.byteLength;$('progress').value=Math.round(offset/f.size*100)}await drain(channel);await channel.send(JSON.stringify({type:'file-end'}));status('已送出檔案，等待接收端下載')}catch(e){status('傳送失敗：'+e.message)}finally{$('sendFile').disabled=false}
};
const query=new URLSearchParams(location.search),id=query.get('room');
if(id){
 if(query.get('relay')==='1'&&!location.hash.slice(1))alert('中繼房間連結缺少金鑰，請重新掃碼');
 else join(id,false,query.get('relay')==='1'?location.hash.slice(1):'');
}