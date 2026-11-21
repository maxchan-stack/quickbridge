const $=id=>document.getElementById(id);
let ws,pc,dc,room,confirmed=false,remoteReady=false,verified=false,incoming=null,pending=[];
const max=20*1024*1024,chunk=16384;
const status=s=>$('status').textContent=s;
const send=(type,data={})=>{if(ws?.readyState===1)ws.send(JSON.stringify({type,...data}))};
const random=()=>Array.from(crypto.getRandomValues(new Uint8Array(16)),x=>x.toString(16).padStart(2,'0')).join('');
const reset=()=>{dc?.close();pc?.close();ws?.close();dc=pc=ws=null;confirmed=remoteReady=verified=false;incoming=null;pending=[];$('setup').hidden=false;$('room').hidden=true;$('transfer').hidden=true;$('confirm').hidden=true;$('reject').hidden=true;$('sas').hidden=true;$('qr').replaceChildren()};
$('leave').onclick=()=>{reset();history.replaceState({},'',location.pathname)};
$('create').onclick=()=>join(random(),true);
function join(id,host){
 if(!/^[a-f0-9]{32}$/.test(id))return alert('房間連結無效');
 const origin=window.QUICKBRIDGE_SIGNAL_ORIGIN;
 if(!origin||origin.includes('REPLACE-ME'))return alert('配對服務尚未部署，請先設定 config.js');
 reset();room=id;$('setup').hidden=true;$('room').hidden=false;
 const link=new URL(location.href);link.searchParams.set('room',id);$('invite').href=link.href;$('invite').textContent=link.href;
 if(host&&window.QRCode)new QRCode($('qr'),{text:link.href,width:200,height:200});
 const url=new URL(origin);url.protocol=url.protocol==='https:'?'wss:':'ws:';url.pathname='/room/'+id;
 ws=new WebSocket(url.href);ws.onopen=()=>status('等待另一台裝置加入');ws.onerror=()=>status('配對伺服器連線失敗');ws.onclose=()=>{if(!$('room').hidden)status('配對連線已關閉')};
 ws.onmessage=async e=>{let m;try{m=JSON.parse(e.data)}catch{return}
  if(m.type==='peer-joined'){status('裝置加入，正在建立連線');await prepare(true)}
  if(m.type==='signal')await signal(m.data);
  if(m.type==='ready'){remoteReady=true;activate()}
  if(m.type==='reject'){status('對方拒絕配對');reset()}
  if(m.type==='peer-left'){status('對方已離線');pc?.close();$('transfer').hidden=true}
 };
}
async function prepare(initiator){
 if(pc)return;
 pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
 pc.onicecandidate=e=>{if(e.candidate)send('signal',{data:{candidate:e.candidate}})};
 pc.onconnectionstatechange=()=>{if(pc.connectionState==='failed')status('P2P 連線失敗，此網路可能需要 TURN 中繼')};
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
 c.onclose=()=>{verified=false;$('transfer').hidden=true;status('傳輸連線已關閉')};
 c.onmessage=async e=>{
  if(typeof e.data==='string'){
   let m;try{m=JSON.parse(e.data)}catch{return}
   if(!verified)return;
   if(m.type==='text'&&typeof m.text==='string'){const div=document.createElement('div');div.textContent=m.text;$('received').prepend(div)}
   if(m.type==='file-start'&&Number.isInteger(m.size)&&m.size>=0&&m.size<=max&&typeof m.name==='string'){incoming={name:m.name,size:m.size,parts:[],bytes:0};status('正在接收：'+m.name)}
   if(m.type==='file-end'&&incoming){const f=incoming;incoming=null;if(f.bytes!==f.size)return status('檔案大小不符，已取消');const blob=new Blob(f.parts),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=f.name;a.textContent='下載 '+f.name;const div=document.createElement('div');div.append(a);$('received').prepend(div);status('檔案已接收，請點選下載');setTimeout(()=>URL.revokeObjectURL(a.href),600000)}
  }else if(verified&&incoming){const b=e.data instanceof ArrayBuffer?e.data:await e.data.arrayBuffer();incoming.bytes+=b.byteLength;if(incoming.bytes>incoming.size){incoming=null;return status('檔案超出預期大小')}incoming.parts.push(b)}
 };
}
function activate(){if(confirmed&&remoteReady&&dc?.readyState==='open'){verified=true;$('transfer').hidden=false;$('reject').hidden=true;status('配對完成，可以傳送')}}
$('confirm').onclick=()=>{confirmed=true;send('ready');$('confirm').hidden=true;activate()};
$('reject').onclick=()=>{send('reject');reset()};
$('sendText').onclick=()=>{if(!verified)return;const value=$('text').value;if(value.length>10000)return alert('文字不可超過 10,000 字');dc.send(JSON.stringify({type:'text',text:value}));$('text').value=''};
const drain=async()=>{while(dc?.readyState==='open'&&dc.bufferedAmount>512*1024)await new Promise(r=>setTimeout(r,50));if(dc?.readyState!=='open')throw Error('連線中斷')};
$('sendFile').onclick=async()=>{
 const f=$('file').files[0];if(!f||!verified)return;if(f.size>max)return alert('單檔上限 20 MB');
 $('sendFile').disabled=true;
 try{dc.send(JSON.stringify({type:'file-start',name:f.name,size:f.size}));let offset=0;while(offset<f.size){await drain();const b=await f.slice(offset,offset+chunk).arrayBuffer();dc.send(b);offset+=b.byteLength;$('progress').value=Math.round(offset/f.size*100)}await drain();dc.send(JSON.stringify({type:'file-end'}));status('已送出檔案，等待接收端下載')}catch(e){status('傳送失敗：'+e.message)}finally{$('sendFile').disabled=false}
};
const id=new URLSearchParams(location.search).get('room');if(id)join(id,false);