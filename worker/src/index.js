const cors={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET, POST, OPTIONS'};
export default {async fetch(request,env){
 if(request.method==='OPTIONS')return new Response(null,{headers:cors});
 const u=new URL(request.url);
 if(u.pathname==='/health')return Response.json({ok:true},{headers:cors});
 const httpRoom=u.pathname.match(/^\/http-relay\/([a-f0-9]{32})$/);
 if(httpRoom&&request.method==='POST')return env.ROOM.get(env.ROOM.idFromName('http:'+httpRoom[1])).fetch(request);
 const match=u.pathname.match(/^\/(room|relay)\/([a-f0-9]{32})$/);
 if(!match||request.headers.get('Upgrade')?.toLowerCase()!=='websocket')return new Response('Not found',{status:404});
 return env.ROOM.get(env.ROOM.idFromName(match[1]==='relay'?'relay:'+match[2]:match[2])).fetch(request);
}};
export class Room{
 constructor(state){this.state=state;this.clients=new Map();}
 async fetch(request){
  if(new URL(request.url).pathname.startsWith('/http-relay/'))return this.exchange(request);
  const relay=new URL(request.url).pathname.startsWith('/relay/');
  let bytes=0;
  if(this.clients.size>=2)return new Response('Room full',{status:409});
  const pair=new WebSocketPair(),client=pair[0],server=pair[1];
  if(relay)server.binaryType='arraybuffer';
  server.accept();
  const role=this.clients.size===0?'host':'guest';this.clients.set(server,role);
  const send=(ws,msg)=>{try{ws.send(JSON.stringify(msg))}catch{}};
  send(server,{type:'role',role});
  if(role==='guest')for(const ws of this.clients.keys())if(relay||ws!==server)send(ws,{type:'peer-joined'});
  server.addEventListener('message',event=>{
   if(relay){
    if(this.clients.size!==2||!(event.data instanceof ArrayBuffer))return;
    const size=event.data.byteLength;
    bytes+=size;
    if(size<29||size>32768||bytes>8*1024*1024){server.close(1008,'Relay limit');return}
    for(const ws of this.clients.keys())if(ws!==server&&ws.readyState===1)ws.send(event.data);
    return;
   }
   if(typeof event.data!=='string'||event.data.length>16000)return;
   let m;try{m=JSON.parse(event.data)}catch{return}
   if(!['signal','ready','reject'].includes(m?.type))return;
   for(const ws of this.clients.keys())if(ws!==server)send(ws,m);
  });
  const close=()=>{if(!this.clients.has(server))return;this.clients.delete(server);for(const ws of this.clients.keys()){
   send(ws,{type:'peer-left'});
   if(relay)ws.close(1000,'Peer left');
  }};
  server.addEventListener('close',close);server.addEventListener('error',close);
  return new Response(null,{status:101,webSocket:client});
 }

 async exchange(request){
  const reply=(data,status=200)=>Response.json(data,{status,headers:{...cors,'Cache-Control':'no-store'}});
  if(Number(request.headers.get('content-length')||0)>400000)return reply({},413);
  let m;
  try{const body=await request.text();if(body.length>400000)return reply({},413);m=JSON.parse(body)}catch{return reply({},400)}
  if(!m||!['host','guest'].includes(m.role)||typeof m.token!=='string'||!/^[a-f0-9]{64}$/.test(m.token))return reply({},400);
  const now=Date.now();
  this.httpPeers??=new Map();
  const peers=this.httpPeers,otherRole=m.role==='host'?'guest':'host';
  let self=peers.get(m.role),other=peers.get(otherRole);
  if(this.finished||[...peers.values()].some(p=>now-p.seen>120000)){this.finished=true;peers.clear();return reply({},410)}
  if(!self){
   if(!m.join||(!other&&m.role==='guest'))return reply({},404);
   self={token:m.token,seen:now,received:0,sent:0,queue:[],bytes:0};
   peers.set(m.role,self);
  }
  if(self.token!==m.token)return reply({},403);
  self.seen=now;
  if(m.leave){this.finished=true;peers.clear();return reply({})}
  const frames=m.frames;
  if(!Array.isArray(frames)||frames.length>16||!Number.isSafeInteger(m.seq)||m.seq<0||m.seq>self.sent||!Number.isSafeInteger(m.ack)||m.ack<self.received||m.ack>self.received+self.queue.length)return reply({},400);
  if(frames.some(f=>typeof f!=='string'||f.length>44000))return reply({},413);
  const fresh=frames.slice(self.sent-m.seq);
  if(fresh.length&&!other)return reply({},409);
  const bytes=fresh.reduce((sum,f)=>sum+f.length,0);
  if(self.bytes+bytes>12*1024*1024)return reply({},413);
  self.queue.splice(0,m.ack-self.received);self.received=m.ack;
  self.bytes+=bytes;self.sent+=fresh.length;
  if(other)other.queue.push(...fresh);
  return reply({paired:Boolean(other),frames:self.queue.slice(0,8)});
 }
}
