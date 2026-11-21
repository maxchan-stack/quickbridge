const cors={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET, OPTIONS'};
export default {async fetch(request,env){
 if(request.method==='OPTIONS')return new Response(null,{headers:cors});
 const u=new URL(request.url);
 if(u.pathname==='/health')return Response.json({ok:true},{headers:cors});
 const match=u.pathname.match(/^\/(room|relay)\/([a-f0-9]{32})$/);
 if(!match||request.headers.get('Upgrade')?.toLowerCase()!=='websocket')return new Response('Not found',{status:404});
 return env.ROOM.get(env.ROOM.idFromName(match[1]==='relay'?'relay:'+match[2]:match[2])).fetch(request);
}};
export class Room{
 constructor(state){this.state=state;this.clients=new Map();}
 async fetch(request){
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
}