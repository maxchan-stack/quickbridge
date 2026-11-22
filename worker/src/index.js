import { DurableObject } from 'cloudflare:workers';

export const MAX_FILE_BYTES = 20 * 1024 * 1024;
export const MAX_ROOM_BYTES = 60 * 1024 * 1024;
export const MIN_FRAME_BYTES = 29; // 12B IV + 1B type + 16B GCM tag
export const MAX_FRAME_BYTES = 70000; // 64 KiB chunk + encryption/header overhead
const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
const CLOSED_RETENTION_MS = 24 * 60 * 60 * 1000;
const ALARM_REFRESH_INTERVAL_MS = 60 * 1000;

export function parseAllowedOrigins(raw) {
  return new Set(
    String(raw || '')
      .split(',')
      .map(s => s.trim())
      .filter(Boolean)
  );
}

export function isOriginAllowed(origin, allowedSet) {
  if (!origin || allowedSet.size === 0) return false;
  return allowedSet.has(origin);
}

function corsHeaders(origin) {
  const headers = {
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Cache-Control': 'no-store'
  };
  if (origin) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Vary'] = 'Origin';
  }
  return headers;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const allowed = parseAllowedOrigins(env.ALLOWED_ORIGINS);

    if (request.method === 'OPTIONS') {
      if (!isOriginAllowed(origin, allowed)) {
        return new Response('Forbidden', { status: 403 });
      }
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (url.pathname === '/health') {
      const headers = isOriginAllowed(origin, allowed)
        ? corsHeaders(origin)
        : { 'Cache-Control': 'no-store' };
      return Response.json(
        {
          ok: true,
          mode: 'ws-hibernation-relay',
          maxFileBytes: MAX_FILE_BYTES,
          maxRoomBytes: MAX_ROOM_BYTES
        },
        { headers }
      );
    }

    const match = url.pathname.match(/^\/relay\/([a-f0-9]{32})$/);
    if (!match) {
      return new Response('Not found', { status: 404 });
    }

    if (!isOriginAllowed(origin, allowed)) {
      return new Response('Forbidden origin', { status: 403 });
    }

    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      return new Response('Expected WebSocket upgrade', { status: 426 });
    }

    const id = env.ROOM.idFromName('relay:' + match[1]);
    return env.ROOM.get(id).fetch(request);
  }
};

export class Room extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.lastAlarmAt = 0;
    if (typeof this.ctx.setWebSocketAutoResponse === 'function' && typeof WebSocketRequestResponsePair === 'function') {
      this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
    }
  }

  async refreshAlarm() {
    const now = Date.now();
    if (now - this.lastAlarmAt < ALARM_REFRESH_INTERVAL_MS) return;
    this.lastAlarmAt = now;
    await this.ctx.storage.setAlarm(now + IDLE_TIMEOUT_MS);
  }

  async closeRoom(leavingSocket, reason) {
    await this.ctx.storage.put('closed', true);
    await this.ctx.storage.setAlarm(Date.now() + CLOSED_RETENTION_MS);

    for (const ws of this.ctx.getWebSockets()) {
      if (ws === leavingSocket) continue;
      try {
        ws.send(JSON.stringify({ type: 'peer-left', reason }));
      } catch {}
      try {
        ws.close(1000, reason);
      } catch {}
    }
  }

  async fetch(request) {
    if (await this.ctx.storage.get('closed')) {
      return new Response('Room closed', { status: 410 });
    }

    const sockets = this.ctx.getWebSockets();
    if (sockets.length >= 2) {
      return new Response('Room full', { status: 409 });
    }

    let role = 'host';
    if (sockets.length === 1) {
      const existing = sockets[0].deserializeAttachment?.() || {};
      if (existing.role !== 'host') {
        return new Response('Room unavailable', { status: 409 });
      }
      role = 'guest';
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];

    this.ctx.acceptWebSocket(server, [role]);
    server.serializeAttachment({ role, bytes: 0 });
    await this.refreshAlarm();

    server.send(
      JSON.stringify({
        type: 'role',
        role,
        limits: {
          maxFileBytes: MAX_FILE_BYTES,
          maxRoomBytes: MAX_ROOM_BYTES,
          maxFrameBytes: MAX_FRAME_BYTES
        }
      })
    );

    if (role === 'guest') {
      for (const ws of this.ctx.getWebSockets()) {
        try {
          ws.send(JSON.stringify({ type: 'peer-joined' }));
        } catch {}
      }
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, message) {
    if (await this.ctx.storage.get('closed')) {
      ws.close(1000, 'Room closed');
      return;
    }

    if (typeof message === 'string') {
      if (message === 'ping') {
        try {
          ws.send('pong');
        } catch {}
        return;
      }
      ws.close(1008, 'Binary frames only');
      return;
    }

    const byteLength = message instanceof ArrayBuffer
      ? message.byteLength
      : ArrayBuffer.isView(message)
        ? message.byteLength
        : 0;

    if (byteLength < MIN_FRAME_BYTES || byteLength > MAX_FRAME_BYTES) {
      ws.close(1008, 'Invalid frame size');
      await this.closeRoom(ws, 'Invalid frame size');
      return;
    }

    const sockets = this.ctx.getWebSockets();
    if (sockets.length !== 2) {
      return;
    }

    const meta = ws.deserializeAttachment?.() || { role: 'unknown', bytes: 0 };
    if (meta.bytes + byteLength > MAX_ROOM_BYTES) {
      try {
        ws.send(JSON.stringify({ type: 'quota-exceeded', maxRoomBytes: MAX_ROOM_BYTES }));
      } catch {}
      ws.close(1008, 'Room quota exceeded');
      await this.closeRoom(ws, 'Room quota exceeded');
      return;
    }

    meta.bytes += byteLength;
    ws.serializeAttachment(meta);
    await this.refreshAlarm();

    for (const other of sockets) {
      if (other !== ws) {
        try {
          other.send(message);
        } catch {
          await this.closeRoom(other, 'Peer send failed');
        }
      }
    }
  }

  async webSocketClose(ws) {
    if (!(await this.ctx.storage.get('closed'))) {
      await this.closeRoom(ws, 'Peer left');
    }
  }

  async webSocketError(ws) {
    if (!(await this.ctx.storage.get('closed'))) {
      await this.closeRoom(ws, 'Peer error');
    }
  }

  async alarm() {
    const alreadyClosed = await this.ctx.storage.get('closed');
    if (alreadyClosed) {
      await this.ctx.storage.deleteAll();
      return;
    }

    await this.ctx.storage.put('closed', true);
    for (const ws of this.ctx.getWebSockets()) {
      try {
        ws.send(JSON.stringify({ type: 'peer-left', reason: 'Room expired' }));
      } catch {}
      try {
        ws.close(1000, 'Room expired');
      } catch {}
    }
    await this.ctx.storage.setAlarm(Date.now() + CLOSED_RETENTION_MS);
  }
}
