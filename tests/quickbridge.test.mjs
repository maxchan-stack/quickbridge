import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { register } from 'node:module';
import vm from 'node:vm';

// Mock `cloudflare:workers` virtual module for Node unit tests
const loaderSource = `
export async function resolve(specifier, context, nextResolve) {
  if (specifier === 'cloudflare:workers') {
    return { shortCircuit: true, url: 'data:text/javascript,export class DurableObject { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }' };
  }
  return nextResolve(specifier, context);
}
`;
register(`data:text/javascript,${encodeURIComponent(loaderSource)}`);

const workerMod = await import('../worker/src/index.js');
const workerDefault = workerMod.default;
const { Room, MAX_FILE_BYTES, MAX_ROOM_BYTES, MAX_FRAME_BYTES, parseAllowedOrigins, isOriginAllowed } = workerMod;

// Load frontend helpers from app.js in a sandbox without DOM
function loadFrontendHelpers() {
  const code = readFileSync(new URL('../app.js', import.meta.url), 'utf8');
  const sandbox = {
    crypto: globalThis.crypto,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    ArrayBuffer,
    Promise,
    Error,
    Math,
    URL,
    URLSearchParams,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    globalThis: {}
  };
  sandbox.globalThis = sandbox;
  vm.runInNewContext(code, sandbox);
  return sandbox.__QUICKBRIDGE_TEST__;
}

const frontend = loadFrontendHelpers();

test('frontend: sanitizeFilename strips traversal, BiDi RLO, control chars, and enforces length', () => {
  assert.equal(frontend.sanitizeFilename('../../etc/passwd'), '_.._etc_passwd');
  assert.equal(frontend.sanitizeFilename('report\u202Efdp.exe'), 'reportfdp.exe');
  assert.equal(frontend.sanitizeFilename('hello\x00world\n.pdf'), 'helloworld.pdf');
  assert.equal(frontend.sanitizeFilename('...'), 'unnamed-file');
  assert.equal(frontend.sanitizeFilename(''), 'unnamed-file');
  const longName = 'a'.repeat(500) + '.pdf';
  assert.equal(frontend.sanitizeFilename(longName).length, 180);
});

test('frontend: ECDH + HKDF + SAS produces identical session key and SAS on both peers', async () => {
  const roomId = '0123456789abcdef0123456789abcdef';
  const secretBytes = crypto.getRandomValues(new Uint8Array(32));

  const kpA = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const kpB = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const kpAttacker = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);

  const pubA = frontend.bytesToHex(new Uint8Array(await crypto.subtle.exportKey('raw', kpA.publicKey)));
  const pubB = frontend.bytesToHex(new Uint8Array(await crypto.subtle.exportKey('raw', kpB.publicKey)));
  const pubAttacker = frontend.bytesToHex(new Uint8Array(await crypto.subtle.exportKey('raw', kpAttacker.publicKey)));

  const sasA = await frontend.computeSas(roomId, pubA, pubB);
  const sasB = await frontend.computeSas(roomId, pubB, pubA);
  const sasMitm = await frontend.computeSas(roomId, pubA, pubAttacker);

  assert.match(sasA, /^[0-9A-F]{4}-[0-9A-F]{4}$/);
  assert.equal(sasA, sasB);
  assert.notEqual(sasA, sasMitm);

  const sharedA = await crypto.subtle.deriveBits({ name: 'ECDH', public: kpB.publicKey }, kpA.privateKey, 256);
  const sharedB = await crypto.subtle.deriveBits({ name: 'ECDH', public: kpA.publicKey }, kpB.privateKey, 256);

  const keyA = await frontend.deriveSessionKey(sharedA, secretBytes, roomId);
  const keyB = await frontend.deriveSessionKey(sharedB, secretBytes, roomId);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(`${roomId}|app|host|0`);
  const plaintext = new TextEncoder().encode('QuickBridge 20MB test payload');
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, keyA, plaintext);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, keyB, ct);
  assert.equal(new TextDecoder().decode(decrypted), 'QuickBridge 20MB test payload');

  // Tampered AAD must fail decryption
  const badAad = new TextEncoder().encode(`${roomId}|app|guest|0`);
  await assert.rejects(() => crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: badAad }, keyB, ct));
});

test('worker: limits are set to 20 MB file and 60 MB room quota', () => {
  assert.equal(MAX_FILE_BYTES, 20 * 1024 * 1024);
  assert.equal(MAX_ROOM_BYTES, 60 * 1024 * 1024);
  assert.ok(MAX_FRAME_BYTES >= 65536 + 29);
});

test('worker: origin validation blocks unauthorized origins and removed endpoints', async () => {
  const allowed = parseAllowedOrigins('https://maxchan-stack.github.io, http://localhost:8080');
  assert.equal(isOriginAllowed('https://maxchan-stack.github.io', allowed), true);
  assert.equal(isOriginAllowed('https://evil.example', allowed), false);
  assert.equal(isOriginAllowed('', allowed), false);

  const env = {
    ALLOWED_ORIGINS: 'https://maxchan-stack.github.io',
    ROOM: {
      idFromName: name => name,
      get: () => ({ fetch: async () => new Response('ok', { status: 200 }) })
    }
  };

  // Health check
  const healthRes = await workerDefault.fetch(new Request('https://signal.example/health'), env);
  assert.equal(healthRes.status, 200);
  const healthJson = await healthRes.json();
  assert.equal(healthJson.maxFileBytes, 20 * 1024 * 1024);

  // Removed legacy endpoints return 404
  const oldHttp = await workerDefault.fetch(
    new Request('https://signal.example/http-relay/0123456789abcdef0123456789abcdef', { method: 'POST' }),
    env
  );
  assert.equal(oldHttp.status, 404);

  const oldRoom = await workerDefault.fetch(
    new Request('https://signal.example/room/0123456789abcdef0123456789abcdef'),
    env
  );
  assert.equal(oldRoom.status, 404);

  // Unauthorized Origin on /relay/ returns 403
  const badOrigin = await workerDefault.fetch(
    new Request('https://signal.example/relay/0123456789abcdef0123456789abcdef', {
      headers: { Origin: 'https://evil.example', Upgrade: 'websocket' }
    }),
    env
  );
  assert.equal(badOrigin.status, 403);

  // Valid Origin without WebSocket Upgrade returns 426
  const noUpgrade = await workerDefault.fetch(
    new Request('https://signal.example/relay/0123456789abcdef0123456789abcdef', {
      headers: { Origin: 'https://maxchan-stack.github.io' }
    }),
    env
  );
  assert.equal(noUpgrade.status, 426);
});

test('worker: Room Durable Object enforces 2-peer cap, binary relay, 60 MB quota, and persistent close', async () => {
  const storageMap = new Map();
  let alarmAt = null;
  const acceptedSockets = [];

  class FakeWebSocket {
    constructor() {
      this.sent = [];
      this.closed = null;
      this.attachment = null;
    }
    send(data) {
      this.sent.push(data);
    }
    close(code, reason) {
      this.closed = { code, reason };
      const idx = acceptedSockets.indexOf(this);
      if (idx >= 0) acceptedSockets.splice(idx, 1);
    }
    serializeAttachment(v) {
      this.attachment = structuredClone(v);
    }
    deserializeAttachment() {
      return this.attachment ? structuredClone(this.attachment) : null;
    }
  }

  globalThis.WebSocketPair = class {
    constructor() {
      this[0] = new FakeWebSocket();
      this[1] = new FakeWebSocket();
    }
  };

  // Patch Response to allow status 101 in Node test runtime
  const OrigResponse = globalThis.Response;
  globalThis.Response = class extends OrigResponse {
    constructor(body, init) {
      if (init?.status === 101) {
        super(null, { status: 200 });
        this._status = 101;
        this.webSocket = init.webSocket;
      } else {
        super(body, init);
        this._status = init?.status ?? 200;
      }
    }
    get status() {
      return this._status;
    }
  };

  try {
    const ctx = {
      storage: {
        get: async k => storageMap.get(k),
        put: async (k, v) => storageMap.set(k, v),
        setAlarm: async t => { alarmAt = t; },
        deleteAll: async () => { storageMap.clear(); }
      },
      acceptWebSocket: ws => { acceptedSockets.push(ws); },
      getWebSockets: () => [...acceptedSockets]
    };

    const room = new Room(ctx, {});

    // Host joins
    const r1 = await room.fetch(new Request('https://signal.example/relay/0123456789abcdef0123456789abcdef'));
    assert.equal(r1.status, 101);
    assert.equal(acceptedSockets.length, 1);
    const hostWs = acceptedSockets[0];
    assert.equal(JSON.parse(hostWs.sent[0]).role, 'host');
    assert.ok(alarmAt > Date.now());

    // Guest joins
    const r2 = await room.fetch(new Request('https://signal.example/relay/0123456789abcdef0123456789abcdef'));
    assert.equal(r2.status, 101);
    assert.equal(acceptedSockets.length, 2);
    const guestWs = acceptedSockets[1];
    assert.equal(JSON.parse(guestWs.sent[0]).role, 'guest');
    assert.equal(JSON.parse(hostWs.sent[1]).type, 'peer-joined');
    assert.equal(JSON.parse(guestWs.sent[1]).type, 'peer-joined');

    // Third peer rejected with 409
    const r3 = await room.fetch(new Request('https://signal.example/relay/0123456789abcdef0123456789abcdef'));
    assert.equal(r3.status, 409);

    // Valid 64 KiB binary frame relays from host to guest
    const frame = new Uint8Array(65565).buffer;
    await room.webSocketMessage(hostWs, frame);
    assert.equal(guestWs.sent.at(-1), frame);

    // Oversized frame closes connection
    const huge = new Uint8Array(MAX_FRAME_BYTES + 1).buffer;
    await room.webSocketMessage(hostWs, huge);
    assert.equal(hostWs.closed.code, 1008);
    assert.equal(storageMap.get('closed'), true);

    // Re-joining closed room (even after DO eviction / fresh Room instance) returns 410
    const freshRoom = new Room(ctx, {});
    const r4 = await freshRoom.fetch(new Request('https://signal.example/relay/0123456789abcdef0123456789abcdef'));
    assert.equal(r4.status, 410);

    // Alarm on already-closed room cleans up storage
    await freshRoom.alarm();
    assert.equal(storageMap.size, 0);
  } finally {
    globalThis.Response = OrigResponse;
    delete globalThis.WebSocketPair;
  }
});
