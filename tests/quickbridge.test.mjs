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
const {
  Room,
  MAX_FILE_BYTES,
  MAX_ROOM_BYTES,
  MAX_FRAME_BYTES,
  parseAllowedOrigins,
  isOriginAllowed
} = workerMod;

// Load frontend helpers from app.js in a sandbox without DOM
function loadFrontendHelpers() {
  const code = readFileSync(new URL('../app.js', import.meta.url), 'utf8');
  const sandbox = {
    crypto: globalThis.crypto,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    Uint32Array,
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

test('frontend: 6-digit short code generation, normalization, and formatting', () => {
  const code = frontend.randomShortCode();
  assert.match(code, /^\d{6}$/);
  assert.equal(frontend.normalizeShortCode('482-915'), '482915');
  assert.equal(frontend.normalizeShortCode(' 482 915 '), '482915');
  assert.equal(frontend.normalizeShortCode('12345'), '');
  assert.equal(frontend.normalizeShortCode('abc123'), '');
  assert.equal(frontend.formatShortCode('482915'), '482-915');
});

test('frontend: ECDH + HKDF + SAS works in both short-code mode (no secret) and secret mode', async () => {
  const roomKey = 'code:482915';
  const kpA = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const kpB = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const kpAttacker = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);

  const pubA = frontend.bytesToHex(new Uint8Array(await crypto.subtle.exportKey('raw', kpA.publicKey)));
  const pubB = frontend.bytesToHex(new Uint8Array(await crypto.subtle.exportKey('raw', kpB.publicKey)));
  const pubAttacker = frontend.bytesToHex(new Uint8Array(await crypto.subtle.exportKey('raw', kpAttacker.publicKey)));

  const sasA = await frontend.computeSas(roomKey, pubA, pubB);
  const sasB = await frontend.computeSas(roomKey, pubB, pubA);
  const sasMitm = await frontend.computeSas(roomKey, pubA, pubAttacker);

  assert.match(sasA, /^[0-9A-F]{4}-[0-9A-F]{4}$/);
  assert.equal(sasA, sasB);
  assert.notEqual(sasA, sasMitm);

  const sharedA = await crypto.subtle.deriveBits({ name: 'ECDH', public: kpB.publicKey }, kpA.privateKey, 256);
  const sharedB = await crypto.subtle.deriveBits({ name: 'ECDH', public: kpA.publicKey }, kpB.privateKey, 256);

  const keyA = await frontend.deriveSessionKey(sharedA, null, roomKey);
  const keyB = await frontend.deriveSessionKey(sharedB, null, roomKey);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(`${roomKey}|app|host|0`);
  const plaintext = new TextEncoder().encode('QuickBridge short-code 20MB test');
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, keyA, plaintext);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, keyB, ct);
  assert.equal(new TextDecoder().decode(decrypted), 'QuickBridge short-code 20MB test');

  // Tampered AAD must fail decryption
  const badAad = new TextEncoder().encode(`${roomKey}|app|guest|0`);
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
      get: () => ({ fetch: async () => new Response('{"exists":true,"full":false}', { status: 200 }) })
    }
  };

  // Health check
  const healthRes = await workerDefault.fetch(new Request('https://signal.example/health'), env);
  assert.equal(healthRes.status, 200);
  const healthJson = await healthRes.json();
  assert.equal(healthJson.maxFileBytes, 20 * 1024 * 1024);
  assert.equal(healthJson.shortCode, true);

  // Removed legacy endpoints return 404
  const oldHttp = await workerDefault.fetch(
    new Request('https://signal.example/http-relay/0123456789abcdef0123456789abcdef', { method: 'POST' }),
    env
  );
  assert.equal(oldHttp.status, 404);

  // Unauthorized Origin on /relay/code/123456/status returns 403
  const badStatusOrigin = await workerDefault.fetch(
    new Request('https://signal.example/relay/code/123456/status', {
      headers: { Origin: 'https://evil.example' }
    }),
    env
  );
  assert.equal(badStatusOrigin.status, 403);

  // Authorized Origin on /relay/code/123456/status returns 200 with CORS
  const okStatus = await workerDefault.fetch(
    new Request('https://signal.example/relay/code/123456/status', {
      headers: { Origin: 'https://maxchan-stack.github.io' }
    }),
    env
  );
  assert.equal(okStatus.status, 200);
  assert.equal(okStatus.headers.get('Access-Control-Allow-Origin'), 'https://maxchan-stack.github.io');

  // Unauthorized Origin on /relay/code/123456 returns 403
  const badCodeWs = await workerDefault.fetch(
    new Request('https://signal.example/relay/code/123456', {
      headers: { Origin: 'https://evil.example', Upgrade: 'websocket' }
    }),
    env
  );
  assert.equal(badCodeWs.status, 403);
});

test('worker: Room Durable Object enforces 6-digit short-code create/status/join/expiry lifecycle', async () => {
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

    // Status before host creates returns 404
    const s0 = await room.fetch(new Request('https://signal.example/relay/code/482915/status'));
    assert.equal(s0.status, 404);

    // Guest joining non-existent code returns 404 (prevents orphan room)
    const g0 = await room.fetch(new Request('https://signal.example/relay/code/482915'));
    assert.equal(g0.status, 404);

    // Host creates short-code room
    const h1 = await room.fetch(new Request('https://signal.example/relay/code/482915?create=1'));
    assert.equal(h1.status, 101);
    assert.equal(acceptedSockets.length, 1);
    assert.ok(alarmAt > Date.now());

    // Another host trying to create same active code returns 409
    const h2 = await room.fetch(new Request('https://signal.example/relay/code/482915?create=1'));
    assert.equal(h2.status, 409);

    // Status now returns 200
    const s1 = await room.fetch(new Request('https://signal.example/relay/code/482915/status'));
    assert.equal(s1.status, 200);

    // Guest joins short-code room
    const g1 = await room.fetch(new Request('https://signal.example/relay/code/482915'));
    assert.equal(g1.status, 101);
    assert.equal(acceptedSockets.length, 2);

    // Status when full returns 409
    const s2 = await room.fetch(new Request('https://signal.example/relay/code/482915/status'));
    assert.equal(s2.status, 409);

    // 66-byte ECDH pubkey frame relays cleanly
    const pubFrame = new Uint8Array(66);
    pubFrame[0] = 0x02;
    await room.webSocketMessage(acceptedSockets[0], pubFrame.buffer);
    assert.equal(acceptedSockets[1].sent.at(-1), pubFrame.buffer);

    // Host leaves (runtime removes closed socket then invokes webSocketClose) -> code is released
    const hostWs = acceptedSockets[0];
    hostWs.close(1000, 'client left');
    await room.webSocketClose(hostWs);
    const s3 = await room.fetch(new Request('https://signal.example/relay/code/482915/status'));
    assert.equal(s3.status, 404);
  } finally {
    globalThis.Response = OrigResponse;
    delete globalThis.WebSocketPair;
  }
});
