(() => {
  'use strict';

  const CHUNK_SIZE = 65536; // 64 KiB binary chunks
  const WINDOW_CHUNKS = 16; // 1 MiB sliding window before waiting for chunk-ack
  const MAX_TEXT_LENGTH = 10000;
  const PING_INTERVAL_MS = 25000;
  const FRAME_OVERHEAD = 29; // 12B IV + 1B type + 16B GCM tag

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  let maxFileBytes = 20 * 1024 * 1024;
  let maxRoomBytes = 60 * 1024 * 1024;

  const $ = id => document.getElementById(id);

  const state = {
    ws: null,
    pingTimer: null,
    roomId: '',
    role: '',
    bootstrapKey: null,
    sessionKey: null,
    ecdhKeyPair: null,
    myPubHex: '',
    peerPubHex: '',
    outgoingSeq: 0,
    incomingSeq: 0,
    sentBytes: 0,
    active: false,
    confirmed: false,
    remoteReady: false,
    verified: false,
    writeQueue: Promise.resolve(),
    readQueue: Promise.resolve(),
    incomingFile: null,
    pendingOffer: null,
    sendingFile: null,
    blobUrls: []
  };

  function randomHex(bytes = 16) {
    const buf = crypto.getRandomValues(new Uint8Array(bytes));
    return bytesToHex(buf);
  }

  function bytesToHex(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
      out += bytes[i].toString(16).padStart(2, '0');
    }
    return out;
  }

  function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  function sanitizeFilename(name) {
    const cleaned = String(name || '')
      .replace(/[\u0000-\u001f\u007f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '')
      .replace(/[\\/:*?"<>|]/g, '_')
      .replace(/^\.+/, '')
      .trim()
      .slice(0, 180);
    return cleaned || 'unnamed-file';
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  function setStatus(text) {
    const el = $('status');
    if (el) el.textContent = text;
  }

  function updateQuotaDisplay() {
    const el = $('quotaText');
    if (!el) return;
    const remaining = Math.max(0, maxRoomBytes - state.sentBytes);
    const remMb = (remaining / (1024 * 1024)).toFixed(1);
    const totalMb = Math.round(maxRoomBytes / (1024 * 1024));
    const maxFileMb = Math.round(maxFileBytes / (1024 * 1024));
    el.textContent = `本房間剩餘送出額度：${remMb} MB／${totalMb} MB（單檔上限 ${maxFileMb} MB）`;
  }

  function clearReceived() {
    for (const url of state.blobUrls) {
      try {
        URL.revokeObjectURL(url);
      } catch {}
    }
    state.blobUrls = [];
    const el = $('received');
    if (el) el.replaceChildren();
  }

  function cancelPendingSend(reason) {
    if (state.sendingFile) {
      state.sendingFile.reject(new Error(reason));
      state.sendingFile = null;
    }
  }

  function reset({ clearHistory = true } = {}) {
    if (state.pingTimer) {
      clearInterval(state.pingTimer);
      state.pingTimer = null;
    }
    if (state.ws) {
      const old = state.ws;
      state.ws = null;
      try {
        old.close(1000, 'Client reset');
      } catch {}
    }
    cancelPendingSend('連線已重設');
    clearReceived();

    state.roomId = '';
    state.role = '';
    state.bootstrapKey = null;
    state.sessionKey = null;
    state.ecdhKeyPair = null;
    state.myPubHex = '';
    state.peerPubHex = '';
    state.outgoingSeq = 0;
    state.incomingSeq = 0;
    state.sentBytes = 0;
    state.active = false;
    state.confirmed = false;
    state.remoteReady = false;
    state.verified = false;
    state.writeQueue = Promise.resolve();
    state.readQueue = Promise.resolve();
    state.incomingFile = null;
    state.pendingOffer = null;

    if ($('app')) $('app').classList.remove('connected');
    if ($('setup')) {
      $('setup').hidden = false;
      $('setup').classList.remove('joining');
    }
    if ($('joinPrompt')) $('joinPrompt').hidden = true;
    if ($('room')) $('room').hidden = true;
    if ($('transfer')) $('transfer').hidden = true;
    if ($('verifyBox')) $('verifyBox').hidden = true;
    if ($('confirm')) $('confirm').hidden = false;
    if ($('reject')) $('reject').hidden = false;
    if ($('modeBadge')) $('modeBadge').hidden = true;
    if ($('qr')) $('qr').replaceChildren();
    if ($('copyResult')) $('copyResult').textContent = '';
    if ($('file')) $('file').value = '';
    if ($('fileMeta')) $('fileMeta').textContent = `點擊選取檔案，或將檔案拖放到這裡（單檔上限 ${Math.round(maxFileBytes / (1024 * 1024))} MB）`;
    if ($('text')) $('text').value = '';
    if ($('progress')) $('progress').value = 0;
    if ($('sendFile')) $('sendFile').disabled = false;

    if (clearHistory && typeof history !== 'undefined' && typeof location !== 'undefined') {
      history.replaceState({}, '', location.pathname);
    }
  }

  function aad(senderRole, seq, phase) {
    return encoder.encode(`${state.roomId}|${phase}|${senderRole}|${seq}`);
  }

  async function deriveSessionKey(sharedBits, secretBytes, roomId) {
    const combined = new Uint8Array(sharedBits.byteLength + secretBytes.byteLength);
    combined.set(new Uint8Array(sharedBits), 0);
    combined.set(secretBytes, sharedBits.byteLength);

    const ikm = await crypto.subtle.importKey('raw', combined, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: encoder.encode('QuickBridge-v2-salt|' + roomId),
        info: encoder.encode('QuickBridge-v2-session-key')
      },
      ikm,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function computeSas(roomId, pubHexA, pubHexB) {
    if (!pubHexA || !pubHexB) throw new Error('缺少雙方臨時公鑰，無法計算驗證碼');
    const sorted = [pubHexA, pubHexB].sort().join('|');
    const digest = await crypto.subtle.digest(
      'SHA-256',
      encoder.encode(`QuickBridge-SAS-v2|${roomId}|${sorted}`)
    );
    const hex = bytesToHex(new Uint8Array(digest, 0, 4)).toUpperCase();
    return `${hex.slice(0, 4)}-${hex.slice(4, 8)}`;
  }

  async function drainSocket(socket, maxBuffered) {
    while (state.ws === socket && socket.readyState === WebSocket.OPEN && socket.bufferedAmount > maxBuffered) {
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    if (state.ws !== socket || socket.readyState !== WebSocket.OPEN) {
      throw new Error('中繼連線已中斷');
    }
  }

  function enqueueSend(payload, isBinary = false, useBootstrap = false) {
    const task = state.writeQueue.then(async () => {
      const socket = state.ws;
      if (!state.active || !socket || socket.readyState !== WebSocket.OPEN) {
        throw new Error('中繼連線已關閉');
      }
      const key = useBootstrap ? state.bootstrapKey : state.sessionKey;
      const phase = useBootstrap ? 'hs' : 'app';
      if (!key) throw new Error('加密金鑰尚未就緒');

      const body = isBinary ? new Uint8Array(payload) : encoder.encode(JSON.stringify(payload));
      const plain = new Uint8Array(body.length + 1);
      plain[0] = isBinary ? 0 : 1;
      plain.set(body, 1);

      const seq = state.outgoingSeq++;
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad(state.role, seq, phase) },
        key,
        plain
      );

      if (!state.active || state.ws !== socket || socket.readyState !== WebSocket.OPEN) {
        throw new Error('中繼連線已關閉');
      }

      const packet = new Uint8Array(iv.length + encrypted.byteLength);
      packet.set(iv, 0);
      packet.set(new Uint8Array(encrypted), iv.length);

      if (state.sentBytes + packet.byteLength > maxRoomBytes) {
        throw new Error('已達本房間累計傳輸上限，請建立新房間');
      }

      await drainSocket(socket, 512 * 1024);
      socket.send(packet);
      state.sentBytes += packet.byteLength;
      updateQuotaDisplay();
    });

    state.writeQueue = task.catch(() => {});
    return task;
  }

  function renderTextItem(text) {
    const item = document.createElement('div');
    item.className = 'item';

    const body = document.createElement('div');
    body.className = 'item-body';

    const urlPattern = /(https?:\/\/[^\s]+)/g;
    let lastIndex = 0;
    for (const match of text.matchAll(urlPattern)) {
      const index = match.index;
      if (index > lastIndex) {
        body.append(document.createTextNode(text.slice(lastIndex, index)));
      }
      const a = document.createElement('a');
      a.href = match[0];
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = match[0];
      body.append(a);
      lastIndex = index + match[0].length;
    }
    if (lastIndex < text.length) {
      body.append(document.createTextNode(text.slice(lastIndex)));
    }

    const actions = document.createElement('div');
    actions.className = 'item-actions';

    const copyBtn = document.createElement('button');
    copyBtn.className = 'quiet';
    copyBtn.textContent = '複製文字';
    copyBtn.onclick = async () => {
      try {
        await navigator.clipboard.writeText(text);
        copyBtn.textContent = '已複製';
        setTimeout(() => { copyBtn.textContent = '複製文字'; }, 1800);
      } catch {
        copyBtn.textContent = '請手動選取複製';
      }
    };

    const meta = document.createElement('span');
    meta.className = 'item-meta';
    meta.textContent = new Date().toLocaleTimeString('zh-TW', { hour12: false });

    actions.append(copyBtn, meta);
    item.append(body, actions);
    $('received').prepend(item);
  }

  function renderFileOffer(offer) {
    const item = document.createElement('div');
    item.className = 'item';

    const title = document.createElement('div');
    title.className = 'item-body';
    title.textContent = `收到檔案傳輸請求：${offer.name}（${formatBytes(offer.size)}）`;

    const actions = document.createElement('div');
    actions.className = 'item-actions';

    const acceptBtn = document.createElement('button');
    acceptBtn.textContent = '接受並接收檔案';

    const rejectBtn = document.createElement('button');
    rejectBtn.className = 'secondary';
    rejectBtn.textContent = '拒絕';

    acceptBtn.onclick = async () => {
      acceptBtn.disabled = true;
      rejectBtn.disabled = true;
      if (state.incomingFile) {
        setStatus('目前已有檔案正在接收中，請稍候');
        acceptBtn.disabled = false;
        rejectBtn.disabled = false;
        return;
      }
      state.incomingFile = {
        ...offer,
        parts: [],
        bytes: 0,
        chunksSinceAck: 0,
        itemEl: item,
        titleEl: title,
        actionsEl: actions
      };
      title.textContent = `正在接收：${offer.name}（0%／${formatBytes(offer.size)}）`;
      actions.replaceChildren();
      try {
        await enqueueSend({ type: 'file-accept', id: offer.id });
        setStatus(`正在接收：${offer.name}`);
      } catch (err) {
        state.incomingFile = null;
        title.textContent = `接受失敗：${err.message}`;
      }
    };

    rejectBtn.onclick = async () => {
      acceptBtn.disabled = true;
      rejectBtn.disabled = true;
      title.textContent = `已拒絕檔案：${offer.name}`;
      actions.replaceChildren();
      try {
        await enqueueSend({ type: 'file-reject', id: offer.id });
      } catch {}
    };

    actions.append(acceptBtn, rejectBtn);
    item.append(title, actions);
    $('received').prepend(item);
  }

  async function finalizeIncomingFile(id) {
    const file = state.incomingFile;
    if (!file || file.id !== id) return;
    state.incomingFile = null;

    if (file.bytes !== file.size) {
      file.titleEl.textContent = `檔案大小不符，已取消：${file.name}`;
      setStatus('檔案大小不符，已取消');
      await enqueueSend({ type: 'file-ack', id, ok: false, reason: 'size-mismatch' }).catch(() => {});
      return;
    }

    const blob = new Blob(file.parts, { type: file.mime });
    const digest = await crypto.subtle.digest('SHA-256', await blob.arrayBuffer());
    const actualSha = bytesToHex(new Uint8Array(digest));

    if (actualSha !== file.sha256) {
      file.titleEl.textContent = `檔案完整性驗證失敗（SHA-256 不符），已丟棄：${file.name}`;
      setStatus('檔案完整性驗證失敗，已丟棄');
      await enqueueSend({ type: 'file-ack', id, ok: false, reason: 'sha256-mismatch' }).catch(() => {});
      return;
    }

    const blobUrl = URL.createObjectURL(blob);
    state.blobUrls.push(blobUrl);

    file.titleEl.textContent = `已通過 SHA-256 驗證：${file.name}（${formatBytes(file.size)}）`;
    const downloadLink = document.createElement('a');
    downloadLink.href = blobUrl;
    downloadLink.download = file.name;
    downloadLink.textContent = `下載 ${file.name}`;
    downloadLink.className = 'download-link';

    file.actionsEl.replaceChildren(downloadLink);
    setStatus(`檔案已完整接收：${file.name}`);
    await enqueueSend({ type: 'file-ack', id, ok: true }).catch(() => {});
  }

  function tryActivate() {
    if (state.confirmed && state.remoteReady && state.active && state.sessionKey) {
      state.verified = true;
      $('app').classList.add('connected');
      $('verifyBox').hidden = true;
      $('transfer').hidden = false;
      $('modeBadge').hidden = false;
      updateQuotaDisplay();
      setStatus('配對完成，可雙向加密傳送文字與檔案（單檔上限 20 MB）');
    }
  }

  async function handleControlMessage(msg) {
    if (msg.type === 'ready') {
      state.remoteReady = true;
      tryActivate();
      return;
    }
    if (msg.type === 'reject') {
      setStatus('對方拒絕配對，房間已結束');
      reset();
      return;
    }
    if (!state.verified) return;

    if (msg.type === 'text' && typeof msg.text === 'string' && msg.text.length <= MAX_TEXT_LENGTH) {
      renderTextItem(msg.text);
      return;
    }

    if (
      msg.type === 'file-offer' &&
      typeof msg.id === 'string' &&
      typeof msg.name === 'string' &&
      Number.isInteger(msg.size) &&
      msg.size >= 0 &&
      msg.size <= maxFileBytes &&
      typeof msg.sha256 === 'string' &&
      /^[a-f0-9]{64}$/.test(msg.sha256)
    ) {
      renderFileOffer({
        id: msg.id,
        name: sanitizeFilename(msg.name),
        size: msg.size,
        mime: typeof msg.mime === 'string' && msg.mime.length <= 128 ? msg.mime : 'application/octet-stream',
        sha256: msg.sha256
      });
      return;
    }

    if (msg.type === 'file-accept' && state.sendingFile?.id === msg.id) {
      state.sendingFile.onAccept();
      return;
    }

    if (msg.type === 'file-reject' && state.sendingFile?.id === msg.id) {
      state.sendingFile.onReject();
      return;
    }

    if (msg.type === 'chunk-ack' && state.sendingFile?.id === msg.id && Number.isInteger(msg.receivedBytes)) {
      state.sendingFile.onChunkAck(msg.receivedBytes);
      return;
    }

    if (msg.type === 'file-end' && typeof msg.id === 'string') {
      await finalizeIncomingFile(msg.id);
      return;
    }

    if (msg.type === 'file-ack' && state.sendingFile?.id === msg.id) {
      state.sendingFile.onFileAck(Boolean(msg.ok), msg.reason || '');
    }
  }

  async function join(id, isHost, secret) {
    if (!/^[a-f0-9]{32}$/.test(id)) return alert('房間連結無效');
    if (!/^[a-f0-9]{64}$/.test(secret)) return alert('房間加密金鑰無效');

    const origin = window.QUICKBRIDGE_SIGNAL_ORIGIN;
    if (!origin || origin.includes('REPLACE-ME')) {
      return alert('配對服務尚未部署，請先設定 config.js');
    }

    reset({ clearHistory: true });
    state.roomId = id;

    const secretBytes = hexToBytes(secret);
    state.bootstrapKey = await crypto.subtle.importKey('raw', secretBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);

    $('setup').hidden = true;
    $('room').hidden = false;
    setStatus('正在連線至加密中繼服務…');

    const inviteUrl = new URL(location.pathname, location.origin);
    inviteUrl.searchParams.set('room', id);
    inviteUrl.hash = secret;
    $('invite').href = inviteUrl.href;
    $('invite').textContent = inviteUrl.href;

    if (isHost) {
      if (typeof window.QRCode === 'function') {
        new window.QRCode($('qr'), { text: inviteUrl.href, width: 200, height: 200 });
      } else {
        $('copyResult').textContent = 'QR Code 模組未載入，請點擊「複製邀請連結」分享。';
      }
    }

    const wsUrl = new URL(origin);
    wsUrl.protocol = wsUrl.protocol === 'https:' ? 'wss:' : 'ws:';
    wsUrl.pathname = `/relay/${id}`;

    const socket = new WebSocket(wsUrl.href);
    socket.binaryType = 'arraybuffer';
    state.ws = socket;

    let socketError = false;

    socket.onopen = () => {
      if (state.ws !== socket) return;
      setStatus(isHost ? '等待另一台裝置掃碼加入…' : '已連線，正在與發起端握手…');
      state.pingTimer = setInterval(() => {
        if (state.ws === socket && socket.readyState === WebSocket.OPEN) {
          try {
            socket.send('ping');
          } catch {}
        }
      }, PING_INTERVAL_MS);
    };

    socket.onerror = () => {
      socketError = true;
    };

    socket.onclose = event => {
      if (state.ws !== socket) return;
      if (state.pingTimer) {
        clearInterval(state.pingTimer);
        state.pingTimer = null;
      }
      state.active = false;
      state.verified = false;
      state.incomingFile = null;
      cancelPendingSend('中繼連線已關閉');
      $('transfer').hidden = true;
      $('verifyBox').hidden = true;
      $('app').classList.remove('connected');

      if (event.reason === 'Peer left') {
        setStatus('對方已離開房間，請點擊「結束房間」後重新建立。');
      } else if (event.reason === 'Room expired') {
        setStatus('房間閒置逾時（15 分鐘）已自動關閉，請重新建立。');
      } else if (event.reason === 'Room quota exceeded') {
        setStatus('已達本房間累計傳輸上限（60 MB），請建立新房間繼續傳送。');
      } else if (event.code === 1000) {
        setStatus('房間已關閉。');
      } else {
        setStatus(`中繼連線已中斷（代碼 ${event.code}${event.reason ? '，' + event.reason : ''}${socketError ? '，網路異常' : ''}）。請重新建立房間。`);
      }
    };

    socket.onmessage = event => {
      if (state.ws !== socket) return;
      if (event.data === 'pong') return;

      state.readQueue = state.readQueue
        .then(async () => {
          if (state.ws !== socket) return;

          if (typeof event.data === 'string') {
            const msg = JSON.parse(event.data);
            if (msg.type === 'role') {
              state.role = msg.role;
              if (msg.limits?.maxFileBytes) maxFileBytes = msg.limits.maxFileBytes;
              if (msg.limits?.maxRoomBytes) maxRoomBytes = msg.limits.maxRoomBytes;
              updateQuotaDisplay();
              return;
            }
            if (msg.type === 'peer-left') {
              state.active = false;
              state.verified = false;
              cancelPendingSend('對方已離線');
              $('transfer').hidden = true;
              $('verifyBox').hidden = true;
              setStatus(msg.reason === 'Room expired' ? '房間閒置逾時已關閉' : '對方已離開房間，請建立新房間');
              return;
            }
            if (msg.type === 'quota-exceeded') {
              setStatus('已達本房間累計傳輸上限，請建立新房間');
              return;
            }
            if (msg.type === 'peer-joined' && state.role && !state.active) {
              state.active = true;
              setStatus('裝置已加入，正在交換臨時加密金鑰…');
              state.ecdhKeyPair = await crypto.subtle.generateKey(
                { name: 'ECDH', namedCurve: 'P-256' },
                false,
                ['deriveBits']
              );
              const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', state.ecdhKeyPair.publicKey));
              state.myPubHex = bytesToHex(rawPub);
              await enqueueSend({ type: 'ecdh', pub: state.myPubHex }, false, true);
              return;
            }
            return;
          }

          if (!state.active) return;

          const packet = new Uint8Array(event.data);
          if (packet.byteLength < FRAME_OVERHEAD) throw new Error('封包長度異常');

          const otherRole = state.role === 'host' ? 'guest' : 'host';
          const isHandshake = !state.sessionKey;
          const key = isHandshake ? state.bootstrapKey : state.sessionKey;
          const phase = isHandshake ? 'hs' : 'app';

          const plain = new Uint8Array(
            await crypto.subtle.decrypt(
              {
                name: 'AES-GCM',
                iv: packet.subarray(0, 12),
                additionalData: aad(otherRole, state.incomingSeq++, phase)
              },
              key,
              packet.subarray(12)
            )
          );

          if (state.ws !== socket || !state.active) return;

          if (isHandshake) {
            if (plain[0] !== 1) throw new Error('握手封包格式錯誤');
            const hsMsg = JSON.parse(decoder.decode(plain.subarray(1)));
            if (hsMsg.type !== 'ecdh' || typeof hsMsg.pub !== 'string' || !/^[a-f0-9]{130}$/.test(hsMsg.pub)) {
              throw new Error('無效的對端公鑰');
            }
            state.peerPubHex = hsMsg.pub;
            const peerPubKey = await crypto.subtle.importKey(
              'raw',
              hexToBytes(hsMsg.pub),
              { name: 'ECDH', namedCurve: 'P-256' },
              false,
              []
            );
            const sharedBits = await crypto.subtle.deriveBits(
              { name: 'ECDH', public: peerPubKey },
              state.ecdhKeyPair.privateKey,
              256
            );
            state.sessionKey = await deriveSessionKey(sharedBits, secretBytes, state.roomId);
            const sasCode = await computeSas(state.roomId, state.myPubHex, state.peerPubHex);
            $('sas').textContent = `請確認兩端驗證碼相同：${sasCode}`;
            $('verifyBox').hidden = false;
            $('confirm').hidden = false;
            $('reject').hidden = false;
            setStatus('加密通道已建立，請核對兩端驗證碼');
            return;
          }

          if (plain[0] === 1) {
            const msg = JSON.parse(decoder.decode(plain.subarray(1)));
            await handleControlMessage(msg);
          } else if (plain[0] === 0 && state.verified && state.incomingFile) {
            const chunk = plain.slice(1).buffer;
            state.incomingFile.bytes += chunk.byteLength;
            if (state.incomingFile.bytes > state.incomingFile.size) {
              const bad = state.incomingFile;
              state.incomingFile = null;
              bad.titleEl.textContent = `檔案超出預期大小，已中止：${bad.name}`;
              setStatus('檔案超出預期大小，已中止');
              await enqueueSend({ type: 'file-ack', id: bad.id, ok: false, reason: 'overflow' }).catch(() => {});
              return;
            }
            state.incomingFile.parts.push(chunk);
            state.incomingFile.chunksSinceAck++;

            const pct = state.incomingFile.size > 0
              ? Math.min(100, Math.round((state.incomingFile.bytes / state.incomingFile.size) * 100))
              : 100;
            state.incomingFile.titleEl.textContent = `正在接收：${state.incomingFile.name}（${pct}%／${formatBytes(state.incomingFile.size)}）`;

            if (state.incomingFile.chunksSinceAck >= WINDOW_CHUNKS) {
              state.incomingFile.chunksSinceAck = 0;
              await enqueueSend({
                type: 'chunk-ack',
                id: state.incomingFile.id,
                receivedBytes: state.incomingFile.bytes
              });
            }
          }
        })
        .catch(err => {
          if (state.ws !== socket) return;
          state.active = false;
          state.verified = false;
          state.incomingFile = null;
          cancelPendingSend('加密驗證失敗');
          $('transfer').hidden = true;
          $('verifyBox').hidden = true;
          setStatus(`加密驗證失敗（${err.message}），連線已中止，請建立新房間`);
          socket.close(1008, 'Crypto verification failed');
        });
    };
  }

  async function sendSelectedFile() {
    const fileInput = $('file');
    const file = fileInput.files?.[0];
    if (!file || !state.verified || state.sendingFile) return;

    if (file.size > maxFileBytes) {
      alert(`單檔上限為 ${Math.round(maxFileBytes / (1024 * 1024))} MB，請選擇較小的檔案。`);
      return;
    }

    const estimatedBytes = file.size + Math.ceil(Math.max(1, file.size) / CHUNK_SIZE) * FRAME_OVERHEAD + 1024;
    if (state.sentBytes + estimatedBytes > maxRoomBytes) {
      alert('本房間剩餘傳輸額度不足以傳送此檔案，請結束並建立新房間。');
      return;
    }

    const socket = state.ws;
    const sendBtn = $('sendFile');
    const progressEl = $('progress');
    sendBtn.disabled = true;
    progressEl.value = 0;

    const fileId = randomHex(8);
    const safeName = sanitizeFilename(file.name);

    try {
      setStatus(`正在計算檔案指紋（SHA-256）：${safeName}…`);
      const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
      const sha256 = bytesToHex(new Uint8Array(digest));

      let acceptResolve;
      let acceptReject;
      const acceptPromise = new Promise((resolve, reject) => {
        acceptResolve = resolve;
        acceptReject = reject;
      });

      let ackResolve;
      let ackReject;
      const fileAckPromise = new Promise((resolve, reject) => {
        ackResolve = resolve;
        ackReject = reject;
      });

      let remoteAckedBytes = 0;
      let windowWaiter = null;

      state.sendingFile = {
        id: fileId,
        onAccept: () => acceptResolve(),
        onReject: () => acceptReject(new Error('對方拒絕接收此檔案')),
        onChunkAck: receivedBytes => {
          remoteAckedBytes = receivedBytes;
          if (windowWaiter) {
            const wake = windowWaiter;
            windowWaiter = null;
            wake();
          }
        },
        onFileAck: (ok, reason) => {
          if (ok) ackResolve();
          else ackReject(new Error(`對方驗證失敗（${reason || 'unknown'}）`));
        },
        reject: err => {
          acceptReject(err);
          ackReject(err);
          if (windowWaiter) {
            const wake = windowWaiter;
            windowWaiter = null;
            wake();
          }
        }
      };

      await enqueueSend({
        type: 'file-offer',
        id: fileId,
        name: safeName,
        size: file.size,
        mime: file.type || 'application/octet-stream',
        sha256
      });

      setStatus(`已送出檔案請求，等待對方點擊接受：${safeName}`);
      await acceptPromise;

      setStatus(`正在加密傳送：${safeName}…`);
      let offset = 0;
      const maxInFlight = WINDOW_CHUNKS * CHUNK_SIZE;

      while (offset < file.size) {
        while (offset - remoteAckedBytes >= maxInFlight && state.ws === socket && state.verified) {
          await new Promise(resolve => { windowWaiter = resolve; });
        }
        if (state.ws !== socket || !state.verified) throw new Error('連線中斷');

        const slice = await file.slice(offset, offset + CHUNK_SIZE).arrayBuffer();
        await enqueueSend(slice, true);
        offset += slice.byteLength;
        progressEl.value = Math.min(99, Math.round((offset / file.size) * 100));
      }

      await state.writeQueue;
      await drainSocket(socket, 0);
      await enqueueSend({ type: 'file-end', id: fileId });
      await state.writeQueue;
      await drainSocket(socket, 0);

      setStatus(`資料已送出，等待對方完成 SHA-256 完整性驗證：${safeName}…`);
      await fileAckPromise;

      progressEl.value = 100;
      setStatus(`檔案已由對方完整接收並通過 SHA-256 驗證：${safeName}`);
      fileInput.value = '';
      $('fileMeta').textContent = `點擊選取檔案，或將檔案拖放到這裡（單檔上限 ${Math.round(maxFileBytes / (1024 * 1024))} MB）`;
    } catch (err) {
      setStatus(`傳送失敗：${err.message}`);
    } finally {
      state.sendingFile = null;
      sendBtn.disabled = false;
    }
  }

  function bindUI() {
    if (typeof document === 'undefined') return;

    $('leave').onclick = () => reset({ clearHistory: true });
    $('createRelay').onclick = () => join(randomHex(16), true, randomHex(32));

    $('copyInvite').onclick = async () => {
      const invite = $('invite');
      try {
        await navigator.clipboard.writeText(invite.href);
        $('copyResult').textContent = '已複製邀請連結，可傳給另一台裝置。';
      } catch {
        $('inviteDetails').open = true;
        $('copyResult').textContent = '請長按或選取上方連結複製。';
      }
    };

    $('confirm').onclick = async () => {
      $('confirm').hidden = true;
      try {
        await enqueueSend({ type: 'ready' });
        state.confirmed = true;
        setStatus('已確認驗證碼，等待對方確認…');
        tryActivate();
      } catch (err) {
        $('confirm').hidden = false;
        setStatus(`確認失敗：${err.message}`);
      }
    };

    $('reject').onclick = async () => {
      try {
        await enqueueSend({ type: 'reject' });
        await state.writeQueue;
      } catch {}
      reset({ clearHistory: true });
    };

    $('sendText').onclick = async () => {
      if (!state.verified) return;
      const textEl = $('text');
      const value = textEl.value;
      if (!value) return;
      if (value.length > MAX_TEXT_LENGTH) {
        return alert(`單次文字不可超過 ${MAX_TEXT_LENGTH.toLocaleString()} 字`);
      }
      try {
        await enqueueSend({ type: 'text', text: value });
        textEl.value = '';
        setStatus('文字已加密送出');
      } catch (err) {
        setStatus(`傳送文字失敗：${err.message}`);
      }
    };

    $('sendFile').onclick = () => sendSelectedFile();
    $('clearReceived').onclick = () => clearReceived();

    const fileInput = $('file');
    const fileMeta = $('fileMeta');
    const dropzone = $('dropzone');

    const showSelectedFile = file => {
      if (!file) return;
      fileMeta.textContent = `已選取：${sanitizeFilename(file.name)}（${formatBytes(file.size)}）`;
    };

    fileInput.addEventListener('change', () => showSelectedFile(fileInput.files?.[0]));

    dropzone.addEventListener('dragover', e => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    dropzone.addEventListener('drop', e => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      const file = e.dataTransfer?.files?.[0];
      if (!file) return;
      const dt = new DataTransfer();
      dt.items.add(file);
      fileInput.files = dt.files;
      showSelectedFile(file);
    });

    const query = new URLSearchParams(location.search);
    const id = query.get('room');
    const secret = location.hash.slice(1);
    if (id) {
      history.replaceState({}, '', location.pathname);
      if (!/^[a-f0-9]{32}$/.test(id) || !/^[a-f0-9]{64}$/.test(secret)) {
        alert('房間連結不完整或已失效，請重新掃碼或開啟完整邀請連結。');
      } else {
        $('setup').classList.add('joining');
        $('joinPrompt').hidden = false;
        const joinBtn = $('joinRoomBtn');
        joinBtn.onclick = () => {
          joinBtn.disabled = true;
          join(id, false, secret);
        };
      }
    }
  }

  if (typeof globalThis !== 'undefined') {
    globalThis.__QUICKBRIDGE_TEST__ = {
      sanitizeFilename,
      formatBytes,
      bytesToHex,
      hexToBytes,
      computeSas,
      deriveSessionKey
    };
  }

  bindUI();
})();
