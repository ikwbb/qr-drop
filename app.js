'use strict';

// QR Drop: one-shot, serverless file transfer.
//
// Sender                                   Receiver
//  ├─ makes AES-256 key + WebRTC offer
//  ├─ shows QR: <page>#o=<offer>&k=<key>  ──▶ scans, page opens
//  │                                        ├─ applies offer, makes answer
//  │   scans reply QR (answer)          ◀── ┤  shows reply QR
//  ├─ data channel opens ═══════════════════╡
//  └─ sends AES-GCM frames ═══════════════▶ └─ decrypts, offers Save
//
// Every frame on the channel is AES-GCM encrypted with the key from the
// first QR code. The IV is the frame's direction and sequence number, so
// frames can't be reordered, replayed or dropped without decryption failing.

const STUN = [{ urls: 'stun:stun.l.google.com:19302' }];
const CHUNK = 64 * 1024;
const HIGH_WATER = 4 * 1024 * 1024;
const LOW_WATER = 1024 * 1024;
const GATHER_TIMEOUT_MS = 3000;

const T_META = 1, T_DATA = 2, T_END = 3, T_ACK = 4;
const DIR_SENDER = 0, DIR_RECEIVER = 1;

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------- encoding helpers ----------

function b64url(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64url(str) {
  const s = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

async function pipeBytes(bytes, stream) {
  const res = new Response(new Blob([bytes]).stream().pipeThrough(stream));
  return new Uint8Array(await res.arrayBuffer());
}

// SDP is shrunk before it goes into a QR code: lines the other side doesn't
// need are dropped, then the rest is deflated.
function trimSdp(sdp) {
  return sdp.split('\r\n').filter((line) => {
    if (!line) return false;
    if (line.startsWith('a=candidate:') && / tcp /i.test(line)) return false;
    if (line.startsWith('a=extmap-allow-mixed')) return false;
    if (line.startsWith('a=msid-semantic')) return false;
    return true;
  }).join('\r\n') + '\r\n';
}

async function packSdp(sdp) {
  return b64url(await pipeBytes(enc.encode(trimSdp(sdp)), new CompressionStream('deflate-raw')));
}

async function unpackSdp(text) {
  return dec.decode(await pipeBytes(unb64url(text.trim()), new DecompressionStream('deflate-raw')));
}

// ---------- crypto ----------

function frameIv(dir, seq) {
  const iv = new Uint8Array(12);
  iv[0] = dir;
  new DataView(iv.buffer).setBigUint64(4, BigInt(seq));
  return iv;
}

class Cipher {
  constructor(key) {
    this.key = key;
    this.sendSeq = 0;
    this.recvSeq = 0;
  }

  async seal(dir, type, payload) {
    const plain = new Uint8Array(1 + payload.byteLength);
    plain[0] = type;
    plain.set(new Uint8Array(payload), 1);
    const iv = frameIv(dir, this.sendSeq++);
    return crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.key, plain);
  }

  async open(dir, frame) {
    const iv = frameIv(dir, this.recvSeq++);
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, this.key, frame));
    return { type: plain[0], payload: plain.subarray(1) };
  }
}

// ---------- WebRTC ----------

function waitForIce(pc) {
  if (pc.iceGatheringState === 'complete') return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => { pc.removeEventListener('icegatheringstatechange', check); resolve(); };
    const check = () => { if (pc.iceGatheringState === 'complete') done(); };
    pc.addEventListener('icegatheringstatechange', check);
    setTimeout(done, GATHER_TIMEOUT_MS);
  });
}

function watchConnection(pc, onFail) {
  pc.addEventListener('connectionstatechange', () => {
    if (pc.connectionState === 'failed') onFail();
  });
}

const CONNECT_FAILED = 'Could not connect the two devices. This usually means they are on networks that block direct connections (some mobile or corporate networks). Try putting both on the same Wi-Fi and start again.';

// ---------- UI helpers ----------

function show(id, on = true) { $(id).hidden = !on; }

function fail(msg) {
  const el = $('error');
  el.textContent = msg;
  el.hidden = false;
}

function drawQr(canvas, text) {
  const qr = qrcode(0, 'L');
  qr.addData(text, 'Byte');
  qr.make();
  const n = qr.getModuleCount();
  const margin = 4;
  const size = n + margin * 2;
  const scale = Math.max(2, Math.floor(720 / size));
  canvas.width = canvas.height = size * scale;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#000';
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (qr.isDark(r, c)) ctx.fillRect((c + margin) * scale, (r + margin) * scale, scale, scale);
    }
  }
}

async function copy(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const old = button.textContent;
    button.textContent = 'Copied';
    setTimeout(() => { button.textContent = old; }, 1500);
  } catch {
    window.prompt('Copy this:', text);
  }
}

function formatBytes(n) {
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
}

function progress(done, total, verb) {
  $('t-bar').max = total || 1;
  $('t-bar').value = done;
  $('t-status').textContent = `${verb} ${formatBytes(done)} of ${formatBytes(total)}`;
}

// Camera QR scanning. Uses the native BarcodeDetector when the browser has
// one, otherwise jsQR on frames drawn to a canvas.
const scanner = {
  stream: null,
  running: false,

  async start(onText) {
    const video = $('video');
    this.stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment' }, audio: false,
    });
    video.srcObject = this.stream;
    await video.play();
    show('scanner');
    this.running = true;

    let detector = null;
    if ('BarcodeDetector' in window) {
      try { detector = new BarcodeDetector({ formats: ['qr_code'] }); } catch { detector = null; }
    }
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });

    const tick = async () => {
      if (!this.running) return;
      if (video.readyState >= 2) {
        let text = null;
        if (detector) {
          const codes = await detector.detect(video).catch(() => []);
          if (codes.length) text = codes[0].rawValue;
        } else {
          const w = Math.min(video.videoWidth, 800);
          const h = Math.round(video.videoHeight * (w / video.videoWidth));
          canvas.width = w;
          canvas.height = h;
          ctx.drawImage(video, 0, 0, w, h);
          const code = jsQR(ctx.getImageData(0, 0, w, h).data, w, h, { inversionAttempts: 'dontInvert' });
          if (code) text = code.data;
        }
        if (text && await onText(text)) { this.stop(); return; }
      }
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  },

  stop() {
    this.running = false;
    if (this.stream) this.stream.getTracks().forEach((t) => t.stop());
    this.stream = null;
    show('scanner', false);
  },
};

// ---------- sender ----------

async function startSender() {
  show('send');
  const input = $('file');
  const drop = $('drop');

  drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => {
    e.preventDefault();
    drop.classList.remove('over');
    if (e.dataTransfer.files.length) pickFile(e.dataTransfer.files[0]);
  });
  input.addEventListener('change', () => { if (input.files.length) pickFile(input.files[0]); });

  let started = false;
  async function pickFile(file) {
    if (started) return;
    started = true;
    input.disabled = true;
    $('drop-label').textContent = `${file.name} (${formatBytes(file.size)})`;
    try {
      await offerFile(file);
    } catch (err) {
      console.error(err);
      fail(`Something went wrong: ${err.message}`);
    }
  }
}

async function offerFile(file) {
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const cipher = new Cipher(key);

  const pc = new RTCPeerConnection({ iceServers: STUN });
  const channel = pc.createDataChannel('file', { ordered: true });
  channel.binaryType = 'arraybuffer';
  watchConnection(pc, () => fail(CONNECT_FAILED));

  await pc.setLocalDescription(await pc.createOffer());
  await waitForIce(pc);
  const offer = await packSdp(pc.localDescription.sdp);

  const base = location.href.split('#')[0];
  const link = `${base}#o=${offer}&k=${b64url(rawKey)}`;
  drawQr($('offer-qr'), link);
  $('copy-link').addEventListener('click', (e) => copy(link, e.currentTarget));
  show('send-offer');
  show('send-answer');

  let answered = false;
  async function useAnswer(text) {
    if (answered) return true;
    let sdp;
    try {
      sdp = await unpackSdp(text);
      if (!sdp.startsWith('v=0')) throw new Error('not an SDP');
    } catch {
      return false; // not our reply code; keep scanning
    }
    answered = true;
    try {
      await pc.setRemoteDescription({ type: 'answer', sdp });
    } catch (err) {
      fail(`That reply code didn't work: ${err.message}`);
      return true;
    }
    show('send', false);
    show('transfer');
    $('t-title').textContent = 'Connecting…';
    $('t-name').textContent = file.name;
    return true;
  }

  $('scan-answer').addEventListener('click', async () => {
    try {
      await scanner.start(useAnswer);
    } catch (err) {
      fail(`Couldn't open the camera (${err.message}). Paste the reply text instead.`);
    }
  });
  $('stop-scan').addEventListener('click', () => scanner.stop());
  $('use-answer').addEventListener('click', async () => {
    if (!(await useAnswer($('answer-text').value))) fail("That doesn't look like a reply code.");
  });

  channel.addEventListener('open', () => sendFile(file, channel, cipher).catch((err) => {
    console.error(err);
    fail(`Transfer failed: ${err.message}`);
  }));
}

function drain(channel) {
  if (channel.bufferedAmount <= HIGH_WATER) return Promise.resolve();
  return new Promise((resolve) => {
    channel.bufferedAmountLowThreshold = LOW_WATER;
    channel.addEventListener('bufferedamountlow', resolve, { once: true });
  });
}

async function sendFile(file, channel, cipher) {
  scanner.stop();
  $('t-title').textContent = 'Sending';
  const chunks = Math.ceil(file.size / CHUNK);

  const acked = new Promise((resolve, reject) => {
    channel.addEventListener('message', async (e) => {
      try {
        const { type } = await cipher.open(DIR_RECEIVER, e.data);
        if (type === T_ACK) resolve();
      } catch (err) { reject(err); }
    });
  });

  const meta = { name: file.name, size: file.size, type: file.type, chunks };
  channel.send(await cipher.seal(DIR_SENDER, T_META, enc.encode(JSON.stringify(meta))));

  let sent = 0;
  for (let i = 0; i < chunks; i++) {
    const buf = await file.slice(i * CHUNK, (i + 1) * CHUNK).arrayBuffer();
    await drain(channel);
    if (channel.readyState !== 'open') throw new Error('the connection closed');
    channel.send(await cipher.seal(DIR_SENDER, T_DATA, buf));
    sent += buf.byteLength;
    progress(sent, file.size, 'Sent');
  }
  channel.send(await cipher.seal(DIR_SENDER, T_END, new Uint8Array(0)));
  $('t-status').textContent = 'Waiting for the receiver to confirm…';

  await acked;
  $('t-title').textContent = 'Delivered';
  $('t-status').textContent = `${formatBytes(file.size)} received and decrypted on the other device.`;
}

// ---------- receiver ----------

async function startReceiver(params) {
  // Take the key out of the address bar and history as soon as we have it.
  history.replaceState(null, '', location.pathname + location.search);
  show('recv');

  const rawKey = unb64url(params.get('k'));
  if (rawKey.length !== 32) throw new Error('the link is incomplete');
  const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const cipher = new Cipher(key);
  const offer = await unpackSdp(params.get('o'));

  const pc = new RTCPeerConnection({ iceServers: STUN });
  watchConnection(pc, () => fail(CONNECT_FAILED));
  pc.addEventListener('datachannel', (e) => receiveFile(e.channel, cipher));

  await pc.setRemoteDescription({ type: 'offer', sdp: offer });
  await pc.setLocalDescription(await pc.createAnswer());
  await waitForIce(pc);
  const answer = await packSdp(pc.localDescription.sdp);

  drawQr($('answer-qr'), answer);
  show('recv-wait', false);
  show('answer-qr');
  show('copy-answer');
  $('copy-answer').addEventListener('click', (e) => copy(answer, e.currentTarget));
}

function receiveFile(channel, cipher) {
  channel.binaryType = 'arraybuffer';
  let meta = null;
  const parts = [];
  let got = 0;
  let finished = false;

  // Frames are decrypted strictly in arrival order, because the IV counter
  // must advance in step with the sender's.
  let queue = Promise.resolve();
  channel.addEventListener('message', (e) => {
    queue = queue.then(() => handle(e.data)).catch((err) => {
      console.error(err);
      finished = true;
      fail('A piece of the file failed to decrypt, so it was thrown away. Start again.');
      channel.close();
    });
  });
  channel.addEventListener('close', () => {
    if (!finished) fail('The connection closed before the whole file arrived.');
  });

  async function handle(frame) {
    if (finished) return;
    const { type, payload } = await cipher.open(DIR_SENDER, frame);
    if (type === T_META) {
      meta = JSON.parse(dec.decode(payload));
      show('recv', false);
      show('transfer');
      $('t-title').textContent = 'Receiving';
      $('t-name').textContent = meta.name;
      progress(0, meta.size, 'Received');
    } else if (type === T_DATA && meta) {
      parts.push(payload.slice());
      got += payload.byteLength;
      progress(got, meta.size, 'Received');
    } else if (type === T_END && meta) {
      if (parts.length !== meta.chunks || got !== meta.size) throw new Error('size mismatch');
      finished = true;
      channel.send(await cipher.seal(DIR_RECEIVER, T_ACK, new Uint8Array(0)));
      const blob = new Blob(parts, { type: meta.type || 'application/octet-stream' });
      const save = $('t-save');
      save.href = URL.createObjectURL(blob);
      save.download = meta.name;
      save.textContent = `Save ${meta.name}`;
      show('t-save');
      $('t-title').textContent = 'Received';
      $('t-status').textContent = `${formatBytes(meta.size)} decrypted and checked.`;
    } else {
      throw new Error('unexpected frame');
    }
  }
}

// ---------- boot ----------

function linkSource() {
  const m = location.hostname.match(/^([^.]+)\.github\.io$/);
  const repo = location.pathname.split('/').filter(Boolean)[0];
  if (m) $('source-link').href = `https://github.com/${m[1]}/${repo || `${m[1]}.github.io`}`;
}

(async function main() {
  linkSource();
  if (!window.RTCPeerConnection || !window.CompressionStream || !crypto.subtle) {
    fail('This browser is missing WebRTC, compression or WebCrypto support. Try a current Chrome, Firefox or Safari.');
    return;
  }
  const params = new URLSearchParams(location.hash.slice(1));
  try {
    if (params.get('o') && params.get('k')) await startReceiver(params);
    else await startSender();
  } catch (err) {
    console.error(err);
    fail(`This link didn't work (${err.message}). Ask the sender to make a new code.`);
  }
})();
