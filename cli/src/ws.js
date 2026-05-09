// Minimal RFC 6455 WebSocket client built on Node's `net`/`tls` modules so
// the CLI keeps zero runtime dependencies. We only implement the subset
// /api/shell needs: text + binary frames, mask client→server frames, handle
// fragmented frames, and reply to ping with pong.

const crypto = require('crypto');
const net = require('net');
const tls = require('tls');
const { URL } = require('url');
const { EventEmitter } = require('events');

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

const OPCODE = {
  CONT:   0x0,
  TEXT:   0x1,
  BINARY: 0x2,
  CLOSE:  0x8,
  PING:   0x9,
  PONG:   0xA
};

// Build the framing for one client→server frame. Client frames MUST be masked
// per RFC 6455 §5.3, so we generate a random 4-byte mask and XOR the payload.
function buildFrame(opcode, payload) {
  if (!Buffer.isBuffer(payload)) payload = Buffer.from(String(payload), 'utf8');
  const n = payload.length;
  const mask = crypto.randomBytes(4);
  let header;
  if (n < 126) {
    header = Buffer.from([0x80 | (opcode & 0x0F), 0x80 | n]);
  } else if (n < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | (opcode & 0x0F);
    header[1] = 0x80 | 126;
    header.writeUInt16BE(n, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | (opcode & 0x0F);
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(n), 2);
  }
  const masked = Buffer.alloc(n);
  for (let i = 0; i < n; i++) masked[i] = payload[i] ^ mask[i & 3];
  return Buffer.concat([header, mask, masked]);
}

// Parse zero or more complete frames from a rolling buffer. Returns
// { frames, rest } — `rest` is the bytes that didn't form a complete frame yet
// and should be prepended to the next chunk.
function parseFrames(buf) {
  const frames = [];
  let off = 0;
  while (off + 2 <= buf.length) {
    const b0 = buf[off];
    const b1 = buf[off + 1];
    const fin = (b0 >> 7) & 1;
    const opcode = b0 & 0x0F;
    const masked = (b1 >> 7) & 1;
    let plen = b1 & 0x7F;
    let headerLen = 2;
    if (plen === 126) {
      if (off + 4 > buf.length) break;
      plen = buf.readUInt16BE(off + 2);
      headerLen = 4;
    } else if (plen === 127) {
      if (off + 10 > buf.length) break;
      // Length values >2^53 are absurd for our protocol; coerce.
      plen = Number(buf.readBigUInt64BE(off + 2));
      headerLen = 10;
    }
    if (masked) headerLen += 4;
    if (off + headerLen + plen > buf.length) break;
    let payload = buf.slice(off + headerLen, off + headerLen + plen);
    if (masked) {
      const m = buf.slice(off + headerLen - 4, off + headerLen);
      const out = Buffer.alloc(plen);
      for (let i = 0; i < plen; i++) out[i] = payload[i] ^ m[i & 3];
      payload = out;
    }
    frames.push({ fin, opcode, payload });
    off += headerLen + plen;
  }
  return { frames, rest: buf.slice(off) };
}

class WsClient extends EventEmitter {
  constructor(socket, url) {
    super();
    this.socket = socket;
    this.url = url;
    this._buf = Buffer.alloc(0);
    this._closed = false;
    // Reassembly state for fragmented frames. WebSocket allows messages to be
    // split across multiple frames (fin=0), and we get binary chunks during
    // large output bursts even when the server doesn't fragment, but we should
    // still handle continuation frames correctly.
    this._fragOpcode = null;
    this._fragChunks = [];

    socket.on('data', (chunk) => this._onData(chunk));
    socket.on('close', () => this._onClose());
    socket.on('error', (err) => this.emit('error', err));
  }

  _onData(chunk) {
    this._buf = this._buf.length ? Buffer.concat([this._buf, chunk]) : chunk;
    const { frames, rest } = parseFrames(this._buf);
    this._buf = rest;
    for (const f of frames) this._dispatch(f);
  }

  _dispatch(frame) {
    const { fin, opcode, payload } = frame;
    if (opcode === OPCODE.PING) {
      this._sendRaw(buildFrame(OPCODE.PONG, payload));
      return;
    }
    if (opcode === OPCODE.PONG) return;
    if (opcode === OPCODE.CLOSE) {
      // Echo the close frame, then destroy the socket and emit 'close'
      // synchronously. We don't wait for the TCP FIN handshake to complete
      // — through cloudflared/Cloudflare that can take seconds (or hang) —
      // because the server has already finished its side.
      if (this._closed) return;
      this._closed = true;
      try { this._sendRaw(buildFrame(OPCODE.CLOSE, payload.slice(0, 2))); } catch {}
      try { this.socket.destroy(); } catch {}
      this.emit('close');
      return;
    }

    if (opcode === OPCODE.CONT) {
      if (this._fragOpcode === null) return; // stray continuation, ignore
      this._fragChunks.push(payload);
      if (fin) {
        const full = Buffer.concat(this._fragChunks);
        const op = this._fragOpcode;
        this._fragOpcode = null;
        this._fragChunks = [];
        this.emit('frame', op, full);
      }
      return;
    }

    if (!fin) {
      this._fragOpcode = opcode;
      this._fragChunks = [payload];
      return;
    }
    this.emit('frame', opcode, payload);
  }

  _onClose() {
    if (this._closed) return;
    this._closed = true;
    this.emit('close');
  }

  _sendRaw(buf) {
    if (this._closed) return;
    this.socket.write(buf);
  }

  sendBinary(payload) { this._sendRaw(buildFrame(OPCODE.BINARY, payload)); }
  sendText(payload)   { this._sendRaw(buildFrame(OPCODE.TEXT, payload)); }

  close() {
    if (this._closed) return;
    this._closed = true;
    try { this._sendRaw(buildFrame(OPCODE.CLOSE, Buffer.from([0x03, 0xe8]))); } catch {}
    try { this.socket.destroy(); } catch {}
    this.emit('close');
  }
}

// Connect to a ws:// or wss:// URL and complete the WebSocket handshake.
// `headers` are merged into the upgrade request — that's where the bearer
// token goes (Authorization: Bearer …). Resolves with a WsClient.
function connect(targetUrl, { headers = {}, rejectUnauthorized = true } = {}) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(targetUrl); }
    catch (e) { return reject(new Error(`invalid URL: ${targetUrl}`)); }

    const isTls = url.protocol === 'wss:' || url.protocol === 'https:';
    if (!isTls && url.protocol !== 'ws:' && url.protocol !== 'http:') {
      return reject(new Error(`unsupported protocol: ${url.protocol}`));
    }
    const port = url.port ? Number(url.port) : (isTls ? 443 : 80);
    const host = url.hostname;
    const path = (url.pathname || '/') + (url.search || '');
    const key = crypto.randomBytes(16).toString('base64');

    const reqHeaders = {
      Host: url.host,
      Upgrade: 'websocket',
      Connection: 'Upgrade',
      'Sec-WebSocket-Key': key,
      'Sec-WebSocket-Version': '13',
      ...headers
    };
    const reqLines = [`GET ${path} HTTP/1.1`];
    for (const [k, v] of Object.entries(reqHeaders)) reqLines.push(`${k}: ${v}`);
    reqLines.push('', '');
    const req = Buffer.from(reqLines.join('\r\n'));

    const socket = isTls
      ? tls.connect({ host, port, servername: host, rejectUnauthorized })
      : net.connect({ host, port });

    let buf = Buffer.alloc(0);
    let settled = false;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch {}
      reject(err);
    };

    socket.once('error', fail);
    socket.once('close', () => fail(new Error('connection closed before handshake')));
    socket.once(isTls ? 'secureConnect' : 'connect', () => {
      socket.write(req);
    });

    socket.on('data', (chunk) => {
      if (settled) return;
      buf = Buffer.concat([buf, chunk]);
      const headerEnd = buf.indexOf('\r\n\r\n');
      if (headerEnd < 0) {
        if (buf.length > 64 * 1024) fail(new Error('handshake response too large'));
        return;
      }
      const head = buf.slice(0, headerEnd).toString('utf8');
      const remainder = buf.slice(headerEnd + 4);
      const lines = head.split(/\r?\n/);
      const statusLine = lines.shift() || '';
      const statusMatch = statusLine.match(/^HTTP\/\d\.\d\s+(\d{3})\b/);
      const status = statusMatch ? Number(statusMatch[1]) : 0;
      if (status !== 101) {
        // Pull more body for a useful error message
        const body = remainder.toString('utf8').slice(0, 500);
        return fail(new Error(`handshake failed: HTTP ${status}${body ? `: ${body.trim()}` : ''}`));
      }
      const lower = {};
      for (const line of lines) {
        const i = line.indexOf(':');
        if (i < 0) continue;
        lower[line.slice(0, i).toLowerCase().trim()] = line.slice(i + 1).trim();
      }
      const accept = lower['sec-websocket-accept'];
      const expected = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
      if (accept !== expected) {
        return fail(new Error('handshake failed: Sec-WebSocket-Accept mismatch'));
      }
      // Hand off the socket to a WsClient. Re-emit any leftover bytes after
      // the headers so the client parses any frame the server sent immediately.
      socket.removeAllListeners('data');
      socket.removeAllListeners('close');
      socket.removeAllListeners('error');
      settled = true;
      const client = new WsClient(socket, targetUrl);
      resolve(client);
      if (remainder.length) client._onData(remainder);
    });
  });
}

module.exports = { connect, OPCODE };
