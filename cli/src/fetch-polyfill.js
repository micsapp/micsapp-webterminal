// Minimal global fetch() polyfill for Node 16 (the runtime used by the
// portable Linux build, see build_cli_portable.sh). On Node 18+ this file
// is a no-op since globalThis.fetch already exists.
//
// We implement only the subset api.js uses:
//   fetch(url, { method, headers, body })
//   res.ok, res.status, res.statusText
//   res.headers.get(name)
//   res.text(), res.json(), res.arrayBuffer()
//
// Built on Node's `http`/`https` so the CLI keeps zero npm runtime deps.

if (typeof globalThis.fetch !== 'function') {
  const http = require('http');
  const https = require('https');
  const { URL } = require('url');

  class FetchHeaders {
    constructor(raw) {
      this._raw = {};
      if (raw && typeof raw === 'object') {
        for (const [k, v] of Object.entries(raw)) {
          this._raw[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
        }
      }
    }
    get(name) {
      return this._raw[String(name).toLowerCase()] ?? null;
    }
  }

  class FetchResponse {
    constructor({ status, statusText, headers, bodyBuf }) {
      this.status = status;
      this.statusText = statusText || '';
      this.ok = status >= 200 && status < 300;
      this.headers = new FetchHeaders(headers);
      this._bodyBuf = bodyBuf;
    }
    async arrayBuffer() {
      // Return a fresh ArrayBuffer slice so the caller can detach it safely.
      const b = this._bodyBuf;
      const ab = new ArrayBuffer(b.length);
      new Uint8Array(ab).set(b);
      return ab;
    }
    async text() {
      return this._bodyBuf.toString('utf8');
    }
    async json() {
      const txt = this._bodyBuf.toString('utf8');
      return txt ? JSON.parse(txt) : null;
    }
  }

  function doRequest(urlStr, init = {}) {
    return new Promise((resolve, reject) => {
      let u;
      try { u = new URL(urlStr); } catch (e) { reject(e); return; }
      const lib = u.protocol === 'https:' ? https : http;
      const method = (init.method || 'GET').toUpperCase();

      const headers = {};
      if (init.headers) {
        for (const [k, v] of Object.entries(init.headers)) headers[k] = v;
      }

      let bodyBuf = null;
      if (init.body !== undefined && init.body !== null) {
        if (Buffer.isBuffer(init.body)) {
          bodyBuf = init.body;
        } else if (typeof init.body === 'string') {
          bodyBuf = Buffer.from(init.body, 'utf8');
        } else {
          bodyBuf = Buffer.from(String(init.body), 'utf8');
        }
        if (headers['Content-Length'] === undefined && headers['content-length'] === undefined) {
          headers['Content-Length'] = String(bodyBuf.length);
        }
      }

      const req = lib.request({
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        method,
        headers
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          resolve(new FetchResponse({
            status: res.statusCode,
            statusText: res.statusMessage,
            headers: res.headers,
            bodyBuf: Buffer.concat(chunks)
          }));
        });
        res.on('error', reject);
      });

      req.on('error', reject);
      if (bodyBuf) req.write(bodyBuf);
      req.end();
    });
  }

  globalThis.fetch = doRequest;
}
