const fs = require('fs');
const path = require('path');

class ApiError extends Error {
  constructor(status, body) {
    const msg = (body && body.error) || (typeof body === 'string' && body) || `HTTP ${status}`;
    super(`${status}: ${msg}`);
    this.status = status;
    this.body = body;
  }
}

function buildClient({ token, baseUrl }) {
  if (typeof fetch !== 'function') {
    throw new Error('Node 18+ is required (global fetch is missing)');
  }

  function authHeaders(extra = {}) {
    if (!token) {
      throw new Error(
        'MICS_TOKEN is not set. Run `mics_cli login` to mint one, or create a token '
        + 'from the webterminal UI and add `MICS_TOKEN=agt_…` to your .env file.'
      );
    }
    return { Authorization: `Bearer ${token}`, ...extra };
  }

  async function request(method, urlPath, { headers, body, query, raw, noAuth } = {}) {
    let url = `${baseUrl}${urlPath}`;
    if (query) {
      const qs = new URLSearchParams(
        Object.fromEntries(Object.entries(query).filter(([, v]) => v !== undefined && v !== null && v !== ''))
      ).toString();
      if (qs) url += `?${qs}`;
    }
    const init = {
      method,
      headers: noAuth ? (headers || {}) : authHeaders(headers || {})
    };
    if (body !== undefined) {
      if (Buffer.isBuffer(body)) {
        init.body = body;
      } else {
        init.body = typeof body === 'string' ? body : JSON.stringify(body);
        if (!init.headers['Content-Type']) {
          init.headers['Content-Type'] = 'application/json';
        }
      }
    }

    const res = await fetch(url, init);
    if (raw) {
      if (!res.ok) {
        let parsed = null;
        try { parsed = await res.json(); } catch {}
        throw new ApiError(res.status, parsed);
      }
      return res;
    }

    const text = await res.text();
    let parsed = null;
    if (text) {
      try { parsed = JSON.parse(text); }
      catch { parsed = text; }
    }
    if (!res.ok) throw new ApiError(res.status, parsed);
    return parsed;
  }

  return {
    // ── Shell exec ──────────────────────────────────────────────────────────
    exec({ command, timeout, cwd, stdin }) {
      const body = { command };
      if (timeout !== undefined) body.timeout = timeout;
      if (cwd !== undefined) body.cwd = cwd;
      if (stdin !== undefined) body.stdin = stdin;
      return request('POST', '/api/exec', { body });
    },

    // ── Files ───────────────────────────────────────────────────────────────
    listFiles(p) { return request('GET', '/api/files/list', { query: { path: p } }); },
    readFile(p)  { return request('GET', '/api/files/read', { query: { path: p } }); },

    async downloadFile(p) {
      const res = await request('GET', '/api/files/download', { query: { path: p }, raw: true });
      const cd = res.headers.get('content-disposition') || '';
      const m = cd.match(/filename\*?="?([^";]+)"?/i);
      const filename = m ? decodeURIComponent(m[1]) : path.basename(p);
      const buf = Buffer.from(await res.arrayBuffer());
      return { buffer: buf, filename };
    },

    async uploadFile(localFile, remoteDir, remoteName) {
      const absPath = path.resolve(localFile);
      const buf = fs.readFileSync(absPath);
      const name = remoteName || path.basename(absPath);
      return request('POST', '/api/files/upload', {
        query: { path: remoteDir, name },
        body: buf,
        headers: { 'Content-Type': 'application/octet-stream' }
      });
    },

    mkdir(p) {
      return request('POST', '/api/files/mkdir', { body: { path: p } });
    },

    deleteFile(p) {
      return request('POST', '/api/files/delete', { body: { path: p } });
    },

    // ── Tokens ──────────────────────────────────────────────────────────────
    listTokens() { return request('GET', '/api/tokens'); },
    revokeToken(name) { return request('POST', '/api/tokens/revoke', { body: { name } }); },

    // ── Quick commands ──────────────────────────────────────────────────────
    listQuickCommands()      { return request('GET', '/api/quick-commands'); },
    exportQuickCommands()    { return request('GET', '/api/quick-commands/export'); },
    importQuickCommands(arr, mode) {
      return request('POST', '/api/quick-commands/import', { body: { commands: arr, mode } });
    },

    // ── Login (no bearer; uses session cookie) ──────────────────────────────
    // Returns { cookie, port } where cookie is the raw "name=value" pair.
    async loginPassword(username, password) {
      const url = `${baseUrl}/api/login`;
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const text = await res.text();
      let parsed = null;
      try { parsed = text ? JSON.parse(text) : null; } catch { parsed = text; }
      if (!res.ok) throw new ApiError(res.status, parsed);
      const setCookie = res.headers.get('set-cookie') || '';
      // Take the first "name=value" pair only (the rest is attributes).
      const cookie = setCookie.split(';')[0].trim();
      if (!cookie || cookie.indexOf('=') < 0) {
        throw new Error('login response did not include a session cookie');
      }
      return { cookie, port: parsed && parsed.port };
    },

    // Mints a long-lived bearer token using the session cookie from loginPassword().
    async mintToken(cookie, name) {
      const url = `${baseUrl}/api/tokens`;
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: cookie },
        body: JSON.stringify({ name })
      });
      const text = await res.text();
      let parsed = null;
      try { parsed = text ? JSON.parse(text) : null; } catch { parsed = text; }
      if (!res.ok) throw new ApiError(res.status, parsed);
      if (!parsed || !parsed.token) throw new Error('mint response missing token');
      return parsed.token;
    },

    // ── Auth probe (used by login --token to validate before saving) ────────
    async probeAuth() {
      const url = `${baseUrl}/api/auth`;
      const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
      if (!res.ok) throw new ApiError(res.status, null);
      return true;
    }
  };
}

module.exports = { buildClient, ApiError };
