const fs = require('fs');
const os = require('os');
const path = require('path');

// ── Minimal .env parser (no dotenv dependency) ─────────────────────────────
// Supports `KEY=value`, `KEY="value"`, `KEY='value'`, comments via `#`, blank
// lines, and trailing comments after unquoted values. Doesn't expand $vars.
function parseEnv(text) {
  const out = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    if (!key) continue;
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    } else {
      const hash = val.indexOf(' #');
      if (hash >= 0) val = val.slice(0, hash).trim();
    }
    out[key] = val;
  }
  return out;
}

function loadEnvFile(filePath) {
  try {
    const text = fs.readFileSync(filePath, 'utf8');
    return parseEnv(text);
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw err;
  }
}

// Walk up from cwd to filesystem root looking for `.env`.
function findEnvFile(startDir) {
  let dir = path.resolve(startDir);
  const root = path.parse(dir).root;
  while (true) {
    const candidate = path.join(dir, '.env');
    if (fs.existsSync(candidate)) return candidate;
    if (dir === root) return null;
    dir = path.dirname(dir);
  }
}

// ── Persisted auth state (~/.mics-webterminal/auth.json) ───────────────────
const AUTH_DIR = path.join(os.homedir(), '.mics-webterminal');
const AUTH_FILE = path.join(AUTH_DIR, 'auth.json');

function readAuthFile() {
  try { return JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8')); } catch { return null; }
}

function writeAuthFile(state) {
  fs.mkdirSync(AUTH_DIR, { recursive: true });
  fs.writeFileSync(AUTH_FILE, JSON.stringify(state, null, 2), { mode: 0o600 });
}

function clearAuthFile() {
  try { fs.unlinkSync(AUTH_FILE); } catch {}
}

// Strip trailing slashes and any "/api" suffix — the server's endpoints
// already start with "/api/...". Storing the bare site root makes it easier
// to reason about and matches how MICS_URL is typically written.
function normalizeBaseUrl(u) {
  return String(u).replace(/\/+$/, '').replace(/\/api$/, '');
}

function loadConfig({ envFile } = {}) {
  const envPath = envFile
    ? path.resolve(envFile)
    : findEnvFile(process.cwd());
  const fileEnv = envPath ? loadEnvFile(envPath) : {};
  const merged = { ...fileEnv, ...process.env };
  const saved = readAuthFile();

  // Resolve token with explicit source tracking so `whoami` can explain.
  let token = '';
  let tokenSource = 'none';
  if (process.env.MICS_TOKEN) {
    token = process.env.MICS_TOKEN;
    tokenSource = 'env';
  } else if (fileEnv.MICS_TOKEN) {
    token = fileEnv.MICS_TOKEN;
    tokenSource = 'env-file';
  } else if (saved && saved.token) {
    token = saved.token;
    tokenSource = 'saved';
  }

  let baseUrl = merged.MICS_URL || (saved && saved.baseUrl) || 'http://localhost';
  baseUrl = normalizeBaseUrl(baseUrl);

  return {
    token,
    tokenSource,
    baseUrl,
    envFilePath: envPath,
    authFilePath: saved ? AUTH_FILE : null,
    savedUsername: saved && saved.username
  };
}

module.exports = {
  loadConfig,
  parseEnv,
  readAuthFile,
  writeAuthFile,
  clearAuthFile,
  normalizeBaseUrl,
  AUTH_FILE
};
