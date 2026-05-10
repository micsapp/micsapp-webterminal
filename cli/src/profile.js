// Profile storage for the CLI.
//
//   ~/.mics-webterminal/
//   ├── current               # text file: name of the active profile
//   └── profiles/
//       └── <name>.json       # {token, baseUrl, username, token_name, saved_at}
//
// The legacy single-file `~/.mics-webterminal/auth.json` is migrated into a
// profile on first run via migrateLegacyIfNeeded().
const fs = require('fs');
const os = require('os');
const path = require('path');
const { URL } = require('url');

const ROOT = path.join(os.homedir(), '.mics-webterminal');
const PROFILES_DIR = path.join(ROOT, 'profiles');
const CURRENT_FILE = path.join(ROOT, 'current');
const LEGACY_AUTH_FILE = path.join(ROOT, 'auth.json');

// Profile names are short, filesystem-safe identifiers — kept narrow on
// purpose so they can't collide with path separators or env quirks.
const NAME_RE = /^[a-zA-Z0-9._-]{1,64}$/;

function validateName(name) {
  if (typeof name !== 'string' || !NAME_RE.test(name)) {
    throw new Error(
      `invalid profile name: ${JSON.stringify(name)}. ` +
      `Allowed: letters, digits, dot, underscore, hyphen; max 64 chars.`
    );
  }
}

// Derive a default profile name from a URL — first label of the hostname,
// e.g. "https://dev-ssh.wetigu.com" → "dev-ssh".
function deriveName(baseUrl) {
  try {
    const u = new URL(baseUrl);
    const host = u.hostname;
    const first = host.split('.')[0];
    if (NAME_RE.test(first)) return first;
    const sanitized = host.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 64);
    return sanitized || 'default';
  } catch {
    return 'default';
  }
}

function ensureDirs() {
  fs.mkdirSync(PROFILES_DIR, { recursive: true });
}

function profilePath(name) {
  validateName(name);
  return path.join(PROFILES_DIR, `${name}.json`);
}

function readProfile(name) {
  try {
    return JSON.parse(fs.readFileSync(profilePath(name), 'utf8'));
  } catch {
    return null;
  }
}

function writeProfile(name, state) {
  ensureDirs();
  fs.writeFileSync(profilePath(name), JSON.stringify(state, null, 2), { mode: 0o600 });
}

function deleteProfile(name) {
  try { fs.unlinkSync(profilePath(name)); return true; }
  catch (e) { if (e.code === 'ENOENT') return false; throw e; }
}

function profileExists(name) {
  try { fs.accessSync(profilePath(name)); return true; }
  catch { return false; }
}

function listProfiles() {
  let entries;
  try { entries = fs.readdirSync(PROFILES_DIR); }
  catch { return []; }
  return entries
    .filter(f => f.endsWith('.json'))
    .map(f => f.slice(0, -5))
    .filter(n => NAME_RE.test(n))
    .sort();
}

function getCurrent() {
  try {
    const v = fs.readFileSync(CURRENT_FILE, 'utf8').trim();
    return v && NAME_RE.test(v) ? v : null;
  } catch { return null; }
}

function setCurrent(name) {
  validateName(name);
  ensureDirs();
  fs.writeFileSync(CURRENT_FILE, name + '\n', { mode: 0o600 });
}

function clearCurrent() {
  try { fs.unlinkSync(CURRENT_FILE); } catch {}
}

// One-time migration of the old single-file ~/.mics-webterminal/auth.json
// into a profile. Returns the migrated profile name, or null if there was
// nothing to migrate. Runs at most once because the legacy file is removed
// on success.
function migrateLegacyIfNeeded() {
  let raw;
  try { raw = fs.readFileSync(LEGACY_AUTH_FILE, 'utf8'); }
  catch { return null; }
  let parsed;
  try { parsed = JSON.parse(raw); }
  catch { return null; }
  if (!parsed || (!parsed.token && !parsed.baseUrl)) return null;

  ensureDirs();
  let base = deriveName(parsed.baseUrl || '');
  let name = base;
  let suffix = 1;
  while (profileExists(name)) {
    suffix += 1;
    name = `${base}-${suffix}`;
  }
  writeProfile(name, parsed);
  if (!getCurrent()) setCurrent(name);
  try { fs.unlinkSync(LEGACY_AUTH_FILE); } catch {}
  return name;
}

module.exports = {
  ROOT,
  PROFILES_DIR,
  CURRENT_FILE,
  LEGACY_AUTH_FILE,
  NAME_RE,
  validateName,
  deriveName,
  profilePath,
  readProfile,
  writeProfile,
  deleteProfile,
  profileExists,
  listProfiles,
  getCurrent,
  setCurrent,
  clearCurrent,
  migrateLegacyIfNeeded
};
