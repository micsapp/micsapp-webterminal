const fs = require('fs');
const path = require('path');
const profileMod = require('./profile');

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

// Strip trailing slashes and any "/api" suffix — the server's endpoints
// already start with "/api/...". Storing the bare site root makes it easier
// to reason about and matches how MICS_URL is typically written.
function normalizeBaseUrl(u) {
  return String(u).replace(/\/+$/, '').replace(/\/api$/, '');
}

// Has the migration banner already been printed in this process? loadConfig
// is called more than once per invocation (cmdLogin re-loads with --env-file
// overrides), so guard against double-printing.
let _migrationAnnounced = false;

function loadConfig({ envFile, profile } = {}) {
  // One-time migration of the legacy ~/.mics-webterminal/auth.json into a
  // profile. After a successful migration the legacy file is gone, so this
  // is a no-op on every subsequent run.
  const migrated = profileMod.migrateLegacyIfNeeded();
  if (migrated && !_migrationAnnounced) {
    _migrationAnnounced = true;
    process.stderr.write(
      `migrated ~/.mics-webterminal/auth.json → profiles/${migrated}.json\n`
    );
  }

  const envPath = envFile
    ? path.resolve(envFile)
    : findEnvFile(process.cwd());
  const fileEnv = envPath ? loadEnvFile(envPath) : {};
  const merged = { ...fileEnv, ...process.env };

  // Resolve which profile (if any) is in play. --profile flag wins over env
  // var, which wins over the persisted `current` pointer. Invalid names from
  // env / current are silently ignored — the user can fix them with `use`.
  let profileName = profile || process.env.MICS_PROFILE || profileMod.getCurrent();
  if (profileName) {
    try { profileMod.validateName(profileName); }
    catch { profileName = null; }
  }
  const profileState = profileName ? profileMod.readProfile(profileName) : null;
  const profileSource = profile ? 'flag' : (process.env.MICS_PROFILE ? 'env' : (profileState ? 'current' : null));

  // Token: env > .env > profile.
  let token = '';
  let tokenSource = 'none';
  if (process.env.MICS_TOKEN) {
    token = process.env.MICS_TOKEN;
    tokenSource = 'env';
  } else if (fileEnv.MICS_TOKEN) {
    token = fileEnv.MICS_TOKEN;
    tokenSource = 'env-file';
  } else if (profileState && profileState.token) {
    token = profileState.token;
    tokenSource = 'profile';
  }

  // Base URL: env > .env > profile > default.
  let baseUrl = merged.MICS_URL || (profileState && profileState.baseUrl) || 'http://localhost';
  baseUrl = normalizeBaseUrl(baseUrl);

  return {
    token,
    tokenSource,
    baseUrl,
    envFilePath: envPath,
    profileName: profileState ? profileName : null,
    profileSource,
    savedUsername: profileState && profileState.username,
    profilesDir: profileMod.PROFILES_DIR
  };
}

module.exports = {
  loadConfig,
  parseEnv,
  normalizeBaseUrl
};
