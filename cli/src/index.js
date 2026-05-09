const fs = require('fs');
const os = require('os');
const path = require('path');
const { loadConfig, writeAuthFile, clearAuthFile, normalizeBaseUrl, AUTH_FILE } = require('./config');
const { buildClient, ApiError } = require('./api');
const { parseArgs } = require('./args');

const VERSION = require('../package.json').version;

const HELP = `mics_cli — command-line client for micsapp-webterminal

Usage:
  mics_cli <command> [options]

Commands:
  exec <command>             Run a shell command remotely (POST /api/exec)
  ls [path]                  List files in a directory
  cat <path>                 Print a text file's contents
  download <path>            Download a file
  upload <local> <remote-dir>
                             Upload a local file to a remote directory
  mkdir <path>               Create a directory
  rm <path>                  Delete a file or directory (recursive)
  tokens list                List your bearer tokens
  tokens revoke <name>       Revoke a bearer token by name
  quick-commands list        List your saved quick commands
  quick-commands export      Export quick commands as JSON
  quick-commands import <f>  Import quick commands from a JSON file
  login                      Log in with username/password (mints a bearer token)
  logout                     Forget the saved token
  whoami                     Show which token / url is in use
  help [command]             Show help for a command
  version                    Print CLI version

Global options:
  --env-file <path>          Load env from a specific file (default: walk up from cwd)
  --token <t>                Override MICS_TOKEN
  --url <baseurl>            Override MICS_URL (e.g. https://term.example.com)
  --json                     Print raw JSON output where applicable
  -h, --help                 Show help

Configuration via .env (in cwd or any parent directory):
  MICS_TOKEN=agt_...         Required. Mint with \`mics_cli login\` or via the UI.
  MICS_URL=https://...       Required. Site root, with or without /api suffix.

Run \`mics_cli help <command>\` for detailed usage.
`;

const COMMAND_HELP = {
  exec: `mics_cli exec <command> [options]

Runs <command> via \`bash -c\` on the remote server and prints stdout/stderr.
Exit code matches the remote command's exit code.

Options:
  --timeout <n>          Max seconds (1–300, default 30)
  --cwd <path>           Working directory on the server (default: ~)
  --stdin <text>         String to pipe to stdin (or use --stdin-file)
  --stdin-file <path>    Read stdin from a local file
  --json                 Print raw JSON {stdout, stderr, exit_code}

Examples:
  mics_cli exec "uname -a"
  mics_cli exec "wc -l" --stdin-file ./big.log
  mics_cli exec "cat /etc/hostname" --json
`,
  ls: `mics_cli ls [path] [--json]

Defaults to your home directory. Output: type, size, mtime, name.
`,
  cat: `mics_cli cat <path> [-o file] [--json]

Prints the file's text contents. Files >8MB are rejected by the server.
Use \`mics_cli download\` for binary files.
`,
  download: `mics_cli download <path> [options]

Options:
  -o, --output <file>    Output filename (default: derived from server path)
`,
  upload: `mics_cli upload <local> <remote-dir> [options]

Uploads <local> into <remote-dir> on the server. Max 40MB per file.

Options:
  --name <text>          Override the destination filename
  --json                 Print raw JSON response
`,
  mkdir: `mics_cli mkdir <path>

Creates a directory at <path>. Fails if it already exists.
`,
  rm: `mics_cli rm <path>

Deletes a file or recursively deletes a directory. There is no undo.
`,
  tokens: `mics_cli tokens <subcommand>

Subcommands:
  list                       List your bearer tokens (name, created_at, last_used)
  revoke <name>              Revoke a token by its display name
`,
  'quick-commands': `mics_cli quick-commands <subcommand>

Subcommands:
  list                       List your saved quick commands
  export [-o file]           Export as JSON (stdout, or to file via -o)
  import <file> [--mode m]   Import from a JSON file. mode is 'merge' (default) or 'replace'.
`,
  whoami: `mics_cli whoami

Prints the configured base URL, env file path, saved auth path, and which
source the active token came from (flag / env / env-file / saved).
`,
  login: `mics_cli login [options]

Logs in with your webterminal username/password and mints a bearer token,
saved to ~/.mics-webterminal/auth.json (mode 0600).

Options:
  --username <name>      Login username (otherwise prompted)
  --password <pw>        Login password (otherwise prompted, hidden)
  --url <baseurl>        Base URL (defaults to MICS_URL or saved). Trailing
                         /api is stripped automatically.
  --name <text>          Display name for the minted token (default:
                         "mics_cli@<hostname> YYYY-MM-DD")

Already have a bearer token? Skip the username/password flow:
  --token <agt_…>        Save this token directly (validated against
                         /api/auth unless --no-validate is given)
  --no-validate          Skip the validation request when using --token

Token resolution priority (highest first):
  1. --token flag (on any command)
  2. MICS_TOKEN env var
  3. .env file (cwd or any parent)
  4. ~/.mics-webterminal/auth.json
`,
  logout: `mics_cli logout

Removes ~/.mics-webterminal/auth.json. Does not touch any .env files.
`
};

function printJson(obj) { process.stdout.write(JSON.stringify(obj, null, 2) + '\n'); }
function out(s) { process.stdout.write(s + '\n'); }
function err(s) { process.stderr.write(s + '\n'); }

function buildContext(flags) {
  const cfg = loadConfig({ envFile: flags['env-file'] });
  if (flags.token) cfg.token = flags.token;
  if (flags.url) cfg.baseUrl = normalizeBaseUrl(flags.url);
  return { cfg, api: buildClient(cfg) };
}

// ── Commands ─────────────────────────────────────────────────────────────────

async function cmdExec(rest) {
  const f = parseArgs(rest, { boolFlags: ['json'] });
  const command = f._.join(' ').trim();
  if (!command) throw new Error('exec requires a command: mics_cli exec "<cmd>"');

  let stdin = f.stdin;
  if (f['stdin-file']) {
    stdin = fs.readFileSync(path.resolve(f['stdin-file']), 'utf8');
  }
  const timeout = f.timeout !== undefined ? parseInt(f.timeout, 10) : undefined;

  const { api } = buildContext(f);
  const res = await api.exec({ command, timeout, cwd: f.cwd, stdin });

  if (f.json) { printJson(res); }
  else {
    if (res.stdout) process.stdout.write(res.stdout.endsWith('\n') ? res.stdout : res.stdout + '\n');
    if (res.stderr) process.stderr.write(res.stderr.endsWith('\n') ? res.stderr : res.stderr + '\n');
  }
  // Mirror the remote exit code so shell pipelines work as expected.
  if (typeof res.exit_code === 'number' && res.exit_code !== 0) {
    process.exit(res.exit_code);
  }
}

function formatBytes(n) {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}K`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)}M`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)}G`;
}

async function cmdLs(rest) {
  const f = parseArgs(rest, { boolFlags: ['json'] });
  const target = f._[0];
  const { api } = buildContext(f);
  const res = await api.listFiles(target);
  if (f.json) return printJson(res);
  out(res.path);
  if (!res.entries || !res.entries.length) { out('(empty)'); return; }
  for (const e of res.entries) {
    const tag = e.type === 'dir' ? 'd' : (e.link ? 'l' : '-');
    const size = e.type === 'dir' ? '-' : formatBytes(e.size || 0);
    const mtime = e.mtime ? new Date(e.mtime * 1000).toISOString().slice(0, 16).replace('T', ' ') : '';
    out(`${tag}  ${size.padStart(7)}  ${mtime}  ${e.name}`);
  }
}

async function cmdCat(rest) {
  const f = parseArgs(rest, { boolFlags: ['json'], aliases: { o: 'output' } });
  const p = f._[0];
  if (!p) throw new Error('cat requires a path: mics_cli cat <path>');
  const { api } = buildContext(f);
  const res = await api.readFile(p);
  if (f.json) return printJson(res);
  if (!res.is_text) throw new Error('file is not text; use `mics_cli download` instead');
  if (f.output) {
    fs.writeFileSync(path.resolve(f.output), res.content);
    out(`wrote ${res.size} bytes to ${f.output}`);
  } else {
    process.stdout.write(res.content);
    if (!res.content.endsWith('\n')) process.stdout.write('\n');
  }
}

async function cmdDownload(rest) {
  const f = parseArgs(rest, { aliases: { o: 'output' } });
  const p = f._[0];
  if (!p) throw new Error('download requires a path: mics_cli download <path>');
  const { api } = buildContext(f);
  const { buffer, filename } = await api.downloadFile(p);
  const outPath = path.resolve(f.output || filename || path.basename(p));
  fs.writeFileSync(outPath, buffer);
  out(`wrote ${buffer.length} bytes to ${outPath}`);
}

async function cmdUpload(rest) {
  const f = parseArgs(rest, { boolFlags: ['json'] });
  const local = f._[0];
  const remoteDir = f._[1];
  if (!local || !remoteDir) {
    throw new Error('upload requires <local> and <remote-dir>: mics_cli upload <local> <remote-dir>');
  }
  if (!fs.existsSync(local)) throw new Error(`local file not found: ${local}`);
  const { api } = buildContext(f);
  const res = await api.uploadFile(local, remoteDir, f.name);
  if (f.json) return printJson(res);
  out(`uploaded → ${res.path} (${res.size} bytes)`);
}

async function cmdMkdir(rest) {
  const f = parseArgs(rest, { boolFlags: ['json'] });
  const p = f._[0];
  if (!p) throw new Error('mkdir requires a path: mics_cli mkdir <path>');
  const { api } = buildContext(f);
  const res = await api.mkdir(p);
  if (f.json) return printJson(res);
  out(`created ${res.path}`);
}

async function cmdRm(rest) {
  const f = parseArgs(rest, { boolFlags: ['json', 'yes'] });
  const p = f._[0];
  if (!p) throw new Error('rm requires a path: mics_cli rm <path>');
  if (!f.yes && process.stdin.isTTY) {
    const ok = (await promptLine(`Delete ${p}? (y/N) `)).trim().toLowerCase();
    if (ok !== 'y' && ok !== 'yes') { out('aborted'); return; }
  }
  const { api } = buildContext(f);
  const res = await api.deleteFile(p);
  if (f.json) return printJson(res);
  out(`deleted ${p}`);
}

async function cmdTokens(rest) {
  const sub = rest[0];
  if (!sub) throw new Error('tokens requires a subcommand: list | revoke');
  const subRest = rest.slice(1);

  if (sub === 'list') {
    const f = parseArgs(subRest, { boolFlags: ['json'] });
    const { api } = buildContext(f);
    const res = await api.listTokens();
    if (f.json) return printJson(res);
    const tokens = res.tokens || [];
    if (!tokens.length) { out('(no tokens)'); return; }
    for (const t of tokens) {
      const created = t.created_at ? new Date(t.created_at * 1000).toISOString().slice(0, 16).replace('T', ' ') : '';
      const used = t.last_used ? new Date(t.last_used * 1000).toISOString().slice(0, 16).replace('T', ' ') : '(never)';
      out(`${t.name}\n  created: ${created}\n  last used: ${used}`);
    }
    return;
  }

  if (sub === 'revoke' || sub === 'rm' || sub === 'delete') {
    const f = parseArgs(subRest, { boolFlags: ['json'] });
    const name = f._[0];
    if (!name) throw new Error('tokens revoke requires a token name');
    const { api } = buildContext(f);
    await api.revokeToken(name);
    out(`revoked ${name}`);
    return;
  }

  throw new Error(`unknown tokens subcommand: ${sub}\nrun \`mics_cli help tokens\` for usage.`);
}

async function cmdQuickCommands(rest) {
  const sub = rest[0];
  if (!sub) throw new Error('quick-commands requires a subcommand: list | export | import');
  const subRest = rest.slice(1);

  if (sub === 'list') {
    const f = parseArgs(subRest, { boolFlags: ['json'] });
    const { api } = buildContext(f);
    const res = await api.listQuickCommands();
    if (f.json) return printJson(res);
    const cmds = res.commands || res.list || res || [];
    const arr = Array.isArray(cmds) ? cmds : (Array.isArray(res) ? res : []);
    if (!arr.length) { out('(no quick commands)'); return; }
    for (const c of arr) {
      out(`${c.name || '(unnamed)'}\n  ${c.command || ''}`);
    }
    return;
  }

  if (sub === 'export') {
    const f = parseArgs(subRest, { aliases: { o: 'output' } });
    const { api } = buildContext(f);
    const res = await api.exportQuickCommands();
    const json = JSON.stringify(res, null, 2);
    if (f.output) {
      fs.writeFileSync(path.resolve(f.output), json);
      out(`wrote ${json.length} bytes to ${f.output}`);
    } else {
      process.stdout.write(json + '\n');
    }
    return;
  }

  if (sub === 'import') {
    const f = parseArgs(subRest, { boolFlags: ['json'] });
    const file = f._[0];
    if (!file) throw new Error('quick-commands import requires a JSON file path');
    const text = fs.readFileSync(path.resolve(file), 'utf8');
    let payload;
    try { payload = JSON.parse(text); }
    catch (e) { throw new Error(`invalid JSON in ${file}: ${e.message}`); }
    // Accept either a bare array or {commands: [...]}.
    const arr = Array.isArray(payload) ? payload : (payload.commands || []);
    if (!Array.isArray(arr) || !arr.length) throw new Error('no commands found in input file');
    const { api } = buildContext(f);
    const res = await api.importQuickCommands(arr, f.mode || 'merge');
    if (f.json) return printJson(res);
    out(`imported ${arr.length} command${arr.length === 1 ? '' : 's'}`);
    return;
  }

  throw new Error(`unknown quick-commands subcommand: ${sub}`);
}

async function cmdWhoami(rest) {
  const f = parseArgs(rest);
  const { cfg } = buildContext(f);
  let source = cfg.tokenSource || 'none';
  if (f.token) source = 'flag';
  out(`base url:   ${cfg.baseUrl}`);
  out(`env file:   ${cfg.envFilePath || '(none found)'}`);
  out(`auth file:  ${AUTH_FILE}`);
  out(`token src:  ${source}`);
  out(`token:      ${cfg.token ? cfg.token.slice(0, 8) + '…' : '(not set)'}`);
  if (cfg.savedUsername) out(`username:   ${cfg.savedUsername}`);
}

// Visible-input prompt — used for usernames, confirmations.
function promptLine(question) {
  return new Promise((resolve, reject) => {
    process.stdout.write(question);
    const stdin = process.stdin;
    if (!stdin.isTTY) {
      let buf = '';
      stdin.on('data', (chunk) => { buf += chunk.toString(); });
      stdin.on('end', () => resolve((buf.split(/\r?\n/)[0] || '')));
      stdin.on('error', reject);
      return;
    }
    stdin.resume();
    let buf = '';
    const onData = (data) => {
      const s = data.toString('utf8');
      const nl = s.indexOf('\n');
      if (nl >= 0) {
        buf += s.slice(0, nl).replace(/\r$/, '');
        stdin.pause();
        stdin.removeListener('data', onData);
        resolve(buf);
        return;
      }
      buf += s;
    };
    stdin.on('data', onData);
  });
}

// Hidden-input prompt — used for passwords / tokens.
function promptHidden(question) {
  return new Promise((resolve, reject) => {
    process.stdout.write(question);
    const stdin = process.stdin;
    if (!stdin.isTTY) {
      let buf = '';
      stdin.on('data', (chunk) => { buf += chunk.toString(); });
      stdin.on('end', () => resolve(buf.replace(/[\r\n]+$/, '')));
      stdin.on('error', reject);
      return;
    }
    stdin.setRawMode(true);
    stdin.resume();
    let buf = '';
    const onData = (data) => {
      const s = data.toString('utf8');
      for (const ch of s) {
        const code = ch.charCodeAt(0);
        if (ch === '\n' || ch === '\r') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener('data', onData);
          process.stdout.write('\n');
          resolve(buf);
          return;
        }
        if (code === 3) { // Ctrl-C
          stdin.setRawMode(false);
          stdin.pause();
          process.stdout.write('\n');
          reject(new Error('aborted'));
          return;
        }
        if (code === 8 || code === 127) buf = buf.slice(0, -1);
        else buf += ch;
      }
    };
    stdin.on('data', onData);
  });
}

function warnIfShadowed(cfgPre) {
  if (process.env.MICS_TOKEN) {
    err(
      `\nwarning: MICS_TOKEN is set in your shell environment — it takes priority\n`
      + `         over the saved token. Unset it (\`unset MICS_TOKEN\`) or the\n`
      + `         saved token won't be used.`
    );
  } else if (cfgPre.tokenSource === 'env-file' && cfgPre.envFilePath) {
    err(
      `\nwarning: MICS_TOKEN is set in ${cfgPre.envFilePath} — it takes priority\n`
      + `         over the saved token. Remove it from .env or the saved token\n`
      + `         won't be used. Run \`mics_cli whoami\` to see which is active.`
    );
  }
}

async function cmdLogin(rest) {
  const f = parseArgs(rest, { boolFlags: ['no-validate'] });
  const { loadConfig } = require('./config');
  const cfgPre = loadConfig({ envFile: f['env-file'] });
  const baseUrl = normalizeBaseUrl(f.url || cfgPre.baseUrl);
  if (!baseUrl) throw new Error('login requires --url or MICS_URL set in your environment');

  // ── Path 1: --token escape hatch (save an existing bearer token directly).
  if (f.token) {
    const token = f.token;
    if (!f['no-validate']) {
      const api = buildClient({ token, baseUrl });
      try { await api.probeAuth(); }
      catch (e) {
        const msg = e instanceof ApiError ? e.message : (e.message || String(e));
        throw new Error(`token validation failed: ${msg}`);
      }
    }
    writeAuthFile({ token, baseUrl, saved_at: new Date().toISOString() });
    out(`saved to  ${AUTH_FILE}`);
    out(`base url: ${baseUrl}`);
    out(`token:    ${token.slice(0, 8)}…`);
    warnIfShadowed(cfgPre);
    return;
  }

  // ── Path 2 (default): username/password → mint a bearer token.
  let username = f.username || f.user;
  if (!username) username = (await promptLine('Username: ')).trim();
  if (!username) throw new Error('login requires a username');

  // Don't trim — leading/trailing whitespace may be intentional.
  const password = f.password !== undefined ? f.password : await promptHidden('Password: ');
  if (!password) throw new Error('password is required');

  const api = buildClient({ token: '__placeholder__', baseUrl });
  let session;
  try {
    session = await api.loginPassword(username, password);
  } catch (e) {
    if (e instanceof ApiError) throw new Error(`login failed (HTTP ${e.status}): ${e.body && e.body.error || 'check username/password'}`);
    throw new Error(`could not reach ${baseUrl}/api/login: ${e.message}`);
  }

  const tokenName = f.name || `mics_cli@${os.hostname()} ${new Date().toISOString().slice(0, 10)}`;
  let secretToken;
  try {
    secretToken = await api.mintToken(session.cookie, tokenName);
  } catch (e) {
    if (e instanceof ApiError) {
      throw new Error(`failed to mint token (HTTP ${e.status}): ${e.body && e.body.error || ''}`);
    }
    throw e;
  }

  writeAuthFile({
    token: secretToken,
    baseUrl,
    username,
    token_name: tokenName,
    saved_at: new Date().toISOString()
  });
  out(`logged in as ${username}`);
  out(`saved to  ${AUTH_FILE}`);
  out(`base url: ${baseUrl}`);
  out(`token:    ${secretToken.slice(0, 8)}…  (name: ${tokenName})`);
  warnIfShadowed(cfgPre);
}

async function cmdLogout() {
  clearAuthFile();
  out(`removed ${AUTH_FILE}`);
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

const COMMANDS = {
  exec: cmdExec,
  ls: cmdLs,
  list: cmdLs,
  cat: cmdCat,
  download: cmdDownload,
  upload: cmdUpload,
  mkdir: cmdMkdir,
  rm: cmdRm,
  delete: cmdRm,
  tokens: cmdTokens,
  'quick-commands': cmdQuickCommands,
  qc: cmdQuickCommands,
  login: cmdLogin,
  logout: cmdLogout,
  whoami: cmdWhoami
};

// Global flags accepted before the command; lifted out and appended to the
// command's own argv so `mics_cli --url X exec foo` and `mics_cli exec foo
// --url X` behave identically.
const GLOBAL_VALUE_FLAGS = new Set(['--token', '--url', '--env-file']);
const GLOBAL_BOOL_FLAGS = new Set(['--json']);

function liftGlobalFlags(argv) {
  const lifted = [];
  let i = 0;
  while (i < argv.length) {
    const a = argv[i];
    if (a === '--') break;
    if (GLOBAL_BOOL_FLAGS.has(a)) { lifted.push(a); i += 1; continue; }
    const eq = a.indexOf('=');
    const head = eq >= 0 ? a.slice(0, eq) : a;
    if (GLOBAL_VALUE_FLAGS.has(head)) {
      if (eq >= 0) { lifted.push(a); i += 1; }
      else { lifted.push(a, argv[i + 1]); i += 2; }
      continue;
    }
    break;
  }
  return { lifted, rest: argv.slice(i) };
}

async function run(rawArgv) {
  const { lifted, rest: argv } = liftGlobalFlags(rawArgv);

  if (!argv.length || argv[0] === '-h' || argv[0] === '--help' || argv[0] === 'help') {
    if (argv[1] && COMMAND_HELP[argv[1]]) {
      out(COMMAND_HELP[argv[1]]);
    } else {
      out(HELP);
    }
    return;
  }
  if (argv[0] === '--version' || argv[0] === '-v' || argv[0] === 'version') {
    out(`mics_cli ${VERSION}`);
    return;
  }

  const [cmd, ...subArgv] = argv;
  const rest = subArgv.concat(lifted);
  const handler = COMMANDS[cmd];
  if (!handler) {
    throw new Error(`unknown command: ${cmd}\nrun \`mics_cli help\` for usage.`);
  }

  if (rest.includes('-h') || rest.includes('--help')) {
    out(COMMAND_HELP[cmd] || HELP);
    return;
  }

  try {
    await handler(rest);
  } catch (e) {
    if (e instanceof ApiError) {
      throw new Error(e.message);
    }
    throw e;
  }
}

module.exports = { run };
