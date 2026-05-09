// Tiny argv parser. Supports: --flag, --key=value, --key value, -k, --no-flag,
// and positional args. `boolFlags` lists keys that don't take a value.
function parseArgs(argv, { boolFlags = [], aliases = {} } = {}) {
  const out = { _: [] };
  const isBool = (k) => boolFlags.includes(k);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') {
      out._.push(...argv.slice(i + 1));
      break;
    }
    if (a.startsWith('--')) {
      let key, val;
      if (a.includes('=')) {
        [key, ...val] = a.slice(2).split('=');
        val = val.join('=');
      } else {
        key = a.slice(2);
        if (key.startsWith('no-') && isBool(key.slice(3))) {
          out[key.slice(3)] = false;
          continue;
        }
        if (isBool(key)) {
          out[key] = true;
          continue;
        }
        val = argv[++i];
        if (val === undefined) throw new Error(`missing value for --${key}`);
      }
      out[key] = val;
    } else if (a.startsWith('-') && a.length > 1) {
      const short = a.slice(1);
      const key = aliases[short] || short;
      if (isBool(key)) { out[key] = true; continue; }
      const val = argv[++i];
      if (val === undefined) throw new Error(`missing value for -${short}`);
      out[key] = val;
    } else {
      out._.push(a);
    }
  }
  return out;
}

module.exports = { parseArgs };
