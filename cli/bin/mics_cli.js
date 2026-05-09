#!/usr/bin/env node
require('../src/index.js').run(process.argv.slice(2)).catch((err) => {
  process.stderr.write(`error: ${err.message || err}\n`);
  process.exit(1);
});
