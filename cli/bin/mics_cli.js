#!/usr/bin/env node
// Exit cleanly when piped into `head`, `less | q`, etc. — Node's default is
// to throw on EPIPE writes, which surfaces as a stack trace.
process.stdout.on('error', (err) => { if (err && err.code === 'EPIPE') process.exit(0); });
process.stderr.on('error', (err) => { if (err && err.code === 'EPIPE') process.exit(0); });

require('../src/index.js').run(process.argv.slice(2)).catch((err) => {
  process.stderr.write(`error: ${err.message || err}\n`);
  process.exit(1);
});
