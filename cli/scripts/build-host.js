#!/usr/bin/env node
// Build a single binary for the current OS/arch using @yao-pkg/pkg.
// pkg ships prebuilt Node runtimes for node18/20/22 only, so we pin to node20
// (current LTS) and resolve platform/arch from process.* for cross-platform
// support of the `npm run build` script.
const { spawnSync } = require('child_process');
const path = require('path');

const platMap = { darwin: 'macos', win32: 'win', linux: 'linux' };
const archMap = { x64: 'x64', arm64: 'arm64' };

const platform = platMap[process.platform];
const arch = archMap[process.arch];
if (!platform) {
  console.error(`unsupported host platform: ${process.platform}`);
  process.exit(1);
}
if (!arch) {
  console.error(`unsupported host arch: ${process.arch} (pkg only ships x64/arm64)`);
  process.exit(1);
}

const target = `node20-${platform}-${arch}`;
const outFile = path.join(__dirname, '..', 'dist', process.platform === 'win32' ? 'mics_cli.exe' : 'mics_cli');
const pkgBin = path.join(__dirname, '..', 'node_modules', '.bin', process.platform === 'win32' ? 'pkg.cmd' : 'pkg');

console.log(`building for ${target} → ${outFile}`);
const res = spawnSync(pkgBin, ['.', '--targets', target, '--output', outFile], {
  stdio: 'inherit',
  cwd: path.join(__dirname, '..')
});
process.exit(res.status ?? 1);
