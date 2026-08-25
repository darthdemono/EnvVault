#!/usr/bin/env node
/**
 * Runs Doxygen with the project version injected.
 *
 * The Doxyfile reads `PROJECT_NUMBER = $(ENVVAULT_VERSION)`. Setting that
 * inline (`ENVVAULT_VERSION=… doxygen`) is shell syntax this project cannot
 * rely on — the primary shell here is PowerShell, where it is a syntax error.
 * Spawning from Node sets the variable the same way on every platform.
 *
 * The alternative — writing the number into the Doxyfile — would make it a
 * seventh copy of a value that already lives in six places, which is the exact
 * problem scripts/version.mjs exists to solve.
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const version = execFileSync(process.execPath, [join(ROOT, 'scripts', 'version.mjs')], {
  encoding: 'utf8',
}).trim();

const r = spawnSync('doxygen', ['Doxyfile'], {
  cwd: ROOT,
  stdio: 'inherit',
  env: { ...process.env, ENVVAULT_VERSION: version },
});

if (r.error) {
  // ENOENT here means doxygen is not installed, which is worth saying plainly:
  // the raw spawn error names the syscall, not the missing program.
  console.error(
    r.error.code === 'ENOENT'
      ? 'error: doxygen not found on PATH. Install it (dnf install doxygen graphviz) or run `npm run docs:rust` for the Rust half only.'
      : `error: ${r.error.message}`,
  );
  process.exit(1);
}
process.exit(r.status ?? 1);
