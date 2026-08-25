#!/usr/bin/env node
/**
 * Single-writer for the project version.
 *
 * The number is stated in six places — `src-tauri/tauri.conf.json`,
 * `package.json` and four `Cargo.toml` files — because each of them is read by
 * a different tool and none of them can read another. Tauri stamps its copy
 * into every bundle filename and into the Windows installer metadata; Cargo
 * stamps its copy into `CARGO_PKG_VERSION`, which is what `envv --version` and
 * `envv describe` report.
 *
 * Before this script existed, the only thing keeping the six in agreement was
 * the `meta` job in `.github/workflows/build.yml`, which *detects* drift and
 * cannot *fix* it. Editing five of six by hand produced a release labelled
 * 0.7.0 containing `EnvVault_0.6.0.AppImage`.
 *
 * Usage:
 *
 *   node scripts/version.mjs                 # print the current version
 *   node scripts/version.mjs --check         # exit 1 if the six disagree
 *   node scripts/version.mjs 0.7.0           # set an explicit version
 *   node scripts/version.mjs patch|minor|major
 *
 * Bumping also refreshes `Cargo.lock`, because the lockfile records the version
 * of every workspace member and a stale one fails CI's `--locked` builds with
 * an error that names the resolver rather than this edit.
 *
 * What it deliberately does NOT do: commit, tag or push. Tagging is a release
 * decision, and it is made by pushing to `main` — see the `meta` job in
 * build.yml, which creates `v<version>` only when no such tag exists yet.
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const CRATES = ['src-tauri', 'vault-core', 'envv-server', 'envv-cli'];

// Directory names and crate names differ for exactly one member: the Tauri app
// lives in `src-tauri/` and is published as `envvault`. Cargo.lock keys on the
// crate name, so the two lists cannot be collapsed into one.
const CRATE_NAMES = ['envvault', 'vault-core', 'envv-server', 'envv-cli'];

/** Semver `major.minor.patch`, no pre-release or build metadata. */
const SEMVER = /^(\d+)\.(\d+)\.(\d+)$/;

/**
 * Every file holding a copy of the version, with a reader and a writer.
 *
 * `tauri.conf.json` is first on purpose: it is the source of truth, and
 * `--check` compares everything else against it.
 */
const SOURCES = [
  {
    file: 'src-tauri/tauri.conf.json',
    read: (s) => JSON.parse(s).version,
    // Rewritten textually rather than via JSON.stringify: the file is
    // hand-maintained, and a round-trip would reorder nothing but would
    // reindent and strip the trailing newline conventions Tauri's own tooling
    // writes. Only the one line changes.
    write: (s, v) => replaceOnce(s, /("version"\s*:\s*")([^"]*)(")/, v, 'tauri.conf.json'),
  },
  {
    file: 'package.json',
    read: (s) => JSON.parse(s).version,
    write: (s, v) => replaceOnce(s, /("version"\s*:\s*")([^"]*)(")/, v, 'package.json'),
  },
  ...CRATES.map((c) => ({
    file: `${c}/Cargo.toml`,
    // `head -n1`-equivalent: the first `version = "…"` at column zero is the
    // package's own. A dependency's version is indented or inline in a table,
    // so anchoring to the start of a line is enough to avoid rewriting one.
    read: (s) => firstMatch(s, /^version\s*=\s*"([^"]*)"/m),
    write: (s, v) => replaceOnce(s, /^(version\s*=\s*")([^"]*)(")/m, v, `${c}/Cargo.toml`),
  })),
];

function firstMatch(text, re) {
  const m = re.exec(text);
  return m ? m[1] : null;
}

/**
 * Replace exactly one occurrence, failing loudly if the pattern is absent.
 *
 * A silent no-op here is the whole failure mode this script exists to prevent:
 * five files updated, one missed, and nothing says so until a user downloads a
 * mislabelled installer.
 */
function replaceOnce(text, re, version, label) {
  if (!re.test(text)) {
    throw new Error(`${label}: no version field matched — the file's shape changed`);
  }
  return text.replace(re, (_m, pre, _old, post) => `${pre}${version}${post}`);
}

function read(file) {
  const path = join(ROOT, file);
  if (!existsSync(path)) throw new Error(`missing: ${file}`);
  return readFileSync(path, 'utf8');
}

/** Current versions, as `[{ file, version }]`. */
function survey() {
  return SOURCES.map((s) => ({ file: s.file, version: s.read(read(s.file)) }));
}

/**
 * Verify all six agree with `tauri.conf.json`.
 *
 * @returns {boolean} true when consistent
 */
function check() {
  const found = survey();
  const truth = found[0].version;
  let ok = true;

  if (!truth || !SEMVER.test(truth)) {
    console.error(`error  ${found[0].file}: '${truth}' is not a bare major.minor.patch`);
    ok = false;
  }

  for (const { file, version } of found) {
    if (version === truth) {
      console.log(`  ok   ${file} = ${version}`);
    } else {
      console.error(`  FAIL ${file} = ${version ?? '<not found>'} (expected ${truth})`);
      ok = false;
    }
  }
  return ok;
}

/** Apply `version` to every source file. */
function set(version) {
  if (!SEMVER.test(version)) {
    throw new Error(`'${version}' is not a bare major.minor.patch version`);
  }

  for (const s of SOURCES) {
    const before = read(s.file);
    const after = s.write(before, version);
    if (before !== after) {
      writeFileSync(join(ROOT, s.file), after);
      console.log(`  set  ${s.file} -> ${version}`);
    } else {
      console.log(`  ok   ${s.file} already ${version}`);
    }
  }

  // The lockfile pins each workspace member's version. Left stale, every
  // `cargo build --locked` in CI fails — and it fails inside the resolver,
  // pointing at Cargo.lock rather than at the manifest edit that caused it.
  //
  // Patched textually rather than by shelling out to `cargo`: regenerating the
  // lock needs a resolver run, which needs the registry, which means this
  // script would fail offline and in any sandbox without network — for an edit
  // that only ever touches four lines of a file already in the tree. Only the
  // `version` line inside each workspace member's own `[[package]]` block is
  // rewritten; every third-party pin is left exactly as it is, which is the
  // entire point of committing the lockfile (rand 0.10 and rusqlite 0.39 have
  // both broken this build via semver-compatible updates).
  const lockPath = join(ROOT, 'Cargo.lock');
  if (existsSync(lockPath)) {
    let lock = readFileSync(lockPath, 'utf8');
    let touched = 0;
    for (const crate of CRATE_NAMES) {
      const block = new RegExp(`(\\[\\[package\\]\\]\\nname = "${crate}"\\nversion = ")([^"]*)(")`);
      if (!block.test(lock)) {
        console.warn(`  warn Cargo.lock has no [[package]] entry for ${crate}`);
        continue;
      }
      lock = lock.replace(block, (_m, pre, _old, post) => `${pre}${version}${post}`);
      touched += 1;
    }
    writeFileSync(lockPath, lock);
    console.log(`  set  Cargo.lock (${touched}/${CRATE_NAMES.length} workspace entries)`);
  } else {
    console.warn('  warn Cargo.lock missing — run `cargo metadata` before committing');
  }
}

/** `patch` / `minor` / `major` applied to the current version. */
function bump(kind) {
  const current = survey()[0].version;
  const m = SEMVER.exec(current ?? '');
  if (!m) throw new Error(`current version '${current}' is not semver; cannot bump`);

  let [, major, minor, patch] = m.map(Number);
  if (kind === 'major') [major, minor, patch] = [major + 1, 0, 0];
  else if (kind === 'minor') [minor, patch] = [minor + 1, 0];
  else patch += 1;

  const next = `${major}.${minor}.${patch}`;
  console.log(`${current} -> ${next}`);
  return next;
}

function main() {
  const arg = process.argv[2];

  if (!arg) {
    console.log(survey()[0].version);
    return;
  }
  if (arg === '--check' || arg === 'check') {
    process.exit(check() ? 0 : 1);
  }
  if (['patch', 'minor', 'major'].includes(arg)) {
    set(bump(arg));
    return;
  }
  set(arg.replace(/^v/, ''));
}

try {
  main();
} catch (err) {
  console.error(`error: ${err.message}`);
  process.exit(1);
}
