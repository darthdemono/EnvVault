// Static guards for the CI/release workflows (roadmap R02). GitHub Actions cannot
// run on a laptop, so what can be proven here is the shape that makes the
// guarantees true: a release needs the CI gate, Docker tags move only after the
// smoke test, every new validator carries a control that must fail, and nothing
// third-party is referenced by a mutable tag.
import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import { describe, expect, it } from 'vitest';

const root = path.resolve(__dirname, '..');
type Step = {
  name?: string;
  uses?: string;
  run?: string;
  with?: Record<string, unknown>;
  if?: string;
};
type Job = {
  needs?: string | string[];
  uses?: string;
  steps?: Step[];
  if?: string;
  with?: Record<string, unknown>;
};
type Workflow = {
  on: Record<string, unknown>;
  jobs: Record<string, Job>;
  concurrency?: Record<string, unknown>;
};

function load(name: string): Workflow {
  return yaml.load(fs.readFileSync(path.join(root, '.github/workflows', name), 'utf8')) as Workflow;
}
const needs = (j: Job): string[] => (Array.isArray(j.needs) ? j.needs : j.needs ? [j.needs] : []);
/** Every job a job depends on, directly or not. */
function ancestors(w: Workflow, id: string, seen = new Set<string>()): Set<string> {
  for (const n of needs(w.jobs[id])) {
    if (!seen.has(n)) {
      seen.add(n);
      ancestors(w, n, seen);
    }
  }
  return seen;
}

describe('the release gate', () => {
  const build = load('build.yml');
  const ci = load('ci.yml');

  it('calls ci.yml as a job of the same run', () => {
    expect(build.jobs.ci.uses).toBe('./.github/workflows/ci.yml');
    expect(build.jobs.ci.with).toEqual({ gate: true });
    expect(Object.keys(ci.on)).toContain('workflow_call');
  });

  it('is needed, directly or not, by everything that builds or publishes', () => {
    for (const id of ['desktop', 'headless', 'docker', 'release']) {
      expect(ancestors(build, id).has('ci'), `${id} must depend on ci`).toBe(true);
    }
  });

  it('release names the gate and every build job on its own needs line', () => {
    expect(needs(build.jobs.release).sort()).toEqual([
      'ci',
      'desktop',
      'docker',
      'headless',
      'meta',
    ]);
  });

  it('keeps the gate run apart from the push-triggered CI run, and never cancels it', () => {
    const c = ci.concurrency as { group: string; 'cancel-in-progress': string };
    expect(c.group).toContain('inputs.gate');
    expect(c['cancel-in-progress']).toContain('!inputs.gate');
  });

  it('has no job called by the gate that asks for more than read access', () => {
    const text = fs.readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8');
    expect(text).not.toMatch(/(contents|packages|id-token|pages): write/);
  });
});

describe('the Docker image', () => {
  const steps = load('build.yml').jobs.docker.steps as Step[];
  // Match command lines, not prose: a comment that mentions `docker push` is not a push.
  const at = (re: RegExp): number => steps.findIndex((s) => re.test(s.run ?? ''));

  it('is built without pushing, then smoke-tested, then pushed', () => {
    const build = steps.find((s) => s.uses?.startsWith('docker/build-push-action'));
    expect(build?.with?.push).toBe(false);
    expect(build?.with?.load).toBe(true);
    const smoke = at(/^\s*docker run --rm --entrypoint unv-server/m);
    const push = at(/^\s*docker push /m);
    expect(smoke).toBeGreaterThan(steps.indexOf(build as Step));
    expect(push).toBeGreaterThan(smoke);
    expect(steps[push].if).toContain("publish == 'true'");
  });

  it('pushes the version, the minor line and latest, and nothing else', () => {
    const run = steps[at(/^\s*docker push /m)].run as string;
    expect(run).toContain('outputs.version');
    expect(run).toContain('outputs.minor');
    expect(run).toContain('latest');
  });
});

describe('Windows no longer pays for the same work twice', () => {
  const ci = load('ci.yml');
  const text = fs.readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8');

  it('splits test from lint, so they run side by side', () => {
    expect(Object.keys(ci.jobs)).toEqual(expect.arrayContaining(['test', 'lint', 'frontend']));
    expect(needs(ci.jobs.lint)).not.toContain('test');
  });

  it('has no separate cargo check of the workspace (clippy --all-targets covers it)', () => {
    expect(text).not.toMatch(/cargo check --workspace/);
    expect(text).toMatch(/cargo clippy --workspace --locked --all-targets/);
  });

  it('installs cargo-deny as a pinned prebuilt binary, not from source', () => {
    expect(text).not.toMatch(/cargo install cargo-deny/);
    expect(text).toMatch(/cargo-deny@0\.\d+\.\d+/);
  });
});

describe('exporter validators', () => {
  const ex = load('exporters.yml');
  const text = fs.readFileSync(path.join(root, '.github/workflows/exporters.yml'), 'utf8');

  it('has wireguard, nginx and compose jobs', () => {
    for (const id of ['wireguard', 'nginx', 'compose']) expect(ex.jobs[id], id).toBeDefined();
  });

  it('proves each new validator can fail, with a control that must be refused', () => {
    for (const id of ['wireguard', 'nginx', 'compose']) {
      const body = JSON.stringify(ex.jobs[id].steps);
      expect(body, `${id} needs a control`).toMatch(/proves nothing/);
    }
  });

  it('triggers on the same paths for push and pull request, and every non-glob path exists', () => {
    const on = ex.on as { push: { paths: string[] }; pull_request: { paths: string[] } };
    expect(on.pull_request.paths).toEqual(on.push.paths);
    for (const p of on.push.paths) {
      if (p.includes('*')) {
        expect(fs.existsSync(path.join(root, p.replace(/\/?\*\*?$/, ''))), p).toBe(true);
      } else {
        expect(fs.existsSync(path.join(root, p)), p).toBe(true);
      }
    }
    for (const must of [
      'unv-cli/src/exporters.rs',
      'unv-cli/src/chunks.rs',
      'unv-cli/src/refs.rs',
      'vault-core/src/config_check.rs',
      'src/ts/chunks/**',
    ]) {
      expect(on.push.paths).toContain(must);
    }
    expect(text).toContain('proves nothing');
  });
});

describe('pinning', () => {
  const files = [
    ...fs.readdirSync(path.join(root, '.github/workflows')).map((f) => `.github/workflows/${f}`),
    '.github/actions/rust-setup/action.yml',
  ];

  it('references every third-party action by a full commit SHA with a version comment', () => {
    const loose: string[] = [];
    for (const f of files) {
      for (const line of fs.readFileSync(path.join(root, f), 'utf8').split('\n')) {
        const m = /^\s*-?\s*uses:\s*(\S+)(.*)$/.exec(line);
        if (!m || m[1].startsWith('./')) continue;
        if (!/@[0-9a-f]{40}$/.test(m[1]) || !/#\s*\S+/.test(m[2]))
          loose.push(`${f}: ${line.trim()}`);
      }
    }
    expect(loose).toEqual([]);
  });

  it('uses no action that still runs on Node 20 (checked at the time of the bump)', () => {
    const text = files.map((f) => fs.readFileSync(path.join(root, f), 'utf8')).join('\n');
    // The pre-bump releases of the actions that moved to Node 24.
    for (const old of [
      'actions/checkout@11bd71901',
      'actions/setup-node@49933ea52',
      'actions/upload-artifact@ea165f8d6',
      'actions/download-artifact@d3f86a106',
      'docker/build-push-action@263435318',
      'Swatinem/rust-cache@bc2d2e71b',
    ]) {
      expect(text, old).not.toContain(old);
    }
  });
});

describe('schedules and Dependabot', () => {
  it('rebuilds the docs weekly, not nightly', () => {
    const docs = load('docs.yml');
    const cron = (docs.on.schedule as { cron: string }[])[0].cron;
    expect(cron.split(' ').slice(2, 5)).toEqual(['*', '*', '1']);
  });

  const dep = yaml.load(fs.readFileSync(path.join(root, '.github/dependabot.yml'), 'utf8')) as {
    updates: {
      'package-ecosystem': string;
      groups?: Record<string, unknown>;
      ignore?: { 'dependency-name': string; 'update-types'?: string[] }[];
      directory?: string;
      directories?: string[];
    }[];
  };
  const eco = (n: string) => dep.updates.find((u) => u['package-ecosystem'] === n);

  it('groups the families that must move together', () => {
    expect(Object.keys(eco('npm')?.groups ?? {})).toEqual(
      expect.arrayContaining(['vitest', 'tauri', 'lint']),
    );
    expect(Object.keys(eco('cargo')?.groups ?? {})).toEqual(
      expect.arrayContaining(['tauri', 'rustcrypto']),
    );
    expect(eco('github-actions')?.groups).toBeDefined();
  });

  it('keeps the format-sensitive crates off the automatic upgrade path', () => {
    const ignored = eco('cargo')?.ignore ?? [];
    for (const name of ['rusqlite', 'libsqlite3-sys', 'argon2']) {
      const rule = ignored.find((i) => i['dependency-name'] === name);
      expect(rule?.['update-types'], name).toContain('version-update:semver-major');
    }
  });

  it('never sets both directory and directories on one ecosystem', () => {
    for (const u of dep.updates)
      expect(Boolean(u.directory) && Boolean(u.directories), u['package-ecosystem']).toBe(false);
  });
});
