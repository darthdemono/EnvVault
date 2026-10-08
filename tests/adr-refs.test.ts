import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const sourceRoots = ['src/ts', 'vault-core', 'envv-cli', 'envv-server', 'src-tauri'];

function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? files(path) : [path];
  });
}

describe('public ADR references', () => {
  it('point to an existing accepted record', () => {
    const records = new Map(
      files(join(root, 'book/src/adr'))
        .filter((path) => /^\d{4}-.*\.md$/.exec(path.split('/').pop() ?? '') !== null)
        .map((path) => {
          const text = readFileSync(path, 'utf8');
          return [/^# ADR-(\d{4}):/m.exec(text)?.[1], text] as const;
        })
        .filter(([id]) => id),
    );
    const references = sourceRoots
      .flatMap((dir) => files(join(root, dir)))
      .flatMap((path) => [...readFileSync(path, 'utf8').matchAll(/ADR-(\d{4})/g)].map((m) => m[1]));

    for (const id of references) {
      const record = records.get(id);
      expect(record, `ADR-${id} has no public record`).toBeTruthy();
      expect(record, `ADR-${id} is superseded`).not.toMatch(/^Status: superseded$/m);
    }
  });
});
