/**
 * The three collapsed-card bands — description, tags, footer — are each clamped
 * to a whole number of their own rows. Getting that arithmetic wrong does not
 * fail loudly; it slices a line of text or a row of chips through the middle,
 * which is what these assertions exist to catch.
 *
 * jsdom has no layout engine, so these read the stylesheet rather than measuring
 * boxes. That is enough to pin the specific mistake that was made: the tag clamp
 * was computed from --cs-row-h (19px, the badge row) while a chip is --cs-tag-h
 * (17px), so the ceiling fell 4px inside the second row.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cards = readFileSync(join(root, 'src/css/cards.css'), 'utf8');
const tools = readFileSync(join(root, 'src/css/activity-tools.css'), 'utf8');

const block = (css: string, selector: string) => {
  const i = css.indexOf(selector + ' {');
  expect(i, `${selector} not found`).toBeGreaterThan(-1);
  return css.slice(i, css.indexOf('}', i));
};

describe('collapsed card sections', () => {
  it('the description ceiling is a whole number of line boxes', () => {
    const b = block(cards, '.card-apidesc');
    expect(b).toContain('max-height: calc(var(--cs-desc-line) * var(--cs-desc-lines))');
    // Without the clamp the ceiling would cut a line rather than ellipsise it.
    expect(b).toContain('-webkit-line-clamp: var(--cs-desc-lines)');
    // content-box: the padding must not eat the third line.
    expect(b).toContain('box-sizing: content-box');
  });

  it('every card size fits at least three lines of description', () => {
    const lines = [...cards.matchAll(/--cs-desc-lines:\s*(\d+)/g)].map(m => Number(m[1]));
    expect(lines.length).toBeGreaterThanOrEqual(3);
    expect(Math.min(...lines)).toBeGreaterThanOrEqual(3);
  });

  it('expanding lifts the description ceiling, not just the clamp', () => {
    // Leaving max-height on would hide the rest with no ellipsis to say so.
    expect(block(cards, '.card.expanded .card-apidesc')).toContain('max-height: none');
  });

  it('the tag clamp is computed from the chip height, not the badge row height', () => {
    const b = block(tools, '.card-tags');
    expect(b).toContain('--cs-tag-h');
    // The regression: 19px + 6px = 25px, which lands 4px inside a 17px second row.
    expect(b).not.toContain('--cs-row-h');
  });

  it('the chip declares the height the clamp assumes', () => {
    expect(block(tools, '.tag-chip-card')).toContain('height: var(--cs-tag-h');
  });
});
