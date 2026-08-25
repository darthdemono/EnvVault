import { describe, it, expect, beforeEach } from 'vitest';
import { loadRealIndexHtml } from '../tests/helpers';
import { Settings, applyGridSettings } from '../src/ts/state';

describe('grid columns', () => {
  beforeEach(() => { loadRealIndexHtml(); });

  it('offers the new counts in the segmented control', () => {
    const vals = [...document.querySelectorAll('#s-grid-cols button')]
      .map(b => (b as HTMLElement).dataset.val);
    expect(vals).toEqual(['auto', '2', '3', '4', '5', '6', '8']);
  });

  it('an explicit column count floors at 0 so it cannot overflow sideways', () => {
    Settings.set('gridColumns', '8');
    Settings.set('cardSize', 'large');
    applyGridSettings();
    const grid = document.getElementById('card-grid')!;
    // 8 * 460px would demand 3680px of track and scroll the workspace.
    expect(grid.style.gridTemplateColumns).toBe('repeat(8, minmax(0, 1fr))');
  });

  it('auto still floors at the card width, but never wider than the viewport', () => {
    Settings.set('gridColumns', 'auto');
    Settings.set('cardSize', 'medium');
    applyGridSettings();
    const grid = document.getElementById('card-grid')!;
    expect(grid.style.gridTemplateColumns).toContain('min(100%, 360px)');
  });
});
