import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  esc, escAttr, maskKey, hexAlpha, generateULID,
  showToast, showConfirm, showPrompt, showPasswordPrompt, clipboardWrite, execCopy,
} from '../src/ts/utils';
import { loadRealIndexHtml } from './helpers';

describe('esc', () => {
  it('neutralises a script tag', () => {
    expect(esc('<script>alert(1)</script>')).toBe('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('escapes the ampersand before anything else, so entities are not double-decoded', () => {
    expect(esc('&lt;')).toBe('&amp;lt;');
  });

  it('returns an empty string for null and undefined', () => {
    expect(esc(null)).toBe('');
    expect(esc(undefined)).toBe('');
  });

  it('stringifies non-string input', () => {
    expect(esc(42)).toBe('42');
    expect(esc(false)).toBe('false');
  });

  it('round-trips through the DOM as the original text', () => {
    const el = document.createElement('div');
    const raw = '<img src=x onerror=alert(1)> & "quoted"';
    el.innerHTML = esc(raw);
    expect(el.querySelector('img')).toBeNull();
    expect(el.textContent).toBe(raw);
  });
});

describe('escAttr', () => {
  it('escapes both quote styles so an attribute cannot be broken out of', () => {
    expect(escAttr(`" onload="alert(1)`)).toBe('&quot; onload=&quot;alert(1)');
    expect(escAttr("' onload='alert(1)")).toBe('&#39; onload=&#39;alert(1)');
  });

  it('preserves a literal &amp; through a data-attribute round trip', () => {
    // Regression: `&` was left raw, so a secret containing the text "&amp;"
    // came back out of data-value as "&" and copy-to-clipboard returned the
    // wrong secret.
    const secret = 'key&amp;value&more';
    const el = document.createElement('div');
    el.innerHTML = `<span data-value="${escAttr(secret)}"></span>`;
    expect(el.querySelector('span')!.getAttribute('data-value')).toBe(secret);
  });

  it('does not let an injected attribute become a real one', () => {
    const el = document.createElement('div');
    el.innerHTML = `<span data-value="${escAttr('x" onmouseover="steal()')}"></span>`;
    const span = el.querySelector('span')!;
    expect(span.hasAttribute('onmouseover')).toBe(false);
    expect(span.getAttribute('data-value')).toBe('x" onmouseover="steal()');
  });

  it('returns an empty string for null', () => {
    expect(escAttr(null)).toBe('');
  });
});

describe('maskKey', () => {
  it('shows an em dash for an empty value', () => {
    expect(maskKey('')).toBe('—');
  });

  it('fully masks a short value, leaking only its length', () => {
    expect(maskKey('12345678')).toBe('••••••••');
  });

  it('reveals the first and last four characters of a long value', () => {
    const masked = maskKey('sk-live-ABCDEFGHIJKLMNOP');
    expect(masked.startsWith('sk-l')).toBe(true);
    expect(masked.endsWith('MNOP')).toBe(true);
    expect(masked).not.toContain('EFGH');
  });

  it('never emits the full secret for a value over the threshold', () => {
    const secret = 'a'.repeat(9);
    expect(maskKey(secret)).not.toBe(secret);
  });
});

describe('hexAlpha', () => {
  it('converts a hex colour to rgba with the given alpha', () => {
    expect(hexAlpha('#ff8800', 0.5)).toBe('rgba(255,136,0,0.5)');
  });

  it('handles black and white ends of the range', () => {
    expect(hexAlpha('#000000', 1)).toBe('rgba(0,0,0,1)');
    expect(hexAlpha('#ffffff', 0)).toBe('rgba(255,255,255,0)');
  });
});

describe('generateULID', () => {
  it('produces a 26-character Crockford base32 identifier', () => {
    expect(generateULID()).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
  });

  it('does not collide across a burst of calls', () => {
    const ids = new Set(Array.from({ length: 500 }, generateULID));
    expect(ids.size).toBe(500);
  });

  it('sorts lexicographically in creation order', () => {
    const first = generateULID();
    vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 60_000);
    const later = generateULID();
    expect(later > first).toBe(true);
  });
});

describe('showToast', () => {
  beforeEach(loadRealIndexHtml);
  afterEach(() => vi.useRealTimers());

  it('writes the message as text, not as markup', () => {
    showToast('<b>hi</b>');
    const el = document.getElementById('toast')!;
    expect(el.textContent).toBe('<b>hi</b>');
    expect(el.querySelector('b')).toBeNull();
  });

  it('applies the type as a class alongside show', () => {
    showToast('saved', 'err');
    expect(document.getElementById('toast')!.className).toBe('show err');
  });

  it('clears itself after the duration', () => {
    vi.useFakeTimers();
    showToast('bye', '', 1000);
    expect(document.getElementById('toast')!.className).toBe('show');
    vi.advanceTimersByTime(1000);
    expect(document.getElementById('toast')!.className).toBe('');
  });

  it('restarts the timer when a second toast interrupts the first', () => {
    vi.useFakeTimers();
    showToast('first', '', 1000);
    vi.advanceTimersByTime(900);
    showToast('second', '', 1000);
    vi.advanceTimersByTime(900);
    // The first toast's timer must not clear the second one early.
    expect(document.getElementById('toast')!.textContent).toBe('second');
    expect(document.getElementById('toast')!.className).toBe('show');
  });
});

describe('showConfirm', () => {
  beforeEach(loadRealIndexHtml);

  it('opens the overlay with the message and resolves true on OK', async () => {
    const p = showConfirm('Delete this key?');
    const overlay = document.getElementById('confirm-overlay')!;
    expect(overlay.classList.contains('open')).toBe(true);
    expect(document.getElementById('confirm-message')!.textContent).toBe('Delete this key?');
    document.getElementById('confirm-ok')!.click();
    await expect(p).resolves.toBe(true);
    expect(overlay.classList.contains('open')).toBe(false);
  });

  it('resolves false on Cancel', async () => {
    const p = showConfirm('sure?');
    document.getElementById('confirm-cancel')!.click();
    await expect(p).resolves.toBe(false);
  });

  it('resolves false on Escape and true on Enter', async () => {
    const esc = showConfirm('a');
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await expect(esc).resolves.toBe(false);

    const enter = showConfirm('b');
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
    await expect(enter).resolves.toBe(true);
  });

  it('treats a backdrop click as cancel but ignores clicks inside the dialog', async () => {
    const p = showConfirm('a');
    document.getElementById('confirm-message')!.click();
    // Still open: an inner click must not dismiss.
    expect(document.getElementById('confirm-overlay')!.classList.contains('open')).toBe(true);
    document.getElementById('confirm-overlay')!.click();
    await expect(p).resolves.toBe(false);
  });

  it('removes its key listener once resolved, so a later Escape is inert', async () => {
    const p = showConfirm('a');
    document.getElementById('confirm-ok')!.click();
    await p;
    // A leaked listener would resolve an unrelated later dialog.
    const second = showConfirm('b');
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
    await expect(second).resolves.toBe(true);
    expect(document.getElementById('confirm-overlay')!.classList.contains('open')).toBe(false);
  });
});

describe('showPrompt', () => {
  beforeEach(loadRealIndexHtml);

  it('seeds the input with the default value and returns the edited text', async () => {
    const p = showPrompt('Name?', 'preset');
    const input = document.getElementById('prompt-input') as HTMLInputElement;
    expect(input.value).toBe('preset');
    input.value = 'edited';
    document.getElementById('prompt-ok')!.click();
    await expect(p).resolves.toBe('edited');
  });

  it('trims surrounding whitespace', async () => {
    const p = showPrompt('Name?');
    (document.getElementById('prompt-input') as HTMLInputElement).value = '  spaced  ';
    document.getElementById('prompt-ok')!.click();
    await expect(p).resolves.toBe('spaced');
  });

  it('returns null for an all-whitespace answer', async () => {
    const p = showPrompt('Name?');
    (document.getElementById('prompt-input') as HTMLInputElement).value = '   ';
    document.getElementById('prompt-ok')!.click();
    await expect(p).resolves.toBeNull();
  });

  it('returns null on cancel and on Escape', async () => {
    const cancelled = showPrompt('a');
    document.getElementById('prompt-cancel')!.click();
    await expect(cancelled).resolves.toBeNull();

    const escaped = showPrompt('b');
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await expect(escaped).resolves.toBeNull();
  });
});

describe('showPasswordPrompt', () => {
  beforeEach(loadRealIndexHtml);

  it('masks the input', async () => {
    const p = showPasswordPrompt('Master password');
    expect((document.getElementById('prompt-input') as HTMLInputElement).type).toBe('password');
    document.getElementById('prompt-cancel')!.click();
    await p;
  });

  it('preserves leading and trailing spaces, which are legal in a password', async () => {
    const p = showPasswordPrompt('Master password');
    (document.getElementById('prompt-input') as HTMLInputElement).value = '  pw  ';
    document.getElementById('prompt-ok')!.click();
    await expect(p).resolves.toBe('  pw  ');
  });

  it('restores the input to type=text so the next plain prompt is not masked', async () => {
    const pw = showPasswordPrompt('secret');
    document.getElementById('prompt-cancel')!.click();
    await pw;
    const plain = showPrompt('Name?');
    expect((document.getElementById('prompt-input') as HTMLInputElement).type).not.toBe('password');
    document.getElementById('prompt-cancel')!.click();
    await plain;
  });
});

describe('clipboard', () => {
  beforeEach(loadRealIndexHtml);

  it('prefers the async clipboard API', async () => {
    const spy = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue(undefined);
    await clipboardWrite('secret');
    expect(spy).toHaveBeenCalledWith('secret');
  });

  it('falls back to execCommand when the async API rejects', async () => {
    // navigator.clipboard silently fails in the Tauri WebView on Linux, which
    // is the whole reason the fallback exists.
    vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValue(new Error('denied'));
    const exec = vi.spyOn(document, 'execCommand').mockReturnValue(true);
    await clipboardWrite('secret');
    expect(exec).toHaveBeenCalledWith('copy');
  });

  it('leaves no textarea behind after execCopy', async () => {
    vi.spyOn(document, 'execCommand').mockReturnValue(true);
    await execCopy('secret');
    expect(document.querySelectorAll('textarea[style*="-9999px"]')).toHaveLength(0);
  });

  it('removes the scratch textarea even when the copy throws', async () => {
    vi.spyOn(document, 'execCommand').mockImplementation(() => { throw new Error('nope'); });
    const before = document.querySelectorAll('textarea').length;
    await expect(execCopy('secret')).rejects.toThrow();
    expect(document.querySelectorAll('textarea').length).toBe(before);
  });
});
