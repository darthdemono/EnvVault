/**
 * @file Global test setup — fills the gaps between jsdom and WebKitGTK.
 *
 * jsdom implements neither `matchMedia` (read at module load by `state.ts`) nor
 * clipboard/`execCommand`, so importing the real modules would throw before a
 * single assertion ran. Everything stubbed here is stubbed because production
 * code touches it on import, not to make tests pass.
 */
import { beforeEach, vi } from 'vitest';

// `state.ts` calls this at module scope to follow the OS colour scheme.
if (!window.matchMedia) {
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })) as any;
}

// Node 22 provides webcrypto, but `randomUUID` is absent from jsdom's shim in
// some versions and `generateULID` / `newEntryId` depend on both.
if (!globalThis.crypto?.randomUUID) {
  Object.defineProperty(globalThis.crypto ?? {}, 'randomUUID', {
    value: () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    }),
    configurable: true,
  });
}

// `clipboardWrite` prefers the async API and falls back to `execCommand`.
if (!navigator.clipboard) {
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
    configurable: true,
  });
}
if (!document.execCommand) {
  (document as any).execCommand = vi.fn().mockReturnValue(true);
}

// jsdom has no layout engine; several render paths read these before painting.
if (!Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = () => {};
}

beforeEach(() => {
  // Each test owns a clean document; fixtures re-populate what they need.
  document.body.innerHTML = '';
  document.documentElement.removeAttribute('data-theme');
  sessionStorage.clear();
  localStorage.clear();
});
