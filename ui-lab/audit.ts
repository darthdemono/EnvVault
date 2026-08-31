/**
 * Mechanical layout defects, measured in a real browser.
 *
 * The 887-test Vitest suite runs in jsdom, which has **no layout engine**: every
 * `offsetWidth` is 0, no stylesheet is applied, nothing has a position. So it
 * cannot see a clipped label, a button pushed off the panel, or a control that
 * overlaps another — the entire class of bug that a person notices in one glance
 * and a unit test never notices at all.
 *
 * This runs inside Chromium against the real stylesheets, and it *measures*
 * rather than eyeballs. A screenshot needs a human to interpret it; a rule that
 * says "this element's content is 40px wider than its box and nothing clips or
 * scrolls it" is a bug report with a selector attached.
 */

/** One measured defect, with enough context to find it in the source. */
export interface LayoutFinding {
  rule: string;
  selector: string;
  detail: string;
  text: string;
}

/**
 * The audit, as a string so it can be handed to `page.evaluate`.
 *
 * It is written as a single self-contained function on purpose: Playwright
 * serialises it into the page, where none of this module's imports exist.
 */
export const AUDIT_FN = `() => {
  const findings = [];
  const seen = new Set();

  const sel = (el) => {
    if (el.id) return '#' + el.id;
    const cls = (el.className && typeof el.className === 'string')
      ? '.' + el.className.trim().split(/\\s+/).slice(0, 3).join('.')
      : '';
    let path = el.tagName.toLowerCase() + cls;
    const p = el.parentElement;
    if (p && p !== document.body) {
      const pid = p.id ? '#' + p.id : p.tagName.toLowerCase();
      path = pid + ' > ' + path;
    }
    return path;
  };
  const label = (el) => (el.textContent || '').trim().replace(/\\s+/g, ' ').slice(0, 60);
  const visible = (el) => {
    const s = getComputedStyle(el);
    if (s.display === 'none' || s.visibility === 'hidden' || s.opacity === '0') return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  };
  const add = (rule, el, detail) => {
    const key = rule + '|' + sel(el) + '|' + detail;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({ rule, selector: sel(el), detail, text: label(el) });
  };

  // ── 1. The page itself must never scroll sideways ─────────────────────────
  // A desktop app that needs a horizontal scrollbar at its own minimum window
  // size has a layout that does not fit the window it ships with.
  const de = document.documentElement;
  if (de.scrollWidth > de.clientWidth + 1) {
    findings.push({
      rule: 'page-h-overflow',
      selector: 'html',
      detail: 'document scrollWidth ' + de.scrollWidth + ' > viewport ' + de.clientWidth,
      text: '',
    });
  }

  const all = [...document.querySelectorAll('body *')].filter(visible);

  for (const el of all) {
    const s = getComputedStyle(el);
    const r = el.getBoundingClientRect();

    // ── 2. Content wider than its box, with nothing to reveal it ───────────
    // Either it scrolls, or it ellipsises, or the user simply cannot read it.
    const overX = el.scrollWidth - el.clientWidth;
    if (overX > 1 && el.clientWidth > 0) {
      const scrolls = s.overflowX === 'auto' || s.overflowX === 'scroll';
      const ellipsis = s.textOverflow === 'ellipsis';
      if (!scrolls && !ellipsis) {
        add('content-clipped-x', el, overX + 'px of content is unreachable (overflow-x: ' + s.overflowX + ')');
      }
    }

    // ── 3. Same, vertically, but only where it is actually hidden ──────────
    // Visible overflow is usually intentional (a dropdown, a shadow); hidden
    // overflow with more content than box is text nobody can read.
    const overY = el.scrollHeight - el.clientHeight;
    if (overY > 1 && s.overflowY === 'hidden' && el.clientHeight > 0) {
      add('content-clipped-y', el, overY + 'px of content is cut off below the fold of this box');
    }

    // ── 4. Painted outside the window ──────────────────────────────────────
    if (r.width > 0 && (r.right < -1 || r.left > de.clientWidth + 1)) {
      add('offscreen-x', el, 'rect x ' + Math.round(r.left) + '..' + Math.round(r.right) + ' vs viewport 0..' + de.clientWidth);
    }

    // ── 5. Interactive controls that are too small to hit ──────────────────
    // 24×24 CSS px is the WCAG 2.2 minimum. Below that it is a target you miss.
    const interactive = el.matches('button, a[href], input, select, textarea, [role="button"], [data-action]');
    if (interactive) {
      if (r.width < 24 || r.height < 24) {
        add('target-too-small', el, Math.round(r.width) + '×' + Math.round(r.height) + ' (minimum 24×24)');
      }
      // ── 6. A control with no accessible name ─────────────────────────────
      const name = (el.getAttribute('aria-label') || el.getAttribute('title') || label(el) ||
                    el.getAttribute('alt') || el.getAttribute('placeholder') || '').trim();
      if (!name) add('control-unnamed', el, 'no text, aria-label, title, alt or placeholder');
    }
  }

  // ── 7. Interactive controls sitting on top of each other ──────────────────
  // Whichever is on top wins every click; the other is unreachable and looks fine.
  const controls = all.filter((el) =>
    el.matches('button, a[href], input, select, [role="button"]') &&
    el.getBoundingClientRect().width > 0);
  for (let i = 0; i < controls.length; i++) {
    for (let j = i + 1; j < controls.length; j++) {
      const a = controls[i], b = controls[j];
      if (a.contains(b) || b.contains(a)) continue;
      const ra = a.getBoundingClientRect(), rb = b.getBoundingClientRect();
      const ox = Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left);
      const oy = Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top);
      if (ox > 4 && oy > 4) {
        add('controls-overlap', a, 'overlaps ' + sel(b) + ' by ' + Math.round(ox) + '×' + Math.round(oy) + 'px');
      }
    }
  }

  return findings;
}`;
