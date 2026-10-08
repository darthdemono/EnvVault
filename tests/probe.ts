/**
 * Shared by the efficacy probes (Phase 32 / 32.1): did a user-visible thing
 * change after an action? Two signals, because each misses what the other sees:
 * a `MutationObserver` sees a write of identical text (a repeated error line),
 * a snapshot sees a control's current `.value` / `.checked`, which are
 * properties and so are not in `innerHTML`.
 */
export function snapshot(): string {
  const state = Array.from(document.querySelectorAll('input, textarea, select'))
    .map((el) => {
      const f = el as HTMLInputElement;
      return `${f.id}=${f.value}|${f.checked}|${f.disabled}`;
    })
    .join('\n');
  // Inline style is layout churn, except `display` / `visibility`, which is how
  // half this app shows an error line or opens a section.
  const html = document.body.innerHTML.replace(/ style="([^"]*)"/g, (_m, css: string) => {
    const keep = css.match(/(?:display|visibility)\s*:\s*[a-z-]+/g);
    return keep ? ` style="${keep.join(';')}"` : '';
  });
  return html + state;
}

/** Clear what a previous probe left showing, so it cannot look like this one's effect. */
export function clearTransient(): void {
  const toast = document.getElementById('toast');
  if (toast) {
    toast.className = '';
    toast.textContent = '';
  }
  // Status lines (`.tool-status`) keep the last message; two probes that end in
  // the same one would otherwise make the second look silent.
  document.querySelectorAll('.tool-status').forEach((el) => {
    el.textContent = '';
    el.className = 'tool-status';
  });
  document.querySelectorAll('.open').forEach((el) => el.classList.remove('open'));
}

/** Run `act`, wait for async effects, and say whether anything visibly changed. */
export async function hadEffect(act: () => void, waitMs = 60): Promise<boolean> {
  const before = snapshot();
  const watcher = new MutationObserver(() => {});
  watcher.observe(document.body, {
    subtree: true,
    childList: true,
    attributes: true,
    characterData: true,
  });
  act();
  await new Promise((r) => setTimeout(r, waitMs));
  const wrote = watcher.takeRecords().length > 0;
  watcher.disconnect();
  return wrote || snapshot() !== before;
}

export interface KindReport {
  targets: number;
  kinds: number;
  /** Every control kind found, so a coverage gap is visible, not just a silent one. */
  reached: string[];
  silent: string[];
  partial: string[];
  threw: string[];
}

/**
 * Click up to `sample` instances of every control kind matched by `selector`
 * (kind = its `data-action`), each on a freshly prepared page, and report which
 * kinds had no visible effect at all. A kind is silent only when NO sampled
 * instance did anything: some instances are legitimately inert (the first
 * member of a bundle has nothing to move up to), and `partial` names those.
 * Instances are spread across the grid so different card types are hit.
 */
export async function probeKinds(opts: {
  /** Rebuild the page from scratch; called before every click. */
  reset: () => void | Promise<void>;
  selector: string;
  /** Runs after every reset, e.g. to clear a toast the reset itself raised. */
  afterReset?: () => void;
  sample?: number;
  errors: string[];
}): Promise<KindReport> {
  const { reset, selector, errors } = opts;
  const sample = opts.sample ?? 6;
  await reset();
  opts.afterReset?.();
  const byKind = new Map<string, number[]>();
  let targets = 0;
  document.querySelectorAll<HTMLElement>(selector).forEach((el, i) => {
    const kind = el.dataset.action ?? '?';
    byKind.set(kind, [...(byKind.get(kind) ?? []), i]);
    targets++;
  });
  const results = new Map<string, boolean[]>();
  const threw: string[] = [];
  for (const [kind, all] of byKind) {
    const picks =
      all.length <= sample
        ? all
        : Array.from(
            { length: sample },
            (_, i) => all[Math.floor((i * (all.length - 1)) / (sample - 1))],
          );
    for (const i of picks) {
      await reset();
      opts.afterReset?.();
      const el = document.querySelectorAll<HTMLElement>(selector)[i];
      // A disabled button is the app saying "not now"; pressing it is not a control.
      if (!el || (el as HTMLButtonElement).disabled) continue;
      const nerr = errors.length;
      const effect = await hadEffect(() => el.click(), 40);
      if (errors.length > nerr) threw.push(`${kind}: ${errors[errors.length - 1]}`);
      results.set(kind, [...(results.get(kind) ?? []), effect]);
    }
  }
  return {
    targets,
    kinds: byKind.size,
    reached: [...byKind.keys()],
    silent: [...results].filter(([, r]) => !r.some(Boolean)).map(([k]) => k),
    partial: [...results].filter(([, r]) => r.some(Boolean) && !r.every(Boolean)).map(([k]) => k),
    threw,
  };
}

/** Compare a report with an allow-list; the shape every efficacy test asserts. */
export function judge(report: KindReport, allowed: Record<string, string>) {
  return {
    unexplained: report.silent.filter((k) => !(k in allowed)),
    threw: report.threw,
    stale: Object.keys(allowed).filter((k) => !report.silent.includes(k)),
  };
}
