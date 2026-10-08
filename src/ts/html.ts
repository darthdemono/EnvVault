/**
 * Escape by construction (Phase 28, review-01 §2.3, ADR-0136).
 *
 * `html` is a tagged template that escapes every interpolated value unless it
 * is already a `SafeHtml`, which only `html` itself and `raw()` can produce.
 * A renderer therefore cannot forget to escape: forgetting is the default
 * that is safe, and the opt-out is a visible, greppable `raw(...)`.
 *
 *   html`<b title="${entry.provider}">${entry.notes}</b>`   // both escaped
 *   html`<ul>${items.map((i) => html`<li>${i}</li>`)}</ul>` // nested + arrays
 *
 * Escaping is the attribute-strength set (`& < > " '`), so one rule is correct
 * in text and in a quoted attribute. It does NOT make `href`/`src` safe:
 * a `javascript:` URL survives HTML escaping, so links still go through
 * `safeHttpUrl`.
 */

/** Markup that has been escaped or vouched for. Only `html`/`raw` build one. */
export class SafeHtml {
  constructor(private readonly markup: string) {}
  toString(): string {
    return this.markup;
  }
}

export type HtmlValue =
  string | number | bigint | boolean | null | undefined | SafeHtml | HtmlValue[];

/** Vouch for a string as markup. Every call site is an audit point. */
export function raw(markup: string): SafeHtml {
  return new SafeHtml(markup);
}

const ESC: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

function escape(v: string | number | bigint | boolean): string {
  return String(v).replace(/[&<>"']/g, (c) => ESC[c]);
}

function part(v: HtmlValue): string {
  if (v instanceof SafeHtml) return v.toString();
  if (Array.isArray(v)) return v.map(part).join('');
  if (v === false || v == null) return '';
  return escape(v);
}

export function html(strings: TemplateStringsArray, ...values: HtmlValue[]): SafeHtml {
  let out = strings[0] ?? '';
  for (let i = 0; i < values.length; i++) out += part(values[i]) + (strings[i + 1] ?? '');
  return new SafeHtml(out);
}

/** The only sanctioned `innerHTML` write: it accepts nothing but `SafeHtml`. */
export function setHtml(el: Element, markup: SafeHtml | ''): void {
  el.innerHTML = markup.toString();
}
