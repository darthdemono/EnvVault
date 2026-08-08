/**
 * @file Permission expression editor — shared by the user and class panels.
 *
 * Two rules per subject: one for read, one for write. Each is a boolean
 * expression (see `permex.ts`). The editor gives you a predicate builder for the
 * common cases, a raw text box for everything else, live syntax validation, and
 * a "matches N of M" preview so a rule can be sanity-checked before it is saved.
 *
 * The preview is advisory. The server re-parses and re-evaluates every rule.
 */

import { st } from './state';
import { esc, escAttr, showToast } from './utils';
import { FIELDS, validate, parse, evaluate, type Field } from './permex';

export interface PermExprs { read: string; write: string; }

/** Distinct values present in the vault for a given predicate field. */
function suggestionsFor(field: Field): string[] {
  const keys = st.vault.api_keys;
  switch (field) {
    case 'project':
      return st.vault.projects.filter(p => p.id !== 'Universal').map(p => p.name).sort();
    case 'category':
      return [...new Set(st.vault.user_categories ?? [])].sort();
    case 'tag':
      return [...new Set(keys.flatMap(k => k.tags ?? []))].sort();
    case 'env':
      return ['production', 'staging', 'development', 'testing'];
    case 'type':
      return ['api_key', 'password', 'certificate', 'env_var', 'connection_string', 'ssh_key', 'file_blob'];
    default:
      return ['*'];
  }
}

/**
 * Markup for one subject's editor.
 * `p` namespaces every id so the user and class panels can both be open.
 */
export function permEditorHtml(p: string, exprs: PermExprs): string {
  const fieldOpts = FIELDS.map(f => `<option value="${f}">${f}</option>`).join('');
  return `
    <div class="perm-expr-editor">
      <p class="perm-expr-help">
        Combine terms with <code>AND</code>, <code>OR</code>, <code>NOT</code> and parentheses.
        A term is <code>field:value</code> and the value may use <code>*</code> / <code>?</code> wildcards.
        <br>Example: <code>project:Alpha AND NOT category:secret</code>
        &nbsp;·&nbsp; <code>field:*</code> means no constraint on that field.
        <br>Leave a box empty to grant nothing. Write access implies read.
      </p>

      <div class="perm-expr-row">
        <label class="perm-expr-label" for="${p}-expr-read">Read</label>
        <textarea id="${p}-expr-read" class="perm-expr-input mono" rows="2"
                  placeholder="e.g. project:* AND NOT category:secret">${esc(exprs.read)}</textarea>
        <div class="perm-expr-status" id="${p}-status-read"></div>
      </div>

      <div class="perm-expr-row">
        <label class="perm-expr-label" for="${p}-expr-write">Write</label>
        <textarea id="${p}-expr-write" class="perm-expr-input mono" rows="2"
                  placeholder="e.g. project:Alpha">${esc(exprs.write)}</textarea>
        <div class="perm-expr-status" id="${p}-status-write"></div>
      </div>

      <div class="perm-builder">
        <span class="perm-builder-label">Insert term</span>
        <select id="${p}-b-field" class="perm-input">${fieldOpts}</select>
        <select id="${p}-b-value" class="perm-input"></select>
        <select id="${p}-b-target" class="perm-input">
          <option value="read">into Read</option>
          <option value="write">into Write</option>
        </select>
        <select id="${p}-b-join" class="perm-input">
          <option value="AND">AND</option>
          <option value="OR">OR</option>
          <option value="AND NOT">AND NOT</option>
        </select>
        <button class="btn btn-xs btn-ghost" id="${p}-b-insert">Insert</button>
      </div>

      <div class="perm-expr-actions">
        <button class="btn btn-xs btn-accent" id="${p}-expr-save">Save rules</button>
        <span class="perm-expr-preview" id="${p}-preview"></span>
      </div>
    </div>`;
}

/**
 * Binds the editor rendered by [`permEditorHtml`].
 * `onSave` receives the two expression strings; it should persist them.
 */
export function wirePermEditor(p: string, onSave: (e: PermExprs) => Promise<void>): void {
  const readEl  = document.getElementById(`${p}-expr-read`)  as HTMLTextAreaElement | null;
  const writeEl = document.getElementById(`${p}-expr-write`) as HTMLTextAreaElement | null;
  if (!readEl || !writeEl) return;

  const fieldSel  = document.getElementById(`${p}-b-field`)  as HTMLSelectElement;
  const valueSel  = document.getElementById(`${p}-b-value`)  as HTMLSelectElement;
  const targetSel = document.getElementById(`${p}-b-target`) as HTMLSelectElement;
  const joinSel   = document.getElementById(`${p}-b-join`)   as HTMLSelectElement;
  const previewEl = document.getElementById(`${p}-preview`)!;

  const refreshValues = () => {
    const field = fieldSel.value as Field;
    const opts = ['*', ...suggestionsFor(field).filter(v => v !== '*')];
    valueSel.innerHTML = opts.map(v => `<option value="${escAttr(v)}">${esc(v)}</option>`).join('');
  };
  fieldSel.addEventListener('change', refreshValues);
  refreshValues();

  /** Show a parse error, or the number of entries the rule currently matches. */
  const refreshOne = (el: HTMLTextAreaElement, statusId: string): boolean => {
    const status = document.getElementById(statusId)!;
    const src = el.value;
    const err = validate(src);
    el.classList.toggle('invalid', !!err);
    if (err) {
      status.className = 'perm-expr-status err';
      status.textContent = err;
      return false;
    }
    if (!src.trim()) {
      status.className = 'perm-expr-status';
      status.textContent = 'Empty — grants nothing.';
      return true;
    }
    const expr = parse(src);
    const total = st.vault.api_keys.length;
    const hits = st.vault.api_keys.filter(e => evaluate(expr, e, st.vault.projects)).length;
    status.className = 'perm-expr-status ok';
    status.textContent = `Valid — matches ${hits} of ${total} entries.`;
    return true;
  };

  const refresh = () => {
    const a = refreshOne(readEl, `${p}-status-read`);
    const b = refreshOne(writeEl, `${p}-status-write`);
    // Write implies read, so the effective read set is the union.
    if (a && b) {
      const parts = [readEl.value, writeEl.value].filter(s => s.trim());
      if (parts.length === 2) {
        const combined = `(${parts[0]}) OR (${parts[1]})`;
        try {
          const expr = parse(combined);
          const hits = st.vault.api_keys.filter(e => evaluate(expr, e, st.vault.projects)).length;
          previewEl.textContent = `Effective read (read OR write): ${hits} of ${st.vault.api_keys.length}`;
        } catch { previewEl.textContent = ''; }
      } else previewEl.textContent = '';
    } else previewEl.textContent = '';
    return a && b;
  };

  readEl.addEventListener('input', refresh);
  writeEl.addEventListener('input', refresh);
  refresh();

  document.getElementById(`${p}-b-insert`)?.addEventListener('click', () => {
    const target = targetSel.value === 'write' ? writeEl : readEl;
    const value  = valueSel.value;
    // Quote values containing characters the lexer would treat as delimiters.
    // Backslash has to be escaped before the quote character, and before any
    // quoting decision: inside a quoted value the lexer reads `\x` as a literal
    // `x`, so a name like `a\b` came back out of the round trip as `ab`.
    const needsQuotes = /[\s()"\\]/.test(value);
    const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    const term = `${fieldSel.value}:${needsQuotes ? `"${escaped}"` : value}`;
    target.value = target.value.trim()
      ? `${target.value.trim()} ${joinSel.value} ${term}`
      : term;
    refresh();
    target.focus();
  });

  document.getElementById(`${p}-expr-save`)?.addEventListener('click', async () => {
    if (!refresh()) { showToast('Fix the expression before saving', 'err'); return; }
    try {
      await onSave({ read: readEl.value.trim(), write: writeEl.value.trim() });
      showToast('Permissions saved ✓', 'ok');
    } catch (e: any) {
      showToast(`Save failed: ${e?.message ?? e}`, 'err', 4000);
    }
  });
}
