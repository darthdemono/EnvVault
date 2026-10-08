# ADR-0136: Markup reaches the DOM only through an escaping tagged template

Status: accepted

## Context

`render.ts` and `chunk-ops.ts` built markup with plain template literals and relied on the author remembering `esc()` or `escAttr()` at each interpolation (review-01 section 2.3: 51 calls against 299 interpolations). Invariant 4 says vault data is untrusted, and the enforcement was memory. The same class had already shipped as stored XSS (`javascript:` in `api_url`) and as unescaped `environment`, `secretType` and `project_type`. Phase 28 found more of it while migrating: `pid` and `cid` (project and chunk ids) were interpolated raw into `data-project-id` and `data-chunk-id` on every chunk and config-view button.

## Decision

`src/ts/html.ts` provides the `html` tagged template, `raw()` and `setHtml()`. `html` escapes every interpolated value unless it is already a `SafeHtml`, which only `html` and `raw()` can produce. `setHtml(el, markup)` accepts nothing but `SafeHtml` (or `''`). ESLint forbids assigning `innerHTML`/`outerHTML` and calling `insertAdjacentHTML` outside `html.ts`. `tests/html.test.ts` pins the exact set of `raw()` call sites per file, so adding one is a reviewed change to that test.

Plain strings are never trusted, even when they look like markup. A function that returns markup returns `SafeHtml`; a function that takes a fragment takes `HtmlValue`. Helpers that used to return pre-escaped strings (`esc()` results held in variables) were changed to return plain values, because a pre-escaped string interpolated into `html` is escaped twice.

Escaping is the attribute-strength set (`& < > " '`), so one rule is right in text and in a quoted attribute. It does not make a URL safe: `href` and `src` still go through the `http(s)` check.

## Consequences

Forgetting to escape is now the safe default and the opt-out is a visible `raw(`. Anything that is not HTML (an SVG data URI, an exporter's config text, an ICS body) must not use `html`: it would be escaped. Those stay plain template literals, and the type system catches the usual mistake because `SafeHtml` is not assignable to `string`.

Prettier's embedded HTML formatting is turned off (`embeddedLanguageFormatting: "off"`). With it on, Prettier re-indented `html` templates and put whitespace inside elements such as `.key-value`; harmless in normal flow, wrong the moment the content is read back with `textContent` or sits in a `white-space: pre*` container.

## Evidence

`src/ts/html.ts`, `tests/html.test.ts`, the `no-restricted-syntax` block in `eslint.config.js`, `.prettierrc.json`
