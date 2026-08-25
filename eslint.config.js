// ESLint flat config.
//
// Two things this file is deliberately *not* doing:
//
// 1. It does not format. Every stylistic rule is disabled by
//    `eslintConfigPrettier` at the end of the array — Prettier owns whitespace,
//    quotes and semicolons, and a rule that argues with the formatter turns
//    `--fix` into a loop. Add stylistic opinions to `.prettierrc.json`, never
//    here.
//
// 2. It does not lint `index.html`. CLAUDE.md records a formatter silently
//    deleting `#new-category-form` from that file, and the app queries element
//    ids that no tool can prove are still present. `index.html` is edited by
//    hand and verified by `tests/modals.test.ts`'s id-contract block.
//
// The rule selection is weighted towards the bug class this codebase actually
// suffers from: a reference that outlives the thing it points at (CLAUDE.md,
// "Invariants"), and unawaited promises around vault writes.

import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';
import eslintConfigPrettier from 'eslint-config-prettier';

export default tseslint.config(
  {
    // Build output, dependencies, and generated artefacts. Flat config has no
    // `.eslintignore`; ignores live in a config object with no other keys.
    ignores: [
      'dist/**',
      'coverage/**',
      'target/**',
      'node_modules/**',
      'src-tauri/gen/**',
      // Generated API references and the assembled Pages site. Both contain
      // vendored JavaScript (rustdoc's search index, Doxygen's tree view) that
      // is outside every tsconfig, so linting it fails with a parser error
      // rather than a lint finding.
      'docs/**',
      'site/**',
      'public/**',
      '**/*.d.ts',
    ],
  },

  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,

  {
    languageOptions: {
      parserOptions: {
        // An explicit `project`, NOT `projectService`: every linted file is
        // then type-checked under the same options `npm run typecheck` uses,
        // instead of a synthesised default program whose compiler options do
        // not match the ones the build runs on. Files outside the tsconfig's
        // `include` get a type-unaware config block below rather than a
        // silently weaker program.
        project: ['./tsconfig.json'],
        tsconfigRootDir: import.meta.dirname,
      },
      globals: {
        ...globals.browser,
        ...globals.es2020,
      },
    },

    rules: {
      // ---- The rules that catch this project's actual bugs -----------------

      // A vault write that is not awaited reports success before it has
      // happened, and a rejection becomes an unhandled rejection with no stack
      // pointing at the caller.
      '@typescript-eslint/no-floating-promises': 'error',
      // `onclick = async () => …` hands a Promise to something expecting void;
      // the error is swallowed and the button appears to have worked.
      '@typescript-eslint/no-misused-promises': 'error',
      '@typescript-eslint/await-thenable': 'error',
      '@typescript-eslint/require-await': 'error',

      // Vault data is untrusted input (invariant 4). Casting it to a union and
      // then trusting the union is how unescaped `environment` and `secretType`
      // reached `innerHTML`.
      '@typescript-eslint/no-unsafe-assignment': 'warn',
      '@typescript-eslint/no-unsafe-member-access': 'warn',
      '@typescript-eslint/no-unsafe-call': 'warn',
      '@typescript-eslint/no-unsafe-argument': 'warn',
      '@typescript-eslint/no-unsafe-return': 'warn',
      '@typescript-eslint/no-explicit-any': 'warn',

      // An unused variable after a refactor is usually the half of a rename
      // that did not happen. `_`-prefixed is the documented opt-out.
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
          ignoreRestSiblings: true,
        },
      ],

      // `==` against null is idiomatic and intentional here; everything else
      // comparing across types is a bug.
      eqeqeq: ['error', 'always', { null: 'ignore' }],
      'no-var': 'error',
      'prefer-const': 'error',
      'no-throw-literal': 'off',
      '@typescript-eslint/only-throw-error': 'error',

      // ---- Noise, downgraded deliberately ---------------------------------
      //
      // These are style preferences, not defects. They are warnings so a real
      // error is never buried under three hundred of them.
      '@typescript-eslint/consistent-type-definitions': 'off',
      '@typescript-eslint/consistent-indexed-object-style': 'off',
      '@typescript-eslint/prefer-nullish-coalescing': 'off',
      '@typescript-eslint/prefer-optional-chain': 'warn',
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/restrict-template-expressions': [
        'warn',
        { allowNumber: true, allowBoolean: true, allowNullish: true },
      ],
      '@typescript-eslint/no-empty-function': 'off',

      // ---- Two assertion rules, both OFF, both with evidence ---------------
      //
      // This codebase's DOM access goes through generic helpers with a default
      // type parameter:
      //
      //   const $ = <T extends HTMLElement = HTMLElement>(id: string) =>
      //     document.getElementById(id) as T;
      //
      // and the same shape is built into the lib itself — `querySelector<E
      // extends Element = Element>`. Ask the checker for the type of
      // `$('t-b-field') as HTMLSelectElement` and it obligingly infers
      // `T = HTMLSelectElement` from the assertion's own context, then reports
      // the assertion as redundant. It is not: drop it and the expression is
      // `HTMLElement`, on which `.value` does not exist.
      //
      // `--fix` with these two enabled rewrote ~170 assertions across src/ts/
      // and tests/ — `as HTMLSelectElement` deleted outright, or replaced with
      // a `!` that only strips null and leaves the base type. `tsc --noEmit`
      // then reported 130+ TS2339/TS2345 errors on a tree that had typechecked
      // clean minutes earlier. Verified three times: with `projectService`,
      // with an explicit `project`, and with each rule disabled in turn.
      //
      // A lint rule whose autofix does not typecheck is worse than no rule.
      '@typescript-eslint/no-unnecessary-type-assertion': 'off',
      '@typescript-eslint/non-nullable-type-assertion-style': 'off',

      '@typescript-eslint/class-methods-use-this': 'off',
      '@typescript-eslint/dot-notation': 'off',
      'no-empty': ['error', { allowEmptyCatch: true }],
    },
  },

  {
    // Tests reach into internals, stub globals and assert on `any` shaped
    // fixtures. Holding them to the type-safety rules above produces noise
    // that says nothing about the code under test.
    files: ['tests/**/*.ts'],
    languageOptions: {
      globals: { ...globals.node },
    },
    rules: {
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/require-await': 'off',
    },
  },

  {
    // Files outside tsconfig's `include`: build config and the version script.
    // They get the same rules minus the type-aware ones — linting them under a
    // synthesised default program is exactly the failure documented above.
    files: ['vite.config.ts', 'eslint.config.js', 'scripts/**/*.mjs'],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: {
      globals: { ...globals.node },
      parserOptions: { project: null, projectService: false },
    },
  },

  {
    // vitest.config.ts IS in tsconfig's include, so it keeps type-aware rules;
    // it only needs Node globals.
    files: ['vitest.config.ts'],
    languageOptions: {
      globals: { ...globals.node },
    },
  },

  // Must stay last: it turns off every rule Prettier would otherwise fight.
  eslintConfigPrettier,
);
