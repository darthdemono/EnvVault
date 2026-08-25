/**
 * @file
 * ENV chunk <-> vault linking — match plain `KEY=value` env-file fields
 * against existing vault entries so they can be replaced by `${ref}`
 * placeholders, and suggest new entries for the ones that have no match.
 */

import type { SecretChunk, VaultEntry, SecretType } from '../types';
import { st } from '../state';
// ── ENV chunk ↔ vault linking ──────────────────────────────────────────────

export interface EnvLinkMatch {
  key: string;
  rawValue: string;
  alreadyLinked: boolean;
  existingRef?: string;
  match?: { entry: VaultEntry; ref: string; field: string; confidence: number };
  suggestCreate?: { provider: string; keyId?: string; secretType: SecretType };
}

function _findBestVaultMatch(
  key: string,
  value: string,
): { entry: VaultEntry; ref: string; field: string; confidence: number } | null {
  let best: { entry: VaultEntry; ref: string; field: string; confidence: number } | null = null;

  const _providerRef = (e: VaultEntry) => (e.key_id ? `${e.provider}_${e.key_id}` : e.provider);

  for (const e of st.vault.api_keys) {
    let score = 0;
    let field = 'key';

    // Tier 0 (92): prefix-aware match — strip one of the entry's env_prefixes, then match.
    // After the prefix is stripped, the remainder is either a named extra_var
    // on this entry, or PROVIDER[_FIELD_SUFFIX].
    //
    // The extra_vars branch used to be gated on `secretType === 'chunk'`. That
    // type is gone, so it now keys on the data instead: if the entry actually
    // has a matching extra_var, that wins. Strictly more capable, and it keeps
    // working for entries migrated off the old chunk type.
    for (const pfx of e.env_prefixes ?? []) {
      if (score >= 92) break;
      const pfxUpper = (pfx.endsWith('_') ? pfx : pfx + '_').toUpperCase();
      if (!key.toUpperCase().startsWith(pfxUpper)) continue;
      const stripped = key.slice(pfxUpper.length); // e.g. "LASTFM_APIKEY" or "JWT_SECRET"

      const xv = e.extra_vars?.find(
        (v) => v.key === stripped || v.key.toUpperCase() === stripped.toUpperCase(),
      );
      if (xv) {
        score = 92;
        field = xv.key;
        break;
      } else {
        // For key types: stripped must start with provider (+ optional key_id).
        const provKey = _providerRef(e).toUpperCase();
        if (stripped.toUpperCase().startsWith(provKey)) {
          const afterProv = stripped.slice(provKey.length);
          const suffix = afterProv.startsWith('_') ? afterProv.slice(1) : afterProv || 'KEY';
          score = 92;
          field = suffix || 'key';
          break;
        }
      }
    }

    // Tier 1 (100/95): exact name match.
    if (score < 95) {
      if (key === e.provider) {
        score = 100;
        field = 'key';
      } else if (e.key_id && key === `${e.provider}_${e.key_id}`) {
        score = 95;
        field = 'key';
      }
    }

    // Tier 2 (88-76): value match against all fields.
    if (score === 0 && value.length >= 6) {
      const candidates: [string, string | null | undefined, number][] = [
        ['key', e.api_key, 88],
        ['secret', e.api_secret, 85],
        ['username', e.username, 80],
        ['url', e.api_url, 78],
        ['key_id', e.key_id, 77],
        ['email', e.email, 76],
      ];
      for (const xv of e.extra_vars ?? []) candidates.push([xv.key, xv.value, 83]);
      for (const [fName, fVal, fScore] of candidates) {
        if (fVal && value === fVal) {
          score = fScore;
          field = fName;
          break;
        }
      }
    }

    // Tier 3 (75-63): name suffix match — strip underscore-delimited prefix segments.
    if (score === 0) {
      const parts = key.split('_');
      for (let i = 1; i < parts.length && score === 0; i++) {
        const stripped = parts.slice(i).join('_');
        if (stripped === e.provider) {
          score = 75;
          field = 'key';
        } else if (e.key_id && stripped === `${e.provider}_${e.key_id}`) {
          score = 70;
          field = 'key';
        } else if (stripped.toLowerCase() === e.provider.toLowerCase()) {
          score = 63;
          field = 'key';
        }
      }
    }

    if (score > (best?.confidence ?? 0)) {
      const provRef = _providerRef(e);
      // For a password entry the primary secret is conceptually its password, so
      // surface it as ${name/password} rather than ${name/key} (both resolve to api_key).
      const fieldOut = e.secretType === 'password' && field === 'key' ? 'password' : field;
      // Build ref as ${PROVIDER_LABEL/field} — key_id disambiguates multiple keys from same provider.
      best = { entry: e, ref: `${provRef}/${fieldOut}`, field: fieldOut, confidence: score };
    }
  }

  return best && best.confidence >= 63 ? best : null;
}

function _suggestCreateEntry(key: string): {
  provider: string;
  keyId?: string;
  secretType: SecretType;
} {
  const k = key.toLowerCase();
  let secretType: SecretType = 'api_key';

  if (/[_-](pass(word)?|pwd)$/.test(k)) secretType = 'password';
  else if (/[_-](user(name)?|login)$/.test(k)) secretType = 'password';
  else if (/[_-](url|uri|dsn|conn(ection)?(_?str(ing)?)?)$/.test(k))
    secretType = 'connection_string';

  const suffixMatch =
    /^(.+)[_-](API_?KEY|APIKEY|KEY|TOKEN|SECRET|PASS(WORD)?|PWD|USER(NAME)?|LOGIN|URL|URI|DSN)$/i.exec(
      key,
    );
  if (suffixMatch) return { provider: suffixMatch[1], keyId: suffixMatch[2], secretType };
  return { provider: key, secretType };
}

export function buildEnvLinkMatches(chunk: SecretChunk): EnvLinkMatch[] {
  return chunk.fields
    .filter((f) => f.key)
    .map((f) => {
      const refM = /^\$\{(.+)\}$/.exec(f.value);
      if (refM) return { key: f.key, rawValue: f.value, alreadyLinked: true, existingRef: refM[1] };
      const match = _findBestVaultMatch(f.key, f.value || '');
      if (match) return { key: f.key, rawValue: f.value || '', alreadyLinked: false, match };
      if (!f.value) return { key: f.key, rawValue: '', alreadyLinked: false };
      return {
        key: f.key,
        rawValue: f.value,
        alreadyLinked: false,
        suggestCreate: _suggestCreateEntry(f.key),
      };
    });
}
