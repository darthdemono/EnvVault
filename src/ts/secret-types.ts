/**
 * @file
 * The secret-type registry — Phase 24.5.
 *
 * `secret-types.json` at the repo root is the one file, read here as a plain
 * JSON import and by `vault_core::secret_types` (`include_str!` + serde) on
 * the Rust side. Not a twin pair needing a parity fixture — there is exactly
 * one copy of the data, so nothing can disagree with it.
 *
 * A descriptor only ever *chooses* — which field is primary, how rotation
 * reads, whether `enrich --online` may probe it. The code that validates,
 * renders and masks a value still lives where it always did; this module
 * does not add a form field, a card body or a validator for any of the
 * sixteen new types. See CLAUDE.md Phase 24.5: "land the shape now, behavior
 * later" — the same call Phase 24.1 made for `composite` and `bundle`.
 */
import registryJson from '../../secret-types.json';

export type Rotation = 'rotate' | 'reissue' | 'verify_session' | 'none';

export interface SecretTypeDescriptor {
  id: string;
  label: string;
  group: string;
  primary: string | null;
  rotation: Rotation;
  probe: boolean;
  mask_whole: boolean;
  cxf: string | null;
  /** Output formats the Copy menu offers (`vault_core::type_emit`). */
  emitters: string[];
}

const REGISTRY: SecretTypeDescriptor[] = (registryJson as { types: SecretTypeDescriptor[] }).types;

/** The full registry, in the order `secret-types.json` lists it. */
export function registry(): SecretTypeDescriptor[] {
  return REGISTRY;
}

/** One type's descriptor, or `undefined` for a type this build has never
 * heard of — the A11 case: an unrecognised type is a fact to check, not a
 * reason to guess at a default. */
export function findSecretType(id: string): SecretTypeDescriptor | undefined {
  return REGISTRY.find((t) => t.id === id);
}

/** Human label for a type, falling back to the raw id — a newer build's type
 * is still readable in an older one, just unlabelled. Kept separate from
 * `TYPE_CHIP_LABELS` in `render.ts`: that one is the eleven types the grid
 * already has UI for, this one is every type the registry knows about. */
export function secretTypeLabel(id: string): string {
  return findSecretType(id)?.label ?? id;
}

/** Descriptors grouped for a settings/picker UI, in registry order within
 * each group. */
export function secretTypesByGroup(): Map<string, SecretTypeDescriptor[]> {
  const out = new Map<string, SecretTypeDescriptor[]>();
  for (const t of REGISTRY) {
    if (!out.has(t.group)) out.set(t.group, []);
    out.get(t.group)!.push(t);
  }
  return out;
}

/** Whether an entry's `extra_vars` should be masked whole regardless of each
 * value's own `public` flag — E5's rule, generalised in Phase 24.5 to every
 * type whose payload is only useful as a set. `secretType` may be absent or
 * unrecognised; both read as "no", matching the fail-open default every other
 * type already has. */
export function maskWholeFor(secretType: string | null | undefined): boolean {
  if (!secretType) return false;
  return findSecretType(secretType)?.mask_whole ?? false;
}

/** The emit formats an entry's type offers (`.npmrc`, a DSN, a Wi-Fi string…). */
export function emittersFor(secretType: string | null | undefined): string[] {
  return secretType ? (findSecretType(secretType)?.emitters ?? []) : [];
}
