/**
 * @file
 * Secret templates (item 23) — predefined field presets for common services.
 */

import type { VaultEntry } from './types';
import templatesJson from '../../secret-templates.json';

export interface SecretTemplate {
  id: string;
  name: string;
  icon: string; // SI slug
  category: string;
  secretType: VaultEntry['secretType'];
  defaults: Partial<VaultEntry>;
  requiredFields: string[];
  hints: Record<string, string>;
}

/**
 * The presets live in `secret-templates.json` at the repo root, read here and by
 * `vault_core::templates` (`include_str!`), so `unv entry add --template` and
 * this pane can never offer different presets. Same one-file shape as
 * `secret-types.json`; no parity fixture is needed because there is one copy.
 */
export const SECRET_TEMPLATES = (templatesJson as unknown as { templates: SecretTemplate[] })
  .templates;
