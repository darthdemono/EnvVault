/**
 * @file
 * Secret templates (item 23) — predefined field presets for common services.
 */

import type { VaultEntry } from './types';

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

export const SECRET_TEMPLATES: SecretTemplate[] = [
  {
    id: 'github-pat',
    name: 'GitHub PAT',
    icon: 'github',
    category: 'Dev Tools',
    secretType: 'api_key',
    defaults: {
      provider: 'GitHub',
      price_type: 'free',
      api_description: 'Personal Access Token',
      api_url: 'https://api.github.com',
      scopes: ['repo', 'read:user'],
    },
    requiredFields: ['api_key'],
    hints: {
      api_key: 'ghp_... token from github.com/settings/tokens',
      scopes: 'e.g. repo, read:user, workflow',
    },
  },
  {
    id: 'aws-access-key',
    name: 'AWS Access Key',
    icon: 'amazonaws',
    category: 'Cloud',
    secretType: 'api_key',
    defaults: {
      provider: 'AWS',
      price_type: 'paid',
      api_description: 'IAM Access Key',
      api_url: 'https://aws.amazon.com',
    },
    requiredFields: ['key_id', 'api_key'],
    hints: {
      key_id: 'Access Key ID (AKIA...)',
      api_key: 'Secret Access Key',
      api_secret: 'Optional: AWS Session Token',
    },
  },
  {
    id: 'stripe-api-key',
    name: 'Stripe API Key',
    icon: 'stripe',
    category: 'Payments',
    secretType: 'api_key',
    defaults: { provider: 'Stripe', price_type: 'paid', api_url: 'https://api.stripe.com' },
    requiredFields: ['api_key'],
    hints: { api_key: 'sk_live_... or sk_test_... key', key_id: 'live or test (for .env naming)' },
  },
  {
    id: 'postgres-dsn',
    name: 'PostgreSQL DSN',
    icon: 'postgresql',
    category: 'Database',
    secretType: 'connection_string',
    defaults: {
      provider: 'PostgreSQL',
      price_type: 'local',
      api_description: 'Database connection string',
    },
    requiredFields: ['api_key'],
    hints: { api_key: 'postgresql://user:password@host:5432/dbname' },
  },
  {
    id: 'openai-key',
    name: 'OpenAI API Key',
    icon: 'openai',
    category: 'AI',
    secretType: 'api_key',
    defaults: {
      provider: 'OpenAI',
      price_type: 'paid',
      api_url: 'https://api.openai.com',
      api_description: 'OpenAI API key',
    },
    requiredFields: ['api_key'],
    hints: {
      api_key: 'sk-... key from platform.openai.com/api-keys',
      api_secret: 'Optional: Organization ID',
    },
  },
  {
    id: 'cloudflare-api',
    name: 'Cloudflare API Token',
    icon: 'cloudflare',
    category: 'Cloud',
    secretType: 'api_key',
    defaults: { provider: 'Cloudflare', price_type: 'free', api_url: 'https://api.cloudflare.com' },
    requiredFields: ['api_key'],
    hints: {
      api_key: 'Token from dash.cloudflare.com/profile/api-tokens',
      api_secret: 'Optional: Account ID',
    },
  },
  {
    id: 'ssh-keypair',
    name: 'SSH Key Pair',
    icon: 'openssh',
    category: 'Infrastructure',
    secretType: 'ssh_key',
    defaults: { provider: 'SSH Key', price_type: 'local', api_description: 'SSH key pair' },
    requiredFields: ['api_key'],
    hints: {
      username: 'Linux/remote username',
      api_key: 'Private key (PEM) or Generate below',
      api_description: 'What server/host does this key access?',
    },
  },
  {
    id: 'tls-cert',
    name: 'TLS Certificate',
    icon: 'letsencrypt',
    category: 'Security',
    secretType: 'certificate',
    defaults: { provider: 'TLS Certificate', price_type: 'local' },
    requiredFields: ['certificate_data'],
    hints: {
      certificate_data: 'PEM-encoded certificate (-----BEGIN CERTIFICATE-----)',
      cert_key_data: 'PEM-encoded private key',
      api_description: 'Domain or service this cert is for',
    },
  },
  {
    id: 'env-file',
    name: '.env Variable',
    icon: 'dotenv',
    category: 'Config',
    secretType: 'env_var',
    defaults: { provider: '', price_type: 'local', env_var_subtype: 'string' },
    requiredFields: ['provider', 'api_key'],
    hints: { provider: 'Variable name (e.g. DATABASE_URL)', api_key: 'Variable value' },
  },
  {
    id: 'docker-registry',
    name: 'Docker Registry',
    icon: 'docker',
    category: 'Dev Tools',
    secretType: 'password',
    defaults: {
      provider: 'Docker Registry',
      price_type: 'local',
      api_description: 'Container registry credentials',
    },
    requiredFields: ['username', 'api_key'],
    hints: {
      username: 'Registry username',
      api_key: 'Password or access token',
      api_url: 'Registry URL (e.g. registry.example.com)',
    },
  },
];
