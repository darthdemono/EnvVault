/**
 * The worst-case vault the UI is expected to survive.
 *
 * Layout bugs do not appear on tidy data. They appear on the longest name, the
 * widest badge row, the deepest project nesting and the character set nobody
 * tested — so the seed is built to be hostile on exactly those axes rather than
 * to be realistic. Anything that renders this at 860×600 renders a real vault.
 *
 * **The `api_key` values deliberately carry no real issuer prefix.** They have
 * always been zero-filled placeholders, but `sk_live_` followed by 48 zeros is
 * still a syntactic match for a Stripe live key, and GitHub push protection
 * blocked a push over it — the fix was a history rewrite of two unpushed
 * commits. Only the *length* of these strings matters to this file, because
 * length is what decides whether a card wraps, so each prefix now names the
 * provider it stands in for, at exactly the character count the real one has.
 *
 * Do not "correct" them back. A secrets manager whose own repository carries an
 * allowlisted "Stripe API key" in its security tab is a poor advertisement, and
 * the next person to hit the block would have no way to tell the value was fake.
 */
export const SEED_VAULT = {
  api_keys: [
    {
      id: 'e1',
      provider: 'GitHub',
      account_name: 'ci-runner',
      key_id: 'primary',
      api_key: 'EXAMPLE_GITHUB_0000000000000000000000000000000',
      environment: 'production',
      price_type: 'free',
      secretType: 'api_key',
      categories: ['Cloud/AWS/Production'],
      projectIds: ['Universal', 'edge'],
      tags: ['ci', 'critical', 'rotate-quarterly'],
      pool: 'github-ci',
      rotation_days: 90,
      last_rotated_at: '2026-01-01T00:00:00Z',
    },
    {
      id: 'e2',
      // The longest realistic provider name, plus the widest possible badge row.
      provider: 'Extremely Long Provider Name That Nobody Would Ever Type But Someone Will',
      account_name: 'billing+alerts@a-very-long-subdomain.example.co.uk',
      key_id: 'this-is-a-long-key-identifier-0001',
      api_key: 'EXAMPLE_STRIPE_00000000000000000000000000000000000000000',
      environment: 'staging',
      price_type: 'paid',
      secretType: 'connection_string',
      categories: ['Cloud/AWS/Production', 'Billing'],
      projectIds: ['Universal', 'stack'],
      tags: ['expensive', 'pii', 'audited', 'do-not-rotate-without-asking'],
      api_url: 'https://api.example.com/v2/some/quite/long/path/that/wraps',
      expires_at: '2026-09-15',
      rate_limit_count: 5000,
      rate_limit_period: 'hour',
    },
    {
      id: 'e3',
      // Non-ASCII, RTL and CJK: the three things that break width assumptions.
      provider: 'Café Ünïcode — 日本語テスト — مرحبا',
      account_name: 'ユーザー名',
      api_key: 'p@ssw0rd-with-emoji-🔐-and-more',
      environment: 'development',
      price_type: 'free',
      secretType: 'password',
      categories: ['Personal'],
      projectIds: ['Universal'],
      tags: ['unicode'],
    },
    {
      id: 'e4',
      provider: 'OpenAI',
      account_name: 'org-main',
      api_key: 'sk-proj-0000000000000000000000000000',
      environment: 'production',
      price_type: 'paid',
      secretType: 'api_key',
      categories: ['AI'],
      projectIds: ['Universal'],
      tags: ['llm'],
      pool: 'llm-fallback',
    },
    {
      id: 'e5',
      provider: 'Anthropic',
      api_key: 'EXAMPLE_ANTHROPIC_00000000000000000',
      environment: 'production',
      price_type: 'paid',
      secretType: 'api_key',
      categories: ['AI'],
      projectIds: ['Universal'],
      tags: ['llm'],
      pool: 'llm-fallback',
    },
    {
      id: 'e6',
      provider: 'WgKey',
      api_key: 'aGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSByZWFsIGtleQ==',
      environment: 'production',
      price_type: 'free',
      secretType: 'ssh_key',
      categories: ['Homelab'],
      projectIds: ['Universal', 'vpn'],
      tags: [],
    },
  ],
  user_categories: [
    'AI',
    'Billing',
    'Cloud',
    'Cloud/AWS',
    'Cloud/AWS/Production',
    'Homelab',
    'Personal',
    // A deliberately over-long category, to test the sidebar's truncation.
    'Operations/Infrastructure/Networking/Edge/Termination/Certificates',
  ],
  projects: [
    { id: 'Universal', name: 'Universal', project_type: 'generic', chunks: [] },
    {
      id: 'edge',
      name: 'Edge (nginx)',
      project_type: 'nginx',
      chunks: [
        {
          id: 'c1',
          name: 'darthdemono.com',
          chunk_type: 'nginx_server',
          fields: [
            { key: 'server_name', value: 'darthdemono.com www.darthdemono.com', field_type: 'var' },
            {
              key: 'ssl_certificate',
              value: '/etc/letsencrypt/live/darthdemono.com/fullchain.pem',
              field_type: 'var',
            },
            { key: 'listen', value: '443 ssl http2', field_type: 'var' },
          ],
        },
      ],
    },
    {
      id: 'stack',
      name: 'Stack (compose)',
      project_type: 'docker',
      chunks: [
        {
          id: 'c2',
          name: 'app',
          chunk_type: 'docker_service',
          fields: [
            { key: 'image', value: 'ghcr.io/example/app:latest', field_type: 'var' },
            {
              key: 'DATABASE_URL',
              value: '${Postgres}',
              field_type: 'env_var',
              description: 'env',
            },
          ],
        },
      ],
    },
    { id: 'vpn', name: 'VPN', project_type: 'wireguard', chunks: [] },
  ],
};
