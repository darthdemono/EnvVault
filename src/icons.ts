/**
 * @file Icon resolution and picker for API Vault.
 * @description Provides Simple Icons CDN integration, provider-name-to-slug auto-detection,
 *              and an interactive icon-picker overlay for custom icon assignment.
 */

import type { VaultEntry } from './types';

/**
 * Master registry of supported Simple Icons entries.
 *
 * Each tuple is `[slug, displayName, category]` where `slug` is the
 * Simple Icons identifier used to construct CDN URLs, `displayName` is shown
 * in the picker, and `category` groups icons in the picker UI.
 *
 * @see {@link https://simpleicons.org} for slug reference.
 */
const SI_REGISTRY: [string, string, string][] = [
  // ── Languages ──────────────────────────────────────────────────────────────
  ['javascript', 'JavaScript', 'Dev'], ['typescript', 'TypeScript', 'Dev'],
  ['python', 'Python', 'Dev'], ['rust', 'Rust', 'Dev'],
  ['go', 'Go', 'Dev'], ['java', 'Java', 'Dev'],
  ['kotlin', 'Kotlin', 'Dev'], ['swift', 'Swift', 'Dev'],
  ['cplusplus', 'C++', 'Dev'], ['csharp', 'C#', 'Dev'],
  ['ruby', 'Ruby', 'Dev'], ['php', 'PHP', 'Dev'],
  ['scala', 'Scala', 'Dev'], ['elixir', 'Elixir', 'Dev'],
  ['haskell', 'Haskell', 'Dev'], ['lua', 'Lua', 'Dev'],
  ['perl', 'Perl', 'Dev'], ['dart', 'Dart', 'Dev'],
  ['flutter', 'Flutter', 'Dev'], ['erlang', 'Erlang', 'Dev'],
  ['clojure', 'Clojure', 'Dev'], ['julia', 'Julia', 'Dev'],
  ['zig', 'Zig', 'Dev'], ['ocaml', 'OCaml', 'Dev'],
  ['groovy', 'Groovy', 'Dev'], ['r', 'R', 'Dev'],
  ['dotnet', '.NET', 'Dev'],
  // ── Runtimes & Package Managers ────────────────────────────────────────────
  ['nodedotjs', 'Node.js', 'Dev'], ['bun', 'Bun', 'Dev'],
  ['deno', 'Deno', 'Dev'], ['npm', 'npm', 'Dev'],
  ['pnpm', 'pnpm', 'Dev'], ['yarn', 'Yarn', 'Dev'],
  ['pypi', 'PyPI', 'Dev'], ['rubygems', 'RubyGems', 'Dev'],
  ['nuget', 'NuGet', 'Dev'], ['homebrew', 'Homebrew', 'Dev'],
  ['chocolatey', 'Chocolatey', 'Dev'],
  // ── Web Frameworks ─────────────────────────────────────────────────────────
  ['react', 'React', 'Dev'], ['vuedotjs', 'Vue.js', 'Dev'],
  ['svelte', 'Svelte', 'Dev'], ['angular', 'Angular', 'Dev'],
  ['nextdotjs', 'Next.js', 'Dev'], ['nuxtdotjs', 'Nuxt.js', 'Dev'],
  ['gatsby', 'Gatsby', 'Dev'], ['astro', 'Astro', 'Dev'],
  ['lit', 'Lit', 'Dev'], ['alpinedotjs', 'Alpine.js', 'Dev'],
  ['nestjs', 'NestJS', 'Dev'], ['express', 'Express', 'Dev'],
  ['fastapi', 'FastAPI', 'Dev'], ['flask', 'Flask', 'Dev'],
  ['django', 'Django', 'Dev'], ['rubyonrails', 'Rails', 'Dev'],
  ['laravel', 'Laravel', 'Dev'], ['symfony', 'Symfony', 'Dev'],
  ['spring', 'Spring', 'Dev'], ['fastify', 'Fastify', 'Dev'],
  // ── CSS & UI ───────────────────────────────────────────────────────────────
  ['tailwindcss', 'Tailwind CSS', 'Dev'], ['bootstrap', 'Bootstrap', 'Dev'],
  ['sass', 'Sass', 'Dev'], ['jquery', 'jQuery', 'Dev'],
  // ── Build Tools & Bundlers ─────────────────────────────────────────────────
  ['webpack', 'webpack', 'Dev'], ['vite', 'Vite', 'Dev'],
  ['parcel', 'Parcel', 'Dev'], ['rollup', 'Rollup', 'Dev'],
  ['gradle', 'Gradle', 'Dev'], ['apachemaven', 'Maven', 'Dev'],
  ['cmake', 'CMake', 'Dev'], ['bazel', 'Bazel', 'Dev'],
  // ── Testing ────────────────────────────────────────────────────────────────
  ['jest', 'Jest', 'Dev'], ['mocha', 'Mocha', 'Dev'],
  ['playwright', 'Playwright', 'Dev'], ['cypress', 'Cypress', 'Dev'],
  ['selenium', 'Selenium', 'Dev'], ['vitest', 'Vitest', 'Dev'],
  ['storybook', 'Storybook', 'Dev'], ['eslint', 'ESLint', 'Dev'],
  // ── State & Misc Frontend ──────────────────────────────────────────────────
  ['redux', 'Redux', 'Dev'],
  // ── Databases ─────────────────────────────────────────────────────────────
  ['postgresql', 'PostgreSQL', 'Dev'], ['mysql', 'MySQL', 'Dev'],
  ['redis', 'Redis', 'Dev'], ['mongodb', 'MongoDB', 'Dev'],
  ['sqlite', 'SQLite', 'Dev'], ['mariadb', 'MariaDB', 'Dev'],
  ['neo4j', 'Neo4j', 'Dev'], ['influxdb', 'InfluxDB', 'Dev'],
  ['supabase', 'Supabase', 'Dev'], ['prisma', 'Prisma', 'Dev'],
  ['firebase', 'Firebase', 'Dev'], ['appwrite', 'Appwrite', 'Dev'],
  ['planetscale', 'PlanetScale', 'Dev'], ['cockroachdb', 'CockroachDB', 'Dev'],
  ['clickhouse', 'ClickHouse', 'Dev'], ['minio', 'MinIO', 'Dev'],
  // ── API ────────────────────────────────────────────────────────────────────
  ['graphql', 'GraphQL', 'Dev'], ['swagger', 'Swagger', 'Dev'],
  ['postman', 'Postman', 'Dev'], ['insomnia', 'Insomnia', 'Dev'],
  // ── Messaging & Queues ─────────────────────────────────────────────────────
  ['apachekafka', 'Kafka', 'Dev'], ['rabbitmq', 'RabbitMQ', 'Dev'],
  // ── VCS & Collaboration ────────────────────────────────────────────────────
  ['git', 'Git', 'Dev'], ['github', 'GitHub', 'Dev'],
  ['gitlab', 'GitLab', 'Dev'], ['bitbucket', 'Bitbucket', 'Dev'],
  ['gitkraken', 'GitKraken', 'Dev'],
  // ── Containers ────────────────────────────────────────────────────────────
  ['docker', 'Docker', 'Dev'], ['kubernetes', 'Kubernetes', 'Dev'],
  // ── ML / AI Dev ───────────────────────────────────────────────────────────
  ['tensorflow', 'TensorFlow', 'Dev'], ['pytorch', 'PyTorch', 'Dev'],
  ['jupyter', 'Jupyter', 'Dev'], ['anaconda', 'Anaconda', 'Dev'],
  ['numpy', 'NumPy', 'Dev'],
  // ── Editors & IDEs ────────────────────────────────────────────────────────
  ['visualstudiocode', 'VS Code', 'Dev'], ['visualstudio', 'Visual Studio', 'Dev'],
  ['vim', 'Vim', 'Dev'], ['neovim', 'Neovim', 'Dev'],
  ['sublimetext', 'Sublime Text', 'Dev'],
  ['jetbrains', 'JetBrains', 'Dev'], ['intellijidea', 'IntelliJ IDEA', 'Dev'],
  ['pycharm', 'PyCharm', 'Dev'], ['webstorm', 'WebStorm', 'Dev'],
  ['phpstorm', 'PhpStorm', 'Dev'], ['goland', 'GoLand', 'Dev'],
  ['rubymine', 'RubyMine', 'Dev'], ['clion', 'CLion', 'Dev'],
  ['rider', 'Rider', 'Dev'], ['datagrip', 'DataGrip', 'Dev'],
  ['androidstudio', 'Android Studio', 'Dev'],
  ['xcode', 'Xcode', 'Dev'], ['emacs', 'Emacs', 'Dev'],
  ['eclipseide', 'Eclipse', 'Dev'], ['notepadplusplus', 'Notepad++', 'Dev'],
  ['obsidian', 'Obsidian', 'Dev'],

  // ── Cloud & Infra ──────────────────────────────────────────────────────────
  ['amazonaws', 'AWS', 'Cloud'], ['googlecloud', 'GCP', 'Cloud'],
  ['microsoftazure', 'Azure', 'Cloud'], ['digitalocean', 'DigitalOcean', 'Cloud'],
  ['linode', 'Linode', 'Cloud'], ['vultr', 'Vultr', 'Cloud'],
  ['hetzner', 'Hetzner', 'Cloud'], ['ovh', 'OVH', 'Cloud'],
  ['scaleway', 'Scaleway', 'Cloud'], ['oracle', 'Oracle', 'Cloud'],
  ['cloudflare', 'Cloudflare', 'Cloud'], ['fastly', 'Fastly', 'Cloud'],
  ['akamai', 'Akamai', 'Cloud'],
  ['netlify', 'Netlify', 'Cloud'], ['vercel', 'Vercel', 'Cloud'],
  ['heroku', 'Heroku', 'Cloud'], ['railway', 'Railway', 'Cloud'],
  ['fly', 'Fly.io', 'Cloud'], ['render', 'Render', 'Cloud'],
  ['nginx', 'nginx', 'Cloud'], ['traefik', 'Traefik', 'Cloud'],
  ['grafana', 'Grafana', 'Cloud'], ['prometheus', 'Prometheus', 'Cloud'],
  ['elasticsearch', 'Elasticsearch', 'Cloud'],
  ['terraform', 'Terraform', 'Cloud'], ['ansible', 'Ansible', 'Cloud'],
  ['vagrant', 'Vagrant', 'Cloud'], ['pulumi', 'Pulumi', 'Cloud'],
  ['helm', 'Helm', 'Cloud'], ['portainer', 'Portainer', 'Cloud'],
  ['podman', 'Podman', 'Cloud'], ['cloudinary', 'Cloudinary', 'Cloud'],
  ['apacheairflow', 'Airflow', 'Cloud'], ['apachespark', 'Spark', 'Cloud'],

  // ── OS & Hardware ──────────────────────────────────────────────────────────
  ['linux', 'Linux', 'OS'], ['ubuntu', 'Ubuntu', 'OS'],
  ['debian', 'Debian', 'OS'], ['fedora', 'Fedora', 'OS'],
  ['archlinux', 'Arch Linux', 'OS'], ['centos', 'CentOS', 'OS'],
  ['redhat', 'Red Hat', 'OS'], ['freebsd', 'FreeBSD', 'OS'],
  ['windows11', 'Windows', 'OS'], ['gnome', 'GNOME', 'OS'],
  ['kde', 'KDE', 'OS'], ['raspberrypi', 'Raspberry Pi', 'OS'],
  ['arduino', 'Arduino', 'OS'],
  ['nvidia', 'NVIDIA', 'OS'], ['amd', 'AMD', 'OS'], ['intel', 'Intel', 'OS'],

  // ── Gaming ─────────────────────────────────────────────────────────────────
  ['steam', 'Steam', 'Gaming'], ['epicgames', 'Epic Games', 'Gaming'],
  ['riotgames', 'Riot Games', 'Gaming'], ['nintendo', 'Nintendo', 'Gaming'],
  ['playstation', 'PlayStation', 'Gaming'], ['xbox', 'Xbox', 'Gaming'],
  ['unity', 'Unity', 'Gaming'], ['unrealengine', 'Unreal Engine', 'Gaming'],
  ['godotengine', 'Godot', 'Gaming'], ['itchdotio', 'itch.io', 'Gaming'],
  ['gog', 'GOG', 'Gaming'], ['ea', 'EA', 'Gaming'],
  ['ubisoft', 'Ubisoft', 'Gaming'], ['nexusmods', 'Nexus Mods', 'Gaming'],
  ['blizzard', 'Blizzard', 'Gaming'], ['bethesda', 'Bethesda', 'Gaming'],

  // ── Media & Entertainment ──────────────────────────────────────────────────
  ['jellyfin', 'Jellyfin', 'Media'], ['plex', 'Plex', 'Media'],
  ['kodi', 'Kodi', 'Media'], ['vlc', 'VLC', 'Media'],
  ['obsstudio', 'OBS Studio', 'Media'], ['streamlabs', 'Streamlabs', 'Media'],
  ['themoviedatabase', 'TMDB', 'Media'], ['tvdb', 'TVDB', 'Media'],
  ['sonarr', 'Sonarr', 'Media'], ['radarr', 'Radarr', 'Media'],
  ['lidarr', 'Lidarr', 'Media'],
  ['youtube', 'YouTube', 'Media'], ['twitch', 'Twitch', 'Media'],
  ['vimeo', 'Vimeo', 'Media'], ['dailymotion', 'Dailymotion', 'Media'],
  ['netflix', 'Netflix', 'Media'], ['hulu', 'Hulu', 'Media'],
  ['disneyplus', 'Disney+', 'Media'], ['crunchyroll', 'Crunchyroll', 'Media'],
  ['primevideo', 'Prime Video', 'Media'],

  // ── Music ──────────────────────────────────────────────────────────────────
  ['spotify', 'Spotify', 'Music'], ['lastdotfm', 'Last.fm', 'Music'],
  ['discogs', 'Discogs', 'Music'], ['soundcloud', 'SoundCloud', 'Music'],
  ['applemusic', 'Apple Music', 'Music'], ['deezer', 'Deezer', 'Music'],
  ['tidal', 'Tidal', 'Music'], ['bandcamp', 'Bandcamp', 'Music'],
  ['musicbrainz', 'MusicBrainz', 'Music'], ['audiomack', 'Audiomack', 'Music'],
  ['mixcloud', 'Mixcloud', 'Music'], ['pandora', 'Pandora', 'Music'],
  ['youtubemusic', 'YouTube Music', 'Music'], ['amazonmusic', 'Amazon Music', 'Music'],

  // ── Social & Comms ─────────────────────────────────────────────────────────
  ['discord', 'Discord', 'Social'], ['slack', 'Slack', 'Social'],
  ['telegram', 'Telegram', 'Social'], ['signal', 'Signal', 'Social'],
  ['whatsapp', 'WhatsApp', 'Social'], ['line', 'LINE', 'Social'],
  ['twitter', 'X / Twitter', 'Social'], ['mastodon', 'Mastodon', 'Social'],
  ['bluesky', 'Bluesky', 'Social'], ['threads', 'Threads', 'Social'],
  ['reddit', 'Reddit', 'Social'], ['instagram', 'Instagram', 'Social'],
  ['facebook', 'Facebook', 'Social'], ['linkedin', 'LinkedIn', 'Social'],
  ['tiktok', 'TikTok', 'Social'], ['pinterest', 'Pinterest', 'Social'],
  ['snapchat', 'Snapchat', 'Social'], ['tumblr', 'Tumblr', 'Social'],
  ['medium', 'Medium', 'Social'], ['devdotto', 'DEV', 'Social'],
  ['stackoverflow', 'Stack Overflow', 'Social'],
  ['ycombinator', 'Hacker News', 'Social'], ['quora', 'Quora', 'Social'],
  ['behance', 'Behance', 'Social'], ['dribbble', 'Dribbble', 'Social'],
  ['artstation', 'ArtStation', 'Social'], ['producthunt', 'Product Hunt', 'Social'],
  ['unsplash', 'Unsplash', 'Social'], ['flickr', 'Flickr', 'Social'],

  // ── Productivity ───────────────────────────────────────────────────────────
  ['notion', 'Notion', 'Productivity'], ['trello', 'Trello', 'Productivity'],
  ['jira', 'Jira', 'Productivity'], ['confluence', 'Confluence', 'Productivity'],
  ['airtable', 'Airtable', 'Productivity'], ['asana', 'Asana', 'Productivity'],
  ['clickup', 'ClickUp', 'Productivity'], ['linear', 'Linear', 'Productivity'],
  ['todoist', 'Todoist', 'Productivity'],
  ['figma', 'Figma', 'Productivity'], ['miro', 'Miro', 'Productivity'],
  ['googledrive', 'Google Drive', 'Productivity'],
  ['googledocs', 'Google Docs', 'Productivity'],
  ['googlesheets', 'Google Sheets', 'Productivity'],
  ['googlemeet', 'Google Meet', 'Productivity'],
  ['microsoftword', 'Word', 'Productivity'],
  ['microsoftexcel', 'Excel', 'Productivity'],
  ['microsoftpowerpoint', 'PowerPoint', 'Productivity'],
  ['microsoftteams', 'Teams', 'Productivity'],
  ['zoom', 'Zoom', 'Productivity'],
  ['zendesk', 'Zendesk', 'Productivity'],
  ['intercom', 'Intercom', 'Productivity'],
  ['hubspot', 'HubSpot', 'Productivity'],
  ['salesforce', 'Salesforce', 'Productivity'],
  ['webflow', 'Webflow', 'Productivity'], ['wordpress', 'WordPress', 'Productivity'],
  ['ghost', 'Ghost', 'Productivity'], ['wix', 'Wix', 'Productivity'],
  ['squarespace', 'Squarespace', 'Productivity'],
  ['contentful', 'Contentful', 'Productivity'],
  ['strapi', 'Strapi', 'Productivity'], ['directus', 'Directus', 'Productivity'],
  ['drupal', 'Drupal', 'Productivity'], ['joomla', 'Joomla', 'Productivity'],
  ['magento', 'Magento', 'Productivity'], ['woocommerce', 'WooCommerce', 'Productivity'],
  ['mailchimp', 'Mailchimp', 'Productivity'],
  ['twilio', 'Twilio', 'Productivity'], ['sendgrid', 'SendGrid', 'Productivity'],
  ['mailgun', 'Mailgun', 'Productivity'],
  ['segment', 'Segment', 'Productivity'], ['hotjar', 'Hotjar', 'Productivity'],
  ['posthog', 'PostHog', 'Productivity'], ['googleanalytics', 'Google Analytics', 'Productivity'],
  ['zapier', 'Zapier', 'Productivity'], ['ifttt', 'IFTTT', 'Productivity'],
  ['pagerduty', 'PagerDuty', 'Productivity'],
  ['mapbox', 'Mapbox', 'Productivity'], ['openstreetmap', 'OpenStreetMap', 'Productivity'],
  ['algolia', 'Algolia', 'Productivity'], ['streamlit', 'Streamlit', 'Productivity'],
  ['mixpanel', 'Mixpanel', 'Productivity'],

  // ── Auth & Security ────────────────────────────────────────────────────────
  ['okta', 'Okta', 'Auth'], ['auth0', 'Auth0', 'Auth'],
  ['keycloak', 'Keycloak', 'Auth'], ['openid', 'OpenID', 'Auth'],
  ['letsencrypt', "Let's Encrypt", 'Auth'],
  ['bitwarden', 'Bitwarden', 'Auth'],
  ['1password', '1Password', 'Auth'],
  ['lastpass', 'LastPass', 'Auth'],
  ['hashicorp', 'HashiCorp', 'Auth'],
  ['wireguard', 'WireGuard', 'Auth'],
  ['tailscale', 'Tailscale', 'Auth'],
  ['openvpn', 'OpenVPN', 'Auth'],

  // ── Finance & Payments ─────────────────────────────────────────────────────
  ['stripe', 'Stripe', 'Finance'], ['paypal', 'PayPal', 'Finance'],
  ['square', 'Square', 'Finance'], ['shopify', 'Shopify', 'Finance'],
  ['coinbase', 'Coinbase', 'Finance'],
  ['ethereum', 'Ethereum', 'Finance'], ['bitcoin', 'Bitcoin', 'Finance'],
  ['binance', 'Binance', 'Finance'], ['solana', 'Solana', 'Finance'],
  ['wise', 'Wise', 'Finance'], ['payoneer', 'Payoneer', 'Finance'],
  ['adyen', 'Adyen', 'Finance'], ['klarna', 'Klarna', 'Finance'],
  ['applepay', 'Apple Pay', 'Finance'], ['googlepay', 'Google Pay', 'Finance'],
  ['revolut', 'Revolut', 'Finance'],

  // ── CI / Monitoring ────────────────────────────────────────────────────────
  ['githubactions', 'GitHub Actions', 'CI'],
  ['circleci', 'CircleCI', 'CI'], ['travisci', 'Travis CI', 'CI'],
  ['jenkins', 'Jenkins', 'CI'], ['sonarcloud', 'SonarCloud', 'CI'],
  ['codecov', 'Codecov', 'CI'], ['sentry', 'Sentry', 'CI'],
  ['datadog', 'Datadog', 'CI'], ['newrelic', 'New Relic', 'CI'],
  ['teamcity', 'TeamCity', 'CI'], ['bamboo', 'Bamboo', 'CI'],
  ['octopusdeploy', 'Octopus Deploy', 'CI'],

  // ── AI / LLM ───────────────────────────────────────────────────────────────
  ['openai', 'OpenAI', 'AI'], ['anthropic', 'Anthropic', 'AI'],
  ['huggingface', 'Hugging Face', 'AI'],
  ['googlegemini', 'Gemini', 'AI'], ['mistral', 'Mistral', 'AI'],
  ['ollama', 'Ollama', 'AI'], ['perplexity', 'Perplexity', 'AI'],

  // ── Misc ───────────────────────────────────────────────────────────────────
  ['google', 'Google', 'Misc'], ['microsoft', 'Microsoft', 'Misc'],
  ['apple', 'Apple', 'Misc'], ['proton', 'Proton', 'Misc'],
  ['wakatime', 'WakaTime', 'Misc'], ['n8n', 'n8n', 'Misc'],
  ['homeassistant', 'Home Assistant', 'Misc'], ['proxmox', 'Proxmox', 'Misc'],
  ['nextcloud', 'Nextcloud', 'Misc'], ['synology', 'Synology', 'Misc'],
  ['googlemaps', 'Google Maps', 'Misc'],
  ['pocketbase', 'PocketBase', 'Misc'],
];

/**
 * Normalised name-to-slug lookup built from {@link SI_REGISTRY} plus manual aliases.
 *
 * Keys are lower-cased and stripped of non-alphanumeric characters so that
 * fuzzy provider-name matching works without exact casing.
 * Manual aliases handle common abbreviations (e.g. `"aws"`, `"gcp"`, `"x"` → `"twitter"`).
 */
const SI_AUTO: Record<string, string> = {};
SI_REGISTRY.forEach(([slug, name]) => {
  const k = name.toLowerCase().replace(/[^a-z0-9]/g, '');
  SI_AUTO[k] = slug;
  SI_AUTO[slug] = slug;
});
Object.assign(SI_AUTO, {
  // Media
  'lastfm': 'lastdotfm', 'last.fm': 'lastdotfm',
  'tmdb': 'themoviedatabase', 'themoviedatabasemdb': 'themoviedatabase',
  'sonarr': 'sonarr', 'radarr': 'radarr', 'lidarr': 'lidarr',
  'jackett': 'sonarr', 'prowlarr': 'sonarr', 'jellyfin': 'jellyfin',
  'obs': 'obsstudio', 'obs studio': 'obsstudio',
  // Cloud shortcuts
  'aws': 'amazonaws', 'gcp': 'googlecloud', 'azure': 'microsoftazure',
  'do': 'digitalocean',
  // Social
  'xtwitter': 'twitter', 'x': 'twitter',
  'devto': 'devdotto', 'dev.to': 'devdotto',
  'hackernews': 'ycombinator', 'hacker news': 'ycombinator', 'hn': 'ycombinator',
  // Gaming
  'riot': 'riotgames', 'riot games': 'riotgames',
  'epic games': 'epicgames', 'nexus mods': 'nexusmods',
  'itchio': 'itchdotio', 'itch.io': 'itchdotio', 'itch': 'itchdotio',
  'electronic arts': 'ea',
  // Dev languages
  'golang': 'go', 'go lang': 'go',
  'c++': 'cplusplus', 'c plus plus': 'cplusplus',
  'c#': 'csharp', 'c sharp': 'csharp',
  '.net': 'dotnet',
  // Frameworks / runtimes
  'node': 'nodedotjs', 'nodejs': 'nodedotjs', 'node.js': 'nodedotjs',
  'rails': 'rubyonrails', 'ror': 'rubyonrails', 'ruby on rails': 'rubyonrails',
  'vue': 'vuedotjs', 'next': 'nextdotjs', 'nuxt': 'nuxtdotjs',
  'alpine': 'alpinedotjs', 'alpine.js': 'alpinedotjs',
  // Editors
  'vscode': 'visualstudiocode', 'vs code': 'visualstudiocode',
  'idea': 'intellijidea', 'intellij': 'intellijidea',
  'eclipse': 'eclipseide',
  // Build tools / queues
  'k8s': 'kubernetes',
  'kafka': 'apachekafka', 'apache kafka': 'apachekafka',
  'maven': 'apachemaven', 'apache maven': 'apachemaven',
  'airflow': 'apacheairflow', 'spark': 'apachespark',
  // OS
  'arch': 'archlinux', 'arch linux': 'archlinux',
  'windows': 'windows11', 'win': 'windows11', 'win11': 'windows11',
  'raspberry pi': 'raspberrypi', 'rpi': 'raspberrypi',
  // Finance / crypto
  'eth': 'ethereum', 'btc': 'bitcoin', 'bnb': 'binance',
  'sol': 'solana', 'transferwise': 'wise',
  // Auth
  'lets encrypt': 'letsencrypt', "let's encrypt": 'letsencrypt',
  '1pass': '1password',
  // Misc DB/data
  'cockroach': 'cockroachdb', 'clickhouse': 'clickhouse',
  // Misc services
  'google maps': 'googlemaps', 'gmaps': 'googlemaps',
  'google analytics': 'googleanalytics', 'ga': 'googleanalytics',
  'google meet': 'googlemeet', 'gmeet': 'googlemeet',
  'google pay': 'googlepay', 'gpay': 'googlepay',
  'apple pay': 'applepay',
  'openstreetmap': 'openstreetmap', 'osm': 'openstreetmap',
  // Legacy / redirects kept
  'topposters': 'themoviedatabase', 'digitalcore': 'themoviedatabase',
  // AI
  'gpt': 'openai', 'chatgpt': 'openai',
  'claude': 'anthropic',
  'gemini': 'googlegemini', 'google gemini': 'googlegemini',
  'hf': 'huggingface',
  // Media
  'prime video': 'primevideo', 'amazon prime': 'primevideo',
  'disney plus': 'disneyplus', 'disney+': 'disneyplus',
});

/**
 * Resolves a Simple Icons slug for a given provider name or custom icon override.
 *
 * Resolution order:
 * 1. If `customIcon` is a non-empty string, return it as-is (explicit override).
 * 2. Strip non-alphanumeric characters from `provider` and look up in {@link SI_AUTO}.
 * 3. Fall back to a trimmed lower-case lookup against the raw provider name.
 * 4. Return `null` if no slug is found (UI will render an initial-letter fallback).
 *
 * @param provider   - Provider display name (e.g. `"GitHub"`, `"AWS"`).
 * @param customIcon - Explicit slug override from the entry's `custom_icon` field.
 * @returns A Simple Icons slug string, or `null` if unresolved.
 */
export function getIconSlug(provider: string, customIcon?: string | null): string | null {
  if (customIcon) return customIcon;
  const k = (provider || '').toLowerCase().replace(/[^a-z0-9.]/g, '');
  return SI_AUTO[k] || SI_AUTO[provider.toLowerCase().trim()] || null;
}

/**
 * Constructs a Simple Icons CDN URL for a given slug.
 *
 * Icons are fetched as light-coloured (`e4e4e4`) SVGs to match dark-theme cards.
 *
 * @param slug - A valid Simple Icons identifier (e.g. `"github"`).
 * @returns Absolute CDN URL string.
 */
function iconImgURL(slug: string): string {
  return `https://cdn.simpleicons.org/${slug}/e4e4e4`;
}

/**
 * Returns an `<img>` tag for a known provider icon, or a letter-initial fallback `<span>`.
 *
 * The `<img>` uses `loading="lazy"` to avoid blocking the initial render.
 * If the CDN request fails at runtime, a global error handler in
 * {@link initIconPicker} replaces the broken image with the letter fallback.
 *
 * @param provider   - Provider name used both for alt text and slug resolution.
 * @param customIcon - Optional explicit slug override.
 * @returns HTML string safe for insertion into `innerHTML`.
 */
export function iconHTML(provider: string, customIcon?: string | null): string {
  const slug = getIconSlug(provider, customIcon);
  const letter = (provider || '?')[0].toUpperCase();
  if (slug) {
    return `<img class="si-icon" src="${iconImgURL(slug)}"
          alt="${(provider || '').replace(/"/g, '&quot;')}" loading="lazy">`;
  }
  return `<span class="si-fallback">${letter}</span>`;
}

/**
 * Shared mutable state for the icon-picker overlay.
 *
 * Using a plain exported object rather than re-assignable variables avoids
 * ESM live-binding issues when the object is imported across modules.
 */
export const iconPicker = {
  /** Callbacks and DOM references for the currently active picker session. */
  target: null as {
    onClose?: (slug: string | null) => void;
    field?: HTMLInputElement;
    preview?: HTMLElement;
  } | null,
  /** The Simple Icons slug that is currently highlighted in the picker grid. */
  selected: null as string | null,
};

/**
 * Renders the icon selection grid filtered by `query`.
 *
 * Matches against both the slug and the display name (case-insensitive).
 * Highlights the currently `iconPicker.selected` item.
 *
 * @param query - Search string; empty string shows all icons.
 */
function renderIconGrid(query: string) {
  const grid = document.getElementById('icon-grid')!;
  const q = query.toLowerCase();
  const items = q
    ? SI_REGISTRY.filter(([s, n]) => s.includes(q) || n.toLowerCase().includes(q))
    : SI_REGISTRY;

  if (!items.length) {
    grid.innerHTML = `<div style="grid-column:1/-1;text-align:center;color:var(--text3);font-size:12px;padding:20px">No icons found</div>`;
    return;
  }

  grid.innerHTML = items.map(([slug, name]) => `
    <div class="icon-item${iconPicker.selected === slug ? ' selected' : ''}"
         data-action="select" data-slug="${slug}" title="${name}">
      <img src="${iconImgURL(slug)}" alt="${name}" width="24" height="24"
           onerror="this.style.opacity='.2';" loading="lazy">
      <div class="icon-item-name">${name}</div>
    </div>
  `).join('');
}

/**
 * Marks a slug as selected, re-renders the grid, and applies the icon to the
 * current picker target immediately so the user sees a live preview.
 *
 * @param slug - Simple Icons slug to select.
 */
function selectIcon(slug: string) {
  iconPicker.selected = slug;
  renderIconGrid((document.getElementById('icon-search') as HTMLInputElement).value);
  applyIconToTarget(slug);
}

/**
 * Writes the chosen slug (or clears it) to the bound form field and preview element.
 *
 * @param slug - Slug to apply, or `null` / empty string to clear the icon.
 */
function applyIconToTarget(slug: string | null) {
  if (!iconPicker.target) return;
  const { field, preview } = iconPicker.target;
  if (field) field.value = slug || '';
  if (preview) preview.innerHTML = slug ? iconHTML('', slug) : '';
}

/**
 * Opens the icon-picker overlay and binds it to the supplied DOM elements.
 *
 * @param fieldEl   - Hidden `<input>` that receives the chosen slug value.
 * @param previewEl - Element that displays a live preview of the selected icon.
 * @param onClose   - Callback fired with the final slug (or `null`) when the picker closes.
 */
export function openIconPicker(
  fieldEl?: HTMLInputElement,
  previewEl?: HTMLElement,
  onClose?: (slug: string | null) => void
) {
  iconPicker.target = { field: fieldEl, preview: previewEl, onClose };
  iconPicker.selected = fieldEl?.value ?? null;
  (document.getElementById('icon-search') as HTMLInputElement).value = '';
  (document.getElementById('icon-manual') as HTMLInputElement).value = '';
  renderIconGrid('');
  document.getElementById('icon-picker-overlay')!.classList.add('open');
  (document.getElementById('icon-search') as HTMLInputElement).focus();
}

/**
 * Closes the icon-picker overlay, fires the `onClose` callback with the final selection,
 * and resets all picker state.
 */
export function closeIconPicker() {
  const slug = iconPicker.selected || null;
  if (iconPicker.target?.onClose) {
    iconPicker.target.onClose(slug);
  } else if (iconPicker.target) {
    applyIconToTarget(slug);
  }
  iconPicker.target = null;
  iconPicker.selected = null;
  document.getElementById('icon-picker-overlay')!.classList.remove('open');
}

/**
 * Attaches all event listeners for the icon-picker overlay.
 *
 * Must be called once during application bootstrap (`init()`).
 * Sets up:
 * - Delegated click handler on `#icon-grid` for icon selection.
 * - Live search filtering via `#icon-search` input.
 * - Close button (`#icon-picker-close`) and backdrop click.
 * - Manual slug entry via `#icon-manual` + `#icon-manual-apply`.
 * - Global `error` capture to replace broken `<img class="si-icon">` with letter fallbacks.
 * - Clear button (`#icon-clear`) to remove the current icon assignment.
 */
export function initIconPicker() {
  // Delegated listener on the icon grid
  document.getElementById('icon-grid')!.addEventListener('click', e => {
    const el = (e.target as HTMLElement).closest<HTMLElement>('[data-action="select"]');
    if (el) selectIcon(el.dataset.slug!);
  });

  document.getElementById('icon-search')!.addEventListener('input', e => renderIconGrid((e.target as HTMLInputElement).value));
  document.getElementById('icon-picker-close')!.addEventListener('click', closeIconPicker);
  document.getElementById('icon-picker-overlay')!.addEventListener('click', e => {
    if (e.target === e.currentTarget) closeIconPicker();
  });
  document.getElementById('icon-manual-apply')!.addEventListener('click', () => {
    const v = (document.getElementById('icon-manual') as HTMLInputElement).value.trim();
    if (v) { selectIcon(v); closeIconPicker(); }
  });
  document.addEventListener('error', (e) => {
    const img = e.target as HTMLImageElement;
    if (!img || !img.classList.contains('si-icon')) return;
    const letter = img.alt?.[0]?.toUpperCase() || '?';
    const span = document.createElement('span');
    span.className = 'si-fallback';
    span.textContent = letter;
    img.replaceWith(span);
  }, true);
  document.getElementById('icon-clear')!.addEventListener('click', () => {
    iconPicker.selected = null;
    selectIcon('');
    closeIconPicker();
  });
}
