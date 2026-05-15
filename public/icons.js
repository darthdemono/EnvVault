/* ── SIMPLE ICONS REGISTRY ─────────────────────────────────────────────────── */
/* Curated slug list. Each entry: [slug, display name, category] */
const SI_REGISTRY = [
  // Dev & APIs
  ['github','GitHub','Dev'],['gitlab','GitLab','Dev'],['bitbucket','Bitbucket','Dev'],
  ['docker','Docker','Dev'],['kubernetes','Kubernetes','Dev'],['npm','npm','Dev'],
  ['pypi','PyPI','Dev'],['rust','Rust','Dev'],['python','Python','Dev'],
  ['typescript','TypeScript','Dev'],['javascript','JavaScript','Dev'],
  ['react','React','Dev'],['vuedotjs','Vue.js','Dev'],['svelte','Svelte','Dev'],
  ['nextdotjs','Next.js','Dev'],['fastapi','FastAPI','Dev'],['flask','Flask','Dev'],
  ['django','Django','Dev'],['postgresql','PostgreSQL','Dev'],['mysql','MySQL','Dev'],
  ['redis','Redis','Dev'],['mongodb','MongoDB','Dev'],['sqlite','SQLite','Dev'],
  ['graphql','GraphQL','Dev'],['swagger','Swagger','Dev'],['postman','Postman','Dev'],
  ['insomnia','Insomnia','Dev'],['git','Git','Dev'],
  // Cloud & Infra
  ['amazonaws','AWS','Cloud'],['googlecloud','GCP','Cloud'],['microsoftazure','Azure','Cloud'],
  ['digitalocean','DigitalOcean','Cloud'],['linode','Linode','Cloud'],['vultr','Vultr','Cloud'],
  ['cloudflare','Cloudflare','Cloud'],['netlify','Netlify','Cloud'],['vercel','Vercel','Cloud'],
  ['heroku','Heroku','Cloud'],['railway','Railway','Cloud'],['fly','Fly.io','Cloud'],
  ['nginx','nginx','Cloud'],['traefik','Traefik','Cloud'],
  ['grafana','Grafana','Cloud'],['prometheus','Prometheus','Cloud'],
  ['elasticsearch','Elasticsearch','Cloud'],
  // Media & Entertainment
  ['jellyfin','Jellyfin','Media'],['plex','Plex','Media'],['kodi','Kodi','Media'],
  ['themoviedatabase','TMDB','Media'],['tvdb','TVDB','Media'],
  ['sonarr','Sonarr','Media'],['radarr','Radarr','Media'],
  ['youtube','YouTube','Media'],['twitch','Twitch','Media'],
  ['vimeo','Vimeo','Media'],['dailymotion','Dailymotion','Media'],
  // Music
  ['spotify','Spotify','Music'],['lastdotfm','Last.fm','Music'],
  ['discogs','Discogs','Music'],['soundcloud','SoundCloud','Music'],
  ['applemusic','Apple Music','Music'],['deezer','Deezer','Music'],
  ['tidal','Tidal','Music'],['bandcamp','Bandcamp','Music'],
  ['musicbrainz','MusicBrainz','Music'],
  // Social & Comms
  ['discord','Discord','Social'],['slack','Slack','Social'],
  ['telegram','Telegram','Social'],['signal','Signal','Social'],
  ['twitter','X / Twitter','Social'],['mastodon','Mastodon','Social'],
  ['reddit','Reddit','Social'],['instagram','Instagram','Social'],
  ['facebook','Facebook','Social'],['linkedin','LinkedIn','Social'],
  ['tiktok','TikTok','Social'],['pinterest','Pinterest','Social'],
  // Productivity
  ['notion','Notion','Productivity'],['trello','Trello','Productivity'],
  ['jira','Jira','Productivity'],['confluence','Confluence','Productivity'],
  ['airtable','Airtable','Productivity'],['asana','Asana','Productivity'],
  ['figma','Figma','Productivity'],['miro','Miro','Productivity'],
  ['googledrive','Google Drive','Productivity'],['googledocs','Google Docs','Productivity'],
  ['googlesheets','Google Sheets','Productivity'],
  ['microsoftword','Word','Productivity'],['microsoftexcel','Excel','Productivity'],
  // Auth & Security
  ['okta','Okta','Auth'],['auth0','Auth0','Auth'],
  ['keycloak','Keycloak','Auth'],['openid','OpenID','Auth'],
  // Finance & Payments
  ['stripe','Stripe','Finance'],['paypal','PayPal','Finance'],
  ['square','Square','Finance'],['shopify','Shopify','Finance'],
  ['coinbase','Coinbase','Finance'],
  // Dev Tools & CI
  ['githubactions','GitHub Actions','CI'],['circleci','CircleCI','CI'],
  ['travisci','Travis CI','CI'],['jenkins','Jenkins','CI'],
  ['sonarcloud','SonarCloud','CI'],['codecov','Codecov','CI'],
  ['sentry','Sentry','CI'],['datadog','Datadog','CI'],
  ['newrelic','New Relic','CI'],
  // Misc
  ['google','Google','Misc'],['microsoft','Microsoft','Misc'],
  ['apple','Apple','Misc'],['proton','Proton','Misc'],
  ['bitwarden','Bitwarden','Misc'],['openai','OpenAI','Misc'],
  ['anthropic','Anthropic','Misc'],['huggingface','Hugging Face','Misc'],
  ['wakatime','WakaTime','Misc'],['n8n','n8n','Misc'],
  ['homeassistant','Home Assistant','Misc'],['proxmox','Proxmox','Misc'],
  ['nextcloud','Nextcloud','Misc'],['synology','Synology','Misc'],
];

/* Auto-detect map: normalized provider name → slug */
const SI_AUTO = {};
SI_REGISTRY.forEach(([slug, name]) => {
  const k = name.toLowerCase().replace(/[^a-z0-9]/g,'');
  SI_AUTO[k] = slug;
  SI_AUTO[slug] = slug;
});
// Manual aliases
Object.assign(SI_AUTO, {
  'lastfm':'lastdotfm','last.fm':'lastdotfm',
  'tmdb':'themoviedatabase','themoviedatabasemdb':'themoviedatabase',
  'jellyfin':'jellyfin','sonarr':'sonarr','radarr':'radarr',
  'aws':'amazonaws','gcp':'googlecloud','azure':'microsoftazure',
  'xtwitter':'twitter','x':'twitter',
  'riotgames':'riotgames','riot':'riotgames','riot games':'riotgames',
  'epicgames':'epicgames','epic games':'epicgames','epicgames':'epicgames',
  'nexusmods':'nexusmods','nexus mods':'nexusmods',
  'topposters':'themoviedatabase','digitalcore':'themoviedatabase',
  'jackett':'sonarr', // closest visual match
  'prowlarr':'sonarr',
});

function getIconSlug(provider, customIcon) {
  if (customIcon) return customIcon;
  const k = (provider || '').toLowerCase().replace(/[^a-z0-9.]/g,'');
  return SI_AUTO[k] || SI_AUTO[provider.toLowerCase().trim()] || null;
}

function iconImgURL(slug) {
  // Uses Simple Icons CDN — color e4e4e4 works on dark themes; CSS will invert for light
  return `https://cdn.simpleicons.org/${slug}/e4e4e4`;
}

function iconHTML(provider, customIcon) {
  const slug = getIconSlug(provider, customIcon);
  const letter = (provider || '?')[0].toUpperCase();
  if (slug) {
    return `<img class="si-icon" src="${iconImgURL(slug)}"
      onerror="this.replaceWith(Object.assign(document.createElement('span'),{className:'si-fallback',textContent:'${letter.replace("'","\\'")}'}));"
      alt="${(provider||'').replace(/"/g,'&quot;')}" loading="lazy">`;
  }
  return `<span class="si-fallback">${letter}</span>`;
}

/* ── ICON PICKER ───────────────────────────────────────────────────────────── */
// var (not let) so vault.js can read/write these across script tags
var _iconPickerTarget = null;
var _iconQuery = '';
var _iconSelected = null;

function openIconPicker(fieldEl, previewEl) {
  _iconPickerTarget = { field: fieldEl, preview: previewEl };
  _iconSelected = fieldEl.value || null;
  _iconQuery = '';
  document.getElementById('icon-search').value = '';
  document.getElementById('icon-manual').value = '';
  renderIconGrid('');
  document.getElementById('icon-picker-overlay').classList.add('open');
  document.getElementById('icon-search').focus();
}

function renderIconGrid(query) {
  const grid = document.getElementById('icon-grid');
  const q = query.toLowerCase();
  const items = q
    ? SI_REGISTRY.filter(([s, n]) => s.includes(q) || n.toLowerCase().includes(q))
    : SI_REGISTRY;

  if (!items.length) {
    grid.innerHTML = `<div style="grid-column:1/-1;text-align:center;color:var(--text3);font-size:12px;padding:20px">No icons found</div>`;
    return;
  }

  grid.innerHTML = items.map(([slug, name]) => `
    <div class="icon-item${_iconSelected === slug ? ' selected' : ''}"
         onclick="selectIcon('${slug}')" title="${name}">
      <img src="${iconImgURL(slug)}" alt="${name}" width="24" height="24"
           onerror="this.style.opacity='.2';" loading="lazy">
      <div class="icon-item-name">${name}</div>
    </div>
  `).join('');
}

function selectIcon(slug) {
  _iconSelected = slug;
  renderIconGrid(document.getElementById('icon-search').value);
  applyIconToTarget(slug);
}

function applyIconToTarget(slug) {
  if (!_iconPickerTarget) return;
  const { field, preview } = _iconPickerTarget;
  field.value = slug || '';
  preview.innerHTML = slug ? iconHTML('', slug) : '';
}

function closeIconPicker() {
  // Fire onClose if vault.js set a direct callback (card icon-click flow)
  if (_iconPickerTarget && typeof _iconPickerTarget.onClose === 'function') {
    _iconPickerTarget.onClose(_iconSelected || null);
  } else if (_iconPickerTarget) {
    applyIconToTarget(_iconSelected || '');
  }
  _iconPickerTarget = null;
  _iconSelected     = null;
  document.getElementById('icon-picker-overlay').classList.remove('open');
}

// Wire icon picker events (called after DOM ready).
// Arrow wrappers ensure calls resolve closeIconPicker at call-time,
// so any override set by vault.js is respected.
function initIconPicker() {
  document.getElementById('icon-search').addEventListener('input', e => renderIconGrid(e.target.value));
  document.getElementById('icon-picker-close').addEventListener('click',   () => closeIconPicker());
  document.getElementById('icon-picker-overlay').addEventListener('click', e => {
    if (e.target === e.currentTarget) closeIconPicker();
  });
  document.getElementById('icon-manual-apply').addEventListener('click', () => {
    const v = document.getElementById('icon-manual').value.trim();
    if (v) { selectIcon(v); closeIconPicker(); }
  });
  document.getElementById('icon-clear').addEventListener('click', () => {
    _iconSelected = null;
    selectIcon('');
    closeIconPicker();
  });
}