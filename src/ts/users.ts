/**
 * @file Users panel — multi-user RBAC management for vault owners.
 */

import type { UserInfo, TokenInfo, PermissionEntry, UserClass, ClassPermission } from './types';
import { st } from './state';
import { esc, escAttr, showToast, showConfirm, showPrompt, clipboardWrite } from './utils';

const invoke = (cmd: string, args?: Record<string, any>) =>
  (window as any).__TAURI__?.core?.invoke?.(cmd, args) as Promise<any> | undefined;

// ── Render user list ──────────────────────────────────────────────────────────

export async function renderUsersPanel() {
  const listEl = document.getElementById('users-list');
  if (!listEl) return;

  let users: UserInfo[] = [];
  try {
    users = await invoke?.('list_users') ?? [];
  } catch (e: any) {
    listEl.innerHTML = `<div class="users-empty">Could not load users: ${esc(String(e?.message ?? e))}</div>`;
    return;
  }

  listEl.innerHTML = users.map(u => `
    <button class="users-list-item${st.selectedUserId === u.id ? ' active' : ''}" data-user-id="${escAttr(u.id)}">
      <span class="user-avatar${u.is_owner ? ' owner' : ''}">${esc(u.username.slice(0, 2).toUpperCase())}</span>
      <span class="user-info">
        <span class="user-name">${esc(u.username)}
          ${u.is_owner ? '<span class="user-badge owner-badge">Owner</span>' : ''}
        </span>
        <span class="user-meta">
          ${u.has_password ? '⬤ password' : '⬤ token-only'}
          ${u.last_seen_at ? ' · ' + u.last_seen_at.slice(0, 10) : ' · never seen'}
        </span>
      </span>
    </button>
  `).join('') || '<div class="users-empty">No users yet. Create one to get started.</div>';
}

// ── Render user detail ────────────────────────────────────────────────────────

export async function renderUserDetail(userId: string) {
  const ws = document.getElementById('users-workspace');
  if (!ws) return;

  ws.innerHTML = '<div class="users-detail-loading">Loading…</div>';

  let users: UserInfo[] = [];
  let tokens: TokenInfo[] = [];
  let perms: PermissionEntry[] = [];
  let classes: UserClass[] = [];

  try {
    // NOTE: Tauri 2 expects camelCase arg names for command parameters
    [users, tokens, perms, classes] = await Promise.all([
      invoke?.('list_users') ?? [],
      invoke?.('list_user_tokens', { userId }) ?? [],
      invoke?.('get_user_permissions', { userId }) ?? [],
      invoke?.('list_user_classes') ?? [],
    ]);
  } catch (e: any) {
    ws.innerHTML = `<div class="users-detail-empty">
      <div class="users-detail-error">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        ${esc(String(e?.message ?? e))}
      </div>
    </div>`;
    return;
  }

  const user = users.find((u: UserInfo) => u.id === userId);
  if (!user) { ws.innerHTML = '<div class="users-detail-empty">User not found.</div>'; return; }

  const scopeTypeOpts = ['vault', 'project', 'category'].map(t =>
    `<option value="${t}">${t}</option>`).join('');
  const permLevelOpts = ['read', 'write'].map(l =>
    `<option value="${l}">${l}</option>`).join('');

  ws.innerHTML = `
    <div class="users-detail">

      <!-- Header -->
      <div class="users-detail-header">
        <div class="users-detail-avatar${user.is_owner ? ' owner' : ''}">${esc(user.username.slice(0, 2).toUpperCase())}</div>
        <div class="users-detail-meta">
          <div class="users-detail-name">
            <span id="detail-username-label">${esc(user.username)}</span>
            ${user.is_owner ? '<span class="user-badge owner-badge">Owner</span>' : ''}
            ${user.has_password ? '' : '<span class="user-badge token-badge">token-only</span>'}
            <button class="icon-action-btn" id="rename-user-btn" title="Rename user">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
              </svg>
            </button>
          </div>
          <div id="rename-user-form" class="rename-form" style="display:none">
            <input id="rename-user-input" class="tool-input rename-input" value="${escAttr(user.username)}" maxlength="64" placeholder="new username">
            <button class="btn btn-xs accent" id="rename-user-confirm">Save</button>
            <button class="btn btn-xs btn-ghost" id="rename-user-cancel">Cancel</button>
          </div>
          <div class="users-detail-sub">
            Created ${esc(user.created_at.slice(0, 10))}
            ${user.last_seen_at ? ' · Last seen ' + esc(user.last_seen_at.slice(0, 10)) : ' · never seen'}
          </div>
        </div>
        <div class="users-detail-actions">
          <button class="btn btn-xs" id="change-pw-btn">Change Password</button>
          ${!user.is_owner ? `<button class="btn btn-xs danger" id="delete-user-btn">Delete User</button>` : ''}
        </div>
      </div>

      <!-- Class assignment (non-owner only) -->
      ${!user.is_owner ? `
      <div class="user-class-row">
        <span class="user-class-label">Role / Class</span>
        <select id="user-class-select" class="perm-input" style="min-width:160px">
          <option value="">— No class assigned —</option>
          ${classes.map(c => `<option value="${escAttr(c.id)}"${user.class_id === c.id ? ' selected' : ''}>${esc(c.name)}</option>`).join('')}
        </select>
        <button class="btn btn-xs accent" id="assign-class-btn">Apply</button>
        <span class="user-class-hint">Effective permissions = class + individual rules below</span>
      </div>` : ''}

      <!-- Tokens -->
      <section class="users-section">
        <div class="users-section-head">
          <span>Access Tokens</span>
          <button class="btn btn-xs accent" id="new-token-btn">+ New Token</button>
        </div>
        <div id="tokens-list" class="tokens-list">
          ${tokens.length ? tokens.map((t: TokenInfo) => `
            <div class="token-row">
              <div class="token-info">
                <span class="token-desc">${esc(t.description ?? 'Unnamed token')}</span>
                <span class="token-meta">Created ${esc(t.created_at.slice(0, 10))} · ${t.expires_at ? 'expires ' + esc(t.expires_at.slice(0, 10)) : 'never expires'}</span>
              </div>
              <button class="btn btn-xs danger revoke-token-btn" data-token-id="${escAttr(t.id)}">Revoke</button>
            </div>
          `).join('') : '<div class="users-empty">No tokens — create one so this user can authenticate via CLI or API.</div>'}
        </div>
      </section>

      <!-- Permissions -->
      <section class="users-section">
        <div class="users-section-head">
          <span>Permissions</span>
          <button class="btn btn-xs accent" id="add-perm-btn">+ Add Rule</button>
        </div>

        ${!perms.length ? `
          <div class="perm-empty-state">
            <div class="perm-empty-icon">⊘</div>
            <div>No permissions — this user cannot access any vault data.</div>
            <div style="font-size:11px;color:var(--text3);margin-top:4px">Add rules to grant read or write access to vault, projects, or categories.</div>
          </div>
        ` : ''}

        <div id="perms-list" class="perms-list">
          ${perms.map((p: PermissionEntry, i: number) => `
            <div class="perm-row" data-perm-idx="${i}">
              <span class="perm-badge scope-${p.scope_type}">${esc(p.scope_type)}</span>
              <span class="perm-scope-value">${esc(p.scope_value)}</span>
              <span class="perm-badge level-${p.permission}">${esc(p.permission)}</span>
              <button class="btn btn-xs danger del-perm-btn" data-perm-idx="${i}" title="Remove permission">✕</button>
            </div>
          `).join('')}
        </div>

        <div id="perm-add-form" class="perm-add-form" style="display:none">
          <div class="perm-add-row">
            <div class="perm-add-group">
              <label class="perm-add-label">Scope type</label>
              <select id="perm-scope-type" class="perm-input">${scopeTypeOpts}</select>
            </div>
            <div class="perm-add-group perm-add-flex">
              <label class="perm-add-label">Value <span class="perm-add-hint">(glob: * = all, wg0-* = prefix)</span></label>
              <input id="perm-scope-value" class="perm-input" placeholder="* or glob pattern" value="*">
            </div>
            <div class="perm-add-group">
              <label class="perm-add-label">Level</label>
              <select id="perm-level" class="perm-input">${permLevelOpts}</select>
            </div>
          </div>
          <div style="display:flex;gap:6px;margin-top:8px">
            <button class="btn btn-xs accent" id="perm-add-confirm">Add Rule</button>
            <button class="btn btn-xs btn-ghost" id="perm-add-cancel">Cancel</button>
          </div>
        </div>
      </section>

    </div>
  `;

  // ── Event bindings ──────────────────────────────────────────────────────────

  document.getElementById('rename-user-btn')?.addEventListener('click', () => {
    const form = document.getElementById('rename-user-form')!;
    const isHidden = form.style.display === 'none';
    form.style.display = isHidden ? 'flex' : 'none';
    if (isHidden) (document.getElementById('rename-user-input') as HTMLInputElement)?.focus();
  });
  document.getElementById('rename-user-cancel')?.addEventListener('click', () => {
    document.getElementById('rename-user-form')!.style.display = 'none';
  });
  document.getElementById('rename-user-confirm')?.addEventListener('click', () => renameUser(userId));

  document.getElementById('change-pw-btn')?.addEventListener('click', () => changePassword(userId));
  document.getElementById('delete-user-btn')?.addEventListener('click', () => deleteUser(userId));
  document.getElementById('assign-class-btn')?.addEventListener('click', async () => {
    const sel = (document.getElementById('user-class-select') as HTMLSelectElement).value || null;
    try {
      await invoke?.('assign_user_class', { userId, classId: sel });
      showToast(sel ? 'Class assigned' : 'Class removed', 'ok');
      await renderUserDetail(userId);
    } catch (e: any) { showToast('Failed: ' + (e?.message ?? e), 'err'); }
  });
  document.getElementById('new-token-btn')?.addEventListener('click', () => newToken(userId));

  document.getElementById('add-perm-btn')?.addEventListener('click', () => {
    const form = document.getElementById('perm-add-form')!;
    form.style.display = form.style.display === 'none' ? 'block' : 'none';
  });
  document.getElementById('perm-add-cancel')?.addEventListener('click', () => {
    document.getElementById('perm-add-form')!.style.display = 'none';
  });
  document.getElementById('perm-add-confirm')?.addEventListener('click', () => addPermission(userId, perms));

  document.querySelectorAll<HTMLButtonElement>('.revoke-token-btn').forEach(btn => {
    btn.addEventListener('click', () => revokeToken(btn.dataset.tokenId!, userId));
  });
  document.querySelectorAll<HTMLButtonElement>('.del-perm-btn').forEach(btn => {
    btn.addEventListener('click', () => deletePermission(userId, perms, parseInt(btn.dataset.permIdx!)));
  });
}

// ── Actions ───────────────────────────────────────────────────────────────────

async function renameUser(userId: string) {
  const val = (document.getElementById('rename-user-input') as HTMLInputElement).value.trim();
  if (!val) { showToast('Username cannot be empty', 'err'); return; }
  try {
    // Tauri 2: camelCase param names
    await invoke?.('rename_user', { userId, newUsername: val });
    showToast(`Renamed to "${val}"`, 'ok');
    await renderUsersPanel();
    await renderUserDetail(userId);
  } catch (e: any) {
    showToast('Rename failed: ' + (e?.message ?? e), 'err');
  }
}

async function changePassword(userId: string) {
  const pw = await showPrompt('New password (leave blank to switch to token-only auth):');
  if (pw === null) return;
  try {
    await invoke?.('set_user_password', { userId, password: pw || null });
    showToast(pw ? 'Password updated' : 'Switched to token-only auth', 'ok');
    await renderUserDetail(userId);
  } catch (e: any) {
    showToast('Failed: ' + (e?.message ?? e), 'err');
  }
}

async function deleteUser(userId: string) {
  if (!await showConfirm('Delete this user and all their tokens and permissions? This cannot be undone.')) return;
  try {
    await invoke?.('delete_user', { userId });
    st.selectedUserId = null;
    showToast('User deleted', 'ok');
    await renderUsersPanel();
    const ws = document.getElementById('users-workspace')!;
    ws.innerHTML = '<div class="users-detail-empty">Select a user to manage, or create one.</div>';
  } catch (e: any) {
    showToast('Delete failed: ' + (e?.message ?? e), 'err');
  }
}

async function newToken(userId: string) {
  const desc = await showPrompt('Token description (e.g. "laptop CLI", "CI pipeline"):');
  if (desc === null) return;
  try {
    const result = await invoke?.('create_user_token', { userId, description: desc ?? '' });
    const token = result?.token as string;
    if (!token) { showToast('Token creation failed', 'err'); return; }
    showTokenCreatedOverlay(token);
    await renderUserDetail(userId);
  } catch (e: any) {
    showToast('Token creation failed: ' + (e?.message ?? e), 'err');
  }
}

function showTokenCreatedOverlay(token: string) {
  const overlay = document.createElement('div');
  overlay.className = 'token-overlay-backdrop';
  overlay.innerHTML = `
    <div class="token-overlay-card">
      <div class="token-overlay-title">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
        </svg>
        Token Created
      </div>
      <div class="token-overlay-sub">Copy this token now — it will <strong>not</strong> be shown again.</div>
      <div class="token-overlay-value" id="token-display">${esc(token)}</div>
      <div class="token-overlay-actions">
        <button id="copy-new-token" class="btn btn-sm btn-accent">Copy Token</button>
        <button id="close-token-overlay" class="btn btn-sm btn-ghost">Done</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  overlay.querySelector('#copy-new-token')!.addEventListener('click', () =>
    clipboardWrite(token).then(() => showToast('Copied ✓', 'ok', 1500)));
  const close = () => { if (document.body.contains(overlay)) document.body.removeChild(overlay); };
  overlay.querySelector('#close-token-overlay')!.addEventListener('click', close);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
}

async function revokeToken(tokenId: string, userId: string) {
  if (!await showConfirm('Revoke this token? The token will stop working immediately.')) return;
  try {
    await invoke?.('revoke_user_token', { tokenId });
    showToast('Token revoked', 'ok');
    await renderUserDetail(userId);
  } catch (e: any) {
    showToast('Revoke failed: ' + (e?.message ?? e), 'err');
  }
}

async function addPermission(userId: string, currentPerms: PermissionEntry[]) {
  const scopeType  = (document.getElementById('perm-scope-type') as HTMLSelectElement).value as PermissionEntry['scope_type'];
  const scopeValue = (document.getElementById('perm-scope-value') as HTMLInputElement).value.trim();
  const permission = (document.getElementById('perm-level') as HTMLSelectElement).value as PermissionEntry['permission'];
  if (!scopeValue) { showToast('Scope value is required', 'err'); return; }

  const newPerm: PermissionEntry = { user_id: userId, scope_type: scopeType, scope_value: scopeValue, permission };
  const updated = [...currentPerms.filter(p => !(p.scope_type === scopeType && p.scope_value === scopeValue)), newPerm];

  try {
    await invoke?.('set_user_permissions', { userId, permissions: updated });
    showToast('Permission added', 'ok');
    await renderUserDetail(userId);
  } catch (e: any) {
    showToast('Failed: ' + (e?.message ?? e), 'err');
  }
}

async function deletePermission(userId: string, currentPerms: PermissionEntry[], idx: number) {
  const updated = currentPerms.filter((_, i) => i !== idx);
  try {
    await invoke?.('set_user_permissions', { userId, permissions: updated });
    showToast('Permission removed', 'ok');
    await renderUserDetail(userId);
  } catch (e: any) {
    showToast('Failed: ' + (e?.message ?? e), 'err');
  }
}

// ── Create user form ──────────────────────────────────────────────────────────

export async function openCreateUserForm() {
  const ws = document.getElementById('users-workspace');
  if (!ws) return;
  ws.innerHTML = `
    <div class="users-detail">
      <div class="users-detail-header" style="border-bottom:1px solid var(--border);padding-bottom:16px;margin-bottom:0">
        <div class="users-detail-avatar" style="background:var(--surface3)">+</div>
        <div class="users-detail-meta">
          <div class="users-detail-name">Create New User</div>
          <div class="users-detail-sub">Users can authenticate via password or tokens.</div>
        </div>
      </div>
      <section class="users-section">
        <div class="users-section-head"><span>User Details</span></div>
        <div class="create-user-form">
          <label class="user-form-label">Username
            <input id="new-user-name" class="tool-input user-form-field" placeholder="alice" autocomplete="off" spellcheck="false">
          </label>
          <label class="user-form-label">
            Password
            <span class="form-label-hint">optional — leave blank for token-only auth</span>
            <input id="new-user-password" type="password" class="tool-input user-form-field" placeholder="••••••••" autocomplete="new-password">
          </label>
          <div class="create-user-actions">
            <button class="btn btn-sm btn-accent" id="confirm-create-user">Create User</button>
            <button class="btn btn-sm btn-ghost" id="cancel-create-user">Cancel</button>
          </div>
        </div>
      </section>
    </div>`;

  (document.getElementById('new-user-name') as HTMLInputElement)?.focus();

  document.getElementById('confirm-create-user')!.addEventListener('click', async () => {
    const username = (document.getElementById('new-user-name') as HTMLInputElement).value.trim();
    const password = (document.getElementById('new-user-password') as HTMLInputElement).value || undefined;
    if (!username) { showToast('Username is required', 'err'); return; }
    try {
      const user: UserInfo = await invoke?.('create_user', { username, password }) ?? null;
      if (!user) { showToast('Failed to create user', 'err'); return; }
      showToast(`User "${username}" created`, 'ok');
      st.selectedUserId = user.id;
      await renderUsersPanel();
      await renderUserDetail(user.id);
    } catch (e: any) {
      showToast('Failed: ' + (e?.message ?? e), 'err');
    }
  });
  document.getElementById('cancel-create-user')!.addEventListener('click', () => {
    ws.innerHTML = '<div class="users-detail-empty">Select a user to manage, or create one.</div>';
  });
}

// ── Class management ──────────────────────────────────────────────────────────

let _activeClassId: string | null = null;

export async function renderClassesPanel() {
  const listEl = document.getElementById('classes-list');
  if (!listEl) return;
  let classes: UserClass[] = [];
  try { classes = await invoke?.('list_user_classes') ?? []; }
  catch (e: any) { listEl.innerHTML = `<div class="users-empty">${esc(String(e?.message ?? e))}</div>`; return; }

  listEl.innerHTML = classes.map(c => `
    <button class="users-list-item${_activeClassId === c.id ? ' active' : ''}" data-class-id="${escAttr(c.id)}">
      <span class="class-dot${c.cap_manage_classes ? ' admin-dot' : c.cap_manage_users ? ' mod-dot' : ''}"></span>
      <span class="user-info">
        <span class="user-name">${esc(c.name)}</span>
        <span class="user-meta">${esc(c.description) || '—'}</span>
      </span>
    </button>
  `).join('') || '<div class="users-empty">No classes found.</div>';
}

async function renderClassDetail(classId: string) {
  const ws = document.getElementById('users-workspace');
  if (!ws) return;
  _activeClassId = classId;
  await renderClassesPanel();

  let classes: UserClass[] = [];
  let perms: ClassPermission[] = [];
  try {
    [classes, perms] = await Promise.all([
      invoke?.('list_user_classes') ?? [],
      invoke?.('get_class_permissions', { classId }) ?? [],
    ]);
  } catch (e: any) {
    ws.innerHTML = `<div class="users-detail-empty">${esc(String(e?.message ?? e))}</div>`;
    return;
  }
  const cls = classes.find(c => c.id === classId);
  if (!cls) { ws.innerHTML = '<div class="users-detail-empty">Class not found.</div>'; return; }

  const isBuiltin = classId.startsWith('cls-');

  ws.innerHTML = `
    <div class="users-detail">
      <div class="users-detail-header">
        <div class="users-detail-avatar" style="background:${cls.cap_manage_classes ? 'var(--accent-dim)' : cls.cap_manage_users ? 'rgba(88,180,220,.14)' : 'var(--surface3)'}; color:${cls.cap_manage_classes ? 'var(--accent)' : cls.cap_manage_users ? '#58b4dc' : 'var(--text3)'}; font-size:14px">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>
        </div>
        <div class="users-detail-meta" style="flex:1">
          <div class="users-detail-name">${esc(cls.name)}</div>
          <div class="users-detail-sub">${esc(cls.description) || 'No description'}</div>
        </div>
        <div class="users-detail-actions">
          ${!isBuiltin ? `<button class="btn btn-xs danger" id="delete-class-btn">Delete</button>` : '<span style="font-size:10px;color:var(--text3)">built-in</span>'}
        </div>
      </div>

      <!-- Edit class name/description -->
      <section class="users-section">
        <div class="users-section-head"><span>Class Details</span></div>
        <div class="create-user-form" style="max-width:380px">
          <label class="user-form-label">Name
            <input id="cls-name" class="tool-input user-form-field" value="${escAttr(cls.name)}" maxlength="48">
          </label>
          <label class="user-form-label">Description
            <input id="cls-desc" class="tool-input user-form-field" value="${escAttr(cls.description)}" placeholder="What can this class do?">
          </label>
        </div>
      </section>

      <!-- Capabilities -->
      <section class="users-section">
        <div class="users-section-head"><span>Capabilities</span></div>
        <div class="class-caps-grid">
          <label class="class-cap-row">
            <input type="checkbox" id="cap-manage-users" ${cls.cap_manage_users ? 'checked' : ''}>
            <span class="class-cap-info">
              <span class="class-cap-name">Manage Users</span>
              <span class="class-cap-desc">Create and delete users, assign classes</span>
            </span>
          </label>
          <label class="class-cap-row">
            <input type="checkbox" id="cap-manage-classes" ${cls.cap_manage_classes ? 'checked' : ''}>
            <span class="class-cap-info">
              <span class="class-cap-name">Manage Classes</span>
              <span class="class-cap-desc">Create, edit and delete user classes</span>
            </span>
          </label>
          <label class="class-cap-row">
            <input type="checkbox" id="cap-delete-projects" ${cls.cap_delete_projects ? 'checked' : ''}>
            <span class="class-cap-info">
              <span class="class-cap-name">Delete Projects</span>
              <span class="class-cap-desc">Can remove projects from the vault</span>
            </span>
          </label>
        </div>
        <div style="margin-top:10px">
          <button class="btn btn-xs accent" id="save-class-btn">Save Changes</button>
        </div>
      </section>

      <!-- Class permissions -->
      <section class="users-section">
        <div class="users-section-head">
          <span>Permissions</span>
          <button class="btn btn-xs accent" id="add-class-perm-btn">+ Add Rule</button>
        </div>
        <div class="perm-empty-state" style="${perms.length ? 'display:none' : ''}">
          <div class="perm-empty-icon">⊘</div>
          <div>No permission rules. All members of this class have no access.</div>
        </div>
        <div class="perms-list" id="class-perms-list">
          ${perms.map((p, i) => `
            <div class="perm-row" data-perm-idx="${i}">
              <span class="perm-badge scope-${p.scope_type}">${esc(p.scope_type)}</span>
              <span class="perm-scope-value">${esc(p.scope_value)}</span>
              <span class="perm-badge level-${p.permission}">${esc(p.permission)}</span>
              <button class="btn btn-xs danger del-class-perm-btn" data-perm-idx="${i}">✕</button>
            </div>
          `).join('')}
        </div>
        <div id="class-perm-add-form" class="perm-add-form" style="display:none">
          <div class="perm-add-row">
            <div class="perm-add-group">
              <label class="perm-add-label">Scope type</label>
              <select id="cls-perm-scope-type" class="perm-input">
                <option value="vault">vault</option>
                <option value="project">project</option>
                <option value="category">category</option>
              </select>
            </div>
            <div class="perm-add-group perm-add-flex">
              <label class="perm-add-label">Value <span class="perm-add-hint">(* = all, project-* = prefix glob)</span></label>
              <input id="cls-perm-scope-value" class="perm-input" placeholder="* or glob" value="*">
            </div>
            <div class="perm-add-group">
              <label class="perm-add-label">Level</label>
              <select id="cls-perm-level" class="perm-input">
                <option value="read">read</option>
                <option value="write">write</option>
              </select>
            </div>
          </div>
          <div style="display:flex;gap:6px;margin-top:8px">
            <button class="btn btn-xs accent" id="cls-perm-add-confirm">Add Rule</button>
            <button class="btn btn-xs btn-ghost" id="cls-perm-add-cancel">Cancel</button>
          </div>
        </div>
      </section>
    </div>
  `;

  document.getElementById('delete-class-btn')?.addEventListener('click', () => deleteClass(classId));
  document.getElementById('save-class-btn')?.addEventListener('click', () => saveClassDetails(classId));
  document.getElementById('add-class-perm-btn')?.addEventListener('click', () => {
    const f = document.getElementById('class-perm-add-form')!;
    f.style.display = f.style.display === 'none' ? 'block' : 'none';
  });
  document.getElementById('cls-perm-add-cancel')?.addEventListener('click', () => {
    document.getElementById('class-perm-add-form')!.style.display = 'none';
  });
  document.getElementById('cls-perm-add-confirm')?.addEventListener('click', () => addClassPermission(classId, perms));
  document.querySelectorAll<HTMLButtonElement>('.del-class-perm-btn').forEach(btn => {
    btn.addEventListener('click', () => deleteClassPermission(classId, perms, parseInt(btn.dataset.permIdx!)));
  });
}

async function saveClassDetails(classId: string) {
  const name        = (document.getElementById('cls-name')         as HTMLInputElement).value.trim();
  const description = (document.getElementById('cls-desc')         as HTMLInputElement).value.trim();
  const cap_manage_users    = (document.getElementById('cap-manage-users')    as HTMLInputElement).checked;
  const cap_manage_classes  = (document.getElementById('cap-manage-classes')  as HTMLInputElement).checked;
  const cap_delete_projects = (document.getElementById('cap-delete-projects') as HTMLInputElement).checked;
  if (!name) { showToast('Name is required', 'err'); return; }
  try {
    await invoke?.('update_user_class', { classId, name, description, capManageUsers: cap_manage_users, capManageClasses: cap_manage_classes, capDeleteProjects: cap_delete_projects });
    showToast('Class updated', 'ok');
    await renderClassDetail(classId);
  } catch (e: any) { showToast('Failed: ' + (e?.message ?? e), 'err'); }
}

async function deleteClass(classId: string) {
  if (!await showConfirm('Delete this class? Users assigned to it will lose their class permissions.')) return;
  try {
    await invoke?.('delete_user_class', { classId });
    showToast('Class deleted', 'ok');
    _activeClassId = null;
    await renderClassesPanel();
    const ws = document.getElementById('users-workspace');
    if (ws) ws.innerHTML = '<div class="users-detail-empty">Select a class to manage, or create one.</div>';
  } catch (e: any) { showToast('Failed: ' + (e?.message ?? e), 'err'); }
}

async function addClassPermission(classId: string, current: ClassPermission[]) {
  const scopeType  = (document.getElementById('cls-perm-scope-type')  as HTMLSelectElement).value as ClassPermission['scope_type'];
  const scopeValue = (document.getElementById('cls-perm-scope-value') as HTMLInputElement).value.trim();
  const permission = (document.getElementById('cls-perm-level')       as HTMLSelectElement).value as ClassPermission['permission'];
  if (!scopeValue) { showToast('Scope value required', 'err'); return; }
  const newP: ClassPermission = { class_id: classId, scope_type: scopeType, scope_value: scopeValue, permission };
  const updated = [...current.filter(p => !(p.scope_type === scopeType && p.scope_value === scopeValue)), newP];
  try {
    await invoke?.('set_class_permissions', { classId, permissions: updated });
    showToast('Permission added', 'ok');
    await renderClassDetail(classId);
  } catch (e: any) { showToast('Failed: ' + (e?.message ?? e), 'err'); }
}

async function deleteClassPermission(classId: string, current: ClassPermission[], idx: number) {
  const updated = current.filter((_, i) => i !== idx);
  try {
    await invoke?.('set_class_permissions', { classId, permissions: updated });
    showToast('Permission removed', 'ok');
    await renderClassDetail(classId);
  } catch (e: any) { showToast('Failed: ' + (e?.message ?? e), 'err'); }
}

async function openCreateClassForm() {
  const ws = document.getElementById('users-workspace');
  if (!ws) return;
  ws.innerHTML = `
    <div class="users-detail">
      <div class="users-detail-header" style="border-bottom:1px solid var(--border);padding-bottom:16px">
        <div class="users-detail-avatar" style="background:var(--surface3);font-size:16px">+</div>
        <div class="users-detail-meta">
          <div class="users-detail-name">Create User Class</div>
          <div class="users-detail-sub">A class defines a reusable set of permissions and capabilities.</div>
        </div>
      </div>
      <section class="users-section">
        <div class="create-user-form">
          <label class="user-form-label">Class Name
            <input id="new-cls-name" class="tool-input user-form-field" placeholder="e.g. Developer, ReadOnly-EU" autocomplete="off">
          </label>
          <label class="user-form-label">Description
            <input id="new-cls-desc" class="tool-input user-form-field" placeholder="What this class is for">
          </label>
          <div class="class-caps-grid">
            <label class="class-cap-row"><input type="checkbox" id="new-cap-mu"><span class="class-cap-info"><span class="class-cap-name">Manage Users</span><span class="class-cap-desc">Create/delete users, assign classes</span></span></label>
            <label class="class-cap-row"><input type="checkbox" id="new-cap-mc"><span class="class-cap-info"><span class="class-cap-name">Manage Classes</span><span class="class-cap-desc">Create, edit and delete classes</span></span></label>
            <label class="class-cap-row"><input type="checkbox" id="new-cap-dp"><span class="class-cap-info"><span class="class-cap-name">Delete Projects</span><span class="class-cap-desc">Can remove projects from vault</span></span></label>
          </div>
          <div class="create-user-actions">
            <button class="btn btn-sm btn-accent" id="confirm-create-class">Create Class</button>
            <button class="btn btn-sm btn-ghost" id="cancel-create-class">Cancel</button>
          </div>
        </div>
      </section>
    </div>`;

  (document.getElementById('new-cls-name') as HTMLInputElement)?.focus();

  document.getElementById('confirm-create-class')!.addEventListener('click', async () => {
    const name        = (document.getElementById('new-cls-name') as HTMLInputElement).value.trim();
    const description = (document.getElementById('new-cls-desc') as HTMLInputElement).value.trim();
    const capManageUsers    = (document.getElementById('new-cap-mu') as HTMLInputElement).checked;
    const capManageClasses  = (document.getElementById('new-cap-mc') as HTMLInputElement).checked;
    const capDeleteProjects = (document.getElementById('new-cap-dp') as HTMLInputElement).checked;
    if (!name) { showToast('Name is required', 'err'); return; }
    try {
      const cls: UserClass = await invoke?.('create_user_class', { name, description, capManageUsers, capManageClasses, capDeleteProjects }) ?? null;
      if (!cls) { showToast('Failed to create class', 'err'); return; }
      showToast(`Class "${name}" created`, 'ok');
      _activeClassId = cls.id;
      await renderClassesPanel();
      await renderClassDetail(cls.id);
    } catch (e: any) { showToast('Failed: ' + (e?.message ?? e), 'err'); }
  });
  document.getElementById('cancel-create-class')!.addEventListener('click', () => {
    ws.innerHTML = '<div class="users-detail-empty">Select a class to manage, or create one.</div>';
  });
}

// ── Init ──────────────────────────────────────────────────────────────────────

let _activeSubPanel: 'users' | 'classes' = 'users';

export function initUsersPanel() {
  // Sub-nav switching
  document.querySelectorAll<HTMLButtonElement>('.users-subnav-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      document.querySelectorAll('.users-subnav-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      _activeSubPanel = btn.dataset.sub as 'users' | 'classes';

      const usersList    = document.getElementById('users-list');
      const classesList  = document.getElementById('classes-list');
      const createUser   = document.getElementById('create-user-btn');
      const createClass  = document.getElementById('create-class-btn');
      const ws           = document.getElementById('users-workspace');

      if (_activeSubPanel === 'users') {
        if (usersList)   usersList.style.display = '';
        if (classesList) classesList.style.display = 'none';
        if (createUser)  createUser.style.display = '';
        if (createClass) createClass.style.display = 'none';
        if (ws) ws.innerHTML = '<div class="users-detail-empty">Select a user to manage, or create one.</div>';
        await renderUsersPanel();
      } else {
        if (usersList)   usersList.style.display = 'none';
        if (classesList) classesList.style.display = '';
        if (createUser)  createUser.style.display = 'none';
        if (createClass) createClass.style.display = '';
        if (ws) ws.innerHTML = '<div class="users-detail-empty">Select a class to configure.</div>';
        await renderClassesPanel();
      }
    });
  });

  document.getElementById('users-list')?.addEventListener('click', async (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('[data-user-id]');
    if (!btn?.dataset.userId) return;
    st.selectedUserId = btn.dataset.userId;
    await renderUsersPanel();
    await renderUserDetail(btn.dataset.userId);
  });

  document.getElementById('classes-list')?.addEventListener('click', async (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('[data-class-id]');
    if (!btn?.dataset.classId) return;
    await renderClassDetail(btn.dataset.classId);
  });

  document.getElementById('create-user-btn')?.addEventListener('click', openCreateUserForm);
  document.getElementById('create-class-btn')?.addEventListener('click', openCreateClassForm);

  const ws = document.getElementById('users-workspace');
  if (ws) ws.innerHTML = '<div class="users-detail-empty">Select a user to manage, or create one.</div>';

  // Show users create btn by default
  const createUser = document.getElementById('create-user-btn');
  if (createUser) createUser.style.display = '';
}
