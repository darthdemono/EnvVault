/**
 * @file
 * Markup for the Tools workspace panes.
 *
 * Extracted verbatim from index.html, which had grown past 1650 lines with ~420
 * of them being static tool-pane markup. Injected into #tools-workspace during
 * bootstrap, before initTools() binds any listener, so every getElementById in
 * tools.ts still resolves.
 *
 * Kept as one template literal rather than generated markup on purpose: the ids
 * here are a hard contract with tools.ts and audit.ts, and hand-rewriting them
 * is exactly how elements silently go missing.
 */

export const TOOLS_PANES_HTML = String.raw`

        <!-- Tool: Secret Generator -->
        <div id="tool-secret-gen" class="tool-pane">
          <div class="tool-header"><h3>Secret Generator</h3><p>Cryptographically secure random bytes via OS CSPRNG.</p></div>
          <div class="tool-body">
            <div class="tool-row"><label class="tool-label">Byte length</label>
              <div class="btn-group-pill">
                <button class="tool-byte-btn active" data-bytes="16">16</button>
                <button class="tool-byte-btn" data-bytes="32">32</button>
                <button class="tool-byte-btn" data-bytes="64">64</button>
                <button class="tool-byte-btn" data-bytes="128">128</button>
              </div>
            </div>
            <div class="tool-row"><label class="tool-label">Format</label>
              <select id="sg-format" class="tool-select">
                <option value="hex">Hex</option>
                <option value="base64">Base64</option>
                <option value="base64url">Base64 URL-safe</option>
              </select>
            </div>
            <textarea id="sg-output" class="tool-output mono" readonly rows="3" placeholder="Output…"></textarea>
            <div class="tool-actions">
              <button id="sg-generate" class="btn btn-accent btn-sm">Generate</button>
              <button id="sg-copy" class="btn btn-ghost btn-sm">Copy</button>
              <button id="sg-inject" class="btn btn-ghost btn-sm" title="Inject into open Add/Edit form">→ Inject</button>
            </div>
          </div>
        </div>

        <!-- Tool: Password Generator -->
        <div id="tool-password-gen" class="tool-pane" style="display:none">
          <div class="tool-header"><h3>Password Generator</h3><p>Configurable length and character sets.</p></div>
          <div class="tool-body">
            <div class="tool-row"><label class="tool-label">Length: <span id="pg-len-display">24</span></label>
              <input type="range" id="pg-length" min="8" max="128" value="24" class="tool-range">
            </div>
            <div class="tool-row"><label class="tool-label">Characters</label>
              <div class="tool-checks">
                <label><input type="checkbox" id="pg-upper" checked> A–Z</label>
                <label><input type="checkbox" id="pg-lower" checked> a–z</label>
                <label><input type="checkbox" id="pg-digits" checked> 0–9</label>
                <label><input type="checkbox" id="pg-symbols" checked> !@#…</label>
                <label><input type="checkbox" id="pg-noambig"> No ambiguous</label>
              </div>
            </div>
            <input id="pg-output" class="tool-output mono" readonly placeholder="Output…">
            <div id="pg-strength" class="strength-bar"><div id="pg-strength-fill"></div></div>
            <div class="tool-actions">
              <button id="pg-generate" class="btn btn-accent btn-sm">Generate</button>
              <button id="pg-copy" class="btn btn-ghost btn-sm">Copy</button>
              <button id="pg-inject" class="btn btn-ghost btn-sm">→ Inject</button>
            </div>
          </div>
        </div>

        <!-- Tool: UUID / ULID -->
        <div id="tool-uuid-ulid" class="tool-pane" style="display:none">
          <div class="tool-header"><h3>UUID / ULID Generator</h3><p>Universally unique identifiers.</p></div>
          <div class="tool-body">
            <div class="tool-row"><label class="tool-label">Type</label>
              <div class="btn-group-pill">
                <button class="tool-id-type-btn active" data-type="uuid">UUID v4</button>
                <button class="tool-id-type-btn" data-type="ulid">ULID</button>
              </div>
            </div>
            <div class="tool-row"><label class="tool-label">Count</label>
              <input type="number" id="uu-count" min="1" max="20" value="1" class="tool-number">
            </div>
            <textarea id="uu-output" class="tool-output mono" readonly rows="5" placeholder="Output…"></textarea>
            <div class="tool-actions">
              <button id="uu-generate" class="btn btn-accent btn-sm">Generate</button>
              <button id="uu-copy" class="btn btn-ghost btn-sm">Copy</button>
            </div>
          </div>
        </div>

        <!-- Tool: API Key Patterns -->
        <div id="tool-api-key-patterns" class="tool-pane" style="display:none">
          <div class="tool-header"><h3>API Key Patterns</h3><p>Common API key formats based on provider patterns.</p></div>
          <div class="tool-body">
            <div class="tool-row"><label class="tool-label">Pattern</label>
              <select id="ak-pattern" class="tool-select">
                <option value="jwt-secret">JWT Secret (256-bit hex)</option>
                <option value="base64-32">Base64 32 bytes</option>
                <option value="hex-32">Hex 32 bytes</option>
                <option value="hex-16">Hex 16 bytes</option>
                <option value="bearer">Bearer token (base64url)</option>
                <option value="sk-prefix">sk- prefixed (OpenAI style)</option>
              </select>
            </div>
            <input id="ak-output" class="tool-output mono" readonly placeholder="Output…">
            <div class="tool-actions">
              <button id="ak-generate" class="btn btn-accent btn-sm">Generate</button>
              <button id="ak-copy" class="btn btn-ghost btn-sm">Copy</button>
              <button id="ak-inject" class="btn btn-ghost btn-sm">→ Inject</button>
            </div>
          </div>
        </div>

        <!-- Tool: Hash Generator -->
        <div id="tool-hash-gen" class="tool-pane" style="display:none">
          <div class="tool-header"><h3>Hash / Key Derivation</h3><p>SHA hash of any input string via Web Crypto API.</p></div>
          <div class="tool-body">
            <div class="tool-row"><label class="tool-label">Algorithm</label>
              <div class="btn-group-pill">
                <button class="tool-hash-algo-btn active" data-algo="SHA-256">SHA-256</button>
                <button class="tool-hash-algo-btn" data-algo="SHA-384">SHA-384</button>
                <button class="tool-hash-algo-btn" data-algo="SHA-512">SHA-512</button>
              </div>
            </div>
            <div class="tool-row"><label class="tool-label">Format</label>
              <div class="btn-group-pill">
                <button class="tool-hash-fmt-btn active" data-fmt="hex">Hex</button>
                <button class="tool-hash-fmt-btn" data-fmt="base64">Base64</button>
              </div>
            </div>
            <textarea id="hg-input" class="tool-textarea mono" rows="3" placeholder="Input text to hash…"></textarea>
            <input id="hg-output" class="tool-output mono" readonly placeholder="Hash output…">
            <div class="tool-actions">
              <button id="hg-hash" class="btn btn-accent btn-sm">Hash</button>
              <button id="hg-copy" class="btn btn-ghost btn-sm">Copy</button>
              <button id="hg-inject" class="btn btn-ghost btn-sm">→ Inject</button>
            </div>
          </div>
        </div>

        <!-- Tool: Token Validator -->
        <div id="tool-token-validator" class="tool-pane" style="display:none">
          <div class="tool-header"><h3>Token Validator</h3><p>Decode and inspect JWT structure and expiry.</p></div>
          <div class="tool-body">
            <textarea id="tv-input" class="tool-textarea mono" rows="4" placeholder="Paste JWT token here…"></textarea>
            <div class="tool-actions" style="margin-bottom:10px">
              <button id="tv-decode" class="btn btn-accent btn-sm">Decode</button>
            </div>
            <div id="tv-status" class="tool-status" style="display:none"></div>
            <div class="tool-row-2">
              <div>
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">
                  <div class="tool-label">Header</div>
                  <button id="tv-copy-header" class="btn btn-ghost btn-sm" style="padding:2px 8px;font-size:10px">Copy</button>
                </div>
                <pre id="tv-header" class="tool-pre"></pre>
              </div>
              <div>
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">
                  <div class="tool-label">Payload</div>
                  <button id="tv-copy-payload" class="btn btn-ghost btn-sm" style="padding:2px 8px;font-size:10px">Copy</button>
                </div>
                <pre id="tv-payload" class="tool-pre"></pre>
              </div>
            </div>
          </div>
        </div>

        <!-- Tool: PEM Certificate Generator -->
        <div id="tool-pem-cert-gen" class="tool-pane" style="display:none">
          <div class="tool-header"><h3>PEM Certificate Generator</h3><p>Self-signed X.509 certificate via Rust <code>rcgen</code>.</p></div>
          <div class="tool-body">
            <div class="tool-row"><label class="tool-label">Common Name</label>
              <input id="pc-cn" class="tool-input" type="text" value="localhost" placeholder="e.g. localhost">
            </div>
            <div class="tool-row"><label class="tool-label">Validity (days): <span id="pc-days-display">365</span></label>
              <input type="range" id="pc-days" min="1" max="3650" value="365" class="tool-range">
            </div>
            <div class="tool-actions" style="margin-bottom:10px">
              <button id="pc-generate" class="btn btn-accent btn-sm">Generate</button>
              <span id="pc-loading" style="display:none;font-size:11px;color:var(--text3)">Generating…</span>
            </div>
            <label class="tool-label">Certificate PEM</label>
            <textarea id="pc-cert-output" class="tool-output mono" readonly rows="5" placeholder="Certificate PEM…"></textarea>
            <div style="margin-bottom:8px"><button id="pc-copy-cert" class="btn btn-ghost btn-sm">Copy Cert</button></div>
            <label class="tool-label">Private Key PEM</label>
            <textarea id="pc-key-output" class="tool-output mono" readonly rows="5" placeholder="Private Key PEM…"></textarea>
            <div><button id="pc-copy-key" class="btn btn-ghost btn-sm">Copy Key</button></div>
          </div>
        </div>

        <!-- Tool: SSH Key Generator -->
        <div id="tool-ssh-keygen" class="tool-pane" style="display:none">
          <div class="tool-header"><h3>SSH Key Generator</h3><p>Ed25519 key pair via Rust <code>ssh-key</code> crate.</p></div>
          <div class="tool-body">
            <div class="tool-row"><label class="tool-label">Comment</label>
              <input id="sk-comment" class="tool-input" type="text" placeholder="user@host">
            </div>
            <div class="tool-actions" style="margin-bottom:10px">
              <button id="sk-generate" class="btn btn-accent btn-sm">Generate</button>
              <span id="sk-loading" style="display:none;font-size:11px;color:var(--text3)">Generating…</span>
            </div>
            <label class="tool-label">Public Key</label>
            <textarea id="sk-pub-output" class="tool-output mono" readonly rows="2" placeholder="ssh-ed25519 …"></textarea>
            <div style="margin-bottom:8px"><button id="sk-copy-pub" class="btn btn-ghost btn-sm">Copy Public Key</button></div>
            <label class="tool-label">Private Key (OpenSSH)</label>
            <textarea id="sk-priv-output" class="tool-output mono" readonly rows="7" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----…"></textarea>
            <div><button id="sk-copy-priv" class="btn btn-ghost btn-sm">Copy Private Key</button></div>
          </div>
        </div>

        <!-- Tool: String Tools -->
        <div id="tool-string-tools" class="tool-pane" style="display:none">
          <div class="tool-header"><h3>String Tools</h3><p>.env escaping, URL encoding, shell quoting.</p></div>
          <div class="tool-body">
            <div class="tool-row"><label class="tool-label">Operation</label>
              <select id="st-op" class="tool-select">
                <option value="dotenv-escape">.env escape</option>
                <option value="url-encode">URL encode</option>
                <option value="url-decode">URL decode</option>
                <option value="shell-quote">Shell quote</option>
                <option value="json-escape">JSON string escape</option>
                <option value="json-unescape">JSON string unescape</option>
              </select>
            </div>
            <textarea id="st-input" class="tool-textarea mono" rows="4" placeholder="Input…"></textarea>
            <div class="tool-actions" style="margin-bottom:8px">
              <button id="st-convert" class="btn btn-accent btn-sm">Convert</button>
            </div>
            <textarea id="st-output" class="tool-output mono" readonly rows="4" placeholder="Output…"></textarea>
            <div class="tool-actions">
              <button id="st-copy" class="btn btn-ghost btn-sm">Copy</button>
            </div>
          </div>
        </div>

        <!-- Tool: Base64 -->
        <div id="tool-base64" class="tool-pane" style="display:none">
          <div class="tool-header"><h3>Base64</h3><p>Encode or decode text / binary data.</p></div>
          <div class="tool-body">
            <div class="tool-row"><label class="tool-label">Operation</label>
              <div class="btn-group-pill">
                <button class="tool-b64-op-btn active" data-op="encode">Encode</button>
                <button class="tool-b64-op-btn" data-op="decode">Decode</button>
              </div>
            </div>
            <div class="tool-row"><label class="tool-label">Variant</label>
              <div class="btn-group-pill">
                <button class="tool-b64-var-btn active" data-var="std">Standard</button>
                <button class="tool-b64-var-btn" data-var="url">URL-safe</button>
              </div>
            </div>
            <textarea id="b64-input" class="tool-textarea mono" rows="4" placeholder="Input…"></textarea>
            <div class="tool-actions" style="margin-bottom:8px">
              <button id="b64-convert" class="btn btn-accent btn-sm">Convert</button>
            </div>
            <textarea id="b64-output" class="tool-output mono" readonly rows="4" placeholder="Output…"></textarea>
            <div class="tool-actions">
              <button id="b64-copy" class="btn btn-ghost btn-sm">Copy</button>
            </div>
          </div>
        </div>

        <!-- Tool: Health Dashboard (item 7) -->
        <div id="tool-health" class="tool-pane" style="display:none">
          <div class="tool-header">
            <h3>Secret Health</h3>
            <p>Audit your vault for weak, stale, or risky credentials.</p>
          </div>
          <div class="tool-body" style="max-width:700px">
            <div class="tool-actions" style="margin-bottom:12px">
              <button id="health-scan-btn" class="btn btn-accent btn-sm">Run Scan</button>
              <span id="health-scan-time" style="font-size:11px;color:var(--text3)"></span>
            </div>
            <div id="health-results"></div>
          </div>
        </div>

        <!-- Tool: Import (item 9) -->
        <div id="tool-import-export" class="tool-pane" style="display:none">
          <div class="tool-header">
            <h3>Import</h3>
            <p>Import secrets from external formats. Existing entries are preserved.</p>
          </div>
          <div class="tool-body">
            <div class="tool-row">
              <label class="tool-label">Format</label>
              <div class="btn-group-pill">
                <button class="import-fmt-btn active" data-fmt="env">.env</button>
                <button class="import-fmt-btn" data-fmt="yaml">YAML</button>
                <button class="import-fmt-btn" data-fmt="bitwarden">Bitwarden</button>
                <button class="import-fmt-btn" data-fmt="1password">1Password</button>
                <button class="import-fmt-btn" data-fmt="json">JSON</button>
              </div>
            </div>
            <div class="tool-row">
              <label class="tool-label">File</label>
              <div style="display:flex;gap:8px;align-items:center">
                <button id="import-file-btn" class="btn btn-ghost btn-sm">Choose File</button>
                <span id="import-file-name" style="font-size:11px;color:var(--text3)">No file chosen</span>
              </div>
            </div>
            <div id="import-preview" style="display:none;margin-top:8px">
              <div class="tool-pre" id="import-preview-text" style="max-height:200px;overflow-y:auto"></div>
            </div>
            <div class="tool-actions" style="margin-top:10px">
              <button id="import-confirm-btn" class="btn btn-accent btn-sm" style="display:none">Import Entries</button>
              <span id="import-status" style="font-size:12px;color:var(--text3)"></span>
            </div>
          </div>
        </div>

        <!-- Tool: Templates (item 23) -->
        <div id="tool-templates" class="tool-pane" style="display:none">
          <div class="tool-header">
            <h3>Secret Templates</h3>
            <p>Start from a predefined template — fields are pre-filled with hints.</p>
          </div>
          <div class="tool-body" style="max-width:700px">
            <div id="template-grid" class="template-grid"></div>
          </div>
        </div>

        <!-- Tool: Secret Diff -->
        <div id="tool-diff" class="tool-pane" style="display:none">
          <div class="tool-header"><h3>Secret Diff</h3><p>Compare two vault entries field by field.</p></div>
          <div class="tool-body wide">
            <div class="tool-row">
              <div style="flex:1;display:flex;flex-direction:column;gap:4px">
                <label class="tool-label">Entry A</label>
                <select id="diff-a" class="tool-select" style="width:100%"><option value="">Select secret…</option></select>
              </div>
              <div style="flex:1;display:flex;flex-direction:column;gap:4px">
                <label class="tool-label">Entry B</label>
                <select id="diff-b" class="tool-select" style="width:100%"><option value="">Select secret…</option></select>
              </div>
            </div>
            <div class="tool-actions"><button id="diff-run" class="btn btn-accent btn-sm">Compare</button></div>
            <div id="diff-output"></div>
          </div>
        </div>

        <!-- Tool: Expiry Calendar -->
        <div id="tool-expiry-calendar" class="tool-pane" style="display:none">
          <div class="tool-header"><h3>Expiry Calendar</h3><p>Month view of secrets with expiry dates.</p></div>
          <div class="tool-body wide">
            <div class="tool-row" style="margin-bottom:16px;gap:12px">
              <button id="cal-prev" class="btn btn-ghost btn-sm">‹ Prev</button>
              <span id="cal-month-label" style="font-weight:700;font-size:14px;min-width:180px;text-align:center"></span>
              <button id="cal-next" class="btn btn-ghost btn-sm">Next ›</button>
            </div>
            <div id="cal-grid" class="calendar-grid"></div>
            <div style="display:flex;gap:16px;margin-top:12px;font-size:11px;color:var(--text3)">
              <span><span class="cal-dot expired"></span>Expired</span>
              <span><span class="cal-dot expiring-soon"></span>&lt;30 days</span>
              <span><span class="cal-dot safe"></span>Safe</span>
            </div>
          </div>
        </div>

        <!-- Tool: Cron Explainer -->
        <div id="tool-cron" class="tool-pane" style="display:none">
          <div class="tool-header"><h3>Cron Explainer</h3><p>Translate cron expressions to human language and show next fire times.</p></div>
          <div class="tool-body">
            <div class="tool-field-group">
              <label class="tool-label">Expression</label>
              <input id="cron-input" class="tool-input" style="font-family:var(--font-mono);max-width:300px" placeholder="0 2 * * 1-5  or  @daily">
            </div>
            <div class="tool-actions"><button id="cron-parse" class="btn btn-accent btn-sm">Explain</button></div>
            <div id="cron-output" style="display:none"></div>
          </div>
        </div>

        <!-- Tool: CIDR Calculator -->
        <div id="tool-cidr" class="tool-pane" style="display:none">
          <div class="tool-header"><h3>CIDR Calculator</h3><p>Network address, broadcast, host range and mask from CIDR notation.</p></div>
          <div class="tool-body">
            <div class="tool-field-group">
              <label class="tool-label">CIDR Block</label>
              <input id="cidr-input" class="tool-input" style="font-family:var(--font-mono);max-width:240px" placeholder="192.168.1.0/24">
            </div>
            <div class="tool-actions"><button id="cidr-calc" class="btn btn-accent btn-sm">Calculate</button></div>
            <div id="cidr-output" style="display:none"></div>
          </div>
        </div>

        <!-- Tool: JSON / YAML Formatter -->
        <div id="tool-formatter" class="tool-pane" style="display:none">
          <div class="tool-header"><h3>JSON / YAML Formatter</h3><p>Pretty-print, validate, and minify structured data.</p></div>
          <div class="tool-body">
            <div class="tool-row">
              <label class="tool-label">Format</label>
              <div class="btn-group-pill">
                <button class="tool-fmt-btn active" data-fmt="json">JSON</button>
                <button class="tool-fmt-btn" data-fmt="yaml">YAML</button>
              </div>
            </div>
            <textarea id="fmt-input" class="tool-textarea" rows="9" placeholder="Paste JSON or YAML here…"></textarea>
            <div class="tool-actions">
              <button id="fmt-format" class="btn btn-accent btn-sm">Format</button>
              <button id="fmt-validate" class="btn btn-ghost btn-sm">Validate</button>
              <button id="fmt-minify" class="btn btn-ghost btn-sm">Minify</button>
            </div>
            <div id="fmt-status" class="tool-status" style="display:none"></div>
            <textarea id="fmt-output" class="tool-output" readonly rows="9" placeholder="Output…" style="display:none"></textarea>
            <div class="tool-actions" id="fmt-copy-row" style="display:none">
              <button id="fmt-copy" class="btn btn-ghost btn-sm">Copy output</button>
            </div>
          </div>
        </div>

        <!-- Tool: Audit Log -->
        <div id="tool-audit" class="tool-pane" style="display:none">
          <div class="tool-header">
            <h3>Audit Log</h3>
            <p>Append-only record of every add, update, delete and read. Each row is hash-chained to the one before it, so any tampering breaks the chain.</p>
          </div>
          <div class="tool-body">
            <div class="tool-actions">
              <button id="audit-refresh" class="btn btn-accent btn-sm">Load log</button>
              <button id="audit-verify" class="btn btn-ghost btn-sm">Verify chain</button>
              <button id="audit-export" class="btn btn-ghost btn-sm">Export JSON</button>
              <span id="audit-count" style="font-size:11px;color:var(--text3);align-self:center"></span>
            </div>
            <div id="audit-status" class="tool-status" style="display:none"></div>
            <div id="audit-results"></div>
          </div>
        </div>

`;

/** Inject the tool panes. Idempotent: safe to call more than once. */
export function mountToolsPanes(): void {
  const host = document.getElementById('tools-workspace');
  if (!host || host.dataset.mounted === '1') return;
  host.insertAdjacentHTML('afterbegin', TOOLS_PANES_HTML);
  host.dataset.mounted = '1';
}
