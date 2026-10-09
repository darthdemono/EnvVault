# UnENVerse for VS Code

Puts the vault where the work happens, by calling the `unv` CLI. **It never shows a secret value**: it asks the CLI only for redacted output (names and fingerprints).

- **Completion** of `${Provider}` and `${Provider/field}` while you edit a config or a `.env`.
- **Hover** on a reference shows its fingerprint and length, so equal fingerprints mean equal secrets without anyone reading one.
- **Tasks** that run a command with secrets in its environment, through `unv exec` and without a shell, so a debug launch gets real credentials without a `.env` on disk:

  ```json
  { "type": "unv", "label": "run api", "project": "api", "command": ["node", "server.js"] }
  ```

- **Warnings on save** at each line holding a value that is a secret in your vault (`unv scan --exposed`), with the fingerprint, never the value.

It uses whatever credentials your shell would: a cached session from `unv login`, or `UNV_PASSWORD`. With the vault locked it says nothing rather than guess.

## Build

```bash
cd vscode-extension
npm install
npm run compile
```

Then press F5 in VS Code with this folder open to try it in an Extension Development Host.

## Install

Every release carries `unenverse-<version>.vsix`. In VS Code: Extensions, the `...` menu, **Install from VSIX...**, or `code --install-extension unenverse-<version>.vsix`. To build it yourself, `npm run package` in this folder writes the file here. It is not published to the Marketplace.

## Status

The logic that needs no editor (finding a reference under the cursor, what to complete, the `exec` argv, reading an exposure report) is unit-tested in the repository's own suite. The VS Code integration itself (the providers and the task) type-checks but has not been run inside a real VS Code.
