#!/usr/bin/env python3
"""Minimal Python wrapper around the `envv` CLI.

The point of this file is to show the shape of a correct integration, not to be
a library. Three rules make it safe to hand to an automated caller:

1. **Every call passes `--json`.** stdout is then exactly one envelope, so
   nothing has to parse a table that may be reformatted next release.
2. **Nothing reads a secret.** `get()` returns fingerprints. To *use* a secret,
   call `exec()` or `render()`, which move the value into a child process or a
   file without it passing through this process at all.
3. **Exit codes are the control flow.** `EnvvError.code` is a stable string
   ("not_found", "ambiguous", "denied", …), so retry logic never string-matches
   a message.

    vault = Envv(server="https://vault.example.com")
    vault.exec(["./deploy.sh"], project="Stack")
"""

from __future__ import annotations

import json
import subprocess
from typing import Any, Sequence


class EnvvError(RuntimeError):
    """A failed command. `code` is the stable machine class, not the message."""

    def __init__(self, code: str, message: str, details: Any = None, exit_code: int = 1):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details
        self.exit_code = exit_code


class Envv:
    def __init__(self, binary: str = "envv", server: str | None = None,
                 db_path: str | None = None, password_command: str | None = None):
        self.binary = binary
        # Global flags every call inherits. No password lives in this object:
        # authenticate with `envv login` once, or point --password-command at a
        # keyring helper, and this process never holds a credential.
        self.globals: list[str] = ["--json"]
        if server:
            self.globals += ["--server", server]
        if db_path:
            self.globals += ["--db-path", db_path]
        if password_command:
            self.globals += ["--password-command", password_command]

    # ── plumbing ──────────────────────────────────────────────────────────

    def _run(self, args: Sequence[str], capture: bool = True) -> Any:
        proc = subprocess.run(
            [self.binary, *self.globals, *args],
            capture_output=capture,
            text=True,
        )
        if not capture:
            return proc.returncode

        # clap's own usage errors (exit 2) are not enveloped.
        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            raise EnvvError("error", (proc.stderr or proc.stdout).strip(), None, proc.returncode)

        if payload.get("ok"):
            return payload.get("data")
        err = payload.get("error", {})
        raise EnvvError(
            err.get("code", "error"),
            err.get("message", "unknown error"),
            err.get("details"),
            proc.returncode,
        )

    def describe(self) -> dict:
        """The full contract: commands, flags, exit codes, output schemas."""
        return json.loads(subprocess.run(
            [self.binary, "describe"], capture_output=True, text=True, check=True
        ).stdout)

    # ── reading (fingerprints only) ───────────────────────────────────────

    def list(self, **filters: str) -> list[dict]:
        args = ["entry", "ls"]
        for key, value in filters.items():
            if value is not None:
                args += [f"--{key.replace('_', '-')}", value]
        return self._run(args)["entries"]

    def get(self, provider: str) -> dict:
        """One entry, secrets replaced by {'redacted', 'fingerprint', 'length'}."""
        return self._run(["entry", "get", provider])["entries"][0]

    def fingerprint(self, provider: str) -> str:
        """Identify a secret without reading it — use this to detect drift."""
        return self.get(provider)["api_key"]["fingerprint"]

    def status(self) -> dict:
        return self._run(["status"])

    def scan(self, severity: str = "low") -> list[dict]:
        return self._run(["scan", "--severity", severity])["issues"]

    # ── writing (values are generated, never supplied) ────────────────────

    def create(self, provider: str, *, generate: bool = True, **fields: str) -> dict:
        """Create an entry. With generate=True the secret never exists here."""
        args = ["entry", "add", provider, "--if-missing"]
        if generate:
            args.append("--generate")
        for key, value in fields.items():
            args += [f"--{key.replace('_', '-')}", value]
        return self._run(args)

    def rotate(self, provider: str) -> dict:
        """Replace a secret with a fresh one. Returns the new fingerprint."""
        return self._run(["entry", "rotate", provider, "--generate"])

    # ── using secrets without holding them ────────────────────────────────

    def exec(self, argv: Sequence[str], *, project: str | None = None,
             entries: Sequence[str] = (), prefix: str | None = None) -> int:
        """Run a command with secrets in its environment.

        Returns the child's exit code. Its stdout/stderr are inherited, so this
        process never buffers whatever the child prints.
        """
        args = ["exec"]
        if project:
            args += ["--project", project]
        for spec in entries:
            args += ["--entry", spec]
        if prefix:
            args += ["--prefix", prefix]
        args += ["--", *argv]
        # capture=False: no secret can be scraped from output we never read.
        return self._run(args, capture=False)

    def render(self, template: str, out_path: str, *, strict: bool = True) -> dict:
        """Resolve ${refs} in a template straight into a file on disk."""
        args = ["render", template, "--out", out_path]
        if strict:
            args.append("--strict")
        return self._run(args)

    def export_project(self, project: str, out_path: str, fmt: str | None = None) -> None:
        args = ["project", "export", project, "--out", out_path]
        if fmt:
            args += ["--format", fmt]
        self._run(args, capture=False)


if __name__ == "__main__":
    vault = Envv()
    print("status:", json.dumps(vault.status(), indent=2))
    for entry in vault.list():
        # Note what is printable here: a name and a fingerprint, never a value.
        key = entry.get("api_key", {})
        mark = key.get("fingerprint") if isinstance(key, dict) else "revealed"
        print(f"  {entry['provider']:<24} {mark}")
