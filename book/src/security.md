# Security model

The vault is encrypted at rest with SQLCipher. A master password is processed
locally with Argon2id; the derived key is not written to disk and is cleared
when the vault is locked. The database salt is required to recover a vault, so
backups must keep it with the encrypted database.

`envv` defaults to redacted output. Commands that would expose stored values on
stdout require an explicit reveal option; use file output or `envv exec` when a
consumer needs a real secret. The optional server supports TLS pinning, scoped
users, and compare-and-swap writes to avoid silent overwrite conflicts.

No security control removes the need to protect an unlocked desktop session or
the machine on which it runs. Report vulnerabilities through the repository's
[security policy](https://github.com/darthdemono/EnvVault/security/policy).
