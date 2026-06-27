# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `@aida/agent`, please report it privately to the maintainers. Do NOT open a public issue.

**Email:** security@agent-interaction-labs.dev (placeholder — update before publishing)

We aim to respond within 48 hours and publish a fix within 7 days of confirmation.

## Cryptographic Dependencies

This package uses `@noble/ed25519` for Ed25519 key generation and signing, and `@noble/hashes` for SHA-256/SHA-512. These are audited, constant-time cryptographic libraries. We do not implement our own cryptography.

## Key Storage

Private keys are stored as base58-encoded JSON on the local filesystem. The storage location is chosen by the user (`storagePath` option). We recommend:

- Storing keys in a directory with restricted permissions (`chmod 700`)
- Using a dedicated key directory (`~/.aida/`)
- Never committing key files to version control
- Rotating keys periodically

## Supported Versions

| Version | Supported |
|---|---|
| 0.x | ✅ (latest only) |

As this package is pre-1.0, only the latest version receives security updates.
