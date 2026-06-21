# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `@aida/verify`, please report it privately to the maintainers. Do NOT open a public issue.

**Email:** security@agent-interaction-labs.dev (placeholder — update before publishing)

We aim to respond within 48 hours and publish a fix within 7 days of confirmation.

## Cryptographic Dependencies

This package uses `@noble/ed25519` for Ed25519 signature verification and `@noble/hashes` for SHA-512. These are audited, constant-time cryptographic libraries. We do not implement our own cryptography.

## Security Design

### Signature Verification

All signature verification is performed using the audited `@noble/ed25519` library with constant-time operations. The RFC 9421 signature base is reconstructed server-side from the original request components (`@method`, `@path`, `@authority`, headers) — the client's signature is verified against this independently reconstructed base, preventing replay or tampering attacks.

### Key Resolution

By default, the public key is extracted from the AIDA URI itself (`aida:<base58-encoded-key>`), which means no external key resolution is needed for basic verification. When a custom `getPublicKey` resolver is provided, it is the caller's responsibility to ensure the resolver is trustworthy and that keys are resolved over secure channels (TLS).

### Identity Document Verification

Identity documents are cryptographically self-signed. The document's Ed25519 proof is verified against the canonicalized document body using the public key embedded in the document itself. Additionally:

- The `proof.verificationMethod` must reference the document's own key (`<id>#publicKey`)
- The `proof.type` must be `Ed25519Signature2020`
- The `created` timestamp must not be in the future (beyond clock skew)
- The `expires` timestamp (if present) must not be in the past (beyond clock skew)

### Timestamp Validation

All timestamps (`created`, `expires`) are validated with configurable clock skew tolerance (default: 300 seconds / 5 minutes). This prevents both replay of expired signatures and acceptance of future-dated forgeries.

### Controller Whitelisting

When `allowedControllers` is configured, agents must match at least one allowed controller. Matching is performed on a per-field basis (`did`, `email`, `dns`, `oauth`) — if any field of the agent's controller matches any field of an allowed controller, the agent is permitted. Non-matching agents receive a 403 Forbidden response.

### Error Handling

In **optional** mode (default), verification errors are captured in `req.aida.error` and the request proceeds. This prevents information leakage through error timing or response codes. In **required** mode, the middleware returns a 401 Unauthorized with a descriptive error message.

## Deployment Recommendations

- **Use TLS everywhere.** All requests carrying AIDA identity headers should be over HTTPS to prevent header modification in transit.
- **Set appropriate clock skew.** The default of 300 seconds (5 minutes) handles typical clock drift. Reduce for high-security environments.
- **Audit your key resolver.** If using a custom `getPublicKey`, ensure it verifies DNS records or ledger entries over secure channels.
- **Cache identity documents.** Use the `cacheTTL` option to avoid repeated DNS/ledger lookups for frequently-seen agents.
- **Monitor 403 responses.** Repeated 403s from controller whitelisting may indicate attempted unauthorized access.

## Supported Versions

| Version | Supported |
|---|---|
| 0.x | ✅ (latest only) |

As this package is pre-1.0, only the latest version receives security updates.
