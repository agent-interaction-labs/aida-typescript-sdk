# Changelog

## 0.1.0 (2026-06-21)

- Initial release
- `createAgent()` — create agent identity with Ed25519 keypair
- `loadAgent()` — load saved agent identity from disk
- `agent.signRequest()` — sign HTTP requests per RFC 9421
- `agent.regenerate()` — regenerate identity document
- `generateKeypair()` — Ed25519 key generation
- `generateDnsRecord()` / `generateDnsInstructions()` — DNS publication helpers
- `verifyIdentityDocument()` — cryptographic signature verification
- `serializeKeypair()` / `deserializeKeypair()` — key serialization
- `saveKeypair()` / `loadKeypair()` / `keypairExists()` — filesystem persistence
