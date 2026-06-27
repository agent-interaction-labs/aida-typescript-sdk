# Changelog

## 0.1.0 (2026-06-21)

- Initial release
- `createMiddleware(options?)` — Express middleware for verifying AIDA agent identities on incoming requests
- `verifySignature(headers, publicKey, options?)` — RFC 9421 HTTP Message Signature verification
- `extractKeyId(signatureInputHeader)` — extract keyid from Signature-Input header
- `extractPurpose(signatureInputHeader, headers)` — extract purpose from signed request
- `verifyIdentityDocument(document, options?)` — cryptographic verification of identity document self-signatures
- `createVerificationResult(agentId, verified, ...)` — structured VerificationResult construction
- `encodeBase58()` / `decodeBase58()` — base58 encoding/decoding utilities
- `publicKeyToAidaUri()` / `aidaUriToPublicKey()` — AIDA URI ↔ public key conversion
- `toHex()` / `formatHashLink()` — hex and hash link formatting
- Full TypeScript type definitions (AidaUri, IdentityDocument, VerificationResult, VerifyOptions, etc.)
- Support for optional and required verification modes
- Controller whitelisting via `allowedControllers`
- Custom public key and identity document resolvers
- Clock skew tolerance for timestamp validation
