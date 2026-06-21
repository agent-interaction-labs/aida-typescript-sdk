# @aida/verify

**AIDA Verify SDK** — server-side verification of AIDA agent identities, RFC 9421 HTTP Message Signatures, and identity documents.

> Part of the [AIDA Protocol](https://github.com/agent-interaction-labs/aida-spec) — the open standard for agent identity, delegation, and attestation.

## Install

```bash
npm install @aida/verify
```

## Quick Start

### Express Middleware

```typescript
import express from 'express';
import { createMiddleware } from '@aida/verify';

const app = express();

// Optional mode (default) — populates req.aida, never blocks
app.use(createMiddleware());

app.get('/api/public', (req, res) => {
  if (req.aida?.verified) {
    res.json({ message: `Hello, ${req.aida.agentId}!` });
  } else {
    res.json({ message: 'Hello, anonymous user!' });
  }
});

app.listen(3000);
```

### Required Mode

```typescript
// Required mode — returns 401 for unverified requests
app.use('/api/private', createMiddleware({ required: true }));

app.get('/api/private', (req, res) => {
  // req.aida.verified is guaranteed true at this point
  res.json({ agent: req.aida.agentId, purpose: req.aida.purpose });
});
```

### Allowed Controllers

```typescript
// Only allow agents controlled by specific identities
app.use(createMiddleware({
  required: true,
  allowedControllers: [
    { email: 'alice@example.com' },
    { dns: 'agents.mycorp.com' },
  ],
}));

app.get('/api/admin', (req, res) => {
  // Only whitelisted controllers reach this handler
  res.json({ admin: true });
});
```

### With Identity Document Resolution

```typescript
app.use(createMiddleware({
  required: true,
  getIdentityDocument: async (agentId) => {
    // Resolve from DNS, ledger, or local cache
    const response = await fetch(`https://resolver.example.com/aida/${agentId}`);
    if (!response.ok) return null;
    return response.json();
  },
}));
```

### Standalone Verification

```typescript
import { verifySignature, verifyIdentityDocument, extractKeyId } from '@aida/verify';

// Verify an RFC 9421 signature
const result = verifySignature(requestHeaders, publicKey, {
  method: 'POST',
  path: '/api/data',
  authority: 'example.com',
});

if (result.valid) {
  console.log('Signature valid');
}

// Extract the key ID from a Signature-Input header
const keyid = extractKeyId(headers['Signature-Input']);
// → 'aida:CcL7R8YxPZnJ2YqkMoF1mBvQrWtLxU9k'

// Verify an identity document's self-signature
const docResult = verifyIdentityDocument(identityDocument);
if (docResult.valid) {
  console.log('Identity document is cryptographically valid');
}
```

## API Reference

### `createMiddleware(options?)`

Creates an Express middleware that verifies AIDA agent identities on incoming requests.

```typescript
function createMiddleware(options?: VerifyOptions): RequestHandler;
```

**Options:**

| Option | Type | Default | Description |
|---|---|---|---|
| `required` | `boolean` | `false` | If `true`, unverified requests receive a 401 response |
| `allowedControllers` | `AgentController[]` | `undefined` | Whitelist of allowed controllers; non-matching agents receive 403 |
| `clockSkew` | `number` | `300` | Maximum clock skew tolerance in seconds |
| `cacheTTL` | `number` | `3600` | Time-to-live in seconds for cached identity documents |
| `getPublicKey` | `(keyid: string) => Promise<Uint8Array>` | `undefined` | Custom public key resolver (default: extract from AIDA URI) |
| `getIdentityDocument` | `(keyid: string) => Promise<IdentityDocument \| null>` | `undefined` | Custom identity document resolver |

**Middleware Behavior:**

The middleware populates `req.aida` with a `VerificationResult`:

```typescript
interface VerificationResult {
  agentId: AidaUri;          // e.g., 'aida:CcL7R8YxPZnJ2YqkMoF1mBvQrWtLxU9k'
  verified: boolean;         // overall verification status
  controller?: AgentController; // from identity document (if resolved)
  purpose?: AgentPurpose;    // 'inference' | 'task' | 'crawler' | 'monitoring'
  publicKey?: Uint8Array;    // public key used for verification
  error?: string;            // failure reason (if !verified)
  metadata?: {
    signedAt?: number;       // Unix timestamp from signature
    verifiedAt: string;      // ISO 8601 timestamp
    identityResolved: boolean;
    identityVerified?: boolean;
  };
}
```

**Verification Flow:**

1. Extract `Aida-Agent` header — missing + `required: true` → 401
2. Extract `Signature-Input` header — missing → error in `req.aida`
3. Extract `Signature` header — missing → error in `req.aida`
4. Extract `keyid` from Signature-Input parameters
5. Resolve public key (via `getPublicKey` or decode from AIDA URI)
6. Verify RFC 9421 signature against resolved public key
7. Optionally resolve and verify identity document (if `getIdentityDocument` provided)
8. Check `allowedControllers` if configured — mismatch → 403
9. Extract `purpose` from covered components
10. Populate `req.aida` and call `next()`

### `verifySignature(headers, publicKey, options?)`

Verify an RFC 9421 HTTP Message Signature.

```typescript
function verifySignature(
  headers: Record<string, string>,
  publicKey: Uint8Array,
  options?: VerifySignatureOptions,
): { valid: boolean; error?: string };
```

**Options:**

| Option | Type | Default | Description |
|---|---|---|---|
| `clockSkew` | `number` | `300` | Maximum clock skew tolerance in seconds |
| `method` | `string` | `'POST'` | HTTP method for `@method` component |
| `path` | `string` | `'/'` | Request path + query string for `@path` component |
| `authority` | `string` | `'unknown'` | Hostname for `@authority` component |

Supported covered components: `@method`, `@path`, `@authority`, `content-digest`, `aida-agent`, `aida-purpose`.

### `extractKeyId(signatureInputHeader)`

Extract the `keyid` parameter from a Signature-Input header.

```typescript
function extractKeyId(signatureInputHeader: string): string | null;
```

### `extractPurpose(signatureInputHeader, headers)`

Extract the declared purpose from a signed request.

```typescript
function extractPurpose(
  signatureInputHeader: string,
  headers: Record<string, string>,
): AgentPurpose | null;
```

### `verifyIdentityDocument(document, options?)`

Verify an identity document's Ed25519 self-signature and timestamps.

```typescript
function verifyIdentityDocument(
  document: IdentityDocument,
  options?: VerifyIdentityDocumentOptions,
): { valid: boolean; error?: string };
```

### `createVerificationResult(agentId, verified, controller?, purpose?, options?)`

Create a structured `VerificationResult` object.

```typescript
function createVerificationResult(
  agentId: AidaUri,
  verified: boolean,
  controller?: AgentController,
  purpose?: AgentPurpose,
  options?: CreateVerificationResultOptions,
): VerificationResult;
```

### Utility Functions

```typescript
import {
  encodeBase58,           // Uint8Array → base58 string
  decodeBase58,           // base58 string → Uint8Array
  publicKeyToAidaUri,     // 32-byte public key → 'aida:...'
  aidaUriToBase58,        // 'aida:...' → base58 string
  aidaUriToPublicKey,     // 'aida:...' → Uint8Array (32 bytes)
  toHex,                  // Uint8Array → hex string
  formatHashLink,         // 32-byte hash → 'sha256:...'
} from '@aida/verify';
```

### Types

```typescript
import type {
  AidaUri,
  HashLink,
  AgentPurpose,
  AgentController,
  AgentProtocol,
  AgentEndpoint,
  VerificationProfileType,
  IdentityDocument,
  VerificationResult,
  VerifyOptions,
} from '@aida/verify';
```

## DNS Publication Guide

Before your server can verify agents, those agents must publish their identity documents so resolvers can discover their public keys.

### Publishing an Agent Identity (from @aida/agent)

```typescript
import { generateDnsInstructions } from '@aida/agent';

// Print DNS setup instructions
console.log(generateDnsInstructions({ dns: 'alice.example.com' }));
// → _aida.alice.example.com  IN  TXT  "v=aida1;u=https://alice.example.com/.well-known/aida"
```

### Resolving an Agent Identity (with @aida/verify)

```typescript
import { createMiddleware } from '@aida/verify';

app.use(createMiddleware({
  required: true,
  getIdentityDocument: async (agentId) => {
    // 1. Look up _aida TXT record for the agent's domain
    // 2. Fetch the identity document from the URL in the TXT record
    // 3. Return the identity document for verification
    const doc = await resolveAgentIdentity(agentId);
    return doc;
  },
}));
```

## How It Works

```
Agent (client)                          Server (your app)
─────────────                           ──────────────────
Ed25519 keypair stored locally
  │
  ├── signRequest(url, { method, body, purpose })
  │     ├── Compute SHA-256 content digest
  │     ├── Build RFC 9421 signature base:
  │     │   "@method": POST
  │     │   "@path": /api/data
  │     │   "@authority": api.example.com
  │     │   "content-digest": sha-256=:...:
  │     │   "aida-agent": aida:CcL7R8Yx...
  │     │   "aida-purpose": inference
  │     ├── Sign with Ed25519 private key
  │     └── Return headers ───────────────►  HTTP Request
  │                                           │
  │                                      createMiddleware()
  │                                           │
  │                                           ├── Extract Aida-Agent header
  │                                           ├── Extract Signature-Input
  │                                           ├── Extract Signature
  │                                           ├── Extract keyid
  │                                           ├── Resolve public key
  │                                           │     (from URI or getPublicKey)
  │                                           ├── Reconstruct signature base
  │                                           ├── Verify Ed25519 signature ✓
  │                                           ├── Resolve identity document
  │                                           │     (via DNS/getIdentityDocument)
  │                                           ├── Verify identity doc signature
  │                                           ├── Check allowedControllers
  │                                           └── Populate req.aida
  │                                                 │
  ▼                                                 ▼
Response ◄──────────────────────────────────  Route handler
```

## Compatibility

- Node.js 18+
- Express 4.x / 5.x
- Connect-compatible frameworks (Fastify with `@fastify/express` adapter)
- Cloudflare Workers (standalone functions without Express middleware)

## Dependencies

| Package | Purpose |
|---|---|
| `@noble/ed25519` | Ed25519 signature verification |
| `@noble/hashes` | SHA-512 (required by @noble/ed25519) |
| `base58-universal` | Base58 decoding for public keys |

Optional peer dependency: `express` (only required for middleware usage).

No native dependencies. No blockchain libraries. No polyfills required.

## Related Packages

- **[@aida/agent](https://github.com/agent-interaction-labs/aida-agent)** — Client SDK for creating agent identities and signing HTTP requests
- **[aida-spec](https://github.com/agent-interaction-labs/aida-spec)** — Protocol specification and JSON Schema

## License

Apache-2.0
