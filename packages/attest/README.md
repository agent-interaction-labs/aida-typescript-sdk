# @aida/agent

**AIDA Agent SDK** — cryptographic identity and HTTP request signing for AI agents on the web.

> Part of the [AIDA Protocol](https://github.com/agent-interaction-labs/aida-spec) — the open standard for agent identity, delegation, and attestation.

## Install

```bash
npm install @aida/agent
```

## Quick Start

```typescript
import { createAgent } from '@aida/agent';

// 1. Create an agent identity (one-time)
const agent = await createAgent({
  controller: { email: 'alice@example.com', dns: 'alice.example.com' },
  storagePath: '~/.aida/agent.json'
});

console.log(agent.identity.id);
// → aida:CcL7R8YxPZnJ2YqkMoF1mBvQrWtLxU9k

// 2. Sign an HTTP request
const req = await agent.signRequest('https://api.example.com/data', {
  method: 'GET',
  purpose: 'inference'
});

// 3. Send it — headers include Aida-Agent, Signature-Input, Signature
const response = await fetch(req.url, { headers: req.headers });
```

## API

### `createAgent(options)`

Creates a new agent identity with a fresh Ed25519 keypair and signed identity document.

```typescript
const agent = await createAgent({
  controller: { email: 'alice@example.com' },  // required
  endpoints: [{ url: 'https://...', protocol: 'mcp' }],  // optional
  capabilities: ['code-generation'],  // optional
  storagePath: '~/.aida/agent.json'  // optional — persist to disk
});
```

Throws if `storagePath` already has an identity (no silent overwrites).

### `loadAgent(storagePath)`

Loads a previously saved agent identity.

```typescript
const agent = await loadAgent('~/.aida/agent.json');
```

### `agent.signRequest(url, options)`

Signs an HTTP request with the agent's Ed25519 identity per RFC 9421.

```typescript
const req = await agent.signRequest('https://api.example.com/data', {
  method: 'GET',           // required
  body: JSON.stringify({ query: '...' }),  // optional
  purpose: 'inference'     // optional — 'inference' | 'task' | 'crawler' | 'monitoring'
});

// req.url, req.method, req.headers, req.body — ready for fetch()
```

**Headers added:**

| Header | Example |
|---|---|
| `Aida-Agent` | `aida:CcL7R8YxPZnJ2YqkMoF1mBvQrWtLxU9k` |
| `Aida-Purpose` | `inference` (if provided) |
| `Signature-Input` | `sig1=("@method" "@path" ...);keyid="aida:CcL7R8...";alg="ed25519"` |
| `Signature` | `sig1=:<base64>:` |
| `Content-Digest` | `sha-256=:<base64>:` |

### `agent.regenerate()`

Regenerates and re-signs the identity document (e.g., after updating metadata or rehashing identity files).

```typescript
const updatedIdentity = await agent.regenerate();
```

### Utility Functions

```typescript
import { generateKeypair, generateDnsRecord, verifyIdentityDocument } from '@aida/agent';

// Generate keys without creating a full agent
const keypair = generateKeypair();

// Generate DNS TXT record for publication
const dnsRecord = generateDnsRecord({ dns: 'alice.example.com' });
// → "v=aida1;u=https://alice.example.com/.well-known/aida"

// Verify an identity document's signature
const isValid = verifyIdentityDocument(identityDoc);
```

## DNS Publication

After creating an agent, publish its identity so web servers can discover the public key:

```typescript
import { generateDnsRecord, generateDnsInstructions } from '@aida/agent';

console.log(generateDnsInstructions({ dns: 'alice.example.com' }));
// Prints:
// ─────────────────────────────────────────
// 📋 Publish this DNS TXT record:
//
//   _aida.alice.example.com  IN  TXT  "v=aida1;u=https://alice.example.com/.well-known/aida"
//
// Verify with:
//   dig +short TXT _aida.alice.example.com
// ─────────────────────────────────────────
```

## How It Works

```
Agent generates Ed25519 keypair
  └── Publishes public key via DNS _aida TXT record
Agent calls signRequest(url, options)
  └── Computes SHA-256 content digest
  └── Builds RFC 9421 signature base
  └── Signs with Ed25519 private key
  └── Returns headers: Aida-Agent, Signature-Input, Signature
Website receives request
  └── Uses @aida/verify to resolve key, verify signature
  └── Identifies agent + controller ✓
```

## Compatibility

- Node.js 18+
- Deno 2.0+
- Cloudflare Workers
- Bun 1.0+
- Browsers (with polyfilled `crypto.subtle`)

## Dependencies

| Package | Purpose |
|---|---|
| `@noble/ed25519` | Ed25519 key generation and signing |
| `@noble/hashes` | SHA-256 and SHA-512 |
| `base58-universal` | Base58 encoding (Bitcoin alphabet) |

No native dependencies. No blockchain libraries. No polyfills required.

## Related Packages

- **[@aida/verify](https://github.com/agent-interaction-labs/aida-verify)** — Web server middleware for verifying AIDA agent identities
- **[aida-spec](https://github.com/agent-interaction-labs/aida-spec)** — Protocol specification and JSON Schema

## License

MIT
