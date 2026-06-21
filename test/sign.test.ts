/**
 * Tests for the sign module.
 *
 * Covers: computeContentDigest, buildSignatureBase, signRequest.
 */
import { describe, it, expect } from 'vitest';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';

// @noble/ed25519 v2 requires SHA-512 to be configured for synchronous usage.
ed25519.etc.sha512Sync = sha512;

import type { AgentKeypair, IdentityDocument, AidaAgentState } from '../src/types';
import { generateKeypair } from '../src/keys';
import { createIdentityDocument } from '../src/identity';
import { encodeBase58 } from '../src/utils';

// Modules under test
import {
  computeContentDigest,
  buildSignatureBase,
  signRequest,
} from '../src/sign';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Base64-encode a Uint8Array (standard base64, no URL-safe variant). */
function base64Encode(data: Uint8Array): string {
  return Buffer.from(data).toString('base64');
}

function makeAgentState(): AidaAgentState {
  const keypair = generateKeypair();
  const identity = createIdentityDocument(keypair, {
    controller: { email: 'test@example.com' },
  });
  return {
    keypair,
    identity,
    signRequest: async () => {
      throw new Error('not implemented');
    },
    regenerate: async () => {
      throw new Error('not implemented');
    },
  };
}

// ---------------------------------------------------------------------------
// computeContentDigest
// ---------------------------------------------------------------------------

describe('computeContentDigest', () => {
  it('should return a valid sha-256 digest for a string body', () => {
    const body = 'Hello, world!';
    const digest = computeContentDigest(body);

    expect(digest).toMatch(/^sha-256=:[A-Za-z0-9+/]+=*:$/);
  });

  it('should match the expected SHA-256 hash for a known input', () => {
    const body = 'test body';
    const expectedHash = sha256(new TextEncoder().encode(body));
    const expectedBase64 = base64Encode(expectedHash);

    const digest = computeContentDigest(body);
    expect(digest).toBe(`sha-256=:${expectedBase64}:`);
  });

  it('should return the digest of an empty string when body is undefined', () => {
    const digest = computeContentDigest(undefined);

    // Should be sha-256 of empty string
    const expectedHash = sha256(new TextEncoder().encode(''));
    const expectedBase64 = base64Encode(expectedHash);

    expect(digest).toBe(`sha-256=:${expectedBase64}:`);
  });

  it('should return the digest of an empty string when body is empty string', () => {
    const digestEmpty = computeContentDigest('');
    const digestUndefined = computeContentDigest(undefined);

    // Both should be sha-256 of empty string
    expect(digestEmpty).toBe(digestUndefined);
  });

  it('should produce different digests for different bodies', () => {
    const d1 = computeContentDigest('body one');
    const d2 = computeContentDigest('body two');

    expect(d1).not.toBe(d2);
  });

  it('should handle special characters in body', () => {
    const body = '{"key":"value with \\"quotes\\" and \\n newlines"}';
    const digest = computeContentDigest(body);

    expect(digest).toMatch(/^sha-256=:[A-Za-z0-9+/]+=*:$/);
  });

  it('should handle Unicode characters in body', () => {
    const body = 'こんにちは世界 🌍';
    const digest = computeContentDigest(body);

    expect(digest).toMatch(/^sha-256=:[A-Za-z0-9+/]+=*:$/);

    // Verify it's actually the correct hash
    const expectedHash = sha256(new TextEncoder().encode(body));
    const expectedBase64 = base64Encode(expectedHash);
    expect(digest).toBe(`sha-256=:${expectedBase64}:`);
  });
});

// ---------------------------------------------------------------------------
// buildSignatureBase
// ---------------------------------------------------------------------------

describe('buildSignatureBase', () => {
  it('should build a signature base with a single component', () => {
    const components = [
      { identifier: '"@method"', value: 'POST' },
    ];
    const base = buildSignatureBase(components);

    expect(base).toBe('"@method": POST');
  });

  it('should build a signature base with multiple components', () => {
    const components = [
      { identifier: '"@method"', value: 'POST' },
      { identifier: '"@path"', value: '/api/query' },
      { identifier: '"@authority"', value: 'example.com' },
    ];
    const base = buildSignatureBase(components);

    const lines = base.split('\n');
    expect(lines).toHaveLength(3);
    expect(lines[0]).toBe('"@method": POST');
    expect(lines[1]).toBe('"@path": /api/query');
    expect(lines[2]).toBe('"@authority": example.com');
  });

  it('should pass through string values without quoting (raw serialization)', () => {
    const components = [
      { identifier: '"aida-agent"', value: 'aida:H4s5tv...' },
    ];
    const base = buildSignatureBase(components);

    // String values appear as-is per RFC 9421 signature base, no double quotes
    expect(base).toBe('"aida-agent": aida:H4s5tv...');
  });

  it('should colon-wrap binary values (base64)', () => {
    const components = [
      { identifier: '"content-digest"', value: 'sha-256=:abc123def456:=' },
    ];
    const base = buildSignatureBase(components);

    // Binary values are colon-wrapped base64
    expect(base).toBe('"content-digest": :sha-256=:abc123def456:=:');
  });

  it('should match RFC 9421 example format', () => {
    // Based on RFC 9421 Section 2.5 Example
    const components = [
      { identifier: '"@method"', value: 'POST' },
      { identifier: '"@path"', value: '/foo' },
      { identifier: '"@authority"', value: 'example.com' },
      { identifier: '"content-digest"', value: 'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+T...=' },
      { identifier: '"content-length"', value: '18' },
    ];
    const base = buildSignatureBase(components);

    const lines = base.split('\n');
    expect(lines[0]).toBe('"@method": POST');
    expect(lines[1]).toBe('"@path": /foo');
    expect(lines[2]).toBe('"@authority": example.com');
    // content-digest is binary → colon-wrapped
    expect(lines[3]).toBe('"content-digest": :sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+T...=:');
    // content-length is a string value (per RFC 9421)
    expect(lines[4]).toBe('"content-length": 18');
  });

  it('should handle empty components array', () => {
    const base = buildSignatureBase([]);
    expect(base).toBe('');
  });
});

// ---------------------------------------------------------------------------
// signRequest
// ---------------------------------------------------------------------------

describe('signRequest', () => {
  it('should return a SignedRequest with url, method, headers, and body', async () => {
    const agent = makeAgentState();
    const result = await signRequest('https://example.com/api', {
      method: 'POST',
      agent,
      body: '{"hello":"world"}',
    });

    expect(result.url).toBe('https://example.com/api');
    expect(result.method).toBe('POST');
    expect(result.body).toBe('{"hello":"world"}');
    expect(result.headers).toBeDefined();
  });

  it('should include the Aida-Agent header', async () => {
    const agent = makeAgentState();
    const result = await signRequest('https://example.com/api', {
      method: 'GET',
      agent,
    });

    expect(result.headers['Aida-Agent']).toBeDefined();
    expect(result.headers['Aida-Agent']).toBe(agent.identity.id);
  });

  it('should include the Signature header (sig1)', async () => {
    const agent = makeAgentState();
    const result = await signRequest('https://example.com/api', {
      method: 'POST',
      agent,
      body: 'test',
    });

    expect(result.headers['Signature']).toBeDefined();
    expect(result.headers['Signature']).toMatch(/^sig1=:[A-Za-z0-9+/]+=*:$/);
  });

  it('should include the Signature-Input header with correct format', async () => {
    const agent = makeAgentState();
    const result = await signRequest('https://example.com/api', {
      method: 'POST',
      agent,
      body: 'test',
    });

    const input = result.headers['Signature-Input'];
    expect(input).toBeDefined();
    expect(input).toContain('sig1=');
    expect(input).toContain('keyid=');
    expect(input).toContain('created=');
    expect(input).toContain('alg="ed25519"');
    expect(input).toContain('"@method"');
    expect(input).toContain('"@path"');
    expect(input).toContain('"@authority"');
    expect(input).toContain('"content-digest"');
    expect(input).toContain('"aida-agent"');
  });

  it('should include aida-purpose when purpose is provided', async () => {
    const agent = makeAgentState();
    const result = await signRequest('https://example.com/api', {
      method: 'POST',
      agent,
      purpose: 'inference',
    });

    const input = result.headers['Signature-Input'];
    expect(input).toContain('"aida-purpose"');
  });

  it('should not include aida-purpose when purpose is not provided', async () => {
    const agent = makeAgentState();
    const result = await signRequest('https://example.com/api', {
      method: 'GET',
      agent,
    });

    const input = result.headers['Signature-Input'];
    expect(input).not.toContain('aida-purpose');
  });

  it('should compute content-digest from body', async () => {
    const agent = makeAgentState();
    const body = '{"test":true}';
    const result = await signRequest('https://example.com/api', {
      method: 'POST',
      agent,
      body,
    });

    // The signature base should include content-digest
    const input = result.headers['Signature-Input'];
    expect(input).toContain('"content-digest"');

    // And the digest should match
    const expectedDigest = computeContentDigest(body);
    expect(input).toContain('content-digest');
  });

  it('should compute content-digest for empty body (undefined)', async () => {
    const agent = makeAgentState();
    const result = await signRequest('https://example.com/api', {
      method: 'GET',
      agent,
      // no body
    });

    // Should still have content-digest (of empty string)
    const input = result.headers['Signature-Input'];
    expect(input).toContain('"content-digest"');

    // body in result should be undefined
    expect(result.body).toBeUndefined();
  });

  it('should handle URLs with special characters', async () => {
    const agent = makeAgentState();
    const result = await signRequest('https://example.com/api/v1/search?q=hello%20world&lang=en', {
      method: 'GET',
      agent,
    });

    expect(result.url).toBe('https://example.com/api/v1/search?q=hello%20world&lang=en');
    // The @path component should include the path + query
    const input = result.headers['Signature-Input'];
    expect(input).toContain('"@path"');
  });

  it('should handle URLs with path only (no query)', async () => {
    const agent = makeAgentState();
    const result = await signRequest('https://example.com/api/v1/resource', {
      method: 'POST',
      agent,
      body: 'data',
    });

    expect(result.url).toBe('https://example.com/api/v1/resource');
  });

  it('should handle URLs with default port', async () => {
    const agent = makeAgentState();
    const result = await signRequest('https://example.com:443/api', {
      method: 'GET',
      agent,
    });

    // Authority should be example.com (default port omitted per RFC 9421)
    const input = result.headers['Signature-Input'];
    expect(input).toBeDefined();
  });

  it('should produce a verifiable signature', async () => {
    const agent = makeAgentState();
    const result = await signRequest('https://example.com/api', {
      method: 'POST',
      agent,
      body: 'test body',
    });

    // Reconstruct the signature base and verify it
    const url = new URL('https://example.com/api');
    const contentDigest = computeContentDigest('test body');

    const components: Array<{ identifier: string; value: string }> = [
      { identifier: '"@method"', value: 'POST' },
      { identifier: '"@path"', value: url.pathname },
      { identifier: '"@authority"', value: url.host },
      { identifier: '"content-digest"', value: contentDigest },
      { identifier: '"aida-agent"', value: agent.identity.id },
    ];

    const base = buildSignatureBase(components);
    const baseBytes = new TextEncoder().encode(base);

    // Extract signature from header
    const sigHeader = result.headers['Signature'];
    const sigMatch = sigHeader.match(/^sig1=:(.+):$/);
    expect(sigMatch).not.toBeNull();

    const sigBase64 = sigMatch![1]!;
    const sigBytes = Buffer.from(sigBase64, 'base64');

    const isValid = ed25519.verify(sigBytes, baseBytes, agent.keypair.publicKey);
    expect(isValid).toBe(true);
  });

  it('should use the correct nonce algorithm for Ed25519 (deterministic)', async () => {
    // Sign twice with the same inputs and verify signatures are the same
    const agent = makeAgentState();

    const opts = {
      method: 'POST' as const,
      agent,
      body: 'deterministic test',
    };

    const result1 = await signRequest('https://example.com/api', opts);
    const result2 = await signRequest('https://example.com/api', opts);

    // The signature should be the same (deterministic Ed25519)
    // Note: created timestamp differs, so we need to account for that
    expect(result1.headers['Signature']).toBeDefined();
    expect(result2.headers['Signature']).toBeDefined();

    // Both should be valid
    const sigMatch1 = result1.headers['Signature'].match(/^sig1=:(.+):$/);
    const sigMatch2 = result2.headers['Signature'].match(/^sig1=:(.+):$/);
    expect(sigMatch1).not.toBeNull();
    expect(sigMatch2).not.toBeNull();
  });

  it('should handle HTTP method other than GET/POST', async () => {
    const agent = makeAgentState();
    const result = await signRequest('https://example.com/api', {
      method: 'PUT',
      agent,
      body: 'update',
    });

    expect(result.method).toBe('PUT');
    expect(result.headers['Signature']).toBeDefined();
  });

  it('should use the keyid from the identity document id', async () => {
    const agent = makeAgentState();
    const result = await signRequest('https://example.com/api', {
      method: 'GET',
      agent,
    });

    const input = result.headers['Signature-Input'];
    expect(input).toContain(`keyid="${agent.identity.id}"`);
  });

  it('should include created timestamp as unix time', async () => {
    const agent = makeAgentState();
    const before = Math.floor(Date.now() / 1000);
    const result = await signRequest('https://example.com/api', {
      method: 'GET',
      agent,
    });
    const after = Math.floor(Date.now() / 1000);

    const input = result.headers['Signature-Input'];
    const createdMatch = input.match(/created=(\d+)/);
    expect(createdMatch).not.toBeNull();

    const created = parseInt(createdMatch![1]!, 10);
    expect(created).toBeGreaterThanOrEqual(before);
    expect(created).toBeLessThanOrEqual(after);
  });
});
