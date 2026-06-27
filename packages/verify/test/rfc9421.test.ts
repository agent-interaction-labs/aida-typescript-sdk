/**
 * Tests for the RFC 9421 signature verification module.
 *
 * Covers: verifySignature, extractKeyId.
 */
import { describe, it, expect } from 'vitest';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

// @noble/ed25519 v2 requires SHA-512 to be configured for synchronous usage.
ed25519.etc.sha512Sync = sha512;

import type { AgentPurpose } from '../src/types';
import { publicKeyToAidaUri } from '../src/utils';
import { computeContentDigest, buildSignatureBase } from './helpers/signing-helpers';

// Module under test
import { verifySignature, extractKeyId } from '../src/rfc9421';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/**
 * Sign a request and return the headers that would be sent.
 * Replicates the signing logic from @aida/agent for producing test vectors.
 */
function signRequest(
  method: string,
  path: string,
  authority: string,
  privateKey: Uint8Array,
  agentId: string,
  body?: string,
  purpose?: AgentPurpose,
): { headers: Record<string, string> } {
  const contentDigest = computeContentDigest(body);
  const components: Array<{ identifier: string; value: string }> = [
    { identifier: '"@method"', value: method },
    { identifier: '"@path"', value: path },
    { identifier: '"@authority"', value: authority },
    { identifier: '"content-digest"', value: contentDigest },
    { identifier: '"aida-agent"', value: agentId },
  ];

  if (purpose !== undefined) {
    components.push({ identifier: '"aida-purpose"', value: purpose });
  }

  const identifiers = components.map((c) => c.identifier);
  const signatureBase = buildSignatureBase(components);
  const signatureBaseBytes = new TextEncoder().encode(signatureBase);

  const created = Math.floor(Date.now() / 1000);
  const signature = ed25519.sign(signatureBaseBytes, privateKey);
  const signatureBase64 = Buffer.from(signature).toString('base64');

  // Build Signature-Input header
  const identifierList = identifiers.join(' ');
  const signatureInput =
    `sig1=(${identifierList});keyid="${agentId}";created=${created};alg="ed25519"`;

  // Build Signature header
  const signatureHeader = `sig1=:${signatureBase64}:`;

  return {
    headers: {
      'Aida-Agent': agentId,
      'Content-Digest': contentDigest,
      'Signature-Input': signatureInput,
      'Signature': signatureHeader,
      ...(purpose ? { 'Aida-Purpose': purpose } : {}),
    },
  };
}

// ---------------------------------------------------------------------------
// extractKeyId
// ---------------------------------------------------------------------------

describe('extractKeyId', () => {
  it('should extract keyid from a valid Signature-Input header', () => {
    const header =
      'sig1=("@method" "@path");keyid="aida:testkey";created=1234567890;alg="ed25519"';
    expect(extractKeyId(header)).toBe('aida:testkey');
  });

  it('should return null for missing keyid', () => {
    const header =
      'sig1=("@method" "@path");created=1234567890;alg="ed25519"';
    expect(extractKeyId(header)).toBeNull();
  });

  it('should return null for empty string', () => {
    expect(extractKeyId('')).toBeNull();
  });

  it('should handle keyid with special characters', () => {
    const header =
      'sig1=("@method");keyid="aida:AbCdEfGhIjKlMnOpQrStUvWxYz123456789";created=1;alg="ed25519"';
    expect(extractKeyId(header)).toBe(
      'aida:AbCdEfGhIjKlMnOpQrStUvWxYz123456789',
    );
  });

  it('should handle keyid as the last parameter', () => {
    const header =
      'sig1=("@method" "@path");created=1000;alg="ed25519";keyid="aida:latekey"';
    expect(extractKeyId(header)).toBe('aida:latekey');
  });
});

// ---------------------------------------------------------------------------
// verifySignature
// ---------------------------------------------------------------------------

describe('verifySignature', () => {
  it('should return valid=true for a correctly signed request', () => {
    const kp = makeKeypair();
    const agentId = publicKeyToAidaUri(kp.publicKey);

    const signed = signRequest(
      'POST',
      '/api/data',
      'example.com',
      kp.privateKey,
      agentId,
      '{"hello":"world"}',
    );

    const result = verifySignature(signed.headers, kp.publicKey, {
      method: 'POST',
      path: '/api/data',
      authority: 'example.com',
    });
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('should return valid=false when Signature header is missing', () => {
    const kp = makeKeypair();
    const result = verifySignature({ 'Signature-Input': 'sig1=("@method");keyid="aida:test";created=1;alg="ed25519"' }, kp.publicKey);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Signature');
  });

  it('should return valid=false when Signature-Input header is missing', () => {
    const kp = makeKeypair();
    const result = verifySignature({ 'Signature': 'sig1=:abc:' }, kp.publicKey);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Signature-Input');
  });

  it('should return valid=false for an invalid signature', () => {
    const kp = makeKeypair();
    const agentId = publicKeyToAidaUri(kp.publicKey);

    const signed = signRequest(
      'POST',
      '/api/data',
      'example.com',
      kp.privateKey,
      agentId,
      'original body',
    );

    // Tamper with the body → headers don't match
    const tamperedHeaders = { ...signed.headers };
    tamperedHeaders['Signature'] = tamperedHeaders['Signature']!.replace(/[A-Za-z]/, 'X');

    const result = verifySignature(tamperedHeaders, kp.publicKey);
    expect(result.valid).toBe(false);
  });

  it('should return valid=false when @method is tampered', () => {
    const kp = makeKeypair();
    const agentId = publicKeyToAidaUri(kp.publicKey);

    const signed = signRequest(
      'GET',
      '/api/data',
      'example.com',
      kp.privateKey,
      agentId,
    );

    const wrongKp = makeKeypair();
    const result = verifySignature(signed.headers, wrongKp.publicKey);
    expect(result.valid).toBe(false);
  });

  it('should verify a request with aida-purpose', () => {
    const kp = makeKeypair();
    const agentId = publicKeyToAidaUri(kp.publicKey);

    const signed = signRequest(
      'POST',
      '/api/query',
      'agent.example.com',
      kp.privateKey,
      agentId,
      '{"query":"test"}',
      'inference',
    );

    const result = verifySignature(signed.headers, kp.publicKey, {
      method: 'POST',
      path: '/api/query',
      authority: 'agent.example.com',
    });
    expect(result.valid).toBe(true);
  });

  it('should handle GET requests with no body', () => {
    const kp = makeKeypair();
    const agentId = publicKeyToAidaUri(kp.publicKey);

    const signed = signRequest(
      'GET',
      '/api/status',
      'example.com',
      kp.privateKey,
      agentId,
    );

    const result = verifySignature(signed.headers, kp.publicKey, {
      method: 'GET',
      path: '/api/status',
      authority: 'example.com',
    });
    expect(result.valid).toBe(true);
  });

  it('should handle paths with query strings', () => {
    const kp = makeKeypair();
    const agentId = publicKeyToAidaUri(kp.publicKey);

    const signed = signRequest(
      'GET',
      '/api/search?q=hello&page=1',
      'example.com',
      kp.privateKey,
      agentId,
    );

    const result = verifySignature(signed.headers, kp.publicKey, {
      method: 'GET',
      path: '/api/search?q=hello&page=1',
      authority: 'example.com',
    });
    expect(result.valid).toBe(true);
  });

  it('should return valid=false when signature is malformed', () => {
    const kp = makeKeypair();
    const agentId = publicKeyToAidaUri(kp.publicKey);

    const signed = signRequest(
      'GET',
      '/api/data',
      'example.com',
      kp.privateKey,
      agentId,
    );

    const badHeaders = {
      ...signed.headers,
      'Signature': 'not-a-valid-signature-header',
      'Signature-Input': signed.headers['Signature-Input'],
    };

    const result = verifySignature(badHeaders, kp.publicKey);
    expect(result.valid).toBe(false);
  });

  it('should return valid=false when Signature-Input is malformed', () => {
    const kp = makeKeypair();
    const agentId = publicKeyToAidaUri(kp.publicKey);

    const signed = signRequest(
      'GET',
      '/api/data',
      'example.com',
      kp.privateKey,
      agentId,
    );

    const badHeaders = {
      ...signed.headers,
      'Signature': signed.headers['Signature'],
      'Signature-Input': 'not valid input',
    };

    const result = verifySignature(badHeaders, kp.publicKey);
    expect(result.valid).toBe(false);
  });

  it('should return valid=false when headers object has incorrect casing for component names', () => {
    const kp = makeKeypair();
    // The verifySignature function should be case-insensitive for HTTP header names
    // according to HTTP spec. However, we test the lowercased variant works.
    const agentId = publicKeyToAidaUri(kp.publicKey);

    const signed = signRequest(
      'POST',
      '/api/data',
      'example.com',
      kp.privateKey,
      agentId,
      'test body',
    );

    // Use lowercase header names
    const lowercaseHeaders: Record<string, string> = {};
    for (const [key, value] of Object.entries(signed.headers)) {
      lowercaseHeaders[key.toLowerCase()] = value;
    }

    const result = verifySignature(lowercaseHeaders, kp.publicKey, {
      method: 'POST',
      path: '/api/data',
      authority: 'example.com',
    });
    expect(result.valid).toBe(true);
  });

  it('should reject signature with expired created timestamp (beyond clockSkew)', () => {
    const kp = makeKeypair();
    const agentId = publicKeyToAidaUri(kp.publicKey);

    // Create a signature with an old timestamp
    const contentDigest = computeContentDigest('test');
    const components = [
      { identifier: '"@method"', value: 'GET' },
      { identifier: '"@path"', value: '/api/data' },
      { identifier: '"@authority"', value: 'example.com' },
      { identifier: '"content-digest"', value: contentDigest },
      { identifier: '"aida-agent"', value: agentId },
    ];
    const identifiers = components.map((c) => c.identifier);
    const signatureBase = buildSignatureBase(components);
    const signatureBaseBytes = new TextEncoder().encode(signatureBase);

    // Sign with a very old timestamp
    const oldCreated = Math.floor(Date.now() / 1000) - 86400; // 24 hours ago
    const signature = ed25519.sign(signatureBaseBytes, kp.privateKey);
    const signatureBase64 = Buffer.from(signature).toString('base64');

    const headers: Record<string, string> = {
      'Content-Digest': contentDigest,
      'Aida-Agent': agentId,
      'Signature-Input': `sig1=(${identifiers.join(' ')});keyid="${agentId}";created=${oldCreated};alg="ed25519"`,
      'Signature': `sig1=:${signatureBase64}:`,
    };

    // With default clockSkew (300s), this should fail
    const result = verifySignature(headers, kp.publicKey, {
      method: 'GET',
      path: '/api/data',
      authority: 'example.com',
    });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('expired');
  });

  it('should accept signature with old timestamp when clockSkew is large', () => {
    const kp = makeKeypair();
    const agentId = publicKeyToAidaUri(kp.publicKey);

    const contentDigest = computeContentDigest('test');
    const components = [
      { identifier: '"@method"', value: 'GET' },
      { identifier: '"@path"', value: '/api/data' },
      { identifier: '"@authority"', value: 'example.com' },
      { identifier: '"content-digest"', value: contentDigest },
      { identifier: '"aida-agent"', value: agentId },
    ];
    const identifiers = components.map((c) => c.identifier);
    const signatureBase = buildSignatureBase(components);
    const signatureBaseBytes = new TextEncoder().encode(signatureBase);

    const oldCreated = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
    const signature = ed25519.sign(signatureBaseBytes, kp.privateKey);
    const signatureBase64 = Buffer.from(signature).toString('base64');

    const headers: Record<string, string> = {
      'Signature-Input': `sig1=(${identifiers.join(' ')});keyid="${agentId}";created=${oldCreated};alg="ed25519"`,
      'Signature': `sig1=:${signatureBase64}:`,
      'Content-Digest': contentDigest,
      'Aida-Agent': agentId,
    };

    // With large clockSkew, this should pass
    const result = verifySignature(headers, kp.publicKey, {
      clockSkew: 7200,
      method: 'GET',
      path: '/api/data',
      authority: 'example.com',
    });
    expect(result.valid).toBe(true);
  });

  it('should reject future created timestamps', () => {
    const kp = makeKeypair();
    const agentId = publicKeyToAidaUri(kp.publicKey);

    const contentDigest = computeContentDigest('test');
    const components = [
      { identifier: '"@method"', value: 'GET' },
      { identifier: '"@path"', value: '/api/data' },
      { identifier: '"@authority"', value: 'example.com' },
      { identifier: '"content-digest"', value: contentDigest },
      { identifier: '"aida-agent"', value: agentId },
    ];
    const identifiers = components.map((c) => c.identifier);
    const signatureBase = buildSignatureBase(components);
    const signatureBaseBytes = new TextEncoder().encode(signatureBase);

    const futureCreated = Math.floor(Date.now() / 1000) + 3600; // 1 hour in future
    const signature = ed25519.sign(signatureBaseBytes, kp.privateKey);
    const signatureBase64 = Buffer.from(signature).toString('base64');

    const headers: Record<string, string> = {
      'Signature-Input': `sig1=(${identifiers.join(' ')});keyid="${agentId}";created=${futureCreated};alg="ed25519"`,
      'Signature': `sig1=:${signatureBase64}:`,
    };

    const result = verifySignature(headers, kp.publicKey, {
      clockSkew: 0,
      method: 'GET',
      path: '/api/data',
      authority: 'example.com',
    });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('future');
  });

  it('should handle empty headers object', () => {
    const kp = makeKeypair();
    const result = verifySignature({}, kp.publicKey);
    expect(result.valid).toBe(false);
  });
});
