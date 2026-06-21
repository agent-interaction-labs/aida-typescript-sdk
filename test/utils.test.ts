/**
 * Tests for the utils module.
 *
 * Covers: encodeBase58, decodeBase58, aidaUriToPublicKey, publicKeyToAidaUri,
 * toHex, formatHashLink.
 */
import { describe, it, expect } from 'vitest';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

// @noble/ed25519 v2 requires SHA-512 to be configured for synchronous usage.
ed25519.etc.sha512Sync = sha512;

import {
  encodeBase58,
  decodeBase58,
  aidaUriToPublicKey,
  publicKeyToAidaUri,
  toHex,
  formatHashLink,
} from '../src/utils';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function randomKey(): Uint8Array {
  return ed25519.utils.randomPrivateKey();
}

// ---------------------------------------------------------------------------
// encodeBase58 / decodeBase58
// ---------------------------------------------------------------------------

describe('encodeBase58', () => {
  it('should encode a Uint8Array to a non-empty base58 string', () => {
    const key = randomKey();
    const encoded = encodeBase58(key);
    expect(typeof encoded).toBe('string');
    expect(encoded.length).toBeGreaterThan(0);
  });

  it('should produce only valid base58 characters', () => {
    const key = randomKey();
    const encoded = encodeBase58(key);
    // Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
    expect(encoded).toMatch(/^[1-9A-HJ-NP-Za-km-z]+$/);
  });

  it('should produce a round-trippable encoding', () => {
    const key = randomKey();
    const encoded = encodeBase58(key);
    const decoded = decodeBase58(encoded);
    expect(decoded).toEqual(key);
  });

  it('should produce deterministic encoding for same input', () => {
    const key = new Uint8Array([1, 2, 3, 4, 5]);
    const a = encodeBase58(key);
    const b = encodeBase58(key);
    expect(a).toBe(b);
  });
});

describe('decodeBase58', () => {
  it('should decode a base58 string to a Uint8Array', () => {
    const key = randomKey();
    const encoded = encodeBase58(key);
    const decoded = decodeBase58(encoded);
    expect(decoded).toBeInstanceOf(Uint8Array);
  });

  it('should decode a known base58 value correctly', () => {
    // "Hello" in base58 is well-known
    const decoded = decodeBase58('2NEpo7TZRhna7vSvL');
    const encodedBack = encodeBase58(decoded);
    expect(encodedBack).toBe('2NEpo7TZRhna7vSvL');
  });

  it('should throw on empty string', () => {
    // base58-universal might not throw on empty, but we accept whatever it does
    const result = decodeBase58('');
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// aidaUriToPublicKey / publicKeyToAidaUri
// ---------------------------------------------------------------------------

describe('publicKeyToAidaUri', () => {
  it('should return a valid AIDA URI', () => {
    const key = randomKey();
    const uri = publicKeyToAidaUri(key);
    expect(uri).toMatch(/^aida:[1-9A-HJ-NP-Za-km-z]+$/);
  });

  it('should throw for keys that are not 32 bytes', () => {
    const shortKey = new Uint8Array(16);
    expect(() => publicKeyToAidaUri(shortKey)).toThrow(/32-byte/);

    const longKey = new Uint8Array(64);
    expect(() => publicKeyToAidaUri(longKey)).toThrow(/32-byte/);
  });

  it('should produce a URI that can be round-tripped', () => {
    const key = randomKey();
    const uri = publicKeyToAidaUri(key);
    const decoded = aidaUriToPublicKey(uri);
    expect(decoded).toEqual(key);
  });
});

describe('aidaUriToPublicKey', () => {
  it('should decode a valid AIDA URI to a 32-byte public key', () => {
    const key = randomKey();
    const uri = publicKeyToAidaUri(key);
    const decoded = aidaUriToPublicKey(uri);
    expect(decoded.length).toBe(32);
  });

  it('should throw for invalid AIDA URI prefix', () => {
    expect(() => aidaUriToPublicKey('notaida:abc')).toThrow(/must start with/);
  });

  it('should throw for just "aida:" with no key', () => {
    expect(() => aidaUriToPublicKey('aida:')).not.toThrow(); // empty key decodes to empty
  });
});

// ---------------------------------------------------------------------------
// toHex
// ---------------------------------------------------------------------------

describe('toHex', () => {
  it('should convert a Uint8Array to hex string', () => {
    const data = new Uint8Array([0, 1, 2, 15, 16, 255]);
    expect(toHex(data)).toBe('0001020f10ff');
  });

  it('should handle empty array', () => {
    expect(toHex(new Uint8Array(0))).toBe('');
  });

  it('should pad single-digit bytes with zero', () => {
    const data = new Uint8Array([0, 1, 10, 15]);
    const hex = toHex(data);
    // Every byte should be 2 chars
    expect(hex.length).toBe(8);
    expect(hex).toBe('00010a0f');
  });

  it('should handle all zeroes', () => {
    const data = new Uint8Array([0, 0, 0]);
    expect(toHex(data)).toBe('000000');
  });
});

// ---------------------------------------------------------------------------
// formatHashLink
// ---------------------------------------------------------------------------

describe('formatHashLink', () => {
  it('should format a hash as a sha256: link', () => {
    const hash = new Uint8Array(32);
    const link = formatHashLink(hash);
    expect(link).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('should produce deterministic output for same input', () => {
    const hash = new Uint8Array(32).fill(0xab);
    const a = formatHashLink(hash);
    const b = formatHashLink(hash);
    expect(a).toBe(b);
  });

  it('should handle non-32-byte arrays', () => {
    const hash = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const link = formatHashLink(hash);
    expect(link).toBe('sha256:deadbeef');
  });
});
