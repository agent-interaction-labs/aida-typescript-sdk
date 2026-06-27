/**
 * AIDA Verify SDK — Utility functions.
 * Base58 encoding/decoding, JWK conversion, hash formatting.
 */

import { encode, decode } from 'base58-universal';

/**
 * Encode a Uint8Array as a base58 string.
 * Uses the Bitcoin alphabet (no 0, O, I, l).
 */
export function encodeBase58(data: Uint8Array): string {
  return encode(data);
}

/**
 * Decode a base58 string to a Uint8Array.
 */
export function decodeBase58(encoded: string): Uint8Array {
  return decode(encoded);
}

/**
 * Convert an Ed25519 public key (32 bytes) to an AIDA URI.
 */
export function publicKeyToAidaUri(publicKey: Uint8Array): `aida:${string}` {
  if (publicKey.length !== 32) {
    throw new Error(`Expected 32-byte Ed25519 public key, got ${publicKey.length} bytes`);
  }
  return `aida:${encodeBase58(publicKey)}`;
}

/**
 * Extract the base58-encoded public key from an AIDA URI.
 */
export function aidaUriToBase58(uri: string): string {
  if (!uri.startsWith('aida:')) {
    throw new Error(`Invalid AIDA URI: must start with "aida:", got "${uri}"`);
  }
  return uri.slice(5);
}

/**
 * Convert an AIDA URI back to a Uint8Array public key.
 */
export function aidaUriToPublicKey(uri: string): Uint8Array {
  return decodeBase58(aidaUriToBase58(uri));
}

/**
 * Convert a Uint8Array to a hex string with optional prefix.
 */
export function toHex(data: Uint8Array): string {
  return Array.from(data)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Format a SHA-256 hash as a HashLink string.
 */
export function formatHashLink(hash: Uint8Array): `sha256:${string}` {
  return `sha256:${toHex(hash)}`;
}
