/**
 * RFC 9421 signing helpers for test use only.
 *
 * These replicate the signing logic from @aida/agent so that verification
 * tests can produce valid signed requests without importing the agent SDK.
 */

import { sha256 } from '@noble/hashes/sha256';

/**
 * Compute the content-digest of a request body per RFC 9421.
 */
export function computeContentDigest(body?: string): string {
  const data = new TextEncoder().encode(body ?? '');
  const hash = sha256(data);
  const base64 = Buffer.from(hash).toString('base64');
  return `sha-256=:${base64}:`;
}

/**
 * Build the RFC 9421 signature base string from an array of components.
 */
export function buildSignatureBase(
  components: ReadonlyArray<{ identifier: string; value: string }>,
): string {
  return components
    .map((comp) => {
      const encodedValue = encodeComponentValue(comp.value);
      return `${comp.identifier}: ${encodedValue}`;
    })
    .join('\n');
}

function encodeComponentValue(value: string): string {
  if (isBinaryValue(value)) {
    return `:${value}:`;
  }
  return value;
}

function isBinaryValue(value: string): boolean {
  return value.includes('=:');
}
