/**
 * AIDA Verify SDK — Identity document verification and result construction.
 *
 * Verifies Ed25519 self-signatures on AIDA Identity Documents, checks
 * timestamps, and creates structured VerificationResult objects.
 */

import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

// @noble/ed25519 v2 requires SHA-512 to be configured for synchronous usage.
ed25519.etc.sha512Sync = sha512;

import { Buffer } from 'node:buffer';
import type { IdentityDocument, VerificationResult, AgentPurpose, AgentController, AidaUri } from './types';
import { decodeBase58 } from './utils';

// ---------------------------------------------------------------------------
// JSON Canonicalization (same algorithm as @aida/agent)
// ---------------------------------------------------------------------------

/**
 * Canonicalize a JSON-serializable value for signing/verification.
 *
 * Sorts all object keys alphabetically and removes whitespace.
 * This ensures deterministic serialization regardless of property order.
 *
 * @param value - Any JSON-serializable value to canonicalize.
 * @returns Canonical JSON string with sorted keys and no whitespace.
 */
function canonicalize(value: unknown): string {
  if (value === null || value === undefined) {
    return 'null';
  }

  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      return 'null';
    }
    return String(value);
  }

  if (typeof value === 'string') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const elements = value.map((v) => canonicalize(v)).join(',');
    return `[${elements}]`;
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value as Record<string, unknown>).sort();
    const pairs = keys.map((k) => {
      const v = (value as Record<string, unknown>)[k];
      if (v === undefined) {
        return '';
      }
      return `${JSON.stringify(k)}:${canonicalize(v)}`;
    });
    return `{${pairs.join(',')}}`;
  }

  return JSON.stringify(value);
}

/**
 * Extract the canonicalizable portion of an IdentityDocument for signing.
 *
 * All fields except `proof` are included. Keys are inserted in alphabetical
 * order as determined by the canonicalize function.
 */
function documentForSigning(doc: IdentityDocument): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  const keys = Object.keys(doc).filter((k) => k !== 'proof').sort();

  for (const key of keys) {
    const value = (doc as unknown as Record<string, unknown>)[key];
    if (value !== undefined) {
      result[key] = value;
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// verifyIdentityDocument
// ---------------------------------------------------------------------------

/**
 * Options for identity document verification.
 */
export interface VerifyIdentityDocumentOptions {
  /**
   * Maximum clock skew tolerance in seconds for timestamp validation.
   * Default: 300 (5 minutes).
   */
  clockSkew?: number;
}

/**
 * Verify an identity document's self-signature and timestamps.
 *
 * Extracts the public key from the document's `publicKey.publicKeyBase58`,
 * re-canonicalizes the document body (everything except `proof`), and
 * verifies the Ed25519 signature from `proof.proofValue`.
 *
 * Also validates that:
 * - The `created` timestamp is not in the future (beyond clock skew).
 * - The `expires` timestamp (if present) has not passed (beyond clock skew).
 *
 * @param document - The identity document to verify.
 * @param options - Optional verification options (clock skew).
 * @returns A result object with `valid` boolean and optional `error` string.
 */
export function verifyIdentityDocument(
  document: IdentityDocument,
  options: VerifyIdentityDocumentOptions = {},
): { valid: boolean; error?: string } {
  const { clockSkew = 300 } = options;

  // Must have a proof
  if (!document.proof) {
    return { valid: false, error: 'Missing proof' };
  }

  // Must be the expected proof type
  if (document.proof.type !== 'Ed25519Signature2020') {
    return {
      valid: false,
      error: `Invalid proof type: expected Ed25519Signature2020, got ${document.proof.type}`,
    };
  }

  // Must reference this document's public key
  if (document.proof.verificationMethod !== `${document.id}#publicKey`) {
    return {
      valid: false,
      error: 'verificationMethod does not reference this document\'s public key',
    };
  }

  // Must have an Ed25519 public key type
  if (document.publicKey.type !== 'Ed25519VerificationKey2020') {
    return {
      valid: false,
      error: `Invalid public key type: expected Ed25519VerificationKey2020, got ${document.publicKey.type}`,
    };
  }

  // Timestamp validation
  const now = Math.floor(Date.now() / 1000);

  // Check created timestamp (should not be in the future)
  const createdTime = Math.floor(new Date(document.created).getTime() / 1000);
  if (isNaN(createdTime)) {
    return { valid: false, error: 'Invalid created timestamp: could not parse' };
  }
  if (createdTime > now + clockSkew) {
    return { valid: false, error: 'Document created timestamp is in the future' };
  }

  // Check expires timestamp (should not be in the past)
  if (document.expires) {
    const expiresTime = Math.floor(new Date(document.expires).getTime() / 1000);
    if (isNaN(expiresTime)) {
      return { valid: false, error: 'Invalid expires timestamp: could not parse' };
    }
    if (expiresTime < now - clockSkew) {
      return { valid: false, error: 'Document has expired' };
    }
  }

  // Cryptographic verification
  try {
    // Decode the public key from base58
    const publicKey = decodeBase58(document.publicKey.publicKeyBase58);

    // Decode the signature from base64
    const signature = Buffer.from(document.proof.proofValue, 'base64');

    // Rebuild the payload to verify
    const payload = documentForSigning(document);
    const canonicalPayload = canonicalize(payload);
    const payloadBytes = new TextEncoder().encode(canonicalPayload);

    // Verify the Ed25519 signature
    const valid = ed25519.verify(signature, payloadBytes, publicKey);
    if (!valid) {
      return { valid: false, error: 'Ed25519 signature verification failed' };
    }

    return { valid: true };
  } catch (err) {
    return { valid: false, error: `Verification error: ${String(err)}` };
  }
}

// ---------------------------------------------------------------------------
// createVerificationResult
// ---------------------------------------------------------------------------

/**
 * Options for creating a verification result.
 */
export interface CreateVerificationResultOptions {
  /** Public key that verified the signature */
  publicKey?: Uint8Array;
  /** Error message for failed verification */
  error?: string;
  /** Whether the identity document was resolved */
  identityResolved?: boolean;
  /** Whether the identity document's self-signature verified */
  identityVerified?: boolean;
  /** Unix timestamp when the request was signed */
  signedAt?: number;
}

/**
 * Create a structured {@link VerificationResult}.
 *
 * @param agentId - The agent's AIDA URI.
 * @param verified - Whether verification succeeded.
 * @param controller - Optional controller information from the identity document.
 * @param purpose - Optional purpose declared in the request signature.
 * @param options - Additional metadata for the result.
 * @returns A fully populated {@link VerificationResult}.
 */
export function createVerificationResult(
  agentId: AidaUri,
  verified: boolean,
  controller?: AgentController,
  purpose?: AgentPurpose,
  options: CreateVerificationResultOptions = {},
): VerificationResult {
  const result: VerificationResult = {
    agentId,
    verified,
    metadata: {
      verifiedAt: new Date().toISOString(),
      identityResolved: options.identityResolved ?? false,
    },
  };

  if (controller !== undefined) {
    result.controller = controller;
  }

  if (purpose !== undefined) {
    result.purpose = purpose;
  }

  if (options.publicKey !== undefined) {
    result.publicKey = options.publicKey;
  }

  if (options.error !== undefined) {
    result.error = options.error;
  }

  if (options.identityVerified !== undefined) {
    result.metadata!.identityVerified = options.identityVerified;
  }

  if (options.signedAt !== undefined) {
    result.metadata!.signedAt = options.signedAt;
  }

  return result;
}
