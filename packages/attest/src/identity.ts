/**
 * AIDA Agent SDK — Identity Document creation, signing, and verification.
 *
 * Implements the AIDA Identity Document specification with Ed25519 self-signatures
 * using JSON canonicalization (sorted keys, no whitespace).
 */
import * as ed25519 from '@noble/ed25519';
import { Buffer } from 'node:buffer';
import type { AgentKeypair, IdentityDocument, CreateAgentOptions } from './types';
import { encodeBase58, publicKeyToAidaUri, nowISO, decodeBase58 } from './utils';

// ---------------------------------------------------------------------------
// JSON Canonicalization
// ---------------------------------------------------------------------------

/**
 * Canonicalize a JSON-serializable value for signing.
 *
 * Sorts all object keys alphabetically and removes whitespace.
 * This ensures deterministic serialization regardless of property order.
 *
 * @param value - Any JSON-serializable value to canonicalize.
 * @returns Canonical JSON string with sorted keys and no whitespace.
 */
export function canonicalize(value: unknown): string {
  if (value === null || value === undefined) {
    return 'null';
  }

  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }

  if (typeof value === 'number') {
    // Handle NaN and Infinity (though they shouldn't appear in valid identity docs)
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
      // Skip undefined values — they won't survive JSON serialization anyway
      if (v === undefined) {
        return '';
      }
      return `${JSON.stringify(k)}:${canonicalize(v)}`;
    });
    return `{${pairs.join(',')}}`;
  }

  // Fallback — shouldn't happen for valid JSON values
  return JSON.stringify(value);
}

/**
 * Extract the canonicalizable portion of an IdentityDocument for signing.
 *
 * All fields except `proof` are included. Keys are sorted alphabetically
 * by the canonicalize function.
 */
function documentForSigning(doc: IdentityDocument): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  // Sort keys to ensure deterministic order
  const keys = Object.keys(doc).filter((k) => k !== 'proof').sort();

  for (const key of keys) {
    const value = (doc as unknown as Record<string, unknown>)[key];
    // Only include defined, non-undefined values
    if (value !== undefined) {
      result[key] = value;
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Create a signed AIDA Identity Document.
 *
 * Computes the AIDA URI from the public key, adds a `created` timestamp,
 * and self-signs the document with the provided Ed25519 keypair.
 *
 * @param keypair - The Ed25519 keypair for this agent identity.
 * @param options - Options including controller, optional endpoints, and capabilities.
 * @returns A fully signed {@link IdentityDocument} ready for publishing.
 */
export function createIdentityDocument(
  keypair: AgentKeypair,
  options: CreateAgentOptions,
): IdentityDocument {
  const id = publicKeyToAidaUri(keypair.publicKey);
  const created = nowISO();

  const doc: IdentityDocument = {
    id,
    controller: options.controller,
    publicKey: {
      type: 'Ed25519VerificationKey2020',
      publicKeyBase58: encodeBase58(keypair.publicKey),
    },
    created,
  };

  // Add optional fields only if provided
  if (options.endpoints !== undefined && options.endpoints.length > 0) {
    doc.endpoints = options.endpoints;
  }

  if (options.capabilities !== undefined && options.capabilities.length > 0) {
    doc.capabilities = options.capabilities;
  }

  // Self-sign the document
  return signIdentityDocument(doc, keypair.privateKey);
}

/**
 * Sign an identity document with an Ed25519 private key.
 *
 * Uses JSON canonicalization (sorted keys, no whitespace) on the document
 * body (everything except `proof`) before signing. Adds or overwrites the
 * `proof` object with an Ed25519Signature2020 proof.
 *
 * @param document - The identity document to sign (with or without existing proof).
 * @param privateKey - The 32-byte Ed25519 private key.
 * @returns The document with an updated {@link IdentityDocument.proof|proof}.
 */
export function signIdentityDocument(
  document: IdentityDocument,
  privateKey: Uint8Array,
): IdentityDocument {
  // Build the payload to sign (everything except proof)
  const payload = documentForSigning(document);
  const canonicalPayload = canonicalize(payload);
  const payloadBytes = new TextEncoder().encode(canonicalPayload);

  // Sign the canonical payload
  const signature = ed25519.sign(payloadBytes, privateKey);
  const proofValue = Buffer.from(signature).toString('base64');

  const verificationMethod = `${document.id}#publicKey`;

  const proof = {
    type: 'Ed25519Signature2020' as const,
    created: nowISO(),
    proofValue,
    verificationMethod,
  };

  return { ...document, proof };
}

/**
 * Verify an identity document's self-signature.
 *
 * Extracts the public key from the document's `publicKey.publicKeyBase58`,
 * re-canonicalizes the document body (everything except `proof`), and
 * verifies the Ed25519 signature from `proof.proofValue`.
 *
 * @param document - The identity document to verify.
 * @returns `true` if the self-signature is valid, `false` otherwise.
 */
export function verifyIdentityDocument(document: IdentityDocument): boolean {
  // Must have a proof
  if (!document.proof) {
    return false;
  }

  // Must be the expected proof type
  if (document.proof.type !== 'Ed25519Signature2020') {
    return false;
  }

  // Must reference this document's public key
  if (document.proof.verificationMethod !== `${document.id}#publicKey`) {
    return false;
  }

  // Must have an Ed25519 public key type
  if (document.publicKey.type !== 'Ed25519VerificationKey2020') {
    return false;
  }

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
    return ed25519.verify(signature, payloadBytes, publicKey);
  } catch {
    // Any failure in decoding keys or signatures means verification fails
    return false;
  }
}
