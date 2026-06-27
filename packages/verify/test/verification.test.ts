/**
 * Tests for the verification module.
 *
 * Covers: verifyIdentityDocument, createVerificationResult.
 */
import { describe, it, expect } from 'vitest';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

// @noble/ed25519 v2 requires SHA-512 to be configured for synchronous usage.
ed25519.etc.sha512Sync = sha512;

import type { IdentityDocument, AgentController } from '../src/types';
import { encodeBase58, publicKeyToAidaUri } from '../src/utils';

// Modules under test
import {
  verifyIdentityDocument,
  createVerificationResult,
} from '../src/verification';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

function makeController(): AgentController {
  return { email: 'test@example.com' };
}

function makeUnsignedDoc(
  keypair: ReturnType<typeof makeKeypair>,
  controller: AgentController,
): IdentityDocument {
  return {
    id: publicKeyToAidaUri(keypair.publicKey),
    controller,
    publicKey: {
      type: 'Ed25519VerificationKey2020',
      publicKeyBase58: encodeBase58(keypair.publicKey),
    },
    created: new Date().toISOString(),
  };
}

/**
 * Sign an identity document (replicating the signing logic from @aida/agent).
 */
function signDoc(
  doc: IdentityDocument,
  privateKey: Uint8Array,
): IdentityDocument {
  const payload: Record<string, unknown> = {};
  const keys = Object.keys(doc).filter((k) => k !== 'proof').sort();
  for (const key of keys) {
    const value = (doc as unknown as Record<string, unknown>)[key];
    if (value !== undefined) payload[key] = value;
  }

  const canonicalize = (v: unknown): string => {
    if (v === null || v === undefined) return 'null';
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (typeof v === 'number') return Number.isFinite(v) ? String(v) : 'null';
    if (typeof v === 'string') return JSON.stringify(v);
    if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
    if (typeof v === 'object') {
      const ks = Object.keys(v as Record<string, unknown>).sort();
      return `{${ks.map((k) => `${JSON.stringify(k)}:${canonicalize((v as Record<string, unknown>)[k])}`).join(',')}}`;
    }
    return JSON.stringify(v);
  };

  const canonicalPayload = canonicalize(payload);
  const payloadBytes = new TextEncoder().encode(canonicalPayload);
  const signature = ed25519.sign(payloadBytes, privateKey);
  const proofValue = Buffer.from(signature).toString('base64');

  return {
    ...doc,
    proof: {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      proofValue,
      verificationMethod: `${doc.id}#publicKey`,
    },
  };
}

function makeSignedDoc(): IdentityDocument {
  const kp = makeKeypair();
  return signDoc(makeUnsignedDoc(kp, makeController()), kp.privateKey);
}

// ---------------------------------------------------------------------------
// verifyIdentityDocument
// ---------------------------------------------------------------------------

describe('verifyIdentityDocument', () => {
  it('should return valid=true for a valid self-signed document', () => {
    const doc = makeSignedDoc();
    const result = verifyIdentityDocument(doc);
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('should return valid=false when proof is missing', () => {
    const doc = makeUnsignedDoc(makeKeypair(), makeController());
    const result = verifyIdentityDocument(doc);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('proof');
  });

  it('should return valid=false when proof type is not Ed25519Signature2020', () => {
    const doc = makeSignedDoc();
    const tampered = JSON.parse(JSON.stringify(doc)) as IdentityDocument;
    (tampered as any).proof!.type = 'RsaSignature2018';
    const result = verifyIdentityDocument(tampered);
    expect(result.valid).toBe(false);
  });

  it('should return valid=false when verificationMethod does not match', () => {
    const doc = makeSignedDoc();
    const tampered = JSON.parse(JSON.stringify(doc)) as IdentityDocument;
    tampered.proof!.verificationMethod = 'aida:attacker#publicKey';
    const result = verifyIdentityDocument(tampered);
    expect(result.valid).toBe(false);
  });

  it('should return valid=false when controller is tampered', () => {
    const doc = makeSignedDoc();
    const tampered = JSON.parse(JSON.stringify(doc)) as IdentityDocument;
    tampered.controller = { email: 'attacker@evil.com' };
    const result = verifyIdentityDocument(tampered);
    expect(result.valid).toBe(false);
  });

  it('should return valid=false when id is changed', () => {
    const doc = makeSignedDoc();
    const tampered = JSON.parse(JSON.stringify(doc)) as IdentityDocument;
    tampered.id = 'aida:EvilAttackerKey';
    const result = verifyIdentityDocument(tampered);
    expect(result.valid).toBe(false);
  });

  it('should return valid=false when publicKey is changed', () => {
    const doc = makeSignedDoc();
    const tampered = JSON.parse(JSON.stringify(doc)) as IdentityDocument;
    tampered.publicKey.publicKeyBase58 = encodeBase58(makeKeypair().publicKey);
    const result = verifyIdentityDocument(tampered);
    expect(result.valid).toBe(false);
  });

  it('should return valid=false when created timestamp is changed', () => {
    const doc = makeSignedDoc();
    const tampered = JSON.parse(JSON.stringify(doc)) as IdentityDocument;
    tampered.created = '2000-01-01T00:00:00.000Z';
    const result = verifyIdentityDocument(tampered);
    expect(result.valid).toBe(false);
  });

  it('should return valid=false when proof.proofValue is tampered', () => {
    const doc = makeSignedDoc();
    const tampered = JSON.parse(JSON.stringify(doc)) as IdentityDocument;
    tampered.proof!.proofValue = 'deadbeef';
    const result = verifyIdentityDocument(tampered);
    expect(result.valid).toBe(false);
  });

  it('should return valid=false for a document signed with the wrong key', () => {
    const kp1 = makeKeypair();
    const kp2 = makeKeypair();
    const unsigned = makeUnsignedDoc(kp2, makeController());
    const signed = signDoc(unsigned, kp1.privateKey);
    const result = verifyIdentityDocument(signed);
    expect(result.valid).toBe(false);
  });

  it('should return valid=false when publicKey type is not Ed25519VerificationKey2020', () => {
    const doc = makeSignedDoc();
    const tampered = JSON.parse(JSON.stringify(doc)) as IdentityDocument;
    (tampered as any).publicKey!.type = 'RsaVerificationKey2018';
    const result = verifyIdentityDocument(tampered);
    expect(result.valid).toBe(false);
  });

  it('should return valid=false for expired document when clockSkew is 0', () => {
    const kp = makeKeypair();
    const unsigned = makeUnsignedDoc(kp, makeController());
    unsigned.expires = '2000-01-01T00:00:00.000Z';
    const signed = signDoc(unsigned, kp.privateKey);
    const result = verifyIdentityDocument(signed, { clockSkew: 0 });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('expired');
  });

  it('should return valid=true for expired document when clockSkew is large', () => {
    const kp = makeKeypair();
    const unsigned = makeUnsignedDoc(kp, makeController());
    unsigned.expires = new Date(Date.now() + 1000).toISOString(); // expires in 1 second
    const signed = signDoc(unsigned, kp.privateKey);
    const result = verifyIdentityDocument(signed, { clockSkew: 3600 });
    expect(result.valid).toBe(true);
  });

  it('should return valid=false when created timestamp is in the future beyond clockSkew', () => {
    const kp = makeKeypair();
    const unsigned = makeUnsignedDoc(kp, makeController());
    unsigned.created = new Date(Date.now() + 86400000).toISOString(); // 1 day in future
    const signed = signDoc(unsigned, kp.privateKey);
    const result = verifyIdentityDocument(signed, { clockSkew: 0 });
    expect(result.valid).toBe(false);
    expect(result.error).toContain('future');
  });

  it('should return valid=false for expired document with default clockSkew', () => {
    const kp = makeKeypair();
    const unsigned = makeUnsignedDoc(kp, makeController());
    unsigned.expires = '2000-01-01T00:00:00.000Z';
    const signed = signDoc(unsigned, kp.privateKey);
    const result = verifyIdentityDocument(signed);
    expect(result.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// createVerificationResult
// ---------------------------------------------------------------------------

describe('createVerificationResult', () => {
  it('should create a result with the agentId', () => {
    const result = createVerificationResult('aida:testkey', true);
    expect(result.agentId).toBe('aida:testkey');
    expect(result.verified).toBe(true);
  });

  it('should include optional controller', () => {
    const controller: AgentController = { email: 'a@b.com' };
    const result = createVerificationResult('aida:test', true, controller);
    expect(result.controller).toEqual(controller);
  });

  it('should include optional purpose', () => {
    const result = createVerificationResult('aida:test', true, undefined, 'inference');
    expect(result.purpose).toBe('inference');
  });

  it('should include metadata with verifiedAt timestamp', () => {
    const result = createVerificationResult('aida:test', true);
    expect(result.metadata).toBeDefined();
    expect(result.metadata!.verifiedAt).toBeTruthy();
    expect(() => new Date(result.metadata!.verifiedAt)).not.toThrow();
  });

  it('should set identityResolved to false by default', () => {
    const result = createVerificationResult('aida:test', true);
    expect(result.metadata!.identityResolved).toBe(false);
  });

  it('should include publicKey when provided', () => {
    const pk = new Uint8Array(32);
    const result = createVerificationResult('aida:test', true, undefined, undefined, { publicKey: pk });
    expect(result.publicKey).toBe(pk);
  });

  it('should include error when verification failed', () => {
    const result = createVerificationResult('aida:test', false, undefined, undefined, { error: 'bad signature' });
    expect(result.verified).toBe(false);
    expect(result.error).toBe('bad signature');
  });
});
