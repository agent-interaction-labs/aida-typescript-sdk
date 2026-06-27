/**
 * Tests for the identity module.
 *
 * Covers: createIdentityDocument, signIdentityDocument, verifyIdentityDocument.
 */
import { describe, it, expect } from 'vitest';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

// @noble/ed25519 v2 requires SHA-512 to be configured for synchronous usage.
ed25519.etc.sha512Sync = sha512;

import type { AgentKeypair, IdentityDocument, AgentController } from '../src/types';
import { encodeBase58 } from '../src/utils';
import { generateKeypair } from '../src/keys';

// Modules under test
import {
  createIdentityDocument,
  signIdentityDocument,
  verifyIdentityDocument,
} from '../src/identity';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeKeypair(): AgentKeypair {
  return generateKeypair();
}

function makeController(): AgentController {
  return { email: 'test@example.com' };
}

/** Deep-clone an IdentityDocument so we can tamper without affecting the original */
function cloneDocument(doc: IdentityDocument): IdentityDocument {
  return JSON.parse(JSON.stringify(doc)) as IdentityDocument;
}

// ---------------------------------------------------------------------------
// createIdentityDocument
// ---------------------------------------------------------------------------

describe('createIdentityDocument', () => {
  it('should create a document with the correct id (AIDA URI)', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const doc = createIdentityDocument(kp, { controller });

    const expectedId = `aida:${encodeBase58(kp.publicKey)}`;
    expect(doc.id).toBe(expectedId);
  });

  it('should set the controller as provided', () => {
    const kp = makeKeypair();
    const controller: AgentController = { email: 'agent@aida.example', dns: 'agent.example.com' };
    const doc = createIdentityDocument(kp, { controller });

    expect(doc.controller).toEqual(controller);
  });

  it('should include the publicKey block with correct type and base58', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const doc = createIdentityDocument(kp, { controller });

    expect(doc.publicKey.type).toBe('Ed25519VerificationKey2020');
    expect(doc.publicKey.publicKeyBase58).toBe(encodeBase58(kp.publicKey));
  });

  it('should set a created timestamp in ISO 8601 format', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const before = new Date().toISOString();
    const doc = createIdentityDocument(kp, { controller });
    const after = new Date().toISOString();

    expect(doc.created).toBeTruthy();
    expect(doc.created >= before).toBe(true);
    expect(doc.created <= after).toBe(true);
    // Should parse as valid ISO date
    expect(() => new Date(doc.created)).not.toThrow();
    expect(new Date(doc.created).toISOString()).toBe(doc.created);
  });

  it('should include optional fields when provided', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const endpoints = [
      { url: 'https://agent.example.com/mcp', protocol: 'mcp' as const },
    ];
    const capabilities = ['text-generation', 'tool-use'];

    const doc = createIdentityDocument(kp, { controller, endpoints, capabilities });

    expect(doc.endpoints).toEqual(endpoints);
    expect(doc.capabilities).toEqual(capabilities);
  });

  it('should not include optional fields when not provided', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const doc = createIdentityDocument(kp, { controller });

    expect(doc.endpoints).toBeUndefined();
    expect(doc.capabilities).toBeUndefined();
    expect(doc.soulHash).toBeUndefined();
    expect(doc.verification).toBeUndefined();
    expect(doc.updated).toBeUndefined();
    expect(doc.expires).toBeUndefined();
  });

  it('should self-sign the document (proof present)', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const doc = createIdentityDocument(kp, { controller });

    expect(doc.proof).toBeDefined();
    expect(doc.proof!.type).toBe('Ed25519Signature2020');
    expect(doc.proof!.created).toBeTruthy();
    expect(doc.proof!.proofValue).toBeTruthy();
    expect(typeof doc.proof!.proofValue).toBe('string');
    expect(doc.proof!.verificationMethod).toBe(`${doc.id}#publicKey`);
  });

  it('should produce a valid self-signature that verifies', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const doc = createIdentityDocument(kp, { controller });

    expect(verifyIdentityDocument(doc)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// signIdentityDocument
// ---------------------------------------------------------------------------

describe('signIdentityDocument', () => {
  it('should add a proof to an unsigned document', () => {
    const kp = makeKeypair();
    const controller = makeController();

    // Create an unsigned document manually
    const unsigned: IdentityDocument = {
      id: `aida:${encodeBase58(kp.publicKey)}`,
      controller,
      publicKey: {
        type: 'Ed25519VerificationKey2020',
        publicKeyBase58: encodeBase58(kp.publicKey),
      },
      created: new Date().toISOString(),
    };

    const signed = signIdentityDocument(unsigned, kp.privateKey);

    expect(signed.proof).toBeDefined();
    expect(signed.proof!.type).toBe('Ed25519Signature2020');
    expect(signed.proof!.proofValue).toBeTruthy();
    expect(signed.proof!.verificationMethod).toBe(`${unsigned.id}#publicKey`);
    expect(signed.proof!.created).toBeTruthy();
  });

  it('should produce a document that passes verification', () => {
    const kp = makeKeypair();
    const controller = makeController();

    const unsigned: IdentityDocument = {
      id: `aida:${encodeBase58(kp.publicKey)}`,
      controller,
      publicKey: {
        type: 'Ed25519VerificationKey2020',
        publicKeyBase58: encodeBase58(kp.publicKey),
      },
      created: new Date().toISOString(),
    };

    const signed = signIdentityDocument(unsigned, kp.privateKey);
    expect(verifyIdentityDocument(signed)).toBe(true);
  });

  it('should overwrite an existing proof', () => {
    const kp = makeKeypair();
    const controller = makeController();

    const unsigned: IdentityDocument = {
      id: `aida:${encodeBase58(kp.publicKey)}`,
      controller,
      publicKey: {
        type: 'Ed25519VerificationKey2020',
        publicKeyBase58: encodeBase58(kp.publicKey),
      },
      created: new Date().toISOString(),
      proof: {
        type: 'Ed25519Signature2020',
        created: '2000-01-01T00:00:00.000Z',
        proofValue: 'bogus',
        verificationMethod: 'aida:bogus#publicKey',
      },
    };

    const signed = signIdentityDocument(unsigned, kp.privateKey);
    expect(signed.proof!.created).not.toBe('2000-01-01T00:00:00.000Z');
    expect(signed.proof!.proofValue).not.toBe('bogus');
    expect(verifyIdentityDocument(signed)).toBe(true);
  });

  it('should produce deterministic signatures (same input → same proof)', () => {
    const kp = makeKeypair();
    const controller = makeController();

    const unsigned: IdentityDocument = {
      id: `aida:${encodeBase58(kp.publicKey)}`,
      controller,
      publicKey: {
        type: 'Ed25519VerificationKey2020',
        publicKeyBase58: encodeBase58(kp.publicKey),
      },
      created: '2025-01-01T00:00:00.000Z',
    };

    const signed1 = signIdentityDocument(unsigned, kp.privateKey);
    const signed2 = signIdentityDocument(unsigned, kp.privateKey);

    expect(signed1.proof!.proofValue).toBe(signed2.proof!.proofValue);
  });
});

// ---------------------------------------------------------------------------
// verifyIdentityDocument
// ---------------------------------------------------------------------------

describe('verifyIdentityDocument', () => {
  it('should return true for a valid self-signed document', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const doc = createIdentityDocument(kp, { controller });

    expect(verifyIdentityDocument(doc)).toBe(true);
  });

  it('should return false when proof is missing', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const doc = createIdentityDocument(kp, { controller });

    // Remove proof
    const noProof = cloneDocument(doc);
    delete noProof.proof;

    expect(verifyIdentityDocument(noProof)).toBe(false);
  });

  it('should return false when proof type is not Ed25519Signature2020', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const doc = createIdentityDocument(kp, { controller });

    const wrongType = cloneDocument(doc);
    wrongType.proof!.type = 'RsaSignature2018' as unknown as 'Ed25519Signature2020';

    expect(verifyIdentityDocument(wrongType)).toBe(false);
  });

  it('should return false when the document has been tampered (changed controller)', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const doc = createIdentityDocument(kp, { controller });

    const tampered = cloneDocument(doc);
    tampered.controller = { email: 'attacker@evil.com' };

    expect(verifyIdentityDocument(tampered)).toBe(false);
  });

  it('should return false when the document id is changed', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const doc = createIdentityDocument(kp, { controller });

    const tampered = cloneDocument(doc);
    tampered.id = 'aida:EvilAttackerKey';

    expect(verifyIdentityDocument(tampered)).toBe(false);
  });

  it('should return false when publicKey is changed', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const doc = createIdentityDocument(kp, { controller });

    const tampered = cloneDocument(doc);
    tampered.publicKey.publicKeyBase58 = encodeBase58(makeKeypair().publicKey);

    expect(verifyIdentityDocument(tampered)).toBe(false);
  });

  it('should return false when created timestamp is changed', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const doc = createIdentityDocument(kp, { controller });

    const tampered = cloneDocument(doc);
    tampered.created = '2000-01-01T00:00:00.000Z';

    expect(verifyIdentityDocument(tampered)).toBe(false);
  });

  it('should return false when capabilities are tampered', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const doc = createIdentityDocument(kp, { controller, capabilities: ['text-generation'] });

    const tampered = cloneDocument(doc);
    tampered.capabilities = ['evil-capability'];

    expect(verifyIdentityDocument(tampered)).toBe(false);
  });

  it('should return false when proofValue itself is tampered', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const doc = createIdentityDocument(kp, { controller });

    const tampered = cloneDocument(doc);
    tampered.proof!.proofValue = 'deadbeef';

    expect(verifyIdentityDocument(tampered)).toBe(false);
  });

  it('should return false when proof.verificationMethod is changed', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const doc = createIdentityDocument(kp, { controller });

    const tampered = cloneDocument(doc);
    tampered.proof!.verificationMethod = 'aida:attacker#publicKey';

    expect(verifyIdentityDocument(tampered)).toBe(false);
  });

  it('should return false for a document signed with a different key', () => {
    const kp1 = makeKeypair();
    const kp2 = makeKeypair();
    const controller = makeController();

    // Create a document with kp2's public key but signed by kp1
    const unsigned: IdentityDocument = {
      id: `aida:${encodeBase58(kp2.publicKey)}`,
      controller,
      publicKey: {
        type: 'Ed25519VerificationKey2020',
        publicKeyBase58: encodeBase58(kp2.publicKey),
      },
      created: new Date().toISOString(),
    };

    // Sign with the wrong key
    const signed = signIdentityDocument(unsigned, kp1.privateKey);

    // The proof claims kp2 (via verificationMethod) but was signed with kp1
    expect(verifyIdentityDocument(signed)).toBe(false);
  });

  it('should return false when publicKey type is not Ed25519VerificationKey2020', () => {
    const kp = makeKeypair();
    const controller = makeController();
    const doc = createIdentityDocument(kp, { controller });

    const wrongType = cloneDocument(doc);
    wrongType.publicKey.type = 'RsaVerificationKey2018' as unknown as 'Ed25519VerificationKey2020';

    expect(verifyIdentityDocument(wrongType)).toBe(false);
  });
});
