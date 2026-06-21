/**
 * Tests for the keys module.
 *
 * Covers: generateKeypair, saveKeypair, loadKeypair, keypairExists,
 * serializeKeypair, deserializeKeypair.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

import {
  generateKeypair,
  saveKeypair,
  loadKeypair,
  keypairExists,
  serializeKeypair,
  deserializeKeypair,
} from '../src/keys';

import type { AgentKeypair } from '../src/types';
import { encodeBase58, decodeBase58 } from '../src/utils';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aida-keys-test-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function keyFile(name: string): string {
  return path.join(tmpDir, name);
}

function corruptJson(keyPath: string): void {
  fs.writeFileSync(keyPath, 'this is not valid json {{{');
}

function writeRawFile(keyPath: string, data: unknown): void {
  fs.writeFileSync(keyPath, JSON.stringify(data));
}

// ---------------------------------------------------------------------------
// generateKeypair
// ---------------------------------------------------------------------------

describe('generateKeypair', () => {
  it('should produce valid 32-byte publicKey and privateKey', () => {
    const kp = generateKeypair();
    expect(kp).toBeDefined();
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.privateKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey).toHaveLength(32);
    expect(kp.privateKey).toHaveLength(32);
  });

  it('should produce different keypairs on successive calls', () => {
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    // Both keys should differ — extremely unlikely chance of collision
    expect(kp1.publicKey).not.toEqual(kp2.publicKey);
    expect(kp1.privateKey).not.toEqual(kp2.privateKey);
  });

  it('should produce a public key that corresponds to its private key', () => {
    // The public key MUST be derivable from the private key.
    // We import @noble/ed25519 directly for this verification.
    // (We do *not* test the underlying library; we test that we wired it correctly.)
    const { getPublicKey } = require('@noble/ed25519');
    const kp = generateKeypair();
    const derivedPub = getPublicKey(kp.privateKey);
    expect(kp.publicKey).toEqual(derivedPub);
  });
});

// ---------------------------------------------------------------------------
// serializeKeypair / deserializeKeypair
// ---------------------------------------------------------------------------

describe('serializeKeypair', () => {
  it('should produce valid base58 strings for both keys', () => {
    const kp = generateKeypair();
    const serialized = serializeKeypair(kp);
    expect(typeof serialized.publicKey).toBe('string');
    expect(typeof serialized.privateKey).toBe('string');
    // Round-trip through base58 decoder to verify they are real base58
    expect(() => decodeBase58(serialized.publicKey)).not.toThrow();
    expect(() => decodeBase58(serialized.privateKey)).not.toThrow();
  });

  it('should produce 32-byte arrays when decoded back from the serialized strings', () => {
    const kp = generateKeypair();
    const serialized = serializeKeypair(kp);
    const decodedPub = decodeBase58(serialized.publicKey);
    const decodedPriv = decodeBase58(serialized.privateKey);
    expect(decodedPub).toHaveLength(32);
    expect(decodedPriv).toHaveLength(32);
  });
});

describe('deserializeKeypair', () => {
  it('should round-trip through serialize', () => {
    const original = generateKeypair();
    const serialized = serializeKeypair(original);
    const deserialized = deserializeKeypair(serialized);
    expect(deserialized.publicKey).toEqual(original.publicKey);
    expect(deserialized.privateKey).toEqual(original.privateKey);
  });

  it('should throw when publicKey is not a valid base58 string', () => {
    expect(() =>
      deserializeKeypair({ publicKey: '!!!!', privateKey: encodeBase58(new Uint8Array(32)) }),
    ).toThrow();
  });

  it('should throw when privateKey is not a valid base58 string', () => {
    expect(() =>
      deserializeKeypair({ publicKey: encodeBase58(new Uint8Array(32)), privateKey: '!!!!' }),
    ).toThrow();
  });

  it('should throw when publicKey decodes to wrong size', () => {
    const tooShort = encodeBase58(new Uint8Array(16));
    const valid32 = encodeBase58(new Uint8Array(32));
    expect(() =>
      deserializeKeypair({ publicKey: tooShort, privateKey: valid32 }),
    ).toThrow(/publicKey.*(32|size|bytes|invalid)/i);
  });

  it('should throw when privateKey decodes to wrong size', () => {
    const valid32 = encodeBase58(new Uint8Array(32));
    const tooShort = encodeBase58(new Uint8Array(16));
    expect(() =>
      deserializeKeypair({ publicKey: valid32, privateKey: tooShort }),
    ).toThrow(/privateKey.*(32|size|bytes|invalid)/i);
  });

  it('should throw when publicKey decodes to 33 bytes', () => {
    const tooLong = encodeBase58(new Uint8Array(33));
    const valid32 = encodeBase58(new Uint8Array(32));
    expect(() =>
      deserializeKeypair({ publicKey: tooLong, privateKey: valid32 }),
    ).toThrow(/publicKey.*(32|size|bytes|invalid)/i);
  });

  it('should throw when privateKey decodes to 33 bytes', () => {
    const valid32 = encodeBase58(new Uint8Array(32));
    const tooLong = encodeBase58(new Uint8Array(33));
    expect(() =>
      deserializeKeypair({ publicKey: valid32, privateKey: tooLong }),
    ).toThrow(/privateKey.*(32|size|bytes|invalid)/i);
  });
});

// ---------------------------------------------------------------------------
// saveKeypair / loadKeypair / keypairExists
// ---------------------------------------------------------------------------

describe('saveKeypair', () => {
  it('should save a JSON file with base58-encoded keys', () => {
    const kp = generateKeypair();
    const kpPath = keyFile('test-keypair.json');
    saveKeypair(kp, kpPath);

    expect(fs.existsSync(kpPath)).toBe(true);

    const raw = JSON.parse(fs.readFileSync(kpPath, 'utf-8'));
    expect(typeof raw.publicKey).toBe('string');
    expect(typeof raw.privateKey).toBe('string');
    // Verify decoded sizes
    expect(decodeBase58(raw.publicKey)).toHaveLength(32);
    expect(decodeBase58(raw.privateKey)).toHaveLength(32);
  });

  it('should create parent directories if they do not exist', () => {
    const kp = generateKeypair();
    const deepPath = path.join(tmpDir, 'deep', 'nested', 'dir', 'keypair.json');
    saveKeypair(kp, deepPath);
    expect(fs.existsSync(deepPath)).toBe(true);
  });

  it('should throw when path points to a directory', () => {
    const kp = generateKeypair();
    const dirPath = keyFile('adir');
    fs.mkdirSync(dirPath);
    expect(() => saveKeypair(kp, dirPath)).toThrow();
  });
});

describe('loadKeypair', () => {
  it('should round-trip through saveKeypair', () => {
    const original = generateKeypair();
    const kpPath = keyFile('roundtrip.json');
    saveKeypair(original, kpPath);
    const loaded = loadKeypair(kpPath);
    expect(loaded.publicKey).toEqual(original.publicKey);
    expect(loaded.privateKey).toEqual(original.privateKey);
  });

  it('should throw when file does not exist', () => {
    const nonexistent = keyFile('does-not-exist.json');
    expect(() => loadKeypair(nonexistent)).toThrow(/ENOENT|no such file|not found|exist/i);
  });

  it('should throw when file contains corrupt JSON', () => {
    const kpPath = keyFile('corrupt.json');
    corruptJson(kpPath);
    expect(() => loadKeypair(kpPath)).toThrow();
  });

  it('should throw when JSON is missing publicKey field', () => {
    const kpPath = keyFile('missing-pub.json');
    writeRawFile(kpPath, { privateKey: encodeBase58(new Uint8Array(32)) });
    expect(() => loadKeypair(kpPath)).toThrow();
  });

  it('should throw when JSON is missing privateKey field', () => {
    const kpPath = keyFile('missing-priv.json');
    writeRawFile(kpPath, { publicKey: encodeBase58(new Uint8Array(32)) });
    expect(() => loadKeypair(kpPath)).toThrow();
  });

  it('should throw when stored publicKey is not valid base58', () => {
    const kpPath = keyFile('bad-pub.json');
    writeRawFile(kpPath, {
      publicKey: '!!!!',
      privateKey: encodeBase58(new Uint8Array(32)),
    });
    expect(() => loadKeypair(kpPath)).toThrow();
  });

  it('should throw when stored privateKey is not valid base58', () => {
    const kpPath = keyFile('bad-priv.json');
    writeRawFile(kpPath, {
      publicKey: encodeBase58(new Uint8Array(32)),
      privateKey: '!!!!',
    });
    expect(() => loadKeypair(kpPath)).toThrow();
  });

  it('should throw when stored publicKey decodes to wrong size', () => {
    const kpPath = keyFile('wrong-size-pub.json');
    writeRawFile(kpPath, {
      publicKey: encodeBase58(new Uint8Array(16)),
      privateKey: encodeBase58(new Uint8Array(32)),
    });
    expect(() => loadKeypair(kpPath)).toThrow(/publicKey.*(32|size|bytes|invalid)/i);
  });

  it('should throw when stored privateKey decodes to wrong size', () => {
    const kpPath = keyFile('wrong-size-priv.json');
    writeRawFile(kpPath, {
      publicKey: encodeBase58(new Uint8Array(32)),
      privateKey: encodeBase58(new Uint8Array(16)),
    });
    expect(() => loadKeypair(kpPath)).toThrow(/privateKey.*(32|size|bytes|invalid)/i);
  });
});

describe('keypairExists', () => {
  it('should return true after saveKeypair', () => {
    const kp = generateKeypair();
    const kpPath = keyFile('exists-test.json');
    expect(keypairExists(kpPath)).toBe(false);
    saveKeypair(kp, kpPath);
    expect(keypairExists(kpPath)).toBe(true);
  });

  it('should return false for a nonexistent file (no throw)', () => {
    const nonexistent = keyFile('never-created.json');
    expect(keypairExists(nonexistent)).toBe(false);
  });

  it('should return false for a directory', () => {
    const dirPath = keyFile('a-directory');
    fs.mkdirSync(dirPath);
    expect(keypairExists(dirPath)).toBe(false);
  });
});
