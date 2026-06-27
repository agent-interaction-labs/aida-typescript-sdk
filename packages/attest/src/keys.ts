/**
 * AIDA Agent SDK — Keypair management.
 *
 * Ed25519 key generation, serialization (base58), and filesystem persistence.
 */
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import * as fs from 'node:fs';
import * as path from 'node:path';

// @noble/ed25519 v2 requires SHA-512 to be configured for synchronous usage.
ed25519.etc.sha512Sync = sha512;

import type { AgentKeypair } from './types';
import { encodeBase58, decodeBase58 } from './utils';

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/**
 * Generate a fresh Ed25519 keypair.
 *
 * Returns an {@link AgentKeypair} with 32-byte `publicKey` and `privateKey`.
 */
export function generateKeypair(): AgentKeypair {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/** The shape stored on disk and passed over the wire. */
export interface SerializedKeypair {
  publicKey: string;
  privateKey: string;
}

/**
 * Serialize an {@link AgentKeypair} to plain base58 strings.
 *
 * The result is safe to JSON-stringify.
 */
export function serializeKeypair(keypair: AgentKeypair): SerializedKeypair {
  return {
    publicKey: encodeBase58(keypair.publicKey),
    privateKey: encodeBase58(keypair.privateKey),
  };
}

/**
 * Deserialize base58-encoded keys back into an {@link AgentKeypair}.
 *
 * @throws If either key is not valid base58, or does not decode to 32 bytes.
 */
export function deserializeKeypair(data: SerializedKeypair): AgentKeypair {
  let publicKey: Uint8Array;
  let privateKey: Uint8Array;

  try {
    publicKey = decodeBase58(data.publicKey);
  } catch (cause) {
    throw new Error(
      `Failed to decode publicKey as base58: ${String(cause)}`,
      { cause },
    );
  }

  try {
    privateKey = decodeBase58(data.privateKey);
  } catch (cause) {
    throw new Error(
      `Failed to decode privateKey as base58: ${String(cause)}`,
      { cause },
    );
  }

  if (publicKey.length !== 32) {
    throw new Error(
      `Invalid publicKey size: expected 32 bytes, got ${publicKey.length}`,
    );
  }

  if (privateKey.length !== 32) {
    throw new Error(
      `Invalid privateKey size: expected 32 bytes, got ${privateKey.length}`,
    );
  }

  return { publicKey, privateKey };
}

// ---------------------------------------------------------------------------
// Filesystem persistence
// ---------------------------------------------------------------------------

/**
 * Save an {@link AgentKeypair} to a JSON file.
 *
 * Keys are serialized as base58 strings. Parent directories are created
 * automatically if they do not exist.
 *
 * @throws On any I/O error (permissions, path is a directory, etc.).
 */
export function saveKeypair(keypair: AgentKeypair, filePath: string): void {
  const serialized = serializeKeypair(keypair);
  const dir = path.dirname(filePath);

  fs.mkdirSync(dir, { recursive: true });

  // Use writeFileSync with an explicit flag so that attempting to write to a
  // directory or other non-file entity produces a clear system error.
  fs.writeFileSync(filePath, JSON.stringify(serialized, null, 2) + '\n', {
    encoding: 'utf-8',
    flag: 'w',
  });
}

/**
 * Load an {@link AgentKeypair} from a JSON file previously written by
 * {@link saveKeypair}.
 *
 * @throws If the file does not exist, contains invalid JSON, or the stored
 *         keys are malformed.
 */
export function loadKeypair(filePath: string): AgentKeypair {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf-8');
  } catch (cause) {
    const nodeErr = cause as NodeJS.ErrnoException;
    if (nodeErr.code === 'ENOENT') {
      throw new Error(
        `Keypair file not found: ${filePath}`,
        { cause },
      );
    }
    throw new Error(
      `Failed to read keypair file: ${String(cause)}`,
      { cause },
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (cause) {
    throw new Error(
      `Keypair file contains invalid JSON: ${String(cause)}`,
      { cause },
    );
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('Keypair file does not contain a JSON object');
  }

  const obj = parsed as Record<string, unknown>;

  if (typeof obj.publicKey !== 'string') {
    throw new Error('Keypair file is missing required field: publicKey');
  }
  if (typeof obj.privateKey !== 'string') {
    throw new Error('Keypair file is missing required field: privateKey');
  }

  return deserializeKeypair({
    publicKey: obj.publicKey,
    privateKey: obj.privateKey,
  });
}

/**
 * Check whether a keypair file exists at the given path.
 *
 * Returns `false` for missing files, directories, and other non-file entities
 * without throwing.
 */
export function keypairExists(filePath: string): boolean {
  try {
    const stat = fs.statSync(filePath);
    return stat.isFile();
  } catch {
    return false;
  }
}
