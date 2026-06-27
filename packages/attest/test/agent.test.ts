/**
 * Tests for the agent module.
 *
 * Covers: createAgent, loadAgent.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

ed25519.etc.sha512Sync = sha512;

import { createAgent, loadAgent } from '../src/agent';
import { keypairExists } from '../src/keys';
import type { AidaAgentState, IdentityDocument } from '../src/types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aida-agent-test-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function keyFile(name: string): string {
  return path.join(tmpDir, name);
}

// ---------------------------------------------------------------------------
// createAgent
// ---------------------------------------------------------------------------

describe('createAgent', () => {
  it('should create an agent with a valid keypair and identity document', async () => {
    const agent = await createAgent({
      controller: { email: 'test@example.com' },
    });

    expect(agent).toBeDefined();
    expect(agent.keypair).toBeDefined();
    expect(agent.keypair.publicKey).toBeInstanceOf(Uint8Array);
    expect(agent.keypair.privateKey).toBeInstanceOf(Uint8Array);
    expect(agent.keypair.publicKey).toHaveLength(32);
    expect(agent.keypair.privateKey).toHaveLength(32);
    expect(agent.identity).toBeDefined();
    expect(agent.identity.id).toMatch(/^aida:/);
    expect(agent.identity.controller.email).toBe('test@example.com');
    expect(agent.identity.publicKey.type).toBe('Ed25519VerificationKey2020');
    expect(agent.identity.proof).toBeDefined();
    expect(agent.identity.proof!.type).toBe('Ed25519Signature2020');
  });

  it('should save the keypair when storagePath is provided', async () => {
    const kpPath = keyFile('agent-keypair.json');

    const agent = await createAgent({
      controller: { email: 'test@example.com' },
      storagePath: kpPath,
    });

    expect(agent.storagePath).toBe(kpPath);
    expect(keypairExists(kpPath)).toBe(true);

    // Verify the stored keypair matches
    const savedRaw = JSON.parse(fs.readFileSync(kpPath, 'utf-8'));
    expect(typeof savedRaw.publicKey).toBe('string');
    expect(typeof savedRaw.privateKey).toBe('string');
  });

  it('should return state with a bound signRequest that works', async () => {
    const agent = await createAgent({
      controller: { email: 'test@example.com' },
    });

    expect(agent.signRequest).toBeDefined();
    expect(typeof agent.signRequest).toBe('function');

    const signed = await agent.signRequest('https://example.com/api', {
      method: 'GET',
    });

    expect(signed.url).toBe('https://example.com/api');
    expect(signed.method).toBe('GET');
    expect(signed.headers['Aida-Agent']).toBe(agent.identity.id);
    expect(signed.headers['Signature']).toBeDefined();
    expect(signed.headers['Signature-Input']).toBeDefined();
  });

  it('should return state with a bound signRequest that includes body and purpose', async () => {
    const agent = await createAgent({
      controller: { email: 'test@example.com' },
    });

    const signed = await agent.signRequest('https://example.com/api', {
      method: 'POST',
      body: '{"key":"value"}',
      purpose: 'inference',
    });

    expect(signed.body).toBe('{"key":"value"}');
    expect(signed.headers['Signature-Input']).toContain('"aida-purpose"');
  });

  it('should return state with a bound regenerate method', async () => {
    const agent = await createAgent({
      controller: { email: 'test@example.com' },
    });

    expect(agent.regenerate).toBeDefined();
    expect(typeof agent.regenerate).toBe('function');

    const newIdentity = await agent.regenerate();
    expect(newIdentity).toBeDefined();
    expect(newIdentity.id).toBe(agent.identity.id);
    expect(newIdentity.proof).toBeDefined();
    expect(newIdentity.proof!.type).toBe('Ed25519Signature2020');
  });

  it('should throw if keypair already exists at storagePath', async () => {
    const kpPath = keyFile('existing.json');

    // Create first agent
    await createAgent({
      controller: { email: 'first@example.com' },
      storagePath: kpPath,
    });

    // Attempt to create second agent at same path
    await expect(
      createAgent({
        controller: { email: 'second@example.com' },
        storagePath: kpPath,
      }),
    ).rejects.toThrow(/already exists|existing/i);
  });

  it('should create agent with endpoints and capabilities', async () => {
    const agent = await createAgent({
      controller: { email: 'test@example.com' },
      endpoints: [{ url: 'https://example.com/mcp', protocol: 'mcp' }],
      capabilities: ['inference', 'search'],
    });

    expect(agent.identity.endpoints).toBeDefined();
    expect(agent.identity.endpoints).toHaveLength(1);
    expect(agent.identity.endpoints![0]!.url).toBe('https://example.com/mcp');
    expect(agent.identity.capabilities).toBeDefined();
    expect(agent.identity.capabilities).toContain('inference');
    expect(agent.identity.capabilities).toContain('search');
  });

  it('should create agent without storagePath (no persistence)', async () => {
    const agent = await createAgent({
      controller: { email: 'test@example.com' },
      // no storagePath
    });

    expect(agent.storagePath).toBeUndefined();
    expect(agent.keypair).toBeDefined();
    expect(agent.identity).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// loadAgent
// ---------------------------------------------------------------------------

describe('loadAgent', () => {
  it('should round-trip through createAgent with storage', async () => {
    const kpPath = keyFile('roundtrip.json');

    const created = await createAgent({
      controller: { email: 'roundtrip@example.com' },
      endpoints: [{ url: 'https://example.com/api', protocol: 'aixa' }],
      capabilities: ['task'],
      storagePath: kpPath,
    });

    const loaded = await loadAgent(kpPath);

    // Keypair should match exactly
    expect(loaded.keypair.publicKey).toEqual(created.keypair.publicKey);
    expect(loaded.keypair.privateKey).toEqual(created.keypair.privateKey);

    // Identity document identifiers should match
    expect(loaded.identity.id).toBe(created.identity.id);
    expect(loaded.identity.publicKey.publicKeyBase58).toBe(
      created.identity.publicKey.publicKeyBase58,
    );

    // Controller should match
    expect(loaded.identity.controller.email).toBe('roundtrip@example.com');

    // Endpoints and capabilities should be reconstructed
    expect(loaded.identity.endpoints).toBeDefined();
    expect(loaded.identity.endpoints![0]!.url).toBe('https://example.com/api');

    expect(loaded.identity.capabilities).toBeDefined();
    expect(loaded.identity.capabilities).toContain('task');

    // Proof should be present and valid
    expect(loaded.identity.proof).toBeDefined();
    expect(loaded.identity.proof!.type).toBe('Ed25519Signature2020');

    // Storage path should be set
    expect(loaded.storagePath).toBe(kpPath);
  });

  it('should return a working signRequest after loading', async () => {
    const kpPath = keyFile('load-sign.json');

    await createAgent({
      controller: { email: 'signer@example.com' },
      storagePath: kpPath,
    });

    const loaded = await loadAgent(kpPath);

    const signed = await loaded.signRequest('https://example.com/api', {
      method: 'POST',
      body: 'loaded and signing',
    });

    expect(signed.headers['Aida-Agent']).toBe(loaded.identity.id);
    expect(signed.headers['Signature']).toBeDefined();
    expect(signed.body).toBe('loaded and signing');
  });

  it('should return a working regenerate after loading', async () => {
    const kpPath = keyFile('load-regen.json');

    await createAgent({
      controller: { email: 'regen@example.com' },
      storagePath: kpPath,
    });

    const loaded = await loadAgent(kpPath);

    const regenerated = await loaded.regenerate();
    expect(regenerated.id).toBe(loaded.identity.id);
    expect(regenerated.proof).toBeDefined();
  });

  it('should throw when file does not exist', async () => {
    const nonexistent = keyFile('does-not-exist.json');

    await expect(loadAgent(nonexistent)).rejects.toThrow(
      /not found|ENOENT|no such file|exist/i,
    );
  });

  it('should throw when file contains corrupt data', async () => {
    const kpPath = keyFile('corrupt.json');
    fs.writeFileSync(kpPath, 'this is not valid json {{{');

    await expect(loadAgent(kpPath)).rejects.toThrow();
  });

  it('should throw when keypair file is missing publicKey field', async () => {
    const kpPath = keyFile('missing-pub.json');
    fs.writeFileSync(
      kpPath,
      JSON.stringify({
        privateKey: '11111111111111111111111111111111',
      }),
    );

    await expect(loadAgent(kpPath)).rejects.toThrow();
  });

  it('should throw when keypair file is missing privateKey field', async () => {
    const kpPath = keyFile('missing-priv.json');
    fs.writeFileSync(
      kpPath,
      JSON.stringify({
        publicKey: '11111111111111111111111111111111',
      }),
    );

    await expect(loadAgent(kpPath)).rejects.toThrow();
  });

  it('should produce different agents when loaded from different paths', async () => {
    const path1 = keyFile('agent1.json');
    const path2 = keyFile('agent2.json');

    await createAgent({
      controller: { email: 'one@example.com' },
      storagePath: path1,
    });

    await createAgent({
      controller: { email: 'two@example.com' },
      storagePath: path2,
    });

    const loaded1 = await loadAgent(path1);
    const loaded2 = await loadAgent(path2);

    expect(loaded1.identity.id).not.toBe(loaded2.identity.id);
    expect(loaded1.identity.controller.email).toBe('one@example.com');
    expect(loaded2.identity.controller.email).toBe('two@example.com');
  });
});
