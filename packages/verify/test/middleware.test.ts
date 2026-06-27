/**
 * Tests for the AIDA verification middleware.
 *
 * Covers: createMiddleware with all VerifyOptions combinations.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

// @noble/ed25519 v2 requires SHA-512 to be configured for synchronous usage.
ed25519.etc.sha512Sync = sha512;

import type { Request, Response, NextFunction } from 'express';
import type {
  IdentityDocument,
  AgentController,
  AgentPurpose,
  VerifyOptions,
} from '../src/types';
import { encodeBase58, publicKeyToAidaUri } from '../src/utils';
import { computeContentDigest, buildSignatureBase } from './helpers/signing-helpers';

// Module under test
import { createMiddleware } from '../src/middleware';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

function makeController(overrides: Partial<AgentController> = {}): AgentController {
  return { email: 'test@example.com', ...overrides };
}

function makeSignedIdentityDoc(
  kp: ReturnType<typeof makeKeypair>,
  controller: AgentController,
): IdentityDocument {
  const unsigned: IdentityDocument = {
    id: publicKeyToAidaUri(kp.publicKey),
    controller,
    publicKey: {
      type: 'Ed25519VerificationKey2020',
      publicKeyBase58: encodeBase58(kp.publicKey),
    },
    created: new Date().toISOString(),
  };

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

  const payload: Record<string, unknown> = {};
  const keys = Object.keys(unsigned)
    .filter((k) => k !== 'proof')
    .sort();
  for (const key of keys) {
    const value = (unsigned as unknown as Record<string, unknown>)[key];
    if (value !== undefined) payload[key] = value;
  }

  const canonicalPayload = canonicalize(payload);
  const payloadBytes = new TextEncoder().encode(canonicalPayload);
  const signature = ed25519.sign(payloadBytes, kp.privateKey);
  const proofValue = Buffer.from(signature).toString('base64');

  return {
    ...unsigned,
    proof: {
      type: 'Ed25519Signature2020',
      created: new Date().toISOString(),
      proofValue,
      verificationMethod: `${unsigned.id}#publicKey`,
    },
  };
}

/**
 * Sign an HTTP request and return headers.
 */
function signHttpRequest(
  method: string,
  path: string,
  authority: string,
  kp: ReturnType<typeof makeKeypair>,
  agentId: string,
  body?: string,
  purpose?: AgentPurpose,
): { headers: Record<string, string> } {
  const contentDigest = computeContentDigest(body);
  const components: Array<{ identifier: string; value: string }> = [
    { identifier: '"@method"', value: method },
    { identifier: '"@path"', value: path },
    { identifier: '"@authority"', value: authority },
    { identifier: '"content-digest"', value: contentDigest },
    { identifier: '"aida-agent"', value: agentId },
  ];

  if (purpose !== undefined) {
    components.push({ identifier: '"aida-purpose"', value: purpose });
  }

  const identifiers = components.map((c) => c.identifier);
  const signatureBase = buildSignatureBase(components);
  const signatureBaseBytes = new TextEncoder().encode(signatureBase);

  const created = Math.floor(Date.now() / 1000);
  const signature = ed25519.sign(signatureBaseBytes, kp.privateKey);
  const signatureBase64 = Buffer.from(signature).toString('base64');

  const identifierList = identifiers.join(' ');
  const signatureInput = `sig1=(${identifierList});keyid="${agentId}";created=${created};alg="ed25519"`;

  const signatureHeader = `sig1=:${signatureBase64}:`;

  return {
    headers: {
      'Aida-Agent': agentId,
      'Content-Digest': contentDigest,
      'Signature-Input': signatureInput,
      'Signature': signatureHeader,
      ...(purpose ? { 'Aida-Purpose': purpose } : {}),
    },
  };
}

/**
 * Create a mock Express Request object.
 */
function mockRequest(overrides: Partial<Request> = {}): Request {
  const headers: Record<string, string | string[] | undefined> = {};

  const req = {
    method: 'GET',
    path: '/',
    originalUrl: '/',
    hostname: 'localhost',
    header: vi.fn((name: string) => {
      const val = headers[name.toLowerCase()];
      return Array.isArray(val) ? val[0] : val;
    }),
    get: vi.fn((name: string) => {
      return headers[name.toLowerCase()];
    }),
    headers: headers as any,
    aida: undefined,
    ...overrides,
  } as unknown as Request;

  return req;
}

/**
 * Create a mock Express Response object.
 */
function mockResponse(): Response {
  const res = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
    send: vi.fn().mockReturnThis(),
    end: vi.fn().mockReturnThis(),
    setHeader: vi.fn(),
    getHeader: vi.fn(),
    headersSent: false,
  } as unknown as Response;
  return res;
}

/**
 * Helper: apply headers from a Record to the mock request's internal storage
 */
function setHeaders(req: Request, headers: Record<string, string>): void {
  for (const [key, value] of Object.entries(headers)) {
    (req.headers as Record<string, string | string[] | undefined>)[key.toLowerCase()] = value;
  }
  // Also set on the raw object for get()/header() to find
  for (const [key, value] of Object.entries(headers)) {
    (req as any)[key.toLowerCase()] = value;
  }
}

// ---------------------------------------------------------------------------
// Tests: createMiddleware
// ---------------------------------------------------------------------------

describe('createMiddleware', () => {
  let kp: ReturnType<typeof makeKeypair>;
  let agentId: string;
  let next: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    kp = makeKeypair();
    agentId = publicKeyToAidaUri(kp.publicKey);
    next = vi.fn();
  });

  // -----------------------------------------------------------------------
  // Missing Aida-Agent header
  // -----------------------------------------------------------------------

  it('should populate req.aida with unverified result when Aida-Agent is missing and not required', async () => {
    const middleware = createMiddleware({ required: false });
    const req = mockRequest({ method: 'GET', path: '/api/data' });
    const res = mockResponse();

    await middleware(req, res, next);

    expect(req.aida).toBeDefined();
    expect(req.aida!.verified).toBe(false);
    expect(req.aida!.agentId).toBe('aida:unknown');
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('should return 401 when Aida-Agent is missing and required=true', async () => {
    const middleware = createMiddleware({ required: true });
    const req = mockRequest({ method: 'GET', path: '/api/data' });
    const res = mockResponse();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  // -----------------------------------------------------------------------
  // Missing Signature-Input or Signature headers
  // -----------------------------------------------------------------------

  it('should set error when Signature-Input header is missing', async () => {
    const middleware = createMiddleware();
    const req = mockRequest({ method: 'POST', path: '/api/test' });
    const res = mockResponse();
    setHeaders(req, { 'Aida-Agent': agentId, 'Signature': 'sig1=:AAAA:' });

    await middleware(req, res, next);

    expect(req.aida).toBeDefined();
    expect(req.aida!.verified).toBe(false);
    expect(req.aida!.error).toContain('Signature-Input');
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('should 401 when Signature-Input is missing and required=true', async () => {
    const middleware = createMiddleware({ required: true });
    const req = mockRequest({ method: 'POST', path: '/api/test' });
    const res = mockResponse();
    setHeaders(req, { 'Aida-Agent': agentId, 'Signature': 'sig1=:AAAA:' });

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  // -----------------------------------------------------------------------
  // Valid headers
  // -----------------------------------------------------------------------

  it('should verify a valid request and populate req.aida with verified=true', async () => {
    const middleware = createMiddleware();
    const req = mockRequest({
      method: 'POST',
      path: '/api/data',
      originalUrl: '/api/data',
      hostname: 'example.com',
    });
    const res = mockResponse();

    const signed = signHttpRequest(
      'POST',
      '/api/data',
      'example.com',
      kp,
      agentId,
      '{"hello":"world"}',
    );
    setHeaders(req, signed.headers);

    await middleware(req, res, next);

    expect(req.aida).toBeDefined();
    expect(req.aida!.verified).toBe(true);
    expect(req.aida!.agentId).toBe(agentId);
    expect(req.aida!.error).toBeUndefined();
    expect(req.aida!.metadata).toBeDefined();
    expect(req.aida!.metadata!.verifiedAt).toBeTruthy();
    expect(next).toHaveBeenCalled();
  });

  it('should verify a GET request successfully', async () => {
    const middleware = createMiddleware();
    const req = mockRequest({
      method: 'GET',
      path: '/api/status',
      originalUrl: '/api/status',
      hostname: 'example.com',
    });
    const res = mockResponse();

    const signed = signHttpRequest('GET', '/api/status', 'example.com', kp, agentId);
    setHeaders(req, signed.headers);

    await middleware(req, res, next);

    expect(req.aida!.verified).toBe(true);
    expect(next).toHaveBeenCalled();
  });

  it('should verify a request with path including query string', async () => {
    const middleware = createMiddleware();
    const req = mockRequest({
      method: 'GET',
      path: '/api/search?q=hello&page=1',
      originalUrl: '/api/search?q=hello&page=1',
      hostname: 'example.com',
    });
    const res = mockResponse();

    const signed = signHttpRequest('GET', '/api/search?q=hello&page=1', 'example.com', kp, agentId);
    setHeaders(req, signed.headers);

    await middleware(req, res, next);

    expect(req.aida!.verified).toBe(true);
  });

  // -----------------------------------------------------------------------
  // Invalid signature
  // -----------------------------------------------------------------------

  it('should set error when signature is tampered', async () => {
    const middleware = createMiddleware();
    const req = mockRequest({
      method: 'POST',
      path: '/api/data',
      originalUrl: '/api/data',
      hostname: 'example.com',
    });
    const res = mockResponse();

    const signed = signHttpRequest('POST', '/api/data', 'example.com', kp, agentId, 'original body');
    const tamperedHeaders = { ...signed.headers };
    tamperedHeaders['Signature'] = 'sig1=:AAAA:';
    setHeaders(req, tamperedHeaders);

    await middleware(req, res, next);

    expect(req.aida!.verified).toBe(false);
    expect(req.aida!.error).toBeDefined();
    expect(next).toHaveBeenCalled();
  });

  it('should set error when wrong key signs the request', async () => {
    const middleware = createMiddleware();
    const otherKp = makeKeypair();
    const req = mockRequest({
      method: 'POST',
      path: '/api/data',
      originalUrl: '/api/data',
      hostname: 'example.com',
    });
    const res = mockResponse();

    // Sign with a different key from the one in agentId
    const signed = signHttpRequest('POST', '/api/data', 'example.com', otherKp, agentId, 'body');
    setHeaders(req, signed.headers);

    await middleware(req, res, next);

    expect(req.aida!.verified).toBe(false);
    expect(req.aida!.error).toBeDefined();
  });

  // -----------------------------------------------------------------------
  // allowedControllers
  // -----------------------------------------------------------------------

  it('should pass when controller matches allowedControllers', async () => {
    const controller = makeController({ email: 'allowed@test.com' });
    const idDoc = makeSignedIdentityDoc(kp, controller);

    const middleware = createMiddleware({
      allowedControllers: [controller],
      getIdentityDocument: async () => idDoc,
    });

    const req = mockRequest({
      method: 'POST',
      path: '/api/data',
      originalUrl: '/api/data',
      hostname: 'example.com',
    });
    const res = mockResponse();

    const signed = signHttpRequest('POST', '/api/data', 'example.com', kp, agentId, 'body');
    setHeaders(req, signed.headers);

    await middleware(req, res, next);

    expect(req.aida!.verified).toBe(true);
    expect(next).toHaveBeenCalled();
  });

  it('should 403 when controller does not match allowedControllers', async () => {
    const allowedController = makeController({ email: 'allowed@test.com' });
    const actualController = makeController({ email: 'attacker@evil.com' });
    const idDoc = makeSignedIdentityDoc(kp, actualController);

    const middleware = createMiddleware({
      allowedControllers: [allowedController],
      getIdentityDocument: async () => idDoc,
    });

    const req = mockRequest({
      method: 'POST',
      path: '/api/data',
      originalUrl: '/api/data',
      hostname: 'example.com',
    });
    const res = mockResponse();

    const signed = signHttpRequest('POST', '/api/data', 'example.com', kp, agentId, 'body');
    setHeaders(req, signed.headers);

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  it('should match allowedControllers by any controller field (email, did, dns, oauth)', async () => {
    const controller = makeController({ dns: 'agent.example.com' });
    const idDoc = makeSignedIdentityDoc(kp, controller);

    const middleware = createMiddleware({
      allowedControllers: [{ dns: 'agent.example.com' }],
      getIdentityDocument: async () => idDoc,
    });

    const req = mockRequest({
      method: 'POST',
      path: '/api/data',
      originalUrl: '/api/data',
      hostname: 'example.com',
    });
    const res = mockResponse();

    const signed = signHttpRequest('POST', '/api/data', 'example.com', kp, agentId, 'body');
    setHeaders(req, signed.headers);

    await middleware(req, res, next);

    expect(req.aida!.verified).toBe(true);
  });

  // -----------------------------------------------------------------------
  // Custom getPublicKey
  // -----------------------------------------------------------------------

  it('should call custom getPublicKey with correct keyid', async () => {
    const getPublicKey = vi.fn().mockResolvedValue(kp.publicKey);

    const middleware = createMiddleware({ getPublicKey });

    const req = mockRequest({
      method: 'POST',
      path: '/api/data',
      originalUrl: '/api/data',
      hostname: 'example.com',
    });
    const res = mockResponse();

    const signed = signHttpRequest('POST', '/api/data', 'example.com', kp, agentId, 'body');
    setHeaders(req, signed.headers);

    await middleware(req, res, next);

    expect(getPublicKey).toHaveBeenCalledWith(agentId);
    expect(req.aida!.verified).toBe(true);
  });

  it('should default to aidaUriToPublicKey when no custom getPublicKey is provided', async () => {
    const middleware = createMiddleware();

    const req = mockRequest({
      method: 'POST',
      path: '/api/data',
      originalUrl: '/api/data',
      hostname: 'example.com',
    });
    const res = mockResponse();

    const signed = signHttpRequest('POST', '/api/data', 'example.com', kp, agentId, 'body');
    setHeaders(req, signed.headers);

    await middleware(req, res, next);

    // Should still verify because public key is extracted from the URI itself
    expect(req.aida!.verified).toBe(true);
  });

  it('should set error when custom getPublicKey throws', async () => {
    const getPublicKey = vi.fn().mockRejectedValue(new Error('Key not found'));

    const middleware = createMiddleware({ getPublicKey });

    const req = mockRequest({
      method: 'POST',
      path: '/api/data',
      originalUrl: '/api/data',
      hostname: 'example.com',
    });
    const res = mockResponse();

    const signed = signHttpRequest('POST', '/api/data', 'example.com', kp, agentId, 'body');
    setHeaders(req, signed.headers);

    await middleware(req, res, next);

    expect(req.aida!.verified).toBe(false);
    expect(req.aida!.error).toContain('Key not found');
    expect(next).toHaveBeenCalled();
  });

  // -----------------------------------------------------------------------
  // Purpose extraction
  // -----------------------------------------------------------------------

  it('should extract purpose from Aida-Purpose header', async () => {
    const middleware = createMiddleware();

    const req = mockRequest({
      method: 'POST',
      path: '/api/query',
      originalUrl: '/api/query',
      hostname: 'agent.example.com',
    });
    const res = mockResponse();

    const signed = signHttpRequest(
      'POST',
      '/api/query',
      'agent.example.com',
      kp,
      agentId,
      '{"query":"test"}',
      'inference',
    );
    setHeaders(req, signed.headers);

    await middleware(req, res, next);

    expect(req.aida!.verified).toBe(true);
    expect(req.aida!.purpose).toBe('inference');
  });

  it('should not set purpose when not present', async () => {
    const middleware = createMiddleware();

    const req = mockRequest({
      method: 'POST',
      path: '/api/data',
      originalUrl: '/api/data',
      hostname: 'example.com',
    });
    const res = mockResponse();

    const signed = signHttpRequest('POST', '/api/data', 'example.com', kp, agentId, 'body');
    setHeaders(req, signed.headers);

    await middleware(req, res, next);

    expect(req.aida!.purpose).toBeUndefined();
  });

  // -----------------------------------------------------------------------
  // Identity document verification
  // -----------------------------------------------------------------------

  it('should verify identity document when getIdentityDocument is provided', async () => {
    const controller = makeController();
    const idDoc = makeSignedIdentityDoc(kp, controller);
    const getIdentityDocument = vi.fn().mockResolvedValue(idDoc);

    const middleware = createMiddleware({ getIdentityDocument });

    const req = mockRequest({
      method: 'POST',
      path: '/api/data',
      originalUrl: '/api/data',
      hostname: 'example.com',
    });
    const res = mockResponse();

    const signed = signHttpRequest('POST', '/api/data', 'example.com', kp, agentId, 'body');
    setHeaders(req, signed.headers);

    await middleware(req, res, next);

    expect(getIdentityDocument).toHaveBeenCalledWith(agentId);
    expect(req.aida!.verified).toBe(true);
    expect(req.aida!.controller).toEqual(controller);
    expect(req.aida!.metadata!.identityResolved).toBe(true);
    expect(req.aida!.metadata!.identityVerified).toBe(true);
  });

  it('should handle null identity document (not found)', async () => {
    const getIdentityDocument = vi.fn().mockResolvedValue(null);

    const middleware = createMiddleware({ getIdentityDocument });

    const req = mockRequest({
      method: 'POST',
      path: '/api/data',
      originalUrl: '/api/data',
      hostname: 'example.com',
    });
    const res = mockResponse();

    const signed = signHttpRequest('POST', '/api/data', 'example.com', kp, agentId, 'body');
    setHeaders(req, signed.headers);

    await middleware(req, res, next);

    // Signature still verifies, but identity doc was not resolved
    expect(req.aida!.verified).toBe(true);
    expect(req.aida!.metadata!.identityResolved).toBe(false);
  });

  it('should set identityVerified=false when identity document fails verification', async () => {
    const controller = makeController();
    const idDoc = makeSignedIdentityDoc(kp, controller);
    // Tamper the document
    idDoc.controller = { email: 'evil@hacker.com' };
    const getIdentityDocument = vi.fn().mockResolvedValue(idDoc);

    const middleware = createMiddleware({ getIdentityDocument });

    const req = mockRequest({
      method: 'POST',
      path: '/api/data',
      originalUrl: '/api/data',
      hostname: 'example.com',
    });
    const res = mockResponse();

    const signed = signHttpRequest('POST', '/api/data', 'example.com', kp, agentId, 'body');
    setHeaders(req, signed.headers);

    await middleware(req, res, next);

    // Signature verification passes (it's separate from doc verification)
    expect(req.aida!.verified).toBe(true);
    expect(req.aida!.metadata!.identityResolved).toBe(true);
    expect(req.aida!.metadata!.identityVerified).toBe(false);
    expect(req.aida!.error).toContain('identity document');
    expect(next).toHaveBeenCalled();
  });

  // -----------------------------------------------------------------------
  // Clock skew
  // -----------------------------------------------------------------------

  it('should accept signature within clockSkew tolerance', async () => {
    const middleware = createMiddleware({ clockSkew: 7200 }); // 2 hours

    const req = mockRequest({
      method: 'POST',
      path: '/api/data',
      originalUrl: '/api/data',
      hostname: 'example.com',
    });
    const res = mockResponse();

    // Create a signature with an old created timestamp
    const contentDigest = computeContentDigest('data');
    const components: Array<{ identifier: string; value: string }> = [
      { identifier: '"@method"', value: 'POST' },
      { identifier: '"@path"', value: '/api/data' },
      { identifier: '"@authority"', value: 'example.com' },
      { identifier: '"content-digest"', value: contentDigest },
      { identifier: '"aida-agent"', value: agentId },
    ];
    const identifiers = components.map((c) => c.identifier);
    const signatureBase = buildSignatureBase(components);
    const signatureBaseBytes = new TextEncoder().encode(signatureBase);

    const oldCreated = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
    const signature = ed25519.sign(signatureBaseBytes, kp.privateKey);
    const signatureBase64 = Buffer.from(signature).toString('base64');

    const headers = {
      'Aida-Agent': agentId,
      'Content-Digest': contentDigest,
      'Signature-Input': `sig1=(${identifiers.join(' ')});keyid="${agentId}";created=${oldCreated};alg="ed25519"`,
      'Signature': `sig1=:${signatureBase64}:`,
    };
    setHeaders(req, headers);

    await middleware(req, res, next);

    expect(req.aida!.verified).toBe(true);
  });

  // -----------------------------------------------------------------------
  // Edge cases
  // -----------------------------------------------------------------------

  it('should handle lowercase and mixed-case header names', async () => {
    const middleware = createMiddleware();

    const req = mockRequest({
      method: 'POST',
      path: '/api/data',
      originalUrl: '/api/data',
      hostname: 'example.com',
    });
    const res = mockResponse();

    const signed = signHttpRequest('POST', '/api/data', 'example.com', kp, agentId, 'body');
    // Convert all headers to lowercase
    const lowerHeaders: Record<string, string> = {};
    for (const [key, value] of Object.entries(signed.headers)) {
      lowerHeaders[key.toLowerCase()] = value;
    }
    setHeaders(req, lowerHeaders);

    await middleware(req, res, next);

    expect(req.aida!.verified).toBe(true);
  });

  it('should pass through errors in req.aida without blocking', async () => {
    const middleware = createMiddleware();

    const req = mockRequest({
      method: 'POST',
      path: '/api/data',
      originalUrl: '/api/data',
      hostname: 'example.com',
    });
    const res = mockResponse();

    // Malformed signature input
    setHeaders(req, {
      'Aida-Agent': agentId,
      'Signature-Input': 'not-valid',
      'Signature': 'sig1=:AAAA:',
    });

    await middleware(req, res, next);

    // Should not 401 - errors go into req.aida.error
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
    expect(req.aida!.verified).toBe(false);
    expect(req.aida!.error).toBeDefined();
  });

  it('should set publicKey in the verification result', async () => {
    const middleware = createMiddleware();

    const req = mockRequest({
      method: 'POST',
      path: '/api/data',
      originalUrl: '/api/data',
      hostname: 'example.com',
    });
    const res = mockResponse();

    const signed = signHttpRequest('POST', '/api/data', 'example.com', kp, agentId, 'body');
    setHeaders(req, signed.headers);

    await middleware(req, res, next);

    expect(req.aida!.publicKey).toBeDefined();
    expect(req.aida!.publicKey).toEqual(kp.publicKey);
  });
});
