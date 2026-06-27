/**
 * AIDA Verify SDK — Express middleware for agent identity verification.
 *
 * Provides `createMiddleware` — an Express-compatible middleware that
 * verifies AIDA agent identities on incoming HTTP requests using
 * RFC 9421 HTTP Message Signatures and optional identity document
 * resolution.
 *
 * @module middleware
 */

import type { Request, Response, NextFunction } from 'express';
import type {
  AidaUri,
  AgentController,
  AgentPurpose,
  IdentityDocument,
  VerificationResult,
  VerifyOptions,
} from './types';
import { aidaUriToPublicKey } from './utils';
import { verifySignature, extractKeyId, extractPurpose } from './rfc9421';
import {
  verifyIdentityDocument,
  createVerificationResult,
} from './verification';

// ---------------------------------------------------------------------------
// Header extraction helpers
// ---------------------------------------------------------------------------

/**
 * Extract an HTTP header value case-insensitively from an Express request.
 *
 * Uses `req.get()` which handles case-insensitive lookup per RFC 7230.
 *
 * @param req - The Express request object.
 * @param name - The header name.
 * @returns The header value, or `undefined` if not present.
 */
function getRequestHeader(req: Request, name: string): string | undefined {
  const value = req.get(name);
  if (value === undefined || value === null) {
    return undefined;
  }
  return value;
}

// ---------------------------------------------------------------------------
// Controller matching
// ---------------------------------------------------------------------------

/**
 * Check whether an agent's controller matches one of the allowed controllers.
 *
 * A match occurs when any field (`did`, `email`, `dns`, `oauth`) matches
 * between the agent's controller and one of the allowed controllers. This
 * allows flexible matching — e.g., allowing an agent if its email matches
 * even if its DNS does not.
 *
 * @param agentController - The controller from the agent's identity document.
 * @param allowedControllers - The list of allowed controllers from options.
 * @returns `true` if the agent's controller matches at least one allowed controller.
 */
function matchesController(
  agentController: AgentController,
  allowedControllers: AgentController[],
): boolean {
  return allowedControllers.some((allowed) => {
    const fields: (keyof AgentController)[] = ['did', 'email', 'dns', 'oauth'];
    for (const field of fields) {
      const agentValue = agentController[field];
      const allowedValue = allowed[field];

      if (agentValue !== undefined && allowedValue !== undefined) {
        if (agentValue === allowedValue) {
          return true;
        }
      }
    }
    return false;
  });
}

// ---------------------------------------------------------------------------
// createMiddleware
// ---------------------------------------------------------------------------

/**
 * Create an Express middleware that verifies AIDA agent identities.
 *
 * The middleware extracts identity headers (`Aida-Agent`, `Signature-Input`,
 * `Signature`) from the request, verifies the RFC 9421 HTTP Message Signature,
 * optionally resolves and verifies an identity document, and populates
 * `req.aida` with a {@link VerificationResult}.
 *
 * In **optional** mode (default), verification errors are captured in
 * `req.aida.error` and the request proceeds to the next handler. This allows
 * handlers to treat unverified requests as anonymous or degraded.
 *
 * In **required** mode (`required: true`), failed verification returns a
 * `401 Unauthorized` response and the request is not passed to the next
 * handler.
 *
 * When `allowedControllers` is configured and the resolved controller
 * does not match, a `403 Forbidden` is returned regardless of the
 * `required` flag.
 *
 * @param options - Verification options (see {@link VerifyOptions}).
 * @returns An Express middleware function.
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { createMiddleware } from '@aida/verify';
 *
 * const app = express();
 * app.use(createMiddleware({ required: true }));
 *
 * app.get('/api/data', (req, res) => {
 *   if (req.aida?.verified) {
 *     res.json({ agent: req.aida.agentId });
 *   } else {
 *     res.status(401).json({ error: 'Unauthorized' });
 *   }
 * });
 * ```
 */
export function createMiddleware(
  options: VerifyOptions = {},
): (req: Request, res: Response, next: NextFunction) => Promise<void> {
  const {
    required = false,
    allowedControllers,
    clockSkew = 300,
    getPublicKey,
    getIdentityDocument,
  } = options;

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    // -------------------------------------------------------------------
    // 1. Extract Aida-Agent header
    // -------------------------------------------------------------------
    const aidaAgent = getRequestHeader(req, 'Aida-Agent');

    if (!aidaAgent) {
      if (required) {
        res.status(401).json({ error: 'Missing Aida-Agent header' });
        return;
      }

      // Optional mode: populate unverified result and continue
      req.aida = createVerificationResult('aida:unknown' as AidaUri, false, undefined, undefined, {
        error: 'Missing Aida-Agent header',
      });
      next();
      return;
    }

    const agentId = aidaAgent as AidaUri;

    // -------------------------------------------------------------------
    // 2. Extract Signature-Input header
    // -------------------------------------------------------------------
    const signatureInputHeader = getRequestHeader(req, 'Signature-Input');

    if (!signatureInputHeader) {
      const error = 'Missing Signature-Input header';
      if (required) {
        res.status(401).json({ error });
        return;
      }
      req.aida = createVerificationResult(agentId, false, undefined, undefined, { error });
      next();
      return;
    }

    // -------------------------------------------------------------------
    // 3. Extract Signature header
    // -------------------------------------------------------------------
    const signatureHeader = getRequestHeader(req, 'Signature');

    if (!signatureHeader) {
      const error = 'Missing Signature header';
      if (required) {
        res.status(401).json({ error });
        return;
      }
      req.aida = createVerificationResult(agentId, false, undefined, undefined, { error });
      next();
      return;
    }

    // -------------------------------------------------------------------
    // 4. Extract keyid from Signature-Input
    // -------------------------------------------------------------------
    const keyid = extractKeyId(signatureInputHeader);

    if (!keyid) {
      const error = 'Could not extract keyid from Signature-Input header';
      if (required) {
        res.status(401).json({ error });
        return;
      }
      req.aida = createVerificationResult(agentId, false, undefined, undefined, { error });
      next();
      return;
    }

    // -------------------------------------------------------------------
    // 5. Resolve public key
    // -------------------------------------------------------------------
    let publicKey: Uint8Array;

    try {
      if (getPublicKey) {
        publicKey = await getPublicKey(keyid);
      } else {
        publicKey = aidaUriToPublicKey(keyid);
      }
    } catch (err) {
      const error = `Failed to resolve public key: ${String(err)}`;
      if (required) {
        res.status(401).json({ error });
        return;
      }
      req.aida = createVerificationResult(agentId, false, undefined, undefined, { error });
      next();
      return;
    }

    // -------------------------------------------------------------------
    // 6. Verify RFC 9421 signature
    // -------------------------------------------------------------------
    const headers: Record<string, string> = {};

    // Collect all relevant headers from the request for signature verification
    // Express normalizes header names in req.headers to lowercase
    if (req.headers) {
      for (const [key, value] of Object.entries(req.headers)) {
        if (typeof value === 'string') {
          headers[key.toLowerCase()] = value;
        } else if (Array.isArray(value) && value.length > 0 && typeof value[0] === 'string') {
          headers[key.toLowerCase()] = value[0];
        }
      }
    }

    const authority = req.hostname || 'unknown';
    const path = req.originalUrl || req.path || '/';
    const method = req.method || 'POST';

    const sigResult = verifySignature(headers, publicKey, {
      clockSkew,
      method,
      path,
      authority,
    });

    // Extract signedAt from the signature input for metadata
    let signedAt: number | undefined;
    const createdMatch = signatureInputHeader.match(/created=(\d+)/);
    if (createdMatch && createdMatch[1]) {
      signedAt = parseInt(createdMatch[1], 10);
    }

    if (!sigResult.valid) {
      const error = sigResult.error ?? 'Signature verification failed';
      if (required) {
        res.status(401).json({ error });
        return;
      }
      const failOptions: {
        error: string;
        publicKey: Uint8Array;
        signedAt?: number;
      } = { error, publicKey };
      if (signedAt !== undefined) {
        failOptions.signedAt = signedAt;
      }
      req.aida = createVerificationResult(agentId, false, undefined, undefined, failOptions);
      next();
      return;
    }

    // -------------------------------------------------------------------
    // 7. Resolve identity document (optional)
    // -------------------------------------------------------------------
    let identityDoc: IdentityDocument | null = null;
    let identityResolved = false;
    let identityVerified: boolean | undefined;

    if (getIdentityDocument) {
      try {
        identityDoc = await getIdentityDocument(keyid);
        identityResolved = identityDoc !== null;
      } catch {
        identityResolved = false;
      }
    }

    // -------------------------------------------------------------------
    // 8. Verify identity document signature
    // -------------------------------------------------------------------
    let controller: AgentController | undefined;

    if (identityDoc) {
      const docVerifyResult = verifyIdentityDocument(identityDoc, { clockSkew });
      identityVerified = docVerifyResult.valid;

      if (docVerifyResult.valid) {
        controller = identityDoc.controller;
      } else {
        // Identity document verification failed, but signature is still valid.
        // We continue but record the failure.
      }
    }

    // -------------------------------------------------------------------
    // 9. Check allowedControllers
    // -------------------------------------------------------------------
    if (allowedControllers && allowedControllers.length > 0) {
      if (!controller) {
        // No controller resolved — cannot match allowed controllers
        res.status(403).json({ error: 'No controller resolved: cannot verify against allowed controllers' });
        return;
      }

      if (!matchesController(controller, allowedControllers)) {
        res.status(403).json({ error: 'Agent controller not in allowed controllers list' });
        return;
      }
    }

    // -------------------------------------------------------------------
    // 10. Extract purpose
    // -------------------------------------------------------------------
    const purpose = extractPurpose(signatureInputHeader, headers) ?? undefined;

    // -------------------------------------------------------------------
    // 11. Populate req.aida with VerificationResult
    // -------------------------------------------------------------------
    const errorMessage = identityVerified === false
      ? 'Signature valid but identity document verification failed'
      : undefined;

    const successOptions: {
      publicKey: Uint8Array;
      error?: string;
      identityResolved: boolean;
      identityVerified?: boolean;
      signedAt?: number;
    } = { publicKey, identityResolved };
    if (errorMessage !== undefined) {
      successOptions.error = errorMessage;
    }
    if (identityVerified !== undefined) {
      successOptions.identityVerified = identityVerified;
    }
    if (signedAt !== undefined) {
      successOptions.signedAt = signedAt;
    }
    req.aida = createVerificationResult(agentId, true, controller, purpose ?? undefined, successOptions);

    // -------------------------------------------------------------------
    // 12. Call next()
    // -------------------------------------------------------------------
    next();
  };
}
