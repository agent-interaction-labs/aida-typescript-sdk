/**
 * AIDA Verify SDK — RFC 9421 HTTP Message Signature Verification.
 *
 * Implements signature verification for AIDA agent-authenticated requests.
 * Parses Signature-Input and Signature headers, reconstructs the signature
 * base from covered components, and verifies Ed25519 signatures.
 */

import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

// @noble/ed25519 v2 requires SHA-512 to be configured for synchronous usage.
ed25519.etc.sha512Sync = sha512;

import type { AgentPurpose } from './types';

// ---------------------------------------------------------------------------
// Header parsing helpers
// ---------------------------------------------------------------------------

/**
 * Find a header value case-insensitively.
 * HTTP header names are case-insensitive per RFC 7230.
 */
function getHeader(headers: Record<string, string>, name: string): string | undefined {
  const lowerName = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lowerName) {
      return value;
    }
  }
  return undefined;
}

/**
 * Parse a single SFV (Structured Field Value) parameter from a semicolon-delimited string.
 * Handles both key=value and key="value" forms.
 */
function parseSfvParam(param: string): { key: string; value: string } | null {
  const eqIdx = param.indexOf('=');
  if (eqIdx === -1) return null;

  const key = param.slice(0, eqIdx).trim();
  let value = param.slice(eqIdx + 1).trim();

  // Unquote string values
  if (value.startsWith('"') && value.endsWith('"')) {
    value = value.slice(1, -1);
  }

  return { key, value };
}

/**
 * Parse the covered components list from a Signature-Input header.
 * Example: `sig1=("@method" "@path" "@authority");keyid="aida:..."` → ["@method", "@path", "@authority"]
 */
function parseCoveredComponents(signatureInput: string): string[] | null {
  const match = signatureInput.match(/sig1=\s*\((.*?)\)/);
  if (!match || !match[1]) return null;

  const inner = match[1];
  // Extract quoted identifiers
  const identifiers: string[] = [];
  const quotedRe = /"([^"]+)"/g;
  let m;
  while ((m = quotedRe.exec(inner)) !== null) {
    identifiers.push(m[1]!);
  }

  return identifiers.length > 0 ? identifiers : null;
}

/**
 * Parse all parameters from a Signature-Input header (after the initial `sig1=(...)`).
 */
function parseSignatureInputParams(signatureInput: string): Map<string, string> {
  const params = new Map<string, string>();

  // Find everything after the closing paren
  const parenClose = signatureInput.indexOf(')');
  if (parenClose === -1) return params;

  const paramsStr = signatureInput.slice(parenClose + 1);

  // Split by semicolons, handling quoted values
  const parts = paramsStr.split(';').filter((p) => p.trim().length > 0);

  for (const part of parts) {
    const parsed = parseSfvParam(part.trim());
    if (parsed) {
      params.set(parsed.key, parsed.value);
    }
  }

  return params;
}

/**
 * Parse the signature value from a Signature header.
 * Example: `sig1=:base64value:` → Uint8Array
 */
function parseSignature(signatureHeader: string): Uint8Array | null {
  // Match sig1=:<base64>:
  const match = signatureHeader.match(/^sig1=:(.+):$/);
  if (!match || !match[1]) return null;

  try {
    return Buffer.from(match[1], 'base64');
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Signature base reconstruction
// ---------------------------------------------------------------------------

/**
 * Encode a component value for the signature base.
 * Binary values (containing `=:`) are colon-wrapped.
 */
function encodeComponentValue(value: string): string {
  if (value.includes('=:')) {
    return `:${value}:`;
  }
  return value;
}

/**
 * Determine the value of a named component for signature base reconstruction.
 *
 * @param componentName - The uncovered component name (without quotes).
 * @param headers - The request headers.
 * @param method - The HTTP method (from caller context).
 * @param path - The request path + query string (from caller context).
 * @param authority - The request authority (from caller context).
 * @returns The component value, or null if it cannot be determined.
 */
function getComponentValue(
  componentName: string,
  headers: Record<string, string>,
  method: string,
  path: string,
  authority: string,
): string | null {
  // Derived components (@-prefixed)
  switch (componentName) {
    case '@method':
      return method;
    case '@path':
      return path;
    case '@authority':
      return authority;
    default:
      break;
  }

  // HTTP header components (case-insensitive lookup)
  const value = getHeader(headers, componentName);
  return value ?? null;
}

/**
 * Reconstruct the RFC 9421 signature base from the signature input and
 * request context.
 */
function reconstructSignatureBase(
  coveredComponents: string[],
  headers: Record<string, string>,
  method: string,
  path: string,
  authority: string,
): string | null {
  const lines: string[] = [];

  for (const componentName of coveredComponents) {
    const value = getComponentValue(componentName, headers, method, path, authority);
    if (value === null) {
      return null; // Cannot reconstruct — missing required component
    }

    const encoded = encodeComponentValue(value);
    lines.push(`"${componentName}": ${encoded}`);
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Options for signature verification.
 */
export interface VerifySignatureOptions {
  /**
   * Maximum clock skew tolerance in seconds for the signature `created` timestamp.
   * Default: 300 (5 minutes).
   */
  clockSkew?: number;

  /**
   * HTTP method override. If not provided, the verify function cannot
   * reconstruct the @method component, unless the caller provides it.
   *
   * When called from middleware, this is typically req.method.
   */
  method?: string;

  /**
   * Request path override (pathname + query string). Required to
   * reconstruct the @path component.
   *
   * When called from middleware, this is typically req.originalUrl or req.path.
   */
  path?: string;

  /**
   * Request authority override (host). Required to reconstruct the
   * @authority component.
   *
   * When called from middleware, this is typically req.hostname or req.get('host').
   */
  authority?: string;
}

/**
 * Verify an RFC 9421 HTTP Message Signature for an AIDA agent request.
 *
 * Parses the `Signature-Input` and `Signature` headers, reconstructs the
 * signature base from the covered components and request context, and
 * verifies the Ed25519 signature against the provided public key.
 *
 * Supports the following covered components:
 * - `@method` — HTTP method (provided via options or derived)
 * - `@path` — request path + query string
 * - `@authority` — hostname[:port]
 * - `content-digest` — from Content-Digest header
 * - `aida-agent` — from Aida-Agent header
 * - `aida-purpose` — from Aida-Purpose header
 *
 * @param headers - The HTTP request headers (keys are case-insensitive).
 * @param publicKey - The Ed25519 public key for the agent (32 bytes).
 * @param options - Additional verification options including clock skew and request context.
 * @returns A result object with `valid` boolean and optional `error` string.
 */
export function verifySignature(
  headers: Record<string, string>,
  publicKey: Uint8Array,
  options: VerifySignatureOptions = {},
): { valid: boolean; error?: string } {
  const { clockSkew = 300, method, path, authority } = options;

  // Extract required headers
  const signatureInputHeader = getHeader(headers, 'Signature-Input');
  const signatureHeader = getHeader(headers, 'Signature');

  if (!signatureInputHeader) {
    return { valid: false, error: 'Missing Signature-Input header' };
  }

  if (!signatureHeader) {
    return { valid: false, error: 'Missing Signature header' };
  }

  // Parse the signature
  const signatureBytes = parseSignature(signatureHeader);
  if (!signatureBytes) {
    return { valid: false, error: 'Malformed Signature header: could not parse base64 signature' };
  }

  // Parse covered components
  const coveredComponents = parseCoveredComponents(signatureInputHeader);
  if (!coveredComponents) {
    return { valid: false, error: 'Malformed Signature-Input header: could not parse covered components' };
  }

  // Parse parameters
  const params = parseSignatureInputParams(signatureInputHeader);

  // Check algorithm
  const alg = params.get('alg');
  if (alg !== 'ed25519') {
    return { valid: false, error: `Unsupported algorithm: expected ed25519, got ${alg ?? 'none'}` };
  }

  // Check created timestamp
  const createdStr = params.get('created');
  if (createdStr) {
    const created = parseInt(createdStr, 10);
    if (isNaN(created)) {
      return { valid: false, error: 'Invalid created timestamp in Signature-Input' };
    }
    const now = Math.floor(Date.now() / 1000);

    if (created > now + clockSkew) {
      return { valid: false, error: 'Signature created timestamp is in the future' };
    }

    if (created < now - clockSkew) {
      return { valid: false, error: 'Signature has expired' };
    }
  }

  // Determine request context for @-derived components
  const resolvedMethod = method ?? 'POST'; // default if not provided
  const resolvedPath = path ?? '/';
  const resolvedAuthority = authority ?? 'unknown';

  // Reconstruct the signature base
  const signatureBase = reconstructSignatureBase(
    coveredComponents,
    headers,
    resolvedMethod,
    resolvedPath,
    resolvedAuthority,
  );

  if (!signatureBase) {
    return { valid: false, error: 'Could not reconstruct signature base: missing covered component value' };
  }

  // Verify the Ed25519 signature
  const signatureBaseBytes = new TextEncoder().encode(signatureBase);

  try {
    const valid = ed25519.verify(signatureBytes, signatureBaseBytes, publicKey);
    if (!valid) {
      return { valid: false, error: 'Ed25519 signature verification failed' };
    }
    return { valid: true };
  } catch (err) {
    return { valid: false, error: `Signature verification error: ${String(err)}` };
  }
}

/**
 * Extract the `keyid` from a Signature-Input header.
 *
 * Parses the SFV parameters from the Signature-Input header and returns
 * the value of the `keyid` parameter.
 *
 * @param signatureInputHeader - The value of the Signature-Input header.
 * @returns The keyid (AIDA URI), or `null` if not present or unparseable.
 */
export function extractKeyId(signatureInputHeader: string): string | null {
  if (!signatureInputHeader || signatureInputHeader.trim().length === 0) {
    return null;
  }

  // Find the keyid parameter after the closing paren
  const parenClose = signatureInputHeader.indexOf(')');
  if (parenClose === -1) return null;

  const paramsStr = signatureInputHeader.slice(parenClose + 1);

  // Look for keyid="<value>"
  const keyidMatch = paramsStr.match(/keyid="([^"]+)"/);
  if (keyidMatch && keyidMatch[1]) {
    return keyidMatch[1];
  }

  // Also try keyid=<value> (unquoted)
  const keyidUnquotedMatch = paramsStr.match(/keyid=([^;]+)/);
  if (keyidUnquotedMatch && keyidUnquotedMatch[1]) {
    return keyidUnquotedMatch[1].trim();
  }

  return null;
}

/**
 * Extract the purpose from a Signature-Input header, if present.
 *
 * Scans the covered components for an `aida-purpose` identifier and
 * returns its value from the corresponding request header.
 *
 * @param signatureInputHeader - The value of the Signature-Input header.
 * @param headers - The request headers (for looking up Aida-Purpose).
 * @returns The purpose string, or `null` if not present.
 */
export function extractPurpose(
  signatureInputHeader: string,
  headers: Record<string, string>,
): AgentPurpose | null {
  const coveredComponents = parseCoveredComponents(signatureInputHeader);
  if (!coveredComponents || !coveredComponents.includes('aida-purpose')) {
    return null;
  }

  const purposeValue = getHeader(headers, 'aida-purpose');
  if (!purposeValue) return null;

  // Validate it's one of the known purposes
  const validPurposes: readonly AgentPurpose[] = ['inference', 'task', 'crawler', 'monitoring'];
  if ((validPurposes as readonly string[]).includes(purposeValue)) {
    return purposeValue as AgentPurpose;
  }

  return null;
}
