/**
 * AIDA Agent SDK — RFC 9421 HTTP Request Signing.
 *
 * Implements HTTP Message Signatures (RFC 9421) for agent-authenticated requests.
 * Signs requests with Ed25519 and produces the Aida-Agent, Signature, and
 * Signature-Input headers required by the AIDA protocol.
 */
import * as ed25519 from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { Buffer } from 'node:buffer';
import type { SignedRequest, SignRequestOptions, AgentPurpose } from './types';

// ---------------------------------------------------------------------------
// Content Digest
// ---------------------------------------------------------------------------

/**
 * Compute the content-digest of a request body per RFC 9421.
 *
 * Returns `sha-256=:<base64-sha256>:` for the given body string.
 * When body is `undefined`, returns the digest of an empty string.
 *
 * @param body - The request body string, or `undefined` for an empty body.
 * @returns The content-digest string in the format `sha-256=:<base64>:`.
 */
export function computeContentDigest(body?: string): string {
  const data = new TextEncoder().encode(body ?? '');
  const hash = sha256(data);
  const base64 = Buffer.from(hash).toString('base64');
  return `sha-256=:${base64}:`;
}

// ---------------------------------------------------------------------------
// Signature Base Construction
// ---------------------------------------------------------------------------

/**
 * A signature base component — an identifier and its value.
 *
 * The identifier is already formatted with surrounding quotes (e.g. `"@method"`).
 * The value is the raw component value before encoding.
 */
interface SignatureBaseComponent {
  /** The component identifier with surrounding quotes, e.g. `"@method"` */
  identifier: string;
  /** The raw component value (before RFC 9421 encoding) */
  value: string;
}

/**
 * Build the RFC 9421 signature base string from an array of components.
 *
 * Each component is emitted on its own line in the format:
 * ```
 * "<identifier>": <value>
 * ```
 *
 * Values are serialized per RFC 9421:
 * - String values appear as-is (e.g. `"@method": POST`).
 * - Binary values (content-digest, etc.) are colon-wrapped
 *   base64 (e.g. `"content-digest": :sha-256=:abc123:=:`).
 *
 * Determining whether a value is binary: values that contain
 * `=:` (digest format) are treated as binary and colon-wrapped.
 *
 * @param components - Array of {@link SignatureBaseComponent} pairs.
 * @returns The RFC 9421 signature base string.
 */
export function buildSignatureBase(components: ReadonlyArray<SignatureBaseComponent>): string {
  return components
    .map((comp) => {
      const encodedValue = encodeComponentValue(comp.value);
      return `${comp.identifier}: ${encodedValue}`;
    })
    .join('\n');
}

/**
 * Encode a component value for the signature base.
 *
 * Values are serialized as raw strings per RFC 9421:
 * - Binary values (those containing `=:` which indicates a digest/signature
 *   format) are colon-wrapped as `:<value>:`.
 * - All other values appear as-is without quoting.
 */
function encodeComponentValue(value: string): string {
  // Binary values are identified by the presence of `=:` (digest format)
  if (isBinaryValue(value)) {
    return `:${value}:`;
  }
  // String values appear as-is per RFC 9421 signature base serialization
  return value;
}

/**
 * Determine if a component value should be treated as binary (colon-wrapped).
 *
 * Values containing `=:` (sha-256=:..., sha-512=:..., etc.) are binary digest values.
 */
function isBinaryValue(value: string): boolean {
  return value.includes('=:');
}

// ---------------------------------------------------------------------------
// Request Signing
// ---------------------------------------------------------------------------

/**
 * The set of covered components for an AIDA agent signature.
 */
interface CoveredComponents {
  identifiers: string[];
  components: SignatureBaseComponent[];
}

/**
 * Build the list of covered components for a request.
 *
 * Always includes: @method, @path, @authority, content-digest, aida-agent.
 * Optionally includes aida-purpose when a purpose is provided.
 */
function buildCoveredComponents(
  url: string,
  method: string,
  agentId: string,
  contentDigest: string,
  purpose?: AgentPurpose,
): CoveredComponents {
  const parsedUrl = new URL(url);

  const components: SignatureBaseComponent[] = [
    { identifier: '"@method"', value: method },
    { identifier: '"@path"', value: parsedUrl.pathname + parsedUrl.search },
    { identifier: '"@authority"', value: parsedUrl.host },
    { identifier: '"content-digest"', value: contentDigest },
    { identifier: '"aida-agent"', value: agentId },
  ];

  if (purpose !== undefined) {
    components.push({ identifier: '"aida-purpose"', value: purpose });
  }

  const identifiers = components.map((c) => c.identifier);

  return { identifiers, components };
}

/**
 * Sign an HTTP request with an AIDA agent identity per RFC 9421.
 *
 * Computes the content-digest of the body, builds the RFC 9421 signature base
 * covering `@method`, `@path`, `@authority`, `content-digest`, `aida-agent`,
 * and optionally `aida-purpose`. Signs with the agent's Ed25519 private key.
 *
 * Returns a {@link SignedRequest} with the following headers set:
 * - `Aida-Agent`: the agent's AIDA URI
 * - `Signature-Input`: the RFC 9421 signature input header
 * - `Signature`: the base64-encoded Ed25519 signature
 *
 * @param url - The full URL of the request.
 * @param options - Signing options including method, agent state, body, and optional purpose.
 * @returns A signed request ready for `fetch()`.
 */
export async function signRequest(
  url: string,
  options: SignRequestOptions,
): Promise<SignedRequest> {
  const { method, agent, body, purpose } = options;

  // Compute content digest
  const contentDigest = computeContentDigest(body);

  // Build covered components
  const { identifiers, components } = buildCoveredComponents(
    url,
    method,
    agent.identity.id,
    contentDigest,
    purpose,
  );

  // Build signature base
  const signatureBase = buildSignatureBase(components);
  const signatureBaseBytes = new TextEncoder().encode(signatureBase);

  // Sign with Ed25519
  const created = Math.floor(Date.now() / 1000);
  const signature = ed25519.sign(signatureBaseBytes, agent.keypair.privateKey);
  const signatureBase64 = Buffer.from(signature).toString('base64');

  // Build Signature-Input header
  // Format: sig1=(<identifiers>);keyid="<uri>";created=<unix>;alg="ed25519"
  const identifierList = identifiers.join(' ');
  const signatureInput =
    `sig1=(${identifierList});keyid="${agent.identity.id}";created=${created};alg="ed25519"`;

  // Build Signature header
  // Format: sig1=:<base64>:
  const signatureHeader = `sig1=:${signatureBase64}:`;

  // Build headers
  const headers: Record<string, string> = {
    'Aida-Agent': agent.identity.id,
    'Signature-Input': signatureInput,
    'Signature': signatureHeader,
  };

  // Build the result, only including body if defined (exactOptionalPropertyTypes)
  const result: SignedRequest = {
    url,
    method,
    headers,
  };

  if (body !== undefined) {
    result.body = body;
  }

  return result;
}
