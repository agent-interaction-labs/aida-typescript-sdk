/**
 * AIDA Verify SDK — TypeScript type definitions.
 * Aligned with the canonical AIDA JSON Schema (aida-spec/schema/draft/schema.ts).
 */

/** AIDA agent identifier: aida:<base58-encoded-ed25519-public-key> */
export type AidaUri = `aida:${string}`;

/** SHA-256 integrity fingerprint */
export type HashLink = `sha256:${string}`;

/** Purpose of an agent's HTTP request */
export type AgentPurpose = 'inference' | 'task' | 'crawler' | 'monitoring';

/** Controller binding for an agent identity */
export interface AgentController {
  did?: string;
  email?: string;
  dns?: string;
  oauth?: string;
}

/** Protocol spoken at an endpoint */
export type AgentProtocol = 'mcp' | 'aixa' | 'a2a' | 'openapi' | 'grpc' | 'graphql' | 'websocket';

/** Service endpoint where the agent can be reached */
export interface AgentEndpoint {
  url: string;
  protocol: AgentProtocol;
  metadata?: Record<string, unknown>;
}

/** Verification profile for an identity document */
export type VerificationProfileType = 'local' | 'dns' | 'ledger' | 'zk';

/** AIDA Identity Document (Layer 1) */
export interface IdentityDocument {
  '@context'?: string[];
  id: AidaUri;
  controller: AgentController;
  publicKey: {
    type: 'Ed25519VerificationKey2020';
    publicKeyBase58: string;
  };
  soulHash?: HashLink;
  endpoints?: AgentEndpoint[];
  capabilities?: string[];
  verification?: Array<{
    type: VerificationProfileType;
    [key: string]: unknown;
  }>;
  created: string;
  updated?: string;
  expires?: string;
  proof?: {
    type: 'Ed25519Signature2020';
    created: string;
    proofValue: string;
    verificationMethod: string;
  };
}

// ---------------------------------------------------------------------------
// Verification-specific types
// ---------------------------------------------------------------------------

/**
 * The result of verifying an AIDA agent identity on a request.
 */
export interface VerificationResult {
  /** The agent's AIDA URI (e.g. aida:CcL7R8Yx...) */
  agentId: AidaUri;
  /** Whether the overall verification succeeded */
  verified: boolean;
  /** Controller information from the identity document (if resolved) */
  controller?: AgentController;
  /** The purpose declared in the signature (if present) */
  purpose?: AgentPurpose;
  /** Public key that verified the signature */
  publicKey?: Uint8Array;
  /** Reason for verification failure (if not verified) */
  error?: string;
  /** Timestamps from the verification */
  metadata?: {
    /** When the request was signed (Unix timestamp) */
    signedAt?: number;
    /** When verification was performed (ISO 8601) */
    verifiedAt: string;
    /** Whether the identity document was resolved */
    identityResolved: boolean;
    /** Whether the identity document's self-signature verified */
    identityVerified?: boolean;
  };
}

/**
 * Options for the `verifyAgent` middleware.
 */
export interface VerifyOptions {
  /**
   * If `true`, requests without AIDA identity headers will receive a 401.
   * Default: `false` (anonymous requests pass through with `verified: false`).
   */
  required?: boolean;

  /**
   * If provided, only agents controlled by one of these controllers are
   * allowed. Requests from agents with non-matching controllers receive a 403.
   */
  allowedControllers?: AgentController[];

  /**
   * Maximum clock skew tolerance in seconds for signature `created` timestamp.
   * Default: 300 (5 minutes).
   */
  clockSkew?: number;

  /**
   * Time-to-live in seconds for cached identity documents.
   * Default: 3600 (1 hour).
   */
  cacheTTL?: number;

  /**
   * Custom public key resolver. Given a keyid (AIDA URI), returns the
   * Ed25519 public key bytes.
   *
   * Default: resolves via `aidaUriToPublicKey(keyid)` which extracts the
   * base58 key embedded in the URI itself.
   */
  getPublicKey?: (keyid: string) => Promise<Uint8Array>;

  /**
   * Custom identity document resolver. Given a keyid (AIDA URI), returns
   * the corresponding identity document, or `null` if unavailable.
   *
   * If not provided, identity document verification is skipped.
   */
  getIdentityDocument?: (keyid: string) => Promise<IdentityDocument | null>;
}

/**
 * Augment the Express Request object with AIDA verification data.
 */
declare global {
  namespace Express {
    interface Request {
      /** Populated by verifyAgent middleware after verification */
      aida?: VerificationResult;
    }
  }
}
