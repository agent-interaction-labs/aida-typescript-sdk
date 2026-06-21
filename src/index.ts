/**
 * @aida/verify — Server-side AIDA agent identity verification SDK.
 *
 * Verifies AIDA agent identities on incoming HTTP requests using
 * RFC 9421 HTTP Message Signatures and optional identity document
 * resolution via DNS / ledger.
 *
 * @packageDocumentation
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type {
  AidaUri,
  HashLink,
  AgentPurpose,
  AgentController,
  AgentProtocol,
  AgentEndpoint,
  VerificationProfileType,
  IdentityDocument,
  VerificationResult,
  VerifyOptions,
} from './types';

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

export {
  encodeBase58,
  decodeBase58,
  publicKeyToAidaUri,
  aidaUriToBase58,
  aidaUriToPublicKey,
  toHex,
  formatHashLink,
} from './utils';

// ---------------------------------------------------------------------------
// RFC 9421 Signature Verification
// ---------------------------------------------------------------------------

export {
  verifySignature,
  extractKeyId,
  extractPurpose,
} from './rfc9421';

export type { VerifySignatureOptions } from './rfc9421';

// ---------------------------------------------------------------------------
// Identity Document Verification
// ---------------------------------------------------------------------------

export {
  verifyIdentityDocument,
  createVerificationResult,
} from './verification';

export type {
  VerifyIdentityDocumentOptions,
  CreateVerificationResultOptions,
} from './verification';

// ---------------------------------------------------------------------------
// Express Middleware
// ---------------------------------------------------------------------------

export { createMiddleware } from './middleware';
