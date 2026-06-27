/**
 * AIDA Agent SDK — Public API.
 *
 * @aida/attest — Cryptographic identity, attestation, and request signing for AI agents on the web.
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
  AgentKeypair,
  IdentityDocument,
  CreateAgentOptions,
  SignedRequest,
  SignRequestOptions,
  AidaAgentState,
} from './types';

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

export {
  encodeBase58,
  decodeBase58,
  publicKeyToAidaUri,
  aidaUriToBase58,
  aidaUriToPublicKey,
  toHex,
  formatHashLink,
  publicKeyToJWK,
  nowISO,
} from './utils';

// ---------------------------------------------------------------------------
// Keypair management
// ---------------------------------------------------------------------------

export {
  generateKeypair,
  loadKeypair,
  saveKeypair,
  keypairExists,
  serializeKeypair,
  deserializeKeypair,
} from './keys';

export type { SerializedKeypair } from './keys';

// ---------------------------------------------------------------------------
// Identity document
// ---------------------------------------------------------------------------

export {
  createIdentityDocument,
  signIdentityDocument,
  verifyIdentityDocument,
  canonicalize,
} from './identity';

// ---------------------------------------------------------------------------
// Request signing
// ---------------------------------------------------------------------------

export {
  signRequest,
  computeContentDigest,
  buildSignatureBase,
} from './sign';

// ---------------------------------------------------------------------------
// Agent facade
// ---------------------------------------------------------------------------

export {
  createAgent,
  loadAgent,
} from './agent';

// ---------------------------------------------------------------------------
// DNS publication
// ---------------------------------------------------------------------------

export {
  generateDnsRecord,
  generateDnsInstructions,
} from './dns';
