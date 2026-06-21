/**
 * AIDA Agent SDK — TypeScript type definitions.
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
export type AgentProtocol = 'mcp' | 'aip' | 'a2a' | 'openapi' | 'grpc' | 'graphql' | 'websocket';

/** Service endpoint where the agent can be reached */
export interface AgentEndpoint {
  url: string;
  protocol: AgentProtocol;
  metadata?: Record<string, unknown>;
}

/** Verification profile for an identity document */
export type VerificationProfileType = 'local' | 'dns' | 'ledger' | 'zk';

/** Ed25519 keypair */
export interface AgentKeypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

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

/** Options for creating an agent identity */
export interface CreateAgentOptions {
  controller: AgentController;
  endpoints?: AgentEndpoint[];
  capabilities?: string[];
  storagePath?: string;
}

/** A signed HTTP request ready to be sent */
export interface SignedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

/** Options for signing an HTTP request */
export interface SignRequestOptions {
  method: string;
  agent: AidaAgentState;
  body?: string;
  purpose?: AgentPurpose;
}

/** Internal agent state (keys + identity document) */
export interface AidaAgentState {
  keypair: AgentKeypair;
  identity: IdentityDocument;
  storagePath?: string;
  /** Generate a signed HTTP request */
  signRequest: (url: string, options: Omit<SignRequestOptions, 'agent'>) => Promise<SignedRequest>;
  /** Regenerate the identity document (e.g., after soul hash changes) */
  regenerate: () => Promise<IdentityDocument>;
}
