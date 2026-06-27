/**
 * AIDA Agent SDK — AidaAgent Facade.
 *
 * The main user-facing API. Creates an agent identity, loads/saves it,
 * and signs requests.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';

import type {
  AidaAgentState,
  AgentEndpoint,
  AgentController,
  CreateAgentOptions,
  IdentityDocument,
  SignedRequest,
} from './types';
import {
  generateKeypair,
  loadKeypair,
  serializeKeypair,
  keypairExists,
} from './keys';
import { createIdentityDocument } from './identity';
import { signRequest } from './sign';

// ---------------------------------------------------------------------------
// Agent file format (private)
// ---------------------------------------------------------------------------

/**
 * The shape persisted to disk for a saved agent.
 * Contains the serialized keypair plus identity metadata so the identity
 * document can be fully reconstructed on load.
 */
interface SavedAgentData {
  publicKey: string;
  privateKey: string;
  controller: AgentController;
  endpoints?: AgentEndpoint[];
  capabilities?: string[];
}

// ---------------------------------------------------------------------------
// Persistence helpers
// ---------------------------------------------------------------------------

/**
 * Save the full agent data (keypair + identity metadata) to a JSON file.
 */
function saveAgentData(storagePath: string, data: SavedAgentData): void {
  const dir = path.dirname(storagePath);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(storagePath, JSON.stringify(data, null, 2) + '\n', {
    encoding: 'utf-8',
    flag: 'w',
  });
}

/**
 * Load agent data from a JSON file. Returns both the keypair
 * (via {@link loadKeypair}) and the identity metadata.
 */
function loadAgentData(storagePath: string): {
  keypair: AidaAgentState['keypair'];
  controller: AgentController;
  endpoints: AgentEndpoint[] | undefined;
  capabilities: string[] | undefined;
} {
  // loadKeypair validates the keypair format and deserializes it
  const keypair = loadKeypair(storagePath);

  // Read the raw JSON to extract identity metadata
  let raw: string;
  try {
    raw = fs.readFileSync(storagePath, 'utf-8');
  } catch (cause) {
    throw new Error(`Failed to read agent file: ${String(cause)}`, {
      cause,
    });
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (cause) {
    throw new Error(
      `Agent file contains invalid JSON: ${String(cause)}`,
      { cause },
    );
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('Agent file does not contain a JSON object');
  }

  const obj = parsed as Record<string, unknown>;

  // Extract controller — required
  const controller = obj.controller;
  if (typeof controller !== 'object' || controller === null) {
    throw new Error('Agent file is missing required field: controller');
  }

  // Extract optional endpoints
  let endpoints: AgentEndpoint[] | undefined;
  if (obj.endpoints !== undefined) {
    if (!Array.isArray(obj.endpoints)) {
      throw new Error('Agent file has invalid endpoints: expected an array');
    }
    endpoints = obj.endpoints as AgentEndpoint[];
  }

  // Extract optional capabilities
  let capabilities: string[] | undefined;
  if (obj.capabilities !== undefined) {
    if (!Array.isArray(obj.capabilities)) {
      throw new Error('Agent file has invalid capabilities: expected an array');
    }
    capabilities = obj.capabilities as string[];
  }

  return {
    keypair,
    controller: controller as AgentController,
    endpoints,
    capabilities,
  };
}

// ---------------------------------------------------------------------------
// createAgent
// ---------------------------------------------------------------------------

/**
 * Create a new AIDA agent identity.
 *
 * Generates a fresh Ed25519 keypair, creates a signed identity document from
 * the provided controller, endpoints, and capabilities, optionally persists
 * the keypair and metadata to disk, and returns the fully-initialized
 * {@link AidaAgentState} with bound `signRequest` and `regenerate` methods.
 *
 * @param options - {@link CreateAgentOptions} with at minimum a `controller`.
 * @returns A fully initialized agent state ready to sign requests.
 *
 * @throws If `storagePath` is provided and a keypair already exists at that
 *         path (identities are never silently overwritten).
 * @throws If saving the keypair fails (permissions, I/O error, etc.).
 */
export async function createAgent(
  options: CreateAgentOptions,
): Promise<AidaAgentState> {
  // Guard against overwriting existing identities
  if (options.storagePath !== undefined && keypairExists(options.storagePath)) {
    throw new Error(
      `An agent identity already exists at "${options.storagePath}". ` +
        `Use loadAgent() to load an existing identity, or choose a different storagePath.`,
    );
  }

  // Generate a fresh keypair
  const keypair = generateKeypair();

  // Create the identity document
  const identity = createIdentityDocument(keypair, options);

  // Persist the keypair and metadata if a storage path is provided
  if (options.storagePath !== undefined) {
    const serialized = serializeKeypair(keypair);
    const data: SavedAgentData = {
      publicKey: serialized.publicKey,
      privateKey: serialized.privateKey,
      controller: options.controller,
    };
    if (options.endpoints !== undefined) {
      data.endpoints = options.endpoints;
    }
    if (options.capabilities !== undefined) {
      data.capabilities = options.capabilities;
    }
    saveAgentData(options.storagePath, data);
  }

  // Build and return the agent state with bound methods
  return buildAgentState(keypair, identity, options.storagePath);
}

// ---------------------------------------------------------------------------
// loadAgent
// ---------------------------------------------------------------------------

/**
 * Load a previously saved AIDA agent identity.
 *
 * Reads the keypair and identity metadata from the filesystem and reconstructs
 * the signed identity document. The identity document is derived from the
 * keypair, not stored separately — only the keypair, controller, endpoints,
 * and capabilities are persisted.
 *
 * @param storagePath - Path to the JSON agent file saved by `createAgent`.
 * @returns A fully initialized agent state ready to sign requests.
 *
 * @throws If the agent file does not exist, contains invalid data, or the
 *         stored keys are malformed.
 */
export async function loadAgent(
  storagePath: string,
): Promise<AidaAgentState> {
  // Load keypair and identity metadata from the agent file
  const { keypair, controller, endpoints, capabilities } =
    loadAgentData(storagePath);

  // Reconstruct the identity document.
  // Only pass optional fields if they are actually defined, to satisfy
  // exactOptionalPropertyTypes.
  const identityOpts: CreateAgentOptions = { controller };
  if (endpoints !== undefined && endpoints.length > 0) {
    identityOpts.endpoints = endpoints;
  }
  if (capabilities !== undefined && capabilities.length > 0) {
    identityOpts.capabilities = capabilities;
  }
  const identity = createIdentityDocument(keypair, identityOpts);

  // Build and return the agent state with bound methods
  return buildAgentState(keypair, identity, storagePath);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Build a fully initialized {@link AidaAgentState} from a keypair and identity.
 *
 * Binds the `signRequest` and `regenerate` methods so the consumer can call
 * `agent.signRequest(...)` without passing the agent state explicitly.
 */
function buildAgentState(
  keypair: AidaAgentState['keypair'],
  identity: IdentityDocument,
  storagePath: string | undefined,
): AidaAgentState {
  // Use a mutable wrapper object so we can update identity on regenerate
  const wrapper: {
    keypair: AidaAgentState['keypair'];
    identity: IdentityDocument;
    storagePath: string | undefined;
  } = { keypair, identity, storagePath };

  // Build the result object. Under exactOptionalPropertyTypes,
  // optional properties must be either present (as string) or absent —
  // we cannot include them with value `undefined`.
  const result = {
    get keypair() {
      return wrapper.keypair;
    },
    get identity() {
      return wrapper.identity;
    },

    /**
     * Sign an HTTP request using this agent's identity.
     *
     * Delegates to the lower-level `signRequest` from `src/sign.ts`,
     * automatically passing this agent's keypair and identity.
     */
    signRequest: async (
      url: string,
      options: Omit<import('./types').SignRequestOptions, 'agent'>,
    ): Promise<SignedRequest> => {
      return signRequest(url, {
        ...options,
        agent: wrapper as AidaAgentState,
      });
    },

    /**
     * Regenerate the identity document (e.g., after updating metadata).
     *
     * Re-creates and re-signs the identity document using the current keypair.
     */
    regenerate: async (): Promise<IdentityDocument> => {
      // Only pass optional fields if they actually have values, to satisfy
      // exactOptionalPropertyTypes.
      const opts: CreateAgentOptions = {
        controller: wrapper.identity.controller,
      };
      if (
        wrapper.identity.endpoints !== undefined &&
        wrapper.identity.endpoints.length > 0
      ) {
        opts.endpoints = wrapper.identity.endpoints;
      }
      if (
        wrapper.identity.capabilities !== undefined &&
        wrapper.identity.capabilities.length > 0
      ) {
        opts.capabilities = wrapper.identity.capabilities;
      }
      const newIdentity = createIdentityDocument(wrapper.keypair, opts);
      wrapper.identity = newIdentity;
      return newIdentity;
    },
  } as AidaAgentState;

  // Only add storagePath when it is not undefined
  if (storagePath !== undefined) {
    (result as unknown as Record<string, unknown>).storagePath = storagePath;
  }

  return result;
}
