# AIDA TypeScript SDK

The official TypeScript SDK for the **Agent Identity & Delegation Attestation (AIDA)** protocol.

> _Just heard of AIDA and not sure where to start? Check out the [AIDA Specification](https://github.com/agent-interaction-labs/aida-spec) for the full protocol architecture and JSON schemas._

---

## 📖 Overview

As AI agents increasingly navigate the web — calling APIs, automating tasks, and interacting with services — traditional identification mechanisms like `User-Agent` strings fall short. They provide no cryptographic proof of identity, no controller binding, and no verifiability.

The **AIDA TypeScript SDK** provides the foundational tools for both AI agents and web servers to establish mutual, zero-trust cryptographic identity and request attestation per RFC 9421 (HTTP Message Signatures).

---

## 📦 SDK Packages

The SDK is highly modular, offering specialized packages depending on whether you are building an AI agent or a web server/API.

| Package | Role | Purpose | Installation | Documentation |
|---|---|---|---|---|
| **[`@aida/attest`](./packages/attest)** | **Agent (Client)** | Generate Ed25519 agent keypairs, create identity documents, and sign outgoing HTTP requests. | `npm install @aida/attest` | [README](./packages/attest/README.md) |
| **[`@aida/verify`](./packages/verify)** | **Server (Verifier)** | Express middleware and validation utilities to discover agent keys and verify incoming request signatures. | `npm install @aida/verify` | [README](./packages/verify/README.md) |

---

## 🏛️ High-Level Architecture

```
┌─────────────────────────────────────────┐
│            AI Agent (Client)            │
├─────────────────────────────────────────┤
│  1. Generate Ed25519 Identity           │
│  2. Publish _aida DNS Record            │
│  3. signRequest() via @aida/attest      │
└────────────────────┬────────────────────┘
                     │
         HTTP Request (RFC 9421)
                     │
                     ▼
┌─────────────────────────────────────────┐
│            Web Server (API)             │
├─────────────────────────────────────────┤
│  4. createMiddleware() via @aida/verify │
│  5. Discover Key (DNS / Cache)          │
│  6. Verify Attestation                  │
└─────────────────────────────────────────┘
```

For granular API details, code examples, and configuration options, please refer to the dedicated documentation within each package directory.

---

## 🚀 Getting Started

If you want to see AIDA in action end-to-end, check out the official **[AIDA Demo Harness](https://github.com/agent-interaction-labs/aida-demo)**, which simulates an agent generating an identity, signing an attestation, and a live web server verifying it in real-time.

---

## 🛠️ Contributing & Development

This repository is maintained as a unified npm workspace.

### Setup
```bash
git clone https://github.com/agent-interaction-labs/aida-typescript-sdk.git
cd aida-typescript-sdk
npm install
```

### Building & Testing
You can build all packages and run the comprehensive test suites from the root directory:
```bash
# Build all packages simultaneously
npm run build

# Run the Vitest test suite across the SDK
npm test
```

---

## 📜 License

This project is licensed under the [Apache-2.0 License](./packages/attest/LICENSE).
