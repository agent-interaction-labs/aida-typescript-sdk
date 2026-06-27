/**
 * Build CJS bundle from ESM output using a simple wrapper.
 *
 * Node.js 18+ supports `require()` of ESM under certain conditions, but to
 * guarantee broad compatibility we generate explicit `.cjs` files that
 * re-export the ESM entry point with the right loaders.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Read the built ESM index
const esmPath = join(__dirname, '..', 'dist', 'index.js');
let esmSource;
try {
  esmSource = readFileSync(esmPath, 'utf-8');
} catch {
  console.error('ERROR: dist/index.js not found. Run "tsc" first.');
  process.exit(1);
}

// Build CJS wrapper — a stub that uses dynamic import to load ESM.
// For Node 18+ with --experimental-require-module this works natively.
// For older runtimes, it provides a synchronous require() proxy.
const cjsWrapper = `"use strict";

// @aida/verify — CJS entry point
// This file re-exports the ESM build for CommonJS consumers.
// Requires Node.js 18+ with --experimental-require-module if using require(),
// or use the ESM import path directly.

Object.defineProperty(exports, "__esModule", { value: true });

// Deferred ESM module reference
let _esmModule = null;

async function getEsmModule() {
  if (_esmModule) return _esmModule;
  _esmModule = await import("./index.js");
  return _esmModule;
}

// Synchronous require() proxy: exports getters that lazily grab from the ESM module.
// This approach relies on Node.js 22+ synchronous require(esm) or
// a bundler that handles CJS→ESM interop.

const ESM_PATH = require.resolve("./index.js");

// Dynamic re-export: on first access, load ESM and populate exports
function initExports() {
  if (_esmModule) return;
  try {
    _esmModule = require(ESM_PATH);
  } catch (e) {
    throw new Error(
      "Failed to load @aida/verify ESM module. " +
      "Ensure you are using Node.js 18+ with --experimental-require-module, " +
      "or import the ESM entry point directly.\\n" + e.message
    );
  }

  // Copy all named exports
  for (const key of Object.keys(_esmModule)) {
    if (key !== "default" && key !== "__esModule") {
      Object.defineProperty(exports, key, {
        enumerable: true,
        get() {
          return _esmModule[key];
        }
      });
    }
  }

  // Handle default export
  if (_esmModule.default) {
    exports.default = _esmModule.default;
  }
}

// Run initialization on load
initExports();
`;

const cjsPath = join(__dirname, '..', 'dist', 'index.cjs');
writeFileSync(cjsPath, cjsWrapper, 'utf-8');
console.log('✓ Built CJS entry: dist/index.cjs');
