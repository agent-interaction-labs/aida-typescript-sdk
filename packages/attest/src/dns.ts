/**
 * AIDA Agent SDK — DNS Publication Helper.
 *
 * Generates DNS TXT records that agents publish so their identity documents
 * can be discovered and verified via the `.well-known/aida` convention.
 */

import type { AgentController } from './types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract a domain from an `AgentController`.
 *
 * Prefers `controller.dns`, then falls back to the domain part of `controller.email`.
 *
 * @returns The domain string if found, `undefined` otherwise.
 */
function deriveDomain(controller: AgentController): string | undefined {
  if (controller.dns && controller.dns.length > 0) {
    return controller.dns;
  }

  // No domain to derive
  return undefined;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate the DNS TXT record value that agents publish.
 *
 * The record associates an agent's controller domain with its identity URL,
 * enabling verifiers to discover and validate the identity document via the
 * `.well-known/aida` convention.
 *
 * **Record format:**
 * ```
 * v=aida1;u=<identityUrl>
 * ```
 *
 * @param controller - The agent's controller record. Must contain a `dns` field.
 * @param identityUrl - The full URL where the identity document is hosted.
 *   Defaults to `https://<controller.dns>/.well-known/aida`.
 * @returns The TXT record value string (no surrounding quotes).
 *
 * @throws If no domain can be derived from the controller (no `dns` field).
 */
export function generateDnsRecord(
  controller: AgentController,
  identityUrl?: string,
): string {
  const domain = deriveDomain(controller);

  if (!domain) {
    throw new Error(
      'No domain found in controller. Provide a controller with a "dns" field ' +
        'to generate a DNS record.',
    );
  }

  const url = identityUrl ?? `https://${domain}/.well-known/aida`;

  return `v=aida1;u=${url}`;
}

/**
 * Generate human-readable instructions for publishing the DNS record.
 *
 * Returns a multi-line string containing:
 * - A description of the DNS record
 * - The exact TXT record value to publish
 * - The domain where the record should be published
 * - A `dig` command to verify publication
 *
 * @param controller - The agent's controller record. Must contain a `dns` field.
 * @param identityUrl - The full URL where the identity document is hosted.
 *   Defaults to `https://<controller.dns>/.well-known/aida`.
 * @returns Multi-line instructions string.
 *
 * @throws If no domain can be derived from the controller.
 */
export function generateDnsInstructions(
  controller: AgentController,
  identityUrl?: string,
): string {
  const domain = deriveDomain(controller);

  if (!domain) {
    throw new Error(
      'No domain found in controller. Provide a controller with a "dns" field ' +
        'to generate DNS instructions.',
    );
  }

  const url = identityUrl ?? `https://${domain}/.well-known/aida`;
  const txtRecord = `v=aida1;u=${url}`;

  return [
    `## DNS TXT Record for AIDA Agent Identity`,
    ``,
    `Publish the following TXT record on your domain to enable identity`,
    `discovery and verification for your AIDA agent.`,
    ``,
    `**Domain:** \`${domain}\``,
    `**TXT Record:**`,
    ``,
    `\`\`\``,
    txtRecord,
    `\`\`\``,
    ``,
    `**Verification:** Once published, verify the record with:`,
    ``,
    `\`\`\`bash`,
    `dig TXT ${domain} +short`,
    `\`\`\``,
    ``,
    `The output should include the string \`${txtRecord}\`.`,
  ].join('\n');
}
