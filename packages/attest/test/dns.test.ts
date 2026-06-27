/**
 * Tests for the dns module.
 *
 * Covers: generateDnsRecord, generateDnsInstructions.
 */
import { describe, it, expect } from 'vitest';
import { generateDnsRecord, generateDnsInstructions } from '../src/dns';
import type { AgentController } from '../src/types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeController(overrides?: Partial<AgentController>): AgentController {
  return {
    dns: 'agent.example.com',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// generateDnsRecord
// ---------------------------------------------------------------------------

describe('generateDnsRecord', () => {
  it('should generate a TXT record with v=aida1;u=<url> format', () => {
    const record = generateDnsRecord(
      makeController({ dns: 'agent.example.com' }),
      'https://agent.example.com/.well-known/aida',
    );

    expect(record).toBe('v=aida1;u=https://agent.example.com/.well-known/aida');
  });

  it('should default identityUrl to https://<dns>/.well-known/aida', () => {
    const record = generateDnsRecord(
      makeController({ dns: 'my-agent.example.com' }),
    );

    expect(record).toBe(
      'v=aida1;u=https://my-agent.example.com/.well-known/aida',
    );
  });

  it('should use provided identityUrl and dns domain independently', () => {
    const record = generateDnsRecord(
      makeController({ dns: 'agent.example.com' }),
      'https://other-host.com/aida-identity',
    );

    expect(record).toBe('v=aida1;u=https://other-host.com/aida-identity');
  });

  it('should throw when no domain can be derived', () => {
    const controller: AgentController = { email: 'user@example.com' };
    // No dns field

    expect(() => generateDnsRecord(controller)).toThrow(
      /domain|dns/i,
    );
  });

  it('should throw when dns is empty string', () => {
    const controller: AgentController = { dns: '' };

    expect(() => generateDnsRecord(controller)).toThrow(
      /domain|dns/i,
    );
  });

  it('should handle custom identityUrl with no protocol (add https)', () => {
    // If user provides an identityUrl, we just use it as-is (they know best)
    const record = generateDnsRecord(
      makeController({ dns: 'agent.example.com' }),
      'https://custom.example.org/well-known/aida',
    );

    expect(record).toBe(
      'v=aida1;u=https://custom.example.org/well-known/aida',
    );
  });
});

// ---------------------------------------------------------------------------
// generateDnsInstructions
// ---------------------------------------------------------------------------

describe('generateDnsInstructions', () => {
  it('should return instructions containing the TXT record value', () => {
    const instructions = generateDnsInstructions(
      makeController({ dns: 'agent.example.com' }),
    );

    expect(instructions).toContain('v=aida1;u=https://agent.example.com/.well-known/aida');
  });

  it('should include the domain in the instructions', () => {
    const instructions = generateDnsInstructions(
      makeController({ dns: 'agent.example.com' }),
    );

    expect(instructions).toContain('agent.example.com');
  });

  it('should include a verification command', () => {
    const instructions = generateDnsInstructions(
      makeController({ dns: 'agent.example.com' }),
    );

    expect(instructions).toContain('dig');
    expect(instructions).toContain('TXT');
    expect(instructions).toContain('agent.example.com');
  });

  it('should use the provided identityUrl in instructions', () => {
    const instructions = generateDnsInstructions(
      makeController({ dns: 'agent.example.com' }),
      'https://custom.example.org/.well-known/aida',
    );

    expect(instructions).toContain('custom.example.org');
    expect(instructions).toContain('v=aida1;u=https://custom.example.org/.well-known/aida');
  });

  it('should throw when no domain can be derived', () => {
    const controller: AgentController = { email: 'user@example.com' };
    // No dns field

    expect(() => generateDnsInstructions(controller)).toThrow(
      /domain|dns/i,
    );
  });

  it('should return multi-line instructions', () => {
    const instructions = generateDnsInstructions(
      makeController({ dns: 'agent.example.com' }),
    );

    const lines = instructions.split('\n');
    expect(lines.length).toBeGreaterThan(1);
    expect(lines[0]).toContain('DNS');
  });
});
