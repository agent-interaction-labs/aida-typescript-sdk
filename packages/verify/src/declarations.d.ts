/**
 * Ambient type declarations for packages that lack their own.
 */

declare module 'base58-universal' {
  /**
   * Encode a Uint8Array of bytes as a base58 string.
   * Uses the Bitcoin alphabet (no 0, O, I, l).
   */
  export function encode(input: Uint8Array): string;

  /**
   * Decode a base58 string back into a Uint8Array of bytes.
   * Throws if the input contains invalid base58 characters.
   */
  export function decode(input: string): Uint8Array;
}
