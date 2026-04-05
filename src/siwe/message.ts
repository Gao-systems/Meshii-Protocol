/**
 * SIWE — Sign-In with Ethereum (EIP-4361) message construction.
 * Pure logic only — no fetch, no viem, no wallet coupling.
 *
 * Used in Meshii IK derivation flow (Section 5.2):
 *   Client signs a SIWE message with their wallet, sends signature + X25519_pub
 *   to server for verification before ECDH-based IK derivation.
 */

import { randomBytes, bytesToHex } from "../crypto/primitives.js";
import type { SIWEMessageParams } from "../types/index.js";

/**
 * Construct an EIP-4361 canonical SIWE message string.
 *
 * Format (EIP-4361 §5.5):
 *   ${domain} wants you to sign in with your Ethereum account:\n
 *   ${address}\n
 *   \n
 *   [${statement}\n\n]
 *   URI: ${uri}\n
 *   Version: ${version}\n
 *   Chain ID: ${chainId}\n
 *   Nonce: ${nonce}\n
 *   Issued At: ${issuedAt}
 *   [Expiration Time: ${expirationTime}]
 *   [Not Before: ${notBefore}]
 *   [Request ID: ${requestId}]
 *   [Resources:\n- ${resource}...]
 */
export function buildSIWEMessage(params: SIWEMessageParams): string {
  const lines: string[] = [
    `${params.domain} wants you to sign in with your Ethereum account:`,
    params.address,
    "",
  ];

  if (params.statement !== undefined) {
    lines.push(params.statement);
    lines.push("");
  }

  lines.push(`URI: ${params.uri}`);
  lines.push(`Version: ${params.version}`);
  lines.push(`Chain ID: ${params.chainId}`);
  lines.push(`Nonce: ${params.nonce}`);
  lines.push(`Issued At: ${params.issuedAt}`);

  if (params.expirationTime !== undefined) {
    lines.push(`Expiration Time: ${params.expirationTime}`);
  }
  if (params.notBefore !== undefined) {
    lines.push(`Not Before: ${params.notBefore}`);
  }
  if (params.requestId !== undefined) {
    lines.push(`Request ID: ${params.requestId}`);
  }
  if (params.resources !== undefined && params.resources.length > 0) {
    lines.push("Resources:");
    for (const resource of params.resources) {
      lines.push(`- ${resource}`);
    }
  }

  return lines.join("\n");
}

/**
 * Generate a SIWE-compliant nonce.
 * EIP-4361 requires ≥ 8 alphanumeric characters.
 * Returns a 32-character lowercase hex string (16 random bytes).
 */
export function generateSIWENonce(): string {
  return bytesToHex(randomBytes(16));
}

/**
 * Validate that a nonce meets EIP-4361 requirements.
 * Must be ≥ 8 alphanumeric characters.
 */
export function validateSIWENonce(nonce: string): boolean {
  return /^[a-zA-Z0-9]{8,}$/.test(nonce);
}
