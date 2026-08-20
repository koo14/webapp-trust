/**
 * @file crypto-sandbox.ts
 * @description Client-side Zero-Trust Cryptographic Sandbox utilizing Web Crypto API
 * non-extractable keys, explicit memory zeroing, and deterministic linear memory management.
 */

export interface PreHashResult {
  /** Hex-encoded or base64-encoded client pre-hash */
  readonly preHash: string;
  /** Cryptographic nonce bound to the operation */
  readonly nonce: string;
  /** Timestamp when pre-hash was computed */
  readonly timestamp: number;
}

export interface ClientCryptoConfig {
  readonly clientSalt: string;
  readonly iterations: number;
}

/**
 * Utility for explicitly sanitizing sensitive memory buffers to prevent heap inspection.
 *
 * @param buffer - The byte array to be sanitized and zeroed.
 */
export function scrubBuffer(buffer: Uint8Array | null): void {
  if (buffer) {
    buffer.fill(0);
  }
}

/**
 * Generates an isolated, non-extractable CryptoKey inside the browser's native cryptographic sandbox.
 * The private key bytes cannot be read by JavaScript or exported.
 *
 * @returns Non-extractable ECDSA key pair handle.
 */
export async function generateNonExtractableSigningKey(): Promise<CryptoKeyPair> {
  return await window.crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    false, // CRITICAL: extractable = false guarantees raw key isolation
    ["sign", "verify"]
  );
}

/**
 * Computes a client-side pre-hash using HMAC-SHA256 over raw password bytes.
 * Immediately zeros raw password memory after computation.
 *
 * @param rawPasswordBytes - Ephemeral byte buffer containing the user's password.
 * @param identifier - Normalized user identity (e.g., email or username).
 * @param nonce - Server-negotiated single-use nonce.
 * @param config - Cryptographic client salt configuration.
 * @returns Computed pre-hash result.
 */
export async function computeClientPreHash(
  rawPasswordBytes: Uint8Array,
  identifier: string,
  nonce: string,
  config: ClientCryptoConfig
): Promise<PreHashResult> {
  const encoder = new TextEncoder();
  const saltBytes = encoder.encode(`${config.clientSalt}:${identifier.toLowerCase()}`);
  let keyHandle: CryptoKey | null = null;

  try {
    // Import raw password into ephemeral CryptoKey
    keyHandle = await window.crypto.subtle.importKey(
      "raw",
      rawPasswordBytes,
      { name: "HMAC", hash: "SHA-256" },
      false, // Do not allow key export
      ["sign"]
    );

    // Compute HMAC digest
    const digest = await window.crypto.subtle.sign(
      "HMAC",
      keyHandle,
      saltBytes
    );

    const hashArray = Array.from(new Uint8Array(digest));
    const preHash = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");

    return {
      preHash,
      nonce,
      timestamp: Date.now(),
    };
  } finally {
    // Guaranteed memory scrubbing regardless of execution path
    scrubBuffer(rawPasswordBytes);
    keyHandle = null;
  }
}

/**
 * Wrapper for WebAssembly deterministic linear memory allocation and immediate scrubbing.
 */
export class WasmLinearMemorySandbox {
  private memory: WebAssembly.Memory;
  private pointer: number;
  private size: number;

  constructor(sizeInBytes: number, memory: WebAssembly.Memory, allocOffset: number) {
    this.size = sizeInBytes;
    this.memory = memory;
    this.pointer = allocOffset;
  }

  /**
   * Retrieves a typed view of the allocated linear memory space.
   */
  public getView(): Uint8Array {
    return new Uint8Array(this.memory.buffer, this.pointer, this.size);
  }

  /**
   * Overwrites the deterministic linear memory slice with zeros immediately after use.
   */
  public wipe(): void {
    const view = new Uint8Array(this.memory.buffer, this.pointer, this.size);
    view.fill(0);
  }
}
