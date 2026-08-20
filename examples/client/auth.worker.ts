/**
 * @file auth.worker.ts
 * @description Dedicated Web Worker sandbox for zero-trust cryptographic computations.
 * Operates in an isolated thread with 0 DOM access, executing pre-hashing and memory scrubbing.
 */

export interface WorkerPreHashMessage {
  readonly type: "COMPUTE_PREHASH";
  readonly passwordBuffer: ArrayBuffer;
  readonly identifier: string;
  readonly clientSalt: string;
  readonly nonce: string;
}

export interface WorkerSuccessResponse {
  readonly success: true;
  readonly preHash: string;
  readonly nonce: string;
}

export interface WorkerErrorResponse {
  readonly success: false;
  readonly error: string;
}

export type WorkerResponse = WorkerSuccessResponse | WorkerErrorResponse;

self.onmessage = async (event: MessageEvent<WorkerPreHashMessage>) => {
  const { type, passwordBuffer, identifier, clientSalt, nonce } = event.data;

  if (type !== "COMPUTE_PREHASH") {
    self.postMessage({ success: false, error: "Unsupported operation" } as WorkerErrorResponse);
    return;
  }

  const rawBytes = new Uint8Array(passwordBuffer);

  try {
    const encoder = new TextEncoder();
    const saltBytes = encoder.encode(`${clientSalt}:${identifier.toLowerCase()}`);

    // Import ephemeral raw key
    const key = await self.crypto.subtle.importKey(
      "raw",
      rawBytes,
      { name: "HMAC", hash: "SHA-256" },
      false, // extractable: false
      ["sign"]
    );

    const signature = await self.crypto.subtle.sign("HMAC", key, saltBytes);
    const hashHex = Array.from(new Uint8Array(signature))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    self.postMessage({
      success: true,
      preHash: hashHex,
      nonce,
    } as WorkerSuccessResponse);
  } catch (err: unknown) {
    const errorMessage = err instanceof Error ? err.message : "Cryptographic computation failure";
    self.postMessage({ success: false, error: errorMessage } as WorkerErrorResponse);
  } finally {
    // Explicitly scrub raw password bytes in Worker linear memory
    rawBytes.fill(0);
  }
};
