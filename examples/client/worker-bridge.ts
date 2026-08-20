/**
 * @file worker-bridge.ts
 * @description Main-thread bridge managing ephemeral Web Worker lifecycles and
 * transferring ArrayBuffers with zero-copy and zero-retention.
 */

import type { WorkerPreHashMessage, WorkerResponse } from "./auth.worker";

export interface ComputePreHashOptions {
  workerUrl: string | URL;
  passwordBytes: Uint8Array;
  identifier: string;
  clientSalt: string;
  nonce: string;
  timeoutMs?: number;
}

/**
 * Dispatches raw password bytes to an ephemeral Web Worker via Transferable Objects,
 * immediately detaching the buffer from the main thread, and terminates the worker upon completion.
 *
 * @param options - Cryptographic computation parameters.
 * @returns Computed client pre-hash.
 */
export async function executeIsolatedPreHash(options: ComputePreHashOptions): Promise<string> {
  const { workerUrl, passwordBytes, identifier, clientSalt, nonce, timeoutMs = 5000 } = options;

  // Create isolated worker instance
  const worker = new Worker(workerUrl, { type: "module" });

  return new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => {
      worker.terminate();
      reject(new Error("Worker computation timed out"));
    }, timeoutMs);

    worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
      clearTimeout(timer);
      worker.terminate(); // Instantly destroy the worker and its entire V8 heap

      if (event.data.success) {
        resolve(event.data.preHash);
      } else {
        reject(new Error(event.data.error));
      }
    };

    worker.onerror = (err) => {
      clearTimeout(timer);
      worker.terminate();
      reject(new Error(`Worker execution error: ${err.message}`));
    };

    const message: WorkerPreHashMessage = {
      type: "COMPUTE_PREHASH",
      passwordBuffer: passwordBytes.buffer,
      identifier,
      clientSalt,
      nonce,
    };

    // CRITICAL: Transfer buffer ownership to the worker thread.
    // The main thread's ArrayBuffer is instantly detached (byteLength becomes 0).
    worker.postMessage(message, [passwordBytes.buffer]);
  });
}
