/**
 * @file nonce-handshake.ts
 * @description Server-side Anti-Replay Nonce Manager implementing atomic consumption,
 * HMAC signing, and continuous chain rotation for high-security operations.
 */

import { randomBytes, createHmac, timingSafeEqual } from "crypto";

export interface NonceToken {
  readonly nonce: string;
  readonly expiresAt: number;
  readonly signature: string;
}

export interface NonceStore {
  /** Atomically gets and deletes a nonce. Returns true if nonce existed and was consumed */
  consumeNonce(nonce: string): Promise<boolean>;
  /** Stores a valid nonce with TTL in seconds */
  saveNonce(nonce: string, ttlSeconds: number): Promise<void>;
}

export class NonceHandshakeService {
  private readonly secretKey: string;
  private readonly ttlSeconds: number;
  private readonly store: NonceStore;

  constructor(secretKey: string, store: NonceStore, ttlSeconds: number = 90) {
    this.secretKey = secretKey;
    this.store = store;
    this.ttlSeconds = ttlSeconds;
  }

  /**
   * Generates a new cryptographic single-use nonce for a client preflight handshake.
   *
   * @param clientContext - Identity or session context to bind to the nonce.
   */
  public async issueNonce(clientContext: string): Promise<NonceToken> {
    const rawNonce = randomBytes(24).toString("hex");
    const expiresAt = Math.floor(Date.now() / 1000) + this.ttlSeconds;

    // Sign payload to prevent tampering
    const signature = this.signPayload(`${rawNonce}:${expiresAt}:${clientContext}`);

    // Persist to store for atomic single-use verification
    await this.store.saveNonce(rawNonce, this.ttlSeconds);

    return {
      nonce: rawNonce,
      expiresAt,
      signature,
    };
  }

  /**
   * Atomically verifies and consumes a nonce. If valid, generates and returns the next nonce in the chain.
   *
   * @param nonce - Raw nonce string.
   * @param expiresAt - Expiration timestamp in seconds.
   * @param signature - HMAC signature.
   * @param clientContext - Client context to verify binding.
   * @returns Next nonce token on success; null on failure or replay.
   */
  public async verifyAndRotateNonce(
    nonce: string,
    expiresAt: number,
    signature: string,
    clientContext: string
  ): Promise<NonceToken | null> {
    const now = Math.floor(Date.now() / 1000);

    // 1. Check expiration
    if (now > expiresAt) {
      return null;
    }

    // 2. Validate cryptographic signature
    const expectedSig = this.signPayload(`${nonce}:${expiresAt}:${clientContext}`);
    const isSignatureValid = timingSafeEqual(
      Buffer.from(signature, "hex"),
      Buffer.from(expectedSig, "hex")
    );

    if (!isSignatureValid) {
      return null;
    }

    // 3. Atomically consume from store to prevent race conditions & replay
    const consumed = await this.store.consumeNonce(nonce);
    if (!consumed) {
      return null; // Replay attack detected
    }

    // 4. Continuously rotate and issue the next nonce in the chain
    return await this.issueNonce(clientContext);
  }

  private signPayload(payload: string): string {
    return createHmac("sha256", this.secretKey).update(payload).digest("hex");
  }
}
