/**
 * @file token-client.ts
 * @description Zero-Trust Client-side Token Manager.
 * Stores Access Tokens strictly in ephemeral memory (closure state, 0 storage on disk),
 * and automatically triggers silent background refresh coupled with Nonce & DPoP proofs.
 */

import { createDPoPProof } from "./dpop-signer";

export interface TokenClientConfig {
  readonly bffBaseUrl: string;
  readonly keyPair: CryptoKeyPair; // Web Crypto Non-extractable key pair
  readonly onAuthFailure?: (error: Error) => void;
}

export interface TokenRefreshResponse {
  readonly accessToken: string;
  readonly expiresIn: number;
}

export class ZeroTrustTokenClient {
  private readonly config: TokenClientConfig;
  private inMemoryAccessToken: string | null = null;
  private tokenExpiresAt: number = 0;
  private refreshPromise: Promise<string> | null = null;

  constructor(config: TokenClientConfig) {
    this.config = config;
  }

  /**
   * Updates the in-memory Access Token.
   *
   * @param accessToken - The newly issued short-lived Access Token.
   * @param expiresInSeconds - Lifetime in seconds (e.g. 900s).
   */
  public setAccessToken(accessToken: string, expiresInSeconds: number): void {
    this.inMemoryAccessToken = accessToken;
    // Set expiration threshold to 80% of token lifetime for proactive silent refresh
    this.tokenExpiresAt = Date.now() + expiresInSeconds * 800;
  }

  /**
   * Clears the in-memory token state immediately upon logout or session revocation.
   */
  public clearAccessToken(): void {
    this.inMemoryAccessToken = null;
    this.tokenExpiresAt = 0;
    this.refreshPromise = null;
  }

  /**
   * Retrieves a valid Access Token, triggering proactive silent refresh if near expiry.
   */
  public async getValidAccessToken(): Promise<string> {
    if (this.inMemoryAccessToken && Date.now() < this.tokenExpiresAt) {
      return this.inMemoryAccessToken;
    }

    // Deduplicate concurrent refresh requests into a single promise
    if (!this.refreshPromise) {
      this.refreshPromise = this.executeSilentRefresh()
        .then((token) => {
          this.refreshPromise = null;
          return token;
        })
        .catch((err) => {
          this.refreshPromise = null;
          this.clearAccessToken();
          if (this.config.onAuthFailure) {
            this.config.onAuthFailure(err);
          }
          throw err;
        });
    }

    return await this.refreshPromise;
  }

  /**
   * Executes a Zero-Trust authenticated fetch request with DPoP proof and in-memory Bearer token.
   *
   * @param endpoint - Target API endpoint path.
   * @param init - Request options.
   */
  public async authenticatedFetch(endpoint: string, init: RequestInit = {}): Promise<Response> {
    const token = await this.getValidAccessToken();
    const targetUrl = new URL(endpoint, this.config.bffBaseUrl).toString();
    const method = init.method ?? "GET";

    // 1. Generate DPoP proof for the specific request
    const dpopProof = await createDPoPProof(this.config.keyPair, {
      httpMethod: method,
      httpUrl: targetUrl,
      accessToken: token,
    });

    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${token}`);
    headers.set("DPoP", dpopProof);

    const response = await fetch(targetUrl, {
      ...init,
      headers,
      credentials: "include", // Enforce sending __Host- cookies
    });

    // Handle step-up / token expiration edge-case
    if (response.status === 401) {
      this.clearAccessToken();
    }

    return response;
  }

  /**
   * Performs silent token refresh via BFF:
   * 1. Fetches pre-negotiated single-use Nonce.
   * 2. Generates DPoP proof bound to Nonce & endpoint.
   * 3. Calls /auth/token/refresh (which automatically includes HttpOnly __Host-refresh_token cookie).
   */
  private async executeSilentRefresh(): Promise<string> {
    const refreshUrl = new URL("/auth/token/refresh", this.config.bffBaseUrl).toString();

    // 1. Acquire preflight Nonce
    const nonceRes = await fetch(new URL("/auth/nonce/preflight", this.config.bffBaseUrl).toString(), {
      method: "POST",
      credentials: "include",
    });

    if (!nonceRes.ok) {
      throw new Error("Failed to acquire preflight nonce for token refresh");
    }

    const { nonce } = (await nonceRes.json()) as { nonce: string };

    // 2. Generate DPoP Proof with Nonce
    const dpopProof = await createDPoPProof(this.config.keyPair, {
      httpMethod: "POST",
      httpUrl: refreshUrl,
      nonce,
    });

    // 3. Request Token Refresh
    const response = await fetch(refreshUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Auth-Nonce": nonce,
        DPoP: dpopProof,
      },
      credentials: "include", // Carries __Host-refresh_token cookie
    });

    if (!response.ok) {
      throw new Error(`Token refresh failed with status ${response.status}`);
    }

    const data = (await response.json()) as TokenRefreshResponse;
    this.setAccessToken(data.accessToken, data.expiresIn);
    return data.accessToken;
  }
}
