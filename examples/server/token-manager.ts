/**
 * @file token-manager.ts
 * @description Zero-Trust Access Token & Refresh Token Lifecycle Manager with
 * Refresh Token Rotation (RTR), Token Family Tree tracking, and Breach/Reuse Detection.
 */

import { randomBytes, createHash, createHmac, timingSafeEqual } from "crypto";

export interface AccessTokenPayload {
  readonly iss: string;
  readonly sub: string;
  readonly aud: string;
  readonly iat: number;
  readonly exp: number;
  readonly jti: string;
  readonly scope: string;
  readonly cnf?: {
    readonly jkt: string; // DPoP JWK Thumbprint
  };
}

export interface RefreshTokenRecord {
  readonly tokenHash: string;      // SHA-256 of raw refresh token
  readonly familyId: string;
  readonly generation: number;
  readonly userId: string;
  readonly dpopJkt?: string;       // Device bound thumbprint
  readonly expiresAt: number;      // Unix timestamp in ms
  isUsed: boolean;
}

export interface TokenFamilyState {
  readonly familyId: string;
  readonly userId: string;
  activeGeneration: number;
  isRevoked: boolean;
  revokedReason?: string;
}

export interface TokenPair {
  readonly accessToken: string;
  readonly accessTokenJti: string;
  readonly rawRefreshToken: string;
  readonly familyId: string;
  readonly generation: number;
  readonly expiresInSeconds: number;
}

export interface TokenStore {
  saveTokenRecord(record: RefreshTokenRecord): Promise<void>;
  getTokenRecord(tokenHash: string): Promise<RefreshTokenRecord | null>;
  updateTokenRecord(tokenHash: string, updates: Partial<RefreshTokenRecord>): Promise<void>;
  saveFamilyState(family: TokenFamilyState): Promise<void>;
  getFamilyState(familyId: string): Promise<TokenFamilyState | null>;
  revokeFamily(familyId: string, reason: string): Promise<void>;
  revokeAllUserFamilies(userId: string): Promise<void>;
  blacklistJti(jti: string, ttlSeconds: number): Promise<void>;
  isJtiBlacklisted(jti: string): Promise<boolean>;
}

export class TokenManagerService {
  private readonly jwtSecret: string;
  private readonly issuer: string;
  private readonly audience: string;
  private readonly atTtlSeconds: number;
  private readonly rtTtlSeconds: number;
  private readonly store: TokenStore;

  constructor(
    store: TokenStore,
    jwtSecret: string,
    issuer: string = "https://auth.example.com",
    audience: string = "https://api.example.com",
    atTtlSeconds: number = 180,       // 1 - 5 minutes (Default: 3 minutes)
    rtTtlSeconds: number = 259200     // 1 - 3 days (Default: 3 days / 259,200s)
  ) {
    this.store = store;
    this.jwtSecret = jwtSecret;
    this.issuer = issuer;
    this.audience = audience;
    this.atTtlSeconds = Math.min(Math.max(atTtlSeconds, 60), 300);          // Enforce 1-5 minutes
    this.rtTtlSeconds = Math.min(Math.max(rtTtlSeconds, 86400), 259200);   // Enforce 1-3 days
  }

  /**
   * Hashes a raw refresh token using SHA-256 for secure storage.
   */
  public hashToken(rawToken: string): string {
    return createHash("sha256").update(rawToken).digest("hex");
  }

  /**
   * Issues an initial Access Token + Refresh Token pair for a newly authenticated session.
   *
   * @param userId - Unique user identifier.
   * @param scope - OAuth / permission scopes.
   * @param dpopJkt - Optional DPoP JWK thumbprint for device binding.
   */
  public async issueInitialTokenPair(
    userId: string,
    scope: string = "default",
    dpopJkt?: string
  ): Promise<TokenPair> {
    const familyId = `fam_${randomBytes(16).toString("hex")}`;
    const generation = 0;

    // Initialize family state
    const familyState: TokenFamilyState = {
      familyId,
      userId,
      activeGeneration: generation,
      isRevoked: false,
    };
    await this.store.saveFamilyState(familyState);

    // Issue tokens
    return await this.generateTokenPair(userId, familyId, generation, scope, dpopJkt);
  }

  /**
   * Rotates a Refresh Token (RTR) and issues a fresh Access Token.
   * Implements automated breach / reuse detection.
   *
   * @param rawOldRefreshToken - The raw refresh token presented by the client.
   * @param scope - Required scopes.
   * @param presentedDpopJkt - DPoP JWK thumbprint presented during refresh.
   */
  public async rotateRefreshToken(
    rawOldRefreshToken: string,
    scope: string = "default",
    presentedDpopJkt?: string
  ): Promise<TokenPair> {
    const oldTokenHash = this.hashToken(rawOldRefreshToken);
    const record = await this.store.getTokenRecord(oldTokenHash);

    if (!record) {
      throw new Error("INVALID_REFRESH_TOKEN: Token record not found");
    }

    const family = await this.store.getFamilyState(record.familyId);
    if (!family || family.isRevoked) {
      throw new Error("SESSION_REVOKED: Token family has been revoked");
    }

    // Check expiration
    if (Date.now() > record.expiresAt) {
      throw new Error("EXPIRED_REFRESH_TOKEN: Token has expired");
    }

    // Check DPoP Device Binding
    if (record.dpopJkt && record.dpopJkt !== presentedDpopJkt) {
      // Possible session theft across devices
      await this.store.revokeFamily(record.familyId, "DPOP_DEVICE_MISMATCH");
      throw new Error("SECURITY_ALERT: DPoP device key mismatch during token refresh");
    }

    // BREACH DETECTION: If a previously used token is presented again (replay/theft)
    if (record.isUsed || record.generation < family.activeGeneration) {
      // Invalidate the entire token family immediately (Cascading Revocation)
      await this.store.revokeFamily(
        record.familyId,
        `REUSE_DETECTED: Stale generation ${record.generation} presented (Active is ${family.activeGeneration})`
      );
      throw new Error("BREACH_DETECTED: Refresh token reuse detected. Entire session revoked.");
    }

    // Legitimate rotation: Mark current token as USED
    await this.store.updateTokenRecord(oldTokenHash, { isUsed: true });

    // Advance generation
    const nextGeneration = record.generation + 1;
    family.activeGeneration = nextGeneration;
    await this.store.saveFamilyState(family);

    // Issue new token pair
    return await this.generateTokenPair(
      record.userId,
      record.familyId,
      nextGeneration,
      scope,
      record.dpopJkt
    );
  }

  /**
   * Verifies an Access Token and verifies against the blacklist.
   */
  public async verifyAccessToken(jwtString: string): Promise<AccessTokenPayload> {
    const parts = jwtString.split(".");
    if (parts.length !== 3) {
      throw new Error("MALFORMED_JWT");
    }

    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf-8"));
    const payload: AccessTokenPayload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
    const signature = Buffer.from(parts[2], "base64url");

    // Verify signature
    const expectedSig = createHmac("sha256", this.jwtSecret)
      .update(`${parts[0]}.${parts[1]}`)
      .digest();

    if (!timingSafeEqual(signature, expectedSig)) {
      throw new Error("INVALID_JWT_SIGNATURE");
    }

    // Verify time claims
    const now = Math.floor(Date.now() / 1000);
    if (now > payload.exp) {
      throw new Error("EXPIRED_ACCESS_TOKEN");
    }

    // Verify blacklist (JTI)
    const isBlacklisted = await this.store.isJtiBlacklisted(payload.jti);
    if (isBlacklisted) {
      throw new Error("REVOKED_ACCESS_TOKEN");
    }

    return payload;
  }

  private async generateTokenPair(
    userId: string,
    familyId: string,
    generation: number,
    scope: string,
    dpopJkt?: string
  ): Promise<TokenPair> {
    const nowSec = Math.floor(Date.now() / 1000);
    const atJti = `at_${randomBytes(16).toString("hex")}`;

    // 1. Construct Access Token Payload
    const atPayload: AccessTokenPayload = {
      iss: this.issuer,
      sub: userId,
      aud: this.audience,
      iat: nowSec,
      exp: nowSec + this.atTtlSeconds,
      jti: atJti,
      scope,
      ...(dpopJkt ? { cnf: { jkt: dpopJkt } } : {}),
    };

    const header = { alg: "HS256", typ: "JWT" };
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString("base64url");
    const encodedPayload = Buffer.from(JSON.stringify(atPayload)).toString("base64url");
    const signature = createHmac("sha256", this.jwtSecret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest("base64url");
    const accessToken = `${encodedHeader}.${encodedPayload}.${signature}`;

    // 2. Construct Refresh Token
    const rawRefreshToken = `rt_${randomBytes(32).toString("hex")}`;
    const tokenHash = this.hashToken(rawRefreshToken);
    const rtExpiresAt = Date.now() + this.rtTtlSeconds * 1000;

    const rtRecord: RefreshTokenRecord = {
      tokenHash,
      familyId,
      generation,
      userId,
      dpopJkt,
      expiresAt: rtExpiresAt,
      isUsed: false,
    };
    await this.store.saveTokenRecord(rtRecord);

    return {
      accessToken,
      accessTokenJti: atJti,
      rawRefreshToken,
      familyId,
      generation,
      expiresInSeconds: this.atTtlSeconds,
    };
  }
}
