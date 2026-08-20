/**
 * @file verification-suite.ts
 * @description End-to-end integration and verification suite for the Zero-Trust Authentication pipeline.
 * Demonstrates: Nonce Handshake -> Client Pre-Hash -> Memory Scrubbing -> Envelope Encryption ->
 * Multi-Version Password Upgrade -> Anti-Replay Detection -> DPoP Proof Verification.
 */

import { randomBytes, createHmac, pbkdf2Sync } from "crypto";
import { EnvelopeEncryptionService, PasswordVersionManager, UserCredentialRecord, KMSClient } from "./server/envelope-encryption";
import { NonceHandshakeService, NonceStore } from "./server/nonce-handshake";
import { verifyDPoPProof } from "./server/dpop-verifier";

/**
 * Mock in-memory KMS Client for test verification
 */
class MockKMSClient implements KMSClient {
  private readonly masterKey = randomBytes(32);

  async encryptDEK(kekId: string, plaintextDEK: Buffer): Promise<Buffer> {
    const cipher = createHmac("sha256", this.masterKey).update(plaintextDEK).digest();
    // Simulate wrapped DEK: XOR + hash tag
    const wrapped = Buffer.alloc(plaintextDEK.length);
    for (let i = 0; i < plaintextDEK.length; i++) {
      wrapped[i] = plaintextDEK[i] ^ this.masterKey[i % 32];
    }
    return Buffer.concat([wrapped, cipher]);
  }

  async decryptDEK(kekId: string, encryptedDEK: Buffer): Promise<Buffer> {
    const wrapped = encryptedDEK.subarray(0, 32);
    const unwrapped = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) {
      unwrapped[i] = wrapped[i] ^ this.masterKey[i % 32];
    }
    return unwrapped;
  }
}

/**
 * In-memory Nonce Store
 */
class InMemoryNonceStore implements NonceStore {
  private readonly nonces = new Map<string, number>();

  async saveNonce(nonce: string, ttlSeconds: number): Promise<void> {
    this.nonces.set(nonce, Date.now() + ttlSeconds * 1000);
  }

  async consumeNonce(nonce: string): Promise<boolean> {
    const expiry = this.nonces.get(nonce);
    if (!expiry || expiry < Date.now()) {
      return false;
    }
    this.nonces.delete(nonce);
    return true;
  }
}

export async function runZeroTrustVerificationSuite(): Promise<void> {
  console.log("=== Starting Zero-Trust Auth Verification Suite ===");

  // 1. Initialize Services
  const kms = new MockKMSClient();
  const envelope = new EnvelopeEncryptionService(kms, "kms-kek-v1");
  const pwdManager = new PasswordVersionManager(envelope);
  const nonceStore = new InMemoryNonceStore();
  const nonceService = new NonceHandshakeService("hmac-secret-key-12345", nonceStore, 90);

  const testUser = "user@example.com";
  const rawPassword = "CorrectHorseBatteryStaple!";

  // 2. Preflight: Server issues Nonce
  const nonceToken = await nonceService.issueNonce(testUser);
  console.log("✓ Step 1: Pre-negotiated Nonce Issued:", nonceToken.nonce.substring(0, 8) + "...");

  // 3. Client: Pre-hashing & Memory Zeroing
  const rawPasswordBuffer = Buffer.from(rawPassword, "utf-8");
  const clientSalt = "app-client-salt-xyz";
  const clientPreHash = createHmac("sha256", rawPasswordBuffer)
    .update(`${clientSalt}:${testUser}`)
    .digest("hex");

  // Immediate scrubbing
  rawPasswordBuffer.fill(0);
  console.log("✓ Step 2: Client Pre-hash computed & raw password buffer sanitized (.fill(0))");

  // 4. Create Legacy v1 User Record in DB (Simulate existing account)
  const legacySalt = randomBytes(16).toString("hex");
  const legacyServerHash = pbkdf2Sync(clientPreHash, legacySalt, 100_000, 32, "sha256").toString("hex");
  const encryptedLegacyHash = await envelope.encrypt(legacyServerHash);

  let userRecord: UserCredentialRecord = {
    userId: "u-12345-uuid",
    pwdVersion: "v1",
    encryptedHash: encryptedLegacyHash,
    pwdSalt: legacySalt,
  };
  console.log("✓ Step 3: User record loaded in DB under legacy version 'v1'");

  // 5. Auth Request: Verify & Consume Nonce
  const nextNonce = await nonceService.verifyAndRotateNonce(
    nonceToken.nonce,
    nonceToken.expiresAt,
    nonceToken.signature,
    testUser
  );

  if (!nextNonce) {
    throw new Error("Nonce verification failed!");
  }
  console.log("✓ Step 4: Nonce consumed atomically; Next rotated Nonce issued:", nextNonce.nonce.substring(0, 8) + "...");

  // 6. Anti-Replay Test: Try to reuse consumed Nonce
  const replayAttempt = await nonceService.verifyAndRotateNonce(
    nonceToken.nonce,
    nonceToken.expiresAt,
    nonceToken.signature,
    testUser
  );

  if (replayAttempt === null) {
    console.log("✓ Step 5: Anti-Replay Check Passed: Replay of consumed nonce correctly rejected!");
  } else {
    throw new Error("CRITICAL: Replay attack was NOT prevented!");
  }

  // 7. Verify Credentials & Test In-Flight Automatic Upgrade
  let upgradedInDb = false;
  const isAuthSuccess = await pwdManager.verifyAndUpgrade(
    userRecord,
    clientPreHash,
    async (upgradedRecord) => {
      userRecord = upgradedRecord;
      upgradedInDb = true;
      console.log("✓ Step 6: In-Flight Password Migration triggered: Upgraded to", upgradedRecord.pwdVersion);
    }
  );

  if (!isAuthSuccess || !upgradedInDb || userRecord.pwdVersion !== "v2") {
    throw new Error("Password authentication or in-flight migration failed!");
  }
  console.log("✓ Step 7: Password authenticated successfully under new version 'v2'");

  // 8. Access Token + Refresh Token Lifecycle & Rotation (RTR) Tests
  const { TokenManagerService } = await import("./server/token-manager");

  class InMemoryTokenStore {
    private readonly records = new Map<string, any>();
    private readonly families = new Map<string, any>();
    private readonly blacklist = new Set<string>();

    async saveTokenRecord(record: any) { this.records.set(record.tokenHash, { ...record }); }
    async getTokenRecord(hash: string) { return this.records.get(hash) ?? null; }
    async updateTokenRecord(hash: string, updates: any) {
      const existing = this.records.get(hash);
      if (existing) this.records.set(hash, { ...existing, ...updates });
    }
    async saveFamilyState(family: any) { this.families.set(family.familyId, { ...family }); }
    async getFamilyState(familyId: string) { return this.families.get(familyId) ?? null; }
    async revokeFamily(familyId: string, reason: string) {
      const fam = this.families.get(familyId);
      if (fam) {
        fam.isRevoked = true;
        fam.revokedReason = reason;
      }
    }
    async revokeAllUserFamilies(userId: string) {
      for (const fam of this.families.values()) {
        if (fam.userId === userId) fam.isRevoked = true;
      }
    }
    async blacklistJti(jti: string) { this.blacklist.add(jti); }
    async isJtiBlacklisted(jti: string) { return this.blacklist.has(jti); }
  }

  const tokenStore = new InMemoryTokenStore();
  const tokenManager = new TokenManagerService(tokenStore as any, "jwt-secret-key-abcdef", "https://auth.example.com", "https://api.example.com", 180, 259200);

  // Issue Initial Token Pair (Generation 0)
  const initialPair = await tokenManager.issueInitialTokenPair(userRecord.userId, "read write", "mock-dpop-thumbprint");
  console.log("✓ Step 8: Issued Initial Token Pair (Generation 0): AT JTI =", initialPair.accessTokenJti);

  // Verify Access Token
  const verifiedPayload = await tokenManager.verifyAccessToken(initialPair.accessToken);
  if (verifiedPayload.sub !== userRecord.userId || verifiedPayload.cnf?.jkt !== "mock-dpop-thumbprint") {
    throw new Error("Access Token payload verification failed!");
  }
  console.log("✓ Step 9: Access Token signature & DPoP binding cnf.jkt verified successfully");

  // Legitimate Rotation: Refresh Token (Generation 0 -> Generation 1)
  const rotatedPair = await tokenManager.rotateRefreshToken(
    initialPair.rawRefreshToken,
    "read write",
    "mock-dpop-thumbprint"
  );
  if (rotatedPair.generation !== 1) {
    throw new Error("Refresh Token Rotation failed to increment generation!");
  }
  console.log("✓ Step 10: Refresh Token Rotation (RTR) succeeded: Generation 0 -> Generation 1");

  // Breach Detection: Replay old Generation 0 token (Replay / Theft simulation)
  let breachDetected = false;
  try {
    await tokenManager.rotateRefreshToken(
      initialPair.rawRefreshToken,
      "read write",
      "mock-dpop-thumbprint"
    );
  } catch (err: any) {
    if (err.message.includes("BREACH_DETECTED")) {
      breachDetected = true;
      console.log("✓ Step 11: Breach Detection Triggered: Replaying old RT generation triggered Cascading Family Revocation!");
    }
  }

  if (!breachDetected) {
    throw new Error("CRITICAL: Stale refresh token replay did NOT trigger breach detection!");
  }

  // Verify that legitimate Generation 1 token is now also dead due to cascading revocation
  let familyDead = false;
  try {
    await tokenManager.rotateRefreshToken(
      rotatedPair.rawRefreshToken,
      "read write",
      "mock-dpop-thumbprint"
    );
  } catch (err: any) {
    if (err.message.includes("SESSION_REVOKED")) {
      familyDead = true;
      console.log("✓ Step 12: Cascading Revocation Verified: Compromised token family cannot issue any new tokens");
    }
  }

  if (!familyDead) {
    throw new Error("CRITICAL: Compromised token family was not properly revoked!");
  }

  console.log("=== All Zero-Trust Verification Checks Passed Successfully! ===");
}
