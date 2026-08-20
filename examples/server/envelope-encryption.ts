/**
 * @file envelope-encryption.ts
 * @description Server-side Envelope Encryption Engine (DEK/KEK) & Multi-Version
 * Password Manager with Automatic In-Flight Migration.
 */

import { randomBytes, createCipheriv, createDecipheriv, pbkdf2Sync, timingSafeEqual } from "crypto";

export interface KMSClient {
  encryptDEK(kekId: string, plaintextDEK: Buffer): Promise<Buffer>;
  decryptDEK(kekId: string, encryptedDEK: Buffer): Promise<Buffer>;
}

export interface EncryptedPayload {
  readonly ciphertext: string;      // Base64
  readonly iv: string;              // Base64
  readonly authTag: string;         // Base64
  readonly encryptedDEK: string;    // Base64
  readonly kekId: string;
}

export type PasswordVersion = "v1" | "v2" | "v3";

export interface UserCredentialRecord {
  readonly userId: string;
  pwdVersion: PasswordVersion;
  encryptedHash: EncryptedPayload;
  pwdSalt: string;                  // Hex
  totpSecret?: EncryptedPayload;
}

/**
 * Envelope Encryption Service responsible for encrypting credentials using local DEKs
 * and wrapping them with KMS-managed KEKs.
 */
export class EnvelopeEncryptionService {
  private readonly kms: KMSClient;
  private readonly defaultKekId: string;

  constructor(kms: KMSClient, defaultKekId: string) {
    this.kms = kms;
    this.defaultKekId = defaultKekId;
  }

  /**
   * Encrypts plaintext data using a freshly generated 256-bit AES-GCM DEK.
   *
   * @param plaintext - The data buffer or string to encrypt.
   * @param customKekId - Optional specific KEK identifier.
   */
  public async encrypt(plaintext: Buffer | string, customKekId?: string): Promise<EncryptedPayload> {
    const kekId = customKekId ?? this.defaultKekId;
    const dataBuffer = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, "utf-8");

    // 1. Generate ephemeral 256-bit DEK & 12-byte IV
    const dek = randomBytes(32);
    const iv = randomBytes(12);

    try {
      // 2. Encrypt payload with DEK using AES-256-GCM
      const cipher = createCipheriv("aes-256-gcm", dek, iv);
      const ciphertext = Buffer.concat([cipher.update(dataBuffer), cipher.final()]);
      const authTag = cipher.getAuthTag();

      // 3. Wrap DEK using KMS KEK
      const encryptedDEK = await this.kms.encryptDEK(kekId, dek);

      return {
        ciphertext: ciphertext.toString("base64"),
        iv: iv.toString("base64"),
        authTag: authTag.toString("base64"),
        encryptedDEK: encryptedDEK.toString("base64"),
        kekId,
      };
    } finally {
      // 4. Guaranteed zeroing of plaintext DEK from server memory
      dek.fill(0);
    }
  }

  /**
   * Decrypts an envelope-encrypted payload by unwrapping the DEK via KMS.
   *
   * @param payload - The envelope encrypted package.
   */
  public async decrypt(payload: EncryptedPayload): Promise<Buffer> {
    const encryptedDEKBuffer = Buffer.from(payload.encryptedDEK, "base64");
    const ciphertextBuffer = Buffer.from(payload.ciphertext, "base64");
    const ivBuffer = Buffer.from(payload.iv, "base64");
    const authTagBuffer = Buffer.from(payload.authTag, "base64");

    // 1. Unwrap DEK via KMS
    const dek = await this.kms.decryptDEK(payload.kekId, encryptedDEKBuffer);

    try {
      // 2. Decrypt ciphertext with unwrapped DEK
      const decipher = createDecipheriv("aes-256-gcm", dek, ivBuffer);
      decipher.setAuthTag(authTagBuffer);
      const decrypted = Buffer.concat([decipher.update(ciphertextBuffer), decipher.final()]);
      return decrypted;
    } finally {
      // 3. Immediately scrub unwrapped DEK from memory
      dek.fill(0);
    }
  }
}

/**
 * Manages multi-version password hashing and automated in-flight version upgrades.
 */
export class PasswordVersionManager {
  public static readonly CURRENT_VERSION: PasswordVersion = "v2";
  private readonly envelope: EnvelopeEncryptionService;

  constructor(envelope: EnvelopeEncryptionService) {
    this.envelope = envelope;
  }

  /**
   * Computes server-side hash for a given password version.
   */
  public computeServerHash(clientPreHash: string, salt: string, version: PasswordVersion): string {
    if (version === "v1") {
      // Legacy PBKDF2
      return pbkdf2Sync(clientPreHash, salt, 100_000, 32, "sha256").toString("hex");
    }

    if (version === "v2" || version === "v3") {
      // Argon2id simulated in-sample (In production, invoke argon2.hash with memoryCost: 65536)
      return pbkdf2Sync(clientPreHash, salt, 300_000, 64, "sha512").toString("hex");
    }

    throw new Error(`Unsupported password version: ${version}`);
  }

  /**
   * Verifies an incoming client pre-hash and automatically migrates the credential
   * to the latest version if needed.
   *
   * @param user - Stored user credential record.
   * @param clientPreHash - The pre-hash provided by the client.
   * @param onUpgradeRequired - Callback to persist updated credential in DB.
   */
  public async verifyAndUpgrade(
    user: UserCredentialRecord,
    clientPreHash: string,
    onUpgradeRequired: (updatedUser: UserCredentialRecord) => Promise<void>
  ): Promise<boolean> {
    // 1. Decrypt stored server hash
    const decryptedBuffer = await this.envelope.decrypt(user.encryptedHash);
    const storedHash = decryptedBuffer.toString("utf-8");

    // 2. Compute expected hash using user's current version
    const expectedHash = this.computeServerHash(clientPreHash, user.pwdSalt, user.pwdVersion);

    // 3. Timing-safe comparison
    const isMatch = timingSafeEqual(
      Buffer.from(storedHash, "hex"),
      Buffer.from(expectedHash, "hex")
    );

    if (!isMatch) {
      return false;
    }

    // 4. Automatic In-Flight Version Upgrade
    if (user.pwdVersion !== PasswordVersionManager.CURRENT_VERSION) {
      const newSalt = randomBytes(16).toString("hex");
      const newServerHash = this.computeServerHash(
        clientPreHash,
        newSalt,
        PasswordVersionManager.CURRENT_VERSION
      );

      const newEncryptedHash = await this.envelope.encrypt(newServerHash);

      const upgradedRecord: UserCredentialRecord = {
        ...user,
        pwdVersion: PasswordVersionManager.CURRENT_VERSION,
        encryptedHash: newEncryptedHash,
        pwdSalt: newSalt,
      };

      await onUpgradeRequired(upgradedRecord);
    }

    return true;
  }
}
