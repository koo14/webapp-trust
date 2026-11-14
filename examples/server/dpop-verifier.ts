/**
 * @file dpop-verifier.ts
 * @description Server-side DPoP Proof Validator for Zero-Trust Request Verification.
 */

import { createPublicKey, createVerify, createHash } from "crypto";

export interface DPoPVerificationParams {
  dpopHeader: string;
  expectedMethod: string;
  expectedUrl: string;
  expectedNonce: string;
  sessionJWKThumbprint?: string;
  accessToken?: string;
  maxAgeSeconds?: number;
}

export interface DPoPVerificationResult {
  readonly isValid: boolean;
  readonly jwkThumbprint: string;
  readonly error?: string;
}

function base64UrlDecode(input: string): Buffer {
  let base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  return Buffer.from(base64, "base64");
}

/**
 * Calculates RFC 7638 JWK Thumbprint (SHA-256).
 */
export function computeJWKThumbprint(jwk: { crv: string; kty: string; x: string; y: string }): string {
  const canonicalJWK = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });
  return createHash("sha256").update(canonicalJWK).digest("base64url");
}

/**
 * Validates an incoming DPoP proof against the request context and non-extractable device key thumbprint.
 */
export function verifyDPoPProof(params: DPoPVerificationParams): DPoPVerificationResult {
  const {
    dpopHeader,
    expectedMethod,
    expectedUrl,
    expectedNonce,
    sessionJWKThumbprint,
    accessToken,
    maxAgeSeconds = 120,
  } = params;

  try {
    const parts = dpopHeader.split(".");
    if (parts.length !== 3) {
      return { isValid: false, jwkThumbprint: "", error: "Malformatted DPoP JWT" };
    }

    const header = JSON.parse(base64UrlDecode(parts[0]).toString("utf-8"));
    const payload = JSON.parse(base64UrlDecode(parts[1]).toString("utf-8"));
    const signature = base64UrlDecode(parts[2]);

    // 1. Verify Header fields
    if (header.typ !== "dpop+jwt" || header.alg !== "ES256" || !header.jwk) {
      return { isValid: false, jwkThumbprint: "", error: "Invalid DPoP header or algorithm" };
    }

    const thumbprint = computeJWKThumbprint(header.jwk);

    // 2. If session is device-bound, verify JWK matches registered thumbprint
    if (sessionJWKThumbprint && sessionJWKThumbprint !== thumbprint) {
      return { isValid: false, jwkThumbprint: thumbprint, error: "DPoP key does not match session device key" };
    }

    // 3. Verify Method and URL binding
    const normalizedExpectedUrl = expectedUrl.split("?")[0];
    if (payload.htm !== expectedMethod.toUpperCase() || payload.htu !== normalizedExpectedUrl) {
      return { isValid: false, jwkThumbprint: thumbprint, error: "HTTP method or URI mismatch" };
    }

    // 4. Verify Nonce Anti-Replay
    if (payload.nonce !== expectedNonce) {
      return { isValid: false, jwkThumbprint: thumbprint, error: "DPoP nonce mismatch" };
    }

    // 5. Verify Timestamp freshness
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - payload.iat) > maxAgeSeconds) {
      return { isValid: false, jwkThumbprint: thumbprint, error: "DPoP proof expired or clock skewed" };
    }

    // 6. Verify Access Token Hash (RFC 9449 Section 4.2: ath is mandatory when accessToken is bound)
    if (accessToken) {
      if (typeof payload.ath !== "string" || !payload.ath) {
        return { isValid: false, jwkThumbprint: thumbprint, error: "Missing required access token hash (ath)" };
      }
      const expectedAth = createHash("sha256").update(accessToken).digest("base64url");
      if (expectedAth !== payload.ath) {
        return { isValid: false, jwkThumbprint: thumbprint, error: "Access token hash (ath) mismatch" };
      }
    }

    // 7. Verify ECDSA signature using public key reconstructed from JWK
    const keyObject = createPublicKey({
      key: header.jwk,
      format: "jwk",
    });

    const verifier = createVerify("SHA256");
    verifier.update(`${parts[0]}.${parts[1]}`);
    const isSignatureValid = verifier.verify(
      { key: keyObject, dsaEncoding: "ieee-p1363" },
      signature
    );

    if (!isSignatureValid) {
      return { isValid: false, jwkThumbprint: thumbprint, error: "Invalid cryptographic signature" };
    }

    return { isValid: true, jwkThumbprint: thumbprint };
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : "DPoP verification exception";
    return { isValid: false, jwkThumbprint: "", error: errorMsg };
  }
}
