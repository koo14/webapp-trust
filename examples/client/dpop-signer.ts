/**
 * @file dpop-signer.ts
 * @description Client-side RFC 9449 DPoP Proof Generator using Web Crypto Non-Extractable Keys.
 */

export interface DPoPProofParams {
  httpMethod: string;
  httpUrl: string;
  nonce?: string;
  accessToken?: string;
}

/**
 * Base64URL string encoder for ArrayBuffers and JSON objects.
 */
function base64UrlEncode(data: Uint8Array | string): string {
  const binary = typeof data === "string" ? data : String.fromCharCode(...data);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Generates an RFC 9449 compliant DPoP Proof JWT using a non-extractable private key.
 *
 * @param keyPair - Non-extractable ECDSA P-256 CryptoKeyPair.
 * @param params - HTTP request context and server nonce.
 */
export async function createDPoPProof(
  keyPair: CryptoKeyPair,
  params: DPoPProofParams
): Promise<string> {
  const exportedPublicJWK = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);

  // 1. Build DPoP Header with ephemeral public JWK
  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: {
      kty: exportedPublicJWK.kty,
      crv: exportedPublicJWK.crv,
      x: exportedPublicJWK.x,
      y: exportedPublicJWK.y,
    },
  };

  // 2. Build DPoP Payload
  const payload: Record<string, unknown> = {
    jti: window.crypto.randomUUID(),
    htm: params.httpMethod.toUpperCase(),
    htu: params.httpUrl.split("?")[0], // Strip query parameters
    iat: Math.floor(Date.now() / 1000),
  };

  if (params.nonce) {
    payload.nonce = params.nonce;
  }

  if (params.accessToken) {
    // ath: SHA-256 hash of the access token
    const tokenHash = await window.crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(params.accessToken)
    );
    payload.ath = base64UrlEncode(new Uint8Array(tokenHash));
  }

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  // 3. Sign using the non-extractable private key
  const signatureBuffer = await window.crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    keyPair.privateKey,
    new TextEncoder().encode(signingInput)
  );

  const encodedSignature = base64UrlEncode(new Uint8Array(signatureBuffer));
  return `${signingInput}.${encodedSignature}`;
}
