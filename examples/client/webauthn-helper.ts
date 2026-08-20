/**
 * @file webauthn-helper.ts
 * @description Zero-Trust WebAuthn / Passkey helper facilitating hardware-isolated
 * registration and authentication ceremonies without exposing raw credentials.
 */

export interface WebAuthnRegisterOptions {
  challenge: string; // Base64URL
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: Array<{ alg: number; type: "public-key" }>;
  timeout?: number;
  attestation?: AttestationConveyancePreference;
}

export interface WebAuthnAuthOptions {
  challenge: string; // Base64URL
  rpId: string;
  allowCredentials?: Array<{ id: string; type: "public-key" }>;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
}

/**
 * Converts Base64URL string to Uint8Array buffer.
 */
export function base64UrlToBuffer(base64url: string): Uint8Array {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = (4 - (base64.length % 4)) % 4;
  const padded = base64 + "=".repeat(padLength);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Converts ArrayBuffer to Base64URL string.
 */
export function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Executes a WebAuthn Passkey Registration Ceremony.
 */
export async function registerPasskey(options: WebAuthnRegisterOptions): Promise<Record<string, unknown>> {
  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: base64UrlToBuffer(options.challenge),
      rp: options.rp,
      user: {
        id: new TextEncoder().encode(options.user.id),
        name: options.user.name,
        displayName: options.user.displayName,
      },
      pubKeyCredParams: options.pubKeyCredParams,
      timeout: options.timeout ?? 60000,
      attestation: options.attestation ?? "none",
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
    },
  })) as PublicKeyCredential;

  if (!credential) {
    throw new Error("WebAuthn registration aborted or unsupported");
  }

  const response = credential.response as AuthenticatorAttestationResponse;

  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      attestationObject: bufferToBase64Url(response.attestationObject),
    },
  };
}

/**
 * Executes a WebAuthn Passkey Authentication Ceremony.
 */
export async function authenticatePasskey(options: WebAuthnAuthOptions): Promise<Record<string, unknown>> {
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: base64UrlToBuffer(options.challenge),
      rpId: options.rpId,
      allowCredentials: options.allowCredentials?.map((c) => ({
        id: base64UrlToBuffer(c.id),
        type: "public-key" as const,
      })),
      timeout: options.timeout ?? 60000,
      userVerification: options.userVerification ?? "preferred",
    },
  })) as PublicKeyCredential;

  if (!credential) {
    throw new Error("WebAuthn authentication aborted");
  }

  const response = credential.response as AuthenticatorAssertionResponse;

  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      authenticatorData: bufferToBase64Url(response.authenticatorData),
      signature: bufferToBase64Url(response.signature),
      userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : null,
    },
  };
}
