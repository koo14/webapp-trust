# DPoP (Demonstrating Proof-of-Possession) & Device Binding

While `HttpOnly` and `SameSite` cookies eliminate direct JavaScript extraction of session tokens, an attacker with local proxy access or network tap could potentially replay captured tokens if not bound to the client device.

RFC 9449 (DPoP) combined with **Web Crypto Non-Extractable Keys** provides end-to-end device binding under Zero-Trust.

---

## 1. DPoP Zero-Trust Flow with Non-Extractable Keys

```mermaid
sequenceDiagram
    autonumber
    participant Client as Client Browser (Web Crypto)
    participant Gateway as BFF / API Gateway
    participant AuthSvc as Backend Services

    Note over Client: Step 0: Browser generates non-extractable ECDSA P-256 KeyPair (extractable: false).<br/>Public Key (JWK) is registered during session establishment.

    Client->>Gateway: POST /api/sensitive-operation<br/>Header: DPoP: <Signed_JWT><br/>Header: X-Auth-Nonce: <PreNegotiated_Nonce><br/>Cookie: __Host-auth_session
    Note over Client: DPoP JWT contains:<br/>- htm (HTTP Method): "POST"<br/>- htu (HTTP URI): "/api/sensitive-operation"<br/>- nonce: Server Nonce<br/>- jwk: Ephemeral Public Key<br/>- ath: Hash of Session Token<br/>Signed with Non-Extractable Private Key.

    Gateway->>Gateway: 1. Validate Cookie & Session<br/>2. Atomically verify Nonce<br/>3. Verify DPoP Signature using JWK<br/>4. Ensure JWK matches session's registered Device Key<br/>5. Validate ath, htm, htu

    alt Any Check Fails (Replay or Stolen Token)
        Gateway-->>Client: 401 Unauthorized (INVALID_DPOP_OR_DEVICE_MISMATCH)
    else All Valid
        Gateway->>AuthSvc: Forward authenticated request
        AuthSvc-->>Gateway: Result
        Gateway-->>Client: 200 OK (Header: DPoP-Nonce: <Next_Nonce>)
    end
```

---

## 2. DPoP Proof Structure

A DPoP proof is a compact JWT signed with the client's non-extractable private key:

### DPoP Header:
```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xFMTbKEBaNk-8qnviRtWmOiEUAENv95460Y",
    "y": "x_daQgahOu01DEtoNphbGwoxQh42eB2ng-144214534"
  }
}
```

### DPoP Payload:
```json
{
  "jti": "b3c66f5a-2e4d-44a6-8092-234b07d612e4",
  "htm": "POST",
  "htu": "https://api.domain.com/auth/modify-credentials",
  "iat": 1718000000,
  "nonce": "server_negotiated_nonce_abc123",
  "ath": "fUHyO2R2Z3DZ520SNSnAlryznJe9WHLocnqDex6P864"
}
```

---

## 3. Security Properties
1. **Theft Immunity**: Even if an adversary intercepts the session cookie, they cannot forge a valid DPoP proof because the private key cannot be exported from the legitimate user's browser sandbox.
2. **Path & Method Pinning**: The proof explicitly binds to `htm` and `htu`, preventing cross-endpoint token relay.
3. **Nonce Anti-Replay Coupling**: The DPoP payload directly embeds the server-issued cryptographic nonce.
