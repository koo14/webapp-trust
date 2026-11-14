---
name: webapp-trust
description: >-
  Expert guidance and architecture standards for developing zero-trust authentication systems in modern web applications.
  Use this skill when designing, implementing, auditing, or refactoring webapp authentication, including nonce anti-replay,
  multi-tier password hashing with versioning, envelope encryption (DEK/KEK), Web Crypto non-extractable keys,
  WebAssembly linear memory management, client-side memory scrubbing, Trusted Types/CSP, Cross-Origin Isolation,
  WebAuthn/Passkeys, TOTP, DPoP device binding (RFC 9449), Access Token + Refresh Token Rotation (RTR),
  Web Worker task sandboxing, and BFF HttpOnly session architectures.
---

# WebApp Trust: Zero-Trust Web Application Authentication Skill

This skill provides a **two-layer** security framework:
1. **Theoretical Layer (Protocol-Agnostic)**: Formal trust boundaries, capability-based adversary models ($\mathcal{A}_{\text{net}}$, $\mathcal{A}_{\text{client}}$, $\mathcal{A}_{\text{store}}$, $\mathcal{A}_{\text{post}}$), five cryptographic/system invariants (`I1`–`I5`), and deterministic security state machines ([Formal Security Model](./references/formal-security-model.md)).
2. **Instantiation Layer (Web / BFF / TypeScript)**: Concrete production bindings using Web Crypto (`extractable: false`), Web Workers/Wasm, RFC 9449 DPoP, RTR, `__Host-` `HttpOnly` cookies, Argon2id, and KMS envelope encryption.

---

## 1. Theoretical Axioms & Security Invariants

Before selecting libraries or writing endpoints, align every design or audit against these five protocol-agnostic invariants (see [Formal Security Model](./references/formal-security-model.md) for formal definitions and FSMs):

| Invariant | Formal Guarantee | Adversary Mitigated | Web / BFF Instantiation |
| :--- | :--- | :--- | :--- |
| **I1. State Freshness** | Challenges are single-use (`AtomicConsume`) within a bounded window $\Delta t$. | $\mathcal{A}_{\text{net}}$ (Replay) | Pre-negotiated Nonce + Redis `GETDEL` |
| **I2. Proof-of-Possession** | Bearer credential + non-exportable key signature bound to `(method, uri, t, n, ath)`. | $\mathcal{A}_{\text{post}}$, $\mathcal{A}_{\text{net}}$ | RFC 9449 DPoP + `SubtleCrypto` (`extractable: false`) |
| **I3. Monotonic Family** | At most one generation $G_k$ is `ACTIVE`; reuse of any `USED` $G_i$ collapses family to `REVOKED`. | $\mathcal{A}_{\text{post}}$ (Token Theft) | Dual-Token + RTR Family Tree |
| **I4. Key Hierarchy** | Per-record $\text{DEK}_r$ wrapped by external root $\text{KEK}_v$; no plaintext key co-located with data. | $\mathcal{A}_{\text{store}}$ (DB Dump) | KMS / HSM Envelope Encryption (`AES-256-GCM`) |
| **I5. Ephemeral Residency** | Plaintext secrets have bounded residency $T_{\text{res}} \to 0$ in GC heaps and 0 disk persistence. | $\mathcal{A}_{\text{client}}$ (XSS / Heap) | Web Worker + Wasm Linear Memory + `.fill(0)` + In-Memory AT |

### Agent Execution Workflows & Anti-Patterns
- **Designing / Building from Scratch**: Start by reading [Formal Security Model](./references/formal-security-model.md) to define trust zones and choose a security tier (Baseline $\to$ High-Assurance), then read the specific `references/*.md` guides for each primitive.
- **Auditing / Refactoring**: Check invariants `I1`–`I5` systematically. Flag **Red Flags** immediately: AT stored in `localStorage`/`IndexedDB`, `extractable: true` keys, missing `ath` enforcement when `accessToken` is present, non-atomic nonce checks, `window.crypto` inside Workers, or unencrypted TOTP/password verifiers in DB.

---

## 2. Core Security Architecture

```mermaid
flowchart TB
    subgraph Client ["Client Browser (Zero-Trust Frontier)"]
        UI["DOM & UI Layer<br/>(Trusted Types + Strict CSP)"]
        Worker["Web Worker Sandbox<br/>(0 DOM Access / Ephemeral V8 Heap)"]
        WebCrypto["Web Crypto API<br/>(extractable: false)"]
        DPoPSigner["DPoP Signer (RFC 9449)<br/>Hardware/Sandbox Device Bound"]
        TokenClient["Zero-Trust Token Client<br/>(In-Memory AT + Silent Refresh)"]
        Wasm["WebAssembly Engine<br/>(Deterministic Linear Memory)"]
        MemScrub["Explicit Memory Scrubbing<br/>(.fill(0) + Detach ArrayBuffer)"]
        COI["Cross-Origin Isolation<br/>(COOP + COEP)"]
    end

    subgraph Transport ["Secure Transport & Gateway"]
        HTTPS["TLS 1.3 + Nonce Anti-Replay"]
        BFF["BFF (Backend for Frontend)<br/>__Host-refresh_token HttpOnly Cookie"]
    end

    subgraph Server ["Server & Backend Services"]
        DPoPVerifier["DPoP Verifier & JWK Thumbprint"]
        TokenMgr["Token Manager & RTR Engine<br/>(Family Tree & Breach Reuse Detector)"]
        AuthSvc["Auth Service<br/>(Argon2id Multi-Tier Rehash)"]
        VersionMgr["Password Version Manager<br/>(In-Flight Migration State Machine)"]
        KMS["KMS / HSM (Master KEK Provider)"]
        Envelope["Envelope Encryption Engine<br/>(Per-Record AES-256-GCM DEK)"]
        Telemetry["Zero-Trust Audit & Threat Telemetry"]
    end

    subgraph Storage ["Encrypted Persistence"]
        DB[("Encrypted DB & Token Store<br/>Ciphertext + Hashed RTs + Family State")]
    end

    UI -->|Transferable Buffer| Worker
    Worker --> WebCrypto
    Worker --> Wasm
    Worker --> MemScrub
    WebCrypto --> DPoPSigner
    TokenClient --> DPoPSigner
    UI -->|Pre-hashed + Nonce + DPoP| BFF
    TokenClient -->|Bearer AT + DPoP Proof| BFF
    BFF --> DPoPVerifier
    BFF --> TokenMgr
    BFF --> AuthSvc
    AuthSvc --> VersionMgr
    AuthSvc --> Envelope
    TokenMgr --> Telemetry
    AuthSvc --> Telemetry
    Envelope <-->|Unwrap/Wrap DEK| KMS
    TokenMgr <--> DB
    Envelope --> DB
```

---

## 3. Architectural Checklist & Standards

| Security Domain | Mandatory Controls | Reference Guide |
| :--- | :--- | :--- |
| **Anti-Replay Nonce** | Pre-negotiated server nonce for high-security actions; atomic single-use consumption (`GETDEL`), continuous chain rotation. | [Nonce Anti-Replay](./references/zero-trust-auth-flow.md) |
| **Token Dual-Model** | Ultra short-lived Access Token (1-5m in-memory variable, destroyed on page close) + Rolling Refresh Token (1-3d, `__Host-` `HttpOnly`, `Secure`, `SameSite=Strict/Lax` cookie) with RTR & breach invalidation. | [Token Lifecycle & Rotation](./references/tokens-and-rotation-lifecycle.md) |
| **Password Pipeline** | Client pre-hashing (HMAC-SHA256) + Server multi-tier re-hashing (Argon2id) + `pwd_version` in-flight migration. | [Password Pipeline & Versioning](./references/zero-trust-auth-flow.md) |
| **Database Encryption** | Envelope encryption (KEK in KMS/HSM, per-record AES-256-GCM DEK) for TOTP seeds, password verifiers, and credentials. | [Envelope Encryption](./references/envelope-encryption-and-storage.md) |
| **Passwordless Auth** | WebAuthn / Passkeys (FIDO2 Level 3) + Replay-resistant encrypted TOTP (RFC 6238). | [Passwordless & 2FA](./references/passwordless-webauthn-totp.md) |
| **Key Isolation** | Browser Web Crypto API with `extractable: false` (Non-extractable CryptoKey handles). | [Client Defense & Web Crypto](./references/client-defense-and-webcrypto.md) |
| **Device Binding** | DPoP (RFC 9449) device-bound session proofs signed with non-extractable client keys. | [DPoP & Device Binding](./references/dpop-and-device-binding.md) |
| **Worker Sandboxing** | Isolated Web Worker cryptographic thread with zero-copy transferable ArrayBuffers. | [Client Defense & Web Crypto](./references/client-defense-and-webcrypto.md) |
| **Memory Sanitization** | Wasm deterministic linear memory + JavaScript explicit zeroing (`Uint8Array.fill(0)` and nulling). | [Client Defense & Web Crypto](./references/client-defense-and-webcrypto.md) |
| **Runtime Hardening** | Cross-Origin Isolation (`COOP: same-origin`, `COEP: require-corp`) + Strict CSP (`require-trusted-types-for 'script'`). | [Client Defense & Web Crypto](./references/client-defense-and-webcrypto.md) |
| **Token Invisibility** | BFF architecture sinking session state into `__Host-` `HttpOnly`, `Secure`, `SameSite=Strict` cookies. | [BFF & Session Architecture](./references/bff-and-session-architecture.md) |
| **Security Telemetry** | Structured OpenTelemetry audit events for replay spikes, token reuse breach, and key mismatches. | [Audit Logging & Threats](./references/audit-logging-and-threat-detection.md) |

---

## 4. Directory Navigation

### Technical References
- [Formal Security Model, Adversary Abstractions & Invariants](./references/formal-security-model.md)
- [Detailed Auth Flow & Nonce Protocol](./references/zero-trust-auth-flow.md)
- [Access Token & Refresh Token Rotation (RTR) Lifecycle](./references/tokens-and-rotation-lifecycle.md)
- [Client Memory Defense, Wasm & Web Crypto](./references/client-defense-and-webcrypto.md)
- [DPoP (RFC 9449) Device Binding & Non-Extractable Keys](./references/dpop-and-device-binding.md)
- [Envelope Encryption & KMS Schemas](./references/envelope-encryption-and-storage.md)
- [Passwordless WebAuthn & TOTP](./references/passwordless-webauthn-totp.md)
- [BFF & HttpOnly Session Management](./references/bff-and-session-architecture.md)
- [Zero-Trust Audit Logging & Threat Detection](./references/audit-logging-and-threat-detection.md)

### Reference Implementations (TypeScript)
- [Client Cryptographic Sandbox](./examples/client/crypto-sandbox.ts)
- [Client Web Worker Sandbox & Thread Isolation](./examples/client/auth.worker.ts)
- [Client Worker Bridge & Memory Zero-Copy Transfer](./examples/client/worker-bridge.ts)
- [Client Zero-Trust Token Manager (In-Memory AT & Silent Refresh)](./examples/client/token-client.ts)
- [Client DPoP Proof Signer](./examples/client/dpop-signer.ts)
- [Client WebAuthn Ceremony Handler](./examples/client/webauthn-helper.ts)
- [Server Nonce Handshake & Anti-Replay Manager](./examples/server/nonce-handshake.ts)
- [Server Token Manager & RTR Engine (Family Tree / Reuse Detection)](./examples/server/token-manager.ts)
- [Server Envelope Encryption & Password Version Manager](./examples/server/envelope-encryption.ts)
- [Server DPoP Proof Verifier](./examples/server/dpop-verifier.ts)
- [End-to-End Integration Verification Suite](./examples/verification-suite.ts)
