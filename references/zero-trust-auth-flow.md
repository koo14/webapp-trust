# Zero-Trust Authentication Flow & Password Versioning

This guide specifies the end-to-end authentication protocol, covering cryptographic nonce handshakes, multi-tier salted hashing, and transparent password version upgrades.

---

## 1. Nonce Handshake & Anti-Replay Architecture

In a zero-trust model, even under full TLS transport, any high-security operation (login, password modification, 2FA addition, profile credential update) must be immune to replay attacks through pre-negotiated, single-use cryptographic nonces.

```mermaid
sequenceDiagram
    autonumber
    participant Client as Client Browser
    participant Gateway as BFF / API Gateway
    participant Redis as Nonce Cache / Store
    participant AuthSvc as Auth Service

    Client->>Gateway: POST /auth/nonce/preflight (with ClientID / SessionID)
    Gateway->>Redis: Store Nonce (UUIDv4/CryptoRandom, TTL=90s, Status=ISSUED)
    Gateway-->>Client: 200 OK { nonce: "N1", expires_at: 1718000090 }

    Note over Client: User enters password.<br/>Client computes PreHash(pwd, salt).<br/>Client attaches Nonce N1.

    Client->>Gateway: POST /auth/login { identifier, client_prehash, nonce: "N1", ... }
    Gateway->>Redis: Atomic Consume Nonce N1 (GETDEL or Lua Script)
    alt Nonce Invalid or Already Consumed
        Redis-->>Gateway: Null / Expired
        Gateway-->>Client: 401 Unauthorized (NONCE_REPLAY_OR_EXPIRED)
    else Nonce Valid
        Redis-->>Gateway: Valid (Consumed)
        Gateway->>AuthSvc: Validate Credentials & Rehash
        AuthSvc-->>Gateway: Auth Result + Generate New Nonce N2
        Gateway->>Redis: Store Nonce N2 (TTL=90s, Status=ISSUED)
        Gateway-->>Client: 200 OK (Set HttpOnly Cookie) { next_nonce: "N2" }
    end
```

### Nonce Lifecycle Rules:
1. **Scope Specificity**: Nonces can be bound to action scopes (e.g., `scope: "login"`, `scope: "mfa_verify"`).
2. **Atomic Consumption**: Must use atomic operations (e.g., Redis `GETDEL` or database conditional updates) to prevent race condition replay.
3. **Continuous Rotation**: Every successful or failed authenticated response returns a fresh `next_nonce` to maintain the chain for subsequent operations.

---

## 2. Multi-Tier Salted Hashing Pipeline

To prevent plaintext password exposure in client memory snapshots, network hops, and server compromises, password verification is split across multiple cryptographic tiers.

```mermaid
flowchart TB
    Raw["Raw User Password"] -->|"Client Side: Web Worker / Wasm"| PreHash["Client Pre-Hash = HMAC-SHA256(RawPassword, ClientSalt + UserIdentifier)"]
    PreHash -->|"Over TLS with Nonce"| Ingress["Server Ingress"]
    Ingress -->|"Server Side: Auth Service"| Argon["Server Multi-Tier Hash = Argon2id(ClientPreHash, ServerSalt, Memory=64MB, Iterations=3, Parallelism=4)"]
    Argon -->|"Persistence: KMS Envelope Encryption"| Cipher["Ciphertext = AES-256-GCM_Encrypt(ServerMultiTierHash, DEK)"]
```

### Advantages:
- **Zero Raw Password on Network**: Even if TLS terminates at an untrusted intermediary or internal proxy, the raw password is never present.
- **Immunity to Database Leaks**: Even if raw DB tables leak, an attacker only gets AES-GCM ciphertext. If DEKs leak, they get Argon2id hashes of client pre-hashes, requiring double brute-force.

---

## 3. Password Versioning & Automatic In-Flight Migration

As cryptographic standards evolve (e.g., from PBKDF2/SHA-256 to Argon2id with increasing memory costs), applications must support multiple password schema versions concurrently without forcing mass password resets.

### Schema Version Registry

| Version | Client Pre-Hash | Server Hash Algorithm | Parameters | Status |
| :--- | :--- | :--- | :--- | :--- |
| `v1` (Legacy) | SHA-256 | PBKDF2-HMAC-SHA256 | Iterations: 100,000 | Deprecated |
| `v2` (Stable) | HMAC-SHA256 | Argon2id | Memory: 64MB, Iter: 3, Parallelism: 4 | Active |
| `v3` (Next-Gen)| HMAC-SHA512 | Argon2id + Pepper (HSM) | Memory: 128MB, Iter: 4, Parallelism: 8 | Target |

### Automated Upgrade State Machine:

```mermaid
stateDiagram-v2
    [*] --> LoginAttempt: Client submits (Identifier, PreHash, Nonce)
    LoginAttempt --> FetchUser: Retrieve User Record & pwd_version
    FetchUser --> VerifyHash: Verify against version-specific algorithm

    state VerifyHash {
        v1_Verify: PBKDF2 Verification
        v2_Verify: Argon2id Verification
        v3_Verify: Argon2id+Pepper Verification
    }

    VerifyHash --> Failed: Verification Failed
    Failed --> [*]: Return 401 Unauthorized

    VerifyHash --> Succeeded: Verification Succeeded
    Succeeded --> CheckVersion: Is pwd_version == LATEST_VERSION (v3)?

    CheckVersion --> IssueSession: Yes (Up to Date)
    CheckVersion --> TriggerRehash: No (Legacy Version Detected)

    TriggerRehash --> ComputeNewHash: Compute new Server Hash under v3
    ComputeNewHash --> EnvelopeEncrypt: Encrypt with new DEK
    EnvelopeEncrypt --> UpdateDB: Atomic Update (hash, pwd_version=v3)
    UpdateDB --> IssueSession: Success
    IssueSession --> [*]: Return 200 OK + Session Cookie
```

### Code Implementation Guidelines:
- The version upgrade must be non-blocking to the user (asynchronous queue or fast inline transaction).
- Version upgrades must log audit events (`AUTH_PASSWORD_VERSION_UPGRADED`) for compliance tracking.
- Client pre-hash versions can be communicated during the nonce preflight phase via headers or preflight metadata (e.g., `X-Auth-Version-Supported: v2,v3`).
