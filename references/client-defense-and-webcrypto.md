# Client-Side Defense, Web Crypto & Memory Sandboxing

In a Zero-Trust client architecture, the browser runtime is treated as an untrusted, multi-tenant environment susceptible to memory inspection, prototype pollution, XSS probing, and side-channel timing attacks.

---

## 1. Web Crypto API Non-Extractable Keys

Modern web applications must protect cryptographic private keys and symmetric keys from JavaScript runtime inspection by leveraging native browser security sandboxes.

### Core Principle:
- When generating (`SubtleCrypto.generateKey()`) or importing (`SubtleCrypto.importKey()`) cryptographic keys, the `extractable` parameter **MUST** be explicitly set to `false`.
- Once marked non-extractable:
  1. The raw private key bytes reside entirely inside the browser's C++/Rust native cryptographic subsystem or OS keychain.
  2. JavaScript receives only an opaque `CryptoKey` reference handle.
  3. Calling `crypto.subtle.exportKey()` throws a `DOMException (InvalidAccessError)`.
  4. Even if an attacker executes arbitrary JavaScript in the page (via XSS or malicious extensions), they **cannot export or dump the raw private key**.

```typescript
// Key generation with extractable: false
const keyPair = await window.crypto.subtle.generateKey(
  {
    name: "ECDSA",
    namedCurve: "P-256",
  },
  false, // CRITICAL: Non-extractable private key
  ["sign", "verify"]
);

// JavaScript can sign data:
const signature = await window.crypto.subtle.sign(
  { name: "ECDSA", hash: { name: "SHA-256" } },
  keyPair.privateKey,
  dataBuffer
);

// Attempting to export throws an error:
try {
  await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
} catch (e) {
  // Throws DOMException: Key is not extractable
}
```

---

## 2. WebAssembly Deterministic Linear Memory Management

JavaScript objects and strings are subject to automatic garbage collection (GC), meaning raw password strings and decrypted tokens may linger indeterminately across multiple memory heap generations, exposed to heap profiling, memory snapshots, or cold-boot inspections.

### Solution: WebAssembly Sandboxed Memory
- High-security cryptographic operations (e.g., Argon2 hashing, key derivation, signature verification) are executed in a compiled WebAssembly module.
- **Wasm Linear Memory (`WebAssembly.Memory`)**:
  - Provides a contiguous, fixed byte array managed directly via byte offsets.
  - Allows deterministic, instantaneous memory wiping immediately after calculations.
  - Wasm memory does not suffer from JavaScript engine string intern caching.

```typescript
// Conceptual Wasm zeroing workflow
class WasmSecureBuffer {
  private memory: WebAssembly.Memory;
  private pointer: number;
  private length: number;

  constructor(size: number, memory: WebAssembly.Memory, allocFn: (size: number) => number) {
    this.memory = memory;
    this.length = size;
    this.pointer = allocFn(size);
  }

  public getBuffer(): Uint8Array {
    return new Uint8Array(this.memory.buffer, this.pointer, this.length);
  }

  public wipe(): void {
    // Overwrite the deterministic linear memory space
    const view = new Uint8Array(this.memory.buffer, this.pointer, this.length);
    view.fill(0);
  }
}
```

---

## 3. Explicit Memory Scrubbing & Dereferencing in JavaScript

For sensitive byte sequences that must temporarily pass through JavaScript (e.g., user PIN, OTP inputs, transient HMAC digests):

1. **Avoid String Types**: Strings are immutable in JavaScript and cannot be zeroed in-place. Always represent sensitive inputs as `Uint8Array` or `ArrayBuffer`.
2. **Explicit Overwrite (`.fill(0)`)**: Immediately upon completing the cryptographic operation or network transmission, overwrite every byte with zeros.
3. **Nullify References**: Set buffer variables to `null` to sever references and allow GC reclamation.

```typescript
function processTransientSecret(secretBytes: Uint8Array): void {
  try {
    // Perform cryptographic operation
    computeHash(secretBytes);
  } finally {
    // Guarantee memory scrubbing even if an exception occurs
    secretBytes.fill(0);
  }
}
```

---

## 4. Web Worker Task Sandboxing

Isolate sensitive cryptographic and authentication workloads from the main UI thread.

- **Benefits**:
  - Eliminates DOM access in the execution thread.
  - Restricts malicious UI library prototype modifications from intercepting cryptographic operations.
  - Workers can be terminated (`worker.terminate()`) at the end of an auth transaction, instantly discarding their entire execution environment and V8 isolate memory.

---

## 5. Defense Against Side-Channel Timing Attacks: Cross-Origin Isolation

Modern browsers provide high-precision timers (`performance.now()`, `SharedArrayBuffer`) which can be exploited for microarchitectural cache timing (Spectre-style) attacks to infer secret key materials.

### Mandatory HTTP Response Headers:
```http
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

- **COOP (`same-origin`)**: Ensures the browsing context is isolated in its own top-level process, preventing other windows/tabs from accessing DOM handles.
- **COEP (`require-corp`)**: Prevents the document from loading cross-origin subresources unless explicitly permitted via CORS or `Cross-Origin-Resource-Policy`.

---

## 6. Eradicating XSS Memory Probing: CSP & Trusted Types

To prevent malicious scripts from tampering with authentication logic or injecting DOM sinks:

### 1. Trusted Types Enforcement:
Require that all sinks (e.g., `innerHTML`, `script.src`) accept only typed, validated objects rather than arbitrary strings.

```http
Content-Security-Policy: require-trusted-types-for 'script'; trusted-types default authPolicy;
```

```typescript
// Define policy in initialization script
if (window.trustedTypes && window.trustedTypes.createPolicy) {
  window.trustedTypes.createPolicy('authPolicy', {
    createHTML: (string) => sanitizeHtml(string),
    createScriptURL: (url) => (isAllowedDomain(url) ? url : null),
  });
}
```

### 2. Strict Content Security Policy (CSP):
- Ban `eval()` and inline scripts without cryptographic nonces.
- Restrict connect targets strictly to your BFF API gateway.
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-RANDOM_NONCE' 'strict-dynamic'; connect-src 'self' https://api.yourdomain.com; object-src 'none'; base-uri 'none';
```
