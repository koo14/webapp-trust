# Zero-Trust Audit Logging & Threat Detection

Continuous verification in Zero Trust requires end-to-end security observability. Every authentication event, nonce consumption failure, cryptographic downgrade attempt, and session lifecycle change must produce structured, tamper-resistant audit logs.

---

## 1. Standard Audit Event Catalog

| Event Code | Severity | Trigger Condition | Mandatory Attributes |
| :--- | :--- | :--- | :--- |
| `AUTH_LOGIN_SUCCESS` | INFO | Successful authentication. | `user_id`, `pwd_version`, `auth_method`, `client_ip`, `ja3_hash`, `device_bound` |
| `AUTH_TOKEN_ROTATED` | INFO | Access & Refresh Token pair rotated via RTR. | `user_id`, `family_id`, `generation`, `client_ip` |
| `AUTH_NONCE_REPLAY` | WARN | Nonce already consumed or expired. | `attempted_nonce`, `client_ip`, `user_agent`, `target_endpoint` |
| `AUTH_REFRESH_TOKEN_REUSE_DETECTED` | CRITICAL| Rotated/Used refresh token replayed (Breach/Theft). Entire family revoked. | `user_id`, `family_id`, `presented_generation`, `active_generation`, `client_ip` |
| `AUTH_VERSION_DOWNGRADE_ATTEMPT` | ERROR | Client sent payload targeting deprecated version (e.g. v1) when user is v2+. | `user_id`, `attempted_version`, `actual_version`, `client_ip` |
| `AUTH_PASSWORD_VERSION_UPGRADED` | INFO | Credential automatically migrated to higher version. | `user_id`, `old_version`, `new_version`, `duration_ms` |
| `AUTH_DPOP_KEY_MISMATCH` | CRITICAL| DPoP signature key does not match session registered device key (stolen session indicator). | `user_id`, `session_id`, `registered_jwk_thumbprint`, `presented_jwk_thumbprint` |
| `AUTH_DEK_ROTATION` | INFO | DEK re-wrapped under new KEK version. | `user_id`, `old_kek_id`, `new_kek_id` |

---

## 2. Structured Log Schema (OpenTelemetry / JSON)

```json
{
  "timestamp": "2026-08-16T08:27:00.123Z",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "event_type": "AUTH_SECURITY_ALERT",
  "event_code": "AUTH_NONCE_REPLAY",
  "severity": "WARN",
  "actor": {
    "user_id": "a3b2c1d0-0000-0000-0000-000000000001",
    "session_id": "s_8f9e0a1b2c3d4e5f",
    "ip_address": "198.51.100.42",
    "asn": "AS13335",
    "user_agent": "Mozilla/5.0 ...",
    "ja3_fingerprint": "771,4865-4866-4867,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
  },
  "context": {
    "endpoint": "/auth/modify-password",
    "http_method": "POST",
    "presented_nonce": "9a8b7c6d5e4f3a2b1c0d9e8f",
    "failure_reason": "NONCE_ALREADY_CONSUMED"
  },
  "threat_score": 75
}
```

---

## 3. Real-Time SIEM & Anomaly Rule Automation
1. **Nonce Replay Spike Threshold**: >3 duplicate nonces from same IP/Session within 60s triggers temporary IP tarpit / Captcha step-up.
2. **DPoP Thumbprint Invalidation**: Any DPoP signature failure immediately terminates the associated session and flags user credentials for step-up authentication.
