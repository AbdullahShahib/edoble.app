# Phase 1: Database Schema + Vercel Secure Auth Logic

## Objective
Implement Zero-Trust access for a high-security chat system by enforcing:
- no public signup,
- pre-authorized email-only login,
- device and app integrity attestation,
- short-lived server-side session tokens,
- 5-minute Cloudflare R2 pre-signed URLs.

## API Endpoints
- `POST /api/auth/challenge`
  - Input: `{ email }`
  - Output: `{ nonce }`
  - Purpose: issue nonce for Google Play Integrity token generation.
- `POST /api/auth/login`
  - Input: `{ email, password, deviceId, nonce, integrityToken }`
  - Output: `{ accessToken, tokenType, expiresIn }`
  - Checks: nonce replay protection, Play Integrity, authorized_users membership, password hash.
- `GET /api/auth/attest`
  - Auth required.
  - Output: `{ nonce }` for periodic re-attestation.
- `POST /api/auth/attest`
  - Auth required.
  - Input: `{ nonce, integrityToken }`
  - Output: `{ ok }`
  - Purpose: refresh active device attestation window.
- `POST /api/media/presign`
  - Auth + fresh attestation required.
  - Input: `upload|download`, scoped object key, upload metadata.
  - Output: 5-minute pre-signed URL.

## Database Tables
Defined in [sql/001_phase1_core.sql](../sql/001_phase1_core.sql).
- `authorized_users`: allow-list identities only.
- `integrity_nonces`: anti-replay nonce records.
- `auth_sessions`: short-lived JWT-linked sessions.
- `device_attestations`: attestation validity per device.
- `auth_audit_log`: security audit events.

## Security Controls in This Phase
- Strict allow-list login with `authorized_users`.
- No signup endpoint exists.
- Integrity token checks include nonce match, package match, app recognition, device integrity, and licensing.
- Nonce is one-time-use (`consumed_at`) with TTL.
- Media object key scope is constrained to `users/{userId}/...`.
- R2 credentials never leave backend.

## OWASP Top 10 Self-Audit (Phase 1)
1. A01 Broken Access Control: mitigated via JWT session validation, object-key scope enforcement, allow-list login.
2. A02 Cryptographic Failures: no plaintext passwords (bcrypt compare), short JWT expiry, HTTPS-only expected in Vercel.
3. A03 Injection: all SQL uses parameterized statements (`?` placeholders), no string concatenation with user data.
4. A04 Insecure Design: Zero-Trust flow requires both identity and verified app/device integrity.
5. A05 Security Misconfiguration: environment-validated startup fails closed when secrets missing.
6. A06 Vulnerable Components: dependency pinning present, but SCA (npm audit/Snyk) still required in CI.
7. A07 Identification and Authentication Failures: no signup path, account status check, nonce anti-replay.
8. A08 Software and Data Integrity Failures: Play Integrity blocks sideloaded/tampered builds.
9. A09 Security Logging and Monitoring Failures: auth and integrity events logged in `auth_audit_log`.
10. A10 SSRF: no user-supplied URL fetching implemented in this phase.

## Hardcoded Credentials Check
- No hardcoded DB, JWT, Google, or R2 credentials in source files.
- All sensitive values expected from runtime environment variables.

## Bypass Check: APK Without Authorized Credentials
A user with only the APK cannot fetch protected data because:
- login requires email present in `authorized_users`,
- login requires valid password hash match,
- login requires valid Play Integrity verdict,
- protected endpoints require valid bearer token and fresh attestation,
- media pre-sign endpoint enforces per-user object-key scope.

## Deployment Notes
- Restrict MySQL network ACLs to trusted origin.
- Rotate JWT and R2 secrets periodically.
- Add rate limiting and lockout controls at API gateway or edge middleware in next hardening pass.
