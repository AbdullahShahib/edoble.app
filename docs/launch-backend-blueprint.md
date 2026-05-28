# Edoble Launch Backend Blueprint

This repo currently contains the client app only. To make Edoble production-ready, the backend must enforce authentication, authorization, session revocation, and rate limiting server-side.

## 1. Authentication
- Use an identity provider or token issuer that returns short-lived access tokens and rotating refresh tokens.
- Require MFA at the identity layer, not only in the client UI.
- Store only hashed refresh-token identifiers server-side for revocation.

## 2. Authorization
- Enforce RBAC on every API route.
- Map roles to explicit permissions, such as:
  - `chat:read`
  - `contact:read`
  - `settings:read`
  - `settings:write`
  - `admin:access`
  - `admin:dashboard:read`
  - `admin:users:read`
  - `admin:audit:read`
- Validate authorization in middleware before any business logic runs.

## 3. Session management
- Issue access tokens with a short TTL, typically 10 to 15 minutes.
- Rotate refresh tokens on use.
- Support immediate revocation through a session blacklist or token-version check.
- Track absolute session age separately from idle timeout.

## 4. Rate limiting and lockout
- Put login, MFA, password reset, and admin endpoints behind Redis-backed rate limiting.
- Rate-limit by user ID, IP, device fingerprint, and tenant where applicable.
- Return generic auth errors to avoid account enumeration.

## 5. Caching and performance
- Use Redis for hot session metadata, permission lookup, and throttling counters.
- Cache read-heavy, low-risk data with strict cache keys and short TTLs.
- Add DB indexes for:
  - user lookup by email
  - conversation lookup by tenant and timestamp
  - audit log lookup by actor and time range
- Use pagination for all list endpoints.

## 6. Static asset delivery
- Serve stitched media and public assets through a CDN.
- Set immutable cache headers for fingerprinted assets.
- Keep sensitive uploads private and signed.

## 7. Observability and audit
- Log auth events, MFA challenges, token refresh, role changes, and revocations.
- Emit structured logs with request IDs and tenant IDs.
- Build an audit log UI backed by a write-only audit table.

## 8. Launch blockers still unresolved in this repo
- No backend credential verification exists yet.
- No server-side RBAC enforcement exists yet.
- npm audit reports transitive Expo-related vulnerabilities that require a breaking Expo upgrade to clear fully.

## 9. Recommended launch order
1. Implement the token issuer and session store.
2. Enforce auth and RBAC in middleware.
3. Add Redis rate limiting and revocation.
4. Wire the client to real auth endpoints.
5. Add CDN and cache headers.
6. Upgrade Expo and dependencies in a controlled branch.
