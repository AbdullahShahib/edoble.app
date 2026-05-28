**Security hardening checklist and notes**

Implemented in this repo:

- Server-side auth service with JWT access tokens and rotating refresh tokens persisted in DB (`Prisma` + `RefreshToken` model).
- Redis fast-path for refresh token lookups and pub/sub for messaging fanout.
- Helmet and global rate limiter added to Express server (`src/index.ts`) to apply secure headers and basic DDoS protection.
- Input validation points and content-type checks recommended for file uploads.
- Cloudflare R2 support for S3-compatible object storage with presigned uploads.

Recommended next steps (priority order):

1. Move refresh tokens to HttpOnly, Secure cookies in production to reduce XSS theft risk.
2. Add strict CORS origins list instead of allowing all origins.
3. Add Content Security Policy (CSP) tuned for your frontend.
4. Add SCA and secret scanning to CI (Dependabot, CodeQL, trufflehog) and fail PRs with critical vulnerabilities.
5. Add Sentry for server error monitoring and integrate with alerting.
6. Enforce TLS at load balancer and HSTS header on CDN.
7. Implement per-account adaptive rate limiting and CAPTCHA challenges for suspicious login attempts.
8. Add penetration testing and scheduled dependency upgrade windows.
