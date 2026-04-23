import type { VercelRequest, VercelResponse } from "../../lib/vercel-types.js";
import { z } from "zod";
import {
  consumeIntegrityNonce,
  createSession,
  findAuthorizedUserByEmail,
  upsertDeviceAttestation,
  verifyPassword
} from "../../lib/auth.js";
import { signAccessToken } from "../../lib/jwt.js";
import { verifyPlayIntegrityToken } from "../../lib/integrity.js";
import { badRequest, forbidden, json, methodNotAllowed, serverError, unauthorized, handleOptions } from "../../lib/http.js";
import { env } from "../../lib/env.js";
import { writeAuthAudit } from "../../lib/audit.js";
import {
  checkRateLimit,
  sanitizeEmail,
  validateDeviceId,
  validateNonce,
  recordFailedLoginAttempt
} from "../../lib/security.js";

const schema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(12).max(128),
  deviceId: z.string().min(32).max(128),
  nonce: z.string().min(24).max(512),
  integrityToken: z.string().min(10)
});

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  if (req.method === "OPTIONS") {
    handleOptions(res, req);
    return;
  }

  if (req.method !== "POST") {
    methodNotAllowed(res, ["POST"], req);
    return;
  }

  try {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      badRequest(res, undefined, req);
      return;
    }

    const email = sanitizeEmail(parsed.data.email);
    if (!email) {
      badRequest(res, undefined, req);
      return;
    }

    // Validate device ID format (prevent spoofing)
    if (!validateDeviceId(parsed.data.deviceId)) {
      badRequest(res, undefined, req);
      return;
    }

    // Validate nonce format
    if (!validateNonce(parsed.data.nonce)) {
      badRequest(res, undefined, req);
      return;
    }

    // Rate limit: max 5 login attempts per 15 minutes per email
    const rateLimit = await checkRateLimit(`login:${email}`, 5, 900);
    if (!rateLimit.allowed) {
      json(res, 429, {
        error: "rate_limited",
        retryAfterSeconds: rateLimit.resetSeconds
      }, req);
      return;
    }

    // Check account lockout (5+ failed attempts in last hour)
    const lockout = await recordFailedLoginAttempt(email);
    if (lockout.locked) {
      json(res, 423, {
        error: "account_locked",
        message: "Too many failed attempts. Try again in 1 hour."
      }, req);
      return;
    }

    const nonceOk = await consumeIntegrityNonce(email, parsed.data.nonce);
    if (!nonceOk) {
      await writeAuthAudit({
        email,
        deviceId: parsed.data.deviceId,
        eventType: "login_failure",
        reason: "nonce_invalid_or_expired"
      });
      unauthorized(res, req);
      return;
    }

    const verdict = await verifyPlayIntegrityToken(parsed.data.integrityToken, parsed.data.nonce);
    if (!(verdict.nonceMatches && verdict.packageMatches && verdict.appRecognized && verdict.deviceRecognized && verdict.licensed)) {
      await writeAuthAudit({
        email,
        deviceId: parsed.data.deviceId,
        eventType: "integrity_failure",
        reason: "play_integrity_verdict_failed"
      });
      forbidden(res, undefined, req);
      return;
    }

    const user = await findAuthorizedUserByEmail(email);
    if (!user || user.status !== "active") {
      await writeAuthAudit({
        email,
        deviceId: parsed.data.deviceId,
        eventType: "login_failure",
        reason: "user_not_authorized"
      });
      unauthorized(res, req);
      return;
    }

    const passwordOk = await verifyPassword(parsed.data.password, user.password_hash);
    if (!passwordOk) {
      await writeAuthAudit({
        email,
        deviceId: parsed.data.deviceId,
        eventType: "login_failure",
        reason: "invalid_password"
      });
      unauthorized(res, req);
      return;
    }

    const session = await createSession({
      userId: user.id,
      deviceId: parsed.data.deviceId,
      ipAddress: req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() ?? null,
      userAgent: Array.isArray(req.headers["user-agent"])
        ? req.headers["user-agent"][0] ?? null
        : req.headers["user-agent"] ?? null
    });

    await upsertDeviceAttestation({
      userId: user.id,
      deviceId: parsed.data.deviceId,
      integrityPayload: verdict.raw
    });

    const token = await signAccessToken({
      sub: String(user.id),
      sid: session.jti,
      did: parsed.data.deviceId,
      email
    });

    await writeAuthAudit({
      email,
      deviceId: parsed.data.deviceId,
      eventType: "login_success"
    });

    json(res, 200, {
      accessToken: token,
      tokenType: "Bearer",
      expiresIn: env.JWT_EXPIRES_SECONDS
    }, req);
  } catch {
    serverError(res, req);
  }
}
