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
import { badRequest, forbidden, json, methodNotAllowed, serverError, unauthorized } from "../../lib/http.js";
import { env } from "../../lib/env.js";
import { writeAuthAudit } from "../../lib/audit.js";

const schema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(8).max(128),
  deviceId: z.string().min(8).max(128),
  nonce: z.string().min(10).max(256),
  integrityToken: z.string().min(10)
});

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  if (req.method !== "POST") {
    methodNotAllowed(res, ["POST"]);
    return;
  }

  try {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      badRequest(res, "invalid_payload");
      return;
    }

    const email = parsed.data.email.toLowerCase();
    const nonceOk = await consumeIntegrityNonce(email, parsed.data.nonce);
    if (!nonceOk) {
      await writeAuthAudit({
        email,
        deviceId: parsed.data.deviceId,
        eventType: "login_failure",
        reason: "nonce_invalid_or_expired"
      });
      unauthorized(res);
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
      forbidden(res, "device_integrity_failed");
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
      unauthorized(res);
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
      unauthorized(res);
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
    });
  } catch {
    serverError(res);
  }
}
