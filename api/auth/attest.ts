import type { VercelRequest, VercelResponse } from "../../lib/vercel-types.js";
import { z } from "zod";
import {
  consumeIntegrityNonce,
  hasFreshDeviceAttestation,
  resolveSessionFromBearer,
  upsertDeviceAttestation
} from "../../lib/auth.js";
import { verifyPlayIntegrityToken } from "../../lib/integrity.js";
import { badRequest, forbidden, json, methodNotAllowed, serverError, handleOptions } from "../../lib/http.js";
import { createIntegrityNonce } from "../../lib/auth.js";
import { writeAuthAudit } from "../../lib/audit.js";
import { validateNonce } from "../../lib/security.js";

const schema = z.object({
  nonce: z.string().min(24).max(512),
  integrityToken: z.string().min(10)
});

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  if (req.method === "OPTIONS") {
    handleOptions(res, req);
    return;
  }

  if (req.method === "GET") {
    const session = await resolveSessionFromBearer(req, res);
    if (!session) {
      return;
    }

    try {
      const nonce = await createIntegrityNonce(session.email);
      json(res, 200, { nonce, use: "submit_to_play_integrity_then_POST_same_nonce" }, req);
    } catch {
      serverError(res, req);
    }

    return;
  }

  if (req.method !== "POST") {
    methodNotAllowed(res, ["GET", "POST"], req);
    return;
  }

  try {
    const session = await resolveSessionFromBearer(req, res);
    if (!session) {
      return;
    }

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      badRequest(res, undefined, req);
      return;
    }

    // Validate nonce format
    if (!validateNonce(parsed.data.nonce)) {
      badRequest(res, undefined, req);
      return;
    }

    const nonceOk = await consumeIntegrityNonce(session.email, parsed.data.nonce);
    if (!nonceOk) {
      await writeAuthAudit({
        email: session.email,
        deviceId: session.deviceId,
        eventType: "integrity_failure",
        reason: "attestation_nonce_invalid_or_expired"
      });
      forbidden(res, undefined, req);
      return;
    }

    const verdict = await verifyPlayIntegrityToken(parsed.data.integrityToken, parsed.data.nonce);
    if (!(verdict.nonceMatches && verdict.packageMatches && verdict.appRecognized && verdict.deviceRecognized && verdict.licensed)) {
      await writeAuthAudit({
        email: session.email,
        deviceId: session.deviceId,
        eventType: "integrity_failure",
        reason: "attestation_refresh_failed"
      });
      forbidden(res, undefined, req);
      return;
    }

    await upsertDeviceAttestation({
      userId: session.userId,
      deviceId: session.deviceId,
      integrityPayload: verdict.raw
    });

    const nowFresh = await hasFreshDeviceAttestation(session.userId, session.deviceId);
    json(res, 200, { ok: nowFresh }, req);
  } catch {
    serverError(res, req);
  }
}
