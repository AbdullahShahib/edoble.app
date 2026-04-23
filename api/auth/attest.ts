import type { VercelRequest, VercelResponse } from "@vercel/node";
import { z } from "zod";
import {
  consumeIntegrityNonce,
  hasFreshDeviceAttestation,
  resolveSessionFromBearer,
  upsertDeviceAttestation
} from "../../lib/auth.js";
import { verifyPlayIntegrityToken } from "../../lib/integrity.js";
import { badRequest, forbidden, json, methodNotAllowed, serverError } from "../../lib/http.js";
import { createIntegrityNonce } from "../../lib/auth.js";
import { writeAuthAudit } from "../../lib/audit.js";

const schema = z.object({
  nonce: z.string().min(10).max(256),
  integrityToken: z.string().min(10)
});

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  if (req.method === "GET") {
    const session = await resolveSessionFromBearer(req, res);
    if (!session) {
      return;
    }

    try {
      const nonce = await createIntegrityNonce(session.email);
      json(res, 200, { nonce, use: "submit_to_play_integrity_then_POST_same_nonce" });
    } catch {
      serverError(res);
    }

    return;
  }

  if (req.method !== "POST") {
    methodNotAllowed(res, ["GET", "POST"]);
    return;
  }

  try {
    const session = await resolveSessionFromBearer(req, res);
    if (!session) {
      return;
    }

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      badRequest(res, "invalid_payload");
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
      forbidden(res, "invalid_nonce");
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
      forbidden(res, "device_integrity_failed");
      return;
    }

    await upsertDeviceAttestation({
      userId: session.userId,
      deviceId: session.deviceId,
      integrityPayload: verdict.raw
    });

    const nowFresh = await hasFreshDeviceAttestation(session.userId, session.deviceId);
    json(res, 200, { ok: nowFresh });
  } catch {
    serverError(res);
  }
}
