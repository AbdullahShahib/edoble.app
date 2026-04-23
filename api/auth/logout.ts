import type { VercelRequest, VercelResponse } from "../../lib/vercel-types.js";
import { resolveSessionFromBearer, revokeSession } from "../../lib/auth.js";
import { badRequest, json, methodNotAllowed, serverError, handleOptions } from "../../lib/http.js";
import { writeAuthAudit } from "../../lib/audit.js";

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
    const session = await resolveSessionFromBearer(req, res);
    if (!session) {
      return;
    }

    const revoked = await revokeSession(session.sessionJti);
    if (!revoked) {
      badRequest(res, undefined, req);
      return;
    }

    await writeAuthAudit({
      email: session.email,
      deviceId: session.deviceId,
      eventType: "logout_success"
    });

    json(res, 200, { ok: true }, req);
  } catch {
    serverError(res, req);
  }
}
