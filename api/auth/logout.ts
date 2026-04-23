import type { VercelRequest, VercelResponse } from "@vercel/node";
import { resolveSessionFromBearer, revokeSession } from "../../lib/auth.js";
import { badRequest, json, methodNotAllowed, serverError } from "../../lib/http.js";
import { writeAuthAudit } from "../../lib/audit.js";

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  if (req.method !== "POST") {
    methodNotAllowed(res, ["POST"]);
    return;
  }

  try {
    const session = await resolveSessionFromBearer(req, res);
    if (!session) {
      return;
    }

    const revoked = await revokeSession(session.sessionJti);
    if (!revoked) {
      badRequest(res, "session_not_revoked");
      return;
    }

    await writeAuthAudit({
      email: session.email,
      deviceId: session.deviceId,
      eventType: "logout_success"
    });

    json(res, 200, { ok: true });
  } catch {
    serverError(res);
  }
}
