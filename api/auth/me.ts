import type { VercelRequest, VercelResponse } from "../../lib/vercel-types.js";
import { isSessionActive, resolveSessionFromBearer, hasFreshDeviceAttestation } from "../../lib/auth.js";
import { json, methodNotAllowed, serverError, handleOptions } from "../../lib/http.js";

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  if (req.method === "OPTIONS") {
    handleOptions(res, req);
    return;
  }

  if (req.method !== "GET") {
    methodNotAllowed(res, ["GET"], req);
    return;
  }

  try {
    const session = await resolveSessionFromBearer(req, res);
    if (!session) {
      return;
    }

    const [sessionActive, attestationFresh] = await Promise.all([
      isSessionActive(session.sessionJti),
      hasFreshDeviceAttestation(session.userId, session.deviceId)
    ]);

    if (!sessionActive) {
      json(res, 401, { error: "unauthorized" }, req);
      return;
    }

    json(res, 200, {
      authenticated: true,
      userId: session.userId,
      deviceId: session.deviceId,
      attestationFresh
    }, req);
  } catch {
    serverError(res, req);
  }
}
