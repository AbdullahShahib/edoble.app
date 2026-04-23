import type { VercelRequest, VercelResponse } from "@vercel/node";
import { isSessionActive, resolveSessionFromBearer, hasFreshDeviceAttestation } from "../../lib/auth.js";
import { json, methodNotAllowed, serverError } from "../../lib/http.js";

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  if (req.method !== "GET") {
    methodNotAllowed(res, ["GET"]);
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
      json(res, 401, { error: "unauthorized" });
      return;
    }

    json(res, 200, {
      authenticated: true,
      userId: session.userId,
      deviceId: session.deviceId,
      attestationFresh
    });
  } catch {
    serverError(res);
  }
}
