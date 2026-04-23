import type { VercelRequest, VercelResponse } from "@vercel/node";
import { z } from "zod";
import { createIntegrityNonce } from "../../lib/auth.js";
import { writeAuthAudit } from "../../lib/audit.js";
import { env } from "../../lib/env.js";
import { badRequest, methodNotAllowed, serverError, json } from "../../lib/http.js";

const schema = z.object({
  email: z.string().email().max(254)
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
    const nonce = await createIntegrityNonce(email);
    await writeAuthAudit({ email, eventType: "challenge_issued" });
    json(res, 200, { nonce, nonceTtlSeconds: env.INTEGRITY_NONCE_TTL_SECONDS });
  } catch {
    serverError(res);
  }
}
