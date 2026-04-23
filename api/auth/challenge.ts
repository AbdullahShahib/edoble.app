import type { VercelRequest, VercelResponse } from "../../lib/vercel-types.js";
import { z } from "zod";
import { createIntegrityNonce } from "../../lib/auth.js";
import { writeAuthAudit } from "../../lib/audit.js";
import { env } from "../../lib/env.js";
import { badRequest, methodNotAllowed, serverError, json, handleOptions } from "../../lib/http.js";
import { checkRateLimit, sanitizeEmail } from "../../lib/security.js";

const schema = z.object({
  email: z.string().email().max(254)
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

    // Rate limit: max 10 challenge requests per 15 minutes
    const rateLimit = await checkRateLimit(`challenge:${email}`, 10, 900);
    if (!rateLimit.allowed) {
      json(res, 429, {
        error: "rate_limited",
        retryAfterSeconds: rateLimit.resetSeconds
      }, req);
      return;
    }

    const nonce = await createIntegrityNonce(email);
    await writeAuthAudit({ email, eventType: "challenge_issued" });
    json(res, 200, { nonce, nonceTtlSeconds: env.INTEGRITY_NONCE_TTL_SECONDS }, req);
  } catch {
    serverError(res, req);
  }
}
