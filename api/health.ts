import type { VercelRequest, VercelResponse } from "../lib/vercel-types.js";

export default function handler(_req: VercelRequest, res: VercelResponse): void {
  res.status(200).json({
    ok: true,
    service: "secure-chat-vercel-backend",
    timestamp: new Date().toISOString()
  });
}
