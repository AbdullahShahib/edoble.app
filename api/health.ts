import type { VercelRequest, VercelResponse } from "../lib/vercel-types.js";
import { json, handleOptions } from "../lib/http.js";

export default function handler(req: VercelRequest, res: VercelResponse): void {
  if (req.method === "OPTIONS") {
    handleOptions(res);
    return;
  }

  res.status(200).json({
    ok: true,
    service: "secure-chat-vercel-backend",
    timestamp: new Date().toISOString()
  });
}
