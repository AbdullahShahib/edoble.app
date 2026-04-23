import type { VercelRequest, VercelResponse } from "./vercel-types.js";
import { addRestrictedCorsHeaders } from "./security.js";

/**
 * PRIVATE APP CORS
 * Only allow requests from your startup agency's domains
 * Configure allowed origins in lib/security.ts
 */
export function addCorsHeaders(res: VercelResponse, req?: VercelRequest): VercelResponse {
  const origin = req?.headers["origin"] as string | undefined;
  addRestrictedCorsHeaders(res, origin);
  return res;
}

export function handleCorsPreFlight(res: VercelResponse, req?: VercelRequest): void {
  addCorsHeaders(res, req);
  res.status(200).send("");
}
