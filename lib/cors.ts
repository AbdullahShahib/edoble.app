import type { VercelResponse } from "./vercel-types.js";

export function addCorsHeaders(res: VercelResponse): VercelResponse {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Max-Age", "86400");
  return res;
}

export function handleCorsPreFlight(res: VercelResponse): void {
  addCorsHeaders(res);
  res.status(200).send("");
}
