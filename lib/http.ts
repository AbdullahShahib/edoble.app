import type { VercelRequest, VercelResponse } from "./vercel-types.js";
import { addCorsHeaders, handleCorsPreFlight } from "./cors.js";
import { addSecurityHeaders } from "./security.js";

export function json(res: VercelResponse, status: number, payload: unknown, req?: VercelRequest): void {
  addSecurityHeaders(res);
  addCorsHeaders(res, req);
  res.status(status).setHeader("Content-Type", "application/json").send(JSON.stringify(payload));
}

export function handleOptions(res: VercelResponse, req?: VercelRequest): void {
  addSecurityHeaders(res);
  handleCorsPreFlight(res, req);
}

export function methodNotAllowed(res: VercelResponse, allowed: string[], req?: VercelRequest): void {
  addSecurityHeaders(res);
  addCorsHeaders(res, req);
  res.setHeader("Allow", allowed.join(", "));
  json(res, 405, { error: "method_not_allowed" }, req);
}

export function unauthorized(res: VercelResponse, req?: VercelRequest): void {
  addSecurityHeaders(res);
  addCorsHeaders(res, req);
  json(res, 401, { error: "unauthorized" }, req);
}

export function forbidden(res: VercelResponse, reason?: string, req?: VercelRequest): void {
  addSecurityHeaders(res);
  addCorsHeaders(res, req);
  // Don't expose specific failure reasons
  json(res, 403, { error: "forbidden" }, req);
}

export function badRequest(res: VercelResponse, reason?: string, req?: VercelRequest): void {
  addSecurityHeaders(res);
  addCorsHeaders(res, req);
  // Only show generic error, don't leak validation details
  json(res, 400, { error: "invalid_request" }, req);
}

export function serverError(res: VercelResponse, req?: VercelRequest): void {
  addSecurityHeaders(res);
  addCorsHeaders(res, req);
  // Don't expose internal error details
  json(res, 500, { error: "internal_error" }, req);
}
