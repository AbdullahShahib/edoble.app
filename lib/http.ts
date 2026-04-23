import type { VercelRequest, VercelResponse } from "./vercel-types.js";
import { addCorsHeaders, handleCorsPreFlight } from "./cors.js";

export function json(res: VercelResponse, status: number, payload: unknown): void {
  addCorsHeaders(res);
  res.status(status).setHeader("Content-Type", "application/json").send(JSON.stringify(payload));
}

export function handleOptions(res: VercelResponse): void {
  handleCorsPreFlight(res);
}

export function methodNotAllowed(res: VercelResponse, allowed: string[]): void {
  addCorsHeaders(res);
  res.setHeader("Allow", allowed.join(", "));
  json(res, 405, { error: "method_not_allowed" });
}

export function unauthorized(res: VercelResponse): void {
  json(res, 401, { error: "unauthorized" });
}

export function forbidden(res: VercelResponse, message = "forbidden"): void {
  json(res, 403, { error: message });
}

export function badRequest(res: VercelResponse, message = "bad_request"): void {
  json(res, 400, { error: message });
}

export function serverError(res: VercelResponse): void {
  json(res, 500, { error: "internal_error" });
}
