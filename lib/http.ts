import type { VercelResponse } from "./vercel-types.js";

export function json(res: VercelResponse, status: number, payload: unknown): void {
  res.status(status).setHeader("Content-Type", "application/json").send(JSON.stringify(payload));
}

export function methodNotAllowed(res: VercelResponse, allowed: string[]): void {
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
