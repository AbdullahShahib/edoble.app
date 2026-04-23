import type { VercelRequest, VercelResponse } from "@vercel/node";
import { z } from "zod";
import { hasFreshDeviceAttestation, resolveSessionFromBearer } from "../../lib/auth.js";
import { env } from "../../lib/env.js";
import { badRequest, forbidden, json, methodNotAllowed, serverError } from "../../lib/http.js";
import { createDownloadUrl, createUploadUrl } from "../../lib/r2.js";

const schema = z.object({
  action: z.enum(["upload", "download"]),
  objectKey: z.string().min(3).max(512),
  mimeType: z.string().min(3).max(128).optional(),
  sizeBytes: z.number().int().positive().optional()
});

function isKeyAllowedForUser(objectKey: string, userId: number): boolean {
  return objectKey.startsWith(`users/${userId}/`);
}

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  if (req.method !== "POST") {
    methodNotAllowed(res, ["POST"]);
    return;
  }

  try {
    const session = await resolveSessionFromBearer(req, res);
    if (!session) {
      return;
    }

    const hasAttestation = await hasFreshDeviceAttestation(session.userId, session.deviceId);
    if (!hasAttestation) {
      forbidden(res, "stale_or_missing_attestation");
      return;
    }

    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      badRequest(res, "invalid_payload");
      return;
    }

    if (!isKeyAllowedForUser(parsed.data.objectKey, session.userId)) {
      forbidden(res, "invalid_object_scope");
      return;
    }

    if (parsed.data.action === "upload") {
      const mimeType = parsed.data.mimeType;
      const sizeBytes = parsed.data.sizeBytes;
      if (!mimeType || !sizeBytes) {
        badRequest(res, "mimeType_and_size_required");
        return;
      }

      if (!env.allowedMediaMime.has(mimeType)) {
        forbidden(res, "unsupported_media_type");
        return;
      }

      if (sizeBytes > env.MAX_UPLOAD_BYTES) {
        forbidden(res, "file_too_large");
        return;
      }

      const uploadUrl = await createUploadUrl({
        objectKey: parsed.data.objectKey,
        contentType: mimeType,
        contentLength: sizeBytes
      });

      json(res, 200, {
        method: "PUT",
        url: uploadUrl,
        expiresIn: env.R2_PRESIGN_TTL_SECONDS
      });
      return;
    }

    const downloadUrl = await createDownloadUrl({ objectKey: parsed.data.objectKey });
    json(res, 200, {
      method: "GET",
      url: downloadUrl,
      expiresIn: env.R2_PRESIGN_TTL_SECONDS
    });
  } catch {
    serverError(res);
  }
}
