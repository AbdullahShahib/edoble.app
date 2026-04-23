import { GetObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { env } from "./env.js";

const r2Client = new S3Client({
  region: "auto",
  endpoint: `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: env.R2_ACCESS_KEY_ID,
    secretAccessKey: env.R2_SECRET_ACCESS_KEY
  }
});

export async function createUploadUrl(input: {
  objectKey: string;
  contentType: string;
  contentLength: number;
}): Promise<string> {
  const command = new PutObjectCommand({
    Bucket: env.R2_BUCKET,
    Key: input.objectKey,
    ContentType: input.contentType,
    ContentLength: input.contentLength
  });

  return await getSignedUrl(r2Client, command, { expiresIn: env.R2_PRESIGN_TTL_SECONDS });
}

export async function createDownloadUrl(input: { objectKey: string }): Promise<string> {
  const command = new GetObjectCommand({
    Bucket: env.R2_BUCKET,
    Key: input.objectKey
  });

  return await getSignedUrl(r2Client, command, { expiresIn: env.R2_PRESIGN_TTL_SECONDS });
}
