import { z } from "zod";

const envSchema = z.object({
  MYSQL_HOST: z.string().min(1),
  MYSQL_PORT: z.coerce.number().int().positive().default(3306),
  MYSQL_USER: z.string().min(1),
  MYSQL_PASSWORD: z.string().min(1),
  MYSQL_DATABASE: z.string().min(1),

  JWT_ISSUER: z.string().min(1),
  JWT_AUDIENCE: z.string().min(1),
  JWT_SECRET: z.string().min(32),
  JWT_EXPIRES_SECONDS: z.coerce.number().int().positive().default(900),

  GOOGLE_APPLICATION_CREDENTIALS_JSON: z.string().min(1),
  GOOGLE_PLAY_PACKAGE_NAME: z.string().min(1),
  INTEGRITY_NONCE_TTL_SECONDS: z.coerce.number().int().positive().default(300),
  INTEGRITY_ATTEST_TTL_SECONDS: z.coerce.number().int().positive().default(600),

  R2_ACCOUNT_ID: z.string().min(1),
  R2_ACCESS_KEY_ID: z.string().min(1),
  R2_SECRET_ACCESS_KEY: z.string().min(1),
  R2_BUCKET: z.string().min(1),
  R2_PUBLIC_BASE_URL: z.string().url(),
  R2_PRESIGN_TTL_SECONDS: z.coerce.number().int().positive().max(300).default(300),

  ALLOWED_MEDIA_MIME: z.string().min(1),
  MAX_UPLOAD_BYTES: z.coerce.number().int().positive().default(10485760)
});

const parsed = envSchema.safeParse(process.env);
if (!parsed.success) {
  throw new Error(`Invalid environment: ${parsed.error.message}`);
}

export const env = {
  ...parsed.data,
  allowedMediaMime: new Set(
    parsed.data.ALLOWED_MEDIA_MIME.split(",").map((v) => v.trim()).filter(Boolean)
  )
};
