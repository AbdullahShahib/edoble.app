import express from 'express';
import AWS from 'aws-sdk';
import { authMiddleware, requirePermission } from './middleware';
import dotenv from 'dotenv';
import express from 'express';

dotenv.config();

const router = express.Router();

// Support AWS S3 and Cloudflare R2 (S3-compatible) via env configuration
const useR2 = Boolean(process.env.R2_ACCOUNT_ID);
let s3: AWS.S3;
if (useR2) {
  const endpoint = process.env.R2_ENDPOINT || `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
  const creds = {
    accessKeyId: process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  } as any;
  const cfg: AWS.S3.ClientConfiguration = {
    endpoint: new AWS.Endpoint(endpoint),
    region: process.env.AWS_REGION || 'auto',
    signatureVersion: 'v4',
    s3ForcePathStyle: false,
    ...creds,
  };
  s3 = new AWS.S3(cfg);
} else {
  s3 = new AWS.S3({ region: process.env.AWS_REGION });
}

const BUCKET = process.env.S3_BUCKET || process.env.R2_BUCKET || '';

router.post('/presign', authMiddleware, requirePermission('media:upload'), async (req, res) => {
  const { filename, contentType } = req.body;
  if (!filename || !contentType) return res.status(400).json({ error: 'missing' });
  const key = `uploads/${Date.now()}-${filename}`;
  const params: AWS.S3.PutObjectRequest & { Expires?: number } = { Bucket: BUCKET, Key: key, ContentType: contentType, Expires: 60 } as any;
  try {
    // AWS SDK v2 supports getSignedUrlPromise for both S3 and R2-compatible endpoints
    const url = await s3.getSignedUrlPromise('putObject', params as any);
    res.json({ url, key, provider: useR2 ? 'r2' : 's3' });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 's3 error' });
  }
});

export default router;
