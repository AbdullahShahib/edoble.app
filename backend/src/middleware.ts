import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import redis from './redisClient';
import dotenv from 'dotenv';

dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

export interface AuthedRequest extends Request {
  user?: { sub: string; permissions: string[] };
}

export async function authMiddleware(req: AuthedRequest, res: Response, next: NextFunction) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'no auth' });
  const parts = auth.split(' ');
  if (parts.length !== 2) return res.status(401).json({ error: 'malformed' });
  const token = parts[1];
  try {
    const payload: any = jwt.verify(token, JWT_SECRET);
    // check session revocation in Redis (simple pattern)
    const revoked = await redis.get(`revoked:${payload.sub}`);
    if (revoked) return res.status(401).json({ error: 'session revoked' });
    req.user = { sub: payload.sub, permissions: payload.permissions || [] };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid token' });
  }
}

export function requirePermission(permission: string) {
  return (req: AuthedRequest, res: Response, next: NextFunction) => {
    const p = req.user?.permissions || [];
    if (p.includes(permission)) return next();
    return res.status(403).json({ error: 'forbidden' });
  };
}

export async function rateLimit(req: Request, res: Response, next: NextFunction) {
  try {
    const key = `rl:${req.ip}`;
    const current = await redis.incr(key);
    if (current === 1) await redis.expire(key, 1);
    if (current > 30) return res.status(429).json({ error: 'rate limited' });
    next();
  } catch (err) {
    next();
  }
}
