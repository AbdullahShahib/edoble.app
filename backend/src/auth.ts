import express from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import redis from './redisClient';
import dotenv from 'dotenv';
import prisma from './db';

dotenv.config();

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const ACCESS_TTL = Number(process.env.ACCESS_TOKEN_TTL_SECONDS || 300);
const REFRESH_TTL = Number(process.env.REFRESH_TOKEN_TTL_SECONDS || 60 * 60 * 24 * 14);

function hashToken(token: string) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

router.post('/login', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'username required' });
  // upsert user
  const user = await prisma.user.upsert({
    where: { username },
    update: {},
    create: { username },
  });
  const userId = user.id;
  const permissions = ['messages:read', 'messages:write', 'media:upload'];

  const accessToken = jwt.sign({ sub: userId, permissions }, JWT_SECRET, { expiresIn: ACCESS_TTL });

  const refreshToken = uuidv4();
  const refreshHash = hashToken(refreshToken);
  const expiresAt = new Date(Date.now() + REFRESH_TTL * 1000);
  // store refresh token in DB for strong revocation + audit
  await prisma.refreshToken.create({ data: { tokenHash: refreshHash, userId, expiresAt } });
  // keep quick lookup in Redis too for speed
  await redis.set(`refresh:${userId}:${refreshHash}`, '1', 'EX', REFRESH_TTL);

  // set refresh token as HttpOnly secure cookie (rotation will update it)
  const cookieOptions: any = {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE !== 'false',
    sameSite: 'strict',
    maxAge: REFRESH_TTL * 1000,
    path: '/auth',
  };
  if (process.env.COOKIE_DOMAIN) cookieOptions.domain = process.env.COOKIE_DOMAIN;
  res.cookie('refreshToken', refreshToken, cookieOptions);

  res.json({ accessToken, expiresIn: ACCESS_TTL, permissions });
});

router.post('/refresh', async (req, res) => {
  // read refresh token from HttpOnly cookie
  const cookieToken = (req as any).cookies?.refreshToken;
  const accessToken = req.body?.accessToken;
  if (!cookieToken) return res.status(400).json({ error: 'refreshToken cookie required' });

  const refreshToken = cookieToken;
  const refreshHash = hashToken(refreshToken);
  // check DB for refresh token
  const tokenRow = await prisma.refreshToken.findUnique({ where: { tokenHash: refreshHash } });
  if (!tokenRow || tokenRow.revoked) return res.status(401).json({ error: 'invalid refresh token' });

  // derive userId either from provided access token or from the refresh token DB row
  const decoded: any = jwt.decode(accessToken) || {};
  const userId = decoded.sub || tokenRow.userId;

  // Rotate: revoke old, create new
  await prisma.refreshToken.update({ where: { id: tokenRow.id }, data: { revoked: true } });
  const newRefresh = uuidv4();
  const newHash = hashToken(newRefresh);
  const expiresAt = new Date(Date.now() + REFRESH_TTL * 1000);
  await prisma.refreshToken.create({ data: { tokenHash: newHash, userId, expiresAt } });
  // update Redis fast-path
  await redis.del(`refresh:${userId}:${refreshHash}`);
  await redis.set(`refresh:${userId}:${newHash}`, '1', 'EX', REFRESH_TTL);

  const permissions = decoded.permissions || ['messages:read', 'messages:write', 'media:upload'];
  const newAccess = jwt.sign({ sub: userId, permissions }, JWT_SECRET, { expiresIn: ACCESS_TTL });

  // set rotated refresh token cookie
  const cookieOptions: any = {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE !== 'false',
    sameSite: 'strict',
    maxAge: REFRESH_TTL * 1000,
    path: '/auth',
  };
  if (process.env.COOKIE_DOMAIN) cookieOptions.domain = process.env.COOKIE_DOMAIN;
  res.cookie('refreshToken', newRefresh, cookieOptions);

  res.json({ accessToken: newAccess, expiresIn: ACCESS_TTL });
});

router.post('/logout', async (req, res) => {
  const accessToken = req.body?.accessToken || (req.headers.authorization || '').split(' ')[1];
  // decode and remove all refresh tokens for user
  const decoded: any = jwt.decode(accessToken) || {};
  const userId = decoded.sub;
  if (userId) {
    // revoke DB tokens for user
    await prisma.refreshToken.updateMany({ where: { userId }, data: { revoked: true } });
    const keys = await redis.keys(`refresh:${userId}:*`);
    if (keys.length) await redis.del(...keys);
  }
  // clear cookie
  res.clearCookie('refreshToken', { path: '/auth', domain: process.env.COOKIE_DOMAIN || undefined });
  res.json({ ok: true });
});

export default router;
