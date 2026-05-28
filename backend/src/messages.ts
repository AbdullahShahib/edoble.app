import express from 'express';
import { authMiddleware, requirePermission } from './middleware';
import redis from './redisClient';
import prisma from './db';

const router = express.Router();

router.post('/send', authMiddleware, requirePermission('messages:write'), async (req, res) => {
  const user = (req as any).user;
  const { conversationId, text } = req.body;
  if (!conversationId || !text) return res.status(400).json({ error: 'missing fields' });
  try {
    const msg = await prisma.message.create({
      data: {
        conversationId,
        text,
        fromId: user.sub,
      },
    });
    // publish to Redis channel for fanout to real-time workers
    await redis.publish(`conv:${conversationId}`, JSON.stringify(msg));
    res.json({ ok: true, message: msg });
  } catch (err:any) {
    res.status(500).json({ error: err.message || 'db error' });
  }
});

router.get('/:conversationId', authMiddleware, requirePermission('messages:read'), async (req, res) => {
  const { conversationId } = req.params;
  const page = Number(req.query.page || 0);
  const pageSize = Math.min(Number(req.query.pageSize || 50), 200);
  try {
    const messages = await prisma.message.findMany({
      where: { conversationId },
      orderBy: { createdAt: 'desc' },
      skip: page * pageSize,
      take: pageSize,
    });
    res.json({ messages });
  } catch (err:any) {
    res.status(500).json({ error: err.message || 'db error' });
  }
});

export default router;
