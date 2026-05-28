import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import dotenv from 'dotenv';
import authRoutes from './auth';
import messagesRoutes from './messages';
import mediaRoutes from './media';
import { rateLimit } from './middleware';
import helmet from 'helmet';
import rateLimitLib from 'express-rate-limit';
import cookieParser from 'cookie-parser';

dotenv.config();
const app = express();
app.use(helmet());
// global rate limiter (tunable)
const globalLimiter = rateLimitLib({ windowMs: 1000, max: 1000 });
app.use(globalLimiter);
app.use(cookieParser());

const corsOptions: any = { origin: process.env.CORS_ORIGIN || true, credentials: true };
app.use(cors(corsOptions));
app.use(bodyParser.json());

app.use(rateLimit);

app.use('/auth', authRoutes);
app.use('/messages', messagesRoutes);
app.use('/media', mediaRoutes);

app.get('/health', (req, res) => res.json({ ok: true }));

const port = Number(process.env.PORT || 4000);
app.listen(port, () => console.log(`Backend listening on ${port}`));
