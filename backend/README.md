# Edoble Backend (skeleton)

This folder contains a minimal Node + Express + TypeScript backend skeleton demonstrating:

- JWT-based access tokens
- Refresh-token rotation stored in Redis
- RBAC middleware and permission checks
- Simple message endpoints with Redis publish for fanout
- S3 presigned upload URL endpoint for media

R2 support:

This backend supports Cloudflare R2 (S3-compatible) in addition to AWS S3. To use R2, set the following env vars in `.env`:

- `R2_ACCOUNT_ID` — your Cloudflare account id
- `R2_BUCKET` — bucket name
- `R2_ACCESS_KEY_ID` and `R2_SECRET_ACCESS_KEY` — R2 credentials
- optionally `R2_ENDPOINT` — defaults to `https://<R2_ACCOUNT_ID>.r2.cloudflarestorage.com`

The `/media/presign` endpoint will return a `provider` field indicating `r2` or `s3`.

Prereqs:

- Node 18+
- Redis available and reachable via `REDIS_URL`
- AWS credentials for S3 (or mock)

Database:

- This project uses Prisma. By default `DATABASE_URL` is set to `file:./dev.db` (SQLite) for easy local development.
- To initialize Prisma locally:

```bash
# from backend/
npm ci
npx prisma generate
npx prisma migrate dev --name init
```

For production, set `DATABASE_URL` to a managed Postgres and run migrations with `npx prisma migrate deploy`.

cPanel notes:

- If you plan to deploy to cPanel MySQL, switch the `DATABASE_URL` to your cPanel MySQL connection string (example in `.env.example`).
- See `deploy/cpanel-deploy.md` for step-by-step instructions to run migrations, set env vars, and start the app via Application Manager or PM2.

If you cannot run Prisma CLI on cPanel, use the included SQL migration:

```bash
# on cPanel server, ensure `mysql` client is available
cd ~/edoble-backend/backend
bash deploy/apply-migration-cpanel.sh 127.0.0.1 3306 edoble dbuser
```

This runs `prisma/migrations/0001_init/migration.sql` directly against MySQL.

Refresh token cookie behavior
- The backend now issues refresh tokens as `HttpOnly`, `Secure`, `SameSite=Strict` cookies at the `/auth` path. The client does not need to store refresh tokens; it should call `POST /auth/refresh` with the current access token (in Authorization header or body) to receive a new access token. The cookie will be rotated by the server on each refresh.

If you deploy to cPanel behind HTTPS, set `COOKIE_DOMAIN` and ensure `COOKIE_SECURE=true` in your environment.

Run locally:

```bash
cp .env.example .env
# fill env values
npm ci
npm run dev
```

Notes:

- This is a demo skeleton. Replace the simple user validation in `/auth/login` with your user datastore.
- Replace in-memory message store with a durable DB (Postgres) and use Kafka / Redis Streams for large-scale fanout.
