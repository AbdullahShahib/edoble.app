cPanel Deployment Guide

This guide explains how to deploy the `edoble-backend` Node/Express app to a cPanel account using either the Application Manager (UI) or SSH + PM2. It assumes you want to use the cPanel-provided MySQL database.

Prerequisites
- SSH access to your cPanel account (recommended)
- Node 18+ available (use Application Manager or install via cPanel)
- A MySQL database created in cPanel (note the host, port, database name, user, and password)
- External Redis (recommended) — Redis is typically not available on shared cPanel; use managed Redis (Upstash, RedisCloud) and set `REDIS_URL`.
- R2 or S3 credentials if you need media uploads.

High-level steps
1. Prepare MySQL in cPanel
2. Upload app code (Git or SCP)
3. Install dependencies and generate Prisma client
4. Run migrations (`npx prisma migrate deploy`)
5. Configure Application Manager or PM2 to start the app
6. Set environment variables in cPanel Application Manager

Detailed steps

1) Create MySQL database and user in cPanel
- Login to cPanel -> MySQL® Databases
- Create a database (e.g. `edoble`)
- Create a database user and assign a strong password
- Add the user to the database and grant ALL privileges
- Note the DB host (usually `localhost` for cPanel) and port (3306)

2) Upload code to server
Option A (recommended): Use Git via cPanel Git Version Control or push via SCP/SFTP
- Create repository or upload archive and extract to a folder like `~/edoble-backend`

Option B: Use SSH and `git clone` if your cPanel supports it

3) Install Node deps and build
SSH into the cPanel account, go to the app directory (e.g. `~/edoble-backend/backend`)

```bash
cd ~/edoble-backend/backend
npm ci
npx prisma generate
npm run build
```

4) Configure environment variables
- In cPanel Application Manager (Setup Node.js App), create or edit the application and set these environment variables in the UI:
  - `DATABASE_URL` -> `mysql://DB_USER:DB_PASS@127.0.0.1:3306/edoble`
  - `REDIS_URL` -> `redis://...` (use external managed Redis)
  - `JWT_SECRET`, `AWS_*` or `R2_*` as needed
  - `PORT` -> set to `4000` or the port cPanel expects

If using SSH/PM2, set `.env` in your app folder (do NOT commit secrets):

```bash
cp .env.example .env
# edit .env with your production values
```

5) Run Prisma migrations (first deploy)
- For initial setup on the server, you can run interactive migrations locally and commit the migration folder, then on the server run:

```bash
npx prisma migrate deploy
```

This applies migrations non-interactively. For local dev you can use `npx prisma migrate dev` to create migrations.

6) Start the app
Option A: Application Manager
- Use cPanel's "Setup Node.js App" -> Select app root (`backend/`), startup file `dist/index.js` and environment variables, then click "Run".

Option B: PM2 via SSH
```bash
# from backend/
# ensure build completed (npm run build)
npm install -g pm2
npm run build
npm run prisma:generate || npx prisma generate
# start with pm2
pm2 start dist/index.js --name edoble-backend
pm2 save
```

7) Verify health endpoint
- Visit `https://your-domain/health` or the configured port to confirm `{ "ok": true }` is returned.

Troubleshooting
- Check `~/.pm2/logs/` for runtime logs if using PM2.
- If Prisma throws connection errors, ensure `DATABASE_URL` is correct and the DB user has privileges.
- Ensure your cPanel firewall allows outbound connections to your Redis host if using external Redis.

Security notes
- Never commit `.env` to source control. Store secrets in cPanel Application Manager environment variables or a secrets manager.
- Use secure cookies for refresh tokens and enable HTTPS for your domain.
