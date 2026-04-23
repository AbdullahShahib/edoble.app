import type { VercelRequest, VercelResponse } from "@vercel/node";
import bcrypt from "bcryptjs";
import { pool, queryOne } from "./db.js";
import { env } from "./env.js";
import { randomId, sha256 } from "./crypto.js";
import { verifyAccessToken } from "./jwt.js";
import { unauthorized } from "./http.js";
import type { AuthorizedUserRow, SessionRow } from "./types.js";

export async function createIntegrityNonce(email: string): Promise<string> {
  const nonce = randomId(24);
  const emailHash = sha256(email.toLowerCase());

  await pool.execute(
    `INSERT INTO integrity_nonces (nonce, email_hash, expires_at)
     VALUES (?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND))`,
    [nonce, emailHash, env.INTEGRITY_NONCE_TTL_SECONDS]
  );

  return nonce;
}

export async function consumeIntegrityNonce(email: string, nonce: string): Promise<boolean> {
  const emailHash = sha256(email.toLowerCase());
  const [result] = await pool.execute(
    `UPDATE integrity_nonces
     SET consumed_at = UTC_TIMESTAMP()
     WHERE nonce = ?
       AND email_hash = ?
       AND consumed_at IS NULL
       AND expires_at > UTC_TIMESTAMP()`,
    [nonce, emailHash]
  );

  const changed = (result as { affectedRows?: number }).affectedRows ?? 0;
  return changed === 1;
}

export async function findAuthorizedUserByEmail(email: string): Promise<AuthorizedUserRow | null> {
  return await queryOne<AuthorizedUserRow>(
    `SELECT id, email, password_hash, status
     FROM authorized_users
     WHERE email = ?
     LIMIT 1`,
    [email.toLowerCase()]
  );
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return await bcrypt.compare(password, hash);
}

export async function createSession(input: {
  userId: number;
  deviceId: string;
  ipAddress: string | null;
  userAgent: string | null;
}): Promise<{ sessionId: number; jti: string }> {
  const jti = randomId(24);

  const [result] = await pool.execute(
    `INSERT INTO auth_sessions (
      user_id,
      jti,
      device_id,
      ip_address,
      user_agent,
      expires_at
     ) VALUES (
      ?, ?, ?, ?, ?,
      DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND)
     )`,
    [input.userId, jti, input.deviceId, input.ipAddress, input.userAgent, env.JWT_EXPIRES_SECONDS]
  );

  return {
    sessionId: (result as { insertId: number }).insertId,
    jti
  };
}

export async function upsertDeviceAttestation(input: {
  userId: number;
  deviceId: string;
  integrityPayload: unknown;
}): Promise<void> {
  await pool.execute(
    `INSERT INTO device_attestations (
      user_id,
      device_id,
      verified_at,
      expires_at,
      integrity_payload
    ) VALUES (
      ?, ?, UTC_TIMESTAMP(),
      DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND),
      ?
    ) ON DUPLICATE KEY UPDATE
      verified_at = VALUES(verified_at),
      expires_at = VALUES(expires_at),
      integrity_payload = VALUES(integrity_payload)`,
    [input.userId, input.deviceId, env.INTEGRITY_ATTEST_TTL_SECONDS, JSON.stringify(input.integrityPayload)]
  );
}

export async function hasFreshDeviceAttestation(userId: number, deviceId: string): Promise<boolean> {
  const row = await queryOne<{ ok: number }>(
    `SELECT 1 AS ok
     FROM device_attestations
     WHERE user_id = ?
       AND device_id = ?
       AND expires_at > UTC_TIMESTAMP()
     LIMIT 1`,
    [userId, deviceId]
  );
  return row?.ok === 1;
}

export async function resolveSessionFromBearer(
  req: VercelRequest,
  res: VercelResponse
): Promise<{ userId: number; sessionJti: string; deviceId: string; email: string } | null> {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    unauthorized(res);
    return null;
  }

  const token = authHeader.slice("Bearer ".length);

  try {
    const claims = await verifyAccessToken(token);
    const row = await queryOne<SessionRow>(
      `SELECT id, user_id, jti, device_id, expires_at, revoked_at
       FROM auth_sessions
       WHERE jti = ?
       LIMIT 1`,
      [claims.sid]
    );

    if (!row || row.revoked_at !== null) {
      unauthorized(res);
      return null;
    }

    const sessionExpired = new Date(row.expires_at).getTime() <= Date.now();
    if (sessionExpired) {
      unauthorized(res);
      return null;
    }

    if (claims.did !== row.device_id || Number(claims.sub) !== row.user_id) {
      unauthorized(res);
      return null;
    }

    return {
      userId: row.user_id,
      sessionJti: row.jti,
      deviceId: claims.did,
      email: claims.email
    };
  } catch {
    unauthorized(res);
    return null;
  }
}
