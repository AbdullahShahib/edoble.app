import { pool } from "./db.js";
import { sha256 } from "./crypto.js";

export async function writeAuthAudit(input: {
  email?: string;
  deviceId?: string;
  eventType: "challenge_issued" | "login_success" | "login_failure" | "integrity_failure";
  reason?: string;
}): Promise<void> {
  const emailHash = input.email ? sha256(input.email.toLowerCase()) : sha256("unknown");

  await pool.execute(
    `INSERT INTO auth_audit_log (email_hash, device_id, event_type, reason)
     VALUES (?, ?, ?, ?)`,
    [emailHash, input.deviceId ?? null, input.eventType, input.reason ?? null]
  );
}
