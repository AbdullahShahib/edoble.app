import type { VercelResponse } from "./vercel-types.js";
import { pool } from "./db.js";

/**
 * SECURITY HEADERS
 * Add to all responses for defense-in-depth
 */
export function addSecurityHeaders(res: VercelResponse): void {
  // Prevent clickjacking
  res.setHeader("X-Frame-Options", "DENY");

  // Prevent MIME type sniffing
  res.setHeader("X-Content-Type-Options", "nosniff");

  // XSS protection (legacy, but good fallback)
  res.setHeader("X-XSS-Protection", "1; mode=block");

  // HSTS - force HTTPS for 1 year (including subdomains)
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");

  // Referrer Policy - don't leak referer to external sites
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

  // Content Security Policy - prevent XSS and data exfiltration
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
  );

  // Permissions Policy - disable dangerous APIs
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
  );

  // Prevent caching of sensitive data
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
}

/**
 * CORS FOR PRIVATE APP
 * Only allow specific origins for your startup agency
 */
export function addRestrictedCorsHeaders(res: VercelResponse, origin?: string): void {
  // For private app: hardcode allowed origins
  // Replace with your actual domains
  const allowedOrigins = [
    "http://localhost:3000", // Local development
    "http://localhost:5173", // Vite dev
    "http://localhost:8081" // Mobile preview
  ];

  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Max-Age", "3600");
  }
}

/**
 * PASSWORD STRENGTH VALIDATION
 * Enforce strong passwords to prevent brute force effectiveness
 */
export function validatePasswordStrength(password: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (password.length < 12) {
    errors.push("Password must be at least 12 characters");
  }
  if (password.length > 128) {
    errors.push("Password must not exceed 128 characters");
  }
  if (!/[A-Z]/.test(password)) {
    errors.push("Password must contain at least one uppercase letter");
  }
  if (!/[a-z]/.test(password)) {
    errors.push("Password must contain at least one lowercase letter");
  }
  if (!/[0-9]/.test(password)) {
    errors.push("Password must contain at least one number");
  }
  if (!/[!@#$%^&*()_\-+=\[\]{}|;:'"<>,.?/]/.test(password)) {
    errors.push("Password must contain at least one special character (!@#$%^&*...)");
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * RATE LIMITING
 * Prevent brute force attacks by limiting requests per IP/email
 */
export async function checkRateLimit(
  key: string, // e.g., "login:192.168.1.1" or "challenge:user@example.com"
  maxAttempts: number = 5,
  windowSeconds: number = 300 // 5 minute window
): Promise<{ allowed: boolean; remainingAttempts: number; resetSeconds: number }> {
  const now = new Date();
  const windowStart = new Date(now.getTime() - windowSeconds * 1000);

  // Create table if it doesn't exist (one-time setup)
  await pool.execute(`
    CREATE TABLE IF NOT EXISTS rate_limits (
      id INT AUTO_INCREMENT PRIMARY KEY,
      key VARCHAR(255) NOT NULL,
      attempt_count INT NOT NULL DEFAULT 1,
      window_start DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY unique_key_window (key, window_start)
    )
  `);

  // Clean up old entries (older than 24 hours)
  await pool.execute(
    `DELETE FROM rate_limits WHERE created_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)`
  );

  // Get current attempt count
  const [result]: any = await pool.execute(
    `SELECT attempt_count FROM rate_limits
     WHERE key = ? AND window_start > ?
     ORDER BY window_start DESC
     LIMIT 1`,
    [key, windowStart.toISOString()]
  );

  const currentAttempts = result?.[0]?.attempt_count || 0;

  if (currentAttempts >= maxAttempts) {
    const resetTime = new Date(windowStart.getTime() + windowSeconds * 1000);
    const resetSeconds = Math.ceil((resetTime.getTime() - now.getTime()) / 1000);
    return {
      allowed: false,
      remainingAttempts: 0,
      resetSeconds: Math.max(1, resetSeconds)
    };
  }

  // Increment attempt
  await pool.execute(
    `INSERT INTO rate_limits (key, attempt_count, window_start)
     VALUES (?, 1, ?)
     ON DUPLICATE KEY UPDATE attempt_count = attempt_count + 1`,
    [key, windowStart.toISOString()]
  );

  return {
    allowed: true,
    remainingAttempts: maxAttempts - currentAttempts - 1,
    resetSeconds: windowSeconds
  };
}

/**
 * ACCOUNT LOCKOUT
 * Disable accounts after repeated failed login attempts
 */
export async function recordFailedLoginAttempt(email: string): Promise<{ locked: boolean; attemptsRemaining: number }> {
  const email_hash = Buffer.from(email.toLowerCase()).toString("hex");

  // Get current failed attempts (within last hour)
  const [result]: any = await pool.execute(
    `SELECT COUNT(*) as count FROM auth_audit_log
     WHERE event_type = 'login_failure'
     AND email_hash = ?
     AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)`,
    [email_hash]
  );

  const failedAttempts = result?.[0]?.count || 0;
  const maxAttempts = 5;

  // Lock account after 5 failed attempts
  if (failedAttempts >= maxAttempts) {
    return {
      locked: true,
      attemptsRemaining: 0
    };
  }

  return {
    locked: false,
    attemptsRemaining: maxAttempts - failedAttempts - 1
  };
}

/**
 * DEVICE FINGERPRINTING
 * Validate device ID format to prevent spoofing
 */
export function validateDeviceId(deviceId: string): boolean {
  // Device ID should be:
  // - 32-128 hex characters (from Android Build.ID or similar)
  // - No special characters that could be used for injection
  return /^[a-f0-9]{32,128}$/i.test(deviceId);
}

/**
 * INPUT SANITIZATION
 * Prevent injection attacks by validating all inputs
 */
export function sanitizeEmail(email: string): string | null {
  // RFC 5321 simplified check
  const trimmed = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
    return null;
  }
  if (trimmed.length > 254) {
    return null;
  }
  // Prevent LDAP/SQL injection via email
  if (/[;'"`\\]/.test(trimmed)) {
    return null;
  }
  return trimmed;
}

/**
 * NONCE VALIDATION
 * Ensure nonce hasn't been manipulated
 */
export function validateNonce(nonce: string): boolean {
  // Nonce should be:
  // - 24-512 alphanumeric + hyphen only
  // - No special chars that could be used for injection
  return /^[a-zA-Z0-9\-]{24,512}$/.test(nonce);
}

/**
 * PREVENT TIMING ATTACKS
 * Use constant-time comparison for sensitive values
 */
export function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/**
 * SESSION SECURITY
 * Enforce strict session requirements
 */
export function validateSessionConsistency(
  tokenClaims: { sub: string; sid: string; did: string; email: string },
  sessionData: { user_id: number; jti: string; device_id: string }
): boolean {
  // Verify token claims match session data
  return (
    parseInt(tokenClaims.sub) === sessionData.user_id &&
    tokenClaims.sid === sessionData.jti &&
    tokenClaims.did === sessionData.device_id
  );
}
