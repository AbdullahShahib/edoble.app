-- Phase 1: Secure authentication and media presign backend schema
-- MySQL 8+

CREATE TABLE IF NOT EXISTS authorized_users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  email VARCHAR(254) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
  role ENUM('user', 'admin') NOT NULL DEFAULT 'user',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_authorized_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_ci;

CREATE TABLE IF NOT EXISTS integrity_nonces (
  nonce VARCHAR(255) NOT NULL,
  email_hash CHAR(64) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  consumed_at TIMESTAMP NULL,
  PRIMARY KEY (nonce),
  KEY idx_integrity_nonces_email_hash (email_hash),
  KEY idx_integrity_nonces_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS auth_sessions (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id BIGINT UNSIGNED NOT NULL,
  jti VARCHAR(255) NOT NULL,
  device_id VARCHAR(128) NOT NULL,
  ip_address VARCHAR(64) NULL,
  user_agent VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_auth_sessions_jti (jti),
  KEY idx_auth_sessions_user_device (user_id, device_id),
  KEY idx_auth_sessions_expiry (expires_at),
  CONSTRAINT fk_auth_sessions_user FOREIGN KEY (user_id) REFERENCES authorized_users(id)
    ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS device_attestations (
  user_id BIGINT UNSIGNED NOT NULL,
  device_id VARCHAR(128) NOT NULL,
  verified_at TIMESTAMP NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  integrity_payload JSON NOT NULL,
  PRIMARY KEY (user_id, device_id),
  KEY idx_device_attestations_expiry (expires_at),
  CONSTRAINT fk_device_attestations_user FOREIGN KEY (user_id) REFERENCES authorized_users(id)
    ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS auth_audit_log (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  email_hash CHAR(64) NOT NULL,
  device_id VARCHAR(128) NULL,
  event_type ENUM('challenge_issued', 'login_success', 'login_failure', 'integrity_failure') NOT NULL,
  reason VARCHAR(128) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_auth_audit_email_hash_created (email_hash, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Optional cleanup events (enable event_scheduler = ON if used)
-- DELETE FROM integrity_nonces WHERE expires_at < UTC_TIMESTAMP() - INTERVAL 1 DAY;
-- DELETE FROM auth_sessions WHERE expires_at < UTC_TIMESTAMP() - INTERVAL 7 DAY;
-- DELETE FROM device_attestations WHERE expires_at < UTC_TIMESTAMP() - INTERVAL 1 DAY;
