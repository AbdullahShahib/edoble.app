export type AuthorizedUserRow = {
  id: number;
  email: string;
  password_hash: string;
  status: "active" | "disabled";
};

export type SessionRow = {
  id: number;
  user_id: number;
  jti: string;
  device_id: string;
  expires_at: string;
  revoked_at: string | null;
};

export type NonceRow = {
  nonce: string;
  email_hash: string;
  expires_at: string;
  consumed_at: string | null;
};
