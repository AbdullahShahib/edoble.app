import { SignJWT, jwtVerify } from "jose";
import { env } from "./env.js";

const jwtSecret = new TextEncoder().encode(env.JWT_SECRET);

export type AccessTokenClaims = {
  sub: string;
  sid: string;
  did: string;
  email: string;
};

export async function signAccessToken(claims: AccessTokenClaims): Promise<string> {
  return await new SignJWT({
    sid: claims.sid,
    did: claims.did,
    email: claims.email
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setSubject(claims.sub)
    .setIssuedAt()
    .setIssuer(env.JWT_ISSUER)
    .setAudience(env.JWT_AUDIENCE)
    .setExpirationTime(`${env.JWT_EXPIRES_SECONDS}s`)
    .sign(jwtSecret);
}

export async function verifyAccessToken(token: string): Promise<AccessTokenClaims> {
  const verified = await jwtVerify(token, jwtSecret, {
    issuer: env.JWT_ISSUER,
    audience: env.JWT_AUDIENCE
  });

  const sub = verified.payload.sub;
  const sid = verified.payload.sid;
  const did = verified.payload.did;
  const email = verified.payload.email;

  if (typeof sub !== "string" || typeof sid !== "string" || typeof did !== "string" || typeof email !== "string") {
    throw new Error("invalid_token_claims");
  }

  return { sub, sid, did, email };
}
