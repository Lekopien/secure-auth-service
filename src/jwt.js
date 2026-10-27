import { createHmac, timingSafeEqual } from "node:crypto";

const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");

/** Minimal HS256 JSON Web Token implementation (RFC 7519) using node:crypto. */
export function sign(payload, secret, { expiresInSec = 900, now = Date.now() } = {}) {
  const iat = Math.floor(now / 1000);
  const body = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ ...payload, iat, exp: iat + expiresInSec })}`;
  const sig = createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${sig}`;
}

export class TokenError extends Error {}

export function verify(token, secret, { now = Date.now() } = {}) {
  const parts = String(token).split(".");
  if (parts.length !== 3) throw new TokenError("malformed token");
  const [header, payload, sig] = parts;
  let head;
  try { head = JSON.parse(Buffer.from(header, "base64url")); } catch { throw new TokenError("malformed token"); }
  // Pin the algorithm: rejects "alg": "none" and algorithm-confusion attacks.
  if (head.alg !== "HS256") throw new TokenError("unsupported algorithm");
  const expected = createHmac("sha256", secret).update(`${header}.${payload}`).digest();
  const given = Buffer.from(sig, "base64url");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) throw new TokenError("bad signature");
  const claims = JSON.parse(Buffer.from(payload, "base64url"));
  if (typeof claims.exp !== "number" || claims.exp * 1000 <= now) throw new TokenError("token expired");
  return claims;
}
