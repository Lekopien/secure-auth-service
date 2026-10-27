import { createHash, randomBytes, randomUUID } from "node:crypto";
import { hashPassword, passwordProblems, verifyPassword } from "./passwords.js";
import { sign } from "./jwt.js";

export class AuthError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    Object.assign(this, extra);
  }
}

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[a-z]{2,}$/i;
const sha256 = (s) => createHash("sha256").update(s).digest("hex");

/**
 * Users, sessions and lockouts, kept in memory (swap the Maps for a database in production).
 *
 * Refresh tokens are random, stored only as SHA-256 hashes, rotated on every use,
 * and grouped in families: reusing an already-rotated token revokes the whole family,
 * which is how a stolen refresh token gets detected.
 */
export class AuthService {
  constructor({ secret, accessTtlSec = 900, refreshTtlSec = 60 * 60 * 24 * 14, maxFailures = 5, lockMs = 15 * 60_000, now = () => Date.now() }) {
    if (!secret || secret.length < 32) throw new Error("JWT secret must be at least 32 characters");
    Object.assign(this, { secret, accessTtlSec, refreshTtlSec, maxFailures, lockMs, now });
    this.users = new Map();       // email -> { id, email, hash }
    this.refresh = new Map();     // sha256(token) -> { userId, family, expires, used }
    this.failures = new Map();    // email -> { count, lockedUntil }
    // A real hash to compare against when the email doesn't exist, so timing doesn't reveal accounts.
    this.dummyHash = hashPassword(randomBytes(16).toString("hex"));
  }

  async register(email, password) {
    email = String(email ?? "").trim().toLowerCase();
    if (!EMAIL_RE.test(email)) throw new AuthError(422, "enter a valid email");
    const problems = passwordProblems(password, email);
    if (problems.length) throw new AuthError(422, "weak password", { problems });
    if (this.users.has(email)) throw new AuthError(409, "account already exists");
    const user = { id: randomUUID(), email, hash: await hashPassword(password), createdAt: new Date(this.now()).toISOString() };
    this.users.set(email, user);
    return { id: user.id, email };
  }

  async login(email, password) {
    email = String(email ?? "").trim().toLowerCase();
    const lock = this.failures.get(email);
    if (lock?.lockedUntil > this.now()) {
      throw new AuthError(429, "too many failed attempts, try again later", { retryAfterSec: Math.ceil((lock.lockedUntil - this.now()) / 1000) });
    }
    const user = this.users.get(email);
    const ok = await verifyPassword(String(password ?? ""), user?.hash ?? (await this.dummyHash));
    if (!user || !ok) {
      const f = { count: (lock?.lockedUntil && lock.lockedUntil <= this.now() ? 0 : lock?.count ?? 0) + 1, lockedUntil: 0 };
      if (f.count >= this.maxFailures) f.lockedUntil = this.now() + this.lockMs;
      this.failures.set(email, f);
      throw new AuthError(401, "invalid email or password"); // same message either way: no account enumeration
    }
    this.failures.delete(email);
    return this.#issue(user, randomUUID());
  }

  rotate(refreshToken) {
    const key = sha256(String(refreshToken ?? ""));
    const rec = this.refresh.get(key);
    if (!rec || rec.expires <= this.now()) throw new AuthError(401, "invalid refresh token");
    if (rec.used) {
      this.revokeFamily(rec.family);
      throw new AuthError(401, "refresh token reuse detected; all sessions in this chain were signed out");
    }
    rec.used = true;
    const user = [...this.users.values()].find((u) => u.id === rec.userId);
    return this.#issue(user, rec.family);
  }

  logout(refreshToken) {
    const rec = this.refresh.get(sha256(String(refreshToken ?? "")));
    if (rec) this.revokeFamily(rec.family);
  }

  revokeFamily(family) {
    for (const [k, r] of this.refresh) if (r.family === family) this.refresh.delete(k);
  }

  userById(id) {
    const u = [...this.users.values()].find((x) => x.id === id);
    return u && { id: u.id, email: u.email, createdAt: u.createdAt };
  }

  #issue(user, family) {
    const refreshToken = randomBytes(32).toString("base64url");
    this.refresh.set(sha256(refreshToken), { userId: user.id, family, expires: this.now() + this.refreshTtlSec * 1000, used: false });
    return {
      accessToken: sign({ sub: user.id, email: user.email }, this.secret, { expiresInSec: this.accessTtlSec, now: this.now() }),
      refreshToken,
      tokenType: "Bearer",
      expiresIn: this.accessTtlSec,
    };
  }
}
