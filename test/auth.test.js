import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { createApp } from "../src/app.js";
import { sign, verify } from "../src/jwt.js";
import { hashPassword, passwordProblems, verifyPassword } from "../src/passwords.js";

const SECRET = "test-secret-that-is-at-least-32-characters-long";
const GOOD = "Correct-Horse-42";

describe("passwords", () => {
  it("hashes with a random salt and verifies", async () => {
    const [a, b] = await Promise.all([hashPassword(GOOD), hashPassword(GOOD)]);
    assert.notEqual(a, b);
    assert.match(a, /^scrypt\$32768\$8\$1\$/);
    assert.equal(await verifyPassword(GOOD, a), true);
    assert.equal(await verifyPassword("wrong", a), false);
  });

  it("enforces the password policy", () => {
    assert.deepEqual(passwordProblems(GOOD, "amy@x.io"), []);
    assert.ok(passwordProblems("short").length);
    assert.ok(passwordProblems("alllowercaseletters").some((p) => p.includes("mix")));
    assert.ok(passwordProblems("Amyjones-2026!", "amyjones@x.io").some((p) => p.includes("email")));
  });
});

describe("jwt", () => {
  it("round-trips and rejects tampering, expiry and alg=none", () => {
    const t = sign({ sub: "u1" }, SECRET, { expiresInSec: 60, now: 0 });
    assert.equal(verify(t, SECRET, { now: 1000 }).sub, "u1");
    assert.throws(() => verify(t, SECRET, { now: 61_000 }), /expired/);
    assert.throws(() => verify(t, "another-secret-another-secret-12345", { now: 0 }), /signature/);
    const [, payload, sig] = t.split(".");
    const forged = Buffer.from(JSON.stringify({ sub: "admin", exp: 9e9 })).toString("base64url");
    assert.throws(() => verify(`${t.split(".")[0]}.${forged}.${sig}`, SECRET, { now: 0 }), /signature/);
    const none = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
    assert.throws(() => verify(`${none}.${payload}.`, SECRET, { now: 0 }), /algorithm/);
  });
});

describe("HTTP API", () => {
  let server, base, clock = Date.now();
  before(async () => {
    server = createApp({ secret: SECRET, maxFailures: 3, lockMs: 60_000, now: () => clock });
    await new Promise((r) => server.listen(0, r));
    base = `http://localhost:${server.address().port}`;
  });
  after(() => server.close());

  const call = async (method, path, body, token) => {
    const res = await fetch(base + path, {
      method,
      headers: { "content-type": "application/json", ...(token && { authorization: `Bearer ${token}` }) },
      body: body && JSON.stringify(body),
    });
    return { status: res.status, headers: res.headers, body: res.status === 204 ? null : await res.json() };
  };

  it("registers, logs in and reads the profile", async () => {
    assert.equal((await call("POST", "/register", { email: "Amy@Example.com", password: GOOD })).status, 201);
    assert.equal((await call("POST", "/register", { email: "amy@example.com", password: GOOD })).status, 409);
    const weak = await call("POST", "/register", { email: "bob@example.com", password: "password" });
    assert.equal(weak.status, 422);
    assert.ok(weak.body.problems.length);

    const login = await call("POST", "/login", { email: "amy@example.com", password: GOOD });
    assert.equal(login.status, 200);
    const me = await call("GET", "/me", null, login.body.accessToken);
    assert.equal(me.body.email, "amy@example.com");
    assert.equal(me.headers.get("x-content-type-options"), "nosniff");
    assert.equal(me.headers.get("cache-control"), "no-store");
    assert.equal(me.body.hash, undefined);
  });

  it("gives the same error for unknown users and wrong passwords", async () => {
    const a = await call("POST", "/login", { email: "nobody@example.com", password: GOOD });
    const b = await call("POST", "/login", { email: "amy@example.com", password: "Wrong-Pass-99" });
    assert.equal(a.status, 401);
    assert.deepEqual(a.body, b.body);
  });

  it("locks the account after repeated failures, then recovers", async () => {
    await call("POST", "/register", { email: "lock@example.com", password: GOOD });
    for (let i = 0; i < 3; i++) {
      assert.equal((await call("POST", "/login", { email: "lock@example.com", password: "Nope-Nope-123" })).status, 401);
    }
    // Locked now: even the right password is refused until the lock expires.
    const blocked = await call("POST", "/login", { email: "lock@example.com", password: GOOD });
    assert.equal(blocked.status, 429);
    assert.ok(Number(blocked.headers.get("retry-after")) > 0);
    clock += 61_000;
    assert.equal((await call("POST", "/login", { email: "lock@example.com", password: GOOD })).status, 200);
  });

  it("rotates refresh tokens and detects reuse", async () => {
    const { body: s1 } = await call("POST", "/login", { email: "amy@example.com", password: GOOD });
    const { status, body: s2 } = await call("POST", "/refresh", { refreshToken: s1.refreshToken });
    assert.equal(status, 200);
    assert.notEqual(s2.refreshToken, s1.refreshToken);
    // An attacker replays the old token: the whole family is revoked, including s2.
    const replay = await call("POST", "/refresh", { refreshToken: s1.refreshToken });
    assert.equal(replay.status, 401);
    assert.match(replay.body.error, /reuse/);
    assert.equal((await call("POST", "/refresh", { refreshToken: s2.refreshToken })).status, 401);
  });

  it("logout revokes the refresh token; bad tokens are rejected", async () => {
    const { body } = await call("POST", "/login", { email: "amy@example.com", password: GOOD });
    assert.equal((await call("POST", "/logout", { refreshToken: body.refreshToken })).status, 204);
    assert.equal((await call("POST", "/refresh", { refreshToken: body.refreshToken })).status, 401);
    assert.equal((await call("GET", "/me", null, "abc.def.ghi")).status, 401);
    assert.equal((await call("GET", "/me")).status, 401);
  });
});
