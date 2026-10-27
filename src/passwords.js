import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scryptAsync = promisify(scrypt);
// N=2^15 costs ~50 ms per hash: slow for attackers, fine for one login.
const PARAMS = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const KEYLEN = 64;

/** Returns "scrypt$N$r$p$salt$hash" so parameters can be raised later without breaking old hashes. */
export async function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = await scryptAsync(password.normalize("NFKC"), salt, KEYLEN, PARAMS);
  return ["scrypt", PARAMS.N, PARAMS.r, PARAMS.p, salt.toString("base64url"), hash.toString("base64url")].join("$");
}

export async function verifyPassword(password, stored) {
  const [alg, N, r, p, salt, hash] = stored.split("$");
  if (alg !== "scrypt") return false;
  const expected = Buffer.from(hash, "base64url");
  const actual = await scryptAsync(password.normalize("NFKC"), Buffer.from(salt, "base64url"), expected.length,
    { N: Number(N), r: Number(r), p: Number(p), maxmem: PARAMS.maxmem });
  return timingSafeEqual(actual, expected); // constant time: no early exit leaks how much matched
}

const COMMON = new Set(["password", "password1", "123456", "12345678", "123456789", "qwerty", "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon"]);

/** Returns a list of problems; empty means the password is acceptable. */
export function passwordProblems(password, email = "") {
  const problems = [];
  if (typeof password !== "string" || password.length < 10) problems.push("use at least 10 characters");
  if (password?.length > 128) problems.push("use at most 128 characters");
  if (COMMON.has(String(password).toLowerCase())) problems.push("this password is too common");
  const kinds = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  if (kinds < 3) problems.push("mix at least three of: lowercase, uppercase, digits, symbols");
  const local = email.split("@")[0].toLowerCase();
  if (local.length >= 3 && String(password).toLowerCase().includes(local)) problems.push("don't include your email name");
  return problems;
}
