# Secure Auth Service

[![ci](https://github.com/Lekopien/secure-auth-service/actions/workflows/ci.yml/badge.svg)](https://github.com/Lekopien/secure-auth-service/actions/workflows/ci.yml)

**Live demos: https://auth.lekopien.com**

An authentication service written with **Node.js and zero dependencies**, so every security decision is in plain sight. It covers the parts that are easy to get wrong: password storage, token signing, session theft, brute force, account enumeration and HTTP hardening.

## Security features

| Threat | Defence | Where |
| --- | --- | --- |
| Leaked database | `scrypt` (N=2¹⁵) with per-user salt, parameters stored in the hash | `src/passwords.js` |
| Weak passwords | Length, character mix, common-password list, no email name | `src/passwords.js` |
| Forged tokens | HS256 JWT implemented with `node:crypto`, algorithm pinned (no `alg: none`), constant-time signature check | `src/jwt.js` |
| Stolen refresh token | Single-use refresh tokens stored as SHA-256 hashes; **reuse revokes the whole session family** | `src/auth.js` |
| Brute force | Lockout after N failures, `429` with `Retry-After` | `src/auth.js` |
| Account enumeration | Identical errors, and a dummy hash comparison for unknown emails so timing matches | `src/auth.js` |
| Browser attacks | `no-store`, `nosniff`, CSP, HSTS, `X-Frame-Options: DENY`, `no-referrer` | `src/app.js` |
| Oversized payloads | 10 KB body limit | `src/app.js` |

## API

| Method | Path | Body | Returns |
| --- | --- | --- | --- |
| POST | `/register` | `{ email, password }` | `201 { id, email }` or `422 { problems }` |
| POST | `/login` | `{ email, password }` | `{ accessToken, refreshToken, expiresIn }` |
| POST | `/refresh` | `{ refreshToken }` | a new token pair (old refresh token is spent) |
| POST | `/logout` | `{ refreshToken }` | `204`, revokes the session family |
| GET | `/me` | `Authorization: Bearer <accessToken>` | `{ id, email, createdAt }` |

## Run it

```bash
JWT_SECRET=$(openssl rand -base64 48) npm start    # http://localhost:4000
npm test
```

```bash
curl -s localhost:4000/register -d '{"email":"amy@example.com","password":"Correct-Horse-42"}'
TOKEN=$(curl -s localhost:4000/login -d '{"email":"amy@example.com","password":"Correct-Horse-42"}' | jq -r .accessToken)
curl -s localhost:4000/me -H "Authorization: Bearer $TOKEN"
```

## Tests

`test/auth.test.js` checks hashing and salts, policy rules, JWT tampering, expiry and `alg: none`, identical login errors, lockout and recovery (with an injected clock), refresh rotation, reuse detection and logout.

## Production notes

Storage is in memory to keep the project self-contained. For production, move users and refresh-token records to a database, keep `JWT_SECRET` in a secret manager, serve over HTTPS, and consider sending the refresh token as an `HttpOnly; Secure; SameSite=Strict` cookie.

## License

MIT

## Author

Built by **David Lekopien** ([@Lekopien](https://github.com/Lekopien)) · [lekopien.com](https://lekopien.com)
