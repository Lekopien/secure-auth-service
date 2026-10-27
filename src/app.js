import { createServer } from "node:http";
import { AuthError, AuthService } from "./auth.js";
import { TokenError, verify } from "./jwt.js";

const SECURITY_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  "strict-transport-security": "max-age=63072000; includeSubDomains",
};

async function readJson(req, limit = 10_000) {
  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (body.length > limit) throw new AuthError(413, "body too large");
  }
  try { return body ? JSON.parse(body) : {}; } catch { throw new AuthError(400, "invalid JSON"); }
}

/** A plain node:http server, no framework, so every security decision is visible. */
export function createApp(options) {
  const auth = new AuthService(options);
  const routes = {
    "POST /register": async (b) => [201, await auth.register(b.email, b.password)],
    "POST /login": async (b) => [200, await auth.login(b.email, b.password)],
    "POST /refresh": async (b) => [200, auth.rotate(b.refreshToken)],
    "POST /logout": async (b) => { auth.logout(b.refreshToken); return [204, null]; },
    "GET /me": async (_, req) => {
      const token = req.headers.authorization?.match(/^Bearer (.+)$/)?.[1];
      if (!token) throw new AuthError(401, "missing bearer token");
      const claims = verify(token, options.secret, { now: auth.now() });
      const user = auth.userById(claims.sub);
      if (!user) throw new AuthError(401, "user no longer exists");
      return [200, user];
    },
    "GET /health": async () => [200, { status: "ok" }],
  };

  const server = createServer(async (req, res) => {
    const handler = routes[`${req.method} ${req.url.split("?")[0]}`];
    let status, body;
    try {
      if (!handler) throw new AuthError(404, "not found");
      [status, body] = await handler(req.method === "POST" ? await readJson(req) : {}, req);
    } catch (err) {
      if (err instanceof TokenError) [status, body] = [401, { error: err.message }];
      else if (err instanceof AuthError) {
        const { status: s, message, ...extra } = err;
        [status, body] = [s, { error: message, ...extra }];
        if (err.retryAfterSec) res.setHeader("retry-after", err.retryAfterSec);
      } else {
        console.error(err);
        [status, body] = [500, { error: "internal error" }];
      }
    }
    res.writeHead(status, SECURITY_HEADERS).end(body === null ? undefined : JSON.stringify(body));
  });
  server.auth = auth;
  return server;
}
