import { randomBytes } from "node:crypto";
import { createApp } from "./app.js";

let secret = process.env.JWT_SECRET;
if (!secret) {
  secret = randomBytes(48).toString("base64url");
  console.warn("JWT_SECRET not set: using a random secret, so tokens reset on restart.");
}
const port = Number(process.env.PORT ?? 4000);
createApp({ secret }).listen(port, () => console.log(`auth service on http://localhost:${port}`));
