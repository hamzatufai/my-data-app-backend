/**
 * Password hashing, token hashing, signing, sessions and rate limits.
 * PRD v2.0: AUTH-05 (password security), AUTH-02 (normalised email),
 * AUTH-06/03 (single-use tokens), AUTH-08 (sessions), AUTH-09 (rate limits).
 */
import crypto from "crypto";

const SCRYPT_KEYLEN = 64;

export function normaliseEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, SCRYPT_KEYLEN);
  return `scrypt$${salt.toString("hex")}$${hash.toString("hex")}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [scheme, saltHex, hashHex] = stored.split("$");
  if (scheme !== "scrypt" || !saltHex || !hashHex) return false;
  const candidate = crypto.scryptSync(password, Buffer.from(saltHex, "hex"), SCRYPT_KEYLEN);
  const expected = Buffer.from(hashHex, "hex");
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

/** Banned-password check: for the launch build we enforce length + trivial-list check. */
const TRIVIAL_PASSWORDS = new Set([
  "password", "password1", "password12", "password123", "12345678", "123456789",
  "qwertyuiop", "letmein", "welcome1", "admin123", "iloveyou", "defaultpassword",
]);

export function passwordIssues(password: string): string[] {
  const issues: string[] = [];
  if (password.length < 12) issues.push("Password must be at least 12 characters long.");
  if (TRIVIAL_PASSWORDS.has(password.toLowerCase())) {
    issues.push("This password appears on a known-breach list. Choose a different one.");
  }
  return issues;
}

export function newToken(): { token: string; tokenHash: string } {
  const token = crypto.randomBytes(32).toString("base64url");
  return { token, tokenHash: hashToken(token) };
}

export function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function newId(): string {
  return crypto.randomUUID();
}

const now = () => new Date().toISOString();

const attemptBuckets = new Map<string, number[]>();

/**
 * In-process sliding-window rate limiter (AUTH-09). Suitable for a launch
 * deployment on a single function instance; a durable limiter (e.g. Vercel KV)
 * is required for multi-instance production scaling.
 */
export function rateLimit(key: string, max: number, windowMs: number): { ok: boolean; retryAfterSec: number } {
  const current = Date.now();
  const hits = (attemptBuckets.get(key) ?? []).filter((t) => current - t < windowMs);
  if (hits.length >= max) {
    const oldest = hits[0] ?? current;
    return { ok: false, retryAfterSec: Math.max(1, Math.ceil((windowMs - (current - oldest)) / 1000)) };
  }
  hits.push(current);
  attemptBuckets.set(key, hits);
  if (attemptBuckets.size > 10_000) attemptBuckets.clear();
  return { ok: true, retryAfterSec: 0 };
}

/** Sign-in lock policy: 5 failures locks the account for 15 minutes (AUTH-09). */
export const SIGN_IN_LOCK = { maxFailures: 5, lockMs: 15 * 60_000 };

export const SESSION_TTL = {
  userIdle: 1000 * 60 * 60 * 12,
  adminIdle: 1000 * 60 * 30, // ADM-02 30-minute idle timeout
  absolute: 1000 * 60 * 60 * 8, // 8-hour absolute limit
};

export function sessionValid(session: { createdAt: string; lastSeenAt: string; revokedAt: string | null; role: string }, nowMs = Date.now()): boolean {
  if (session.revokedAt) return false;
  const idleLimit = session.role === "admin" ? SESSION_TTL.adminIdle : SESSION_TTL.userIdle;
  const idleOk = nowMs - Date.parse(session.lastSeenAt) < idleLimit;
  const absOk = nowMs - Date.parse(session.createdAt) < SESSION_TTL.absolute;
  return idleOk && absOk;
}

export function sessionCookie(sessionId: string, kind: "user" | "admin"): string {
  const name = kind === "admin" ? "cleancsv_admin_session" : "cleancsv_session";
  return `${name}=${sessionId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${8 * 60 * 60}`;
}

export function clearCookie(kind: "user" | "admin"): string {
  const name = kind === "admin" ? "cleancsv_admin_session" : "cleancsv_session";
  return `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

export type SessionContext = { userId: string; role: "user" | "admin"; sessionId: string };

/** Read the caller's session from an Authorization header or an HttpOnly cookie. */
export async function readSession(request: Request, db: import("./store").Db): Promise<SessionContext | null> {
  let sessionId = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ?? "";
  if (!sessionId) {
    const cookies = request.headers.get("cookie") ?? "";
    for (const part of cookies.split(";")) {
      const [k, v] = part.trim().split("=");
      if (k === "cleancsv_session" || k === "cleancsv_admin_session") sessionId = v ?? "";
    }
  }
  if (!sessionId) return null;
  const session = db.sessions.find((s) => s.id === sessionId);
  if (!session || !sessionValid(session)) return null;
  return { userId: session.userId, role: session.role, sessionId };
}
