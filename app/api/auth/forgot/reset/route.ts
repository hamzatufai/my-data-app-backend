import { preflight } from "@/lib/cors";
/** AUTH-06: apply a password reset with a single-use token; revoke all sessions. */
import {
  RateLimited, ValidationError, fail, handleError, json, readClientIp, readJsonBody,
} from "@/lib/api-helpers";
import { hashPassword, hashToken, passwordIssues, rateLimit } from "@/lib/auth";
import { withDb } from "@/lib/store";
import crypto from "crypto";

const RESET_TTL_MS = 45 * 60_000;

export async function POST(request: Request) {
  try {
    const ip = readClientIp(request);
    const limit = rateLimit(limiterKey(ip), 10, 60 * 60_000);
    if (!limit.ok) throw new RateLimited(limit.retryAfterSec);

    const body = await readJsonBody(request);
    const token = String(body.token ?? "");
    const password = String(body.password ?? "");
    if (!token) throw new ValidationError("Reset token is missing.");
    const issues = passwordIssues(password);
    if (issues.length) throw new ValidationError(issues[0]);

    const result = await withDb((db) => {
      const record = db.tokens.find(
        (t) => t.kind === "reset_password" && t.tokenHash === hashToken(token) && !t.usedAt,
      );
      if (!record || Date.parse(record.expiresAt) < Date.now()) return false;
      record.usedAt = new Date().toISOString();
      const user = db.users.find((u) => u.id === record.userId);
      if (!user) return false;
      user.passwordHash = hashPassword(password);
      user.failedSignInCount = 0;
      user.lockedUntil = null;
      // All active sessions are revoked after a successful reset (AUTH-06).
      db.sessions.forEach((s) => {
        if (s.userId === user.id && !s.revokedAt) s.revokedAt = new Date().toISOString();
      });
      // Single-use: burn all outstanding reset tokens for this user.
      db.tokens.forEach((t) => {
        if (t.userId === user.id && t.kind === "reset_password" && !t.usedAt) {
          t.usedAt = new Date().toISOString();
        }
      });
      db.adminAuditEvents.push({
        id: crypto.randomUUID(),
        adminId: null,
        action: "auth.password_reset",
        targetType: "system",
        targetId: user.email.slice(0, 2) + "***",
        details: "Password reset completed; sessions revoked",
        timestamp: new Date().toISOString(),
      });
      return true;
    });

    if (!result) {
      return fail(request, 400, "This reset link is invalid or expired. Request a new one.");
    }
    return json(request, { message: "Password updated. Sign in with your new password." });
  } catch (error) {
    return handleError(request, error);
  }
}

function limiterKey(ip: string): string {
  return `reset:${ip}`;
}

export async function OPTIONS(request: Request) {
  return preflight(request);
}
