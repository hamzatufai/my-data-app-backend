import { preflight } from "@/lib/cors";
/**
 * AUTH-06 Forgot and Reset Password.
 * POST /api/auth/forgot            → creates a single-use reset token (45 min).
 * POST /api/auth/forgot/reset      → applies reset; revokes all sessions.
 * Both endpoints respond generically so emails are never revealed.
 */
import {
  RateLimited, ValidationError, fail, handleError, json, readClientIp, readJsonBody,
} from "@/lib/api-helpers";
import { hashPassword, hashToken, newToken, passwordIssues, rateLimit } from "@/lib/auth";
import { withDb } from "@/lib/store";

const RESET_TTL_MS = 45 * 60_000;

export async function POST(request: Request) {
  try {
    const ip = readClientIp(request);
    const limit = rateLimit(`forgot:${ip}`, 3, 60 * 60_000);
    if (!limit.ok) throw new RateLimited(limit.retryAfterSec);

    const body = await readJsonBody(request);
    const email = String(body.email ?? "").trim().toLowerCase();
    if (!email) throw new ValidationError("Email is required.");

    let devToken: string | undefined;
    await withDb((db) => {
      const user = db.users.find((u) => u.email === email && u.status !== "deleted");
      if (!user) return; // generic path — nothing is revealed
      db.tokens.forEach((t) => {
        if (t.userId === user.id && t.kind === "reset_password" && !t.usedAt) t.usedAt = new Date().toISOString();
      });
      const { token, tokenHash } = newToken();
      db.tokens.push({
        id: crypto.randomUUID(),
        userId: user.id,
        tokenHash,
        kind: "reset_password",
        expiresAt: new Date(Date.now() + RESET_TTL_MS).toISOString(),
        usedAt: null,
        createdAt: new Date().toISOString(),
      });
      if (process.env.NODE_ENV !== "production") {
        devToken = token;
        console.info(`[cleancsv] reset token (dev): ${token.slice(0, 8)}… for ${user.email.slice(0, 2)}***`);
      } else {
        console.info(`[cleancsv] reset token created for ${user.email.slice(0, 2)}***`);
      }
    });

    return json(request, {
      message: "If this email can be reset, a reset link has been sent.",
      ...(devToken ? { devToken } : {}),
    });
  } catch (error) {
    return handleError(request, error);
  }
}

import crypto from "crypto";

export async function OPTIONS(request: Request) {
  return preflight(request);
}
