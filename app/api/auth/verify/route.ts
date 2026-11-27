import { preflight } from "@/lib/cors";
/**
 * AUTH-03 Email Verification: single-use link, 24h expiry.
 * GET  /api/auth/verify?token=...  → consumes the token (single use)
 * POST /api/auth/verify            → resend (rate limited, 3/hour)
 */
import {
  Conflict, RateLimited, ValidationError, fail, handleError, json, readClientIp, readJsonBody,
} from "@/lib/api-helpers";
import { hashToken, newToken, rateLimit } from "@/lib/auth";
import { withDb } from "@/lib/store";
import { emailConfigured, frontendUrl, sendEmail, verificationEmail } from "@/lib/email";

export async function GET(request: Request) {
  try {
    const url = new URL(request.url);
    const token = url.searchParams.get("token") ?? "";
    if (!token) throw new ValidationError("Verification token is missing.");

    const verified = await withDb((db) => {
      const record = db.tokens.find(
        (t) => t.kind === "verify_email" && t.tokenHash === hashToken(token) && !t.usedAt,
      );
      // Generic failure: single-use tokens are never reusable (AUTH-03).
      if (!record) return "invalid";
      if (Date.parse(record.expiresAt) < Date.now()) return "expired";
      record.usedAt = new Date().toISOString();
      const user = db.users.find((u) => u.id === record.userId);
      if (!user) return "invalid";
      // Consume every other outstanding verification token for this user.
      db.tokens.forEach((t) => {
        if (t.userId === user.id && t.kind === "verify_email" && !t.usedAt) t.usedAt = new Date().toISOString();
      });
      user.emailVerifiedAt = record.usedAt;
      user.status = "pending";
      user.statusHistory.push({ status: "pending", at: record.usedAt, by: "email-verification" });
      return user.id;
    });

    if (verified === "invalid" || verified === "expired") {
      return fail(request, 400, `This verification link is ${verified}. Request a new verification email.`);
    }
    return json(request, {
      message: "Email verified. Your access request is the next step.",
      status: "pending",
      userId: undefined,
    });
  } catch (error) {
    return handleError(request, error);
  }
}

export async function POST(request: Request) {
  try {
    const ip = readClientIp(request);
    const limit = rateLimit(`verify-resend:${ip}`, 3, 60 * 60_000);
    if (!limit.ok) throw new RateLimited(limit.retryAfterSec);

    const body = await readJsonBody(request);
    const email = String(body.email ?? "").trim().toLowerCase();
    if (!email) throw new ValidationError("Email is required.");

    let pendingName = "";
    await withDb((db) => {
      const user = db.users.find((u) => u.email === email);
      if (!user || user.emailVerifiedAt || user.status === "deleted") {
        // Generic: do not reveal which emails exist.
        return;
      }
      db.tokens.forEach((t) => {
        if (t.userId === user.id && t.kind === "verify_email" && !t.usedAt) t.usedAt = new Date().toISOString();
      });
      const { token, tokenHash } = newToken();
      db.tokens.push({
        id: crypto.randomUUID(),
        userId: user.id,
        tokenHash,
        kind: "verify_email",
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
        usedAt: null,
        createdAt: new Date().toISOString(),
      });
      pendingName = user.name;
      devTokens.push(token);
    });

    const resendToken = devTokens.pop();
    let devToken: string | undefined;
    if (resendToken) {
      const mail = verificationEmail(pendingName, `${frontendUrl()}/verify-email?token=${resendToken}`);
      if (await sendEmail(email, mail.subject, mail.text)) {
        devToken = undefined;
      } else {
        devToken = process.env.NODE_ENV !== "production" ? resendToken : undefined;
        if (process.env.NODE_ENV === "production") {
          console.error("[cleancsv] resend: email delivery failed");
        }
      }
    }
    return json(request, {
      message: "If this email can be verified, a new link has been sent.",
      ...(devToken ? { devToken } : {}),
    });

    async function deliverVerification(to: string, name: string, token: string) {
      const mail = verificationEmail(name, `${frontendUrl()}/verify-email?token=${token}`);
      return sendEmail(to, mail.subject, mail.text);
    }
  } catch (error) {
    return handleError(request, error);
  }
}

import crypto from "crypto";
const devTokens: string[] = [];

export async function OPTIONS(request: Request) {
  return preflight(request);
}
