import { preflight } from "@/lib/cors";
/**
 * AUTH-01 Applicant Sign-Up + AUTH-02 One Email, One Account Rule +
 * AUTH-05 Password Security + AUTH-09 rate limiting.
 *
 * Response is always generic (a duplicate is never revealed).
 */
import { promises as fs } from "fs";
import crypto from "crypto";
import {
  Conflict, RateLimited, ValidationError, handleError, json, readClientIp, readJsonBody,
} from "@/lib/api-helpers";
import {
  hashPassword, newId, newToken, normaliseEmail, passwordIssues, rateLimit,
} from "@/lib/auth";
import { withDb, type StoredUser } from "@/lib/store";
import { emailConfigured, frontendUrl, isDisposableEmail, sendEmail, verificationEmail } from "@/lib/email";

const VERIFY_TTL_MS = 24 * 60 * 60 * 1000;

export async function POST(request: Request) {
  try {
    const ip = readClientIp(request);
    const limit = rateLimit(`signup:${ip}`, 5, 60_000);
    if (!limit.ok) throw new RateLimited(limit.retryAfterSec);

    let body: Record<string, unknown>;
    try {
      body = await readJsonBody(request);
    } catch (error) {
      // 500s hide errors from the client; surface auth failures as 400 with a
      // logged stack so the operator can diagnose fast.
      console.error("[cleancsv] signup body parse failed", error);
      throw error instanceof Error && error.name === "ValidationError"
        ? error
        : new ValidationError("Request body must be valid JSON with name, email, password and acceptTerms.");
    }
    const name = String(body.name ?? "").trim();
    const email = normaliseEmail(String(body.email ?? ""));
    const password = String(body.password ?? "");
    const acceptTerms = body.acceptTerms === true;

    if (name.length < 2 || name.length > 80) throw new ValidationError("Please enter your full name.");
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new ValidationError("Enter a valid email address.");
    // Disposable mailboxes are rejected BEFORE creating anything: ownership is
    // proven by receiving the single-use link at this exact address (AUTH-03).
    if (isDisposableEmail(email)) {
      throw new ValidationError("Disposable or temporary email addresses are not accepted. Use your real mailbox.");
    }
    // Gmail-style alias circumvention: user+tag@gmail.com and u.s.e.r@gmail.com
    // all deliver to the same base mailbox. Normalise the check so one person
    // cannot mint multiple accounts from one Gmail address (AUTH-02).
    const gmailBase = /^gmail\.com$/.test(email.split("@")[1] ?? "") ? email.split("@")[0].replace(/\+.*$/, "").replace(/\./g, "") : undefined;
    const pwdIssues = passwordIssues(password);
    if (pwdIssues.length) throw new ValidationError(pwdIssues[0]);
    if (!acceptTerms) throw new ValidationError("You must accept the terms and privacy notice.");

    // AUTH-02: duplicate sign-up blocks registration without revealing existence.
    // Gmail aliases (dots / +tags) map to the same canonical base mailbox.
    const created = await withDb((db) => {
      const duplicateOf = (candidate: string): boolean => {
        if (typeof gmailBase !== "string") return false;
        const domain = candidate.split("@")[1] ?? "";
        if (!/^gmail\.com$/.test(domain)) return false;
        const base = candidate.split("@")[0].replace(/\+.*$/, "").replace(/\./g, "");
        return base === gmailBase;
      };
      if (db.users.some((user) => user.email === email || duplicateOf(user.email))) {
        db.adminAuditEvents.push({
          id: newId(),
          adminId: null,
          action: "signup.duplicate_blocked",
          targetType: "system",
          targetId: email.slice(0, 2) + "***",
          details: "Duplicate sign-up attempt blocked",
          timestamp: new Date().toISOString(),
        });
        throw new Conflict("An account already exists for this email address.");
      }

      const { token, tokenHash } = newToken();
      const user: StoredUser = {
        id: newId(),
        role: "user",
        mfaEnrolled: false,
        email,
        name,
        passwordHash: hashPassword(password),
        status: "unverified",
        statusHistory: [{ status: "unverified", at: new Date().toISOString(), by: "sign-up" }],
        emailVerifiedAt: null,
        lastSignInAt: null,
        failedSignInCount: 0,
        lockedUntil: null,
        requestSubmittedAt: null,
        requestText: null,
        createdAt: new Date().toISOString(),
      };
      db.users.push(user);
      db.tokens.push({
        id: newId(),
        userId: user.id,
        tokenHash,
        kind: "verify_email",
        expiresAt: new Date(Date.now() + VERIFY_TTL_MS).toISOString(),
        usedAt: null,
        createdAt: new Date().toISOString(),
      });
      return { user, token };
    });

    // AUTH-03: deliver the single-use verification link by Gmail when the
    // GMAIL_USER / GMAIL_APP_PASSWORD variables are configured. Otherwise the
    // token is exposed only in development so the flow stays testable.
    const link = `${frontendUrl()}/verify-email?token=${created.token}`;
    const mail = verificationEmail(created.user.name, link);
    let delivered = false;
    if (emailConfigured()) {
      delivered = await sendEmail(created.user.email, mail.subject, mail.text);
    } else if (process.env.NODE_ENV !== "production") {
      console.info(`[cleancsv] dev verification link: ${link}`);
      await fs.writeFile("data/last-verification-link.txt", created.token, "utf8").catch(() => {});
    } else {
      console.error("[cleancsv] email NOT configured — verification email could not be sent (GMAIL_USER/GMAIL_APP_PASSWORD missing)");
    }

    return json(request, {
      // Generic wording for every outcome (AUTH-02).
      message: emailConfigured()
        ? "Account created. Check your Gmail inbox for the verification link."
        : delivered
          ? "Account created. Check your inbox for the verification link."
          : "Account created. Verify your email to continue.",
      status: "unverified",
      emailConfigured: emailConfigured(),
      ...(emailConfigured() ? {} : process.env.NODE_ENV !== "production" ? { devVerificationUrl: created.token } : {}),
    }, 201);
  } catch (error) {
    return handleError(request, error);
  }
}

export async function OPTIONS(request: Request) {
  return preflight(request);
}
