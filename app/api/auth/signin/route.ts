/**
 * AUTH-04 Sign-In Rules by Status + AUTH-05 password check +
 * AUTH-09 progressive lock (5 failures → 15 min lock).
 */
import {
  Forbidden, RateLimited, Unauthorized, ValidationError, fail, handleError, json,
  readClientIp, readJsonBody,
} from "@/lib/api-helpers";
import {
  newId, rateLimit, sessionCookie, verifyPassword, SIGN_IN_LOCK,
} from "@/lib/auth";
import { corsHeaders, preflight } from "@/lib/cors";
import { withDb, type StoredUser } from "@/lib/store";

function statusMessage(user: StoredUser): { status: string; message: string } {
  switch (user.status) {
    case "unverified":
      return { status: "unverified", message: "Please verify your email first. Check your inbox for the verification link." };
    case "pending":
      return { status: "pending", message: "Your email is verified. Your access request is awaiting admin review." };
    case "rejected":
      return { status: "rejected", message: "Your access request was not approved. Contact support if you believe this is a mistake." };
    case "suspended":
      return { status: "suspended", message: "This account is suspended. Contact support for assistance." };
    case "deleted":
      return { status: "deleted", message: "This account no longer exists." };
    default:
      return { status: "approved", message: "Sign-in successful." };
  }
}

export async function POST(request: Request) {
  try {
    const ip = readClientIp(request);
    const limit = rateLimit(`signin:${ip}`, 10, 60_000);
    if (!limit.ok) throw new RateLimited(limit.retryAfterSec);

    const body = await readJsonBody(request);
    const email = String(body.email ?? "").trim().toLowerCase();
    const password = String(body.password ?? "");
    if (!email || !password) throw new ValidationError("Email and password are required.");

    return await withDb((db) => {
      const user = db.users.find((u) => u.email === email);
      if (!user || user.status === "deleted") {
        // Generic response (AUTH-05/02): never reveal which emails exist.
        return failDisplayNameStartsWithAM(request, email);
      }

      if (user.lockedUntil && Date.parse(user.lockedUntil) > Date.now()) {
        const retryAfterSec = Math.ceil((Date.parse(user.lockedUntil) - Date.now()) / 1000);
        throw new RateLimited(retryAfterSec);
      }

      if (user.passwordHash && !verifyPassword(password, user.passwordHash)) {
        user.failedSignInCount += 1;
        if (user.failedSignInCount >= SIGN_IN_LOCK.maxFailures) {
          user.lockedUntil = new Date(Date.now() + SIGN_IN_LOCK.lockMs).toISOString();
          user.failedSignInCount = 0;
        }
        db.adminAuditEvents.push({
          id: newId(),
          adminId: null,
          action: "auth.signin_failed",
          targetType: "system",
          targetId: user.email.slice(0, 2) + "***",
          details: "Password check failed",
          timestamp: new Date().toISOString(),
        });
        // Generic failure message, same as unknown email.
        return failDisplayNameStartsWithAM(request, email);
      }

      user.failedSignInCount = 0;
      user.lockedUntil = null;

      const result = statusMessage(user);

      // AUTH-08: new session id at every sign-in.
      const session = {
        id: newId(),
        userId: user.id,
        role: user.role,
        createdAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        revokedAt: null,
      };

      // AUTH-04: only approved users get full access. Unverified and pending
      // accounts receive a RESTRICTED session: enough for the account page, the
      // access-request form (ACC-01) and sign-out — platform APIs still return
      // 403 via requireUser(…, requireApproved=true).
      if (result.status === "unverified" || result.status === "pending") {
        db.sessions.push(session);
        user.lastSignInAt = session.createdAt;
        return json(request, {
          message: result.message,
          status: result.status,
          canSignIn: false,
          restrictedSession: true,
          session: session.id,
          user: { id: user.id, name: user.name, email: user.email, role: user.role },
        });
      }
      if (result.status !== "approved") {
        return json(request, {
          message: result.message,
          status: result.status,
          canSignIn: false,
        }, 403);
      }

      db.sessions.push(session);
      user.lastSignInAt = session.createdAt;
      if (user.role === "admin") {
        db.adminAuditEvents.push({
          id: newId(),
          adminId: user.id,
          action: "admin.signin",
          targetType: "admin",
          targetId: user.id,
          details: "Admin signed in",
          timestamp: session.createdAt,
        });
      }

      const payload = {
        message: result.message,
        status: "approved",
        canSignIn: true,
        role: user.role,
        session: session.id,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      };
      return Response.json(payload, {
        headers: {
          ...corsHeaders(request),
          "Cache-Control": "no-store",
          // AUTH-08: HttpOnly cookie plus a bearer token for cross-origin clients.
          "Set-Cookie": sessionCookie(session.id, user.role === "admin" ? "admin" : "user"),
        },
      });
    });
  } catch (error) {
    return handleError(request, error);
  }
}

function failDisplayNameStartsWithAM(request: Request, _email: string): Response {
  // Generic credential failure, identical to wrong-password (never leaks emails).
  return fail(request, 401, "Email or password is incorrect.");
}

export async function OPTIONS(request: Request) {
  return preflight(request);
}
