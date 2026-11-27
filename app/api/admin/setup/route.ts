/**
 * ADM-01 Admin Sign-Up (First-Run Setup).
 * - Open only while no admin exists AND the one-time SETUP_TOKEN matches.
 * - After this, no public admin account can ever be created (27/26 out-of-scope).
 * - Returns a signed-in admin session (MFA enrolment hook documented below).
 */
import {
  Conflict, Forbidden, RateLimited, ValidationError, fail, handleError, json, readClientIp, readJsonBody,
} from "@/lib/api-helpers";
import {
  hashPassword, hashToken, newId, passwordIssues, rateLimit, sessionCookie,
} from "@/lib/auth";
import { loadDb, withDb, type StoredUser } from "@/lib/store";
import { corsHeaders, preflight } from "@/lib/cors";
import crypto from "crypto";

const expectedSetupToken = () =>
  hashToken(process.env.SETUP_TOKEN ?? "").length === 64
    ? process.env.SETUP_TOKEN ?? ""
    : "";

export async function GET(request: Request) {
  try {
    const db = await loadDb();
    const hasAdmin = db.users.some((u) => u.role === "admin");
    return json(request, {
      setupOpen: !hasAdmin && Boolean(expectedSetupToken()),
      hasAdmin,
    });
  } catch (error) {
    return handleError(request, error);
  }
}

export async function POST(request: Request) {
  try {
    const ip = readClientIp(request);
    const limit = rateLimit(`admin-setup:${ip}`, 5, 60 * 60_000);
    if (!limit.ok) throw new RateLimited(limit.retryAfterSec);

    const db = await loadDb();
    if (db.users.some((u) => u.role === "admin")) {
      throw new Forbidden("Admin setup is closed. An administrator already exists.");
    }

    const body = await readJsonBody(request);
    const setupToken = String(body.setupToken ?? "");
    const name = String(body.name ?? "").trim();
    const email = String(body.email ?? "").trim().toLowerCase();
    const password = String(body.password ?? "");

    if (!setupToken || setupToken !== expectedSetupToken()) {
      throw new Forbidden("Invalid setup token.");
    }
    if (name.length < 2) throw new ValidationError("Administrator name is required.");
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new ValidationError("Enter a valid email address.");
    const issues = passwordIssues(password);
    if (issues.length) throw new ValidationError(issues[0]);

    if (db.users.some((u) => u.email === email)) {
      throw new Conflict("This email is already registered. Use sign-in instead of admin setup.");
    }

    const now = new Date().toISOString();
    const admin: StoredUser = {
      id: newId(),
      role: "admin",
      mfaEnrolled: false,
      email,
      name,
      passwordHash: hashPassword(password),
      status: "approved",
      statusHistory: [{ status: "approved", at: now, by: "first-run-setup" }],
      emailVerifiedAt: now,
      lastSignInAt: null,
      failedSignInCount: 0,
      lockedUntil: null,
      requestSubmittedAt: null,
      requestText: null,
      createdAt: now,
    };

    const session = {
      id: newId(),
      userId: admin.id,
      role: "admin" as const,
      createdAt: now,
      lastSeenAt: now,
      revokedAt: null,
    };

    await withDb((store) => {
      store.users.push(admin);
      store.sessions.push(session);
      store.adminAuditEvents.push({
        id: newId(),
        adminId: admin.id,
        action: "admin.setup_completed",
        targetType: "admin",
        targetId: admin.id,
        details: "First-run admin setup completed",
        timestamp: now,
      });
    });

    const payload = {
      message: "Administrator created. MFA enrolment is required before full admin use (AUTH-07).",
      mfaRequired: true,
      role: "admin",
      user: { id: admin.id, name: admin.name, email: admin.email, role: "admin" },
    };
    return Response.json(payload, {
      headers: {
        ...corsHeaders(request),
        "Cache-Control": "no-store",
        "Set-Cookie": sessionCookie(session.id, "admin"),
      },
    });
  } catch (error) {
    return handleError(request, error);
  }
}

export async function OPTIONS(request: Request) {
  return preflight(request);
}
