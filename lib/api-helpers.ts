import { corsHeaders } from "./cors";
import type { Db, StoredUser, AccessRequest, PlatformSettings } from "./store";
import { readSession, type SessionContext } from "./auth";

export function json(request: Request, body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: { ...corsHeaders(request), "Cache-Control": "no-store" },
  });
}

export function fail(request: Request, status: number, error: string, extra: Record<string, unknown> = {}): Response {
  return json(request, { error, ...extra }, status);
}

export function readClientIp(request: Request): string {
  return (
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    request.headers.get("x-real-ip") ??
    "unknown"
  );
}

/** Disallow cross-origin JSON mutations unless the caller sent JSON. */
export async function readJsonBody(request: Request): Promise<Record<string, unknown>> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    throw new ValidationError("Content-Type must be application/json");
  }
  const body: unknown = await request.json().catch(() => null);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new ValidationError("Body must be a JSON object");
  }
  return body as Record<string, unknown>;
}

export class ValidationError extends Error {}
export class Unauthorized extends Error {}
export class Forbidden extends Error {}
export class Conflict extends Error {}
export class RateLimited extends Error {
  retryAfterSec: number;
  constructor(retryAfterSec: number) {
    super("Too many requests");
    this.retryAfterSec = retryAfterSec;
  }
}

export function handleError(request: Request, error: unknown): Response {
  if (error instanceof ValidationError) return fail(request, 400, error.message);
  if (error instanceof Unauthorized) return fail(request, 401, error.message);
  if (error instanceof Forbidden) return fail(request, 403, error.message);
  if (error instanceof Conflict) return fail(request, 409, error.message);
  if (error instanceof RateLimited) {
    return fail(request, 429, "Too many requests. Try again later.", {
      retryAfterSec: error.retryAfterSec,
    });
  }
  // Log the server-side detail but never echo it to the client.
  console.error("[cleancsv] unhandled API error", error);
  return fail(request, 500, "Internal error");
}

function publicUser(user: StoredUser) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    status: user.status,
    role: user.role,
    emailVerified: Boolean(user.emailVerifiedAt),
    createdAt: user.createdAt,
    lastSignInAt: user.lastSignInAt,
    requestSubmittedAt: user.requestSubmittedAt,
  };
}

/**
 * ACC-05: server-side access gate. Every user-facing page/API must pass here.
 * Parameter `requireApproved` blocks Unverified/Pending/Rejected/Suspended.
 */
export async function requireUser(
  request: Request,
  db: Db,
  requireApproved = true,
): Promise<{ session: SessionContext; user: StoredUser }> {
  const session = await readSession(request, db);
  if (!session || session.role !== "user") throw new Unauthorized("Sign in to continue.");
  const user = db.users.find((u) => u.id === session.userId);
  if (!user || user.role !== "user") throw new Unauthorized("Sign in to continue.");

  if (requireApproved) {
    if (user.status === "pending") {
      throw new Forbidden("Your access request is awaiting review.");
    }
    if (user.status === "rejected") {
      throw new Forbidden("Your access request was not approved.");
    }
    if (user.status === "suspended" || user.status === "deleted") {
      throw new Forbidden("This account no longer has platform access.");
    }
    if (user.status === "unverified") {
      throw new Unauthorized("Verify your email to continue.");
    }
    if (!user.emailVerifiedAt) throw new Unauthorized("Verify your email to continue.");
    if (user.status !== "approved") throw new Forbidden("Platform access is not active.");
  }
  return { session, user };
}

/** ADM-08: server-side admin-only gate. Non-admins get 403. */
export async function requireAdmin(
  request: Request,
  db: Db,
): Promise<{ session: SessionContext; user: StoredUser }> {
  const session = await readSession(request, db);
  if (!session || session.role !== "admin") throw new Forbidden("Admin access required.");
  const admin = db.users.find((u) => u.id === session.userId && u.role === "admin");
  if (!admin) throw new Forbidden("Admin access required.");
  return { session, user: admin };
}

export { publicUser, type AccessRequest, type PlatformSettings };
