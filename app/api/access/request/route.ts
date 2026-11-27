import { preflight } from "@/lib/cors";
/**
 * ACC-01 Access Request Form. Available after email verification.
 * Creates a Pending request visible in the admin queue (ACC-02).
 */
import {
  Conflict, Forbidden, Unauthorized, ValidationError, handleError, json, readJsonBody,
} from "@/lib/api-helpers";
import { requireUser } from "@/lib/api-helpers";
import { loadDb, withDb, type AccessRequest } from "@/lib/store";
import { newId } from "@/lib/auth";

export async function GET(request: Request) {
  try {
    const db = await loadDb();
    const { user } = await requireUser(request, db, false);
    const existing = db.accessRequests
      .filter((r) => r.userId === user.id)
      .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))[0];
    return json(request, {
      request: existing
        ? {
            status: existing.status,
            reasonCode: existing.reasonCode ?? undefined,
            reasonMessage: existing.reasonMessage ?? undefined,
            decidedAt: existing.decidedAt ?? undefined,
            createdAt: existing.createdAt,
          }
        : undefined,
      userStatus: user.status,
      emailVerified: Boolean(user.emailVerifiedAt),
    });
  } catch (error) {
    return handleError(request, error);
  }
}

export async function POST(request: Request) {
  try {
    const db = await loadDb();
    const { user } = await requireUser(request, db, false);
    if (user.role !== "user") throw new Forbidden("Admins do not submit access requests.");
    if (!user.emailVerifiedAt || user.status === "unverified") {
      throw new Unauthorized("Verify your email before submitting an access request.");
    }
    // The guard is on the request record, not the user status: after email
    // verification the user is already in status Pending (awaiting approval),
    // so the request record is the source of truth (ACC-01).
    if (db.accessRequests.some((r) => r.userId === user.id)) {
      throw new Conflict("An access request already exists for this account.");
    }
    if (user.status === "approved") {
      throw new Conflict("You already have platform access.");
    }
    if (user.status === "rejected" || user.status === "suspended") {
      throw new Forbidden("This account cannot submit a new access request.");
    }

    const body = await readJsonBody(request);
    const fullName = String(body.fullName ?? "").trim();
    const jobRole = String(body.jobRole ?? "").trim();
    const intendedUse = String(body.intendedUse ?? "").trim();
    const organisation = String(body.organisation ?? "").trim();
    const dataTypes = String(body.dataTypes ?? "").trim();

    if (fullName.length < 2) throw new ValidationError("Full name is required.");
    if (jobRole.length < 2) throw new ValidationError("Job role is required.");
    if (intendedUse.length < 20) {
      throw new ValidationError("Please describe your intended use in at least 20 characters.");
    }

    const record: AccessRequest = {
      id: newId(),
      userId: user.id,
      fullName,
      organisation,
      dataTypes,
      jobRole,
      intendedUse,
      createdAt: new Date().toISOString(),
      status: "pending",
    };

    await withDb((store) => {
      store.accessRequests.push(record);
      user.requestSubmittedAt = record.createdAt;
      user.status = "pending";
      user.requestText = intendedUse;
      user.statusHistory.push({ status: "pending", at: record.createdAt, by: "access-request" });
      store.adminAuditEvents.push({
        id: newId(),
        adminId: null,
        action: "access.request_submitted",
        targetType: "request",
        targetId: record.id,
        details: `Access request submitted by ${user.email.slice(0, 2)}***`,
        timestamp: record.createdAt,
      });
    });

    // ACC-06 admin notification would be emailed here (email provider TBD — PRD Open Decision).
    console.info(`[cleancsv] access request pending: ${user.email.slice(0, 2)}***`);

    return json(request, {
      message: "Your access request has been submitted and is awaiting review.",
      status: "pending",
      requestId: record.id,
    }, 201);
  } catch (error) {
    return handleError(request, error);
  }
}

export async function OPTIONS(request: Request) {
  return preflight(request);
}
