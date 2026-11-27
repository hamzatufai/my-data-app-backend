import { preflight } from "@/lib/cors";
/**
 * ADM-04 User Detail View + ADM-05 User Status Actions.
 * GET  /api/admin/users/:id    → profile, status timeline, request + history
 * POST /api/admin/users/:id    → status action (approve/reject/suspend/reactivate/delete)
 */
import {
  Forbidden, ValidationError, fail, handleError, json, readJsonBody,
} from "@/lib/api-helpers";
import { requireAdmin } from "@/lib/api-helpers";
import { loadDb, withDb, type ScheduledStatusAction, type UserStatus } from "@/lib/store";
import { newId } from "@/lib/auth";
import { accessDecisionEmail, sendEmail } from "@/lib/email";

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const db = await loadDb();
    await requireAdmin(request, db);
    const { id } = await params;
    const user = db.users.find((u) => u.id === id);
    if (!user) return fail(request, 404, "User not found.");

    const accessRequests = db.accessRequests
      .filter((r) => r.userId === id)
      .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
    const userAudit = db.adminAuditEvents.filter(
      (e) => e.targetId === id || (e.details.includes(id) && e.action.startsWith("admin.")),
    );
    return json(request, {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        status: user.status,
        role: user.role,
        emailVerified: Boolean(user.emailVerifiedAt),
        createdAt: user.createdAt,
        lastSignInAt: user.lastSignInAt,
        requestSubmittedAt: user.requestSubmittedAt,
      },
      statusTimeline: user.statusHistory,
      accessRequests,
      audit: userAudit.sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)),
    });
  } catch (error) {
    return handleError(request, error);
  }
}

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const db = await loadDb();
    const { user: admin } = await requireAdmin(request, db);
    const { id } = await params;
    const body = await readJsonBody(request);
    const action = String(body.action ?? "") as ScheduledStatusAction;
    const reason = String(body.reason ?? "").trim();

    if (!["approve", "reject", "suspend", "reactivate", "delete"].includes(action)) {
      throw new ValidationError("Unknown status action.");
    }
    if ((action === "reject" || action === "suspend") && reason.length < 4) {
      throw new ValidationError("A reason is required for reject and suspend.");
    }

    const now = new Date().toISOString();
    const updated = await withDb((store) => {
      const target = store.users.find((u) => u.id === id && u.role === "user");
      if (!target) return null;
      // Database-truth rule (AUTH-03): approval is only possible after the
      // single-use link from that exact mailbox was consumed. The DB field
      // emailVerifiedAt is the source of truth, not any UI state.
      if (action === "approve" && !target.emailVerifiedAt) {
        throw new ValidationError("This email is not verified yet. The applicant must open the link sent to their mailbox first.");
      }
      const next: UserStatus =
        action === "approve" ? "approved"
        : action === "reject" ? "rejected"
        : action === "suspend" ? "suspended"
        : action === "reactivate" ? "approved"
        : "deleted";
      target.status = next;
      target.statusHistory.push({ status: next, at: now, by: admin.email, reason: reason || undefined });

      // Suspended/deleted users are signed out immediately (ADM-05).
      if (action === "suspend" || action === "delete") {
        store.sessions.forEach((s) => {
          if (s.userId === target.id && !s.revokedAt) s.revokedAt = now;
        });
      }
      if (action === "approve" || action === "reject") {
        store.accessRequests.forEach((r) => {
          if (r.userId === target.id && r.status === "pending") {
            r.status = action === "approve" ? "approved" : "rejected";
            r.reasonCode = action === "approve" ? undefined : reasonCodeFor(reason);
            r.reasonMessage = reason || undefined;
            r.decidedBy = admin.email;
            r.decidedAt = now;
          }
        });
      }
      store.adminAuditEvents.push({
        id: newId(),
        adminId: admin.id,
        action: `user.${action}`,
        targetType: "user",
        targetId: target.id,
        details: reason ? `${action}: ${reason}` : action,
        timestamp: now,
      });
      // ACC-06: applicant is emailed on approval / rejection.
      if (action === "approve" || action === "reject" || action === "reactivate") {
        const mail = accessDecisionEmail(
          target.name,
          action === "approve" || action === "reactivate",
          reason || undefined,
        );
        void sendEmail(target.email, mail.subject, mail.text);
      }
      return target.status;
    });

    if (!updated) return fail(request, 404, "User not found.");
    return json(request, { status: updated, action, decidedAt: now });
  } catch (error) {
    return handleError(request, error);
  }
}

function reasonCodeFor(reason: string): string {
  const normalized = reason.toLowerCase();
  if (normalized.includes("duplicate")) return "duplicate";
  if (normalized.includes("out of scope")) return "out_of_scope";
  return "unknown_organisation";
}

export async function OPTIONS(request: Request) {
  return preflight(request);
}
