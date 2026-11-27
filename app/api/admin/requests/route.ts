/**
 * ACC-02 Request Queue: pending requests oldest-first with a badge count.
 * Also exposes decision history. Full request decisions happen through
 * ADM-05 user status actions (approve/reject) recorded on the request.
 */
import { Forbidden, handleError, json } from "@/lib/api-helpers";
import { requireAdmin } from "@/lib/api-helpers";
import { loadDb } from "@/lib/store";

export async function GET(request: Request) {
  try {
    const db = await loadDb();
    await requireAdmin(request, db);

    const url = new URL(request.url);
    const status = url.searchParams.get("status") ?? "pending";
    const target = ["pending", "approved", "rejected", "all"].includes(status) ? status : "pending";

    const requests = db.accessRequests
      .filter((r) => target === "all" || r.status === target)
      .sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt))
      .map((r) => {
        const user = db.users.find((u) => u.id === r.userId);
        return {
          id: r.id,
          userId: r.userId,
          fullName: r.fullName,
          organisation: r.organisation,
          jobRole: r.jobRole,
          intendedUse: r.intendedUse,
          dataTypes: r.dataTypes,
          reasonCode: r.reasonCode,
          reasonMessage: r.reasonMessage,
          decidedBy: r.decidedBy,
          decidedAt: r.decidedAt,
          status: r.status,
          createdAt: r.createdAt,
          email: user?.email ?? "",
          userStatus: user?.status ?? "unknown",
        };
      });

    return json(request, {
      requests,
      pendingCount: db.accessRequests.filter((r) => r.status === "pending").length,
    });
  } catch (error) {
    return handleError(request, error);
  }
}
