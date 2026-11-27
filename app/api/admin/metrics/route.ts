/** ADM-06 Admin Overview Metrics — live database counts, not estimates. */
import { Forbidden, handleError, json } from "@/lib/api-helpers";
import { requireAdmin } from "@/lib/api-helpers";
import { loadDb } from "@/lib/store";

export async function GET(request: Request) {
  try {
    const db = await loadDb();
    await requireAdmin(request, db); // ADM-08 server-side route protection

    const users = db.users.filter((u) => u.role === "user");
    const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    const pending = db.accessRequests.filter((r) => r.status === "pending");

    return json(request, {
      metrics: {
        totalUsers: users.length,
        verifiedUsers: users.filter((u) => u.emailVerifiedAt).length,
        pendingRequests: pending.length,
        approved: users.filter((u) => u.status === "approved").length,
        rejected: users.filter((u) => u.status === "rejected").length,
        suspended: users.filter((u) => u.status === "suspended").length,
        newSignUps7d: users.filter((u) => Date.parse(u.createdAt) >= sevenDaysAgo).length,
      },
    });
  } catch (error) {
    return handleError(request, error);
  }
}
