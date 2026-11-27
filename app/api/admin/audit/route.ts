/**
 * ADM-07 Admin Audit Log. Read-only: filters by admin, date range and action
 * type. Entries cannot be edited or deleted by anyone — no mutation endpoint
 * exists for this table.
 */
import { Forbidden, handleError, json } from "@/lib/api-helpers";
import { requireAdmin } from "@/lib/api-helpers";
import { loadDb, withDb } from "@/lib/store";

export async function GET(request: Request) {
  try {
    const db = await loadDb();
    await requireAdmin(request, db);

    const url = new URL(request.url);
    const adminId = url.searchParams.get("adminId") ?? "";
    const actionPrefix = url.searchParams.get("action") ?? "";
    const from = url.searchParams.get("from") ?? "";
    const to = url.searchParams.get("to") ?? "";

    let entries = [...db.adminAuditEvents].sort(
      (a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp),
    );
    if (adminId) entries = entries.filter((e) => e.adminId === adminId);
    if (actionPrefix) entries = entries.filter((e) => e.action.startsWith(actionPrefix));
    if (from) entries = entries.filter((e) => e.timestamp >= from);
    if (to) entries = entries.filter((e) => e.timestamp <= to);

    await withDb(() => undefined);
    return json(request, {
      events: entries.slice(0, 300).map((e) => ({
        id: e.id,
        adminId: e.adminId,
        adminEmail: db.users.find((u) => u.id === e.adminId)?.email ?? null,
        action: e.action,
        targetType: e.targetType,
        targetId: e.targetId,
        details: e.details,
        timestamp: e.timestamp,
      })),
      total: entries.length,
    });
  } catch (error) {
    return handleError(request, error);
  }
}
