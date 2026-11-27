/**
 * ADM-03 All Users List: search, status filter, sort, server-side pagination,
 * CSV export. Never includes password data or tokens.
 */
import { Forbidden, ValidationError, handleError, json } from "@/lib/api-helpers";
import { requireAdmin } from "@/lib/api-helpers";
import { loadDb, withDb, type UserStatus } from "@/lib/store";
import { newId } from "@/lib/auth";

const STATUSES: UserStatus[] = ["unverified", "pending", "approved", "rejected", "suspended", "deleted"];
const PAGE_SIZES = [25, 50, 100];

function publicRow(u: import("@/lib/store").StoredUser, db: import("@/lib/store").Db) {
  const latestRequest = db.accessRequests
    .filter((r) => r.userId === u.id)
    .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))[0];
  return {
    id: u.id,
    name: u.name,
    email: u.email,
    status: u.status,
    role: u.role,
    emailVerified: Boolean(u.emailVerifiedAt),
    createdAt: u.createdAt,
    lastSignInAt: u.lastSignInAt,
    requestDate: latestRequest?.createdAt ?? null,
    requestStatus: latestRequest?.status ?? null,
  };
}

export async function GET(request: Request) {
  try {
    const db = await loadDb();
    await requireAdmin(request, db);

    const url = new URL(request.url);
    if (url.searchParams.get("format") === "csv") {
      const rows = db.users
        .filter((u) => u.role === "user")
        .map((u) => publicRow(u, db));
      const lines = [
        ["id", "name", "email", "status", "email_verified", "created_at", "last_sign_in", "request_date"].join(","),
        ...rows.map((r) =>
          [r.id, r.name, r.email, r.status, r.emailVerified, r.createdAt, r.lastSignInAt ?? "", r.requestDate ?? ""]
            .map((v) => {
              const text = String(v);
              return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
            })
            .join(","),
        ),
      ];
      db.adminAuditEvents.push({
        id: newId(),
        adminId: null,
        action: "admin.users_exported",
        targetType: "system",
        targetId: null,
        details: "CSV export of user list",
        timestamp: new Date().toISOString(),
      });
      await withDb(() => undefined);
      return Response.json(lines.join("\n"), {
        headers: {
          "Cache-Control": "no-store",
          "Content-Disposition": 'attachment; filename="cleancsv-users.csv"',
        },
      });
    }

    const search = (url.searchParams.get("search") ?? "").trim().toLowerCase();
    const statusFilter = url.searchParams.get("status") ?? "";
    const sortKey = url.searchParams.get("sort") ?? "createdAt";
    const sortDir = url.searchParams.get("dir") === "asc" ? 1 : -1;
    const page = Math.max(1, Number(url.searchParams.get("page") ?? "1") || 1);
    const pageSize = PAGE_SIZES.includes(Number(url.searchParams.get("pageSize")))
      ? Number(url.searchParams.get("pageSize"))
      : 25;

    let rows = db.users.filter((u) => u.role === "user").map((u) => publicRow(u, db));
    if (search) {
      rows = rows.filter(
        (r) => r.name.toLowerCase().includes(search) || r.email.toLowerCase().includes(search),
      );
    }
    if (STATUSES.includes(statusFilter as UserStatus)) {
      rows = rows.filter((r) => r.status === statusFilter);
    }
    const validSortKeys = ["name", "email", "status", "createdAt", "lastSignInAt"];
    const key = validSortKeys.includes(sortKey) ? sortKey : "createdAt";
    rows.sort((a, b) => {
      const av = key === "createdAt" || key === "lastSignInAt" ? Date.parse(String((a as never)[key] ?? 0)) : String((a as never)[key] ?? "").toLowerCase();
      const bv = key === "createdAt" || key === "lastSignInAt" ? Date.parse(String((b as never)[key] ?? 0)) : String((b as never)[key] ?? "").toLowerCase();
      if (av === bv) return 0;
      return av > bv ? sortDir : -sortDir;
    });

    const total = rows.length;
    const pageCount = Math.max(1, Math.ceil(total / pageSize));
    const slice = rows.slice((page - 1) * pageSize, page * pageSize);

    return json(request, {
      users: slice,
      total,
      page,
      pageCount,
      pageSize,
    });
  } catch (error) {
    return handleError(request, error);
  }
}
