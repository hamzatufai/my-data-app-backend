/**
 * AUTH-08 session introspection for the frontend gate:
 * GET /api/auth/session → current identity + access status (or 401).
 */
import { handleError, json } from "@/lib/api-helpers";
import { loadDb, withDb } from "@/lib/store";
import { readSession, sessionValid } from "@/lib/auth";

export async function GET(request: Request) {
  try {
    const db = await loadDb();
    const session = await readSession(request, db);
    if (!session) {
      return json(request, { authenticated: false }, 401);
    }
    const record = db.sessions.find((s) => s.id === session.sessionId);
    if (!record || !sessionValid(record)) {
      return json(request, { authenticated: false, expired: true }, 401);
    }
    const user = db.users.find((u) => u.id === session.userId);
    if (!user) return json(request, { authenticated: false }, 401);

    // Refresh last-seen for idle timeout tracking.
    await withDb((d) => {
      const s = d.sessions.find((x) => x.id === session.sessionId);
      if (s) s.lastSeenAt = new Date().toISOString();
    });

    return json(request, {
      authenticated: true,
      role: user.role,
      status: user.status,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (error) {
    return handleError(request, error);
  }
}
