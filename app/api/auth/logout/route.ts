import { preflight } from "@/lib/cors";
/** AUTH-08 / ADM-02: revokes the caller's session. */
import { handleError, json } from "@/lib/api-helpers";
import { clearCookie } from "@/lib/auth";
import { withDb } from "@/lib/store";

export async function POST(request: Request) {
  try {
    let sessionId = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ?? "";
    if (!sessionId) {
      const cookies = request.headers.get("cookie") ?? "";
      for (const part of cookies.split(";")) {
        const [k, v] = part.trim().split("=");
        if (k === "cleancsv_session" || k === "cleancsv_admin_session") sessionId = v ?? "";
      }
    }
    if (sessionId) {
      await withDb((db) => {
        const session = db.sessions.find((s) => s.id === sessionId);
        if (session) session.revokedAt = new Date().toISOString();
      });
    }
    return new Response(JSON.stringify({ message: "Signed out." }), {
      headers: {
        "Cache-Control": "no-store",
        "Set-Cookie": clearCookie("user") + ", " + clearCookie("admin"),
      },
    });
  } catch (error) {
    return handleError(request, error);
  }
}

export async function OPTIONS(request: Request) {
  return preflight(request);
}
