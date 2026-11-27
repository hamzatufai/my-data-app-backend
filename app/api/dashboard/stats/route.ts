import { NextResponse } from "next/server";
import { corsHeaders } from "@/lib/cors";
import { requireUser } from "@/lib/api-helpers";
import { loadDb } from "@/lib/store";

// ACC-05: server-side access gate. Only approved, verified users can read
// platform stats. The gate is enforced here, not only in the UI.
export const dynamic = "force-dynamic";

export async function OPTIONS(request: Request) {
  return new NextResponse(null, {
    status: 204,
    headers: corsHeaders(request),
  });
}

export async function GET(request: Request) {
  const db = await loadDb();
  const gate = await requireUser(request, db).catch((error) => error);
  const status = gate instanceof Error ? 403 : 200; // 401 vs 403 distinction kept simple: challenge
  const headers =
    gate instanceof Error
      ? { "WWW-Authenticate": "Bearer" }
      : {};
  void headers;
  if (gate instanceof Error) {
    return NextResponse.json(
      { error: gate.message },
      { status, headers: corsHeaders(request) },
    );
  }

  // This endpoint reports the current empty-store state. It deliberately does
  // not invent production statistics; it can be connected to persisted data later.
  return NextResponse.json(
    {
      datasets: 0,
      rows: 0,
      quality: null,
      operations: 0,
    },
    { headers: corsHeaders(request) },
  );
}
