import { NextResponse } from "next/server";
import { corsHeaders } from "@/lib/cors";

// This endpoint reports the current empty-store state. It deliberately does not
// invent production statistics; it can be connected to persisted data later.
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
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

export async function OPTIONS(request: Request) {
  return new NextResponse(null, {
    status: 204,
    headers: corsHeaders(request),
  });
}
