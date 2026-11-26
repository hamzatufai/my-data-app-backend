import { NextResponse } from "next/server";
import { corsHeaders } from "@/lib/cors";

export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json(
    { status: "ok", service: "cleancsv-backend" },
    { headers: corsHeaders() },
  );
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: corsHeaders() });
}
