import { NextResponse } from "next/server";
import { corsHeaders } from "@/lib/cors";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  return NextResponse.json(
    {
      status: "ok",
      service: "cleancsv-backend",
    },
    {
      headers: corsHeaders(request),
    },
  );
}

export async function OPTIONS(request: Request) {
  return new NextResponse(null, {
    status: 204,
    headers: corsHeaders(request),
  });
}
