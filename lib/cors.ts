const ALLOWED_ORIGINS = [
  "https://hamzatufai-my-data-app-frontend.vercel.app",
  "http://localhost:3000",
];

// Vercel gives each preview deployment its own hostname. Keep this pattern
// scoped to this project and team; never allow every *.vercel.app origin.
const VERCEL_PREVIEW_ORIGIN =
  /^https:\/\/hamzatufai-my-data-app-frontend-[a-z0-9-]+-data-yard\.vercel\.app$/;

// Allows only configured frontend origins to call the API from a browser.
export function corsHeaders(request: Request): HeadersInit {
  // Get the request origin.
  const origin = request.headers.get("origin") ?? "";

  const allowed =
    ALLOWED_ORIGINS.includes(origin) || VERCEL_PREVIEW_ORIGIN.test(origin);

  const headers: Record<string, string> = {
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    Vary: "Origin",
  };

  // Never send a different origin as a fallback; browsers reject it and it
  // obscures which origins are actually permitted.
  if (allowed) headers["Access-Control-Allow-Origin"] = origin;

  return headers;
}
