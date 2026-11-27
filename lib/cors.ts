const ALLOWED_ORIGINS = [
  "https://hamzatufai-my-data-app-frontend.vercel.app",
  "http://localhost:3000",
];

// Extra production/preview origins can be added without a code change by
// setting ALLOWED_ORIGINS_EXTRA as a comma-separated list, e.g:
//   https://cleancsv.vercel.app,https://www.example.com
const EXTRA_ORIGINS = (process.env.ALLOWED_ORIGINS_EXTRA ?? "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

// Vercel gives each preview deployment its own hostname. Keep this pattern
// scoped to this project and team; never allow every *.vercel.app origin.
const VERCEL_PREVIEW_ORIGIN =
  /^https:\/\/hamzatufai-my-data-app-frontend-[a-z0-9-]+-data-yard\.vercel\.app$/;

// Allows only configured frontend origins to call the API from a browser.
export function corsHeaders(request: Request): HeadersInit {
  // Get the request origin.
  const origin = request.headers.get("origin") ?? "";

  const allowed =
    ALLOWED_ORIGINS.includes(origin) ||
    EXTRA_ORIGINS.includes(origin) ||
    VERCEL_PREVIEW_ORIGIN.test(origin);

  const headers: Record<string, string> = {
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    // Serverless responses can be cached at the edge and served without the
    // caller's Origin header, which breaks CORS for later requests. This
    // prevents cross-origin flakiness between users.
    "Cache-Control": "no-store",
    Vary: "Origin",
  };

  // Never send a different origin as a fallback; browsers reject it and it
  // obscures which origins are actually permitted.
  if (allowed) headers["Access-Control-Allow-Origin"] = origin;

  return headers;
}

/**
 * Correct answer to a CORS preflight (OPTIONS) for JSON-method routes.
 * Every route with POST/PUT/PATCH/DELETE must respond to OPTIONS with 204 and
 * echo the requested headers — otherwise the browser blocks the real request
 * with the opaque "Failed to fetch".
 */
export function preflight(request: Request): Response {
  const requestHeaders = request.headers.get("access-control-request-headers");
  const base = corsHeaders(request) as Record<string, string>;
  if (requestHeaders) base["Access-Control-Allow-Headers"] = requestHeaders;
  return new Response(null, { status: 204, headers: base });
}
