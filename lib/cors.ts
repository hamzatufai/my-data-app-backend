const ALLOWED_ORIGINS = [
  "https://hamzatufai-my-data-app-frontend.vercel.app",
  "http://localhost:3000",
];

// Allows only configured frontend origins to call the API from a browser.
export function corsHeaders(request: Request): HeadersInit {
  // Get the request origin.
  const origin = request.headers.get("origin") ?? "";

  // Allow only origins included in the allow list.
  const allowed = ALLOWED_ORIGINS.includes(origin)
    ? origin
    : ALLOWED_ORIGINS[0];

  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    Vary: "Origin",
  };
}
