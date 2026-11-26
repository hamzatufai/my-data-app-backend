// Allows only the configured frontend origin to call the API from a browser.
export function corsHeaders(): HeadersInit {
  return {
    "Access-Control-Allow-Origin": process.env.FRONTEND_ORIGIN ?? "http://localhost:3000",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    Vary: "Origin",
  };
}
