/** @type {import('next').NextConfig} */
const nextConfig = {
  poweredByHeader: false,
  // Keep Turbopack scoped to this independently deployed application.
  turbopack: { root: process.cwd() },
};
export default nextConfig;
