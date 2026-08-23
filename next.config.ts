import type { NextConfig } from 'next';

/**
 * Quarantine — Next.js configuration.
 *
 * `serverExternalPackages` keeps native / filesystem-bound modules out of the
 * server bundle. Prisma ships query engine binaries, @node-rs/argon2 is a
 * native addon, and `tar` is used by the sandboxed extractor — none of them
 * survive bundling. `pino` is listed for the same reason: its transport layer
 * resolves worker files at runtime.
 */
const nextConfig: NextConfig = {
  output: 'standalone',
  poweredByHeader: false,
  reactStrictMode: true,
  serverExternalPackages: ['@prisma/client', 'prisma', '@node-rs/argon2', 'tar', 'pino'],
  eslint: {
    // Linting runs as its own gate (`npm run lint`); don't duplicate it in the build.
    ignoreDuringBuilds: true,
  },
  typescript: {
    // Type checking runs as its own gate (`npm run typecheck`).
    ignoreBuildErrors: false,
  },
};

export default nextConfig;
