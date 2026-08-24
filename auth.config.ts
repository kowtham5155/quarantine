import type { NextAuthConfig } from 'next-auth';

/**
 * Edge-safe half of the Auth.js configuration.
 *
 * Nothing here may touch Prisma or argon2 — both are native/Node-only, and this
 * object has to be loadable from the edge runtime. The credentials provider and
 * every callback that reads the database live in auth.ts.
 *
 * Session lifetimes come from the security baseline: 30 minutes idle, 12 hours
 * absolute. The JWT `maxAge` enforces the idle bound (Auth.js re-issues the
 * cookie on activity); the absolute bound is enforced against the Session row,
 * which a re-issued JWT cannot extend.
 */

export const SESSION_IDLE_SECONDS = 30 * 60;
export const SESSION_ABSOLUTE_SECONDS = 12 * 60 * 60;

export const authConfig = {
  // Credentials sign-in requires JWT sessions; revocation is handled against
  // the Session table rather than by Auth.js.
  session: {
    strategy: 'jwt',
    maxAge: SESSION_IDLE_SECONDS,
    updateAge: 5 * 60,
  },
  pages: {
    signIn: '/login',
    error: '/login',
    newUser: '/onboarding',
  },
  trustHost: true,
  providers: [],
  callbacks: {
    /**
     * Used by the middleware wrapper. Route protection proper lives in
     * middleware.ts; this only reports whether a session exists.
     */
    authorized({ auth }) {
      return Boolean(auth?.user);
    },
  },
} satisfies NextAuthConfig;

export default authConfig;
