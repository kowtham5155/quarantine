import type { Role } from '@prisma/client';

/**
 * Shape of the data carried in the JWT and exposed on the session.
 *
 * `orgId` and `role` are cached here so a page render does not need a database
 * round trip to decide what to show. They are never trusted for an
 * authorisation decision: `requireAuthContext()` re-reads the membership on
 * every request (CLAUDE.md rule 3).
 */
export interface SessionClaims {
  userId: string;
  /** Opaque session token; its SHA-256 is stored on the Session row. */
  sid: string;
  email: string;
  name: string;
  orgId: string | null;
  role: Role | null;
  /** Epoch seconds when this session must end regardless of activity. */
  absoluteExpiry: number;
}

declare module 'next-auth' {
  interface Session {
    user: {
      id: string;
      email: string;
      name: string;
      emailVerified: Date | null;
      orgId: string | null;
      role: Role | null;
    };
    sid: string;
    absoluteExpiry: number;
  }

  interface User {
    id?: string;
    email?: string | null;
    name?: string | null;
    sid?: string;
    orgId?: string | null;
    role?: Role | null;
    absoluteExpiry?: number;
  }
}

// `next-auth/jwt` is a bare re-export, so the augmentation has to target the
// module that actually declares the interface.
declare module '@auth/core/jwt' {
  interface JWT {
    userId?: string;
    sid?: string;
    orgId?: string | null;
    role?: Role | null;
    absoluteExpiry?: number;
  }
}
