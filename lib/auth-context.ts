import { cache } from 'react';
import { headers } from 'next/headers';
import type { Role } from '@prisma/client';

import { auth } from '@/auth';
import { SESSION_ABSOLUTE_SECONDS, SESSION_IDLE_SECONDS } from '@/auth.config';
import { prisma } from '@/lib/db';
import { AuthError, ForbiddenError } from '@/lib/errors';
import type { AuthContext } from '@/lib/rbac';
import { hashToken } from '@/lib/tokens';

/**
 * Resolving the caller's identity, org and role.
 *
 * The JWT already carries orgId and role, but they are treated as a cache, not
 * as authority. Every call re-reads the Session row (so a revoked session dies
 * immediately rather than at token expiry) and the Membership row (so a removed
 * user or a downgraded role takes effect on the next request). CLAUDE.md rule 3
 * is explicit that a service enforces tenancy itself and never trusts the
 * caller to have filtered.
 *
 * `cache()` deduplicates this within a single render pass — a page with a
 * layout and six server components resolves it once.
 */

export interface FullAuthContext extends AuthContext {
  email: string;
  name: string;
  sessionId: string;
}

/**
 * Who the caller is, independent of any organisation.
 *
 * A user who has just registered has a valid session but no membership yet, so
 * `getAuthContext` correctly refuses to produce an org-scoped context for them.
 * Onboarding and the org switcher still need to know who they are — that is
 * what this is for. It is never a substitute for `getAuthContext` in anything
 * that touches tenant data.
 */
export interface SessionIdentity {
  userId: string;
  email: string;
  name: string;
  sessionId: string;
  /** Active org from the token, if the token carries one. */
  activeOrgId: string | null;
}

/** Sliding idle window, capped by the session's absolute expiry. */
async function touchSession(sessionId: string, absoluteExpiry: Date): Promise<void> {
  const idleExpiry = new Date(Date.now() + SESSION_IDLE_SECONDS * 1000);
  const next = idleExpiry < absoluteExpiry ? idleExpiry : absoluteExpiry;

  await prisma.session.update({
    where: { id: sessionId },
    data: { expiresAt: next },
  });
}

/**
 * The caller's context, or null when unauthenticated. Prefer
 * `requireAuthContext()` in anything that is not explicitly public.
 */
export const getSessionIdentity = cache(async (): Promise<SessionIdentity | null> => {
  const session = await auth();
  if (!session?.user?.id || !session.sid) return null;

  const row = await prisma.session.findUnique({
    where: { tokenHash: hashToken(session.sid) },
    include: {
      user: {
        select: { id: true, email: true, name: true, lockedUntil: true },
      },
    },
  });

  if (!row) return null;
  if (row.revokedAt) return null;
  if (row.expiresAt.getTime() <= Date.now()) return null;
  if (row.user.lockedUntil && row.user.lockedUntil.getTime() > Date.now()) return null;

  // Absolute cap: 12 hours from creation, whatever the activity.
  const absoluteExpiry = new Date(row.createdAt.getTime() + SESSION_ABSOLUTE_SECONDS * 1000);
  if (absoluteExpiry.getTime() <= Date.now()) return null;

  await touchSession(row.id, absoluteExpiry);

  return {
    userId: row.user.id,
    email: row.user.email,
    name: row.user.name,
    sessionId: row.id,
    activeOrgId: session.user.orgId ?? null,
  };
});

export const getAuthContext = cache(async (): Promise<FullAuthContext | null> => {
  const identity = await getSessionIdentity();
  if (!identity) return null;

  // A token issued before the user had any membership carries no orgId — the
  // account was created, then an org was made during onboarding. Fall back to
  // the same default-org resolution the credentials provider does at sign-in.
  // This reads the membership from the database either way, so it is not the
  // client choosing an org; it is the server picking one when asked for none.
  const membership = identity.activeOrgId
    ? await prisma.membership.findUnique({
        where: { userId_orgId: { userId: identity.userId, orgId: identity.activeOrgId } },
        include: { org: { select: { deletedAt: true } } },
      })
    : await prisma.membership.findFirst({
        where: { userId: identity.userId, org: { deletedAt: null } },
        orderBy: [{ role: 'asc' }, { createdAt: 'asc' }],
        include: { org: { select: { deletedAt: true } } },
      });

  // Removed from the org, or the org was soft-deleted, since the token was issued.
  if (!membership || membership.org.deletedAt) return null;

  return {
    userId: identity.userId,
    orgId: membership.orgId,
    role: membership.role,
    email: identity.email,
    name: identity.name,
    sessionId: identity.sessionId,
  };
});

/** Identity, or an AuthError. Does not require an organisation. */
export async function requireSessionIdentity(): Promise<SessionIdentity> {
  const identity = await getSessionIdentity();
  if (!identity) {
    throw new AuthError('Authentication is required.');
  }
  return identity;
}

/** The caller's context, or an AuthError. */
export async function requireAuthContext(): Promise<FullAuthContext> {
  const ctx = await getAuthContext();
  if (!ctx) {
    throw new AuthError('Authentication is required.');
  }
  return ctx;
}

/** Context plus a minimum role. */
export async function requireRole(minimum: Role): Promise<FullAuthContext> {
  const ctx = await requireAuthContext();
  const rank: Record<Role, number> = { VIEWER: 0, ANALYST: 1, ADMIN: 2, OWNER: 3 };
  if (rank[ctx.role] < rank[minimum]) {
    throw new ForbiddenError('You do not have permission to perform this action.', {
      details: { requiredRole: minimum },
    });
  }
  return ctx;
}

/** Client IP and user agent, for rate limiting and audit lines. */
export async function requestFingerprint(): Promise<{
  ip: string | null;
  userAgent: string | null;
}> {
  const headerList = await headers();
  const forwarded = headerList.get('x-forwarded-for');
  const ip = forwarded ? (forwarded.split(',')[0]?.trim() ?? null) : headerList.get('x-real-ip');

  return { ip: ip || null, userAgent: headerList.get('user-agent') };
}

/** Every org the caller belongs to, for the org switcher. */
export async function listMemberships(
  userId: string,
): Promise<Array<{ orgId: string; orgName: string; orgSlug: string; role: Role }>> {
  const memberships = await prisma.membership.findMany({
    where: { userId, org: { deletedAt: null } },
    include: { org: { select: { id: true, name: true, slug: true } } },
    orderBy: [{ role: 'asc' }, { createdAt: 'asc' }],
  });

  return memberships.map((membership) => ({
    orgId: membership.org.id,
    orgName: membership.org.name,
    orgSlug: membership.org.slug,
    role: membership.role,
  }));
}
