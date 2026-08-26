import { Plan, Role } from '@prisma/client';
import { z } from 'zod';

import { audit, auditForOrg } from '@/lib/audit';
import { prisma } from '@/lib/db';
import { ForbiddenError, NotFoundError, ValidationError } from '@/lib/errors';
import { logger } from '@/lib/logger';
import { bucketKey, consume } from '@/lib/rate-limit';
import { assertCan, hasRoleAtLeast, type AuthContext } from '@/lib/rbac';
import { hashToken, issueToken, isExpired, verifyToken } from '@/lib/tokens';

/**
 * Organisation and membership service.
 *
 * Every function here takes `ctx` first and filters on `ctx.orgId` itself
 * (CLAUDE.md rules 3 and 4). The two exceptions are `create`, which has no org
 * to scope to yet, and `acceptInvite`, whose whole job is to add the caller to
 * an org they are not yet a member of — that one is scoped by the token
 * instead, which is single-use and hashed at rest.
 */

export interface RequestInfo {
  ip?: string | null;
  userAgent?: string | null;
}

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const nameSchema = z.string().trim().min(2, 'Enter an organisation name.').max(80);

const slugSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(3, 'Slugs are at least 3 characters.')
  .max(48)
  .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, 'Use lowercase letters, numbers and single hyphens.');

/** Reserved because they collide with real or planned top-level routes. */
const RESERVED_SLUGS = new Set([
  'admin',
  'api',
  'app',
  'auth',
  'dashboard',
  'docs',
  'help',
  'login',
  'logout',
  'new',
  'onboarding',
  'register',
  'settings',
  'static',
  'status',
  'support',
]);

/** Best-effort slug from a display name; uniqueness is settled separately. */
export function slugify(name: string): string {
  const base = name
    .normalize('NFKD')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
  return base.length >= 3 ? base : `org-${base}`.slice(0, 40);
}

async function uniqueSlug(preferred: string): Promise<string> {
  const base = preferred;
  for (let attempt = 0; attempt < 50; attempt++) {
    const candidate = attempt === 0 ? base : `${base}-${attempt + 1}`;
    if (RESERVED_SLUGS.has(candidate)) continue;

    const clash = await prisma.organization.findUnique({
      where: { slug: candidate },
      select: { id: true },
    });
    if (!clash) return candidate;
  }

  // 50 collisions on the same base means something is wrong with the input,
  // not with the loop; fall back to something that cannot collide.
  return `${base.slice(0, 30)}-${Date.now().toString(36)}`;
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

export const createOrgSchema = z.object({
  name: nameSchema,
  slug: slugSchema.optional(),
});

export interface CreateOrgResult {
  orgId: string;
  slug: string;
  role: Role;
}

/**
 * Create an organisation and make the caller its OWNER.
 *
 * This is the one function that cannot take an org-scoped context, because the
 * org does not exist yet. It takes the user id alone and is only reachable from
 * an authenticated session.
 */
export async function create(
  actor: { userId: string; email: string },
  input: z.infer<typeof createOrgSchema>,
  request: RequestInfo = {},
): Promise<CreateOrgResult> {
  const parsed = createOrgSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const { name } = parsed.data;
  const requested = parsed.data.slug ?? slugify(name);

  if (parsed.data.slug && RESERVED_SLUGS.has(parsed.data.slug)) {
    throw new ValidationError('That URL is reserved.', {
      details: { fieldErrors: { slug: ['That URL is reserved.'] } },
    });
  }

  if (parsed.data.slug) {
    const clash = await prisma.organization.findUnique({
      where: { slug: parsed.data.slug },
      select: { id: true },
    });
    if (clash) {
      throw new ValidationError('That URL is already taken.', {
        details: { fieldErrors: { slug: ['That URL is already taken.'] } },
      });
    }
  }

  const slug = parsed.data.slug ?? (await uniqueSlug(requested));

  const org = await prisma.$transaction(async (tx) => {
    const created = await tx.organization.create({
      data: { name, slug, plan: Plan.FREE },
    });

    await tx.membership.create({
      data: { userId: actor.userId, orgId: created.id, role: Role.OWNER },
    });

    return created;
  });

  await auditForOrg(
    { userId: actor.userId, email: actor.email },
    org.id,
    'org.created',
    { type: 'Organization', id: org.id },
    { name, slug },
    request,
  );

  return { orgId: org.id, slug: org.slug, role: Role.OWNER };
}

// ---------------------------------------------------------------------------
// Read and update
// ---------------------------------------------------------------------------

export interface OrgSummary {
  id: string;
  name: string;
  slug: string;
  plan: Plan;
  memberCount: number;
  createdAt: Date;
}

export async function getCurrent(ctx: AuthContext & { actorEmail: string }): Promise<OrgSummary> {
  assertCan(ctx, 'org:read', { orgId: ctx.orgId });

  const org = await prisma.organization.findFirst({
    where: { id: ctx.orgId, deletedAt: null },
    include: { _count: { select: { memberships: true } } },
  });

  if (!org) throw new NotFoundError('Organisation not found.');

  return {
    id: org.id,
    name: org.name,
    slug: org.slug,
    plan: org.plan,
    memberCount: org._count.memberships,
    createdAt: org.createdAt,
  };
}

export const updateOrgSchema = z.object({
  name: nameSchema.optional(),
  slug: slugSchema.optional(),
});

export async function update(
  ctx: AuthContext & { actorEmail: string },
  input: z.infer<typeof updateOrgSchema>,
  request: RequestInfo = {},
): Promise<OrgSummary> {
  assertCan(ctx, 'org:update', { orgId: ctx.orgId });

  const parsed = updateOrgSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const { name, slug } = parsed.data;
  if (name === undefined && slug === undefined) {
    throw new ValidationError('Nothing to update.');
  }

  if (slug !== undefined) {
    if (RESERVED_SLUGS.has(slug)) {
      throw new ValidationError('That URL is reserved.', {
        details: { fieldErrors: { slug: ['That URL is reserved.'] } },
      });
    }

    const clash = await prisma.organization.findUnique({
      where: { slug },
      select: { id: true },
    });
    if (clash && clash.id !== ctx.orgId) {
      throw new ValidationError('That URL is already taken.', {
        details: { fieldErrors: { slug: ['That URL is already taken.'] } },
      });
    }
  }

  const result = await prisma.organization.updateMany({
    where: { id: ctx.orgId, deletedAt: null },
    data: {
      ...(name !== undefined ? { name } : {}),
      ...(slug !== undefined ? { slug } : {}),
    },
  });

  if (result.count === 0) throw new NotFoundError('Organisation not found.');

  await audit(
    ctx,
    'org.updated',
    { type: 'Organization', id: ctx.orgId },
    { ...(name !== undefined ? { name } : {}), ...(slug !== undefined ? { slug } : {}) },
    request,
  );

  return getCurrent(ctx);
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

export interface MemberSummary {
  membershipId: string;
  userId: string;
  email: string;
  name: string;
  role: Role;
  joinedAt: Date;
  lastLoginAt: Date | null;
  /** True for the caller's own membership. */
  self: boolean;
}

export async function listMembers(
  ctx: AuthContext & { actorEmail: string },
): Promise<MemberSummary[]> {
  assertCan(ctx, 'member:read', { orgId: ctx.orgId });

  const rows = await prisma.membership.findMany({
    where: { orgId: ctx.orgId },
    orderBy: [{ role: 'desc' }, { createdAt: 'asc' }],
    include: {
      user: { select: { id: true, email: true, name: true, lastLoginAt: true } },
    },
  });

  return rows.map((row) => ({
    membershipId: row.id,
    userId: row.user.id,
    email: row.user.email,
    name: row.user.name,
    role: row.role,
    joinedAt: row.createdAt,
    lastLoginAt: row.user.lastLoginAt,
    self: row.user.id === ctx.userId,
  }));
}

export interface PendingInvite {
  id: string;
  email: string;
  role: Role;
  expiresAt: Date;
  createdAt: Date;
}

export async function listInvites(
  ctx: AuthContext & { actorEmail: string },
): Promise<PendingInvite[]> {
  assertCan(ctx, 'member:read', { orgId: ctx.orgId });

  const rows = await prisma.invitation.findMany({
    where: { orgId: ctx.orgId, acceptedAt: null, expiresAt: { gt: new Date() } },
    orderBy: { createdAt: 'desc' },
    select: { id: true, email: true, role: true, expiresAt: true, createdAt: true },
  });

  return rows;
}

export const inviteMemberSchema = z.object({
  email: z.string().trim().toLowerCase().email('Enter a valid email address.').max(254),
  role: z.nativeEnum(Role),
});

export interface InviteMemberResult {
  id: string;
  email: string;
  role: Role;
  expiresAt: Date;
  /**
   * The single-use accept token, returned to the inviter every time.
   *
   * There is no mail transport here, so the inviter is the only party who can
   * deliver the link. Returning it does not widen exposure: it goes to the
   * authenticated caller who just created the invitation and holds
   * `member:invite` — exactly the party a mail provider would have sent it on
   * behalf of. Withholding it in production never made the invitation safer,
   * it only made it impossible to accept.
   */
  inviteToken: string;
}

/**
 * Invite somebody by email.
 *
 * An inviter can never grant a role above their own — otherwise an ADMIN could
 * mint an OWNER and escalate through the back door.
 */
export async function inviteMember(
  ctx: AuthContext & { actorEmail: string },
  input: z.infer<typeof inviteMemberSchema>,
  request: RequestInfo = {},
): Promise<InviteMemberResult> {
  assertCan(ctx, 'member:invite', { orgId: ctx.orgId });

  const parsed = inviteMemberSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const { email, role } = parsed.data;

  if (!hasRoleAtLeast(ctx.role, role)) {
    throw new ForbiddenError('You cannot invite somebody at a higher role than your own.');
  }

  const bucket = bucketKey('inviteSend', { orgId: ctx.orgId });
  const limit = await consume('inviteSend', bucket);
  if (!limit.allowed) {
    throw new ValidationError('Too many invitations sent. Try again shortly.');
  }

  const existingMember = await prisma.membership.findFirst({
    where: { orgId: ctx.orgId, user: { email } },
    select: { id: true },
  });
  if (existingMember) {
    throw new ValidationError('That person is already a member of this organisation.', {
      details: { fieldErrors: { email: ['Already a member.'] } },
    });
  }

  // Supersede any outstanding invitation so only the newest link works.
  await prisma.invitation.deleteMany({
    where: { orgId: ctx.orgId, email, acceptedAt: null },
  });

  const token = issueToken(INVITE_TTL_MS);

  const invitation = await prisma.invitation.create({
    data: {
      orgId: ctx.orgId,
      email,
      role,
      tokenHash: token.tokenHash,
      expiresAt: token.expiresAt,
    },
    select: { id: true, email: true, role: true, expiresAt: true },
  });

  await audit(
    ctx,
    'member.invited',
    { type: 'Invitation', id: invitation.id },
    { email, role },
    request,
  );

  return { ...invitation, inviteToken: token.token };
}

export interface InvitePreview {
  orgName: string;
  email: string;
  role: Role;
  expiresAt: Date;
}

/**
 * Look at an invitation without consuming it, so the accept page can name the
 * organisation before the user commits. Returns null for anything that would
 * not be accepted anyway — the caller renders one "invalid or expired" state
 * either way, so this leaks nothing a submit would not.
 */
export async function previewInvite(token: string): Promise<InvitePreview | null> {
  if (typeof token !== 'string' || token.length < 20 || token.length > 200) return null;

  const invitation = await prisma.invitation.findUnique({
    where: { tokenHash: hashToken(token) },
    include: { org: { select: { name: true, deletedAt: true } } },
  });

  if (
    !invitation ||
    !verifyToken(token, invitation.tokenHash) ||
    invitation.acceptedAt !== null ||
    isExpired(invitation.expiresAt) ||
    invitation.org.deletedAt !== null
  ) {
    return null;
  }

  return {
    orgName: invitation.org.name,
    email: invitation.email,
    role: invitation.role,
    expiresAt: invitation.expiresAt,
  };
}

export interface AcceptInviteResult {
  orgId: string;
  orgName: string;
  slug: string;
  role: Role;
}

/**
 * Accept an invitation.
 *
 * The token is the authority here, but it is not the only check: the invitation
 * is bound to an email address, and it is only honoured for the account that
 * owns that address. Otherwise a forwarded link would let anyone join.
 */
export async function acceptInvite(
  actor: { userId: string; email: string },
  token: string,
  request: RequestInfo = {},
): Promise<AcceptInviteResult> {
  if (typeof token !== 'string' || token.length < 20 || token.length > 200) {
    throw new ValidationError('That invitation is invalid or has expired.');
  }

  const invitation = await prisma.invitation.findUnique({
    where: { tokenHash: hashToken(token) },
    include: { org: { select: { id: true, name: true, slug: true, deletedAt: true } } },
  });

  if (
    !invitation ||
    !verifyToken(token, invitation.tokenHash) ||
    invitation.acceptedAt !== null ||
    isExpired(invitation.expiresAt) ||
    invitation.org.deletedAt !== null
  ) {
    throw new ValidationError('That invitation is invalid or has expired.');
  }

  if (invitation.email !== actor.email.toLowerCase()) {
    throw new ForbiddenError('That invitation was sent to a different email address.');
  }

  const existing = await prisma.membership.findUnique({
    where: { userId_orgId: { userId: actor.userId, orgId: invitation.orgId } },
    select: { id: true, role: true },
  });

  if (existing) {
    // Already a member: burn the invitation and return the membership as-is
    // rather than silently changing a role somebody may have adjusted since.
    await prisma.invitation.update({
      where: { id: invitation.id },
      data: { acceptedAt: new Date() },
    });

    return {
      orgId: invitation.org.id,
      orgName: invitation.org.name,
      slug: invitation.org.slug,
      role: existing.role,
    };
  }

  await prisma.$transaction(async (tx) => {
    // Single use: only the update that flips a still-null acceptedAt wins.
    const claimed = await tx.invitation.updateMany({
      where: { id: invitation.id, acceptedAt: null },
      data: { acceptedAt: new Date() },
    });

    if (claimed.count === 0) {
      throw new ValidationError('That invitation is invalid or has expired.');
    }

    await tx.membership.create({
      data: { userId: actor.userId, orgId: invitation.orgId, role: invitation.role },
    });
  });

  await auditForOrg(
    { userId: actor.userId, email: actor.email },
    invitation.orgId,
    'member.invite_accepted',
    { type: 'Membership', id: invitation.id },
    { role: invitation.role },
    request,
  );

  return {
    orgId: invitation.org.id,
    orgName: invitation.org.name,
    slug: invitation.org.slug,
    role: invitation.role,
  };
}

export const changeMemberRoleSchema = z.object({
  userId: z.string().min(1).max(64),
  role: z.nativeEnum(Role),
});

/**
 * Change a member's role.
 *
 * Three rules, all of which exist to stop an org locking itself out or an admin
 * escalating: you cannot change your own role, you cannot set a role above your
 * own, and the last OWNER cannot be demoted.
 */
export async function changeMemberRole(
  ctx: AuthContext & { actorEmail: string },
  input: z.infer<typeof changeMemberRoleSchema>,
  request: RequestInfo = {},
): Promise<{ ok: boolean; role: Role }> {
  assertCan(ctx, 'member:update_role', { orgId: ctx.orgId });

  const parsed = changeMemberRoleSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const { userId, role } = parsed.data;

  if (userId === ctx.userId) {
    throw new ForbiddenError('You cannot change your own role.');
  }

  if (!hasRoleAtLeast(ctx.role, role)) {
    throw new ForbiddenError('You cannot grant a role higher than your own.');
  }

  const membership = await prisma.membership.findUnique({
    where: { userId_orgId: { userId, orgId: ctx.orgId } },
    select: { id: true, role: true },
  });

  if (!membership) throw new NotFoundError('That person is not a member of this organisation.');

  if (!hasRoleAtLeast(ctx.role, membership.role)) {
    throw new ForbiddenError('You cannot change the role of somebody above you.');
  }

  if (membership.role === Role.OWNER && role !== Role.OWNER) {
    await assertNotLastOwner(ctx.orgId);
  }

  await prisma.membership.update({
    where: { id: membership.id },
    data: { role },
  });

  await audit(
    ctx,
    'member.role_changed',
    { type: 'Membership', id: membership.id },
    { userId, from: membership.role, to: role },
    request,
  );

  return { ok: true, role };
}

/** Remove a member and kill their sessions immediately. */
export async function removeMember(
  ctx: AuthContext & { actorEmail: string },
  userId: string,
  request: RequestInfo = {},
): Promise<{ ok: boolean }> {
  assertCan(ctx, 'member:remove', { orgId: ctx.orgId });

  if (typeof userId !== 'string' || userId.length === 0 || userId.length > 64) {
    throw new ValidationError('Unknown member.');
  }

  if (userId === ctx.userId) {
    throw new ForbiddenError('You cannot remove yourself. Ask another owner to do it.');
  }

  const membership = await prisma.membership.findUnique({
    where: { userId_orgId: { userId, orgId: ctx.orgId } },
    select: { id: true, role: true },
  });

  if (!membership) throw new NotFoundError('That person is not a member of this organisation.');

  if (!hasRoleAtLeast(ctx.role, membership.role)) {
    throw new ForbiddenError('You cannot remove somebody above you.');
  }

  if (membership.role === Role.OWNER) {
    await assertNotLastOwner(ctx.orgId);
  }

  await prisma.membership.delete({ where: { id: membership.id } });

  // If this was their only org, their sessions no longer resolve to anything;
  // revoking is still the right move because a session outliving the removal is
  // exactly the gap an offboarding process is supposed to close.
  const remaining = await prisma.membership.count({ where: { userId } });
  if (remaining === 0) {
    await prisma.session.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  await audit(
    ctx,
    'member.removed',
    { type: 'Membership', id: membership.id },
    { userId, role: membership.role, sessionsRevoked: remaining === 0 },
    request,
  );

  return { ok: true };
}

async function assertNotLastOwner(orgId: string): Promise<void> {
  const owners = await prisma.membership.count({
    where: { orgId, role: Role.OWNER },
  });

  if (owners <= 1) {
    throw new ValidationError(
      'This is the last owner of the organisation. Promote somebody else first.',
    );
  }
}

// ---------------------------------------------------------------------------
// Switching orgs
// ---------------------------------------------------------------------------

export interface SwitchOrgResult {
  orgId: string;
  slug: string;
  role: Role;
}

/**
 * Switch the active org for a session.
 *
 * The membership lookup is the authorisation check: if the caller has no
 * membership row for the target org, there is nothing to switch to. The JWT is
 * updated by the caller via the session `update()` trigger, and `getAuthContext`
 * re-reads the membership on every request regardless, so a stale token cannot
 * grant access here.
 */
export async function switchOrg(
  actor: { userId: string; email: string },
  orgId: string,
  request: RequestInfo = {},
): Promise<SwitchOrgResult> {
  if (typeof orgId !== 'string' || orgId.length === 0 || orgId.length > 64) {
    throw new NotFoundError('Unknown organisation.');
  }

  const membership = await prisma.membership.findUnique({
    where: { userId_orgId: { userId: actor.userId, orgId } },
    include: { org: { select: { id: true, slug: true, deletedAt: true } } },
  });

  if (!membership || membership.org.deletedAt !== null) {
    logger.warn({ userId: actor.userId, orgId }, 'org switch denied');
    throw new NotFoundError('Unknown organisation.');
  }

  await auditForOrg(
    { userId: actor.userId, email: actor.email },
    orgId,
    'org.switched',
    { type: 'Organization', id: orgId },
    {},
    request,
  );

  return { orgId, slug: membership.org.slug, role: membership.role };
}

/** Every org the caller belongs to, for the org switcher. */
export async function listForUser(
  userId: string,
): Promise<Array<{ orgId: string; name: string; slug: string; role: Role }>> {
  const rows = await prisma.membership.findMany({
    where: { userId, org: { deletedAt: null } },
    orderBy: { createdAt: 'asc' },
    include: { org: { select: { id: true, name: true, slug: true } } },
  });

  return rows.map((row) => ({
    orgId: row.org.id,
    name: row.org.name,
    slug: row.org.slug,
    role: row.role,
  }));
}
