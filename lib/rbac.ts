import { Role } from '@prisma/client';

import { ForbiddenError } from '@/lib/errors';

/**
 * Role-based access control.
 *
 * Two independent checks happen on every call, and both must pass:
 *   1. Does this role hold the permission?
 *   2. Does the resource belong to the caller's org?
 *
 * The second is not redundant with the `where: { orgId }` filters in the
 * service layer — it is the backstop for the day someone forgets one
 * (CLAUDE.md rules 3 and 4).
 */

export const PERMISSIONS = [
  // Organisation
  'org:read',
  'org:update',
  'org:delete',
  'org:billing',

  // Membership
  'member:read',
  'member:invite',
  'member:update_role',
  'member:remove',

  // Integrations
  'apikey:read',
  'apikey:create',
  'apikey:revoke',
  'webhook:read',
  'webhook:create',
  'webhook:update',
  'webhook:delete',

  // Projects and scanning
  'project:read',
  'project:create',
  'project:update',
  'project:delete',
  'scan:read',
  'scan:create',
  'analysis:read',
  'analysis:create',

  // Policy and governance
  'policy:read',
  'policy:create',
  'policy:update',
  'policy:delete',
  'violation:read',
  'violation:triage',
  'exception:read',
  'exception:request',
  'exception:approve',
  'quarantine:read',
  'quarantine:review',

  // Intelligence
  'campaign:read',
  'rule:read',
  'rule:update',
  'corpus:read',
  'corpus:manage',
  'eval:run',

  // Reporting and audit
  'alert:read',
  'alert:resolve',
  'report:read',
  'report:generate',
  'audit:read',
] as const;

export type Permission = (typeof PERMISSIONS)[number];

/** Everything a viewer can do: read, and nothing else. */
const VIEWER_PERMISSIONS: readonly Permission[] = [
  'org:read',
  'member:read',
  'apikey:read',
  'webhook:read',
  'project:read',
  'scan:read',
  'analysis:read',
  'policy:read',
  'violation:read',
  'exception:read',
  'quarantine:read',
  'campaign:read',
  'rule:read',
  'corpus:read',
  'alert:read',
  'report:read',
];

/**
 * Analysts do the security work: run scans, triage what comes back, hold and
 * release packages. They cannot change who is in the org, cannot rewrite policy
 * (that is the control they are being measured against), and cannot approve
 * their own exception requests.
 */
const ANALYST_PERMISSIONS: readonly Permission[] = [
  ...VIEWER_PERMISSIONS,
  'project:create',
  'project:update',
  'scan:create',
  'analysis:create',
  'violation:triage',
  'exception:request',
  'quarantine:review',
  'eval:run',
  'alert:resolve',
  'report:generate',
];

/** Admins additionally run the org: members, policy, integrations, audit. */
const ADMIN_PERMISSIONS: readonly Permission[] = [
  ...ANALYST_PERMISSIONS,
  'org:update',
  'member:invite',
  'member:update_role',
  'member:remove',
  'apikey:create',
  'apikey:revoke',
  'webhook:create',
  'webhook:update',
  'webhook:delete',
  'project:delete',
  'policy:create',
  'policy:update',
  'policy:delete',
  'exception:approve',
  'rule:update',
  'corpus:manage',
  'audit:read',
];

/** Owners hold everything, including deleting the org and billing. */
const OWNER_PERMISSIONS: readonly Permission[] = [...PERMISSIONS];

export const ROLE_PERMISSIONS: Record<Role, ReadonlySet<Permission>> = {
  [Role.OWNER]: new Set(OWNER_PERMISSIONS),
  [Role.ADMIN]: new Set(ADMIN_PERMISSIONS),
  [Role.ANALYST]: new Set(ANALYST_PERMISSIONS),
  [Role.VIEWER]: new Set(VIEWER_PERMISSIONS),
};

/** Ordering for "at least this role" checks. Higher is more privileged. */
const ROLE_RANK: Record<Role, number> = {
  [Role.VIEWER]: 0,
  [Role.ANALYST]: 1,
  [Role.ADMIN]: 2,
  [Role.OWNER]: 3,
};

/** The context threaded through every service call (CLAUDE.md rule 3). */
export interface AuthContext {
  userId: string;
  orgId: string;
  role: Role;
}

/**
 * The subject of an authorisation check. `orgId` is compared against the
 * caller's org; `ownerId` supports the handful of rules where acting on your
 * own record differs from acting on someone else's.
 */
export interface ResourceRef {
  orgId?: string | null;
  ownerId?: string | null;
}

export function hasPermission(role: Role, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role].has(permission);
}

export function hasRoleAtLeast(role: Role, minimum: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[minimum];
}

/**
 * Rules that depend on more than the role. Returning false here vetoes a
 * permission the matrix would otherwise grant.
 */
function passesResourceRules(
  ctx: AuthContext,
  permission: Permission,
  resource: ResourceRef,
): boolean {
  // Nobody approves their own exception request, whatever their role. This is
  // the whole point of having an approval step.
  if (permission === 'exception:approve' && resource.ownerId === ctx.userId) {
    return false;
  }

  return true;
}

/**
 * The single authorisation entry point.
 *
 * A resource from another org is always denied, even for an owner — an owner is
 * an owner *of their own org*, and cross-tenant access is never legitimate.
 */
export function can(ctx: AuthContext, permission: Permission, resource?: ResourceRef): boolean {
  if (!hasPermission(ctx.role, permission)) return false;

  if (resource) {
    if (resource.orgId != null && resource.orgId !== ctx.orgId) return false;
    if (!passesResourceRules(ctx, permission, resource)) return false;
  }

  return true;
}

/** `can`, but throws the error the route handlers already know how to render. */
export function assertCan(ctx: AuthContext, permission: Permission, resource?: ResourceRef): void {
  if (!can(ctx, permission, resource)) {
    throw new ForbiddenError('You do not have permission to perform this action.', {
      details: { permission },
    });
  }
}

/** Guard for whole surfaces that are gated by role rather than a single action. */
export function assertRoleAtLeast(ctx: AuthContext, minimum: Role): void {
  if (!hasRoleAtLeast(ctx.role, minimum)) {
    throw new ForbiddenError('You do not have permission to perform this action.', {
      details: { requiredRole: minimum },
    });
  }
}

/** Every permission a role holds. Used to drive the settings UI. */
export function permissionsFor(role: Role): Permission[] {
  return [...ROLE_PERMISSIONS[role]];
}

export { Role };
