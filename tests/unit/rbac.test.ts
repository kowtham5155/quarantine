import { Role } from '@prisma/client';
import { describe, expect, it } from 'vitest';

import {
  assertCan,
  assertRoleAtLeast,
  can,
  hasRoleAtLeast,
  permissionsFor,
  type AuthContext,
} from '@/lib/rbac';

const ORG = 'org_acme';
const OTHER_ORG = 'org_northwind';

function ctx(role: Role, userId = 'user_1', orgId = ORG): AuthContext {
  return { userId, orgId, role };
}

describe('role hierarchy', () => {
  it('ranks viewer below analyst below admin below owner', () => {
    expect(hasRoleAtLeast(Role.OWNER, Role.ADMIN)).toBe(true);
    expect(hasRoleAtLeast(Role.ADMIN, Role.ANALYST)).toBe(true);
    expect(hasRoleAtLeast(Role.ANALYST, Role.VIEWER)).toBe(true);
    expect(hasRoleAtLeast(Role.VIEWER, Role.ANALYST)).toBe(false);
  });

  it('grants every lower role its permissions', () => {
    const viewer = new Set(permissionsFor(Role.VIEWER));
    for (const permission of viewer) {
      expect(can(ctx(Role.ANALYST), permission)).toBe(true);
      expect(can(ctx(Role.ADMIN), permission)).toBe(true);
      expect(can(ctx(Role.OWNER), permission)).toBe(true);
    }
  });
});

describe('tenant isolation', () => {
  it('denies a resource from another org, even to an owner', () => {
    expect(can(ctx(Role.OWNER), 'project:read', { orgId: OTHER_ORG })).toBe(false);
    expect(can(ctx(Role.OWNER), 'project:delete', { orgId: OTHER_ORG })).toBe(false);
  });

  it('allows the same permission inside the caller org', () => {
    expect(can(ctx(Role.OWNER), 'project:read', { orgId: ORG })).toBe(true);
  });

  it('throws ForbiddenError rather than returning false in assertCan', () => {
    expect(() => assertCan(ctx(Role.VIEWER), 'project:delete')).toThrowError(
      /do not have permission/i,
    );
    expect(() => assertCan(ctx(Role.OWNER), 'project:delete', { orgId: ORG })).not.toThrow();
  });
});

describe('resource rules', () => {
  it('never lets a requester approve their own exception', () => {
    const admin = ctx(Role.ADMIN, 'user_admin');
    expect(can(admin, 'exception:approve', { orgId: ORG, ownerId: 'user_other' })).toBe(true);
    expect(can(admin, 'exception:approve', { orgId: ORG, ownerId: 'user_admin' })).toBe(false);
  });

  it('applies the self-approval veto to owners too', () => {
    const owner = ctx(Role.OWNER, 'user_owner');
    expect(can(owner, 'exception:approve', { orgId: ORG, ownerId: 'user_owner' })).toBe(false);
  });
});

describe('role floors', () => {
  it('rejects a role below the minimum', () => {
    expect(() => assertRoleAtLeast(ctx(Role.ANALYST), Role.ADMIN)).toThrowError(
      /do not have permission/i,
    );
    expect(() => assertRoleAtLeast(ctx(Role.ADMIN), Role.ADMIN)).not.toThrow();
  });
});

describe('viewer restrictions', () => {
  it('cannot mutate policy, members or projects', () => {
    const viewer = ctx(Role.VIEWER);
    expect(can(viewer, 'member:invite')).toBe(false);
    expect(can(viewer, 'member:remove')).toBe(false);
    expect(can(viewer, 'project:create')).toBe(false);
    expect(can(viewer, 'org:update')).toBe(false);
  });

  it('can still read', () => {
    const viewer = ctx(Role.VIEWER);
    expect(can(viewer, 'org:read')).toBe(true);
    expect(can(viewer, 'member:read')).toBe(true);
    expect(can(viewer, 'project:read')).toBe(true);
  });
});
