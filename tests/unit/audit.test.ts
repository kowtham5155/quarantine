import { beforeEach, describe, expect, it, vi } from 'vitest';

const create = vi.fn();

vi.mock('@/lib/db', () => ({
  prisma: { auditLog: { create } },
}));

const { audit, auditAnonymous, auditForOrg } = await import('@/lib/audit');

type AuditRow = {
  orgId: string | null;
  actorId: string | null;
  actorEmail: string;
  action: string;
  entityType: string;
  entityId: string | null;
};

function lastRow(): AuditRow {
  const call = create.mock.calls.at(-1);
  return (call?.[0] as { data: AuditRow }).data;
}

beforeEach(() => {
  create.mockReset();
  create.mockResolvedValue({});
});

describe('auditAnonymous', () => {
  it('writes orgId: null rather than guessing an organisation', async () => {
    await auditAnonymous(
      { userId: 'user_1', email: 'dev@example.com' },
      'auth.login_failed',
      { type: 'User', id: 'user_1' },
      { reason: 'bad_password' },
    );

    expect(lastRow().orgId).toBeNull();
    expect(lastRow().actorEmail).toBe('dev@example.com');
  });

  it('still writes a row when the actor is unknown', async () => {
    await auditAnonymous({ userId: null, email: 'stranger@example.com' }, 'auth.login_failed', {
      type: 'User',
      id: null,
    });

    expect(create).toHaveBeenCalledOnce();
    expect(lastRow().orgId).toBeNull();
    expect(lastRow().actorId).toBeNull();
  });
});

describe('audit', () => {
  it('carries the org from the caller context', async () => {
    await audit(
      { userId: 'user_1', orgId: 'org_acme', role: 'OWNER', actorEmail: 'dev@example.com' },
      'project.created',
      { type: 'Project', id: 'proj_1' },
    );

    expect(lastRow().orgId).toBe('org_acme');
  });
});

describe('auditForOrg', () => {
  it('records a verified org for an actor with no role in hand', async () => {
    await auditForOrg({ userId: 'user_1', email: 'dev@example.com' }, 'org_new', 'org.created', {
      type: 'Organization',
      id: 'org_new',
    });

    expect(lastRow().orgId).toBe('org_new');
  });
});

describe('audit failures never break the caller', () => {
  it('swallows a write error', async () => {
    create.mockRejectedValueOnce(new Error('connection reset'));

    await expect(
      auditAnonymous({ userId: null, email: 'dev@example.com' }, 'auth.login_failed', {
        type: 'User',
      }),
    ).resolves.toBeUndefined();
  });
});
