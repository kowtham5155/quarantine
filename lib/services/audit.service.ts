import { type Prisma } from '@prisma/client';
import { z } from 'zod';

import { prisma } from '@/lib/db';
import { ValidationError } from '@/lib/errors';
import { assertCan, type AuthContext } from '@/lib/rbac';

/**
 * Reading the append-only audit log.
 *
 * Writes live in lib/audit.ts; this is the read side, and it is deliberately
 * read-only — there is no update or delete anywhere in the application for an
 * AuditLog row.
 *
 * Rows with `orgId: null` (a failed login, a password reset request) belong to
 * no organisation and are never returned here: attributing a pre-session event
 * to whichever org the reader happens to be in would be a guess, and showing
 * one org another org's failed logins would be a disclosure.
 */

export const auditQuerySchema = z.object({
  action: z.string().trim().max(60).optional(),
  actorEmail: z.string().trim().max(320).optional(),
  entityType: z.string().trim().max(60).optional(),
  days: z.number().int().min(1).max(365).default(30),
  take: z.number().int().min(1).max(500).default(200),
});

export interface AuditRow {
  id: string;
  action: string;
  actorEmail: string;
  actorName: string | null;
  entityType: string;
  entityId: string | null;
  metadata: Record<string, unknown>;
  ip: string | null;
  userAgent: string | null;
  createdAt: Date;
}

export interface AuditPage {
  items: AuditRow[];
  total: number;
  /** Distinct actions present in the window, for the filter. */
  actions: string[];
  days: number;
}

function toMetadata(value: Prisma.JsonValue): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

export async function listAuditLog(
  ctx: AuthContext,
  input: z.input<typeof auditQuerySchema> = {},
): Promise<AuditPage> {
  assertCan(ctx, 'audit:read', { orgId: ctx.orgId });

  const parsed = auditQuerySchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);
  const { action, actorEmail, entityType, days, take } = parsed.data;

  const since = new Date(Date.now() - days * 86_400_000);

  const where: Prisma.AuditLogWhereInput = {
    orgId: ctx.orgId,
    createdAt: { gte: since },
    ...(action ? { action } : {}),
    ...(entityType ? { entityType } : {}),
    ...(actorEmail ? { actorEmail: { contains: actorEmail, mode: 'insensitive' } } : {}),
  };

  const [rows, total, distinct] = await Promise.all([
    prisma.auditLog.findMany({
      where,
      include: { actor: { select: { name: true } } },
      orderBy: { createdAt: 'desc' },
      take,
    }),
    prisma.auditLog.count({ where }),
    prisma.auditLog.findMany({
      where: { orgId: ctx.orgId, createdAt: { gte: since } },
      distinct: ['action'],
      select: { action: true },
      orderBy: { action: 'asc' },
      take: 100,
    }),
  ]);

  return {
    items: rows.map((row) => ({
      id: row.id,
      action: row.action,
      actorEmail: row.actorEmail,
      actorName: row.actor?.name ?? null,
      entityType: row.entityType,
      entityId: row.entityId,
      metadata: toMetadata(row.metadata),
      ip: row.ip,
      userAgent: row.userAgent,
      createdAt: row.createdAt,
    })),
    total,
    actions: distinct.map((row) => row.action),
    days,
  };
}
