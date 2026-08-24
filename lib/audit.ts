import { prisma } from '@/lib/db';
import { logger } from '@/lib/logger';
import type { AuthContext } from '@/lib/rbac';
import type { JsonObject } from '@/prisma/seed-data/json';

/**
 * Append-only audit log.
 *
 * Every privileged service method calls this. Nothing in the application ever
 * updates or deletes an AuditLog row — the table is written and read, and
 * retention is handled out of band.
 *
 * Auditing must never break the operation it is recording: a failure here is
 * logged loudly and swallowed, because losing an audit line is bad but failing
 * a security-relevant action that already succeeded is worse.
 */

export interface AuditActor {
  userId: string | null;
  email: string;
  /**
   * Null for events that happen before a session exists. Do not substitute a
   * placeholder org: a null here means "no organisation", which is the truth,
   * and an org-scoped audit query must not surface these rows.
   */
  orgId: string | null;
}

export interface AuditRequestInfo {
  ip?: string | null;
  userAgent?: string | null;
}

export interface AuditEntity {
  type: string;
  id?: string | null;
}

/** Actions are dot-namespaced: `<entity>.<verb>`, past tense. */
export type AuditAction =
  | 'auth.registered'
  | 'auth.login_succeeded'
  | 'auth.login_failed'
  | 'auth.login_locked'
  | 'auth.logged_out'
  | 'auth.email_verified'
  | 'auth.password_reset_requested'
  | 'auth.password_reset_completed'
  | 'auth.password_changed'
  | 'auth.totp_enabled'
  | 'auth.totp_disabled'
  | 'auth.recovery_code_used'
  | 'auth.totp_failed'
  | 'auth.session_revoked'
  | 'auth.sessions_revoked_all'
  | 'org.created'
  | 'org.updated'
  | 'org.switched'
  | 'member.invited'
  | 'member.invite_accepted'
  | 'member.role_changed'
  | 'member.removed'
  | 'policy.created'
  | 'policy.updated'
  | 'policy.deleted'
  | 'policy.enabled'
  | 'policy.disabled'
  | 'apikey.created'
  | 'apikey.revoked'
  | 'webhook.created'
  | 'webhook.updated'
  | 'webhook.deleted'
  | 'exception.requested'
  | 'exception.approved'
  | 'exception.denied'
  | 'quarantine.released'
  | 'quarantine.confirmed_bad'
  | 'project.created'
  | 'project.deleted'
  | 'scan.created'
  | 'report.generated';

/**
 * Write an audit line for a caller that already has a full AuthContext.
 * `actorEmail` is denormalised on purpose: the log has to stay readable after
 * the user row is deleted.
 */
export async function audit(
  ctx: AuthContext & { actorEmail: string },
  action: AuditAction,
  entity: AuditEntity,
  metadata: JsonObject = {},
  request: AuditRequestInfo = {},
): Promise<void> {
  await writeAudit(
    { userId: ctx.userId, email: ctx.actorEmail, orgId: ctx.orgId },
    action,
    entity,
    metadata,
    request,
  );
}

/**
 * Audit an authenticated action against a known organisation when the caller
 * does not hold a full AuthContext.
 *
 * This is not a loophole around `audit()`: it exists for the two real cases
 * where the org is verified but no role is in play yet — creating an
 * organisation (the membership is created in the same transaction) and
 * accepting an invitation or switching org (the membership has just been read
 * back from the database). The caller must have established that `orgId` is one
 * the actor genuinely belongs to.
 */
export async function auditForOrg(
  actor: { userId: string; email: string },
  orgId: string,
  action: AuditAction,
  entity: AuditEntity,
  metadata: JsonObject = {},
  request: AuditRequestInfo = {},
): Promise<void> {
  await writeAudit(
    { userId: actor.userId, email: actor.email, orgId },
    action,
    entity,
    metadata,
    request,
  );
}

/**
 * Audit an event that happens before a session exists — registration, a failed
 * login, an email verification, a password reset request.
 *
 * These rows carry `orgId: null`. The caller does not get to pass an org,
 * because at this point in the request there is no trustworthy one to pass:
 * the actor may belong to several organisations, or to none, and guessing
 * would put a stranger's failed login into somebody's compliance export.
 */
export async function auditAnonymous(
  actor: { userId: string | null; email: string },
  action: AuditAction,
  entity: AuditEntity,
  metadata: JsonObject = {},
  request: AuditRequestInfo = {},
): Promise<void> {
  await writeAudit(
    { userId: actor.userId, email: actor.email, orgId: null },
    action,
    entity,
    metadata,
    request,
  );
}

async function writeAudit(
  actor: AuditActor,
  action: AuditAction,
  entity: AuditEntity,
  metadata: JsonObject,
  request: AuditRequestInfo,
): Promise<void> {
  try {
    await prisma.auditLog.create({
      data: {
        orgId: actor.orgId,
        actorId: actor.userId,
        actorEmail: actor.email,
        action,
        entityType: entity.type,
        entityId: entity.id ?? null,
        metadata,
        ip: request.ip ?? null,
        userAgent: request.userAgent ?? null,
      },
    });
  } catch (error) {
    logger.error(
      { err: error, action, entityType: entity.type, orgId: actor.orgId },
      'failed to write audit log entry',
    );
  }
}
