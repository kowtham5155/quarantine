import { type Prisma, Verdict } from '@prisma/client';
import { z } from 'zod';

import { audit } from '@/lib/audit';
import { prisma } from '@/lib/db';
import { NotFoundError, ValidationError } from '@/lib/errors';
import type { AuthContext } from '@/lib/rbac';

/**
 * Per-user notification preferences.
 *
 * Stored as JSON on the User row and validated on the way in *and* on the way
 * out: a preferences blob is the kind of column that accumulates shapes across
 * versions, and a settings page that throws because an old key is missing is a
 * page nobody can fix from the UI. Anything unparseable falls back to the
 * defaults rather than failing.
 *
 * Nothing here is security-relevant — no preference can widen what a user may
 * do — which is why it is a JSON column rather than a table.
 */

export const NOTIFY_EVENTS = [
  'maliciousVerdict',
  'policyViolation',
  'quarantineHeld',
  'campaignMatch',
  'exceptionExpiring',
  'scanComplete',
] as const;

export type NotifyEvent = (typeof NOTIFY_EVENTS)[number];

export const NOTIFY_EVENT_LABELS: Record<NotifyEvent, string> = {
  maliciousVerdict: 'A verdict of likely or known malicious',
  policyViolation: 'A policy is violated',
  quarantineHeld: 'A package version is held in quarantine',
  campaignMatch: 'A package joins a known campaign',
  exceptionExpiring: 'An exception is about to expire',
  scanComplete: 'A scan I started finishes',
};

export const preferencesSchema = z.object({
  events: z.object({
    maliciousVerdict: z.boolean().default(true),
    policyViolation: z.boolean().default(true),
    quarantineHeld: z.boolean().default(true),
    campaignMatch: z.boolean().default(true),
    exceptionExpiring: z.boolean().default(true),
    scanComplete: z.boolean().default(false),
  }),
  /** Quietest verdict worth a notification. */
  minVerdict: z.nativeEnum(Verdict).default(Verdict.SUSPICIOUS),
  /** In-app notifications are always on; this is the email channel. */
  emailEnabled: z.boolean().default(true),
  digest: z.enum(['off', 'daily', 'weekly']).default('weekly'),
});

export type Preferences = z.infer<typeof preferencesSchema>;

export const DEFAULT_PREFERENCES: Preferences = preferencesSchema.parse({ events: {} });

/** Read prefs, repairing anything that no longer matches the shape. */
export async function getPreferences(ctx: AuthContext): Promise<Preferences> {
  const user = await prisma.user.findUnique({
    where: { id: ctx.userId },
    select: { settings: true },
  });
  if (!user) throw new NotFoundError('Not found.');

  const raw =
    user.settings && typeof user.settings === 'object' && !Array.isArray(user.settings)
      ? (user.settings as Record<string, unknown>).notifications
      : undefined;

  const parsed = preferencesSchema.safeParse(raw);
  return parsed.success ? parsed.data : DEFAULT_PREFERENCES;
}

export async function updatePreferences(
  ctx: AuthContext & { actorEmail: string },
  input: z.input<typeof preferencesSchema>,
  request: { ip?: string | null; userAgent?: string | null } = {},
): Promise<Preferences> {
  const parsed = preferencesSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const user = await prisma.user.findUnique({
    where: { id: ctx.userId },
    select: { settings: true },
  });
  if (!user) throw new NotFoundError('Not found.');

  const existing =
    user.settings && typeof user.settings === 'object' && !Array.isArray(user.settings)
      ? (user.settings as Record<string, unknown>)
      : {};

  await prisma.user.update({
    where: { id: ctx.userId },
    data: {
      settings: {
        ...existing,
        notifications: parsed.data,
      } as unknown as Prisma.InputJsonValue,
    },
  });

  await audit(ctx, 'user.preferences_updated', { type: 'User', id: ctx.userId }, {}, request);

  return parsed.data;
}
