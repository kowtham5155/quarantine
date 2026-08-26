import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

import { type Prisma } from '@prisma/client';
import { z } from 'zod';

import { audit } from '@/lib/audit';
import { prisma } from '@/lib/db';
import { ExternalServiceError, NotFoundError, ValidationError } from '@/lib/errors';
import { logger } from '@/lib/logger';
import { safeFetch } from '@/lib/net/fetcher';
import { assertCan, type AuthContext } from '@/lib/rbac';

/**
 * Integrations: API keys for the CLI and the public API, and webhooks for
 * pushing verdicts into someone else's system.
 *
 * Secrets are handled the way the security baseline requires:
 *   * An API key is shown in plaintext exactly once, at creation. Only its
 *     SHA-256 is stored, so a database read yields nothing usable, and lookup
 *     is by digest with a timing-safe comparison.
 *   * A webhook signing secret is generated here and displayed once. Deliveries
 *     are signed HMAC-SHA256 over the exact bytes sent, with a timestamp in the
 *     signed material so a captured delivery cannot be replayed later.
 *   * Test deliveries go through lib/net/fetcher.ts, which means the SSRF guard
 *     applies: an org cannot point a webhook at 169.254.169.254 and have this
 *     server read its own cloud metadata for them.
 */

export interface RequestInfo {
  ip?: string | null;
  userAgent?: string | null;
}

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

export const API_KEY_SCOPES = ['scan:write', 'analysis:read', 'policy:read', 'sbom:read'] as const;
export type ApiKeyScope = (typeof API_KEY_SCOPES)[number];

export const API_KEY_SCOPE_LABELS: Record<ApiKeyScope, string> = {
  'scan:write': 'Queue and run scans',
  'analysis:read': 'Read analyses and verdicts',
  'policy:read': 'Read policy decisions',
  'sbom:read': 'Export SBOMs',
};

const KEY_BYTES = 32;
const KEY_PREFIX = 'qrn_live';

export interface ApiKeyRow {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  lastUsedAt: Date | null;
  expiresAt: Date | null;
  revokedAt: Date | null;
  createdAt: Date;
  createdByName: string | null;
  /** Derived, so the UI never has to reimplement the expiry rule. */
  active: boolean;
}

function isActive(row: { revokedAt: Date | null; expiresAt: Date | null }): boolean {
  if (row.revokedAt) return false;
  return !row.expiresAt || row.expiresAt.getTime() > Date.now();
}

export async function listApiKeys(ctx: AuthContext): Promise<ApiKeyRow[]> {
  assertCan(ctx, 'apikey:read', { orgId: ctx.orgId });

  const rows = await prisma.apiKey.findMany({
    where: { orgId: ctx.orgId },
    include: { createdBy: { select: { name: true } } },
    orderBy: { createdAt: 'desc' },
  });

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    prefix: row.prefix,
    scopes: row.scopes,
    lastUsedAt: row.lastUsedAt,
    expiresAt: row.expiresAt,
    revokedAt: row.revokedAt,
    createdAt: row.createdAt,
    createdByName: row.createdBy?.name ?? null,
    active: isActive(row),
  }));
}

export const createApiKeySchema = z.object({
  name: z.string().trim().min(2, 'Name the key so you can recognise it later.').max(80),
  scopes: z
    .array(z.enum(API_KEY_SCOPES))
    .min(1, 'Choose at least one scope.')
    .max(API_KEY_SCOPES.length),
  expiresInDays: z.number().int().min(1).max(365).nullable().default(90),
});

export interface CreatedApiKey {
  id: string;
  prefix: string;
  /** Plaintext. Shown once, never stored, never logged. */
  token: string;
}

export async function createApiKey(
  ctx: AuthContext & { actorEmail: string },
  input: z.input<typeof createApiKeySchema>,
  request: RequestInfo = {},
): Promise<CreatedApiKey> {
  assertCan(ctx, 'apikey:create', { orgId: ctx.orgId });

  const parsed = createApiKeySchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const secret = randomBytes(KEY_BYTES).toString('base64url');
  // The prefix is a non-secret handle: enough to identify the key in a list and
  // in a log line, not enough to be any part of authenticating with it.
  const prefix = `${KEY_PREFIX}_${secret.slice(0, 6)}`;
  const token = `${prefix}.${secret}`;

  const created = await prisma.apiKey.create({
    data: {
      orgId: ctx.orgId,
      name: parsed.data.name,
      keyHash: createHash('sha256').update(token).digest('hex'),
      prefix,
      scopes: parsed.data.scopes,
      createdById: ctx.userId,
      expiresAt:
        parsed.data.expiresInDays === null
          ? null
          : new Date(Date.now() + parsed.data.expiresInDays * 86_400_000),
    },
    select: { id: true },
  });

  await audit(
    ctx,
    'apikey.created',
    { type: 'ApiKey', id: created.id },
    { name: parsed.data.name, prefix, scopes: parsed.data.scopes },
    request,
  );

  return { id: created.id, prefix, token };
}

export async function revokeApiKey(
  ctx: AuthContext & { actorEmail: string },
  keyId: string,
  request: RequestInfo = {},
): Promise<void> {
  assertCan(ctx, 'apikey:revoke', { orgId: ctx.orgId });

  const result = await prisma.apiKey.updateMany({
    where: { id: keyId, orgId: ctx.orgId, revokedAt: null },
    data: { revokedAt: new Date() },
  });

  if (result.count === 0) throw new NotFoundError('That API key does not exist.');

  await audit(ctx, 'apikey.revoked', { type: 'ApiKey', id: keyId }, {}, request);
}

/**
 * Resolve a presented key to the org it belongs to.
 *
 * Lookup is by digest — the plaintext is never in a query — and the stored
 * digest is then compared timing-safely, so response time does not narrow down
 * a partially correct key. Used by the public API and the CLI in phase 7.
 */
export async function resolveApiKey(
  token: string,
): Promise<{ orgId: string; keyId: string; scopes: string[] } | null> {
  if (typeof token !== 'string' || token.length < 20 || token.length > 200) return null;

  const digest = createHash('sha256').update(token).digest('hex');

  const row = await prisma.apiKey.findUnique({
    where: { keyHash: digest },
    select: { id: true, orgId: true, scopes: true, keyHash: true, revokedAt: true, expiresAt: true },
  });

  if (!row) return null;

  const presented = Buffer.from(digest, 'utf8');
  const stored = Buffer.from(row.keyHash, 'utf8');
  if (presented.length !== stored.length || !timingSafeEqual(presented, stored)) return null;

  if (!isActive(row)) return null;

  await prisma.apiKey.update({ where: { id: row.id }, data: { lastUsedAt: new Date() } });

  return { orgId: row.orgId, keyId: row.id, scopes: row.scopes };
}

// ---------------------------------------------------------------------------
// Webhooks
// ---------------------------------------------------------------------------

export const WEBHOOK_EVENTS = [
  'analysis.completed',
  'verdict.malicious',
  'policy.violation',
  'quarantine.held',
  'campaign.match',
] as const;
export type WebhookEvent = (typeof WEBHOOK_EVENTS)[number];

export const WEBHOOK_EVENT_LABELS: Record<WebhookEvent, string> = {
  'analysis.completed': 'An analysis finished, whatever the verdict',
  'verdict.malicious': 'A verdict of likely or known malicious',
  'policy.violation': 'A policy was violated',
  'quarantine.held': 'A package version was held',
  'campaign.match': 'A package joined a known campaign',
};

export interface WebhookRow {
  id: string;
  url: string;
  events: string[];
  active: boolean;
  lastDeliveryAt: Date | null;
  failureCount: number;
  createdAt: Date;
}

export async function listWebhooks(ctx: AuthContext): Promise<WebhookRow[]> {
  assertCan(ctx, 'webhook:read', { orgId: ctx.orgId });

  const rows = await prisma.webhook.findMany({
    where: { orgId: ctx.orgId },
    orderBy: { createdAt: 'desc' },
    // The signing secret is deliberately not selected: it is shown once, at
    // creation, and there is no route that reads it back out.
    select: {
      id: true,
      url: true,
      events: true,
      active: true,
      lastDeliveryAt: true,
      failureCount: true,
      createdAt: true,
    },
  });

  return rows;
}

export const webhookInputSchema = z.object({
  url: z
    .string()
    .trim()
    .url('Enter the absolute URL to POST to.')
    .max(500)
    .refine((value) => value.startsWith('https://'), 'Webhook endpoints must be https.'),
  events: z.array(z.enum(WEBHOOK_EVENTS)).min(1, 'Choose at least one event.'),
  active: z.boolean().default(true),
});

export type WebhookInput = z.infer<typeof webhookInputSchema>;

export interface CreatedWebhook {
  id: string;
  /** Plaintext signing secret. Shown once. */
  secret: string;
}

export async function createWebhook(
  ctx: AuthContext & { actorEmail: string },
  input: z.input<typeof webhookInputSchema>,
  request: RequestInfo = {},
): Promise<CreatedWebhook> {
  assertCan(ctx, 'webhook:create', { orgId: ctx.orgId });

  const parsed = webhookInputSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const secret = `whsec_${randomBytes(24).toString('base64url')}`;

  const created = await prisma.webhook.create({
    data: {
      orgId: ctx.orgId,
      url: parsed.data.url,
      secret,
      events: parsed.data.events,
      active: parsed.data.active,
    },
    select: { id: true },
  });

  await audit(
    ctx,
    'webhook.created',
    { type: 'Webhook', id: created.id },
    { url: parsed.data.url, events: parsed.data.events },
    request,
  );

  return { id: created.id, secret };
}

export async function updateWebhook(
  ctx: AuthContext & { actorEmail: string },
  webhookId: string,
  input: z.input<typeof webhookInputSchema>,
  request: RequestInfo = {},
): Promise<void> {
  assertCan(ctx, 'webhook:update', { orgId: ctx.orgId });

  const parsed = webhookInputSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

  const result = await prisma.webhook.updateMany({
    where: { id: webhookId, orgId: ctx.orgId },
    data: {
      url: parsed.data.url,
      events: parsed.data.events,
      active: parsed.data.active,
      // A change of endpoint clears the failure streak: the new URL has not
      // failed yet, and carrying the old count over would disable it early.
      failureCount: 0,
    },
  });

  if (result.count === 0) throw new NotFoundError('That webhook does not exist.');

  await audit(
    ctx,
    'webhook.updated',
    { type: 'Webhook', id: webhookId },
    { url: parsed.data.url, active: parsed.data.active },
    request,
  );
}

export async function deleteWebhook(
  ctx: AuthContext & { actorEmail: string },
  webhookId: string,
  request: RequestInfo = {},
): Promise<void> {
  assertCan(ctx, 'webhook:delete', { orgId: ctx.orgId });

  const result = await prisma.webhook.deleteMany({ where: { id: webhookId, orgId: ctx.orgId } });
  if (result.count === 0) throw new NotFoundError('That webhook does not exist.');

  await audit(ctx, 'webhook.deleted', { type: 'Webhook', id: webhookId }, {}, request);
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

export interface DeliveryRow {
  id: string;
  webhookId: string;
  event: string;
  statusCode: number | null;
  ok: boolean;
  error: string | null;
  durationMs: number | null;
  createdAt: Date;
}

export async function listDeliveries(
  ctx: AuthContext,
  webhookId?: string,
  take = 50,
): Promise<DeliveryRow[]> {
  assertCan(ctx, 'webhook:read', { orgId: ctx.orgId });

  return prisma.webhookDelivery.findMany({
    where: { orgId: ctx.orgId, ...(webhookId ? { webhookId } : {}) },
    orderBy: { createdAt: 'desc' },
    take: Math.min(Math.max(take, 1), 200),
    select: {
      id: true,
      webhookId: true,
      event: true,
      statusCode: true,
      ok: true,
      error: true,
      durationMs: true,
      createdAt: true,
    },
  });
}

/** `t=<unix>,v1=<hex>` over `<unix>.<body>`, so a captured delivery cannot be replayed. */
export function signPayload(secret: string, body: string, timestamp: number): string {
  const signature = createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
  return `t=${timestamp},v1=${signature}`;
}

/** How many consecutive failures disable a webhook. */
export const FAILURE_LIMIT = 10;

export interface DeliveryOutcome {
  ok: boolean;
  statusCode: number | null;
  error: string | null;
  durationMs: number;
}

/**
 * POST one event to one endpoint and record the attempt.
 *
 * Failure is data, not an exception: an endpoint that is down is a normal
 * condition for a webhook, and the delivery row is the product. Only the caller
 * that wants to react (the test button) inspects the outcome.
 */
export async function deliver(
  orgId: string,
  webhook: { id: string; url: string; secret: string },
  event: string,
  payload: Record<string, unknown>,
): Promise<DeliveryOutcome> {
  const body = JSON.stringify({ event, sentAt: new Date().toISOString(), data: payload });
  const timestamp = Math.floor(Date.now() / 1000);
  const startedAt = Date.now();

  let statusCode: number | null = null;
  let error: string | null = null;

  try {
    const response = await safeFetch(webhook.url, {
      method: 'POST',
      body,
      accept: 'application/json',
      // A webhook receiver's reply is not interesting; cap it hard.
      maxBytes: 64 * 1024,
      headers: {
        'x-quarantine-event': event,
        'x-quarantine-signature': signPayload(webhook.secret, body, timestamp),
      },
    });
    statusCode = response.status;
  } catch (cause) {
    // Never surface the raw failure: it can name internal hosts and resolved
    // addresses (CLAUDE.md rule 5).
    error =
      cause instanceof ExternalServiceError
        ? cause.message
        : 'The endpoint could not be reached.';
  }

  const durationMs = Date.now() - startedAt;
  const ok = statusCode !== null && statusCode >= 200 && statusCode < 300;

  if (!ok && !error && statusCode !== null) {
    error = `The endpoint replied ${statusCode}.`;
  }

  await prisma.webhookDelivery.create({
    data: {
      orgId,
      webhookId: webhook.id,
      event,
      statusCode,
      ok,
      error,
      durationMs,
      payload: payload as Prisma.InputJsonValue,
    },
  });

  await prisma.webhook.update({
    where: { id: webhook.id },
    data: {
      lastDeliveryAt: new Date(),
      failureCount: ok ? 0 : { increment: 1 },
    },
  });

  // A permanently broken endpoint stops being retried rather than being
  // hammered forever; re-saving the webhook clears the count.
  if (!ok) {
    const current = await prisma.webhook.findUnique({
      where: { id: webhook.id },
      select: { failureCount: true },
    });
    if (current && current.failureCount >= FAILURE_LIMIT) {
      await prisma.webhook.update({ where: { id: webhook.id }, data: { active: false } });
      logger.warn({ webhookId: webhook.id }, 'webhook disabled after repeated failures');
    }
  }

  return { ok, statusCode, error, durationMs };
}

/** Send a synthetic event so an operator can prove the endpoint is wired up. */
export async function testWebhook(
  ctx: AuthContext & { actorEmail: string },
  webhookId: string,
  request: RequestInfo = {},
): Promise<DeliveryOutcome> {
  assertCan(ctx, 'webhook:update', { orgId: ctx.orgId });

  const webhook = await prisma.webhook.findFirst({
    where: { id: webhookId, orgId: ctx.orgId },
    select: { id: true, url: true, secret: true },
  });
  if (!webhook) throw new NotFoundError('That webhook does not exist.');

  const outcome = await deliver(ctx.orgId, webhook, 'analysis.completed', {
    test: true,
    message: 'This is a test delivery from Quarantine.',
    package: { ecosystem: 'NPM', name: 'left-pad', version: '1.3.0' },
    verdict: 'CLEAN',
  });

  await audit(
    ctx,
    'webhook.tested',
    { type: 'Webhook', id: webhookId },
    { ok: outcome.ok, statusCode: outcome.statusCode },
    request,
  );

  return outcome;
}

/**
 * Fan one event out to every webhook in the org that subscribes to it.
 *
 * Best-effort and sequential: there are at most a handful of endpoints per org,
 * and a failing one must not stop the next from being tried.
 */
export async function dispatchEvent(
  orgId: string,
  event: WebhookEvent,
  payload: Record<string, unknown>,
): Promise<{ attempted: number; delivered: number }> {
  const webhooks = await prisma.webhook.findMany({
    where: { orgId, active: true, events: { has: event } },
    select: { id: true, url: true, secret: true },
  });

  let delivered = 0;
  for (const webhook of webhooks) {
    try {
      const outcome = await deliver(orgId, webhook, event, payload);
      if (outcome.ok) delivered += 1;
    } catch (cause) {
      logger.warn({ err: cause, webhookId: webhook.id }, 'webhook delivery threw');
    }
  }

  return { attempted: webhooks.length, delivered };
}
