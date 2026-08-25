'use server';

import { Ecosystem } from '@prisma/client';
import { z } from 'zod';

import { requestFingerprint, requireAuthContext } from '@/lib/auth-context';
import { ValidationError } from '@/lib/errors';
import { field, optionalField } from '@/lib/form-state';
import { toFormState } from '@/lib/form-state.server';
import { MAX_LOCKFILE_BYTES, parseLockfile } from '@/lib/lockfile';
import { bucketKey, enforce } from '@/lib/rate-limit';
import * as analysisService from '@/lib/services/analysis.service';

import {
  LOCKFILE_QUEUE_LIMIT,
  splitCoordinate,
  type QueuedScan,
  type ScanFormState,
} from './scan-state';

/**
 * Server Actions for the scan page.
 *
 * Both actions queue work and return immediately; the run itself streams from
 * `POST /api/analyses/[id]/run`, because a Server Action returns exactly once
 * and an analysis takes tens of seconds. Nothing here touches package content —
 * it resolves a coordinate and writes a row.
 */

const coordinateSchema = z.object({
  ecosystem: z.nativeEnum(Ecosystem),
  /** `name`, `name@version`, `@scope/name`, `@scope/name@version`. */
  coordinate: z.string().trim().min(1, 'Enter a package name.').max(300),
});

async function scanContext() {
  const ctx = await requireAuthContext();
  const { ip, userAgent } = await requestFingerprint();
  return { ctx: { ...ctx, actorEmail: ctx.email }, request: { ip, userAgent } };
}

/** Queue one package version, resolving a dist-tag or a missing version first. */
export async function queuePackageScanAction(
  _previous: ScanFormState,
  formData: FormData,
): Promise<ScanFormState> {
  try {
    const parsed = coordinateSchema.safeParse({
      ecosystem: field(formData, 'ecosystem'),
      coordinate: field(formData, 'coordinate'),
    });
    if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);

    const { ctx, request } = await scanContext();
    await enforce('scanCreate', bucketKey('scanCreate', { org: ctx.orgId, user: ctx.userId }));

    const { ecosystem } = parsed.data;
    const { name, version } = splitCoordinate(parsed.data.coordinate);
    const resolved = await analysisService.resolveVersion(ecosystem, name, version);

    const queued = await analysisService.queueAnalysis(
      ctx,
      { ecosystem, name, version: resolved },
      request,
    );

    return {
      status: 'success',
      message: null,
      queued: [
        {
          analysisId: queued.analysisId,
          ecosystem,
          name,
          version: resolved,
          reused: queued.reused,
        },
      ],
    };
  } catch (error) {
    return { ...toFormState(error), queued: [] };
  }
}

/** Queue every coordinate in an uploaded lockfile, up to the per-upload cap. */
export async function queueLockfileScanAction(
  _previous: ScanFormState,
  formData: FormData,
): Promise<ScanFormState> {
  try {
    const ecosystem = Ecosystem.NPM;
    const file = formData.get('lockfile');

    if (!(file instanceof File) || file.size === 0) {
      throw new ValidationError('Choose a lockfile to upload.', {
        details: { fieldErrors: { lockfile: ['Choose a lockfile to upload.'] } },
      });
    }

    if (file.size > MAX_LOCKFILE_BYTES) {
      throw new ValidationError('That lockfile is too large to read.', {
        details: {
          fieldErrors: {
            lockfile: [`Lockfiles are limited to ${MAX_LOCKFILE_BYTES / (1024 * 1024)}MB.`],
          },
        },
      });
    }

    const { ctx, request } = await scanContext();
    await enforce('scanCreate', bucketKey('scanCreate', { org: ctx.orgId, user: ctx.userId }));

    // Read as text and parse. The parser is pure and never executes anything it
    // reads; the file is not written to disk at any point.
    const parsed = parseLockfile(file.name, await file.text(), {
      maxEntries: LOCKFILE_QUEUE_LIMIT,
    });

    if (parsed.kind === 'unknown') {
      throw new ValidationError(
        'That file was not recognised as a package-lock.json or yarn.lock.',
        { details: { fieldErrors: { lockfile: ['Unrecognised lockfile format.'] } } },
      );
    }

    if (parsed.entries.length === 0) {
      throw new ValidationError('That lockfile lists no packages we can analyse.', {
        details: { fieldErrors: { lockfile: ['No usable dependencies found.'] } },
      });
    }

    const queued: QueuedScan[] = [];
    let skipped = 0;

    for (const entry of parsed.entries) {
      try {
        const result = await analysisService.queueAnalysis(
          ctx,
          { ecosystem, name: entry.name, version: entry.version },
          request,
        );
        queued.push({
          analysisId: result.analysisId,
          ecosystem,
          name: entry.name,
          version: entry.version,
          reused: result.reused,
        });
      } catch {
        // One unusable coordinate — a name the registry would reject, a version
        // that is a local path — must not sink the whole upload.
        skipped += 1;
      }
    }

    if (queued.length === 0) {
      throw new ValidationError('None of the packages in that lockfile could be queued.');
    }

    return {
      status: 'success',
      message: null,
      queued,
      lockfile: {
        kind: parsed.kind,
        found: parsed.found,
        queued: queued.length,
        skipped,
        truncated: parsed.truncated,
      },
    };
  } catch (error) {
    return { ...toFormState(error), queued: [] };
  }
}

/** Requeue a coordinate for a fresh analysis, e.g. from a report page. */
export async function rescanAction(
  _previous: ScanFormState,
  formData: FormData,
): Promise<ScanFormState> {
  const ecosystem =
    optionalField(formData, 'ecosystem') === 'PYPI' ? Ecosystem.PYPI : Ecosystem.NPM;
  const name = field(formData, 'name');
  const version = field(formData, 'version');

  try {
    const { ctx, request } = await scanContext();
    await enforce('scanCreate', bucketKey('scanCreate', { org: ctx.orgId, user: ctx.userId }));

    const queued = await analysisService.queueAnalysis(ctx, { ecosystem, name, version }, request);

    return {
      status: 'success',
      message: null,
      queued: [
        {
          analysisId: queued.analysisId,
          ecosystem,
          name,
          version,
          reused: queued.reused,
        },
      ],
    };
  } catch (error) {
    return { ...toFormState(error), queued: [] };
  }
}
