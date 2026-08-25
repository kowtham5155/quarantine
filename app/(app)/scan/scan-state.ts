import type { Ecosystem } from '@prisma/client';

import type { FormState } from '@/lib/form-state';
import type { LockfileKind } from '@/lib/lockfile';

/**
 * Shapes and pure helpers shared by the scan action and the scan form.
 *
 * They live outside `actions.ts` because a `'use server'` module may only
 * export async functions — a constant or a synchronous helper there is a build
 * error, not a style problem.
 */

export interface QueuedScan {
  analysisId: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  /** True when an in-flight analysis was reused rather than a new one queued. */
  reused: boolean;
}

export interface LockfileSummary {
  kind: LockfileKind;
  found: number;
  queued: number;
  skipped: number;
  truncated: boolean;
}

export interface ScanFormState extends FormState {
  queued: QueuedScan[];
  lockfile?: LockfileSummary;
}

export const initialScanState: ScanFormState = { status: 'idle', message: null, queued: [] };

/** How many coordinates one lockfile upload may queue. */
export const LOCKFILE_QUEUE_LIMIT = 25;

/**
 * Split `@scope/name@1.2.3` into its parts without tripping over the scope's
 * own `@`. A bare name returns a null version, which the caller resolves
 * against the registry's current release.
 */
export function splitCoordinate(input: string): { name: string; version: string | null } {
  const trimmed = input.trim().replace(/^npm:/i, '');
  const at = trimmed.lastIndexOf('@');

  if (at <= 0) return { name: trimmed, version: null };

  const version = trimmed.slice(at + 1).trim();
  const name = trimmed.slice(0, at).trim();

  if (name.length === 0 || version.length === 0) return { name: trimmed, version: null };
  return { name, version };
}
