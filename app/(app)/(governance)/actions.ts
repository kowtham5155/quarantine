'use server';

import { revalidatePath } from 'next/cache';
import { ExceptionState, QuarantineState, ViolationState } from '@prisma/client';

import { requestFingerprint, requireAuthContext } from '@/lib/auth-context';
import { ValidationError } from '@/lib/errors';
import { field, optionalField } from '@/lib/form-state';
import { toFormState } from '@/lib/form-state.server';
import * as governanceService from '@/lib/services/governance.service';

import { type GovernanceFormState } from './governance-state';

/**
 * Governance mutations: triage, quarantine review, exception decisions.
 *
 * Every one of these re-checks the permission in the service against the
 * database and scopes its write by `orgId`, so a checkbox list posted from a
 * hostile client can only ever touch the caller's own tenant.
 */

async function governanceContext() {
  const ctx = await requireAuthContext();
  const { ip, userAgent } = await requestFingerprint();
  return { ctx: { ...ctx, actorEmail: ctx.email }, request: { ip, userAgent } };
}

/** Read a repeated checkbox field, bounded so one post cannot sweep the table. */
function readIds(formData: FormData, name: string): string[] {
  const ids = formData
    .getAll(name)
    .filter((value): value is string => typeof value === 'string')
    .map((value) => value.trim())
    .filter((value) => value.length > 0 && value.length <= 64);

  if (ids.length === 0) {
    throw new ValidationError('Select at least one row first.');
  }

  return [...new Set(ids)].slice(0, 200);
}

export async function triageViolationsAction(
  _previous: GovernanceFormState,
  formData: FormData,
): Promise<GovernanceFormState> {
  try {
    const { ctx, request } = await governanceContext();

    const state =
      field(formData, 'state') === 'OPEN' ? ViolationState.OPEN : ViolationState.RESOLVED;

    const { updated } = await governanceService.triageViolations(
      ctx,
      { violationIds: readIds(formData, 'violationIds'), state },
      request,
    );

    revalidatePath('/violations');

    return {
      status: 'success',
      message: `${updated} ${updated === 1 ? 'violation' : 'violations'} marked ${state === ViolationState.OPEN ? 'open' : 'resolved'}.`,
      updated,
    };
  } catch (error) {
    return toFormState(error);
  }
}

export async function reviewQuarantineAction(
  _previous: GovernanceFormState,
  formData: FormData,
): Promise<GovernanceFormState> {
  try {
    const { ctx, request } = await governanceContext();

    const decision =
      field(formData, 'decision') === 'RELEASED'
        ? QuarantineState.RELEASED
        : QuarantineState.CONFIRMED_BAD;

    await governanceService.reviewQuarantineItem(
      ctx,
      {
        itemId: field(formData, 'itemId'),
        decision,
        ...(optionalField(formData, 'note') ? { note: field(formData, 'note') } : {}),
      },
      request,
    );

    revalidatePath('/quarantine');
    revalidatePath('/violations');

    return {
      status: 'success',
      message:
        decision === QuarantineState.RELEASED
          ? 'Released. The open violations on that coordinate are resolved with it.'
          : 'Confirmed bad. It stays held and its violations stay open.',
    };
  } catch (error) {
    return toFormState(error);
  }
}

export async function requestExceptionAction(
  _previous: GovernanceFormState,
  formData: FormData,
): Promise<GovernanceFormState> {
  try {
    const { ctx, request } = await governanceContext();

    const days = Number.parseInt(field(formData, 'expiresInDays'), 10);

    await governanceService.requestException(
      ctx,
      {
        packageVersionId: field(formData, 'packageVersionId'),
        ...(optionalField(formData, 'policyId') ? { policyId: field(formData, 'policyId') } : {}),
        justification: field(formData, 'justification'),
        // An empty or unparseable value means indefinite, which an approver has
        // to consciously accept rather than something a typo can produce.
        expiresInDays: Number.isFinite(days) ? days : null,
      },
      request,
    );

    revalidatePath('/exceptions');

    return {
      status: 'success',
      message: 'Exception requested. An administrator has to approve it before it takes effect.',
    };
  } catch (error) {
    return toFormState(error);
  }
}

export async function decideExceptionAction(
  _previous: GovernanceFormState,
  formData: FormData,
): Promise<GovernanceFormState> {
  try {
    const { ctx, request } = await governanceContext();

    const decision =
      field(formData, 'decision') === 'APPROVED' ? ExceptionState.APPROVED : ExceptionState.DENIED;

    await governanceService.decideException(
      ctx,
      { exceptionId: field(formData, 'exceptionId'), decision },
      request,
    );

    revalidatePath('/exceptions');
    revalidatePath('/violations');
    revalidatePath('/quarantine');

    return {
      status: 'success',
      message:
        decision === ExceptionState.APPROVED
          ? 'Approved. The violations it covers are marked excepted until it expires.'
          : 'Denied. Nothing about the package changed.',
    };
  } catch (error) {
    return toFormState(error);
  }
}
