'use server';

import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { PolicyAction } from '@prisma/client';

import { requestFingerprint, requireAuthContext } from '@/lib/auth-context';
import { ValidationError } from '@/lib/errors';
import { field, optionalField } from '@/lib/form-state';
import { toFormState } from '@/lib/form-state.server';
import * as policyService from '@/lib/services/policy.service';

import { type PolicyFormState, type PolicyPreviewState } from './policy-state';

/**
 * Policy mutations.
 *
 * The condition builder posts its conditions as one JSON field. It is parsed
 * here with the same Zod union the engine evaluates against, so a hand-crafted
 * POST cannot store a condition shape the enforcement path would later choke
 * on.
 */

async function policyContext() {
  const ctx = await requireAuthContext();
  const { ip, userAgent } = await requestFingerprint();
  return { ctx: { ...ctx, actorEmail: ctx.email }, request: { ip, userAgent } };
}

function readAction(formData: FormData): PolicyAction {
  const value = field(formData, 'action');
  return value === 'ALLOW'
    ? PolicyAction.ALLOW
    : value === 'WARN'
      ? PolicyAction.WARN
      : PolicyAction.BLOCK;
}

function readConditions(formData: FormData): policyService.PolicyCondition[] {
  const raw = field(formData, 'conditions');

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw || '[]');
  } catch {
    throw new ValidationError('The conditions could not be read. Rebuild them and try again.', {
      details: { fieldErrors: { conditions: ['The conditions could not be read.'] } },
    });
  }

  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new ValidationError('A policy needs at least one condition.', {
      details: { fieldErrors: { conditions: ['Add at least one condition.'] } },
    });
  }

  const conditions: policyService.PolicyCondition[] = [];
  for (const [index, entry] of parsed.entries()) {
    const result = policyService.policyConditionSchema.safeParse(entry);
    if (!result.success) {
      throw new ValidationError(`Condition ${index + 1} is not complete.`, {
        details: {
          fieldErrors: { conditions: [`Condition ${index + 1} is missing a value.`] },
        },
      });
    }
    conditions.push(result.data);
  }

  return conditions;
}

function readPriority(formData: FormData): number {
  const raw = Number.parseInt(field(formData, 'priority'), 10);
  return Number.isFinite(raw) ? raw : 100;
}

export async function createPolicyAction(
  _previous: PolicyFormState,
  formData: FormData,
): Promise<PolicyFormState> {
  let policyId: string;

  try {
    const { ctx, request } = await policyContext();

    const policy = await policyService.createPolicy(
      ctx,
      {
        name: field(formData, 'name'),
        ...(optionalField(formData, 'description')
          ? { description: field(formData, 'description') }
          : {}),
        action: readAction(formData),
        priority: readPriority(formData),
        enabled: field(formData, 'enabled') !== 'false',
        conditions: readConditions(formData),
      },
      request,
    );

    policyId = policy.id;
  } catch (error) {
    return toFormState(error);
  }

  revalidatePath('/policies');
  redirect(`/policies/${policyId}`);
}

export async function updatePolicyAction(
  _previous: PolicyFormState,
  formData: FormData,
): Promise<PolicyFormState> {
  try {
    const { ctx, request } = await policyContext();
    const policyId = field(formData, 'policyId');

    await policyService.updatePolicy(
      ctx,
      policyId,
      {
        name: field(formData, 'name'),
        ...(optionalField(formData, 'description')
          ? { description: field(formData, 'description') }
          : {}),
        action: readAction(formData),
        priority: readPriority(formData),
        enabled: field(formData, 'enabled') !== 'false',
        conditions: readConditions(formData),
      },
      request,
    );

    revalidatePath('/policies');
    revalidatePath(`/policies/${policyId}`);

    return { status: 'success', message: 'Policy saved.', policyId };
  } catch (error) {
    return toFormState(error);
  }
}

/** Enable or disable a policy from the list, without opening the editor. */
export async function setPolicyEnabledAction(
  _previous: PolicyFormState,
  formData: FormData,
): Promise<PolicyFormState> {
  try {
    const { ctx, request } = await policyContext();
    const policyId = field(formData, 'policyId');
    const enabled = field(formData, 'enabled') === 'true';

    await policyService.setPolicyEnabled(ctx, policyId, enabled, request);

    revalidatePath('/policies');
    revalidatePath(`/policies/${policyId}`);

    return {
      status: 'success',
      message: enabled ? 'Policy enabled.' : 'Policy disabled.',
      policyId,
    };
  } catch (error) {
    return toFormState(error);
  }
}

export async function deletePolicyAction(
  _previous: PolicyFormState,
  formData: FormData,
): Promise<PolicyFormState> {
  try {
    const { ctx, request } = await policyContext();
    await policyService.deletePolicy(ctx, field(formData, 'policyId'), request);
  } catch (error) {
    return toFormState(error);
  }

  revalidatePath('/policies');
  redirect('/policies');
}

/**
 * "What would this have blocked" — a read over the org's recent analyses.
 *
 * Nothing is written: no violation, no quarantine, no audit entry. It is the
 * only way to tell whether a BLOCK policy is about to stop a release before it
 * actually does.
 */
export async function previewPolicyAction(
  _previous: PolicyPreviewState,
  formData: FormData,
): Promise<PolicyPreviewState> {
  try {
    const ctx = await requireAuthContext();

    const preview = await policyService.previewPolicy(ctx, {
      conditions: readConditions(formData),
      action: readAction(formData),
    });

    return {
      status: 'success',
      message: `${preview.matched} of the last ${preview.evaluated} analyses match.`,
      preview,
    };
  } catch (error) {
    return toFormState(error);
  }
}
