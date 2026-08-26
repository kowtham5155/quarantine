import type { FormState } from '@/lib/form-state';
import type { PolicyPreview } from '@/lib/services/policy.service';

/**
 * Shapes shared by the policy actions and the forms that call them.
 *
 * A `'use server'` module may only export async functions, so anything that is
 * not one lives here — exported from `actions.ts` it would reach the client as
 * a server reference and arrive as `undefined`.
 */

export interface PolicyFormState extends FormState {
  policyId?: string;
}

export const initialPolicyState: PolicyFormState = { status: 'idle', message: null };

export interface PolicyPreviewState extends FormState {
  preview?: PolicyPreview;
}

export const initialPreviewState: PolicyPreviewState = { status: 'idle', message: null };
