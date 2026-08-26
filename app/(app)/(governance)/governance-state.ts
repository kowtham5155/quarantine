import type { FormState } from '@/lib/form-state';

/**
 * Form state shared by the three governance surfaces.
 *
 * They are one workflow — a violation is triaged, the package it held is
 * released, or an exception is requested and decided — so they share a route
 * group, a set of Server Actions and this shape. A `'use server'` module may
 * only export async functions, which is why this is not in `actions.ts`.
 */

export interface GovernanceFormState extends FormState {
  /** How many rows the last bulk operation actually changed. */
  updated?: number;
}

export const initialGovernanceState: GovernanceFormState = { status: 'idle', message: null };
