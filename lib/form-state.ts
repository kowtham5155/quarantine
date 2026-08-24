/**
 * The shape every `useActionState` form in this app speaks.
 *
 * This module is imported by client components, so it stays free of anything
 * Node-only. The translation from a thrown error into a FormState needs the
 * logger and therefore lives in `lib/form-state.server.ts`.
 */

export interface FormState {
  status: 'idle' | 'error' | 'success';
  message: string | null;
  fieldErrors?: Record<string, string[]>;
  /** Free-form payload a specific form needs to carry between submissions. */
  data?: Record<string, string>;
}

export const initialFormState: FormState = { status: 'idle', message: null };

export const GENERIC_FORM_ERROR = 'Something went wrong. Please try again.';

/** Read a required string field, normalised. */
export function field(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === 'string' ? value : '';
}

/** Read an optional string field; empty becomes undefined. */
export function optionalField(formData: FormData, name: string): string | undefined {
  const value = field(formData, name).trim();
  return value.length > 0 ? value : undefined;
}
