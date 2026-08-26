import type { FormState } from '@/lib/form-state';

/**
 * Shapes shared by the project actions and the forms that call them.
 *
 * They live outside `actions.ts` because a `'use server'` module may only
 * export async functions — anything else exported from one is shipped to the
 * client as a server reference and silently arrives as `undefined`.
 */

export interface ProjectFormState extends FormState {
  projectId?: string;
  /** Populated by an import so the page can say what was read. */
  imported?: {
    kind: string;
    found: number;
    imported: number;
    direct: number;
    truncated: boolean;
  };
  queued?: { queued: number; skipped: number; remaining: number };
}

export const initialProjectState: ProjectFormState = { status: 'idle', message: null };
