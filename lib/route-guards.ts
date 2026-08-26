import { redirect } from 'next/navigation';

/**
 * Page-level guards.
 *
 * These are *rendering* decisions: they stop a page drawing a surface the user
 * cannot use. They are never the authorisation decision — that happens in the
 * service layer, which re-checks the permission against the database on every
 * call (CLAUDE.md rule 3). A page that forgot to call one of these is a UX bug,
 * not a hole.
 */

/** Send the caller to the explanation page rather than rendering an empty form. */
export function forbidden(): never {
  redirect('/unauthorized');
}
