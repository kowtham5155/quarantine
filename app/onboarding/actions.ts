'use server';

import { redirect } from 'next/navigation';
import { Ecosystem, ProjectSource, Role } from '@prisma/client';

import { getAuthContext, requestFingerprint, requireSessionIdentity } from '@/lib/auth-context';
import { env } from '@/lib/env';
import { field, optionalField, type FormState } from '@/lib/form-state';
import { toFormState } from '@/lib/form-state.server';
import { type InviteState } from '@/app/onboarding/form-states';
import * as orgService from '@/lib/services/org.service';
import * as projectService from '@/lib/services/project.service';

/**
 * Onboarding: organisation, then team, then a first project.
 *
 * Step one is the only action that runs without an org-scoped context — there
 * is no org yet. Everything after it goes through `getAuthContext()`, which
 * re-reads the membership, so the wizard cannot be used to act on an org the
 * caller does not belong to.
 */

async function orgContext() {
  const ctx = await getAuthContext();
  if (!ctx) redirect('/onboarding?step=1');
  return { ...ctx, actorEmail: ctx.email };
}

// ---------------------------------------------------------------------------
// Step 1 — organisation
// ---------------------------------------------------------------------------

export async function createOrgAction(_prev: FormState, formData: FormData): Promise<FormState> {
  const identity = await requireSessionIdentity();
  const name = field(formData, 'name');
  const slug = optionalField(formData, 'slug');

  try {
    await orgService.create(
      { userId: identity.userId, email: identity.email },
      { name, ...(slug ? { slug } : {}) },
      await requestFingerprint(),
    );
  } catch (error) {
    return toFormState(error);
  }

  redirect('/onboarding?step=2');
}

// ---------------------------------------------------------------------------
// Step 2 — team
// ---------------------------------------------------------------------------

export async function inviteTeamAction(
  prev: InviteState,
  formData: FormData,
): Promise<InviteState> {
  const ctx = await orgContext();
  const email = field(formData, 'email');
  const roleValue = field(formData, 'role');
  const role = (Object.values(Role) as string[]).includes(roleValue)
    ? (roleValue as Role)
    : Role.VIEWER;

  try {
    const invite = await orgService.inviteMember(ctx, { email, role }, await requestFingerprint());

    // Absolute, because the inviter has to paste this somewhere else entirely.
    const origin = env.APP_URL.replace(/\/+$/, '');
    const invited = [...(prev.invited ?? []), invite.email];
    const links = {
      ...(prev.links ?? {}),
      [invite.email]: `${origin}/accept-invite/${invite.inviteToken}`,
    };

    return {
      status: 'success',
      message: `Invitation created for ${invite.email}. Nothing was emailed — send them the link below yourself.`,
      invited,
      links,
    };
  } catch (error) {
    return {
      ...toFormState(error),
      ...(prev.invited ? { invited: prev.invited } : {}),
      ...(prev.links ? { links: prev.links } : {}),
    };
  }
}

// ---------------------------------------------------------------------------
// Step 3 — first project
// ---------------------------------------------------------------------------

export async function createProjectAction(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const ctx = await orgContext();

  const name = field(formData, 'name');
  const description = optionalField(formData, 'description');
  const ecosystemValue = field(formData, 'ecosystem');
  const repoUrl = optionalField(formData, 'repoUrl');

  const ecosystem = (Object.values(Ecosystem) as string[]).includes(ecosystemValue)
    ? (ecosystemValue as Ecosystem)
    : Ecosystem.NPM;

  try {
    await projectService.create(
      ctx,
      {
        name,
        ecosystem,
        source: repoUrl ? ProjectSource.GITHUB : ProjectSource.UPLOAD,
        ...(description ? { description } : {}),
        ...(repoUrl ? { repoUrl } : {}),
      },
      await requestFingerprint(),
    );
  } catch (error) {
    return toFormState(error);
  }

  redirect('/dashboard');
}
