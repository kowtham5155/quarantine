import type { Metadata } from 'next';
import { redirect } from 'next/navigation';

import { StepOrganisation } from '@/app/onboarding/StepOrganisation';
import { StepProject } from '@/app/onboarding/StepProject';
import { StepTeam } from '@/app/onboarding/StepTeam';
import { Stepper } from '@/app/onboarding/Stepper';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { getAuthContext, getSessionIdentity } from '@/lib/auth-context';
import { safeText } from '@/lib/safe-display';

export const metadata: Metadata = {
  title: 'Set up your workspace',
  robots: { index: false, follow: false },
};

export const dynamic = 'force-dynamic';

/**
 * Three-step setup: organisation, team, first project.
 *
 * The requested step is a hint, not authority — the real position comes from
 * what exists in the database. Somebody typing `?step=3` with no organisation
 * is sent back to step 1 rather than shown a form that cannot submit.
 */
export default async function OnboardingPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const identity = await getSessionIdentity();
  if (!identity) redirect('/login?next=%2Fonboarding');

  const params = await searchParams;
  const rawStep = typeof params.step === 'string' ? Number.parseInt(params.step, 10) : 1;
  const requested = Number.isFinite(rawStep) && rawStep >= 1 && rawStep <= 3 ? rawStep : 1;

  const ctx = await getAuthContext();

  // No organisation yet: step 1 is the only step that can be shown.
  if (!ctx) {
    return (
      <Wizard step={1} title="Create your organisation" description={ORG_DESCRIPTION}>
        <StepOrganisation />
      </Wizard>
    );
  }

  const step = requested === 1 ? 2 : requested;

  if (step === 2) {
    return (
      <Wizard
        step={2}
        title="Invite your team"
        description="Everyone who reviews a verdict or approves an exception needs an account. You can do this later from Settings."
      >
        <StepTeam maxRole={ctx.role} />
      </Wizard>
    );
  }

  return (
    <Wizard
      step={3}
      title="Add your first project"
      description={`A project is a dependency tree that ${safeText(ctx.name, { maxLength: 60 })} and the rest of your team scan against policy.`}
    >
      <StepProject />
    </Wizard>
  );
}

const ORG_DESCRIPTION =
  'Everything in Quarantine belongs to an organisation: projects, policies, verdicts and the audit log.';

function Wizard({
  step,
  title,
  description,
  children,
}: {
  step: number;
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-8">
      <Stepper current={step} />

      <Card>
        <CardHeader className="gap-1">
          <CardTitle className="text-xl">{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent>{children}</CardContent>
      </Card>
    </div>
  );
}
