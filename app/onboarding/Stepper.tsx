import { Check } from 'lucide-react';

import { cn } from '@/lib/utils';

export const ONBOARDING_STEPS = [
  { number: 1, label: 'Organisation' },
  { number: 2, label: 'Team' },
  { number: 3, label: 'First project' },
] as const;

export function Stepper({ current }: { current: number }) {
  return (
    <ol
      className="flex flex-col gap-3 sm:flex-row sm:items-center sm:gap-0"
      aria-label={`Step ${current} of ${ONBOARDING_STEPS.length}`}
    >
      {ONBOARDING_STEPS.map((step, index) => {
        const done = step.number < current;
        const active = step.number === current;

        return (
          <li key={step.number} className="flex flex-1 items-center gap-3">
            <span
              className={cn(
                'flex size-7 shrink-0 items-center justify-center rounded-full border text-xs font-medium',
                done && 'border-transparent bg-primary text-primary-foreground',
                active && 'border-primary text-primary',
                !done && !active && 'border-border text-muted-foreground',
              )}
              aria-hidden="true"
            >
              {done ? <Check className="size-3.5" /> : step.number}
            </span>

            <span
              className={cn(
                'text-sm whitespace-nowrap',
                active ? 'font-medium text-foreground' : 'text-muted-foreground',
              )}
            >
              {step.label}
              {active ? <span className="sr-only"> (current step)</span> : null}
            </span>

            {index < ONBOARDING_STEPS.length - 1 ? (
              <span
                aria-hidden="true"
                className={cn(
                  'ml-2 hidden h-px flex-1 sm:block',
                  done ? 'bg-primary' : 'bg-border',
                )}
              />
            ) : null}
          </li>
        );
      })}
    </ol>
  );
}
