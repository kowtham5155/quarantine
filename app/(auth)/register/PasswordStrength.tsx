'use client';

import { useEffect, useState, useTransition } from 'react';
import { Check, X } from 'lucide-react';

import { scorePasswordAction } from '@/app/(auth)/actions';
import type { PasswordScore } from '@/app/(auth)/form-states';
import { MIN_PASSWORD_LENGTH, MIN_ZXCVBN_SCORE } from '@/lib/password-policy';
import { cn } from '@/lib/utils';

/**
 * zxcvbn strength meter.
 *
 * Scoring happens in a Server Action so the dictionaries stay out of the client
 * bundle and the browser cannot disagree with the server about the policy. The
 * call is debounced; the meter is advisory, the real gate is in the service.
 */

const SEGMENT_CLASSES = [
  'bg-verdict-known-malicious-accent',
  'bg-verdict-likely-malicious-accent',
  'bg-verdict-suspicious-accent',
  'bg-verdict-low-risk-accent',
  'bg-verdict-clean-accent',
];

export function PasswordStrength({
  password,
  userInputs,
}: {
  password: string;
  userInputs: string[];
}) {
  const [result, setResult] = useState<PasswordScore | null>(null);
  const [, startTransition] = useTransition();
  const inputKey = userInputs.join(' ');

  useEffect(() => {
    if (password.length === 0) {
      setResult(null);
      return;
    }

    let cancelled = false;
    const timer = setTimeout(() => {
      startTransition(async () => {
        const next = await scorePasswordAction(password, inputKey.split(' ').filter(Boolean));
        if (!cancelled) setResult(next);
      });
    }, 220);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [password, inputKey]);

  const longEnough = password.length >= MIN_PASSWORD_LENGTH;
  const score = result?.score ?? 0;
  const strongEnough = score >= MIN_ZXCVBN_SCORE;

  return (
    <div className="space-y-2">
      <div className="flex gap-1" aria-hidden="true">
        {SEGMENT_CLASSES.map((segment, index) => (
          <span
            key={segment}
            className={cn(
              'h-1 flex-1 rounded-full transition-colors',
              password.length > 0 && index <= score ? segment : 'bg-muted',
            )}
          />
        ))}
      </div>

      <p className="text-sm" role="status" aria-live="polite">
        {password.length === 0 ? (
          <span className="text-muted-foreground">
            At least {MIN_PASSWORD_LENGTH} characters, and hard to guess.
          </span>
        ) : (
          <span className={strongEnough ? 'text-verdict-clean-accent' : 'text-muted-foreground'}>
            Strength: {result ? result.label : 'Checking'}
          </span>
        )}
      </p>

      <ul className="space-y-1 text-sm text-muted-foreground">
        <Requirement met={longEnough}>At least {MIN_PASSWORD_LENGTH} characters</Requirement>
        <Requirement met={strongEnough}>Not a guessable or reused password</Requirement>
      </ul>

      {result?.warning ? (
        <p className="text-sm text-verdict-suspicious-accent">{result.warning}</p>
      ) : null}

      {result && !strongEnough && result.suggestions.length > 0 ? (
        <ul className="list-inside list-disc text-sm text-muted-foreground">
          {result.suggestions.map((suggestion) => (
            <li key={suggestion}>{suggestion}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function Requirement({ met, children }: { met: boolean; children: React.ReactNode }) {
  return (
    <li className="flex items-center gap-2">
      {met ? (
        <Check aria-hidden="true" className="size-3.5 text-verdict-clean-accent" />
      ) : (
        <X aria-hidden="true" className="size-3.5 text-muted-foreground" />
      )}
      <span className={met ? 'text-foreground' : undefined}>{children}</span>
      <span className="sr-only">{met ? '(met)' : '(not met)'}</span>
    </li>
  );
}
