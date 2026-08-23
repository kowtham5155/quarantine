import { AlertTriangle } from 'lucide-react';
import Link from 'next/link';

import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { containsDeceptiveCharacters, safeText } from '@/lib/safe-display';
import { cn } from '@/lib/utils';

export interface PackageRefProps {
  name: string;
  version?: string | null;
  ecosystem?: 'npm' | 'pypi' | 'crates' | 'rubygems';
  /** Link target for the package's report page. */
  href?: string;
  size?: 'sm' | 'md';
  /** Hide the ecosystem chip when the surrounding context already states it. */
  hideEcosystem?: boolean;
  className?: string;
}

/**
 * A package identifier. Always monospace, always length-bounded, and always
 * stripped of bidi and zero-width characters — a name is attacker-controlled
 * input, and the entire premise of signal family 4 is that it may be trying to
 * look like something it is not. When such characters are present we say so
 * inline rather than silently normalising and showing a name the reader has no
 * way to verify.
 */
export function PackageRef({
  name,
  version,
  ecosystem = 'npm',
  href,
  size = 'md',
  hideEcosystem = false,
  className,
}: PackageRefProps) {
  const displayName = safeText(name, { maxLength: 214 });
  const displayVersion = version ? safeText(version, { maxLength: 64 }) : null;
  const deceptive =
    containsDeceptiveCharacters(name) || (version ? containsDeceptiveCharacters(version) : false);

  const body = (
    <span
      className={cn(
        'inline-flex min-w-0 items-baseline gap-1 font-mono',
        size === 'sm' ? 'text-xs' : 'text-sm',
      )}
    >
      <span className="break-anywhere truncate">{displayName}</span>
      {displayVersion ? (
        <span className="shrink-0 text-muted-foreground">@{displayVersion}</span>
      ) : null}
    </span>
  );

  return (
    <span className={cn('inline-flex min-w-0 items-center gap-1.5', className)}>
      {hideEcosystem ? null : (
        <span
          aria-label={`${ecosystem} package`}
          className="shrink-0 rounded border border-border px-1 py-px font-mono text-[10px] text-muted-foreground uppercase"
        >
          {ecosystem}
        </span>
      )}
      {href ? (
        <Link href={href} className="min-w-0 underline-offset-4 hover:text-primary hover:underline">
          {body}
        </Link>
      ) : (
        body
      )}
      {deceptive ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <AlertTriangle
              aria-label="Contains invisible or bidirectional characters"
              className="size-3.5 shrink-0 text-verdict-suspicious-accent"
            />
          </TooltipTrigger>
          <TooltipContent>
            This identifier contains invisible or bidirectional Unicode characters. What is rendered
            is not the literal name.
          </TooltipContent>
        </Tooltip>
      ) : null}
    </span>
  );
}
