'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { Check, Copy } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';

export interface CopyButtonProps {
  value: string;
  /** Accessible label; also the tooltip text before copying. */
  label?: string;
  size?: 'icon' | 'sm';
  className?: string;
}

/** Copy-to-clipboard with a two-second confirmation state. */
export function CopyButton({ value, label = 'Copy', size = 'icon', className }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, []);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
      timeoutRef.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard permission denied or unavailable — leave the button idle
      // rather than claiming a copy that did not happen.
      setCopied(false);
    }
  }, [value]);

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size={size === 'icon' ? 'icon' : 'sm'}
          onClick={handleCopy}
          aria-label={copied ? 'Copied' : label}
          className={cn('shrink-0 text-muted-foreground hover:text-foreground', className)}
        >
          {copied ? (
            <Check aria-hidden="true" className="text-verdict-clean-accent" />
          ) : (
            <Copy aria-hidden="true" />
          )}
          {size === 'sm' ? <span>{copied ? 'Copied' : label}</span> : null}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{copied ? 'Copied' : label}</TooltipContent>
    </Tooltip>
  );
}
