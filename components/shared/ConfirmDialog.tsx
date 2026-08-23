'use client';

import { useCallback, useEffect, useId, useState, type ReactNode } from 'react';
import { Loader2 } from 'lucide-react';

import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

export interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Red confirm button, for anything that destroys or revokes. */
  destructive?: boolean;
  /**
   * When set, the confirm button stays disabled until the user types this
   * string exactly. Reserved for the genuinely irreversible: deleting an org,
   * revoking every API key.
   */
  requireTypedConfirmation?: string;
  /**
   * Runs on confirm. If it returns a promise the dialog shows a pending state
   * and stays open until it settles; it closes on success and remains open on
   * rejection so the caller can surface the error.
   */
  onConfirm: () => void | Promise<void>;
}

/**
 * Confirmation gate for destructive and irreversible actions. Focus lands on
 * the cancel button, so a stray Enter never confirms.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  destructive = false,
  requireTypedConfirmation,
  onConfirm,
}: ConfirmDialogProps) {
  const [pending, setPending] = useState(false);
  const [typed, setTyped] = useState('');
  const inputId = useId();

  useEffect(() => {
    if (!open) {
      setTyped('');
      setPending(false);
    }
  }, [open]);

  const confirmDisabled =
    pending || (requireTypedConfirmation ? typed !== requireTypedConfirmation : false);

  const handleConfirm = useCallback(async () => {
    if (confirmDisabled) return;
    try {
      setPending(true);
      await onConfirm();
      onOpenChange(false);
    } catch {
      // Keep the dialog open; the caller reports the failure via a toast.
      setPending(false);
    }
  }, [confirmDisabled, onConfirm, onOpenChange]);

  return (
    <Dialog open={open} onOpenChange={pending ? undefined : onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description ? <DialogDescription>{description}</DialogDescription> : null}
        </DialogHeader>

        {requireTypedConfirmation ? (
          <div className="space-y-2">
            <Label htmlFor={inputId}>
              Type <code className="font-mono">{requireTypedConfirmation}</code> to continue
            </Label>
            <Input
              id={inputId}
              value={typed}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => setTyped(event.target.value)}
              className="font-mono"
            />
          </div>
        ) : null}

        <DialogFooter className="gap-2 sm:gap-2">
          <Button
            type="button"
            variant="outline"
            autoFocus
            disabled={pending}
            onClick={() => onOpenChange(false)}
          >
            {cancelLabel}
          </Button>
          <Button
            type="button"
            variant={destructive ? 'destructive' : 'default'}
            disabled={confirmDisabled}
            onClick={handleConfirm}
          >
            {pending ? <Loader2 aria-hidden="true" className="animate-spin" /> : null}
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
