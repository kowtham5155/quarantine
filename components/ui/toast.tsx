'use client';

import { toast as sonnerToast, type ExternalToast } from 'sonner';

import { Toaster } from '@/components/ui/sonner';

/**
 * Toast API.
 *
 * shadcn/ui retired its own Radix-based `toast` primitive in favour of Sonner;
 * this module is the project's single toast entry point so callers import from
 * one place regardless of what backs it. `<Toaster />` is mounted once in the
 * root layout.
 */

export type ToastOptions = ExternalToast;

export interface ToastFn {
  (message: string, options?: ToastOptions): string | number;
  success: (message: string, options?: ToastOptions) => string | number;
  error: (message: string, options?: ToastOptions) => string | number;
  warning: (message: string, options?: ToastOptions) => string | number;
  info: (message: string, options?: ToastOptions) => string | number;
  loading: (message: string, options?: ToastOptions) => string | number;
  dismiss: (id?: string | number) => void;
  promise: typeof sonnerToast.promise;
}

const base = (message: string, options?: ToastOptions) => sonnerToast(message, options);

export const toast: ToastFn = Object.assign(base, {
  success: (message: string, options?: ToastOptions) => sonnerToast.success(message, options),
  error: (message: string, options?: ToastOptions) => sonnerToast.error(message, options),
  warning: (message: string, options?: ToastOptions) => sonnerToast.warning(message, options),
  info: (message: string, options?: ToastOptions) => sonnerToast.info(message, options),
  loading: (message: string, options?: ToastOptions) => sonnerToast.loading(message, options),
  dismiss: (id?: string | number) => {
    sonnerToast.dismiss(id);
  },
  promise: sonnerToast.promise,
});

/** Hook form, for parity with the previous shadcn/ui toast API. */
export function useToast(): { toast: ToastFn; dismiss: (id?: string | number) => void } {
  return { toast, dismiss: toast.dismiss };
}

export { Toaster };
