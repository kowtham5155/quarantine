'use client';

import { RouteError } from '@/components/shared/RouteError';

export default function GovernanceError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <RouteError
      title="This page could not be loaded"
      error={error}
      reset={reset}
      secondary={{ href: '/dashboard', label: 'Go to the dashboard' }}
    />
  );
}
