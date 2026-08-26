'use client';

import { RouteError } from '@/components/shared/RouteError';

export default function ProjectsError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <RouteError
      title="Projects could not be loaded"
      error={error}
      reset={reset}
      secondary={{ href: '/dashboard', label: 'Go to the dashboard' }}
    />
  );
}
