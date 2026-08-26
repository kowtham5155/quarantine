'use client';

import { RouteError } from '@/components/shared/RouteError';

export default function ProjectError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <RouteError
      title="This project could not be loaded"
      error={error}
      reset={reset}
      secondary={{ href: '/projects', label: 'Back to projects' }}
    />
  );
}
