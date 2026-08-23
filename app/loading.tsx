import { LoadingSkeleton } from '@/components/shared/LoadingSkeleton';

export default function Loading() {
  return (
    <div className="mx-auto w-full max-w-6xl px-4 py-16 sm:px-6">
      <LoadingSkeleton variant="page" />
    </div>
  );
}
