import { cache } from 'react';
import { notFound } from 'next/navigation';
import type { Ecosystem } from '@prisma/client';

import { requireAuthContext } from '@/lib/auth-context';
import { NotFoundError } from '@/lib/errors';
import { getVersionReport, type VersionReport } from '@/lib/services/package.service';

/**
 * Load one version report for the current request.
 *
 * `cache()` deduplicates it across the layout and whichever tab is rendering,
 * so opening the signals tab is one query, not two. A version this organisation
 * has never analysed is a 404: it is not an error, and it is not another org's
 * verdict to show.
 */
export const loadReport = cache(
  async (ecosystem: Ecosystem, name: string, version: string): Promise<VersionReport> => {
    const ctx = await requireAuthContext();
    try {
      return await getVersionReport(ctx, ecosystem, name, version);
    } catch (error) {
      if (error instanceof NotFoundError) notFound();
      throw error;
    }
  },
);
