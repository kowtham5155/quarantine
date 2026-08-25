'use client';

import { useState } from 'react';
import { Play } from 'lucide-react';

import { Button } from '@/components/ui/button';

import { ScanRunner } from '../../scan/ScanRunner';
import type { QueuedScan } from '../../scan/scan-state';

/**
 * Run a queued or failed analysis from its own record page.
 *
 * The runner starts as soon as it mounts, so it is mounted on click rather than
 * on render — otherwise opening the page would start a scan nobody asked for.
 */
export function RunNow({ scan }: { scan: QueuedScan }) {
  const [started, setStarted] = useState(false);

  if (started) {
    return <ScanRunner scans={[scan]} />;
  }

  return (
    <Button onClick={() => setStarted(true)}>
      <Play aria-hidden="true" />
      Run this analysis
    </Button>
  );
}
