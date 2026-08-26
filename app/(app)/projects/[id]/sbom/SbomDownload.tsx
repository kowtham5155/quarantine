'use client';

import { useEffect, useRef, useState } from 'react';
import { Download } from 'lucide-react';

import { Button } from '@/components/ui/button';

export interface SbomDownloadProps {
  json: string;
  filename: string;
}

/**
 * Save the SBOM as a file.
 *
 * The document is already on the page, so the download is built from it in the
 * browser rather than re-querying the graph. The object URL is revoked when the
 * component unmounts — leaving one alive pins the whole string in memory for
 * the lifetime of the document.
 */
export function SbomDownload({ json, filename }: SbomDownloadProps) {
  const [href, setHref] = useState<string | null>(null);
  const urlRef = useRef<string | null>(null);

  useEffect(() => {
    const url = URL.createObjectURL(new Blob([json], { type: 'application/vnd.cyclonedx+json' }));
    urlRef.current = url;
    setHref(url);

    return () => {
      URL.revokeObjectURL(url);
      urlRef.current = null;
    };
  }, [json]);

  return (
    <Button asChild={href !== null} disabled={href === null}>
      {href === null ? (
        <>
          <Download aria-hidden="true" />
          Preparing…
        </>
      ) : (
        <a href={href} download={filename}>
          <Download aria-hidden="true" />
          Download JSON
        </a>
      )}
    </Button>
  );
}
