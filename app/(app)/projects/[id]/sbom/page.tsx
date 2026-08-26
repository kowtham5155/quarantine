import type { Metadata } from 'next';

import { CodeViewer } from '@/components/shared/CodeViewer';
import { CopyButton } from '@/components/shared/CopyButton';
import { EmptyState } from '@/components/shared/EmptyState';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { requireAuthContext } from '@/lib/auth-context';
import * as projectService from '@/lib/services/project.service';

import { readProjectId } from '../project';
import { SbomDownload } from './SbomDownload';

export const metadata: Metadata = { title: 'SBOM' };

interface PageProps {
  params: Promise<{ id: string }>;
}

/** `checkout-api` -> `checkout-api.cdx.json`, with nothing path-shaped left in it. */
function sbomFilename(name: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
  return `${slug || 'project'}.cdx.json`;
}

export default async function ProjectSbomPage({ params }: PageProps) {
  const projectId = await readProjectId(params);
  const ctx = await requireAuthContext();

  const { project, document } = await projectService.buildSbom(ctx, projectId);
  const json = JSON.stringify(document, null, 2);

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="space-y-1.5">
            <CardTitle className="text-base">CycloneDX 1.5</CardTitle>
            <CardDescription>
              {document.components.length.toLocaleString('en-GB')} components. Each carries its purl
              and, under a <code className="font-mono text-xs">quarantine:</code> property
              namespace, the verdict, depth and whether this organisation is holding it — so a
              consumer that has never heard of this tool still gets a valid SBOM.
            </CardDescription>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <CopyButton value={json} label="Copy the SBOM" size="sm" />
            <SbomDownload json={json} filename={sbomFilename(project.name)} />
          </div>
        </CardHeader>
        <CardContent>
          {document.components.length === 0 ? (
            <EmptyState
              size="sm"
              title="Nothing to export yet"
              description="Import a lockfile from the tree tab and its components appear here."
            />
          ) : (
            <CodeViewer
              code={json}
              filename={sbomFilename(project.name)}
              language="json"
              maxLines={600}
              showCopy={false}
            />
          )}
        </CardContent>
      </Card>

      <p className="text-xs text-muted-foreground">
        The serial number is derived from the project id, so exporting the same project twice
        produces documents that diff cleanly. The timestamp in{' '}
        <code className="font-mono">metadata</code> is the only field that moves.
      </p>
    </div>
  );
}
