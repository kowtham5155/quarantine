import { FileSearch } from 'lucide-react';

import { EmptyState } from '@/components/shared/EmptyState';
import { fileInventory } from '@/lib/services/package.service';

import { readVersionParams } from '../../../../params';
import { loadReport } from '../report';
import { FileExplorer } from './FileExplorer';

interface PageProps {
  params: Promise<{ eco: string; name: string; version: string }>;
}

export default async function FilesPage({ params }: PageProps) {
  const { ecosystem, name, version } = await readVersionParams(params);
  const report = await loadReport(ecosystem, name, version);

  const files = fileInventory(report.hits);

  return (
    <div className="space-y-6">
      <div className="max-w-3xl space-y-1">
        <h2 className="text-lg font-semibold tracking-tight">Flagged files</h2>
        <p className="text-sm text-muted-foreground">
          The archive held {report.version.fileCount ?? 'an unrecorded number of'} files;{' '}
          {files.length} of them have evidence attached. Quarantine does not retain package contents
          — the extraction directory is deleted before the analysis returns — so what is shown here
          is the evidence each rule recorded, not the file as published.
        </p>
      </div>

      {files.length === 0 ? (
        <EmptyState
          icon={FileSearch}
          title="No file was flagged"
          description="No rule attached evidence to a file in this artefact. Signals that matched on metadata alone are on the signals tab."
        />
      ) : (
        <FileExplorer files={files} />
      )}
    </div>
  );
}
