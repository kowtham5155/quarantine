import type { Metadata } from 'next';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

import { loadDependencies, readProjectId } from '../project';
import { DependenciesTable } from './DependenciesTable';

export const metadata: Metadata = { title: 'Dependencies' };

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function ProjectDependenciesPage({ params }: PageProps) {
  const rows = await loadDependencies(await readProjectId(params));

  const direct = rows.filter((row) => row.isDirect).length;
  const deepest = rows.reduce((max, row) => Math.max(max, row.depth), 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Every dependency, flattened</CardTitle>
        <CardDescription>
          {rows.length.toLocaleString('en-GB')} packages · {direct.toLocaleString('en-GB')} direct ·
          deepest path {deepest} {deepest === 1 ? 'level' : 'levels'} down. A transitive dependency
          runs the same install scripts as one you chose.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <DependenciesTable rows={rows} />
      </CardContent>
    </Card>
  );
}
