import type { Metadata } from 'next';
import Link from 'next/link';
import { Fingerprint, Radar } from 'lucide-react';

import { EmptyState } from '@/components/shared/EmptyState';
import { PackageRef } from '@/components/shared/PackageRef';
import { PageHeader } from '@/components/shared/PageHeader';
import { VerdictBadge } from '@/components/shared/VerdictBadge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { requireAuthContext } from '@/lib/auth-context';
import { TYPOSQUAT_MAX_DISTANCE } from '@/lib/engine/thresholds';
import { ecosystemSlug, packageHref, versionHref } from '@/lib/routes';
import { safeText } from '@/lib/safe-display';
import { getSimilarPackages } from '@/lib/services/package.service';

import { readPackageParams } from '../../../params';

interface PageProps {
  params: Promise<{ eco: string; name: string }>;
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const { name } = await readPackageParams(params);
  return { title: `Similar to ${safeText(name, { maxLength: 100 })}` };
}

/** Relative download share, the figure that separates a squat from a peer. */
function downloadRatio(candidate: number, target: number): string {
  if (target <= 0) return '—';
  const ratio = candidate / target;
  if (ratio >= 0.01) return `${(ratio * 100).toFixed(1)}%`;
  return `${(ratio * 100).toFixed(3)}%`;
}

export default async function SimilarPage({ params }: PageProps) {
  const ctx = await requireAuthContext();
  const { ecosystem, name } = await readPackageParams(params);
  const similar = await getSimilarPackages(ctx, ecosystem, name);

  return (
    <div className="space-y-8">
      <PageHeader
        breadcrumbs={[
          { label: 'Packages', href: '/packages' },
          { label: safeText(name, { maxLength: 40 }), href: packageHref(ecosystem, name) },
          { label: 'Similar' },
        ]}
        title="Typosquat neighbourhood"
        description={`Names within an edit distance of ${TYPOSQUAT_MAX_DISTANCE}, plus the techniques that produce them: homoglyph substitution, separator manipulation, scope confusion and combosquatting.`}
        actions={
          <Button asChild variant="outline">
            <Link href={packageHref(ecosystem, name)}>Back to package</Link>
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            Packages <span className="font-mono">{safeText(name, { maxLength: 60 })}</span>{' '}
            resembles
          </CardTitle>
          <CardDescription>
            Popular names this one is close to. Distance alone is not evidence — a legitimate
            package can sit one character from a famous one — which is why relative download share
            is shown beside it.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {similar.candidates.length === 0 ? (
            <EmptyState
              size="sm"
              icon={Fingerprint}
              title="No close neighbours"
              description="No package in the popularity corpus sits within the distance threshold of this name."
            />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Resembles</TableHead>
                    <TableHead>Technique</TableHead>
                    <TableHead className="text-right">Distance</TableHead>
                    <TableHead className="text-right">Similarity</TableHead>
                    <TableHead className="text-right">Target downloads</TableHead>
                    <TableHead className="text-right">This package&apos;s share</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {similar.candidates.map((candidate) => (
                    <TableRow key={candidate.targetPackage}>
                      <TableCell>
                        {candidate.analysedEcosystem ? (
                          <PackageRef
                            name={candidate.targetPackage}
                            ecosystem={ecosystemSlug(candidate.analysedEcosystem)}
                            href={packageHref(candidate.analysedEcosystem, candidate.targetPackage)}
                            hideEcosystem
                          />
                        ) : (
                          <span className="break-anywhere font-mono text-sm">
                            {safeText(candidate.targetPackage, { maxLength: 120 })}
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {safeText(candidate.technique, { maxLength: 80 })}
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">
                        {candidate.distance}
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">
                        {(candidate.similarity * 100).toFixed(0)}%
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">
                        {candidate.targetDownloads.toLocaleString('en-GB')}
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">
                        {downloadRatio(similar.weeklyDownloads, candidate.targetDownloads)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Packages that resemble this one</CardTitle>
          <CardDescription>
            Analysed packages whose names sit close to this one. On a popular package, this is the
            list of candidate impersonators.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {similar.impersonators.length === 0 ? (
            <EmptyState
              size="sm"
              icon={Radar}
              title="Nothing analysed here resembles it"
              description="No package this organisation has scanned was matched against this name."
            />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Package</TableHead>
                    <TableHead>Verdict</TableHead>
                    <TableHead>Technique</TableHead>
                    <TableHead className="text-right">Distance</TableHead>
                    <TableHead className="text-right">Weekly downloads</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {similar.impersonators.map((impersonator) => (
                    <TableRow key={`${impersonator.name}@${impersonator.version}`}>
                      <TableCell>
                        <PackageRef
                          name={impersonator.name}
                          version={impersonator.version}
                          ecosystem={ecosystemSlug(impersonator.ecosystem)}
                          href={versionHref(
                            impersonator.ecosystem,
                            impersonator.name,
                            impersonator.version,
                          )}
                          hideEcosystem
                        />
                      </TableCell>
                      <TableCell>
                        {impersonator.verdict ? (
                          <VerdictBadge verdict={impersonator.verdict} size="sm" />
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {safeText(impersonator.technique, { maxLength: 80 })}
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">
                        {impersonator.distance}
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">
                        {impersonator.weeklyDownloads.toLocaleString('en-GB')}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
