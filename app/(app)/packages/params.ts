import { notFound } from 'next/navigation';
import type { Ecosystem } from '@prisma/client';

import { decodeSegment, parseEcosystemSlug } from '@/lib/routes';

/**
 * Read and validate the package route parameters.
 *
 * The name segment is percent-encoded so that `@scope/name` stays inside one
 * segment; it is decoded here and treated as hostile input from that point on.
 * An ecosystem slug that names no registry is a 404 rather than an error page —
 * there is nothing to fix by retrying.
 */

export interface PackageParams {
  ecosystem: Ecosystem;
  name: string;
}

export interface VersionParams extends PackageParams {
  version: string;
}

const MAX_NAME = 214;
const MAX_VERSION = 64;

export async function readPackageParams(
  params: Promise<{ eco: string; name: string }>,
): Promise<PackageParams> {
  const { eco, name } = await params;

  const ecosystem = parseEcosystemSlug(eco);
  if (!ecosystem) notFound();

  const decoded = decodeSegment(name);
  if (decoded.length === 0 || decoded.length > MAX_NAME) notFound();

  return { ecosystem, name: decoded };
}

export async function readVersionParams(
  params: Promise<{ eco: string; name: string; version: string }>,
): Promise<VersionParams> {
  const { eco, name, version } = await params;
  const base = await readPackageParams(Promise.resolve({ eco, name }));

  const decodedVersion = decodeSegment(version);
  if (decodedVersion.length === 0 || decodedVersion.length > MAX_VERSION) notFound();

  return { ...base, version: decodedVersion };
}
