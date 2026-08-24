import { createHash } from 'node:crypto';

import { AnalysisError, ExternalServiceError } from '@/lib/errors';
import { logger } from '@/lib/logger';
import { safeFetch, safeFetchJson } from '@/lib/net/fetcher';
import { normaliseRepositoryUrl } from '@/lib/engine/registry/npm';
import type { Maintainer, PackageMetadata, ReleaseRecord } from '@/lib/engine/types';

/**
 * pypi.org client, mirroring the npm one.
 *
 * PyPI differs from npm in ways that matter to the engine:
 *
 * - There are no lifecycle scripts in metadata. Install-time execution lives in
 *   `setup.py`, which runs on install for an sdist. The install family looks at
 *   the file, not at a `scripts` block.
 * - There is no public download-count API. `pypistats.org` exists but is a
 *   third party; rather than depend on it, downloads stay null and the rules
 *   that need them report NO_DOWNLOAD_DATA.
 * - A release has several files (wheels per platform, plus an sdist). The
 *   engine analyses the sdist when there is one, because a wheel contains no
 *   build script and provenance comparison against source is the point.
 */

const PYPI = 'https://pypi.org/pypi';

export const MAX_SDIST_BYTES = 64 * 1024 * 1024;

/**
 * PEP 508 name grammar. Also a path-injection guard: this string ends up in a
 * URL path, and a name with a slash or `..` in it would address something else.
 */
const PYPI_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;

export function isValidPypiName(name: string): boolean {
  return typeof name === 'string' && name.length > 0 && name.length <= 214 && PYPI_NAME.test(name);
}

/** PEP 503 normalisation: runs of `-_.` collapse to a single `-`, lowercased. */
export function normalisePypiName(name: string): string {
  return name.replace(/[-_.]+/g, '-').toLowerCase();
}

interface PypiFile {
  filename?: string;
  url?: string;
  packagetype?: string;
  digests?: { sha256?: string; md5?: string };
  upload_time_iso_8601?: string;
  size?: number;
  yanked?: boolean;
}

interface PypiInfo {
  name?: string;
  version?: string;
  summary?: string;
  description?: string;
  keywords?: unknown;
  license?: unknown;
  home_page?: unknown;
  project_url?: unknown;
  project_urls?: Record<string, unknown>;
  author?: unknown;
  maintainer?: unknown;
  requires_dist?: unknown;
}

interface PypiDocument {
  info?: PypiInfo;
  releases?: Record<string, PypiFile[]>;
  urls?: PypiFile[];
}

function asString(value: unknown, max = 2048): string | null {
  return typeof value === 'string' && value.length > 0 ? value.slice(0, max) : null;
}

/** PyPI keywords are a comma- or space-separated string, not an array. */
function parseKeywords(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === 'string').slice(0, 100);
  }
  if (typeof value !== 'string') return [];
  return value
    .split(/[,\s]+/)
    .map((keyword) => keyword.trim())
    .filter((keyword) => keyword.length > 0)
    .slice(0, 100);
}

/** Find a repository among `project_urls`, which is a free-form label map. */
function findRepositoryUrl(info: PypiInfo): string | null {
  const candidates = info.project_urls ?? {};
  const preferred = ['source', 'source code', 'repository', 'code', 'github', 'homepage'];

  for (const label of preferred) {
    for (const [key, value] of Object.entries(candidates)) {
      if (key.toLowerCase() === label) {
        const url = normaliseRepositoryUrl(value);
        if (url) return url;
      }
    }
  }

  for (const value of Object.values(candidates)) {
    const url = normaliseRepositoryUrl(value);
    if (url && /github\.com|gitlab\.com|bitbucket\.org/.test(url)) return url;
  }

  return normaliseRepositoryUrl(info.home_page ?? info.project_url);
}

function parseMaintainers(info: PypiInfo): Maintainer[] {
  const names = new Set<string>();
  for (const value of [info.author, info.maintainer]) {
    const name = asString(value, 128);
    if (name) {
      for (const part of name.split(',')) {
        const trimmed = part.split('<')[0]?.trim();
        if (trimmed) names.add(trimmed);
      }
    }
  }

  return [...names].slice(0, 50).map((name) => ({
    name,
    accountCreatedAt: null,
    packageCount: null,
    firstSeenAt: null,
  }));
}

function parseReleaseHistory(releases: Record<string, PypiFile[]> | undefined): ReleaseRecord[] {
  if (!releases) return [];

  const out: ReleaseRecord[] = [];
  for (const [version, files] of Object.entries(releases)) {
    // A release's timestamp is the earliest upload among its files.
    let earliest: Date | null = null;
    for (const file of files ?? []) {
      const stamp = file.upload_time_iso_8601;
      if (!stamp) continue;
      const at = new Date(stamp);
      if (Number.isNaN(at.getTime())) continue;
      if (!earliest || at < earliest) earliest = at;
    }
    if (earliest) out.push({ version, publishedAt: earliest });
  }

  out.sort((a, b) => a.publishedAt.getTime() - b.publishedAt.getTime());
  return out;
}

export async function fetchPypiDocument(name: string): Promise<PypiDocument> {
  if (!isValidPypiName(name)) {
    throw new AnalysisError('INVALID_NAME', 'That is not a valid PyPI package name.');
  }
  return safeFetchJson<PypiDocument>(`${PYPI}/${encodeURIComponent(name)}/json`);
}

export async function fetchPackageMetadata(
  name: string,
  version: string,
): Promise<PackageMetadata> {
  if (!isValidPypiName(name)) {
    throw new AnalysisError('INVALID_NAME', 'That is not a valid PyPI package name.');
  }
  if (!/^[0-9a-zA-Z.\-+!]+$/.test(version) || version.length > 64) {
    throw new AnalysisError('INVALID_VERSION', 'That is not a valid version string.');
  }

  const document = await safeFetchJson<PypiDocument>(
    `${PYPI}/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`,
  );

  const info = document.info ?? {};
  const files = document.urls ?? [];
  const sdist = selectSdist(files);

  const publishedAt = sdist?.upload_time_iso_8601 ? new Date(sdist.upload_time_iso_8601) : null;

  // The per-version document omits the full release history, so fetch the
  // package-level one for it. Failure degrades to an empty history rather than
  // failing the analysis.
  let releaseHistory: ReleaseRecord[] = [];
  try {
    const full = await fetchPypiDocument(name);
    releaseHistory = parseReleaseHistory(full.releases);
  } catch (error) {
    logger.debug({ err: error, name }, 'PyPI release history unavailable');
  }

  return {
    name,
    version,
    ecosystem: 'PYPI',
    description: asString(info.summary ?? info.description, 4096),
    keywords: parseKeywords(info.keywords),
    license: asString(info.license, 128),
    repositoryUrl: findRepositoryUrl(info),
    homepage: asString(info.home_page),
    // PyPI has no scripts block. `setup.py` is inspected as a file instead.
    scripts: {},
    dependencies: {},
    maintainers: parseMaintainers(info),
    publishedAt: publishedAt && !Number.isNaN(publishedAt.getTime()) ? publishedAt : null,
    releaseHistory,
    // No first-party download API; see the module comment.
    weeklyDownloads: null,
    dependentCount: null,
    tarballUrl: sdist?.url ?? null,
    integrity: sdist?.digests?.sha256 ? `sha256-hex:${sdist.digests.sha256}` : null,
    // PyPI supports attestations, but not through this endpoint.
    hasProvenanceAttestation: false,
  };
}

/** Prefer the source distribution: a wheel has no build script to inspect. */
export function selectSdist(files: PypiFile[]): PypiFile | null {
  const sdist = files.find(
    (file) => file.packagetype === 'sdist' && file.filename?.endsWith('.tar.gz'),
  );
  if (sdist) return sdist;

  return files.find((file) => file.filename?.endsWith('.tar.gz')) ?? null;
}

export interface DownloadedSdist {
  bytes: Buffer;
  sha256: string;
  integrityVerified: boolean;
}

export async function downloadSdist(
  url: string,
  expectedSha256?: string | null,
): Promise<DownloadedSdist> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new AnalysisError('BAD_TARBALL_URL', 'PyPI returned an unusable file URL.');
  }

  // PyPI serves files from files.pythonhosted.org. Anything else is refused,
  // for the same reason as npm: the URL comes from package metadata.
  if (parsed.hostname !== 'files.pythonhosted.org' && !parsed.hostname.endsWith('.pypi.org')) {
    throw new AnalysisError(
      'BAD_TARBALL_URL',
      'Refusing to download a distribution from outside PyPI.',
    );
  }

  const response = await safeFetch(parsed.toString(), {
    accept: 'application/octet-stream',
    maxBytes: MAX_SDIST_BYTES,
    timeoutMs: 30_000,
  });

  if (response.status !== 200) {
    throw new ExternalServiceError(
      'files.pythonhosted.org',
      `Distribution request returned ${response.status}.`,
    );
  }

  const sha256 = createHash('sha256').update(response.body).digest('hex');
  const expected = expectedSha256?.replace(/^sha256-hex:/, '') ?? null;

  return {
    bytes: response.body,
    sha256,
    integrityVerified: expected !== null && expected.toLowerCase() === sha256,
  };
}
