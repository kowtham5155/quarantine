import { createHash } from 'node:crypto';

import { AnalysisError, ExternalServiceError } from '@/lib/errors';
import { logger } from '@/lib/logger';
import { safeFetch, safeFetchJson } from '@/lib/net/fetcher';
import type { Maintainer, PackageMetadata, ReleaseRecord } from '@/lib/engine/types';

/**
 * registry.npmjs.org client.
 *
 * Every request goes through `safeFetch`, so even though these hostnames are
 * ours rather than the package's, the SSRF guard, timeout, redirect cap and
 * per-host rate limit all apply. The registry is the slowest dependency in the
 * system and is shared with everyone else on the internet, so responses are
 * cached in process for the lifetime of a request batch.
 */

const REGISTRY = 'https://registry.npmjs.org';
const DOWNLOADS_API = 'https://api.npmjs.org/downloads/point/last-week';

/** Tarballs get a larger ceiling than a metadata response. */
export const MAX_TARBALL_BYTES = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Caching
// ---------------------------------------------------------------------------

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

const CACHE_TTL_MS = 10 * 60 * 1000;
const packumentCache = new Map<string, CacheEntry<NpmPackument>>();
const downloadCache = new Map<string, CacheEntry<number | null>>();

function cacheGet<T>(store: Map<string, CacheEntry<T>>, key: string): T | undefined {
  const entry = store.get(key);
  if (!entry) return undefined;
  if (entry.expiresAt < Date.now()) {
    store.delete(key);
    return undefined;
  }
  return entry.value;
}

function cacheSet<T>(store: Map<string, CacheEntry<T>>, key: string, value: T): void {
  store.set(key, { value, expiresAt: Date.now() + CACHE_TTL_MS });
}

/** Test hook, and a way for a long-lived process to bound memory. */
export function clearRegistryCache(): void {
  packumentCache.clear();
  downloadCache.clear();
}

// ---------------------------------------------------------------------------
// Name validation
// ---------------------------------------------------------------------------

/**
 * npm's own name grammar, applied before the name is put in a URL.
 *
 * This is a path-injection guard as much as a validation: a name containing
 * `..` or a slash would otherwise let a caller address an arbitrary registry
 * path. `encodeURIComponent` handles the rest.
 */
const NPM_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;

export function isValidNpmName(name: string): boolean {
  if (typeof name !== 'string' || name.length === 0 || name.length > 214) return false;
  if (name.startsWith('.') || name.startsWith('_')) return false;
  return NPM_NAME.test(name);
}

/** Scoped names are encoded as `@scope%2Fname` in registry paths. */
function encodeName(name: string): string {
  return name.startsWith('@')
    ? `${encodeURIComponent(name.split('/')[0] ?? '')}%2F${encodeURIComponent(name.split('/')[1] ?? '')}`
    : encodeURIComponent(name);
}

/** Semver-ish, permissive enough for the tags real packages actually publish. */
export function isValidVersion(version: string): boolean {
  return (
    typeof version === 'string' &&
    version.length > 0 &&
    version.length <= 64 &&
    /^[0-9a-zA-Z.\-+]+$/.test(version)
  );
}

// ---------------------------------------------------------------------------
// Registry shapes
// ---------------------------------------------------------------------------

interface NpmDist {
  tarball?: string;
  integrity?: string;
  shasum?: string;
  attestations?: { provenance?: unknown };
}

interface NpmVersionDocument {
  name?: string;
  version?: string;
  description?: string;
  keywords?: unknown;
  license?: unknown;
  homepage?: unknown;
  repository?: unknown;
  scripts?: Record<string, unknown>;
  dependencies?: Record<string, unknown>;
  devDependencies?: Record<string, unknown>;
  maintainers?: unknown;
  dist?: NpmDist;
  _npmUser?: { name?: string };
  deprecated?: unknown;
}

interface NpmPackument {
  name?: string;
  'dist-tags'?: Record<string, string>;
  versions?: Record<string, NpmVersionDocument>;
  time?: Record<string, string>;
  maintainers?: unknown;
  description?: string;
  keywords?: unknown;
  repository?: unknown;
  homepage?: unknown;
}

// ---------------------------------------------------------------------------
// Coercion helpers — every field here is attacker-controlled
// ---------------------------------------------------------------------------

function asString(value: unknown, max = 2048): string | null {
  return typeof value === 'string' && value.length > 0 ? value.slice(0, max) : null;
}

function asStringArray(value: unknown, maxItems = 100, maxLength = 128): string[] {
  if (!Array.isArray(value)) return [];
  const out: string[] = [];
  for (const item of value) {
    if (typeof item === 'string' && item.length > 0) out.push(item.slice(0, maxLength));
    if (out.length >= maxItems) break;
  }
  return out;
}

function asStringRecord(value: unknown, maxKeys = 500): Record<string, string> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const out: Record<string, string> = {};
  let count = 0;
  for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
    if (count >= maxKeys) break;
    if (typeof raw === 'string') {
      out[key.slice(0, 128)] = raw.slice(0, 4096);
      count++;
    }
  }
  return out;
}

/** Normalise the several shapes npm accepts for `repository`. */
export function normaliseRepositoryUrl(value: unknown): string | null {
  const raw =
    typeof value === 'string'
      ? value
      : value && typeof value === 'object'
        ? asString((value as { url?: unknown }).url)
        : null;

  if (!raw) return null;

  let url = raw.trim();

  // `git+https://…`, `git://…`, `git+ssh://git@host/…`
  url = url.replace(/^git\+/, '');
  if (url.startsWith('git://')) url = `https://${url.slice('git://'.length)}`;
  if (url.startsWith('ssh://git@')) url = `https://${url.slice('ssh://git@'.length)}`;
  if (url.startsWith('git@')) url = `https://${url.slice('git@'.length).replace(':', '/')}`;

  // Bare `owner/repo` shorthand means GitHub.
  if (/^[\w.-]+\/[\w.-]+$/.test(url)) url = `https://github.com/${url}`;
  if (url.startsWith('github:')) url = `https://github.com/${url.slice('github:'.length)}`;

  url = url.replace(/\.git$/, '').replace(/\/+$/, '');

  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
    return parsed.toString();
  } catch {
    return null;
  }
}

function parseMaintainers(value: unknown): Maintainer[] {
  if (!Array.isArray(value)) return [];

  const out: Maintainer[] = [];
  for (const item of value.slice(0, 100)) {
    const name =
      typeof item === 'string'
        ? item.split('<')[0]?.trim()
        : asString((item as { name?: unknown })?.name, 128);

    if (name) {
      out.push({
        name,
        // npm's public API exposes neither account age nor package count.
        // Guessing them would fabricate evidence, so they stay null and the
        // rules that need them report NO_METADATA instead of firing.
        accountCreatedAt: null,
        packageCount: null,
        firstSeenAt: null,
      });
    }
  }
  return out;
}

function parseReleaseHistory(time: Record<string, string> | undefined): ReleaseRecord[] {
  if (!time) return [];

  const out: ReleaseRecord[] = [];
  for (const [version, stamp] of Object.entries(time)) {
    if (version === 'created' || version === 'modified') continue;
    const publishedAt = new Date(stamp);
    if (!Number.isNaN(publishedAt.getTime())) out.push({ version, publishedAt });
  }

  out.sort((a, b) => a.publishedAt.getTime() - b.publishedAt.getTime());
  return out;
}

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

/** The full packument: every version, every publish time, every maintainer. */
export async function fetchPackument(name: string): Promise<NpmPackument> {
  if (!isValidNpmName(name)) {
    throw new AnalysisError('INVALID_NAME', 'That is not a valid npm package name.');
  }

  const cached = cacheGet(packumentCache, name);
  if (cached) return cached;

  const document = await safeFetchJson<NpmPackument>(`${REGISTRY}/${encodeName(name)}`, {
    // The abbreviated packument omits `time`, which the maintainer family needs.
    accept: 'application/json',
  });

  cacheSet(packumentCache, name, document);
  return document;
}

/** Weekly downloads, or null. Never throws: this is a nice-to-have. */
export async function fetchWeeklyDownloads(name: string): Promise<number | null> {
  if (!isValidNpmName(name)) return null;

  const cached = cacheGet(downloadCache, name);
  if (cached !== undefined) return cached;

  try {
    const document = await safeFetchJson<{ downloads?: unknown }>(
      `${DOWNLOADS_API}/${encodeName(name)}`,
    );
    const downloads = typeof document.downloads === 'number' ? document.downloads : null;
    cacheSet(downloadCache, name, downloads);
    return downloads;
  } catch (error) {
    logger.debug({ err: error, name }, 'download count unavailable');
    cacheSet(downloadCache, name, null);
    return null;
  }
}

/** Assemble the engine's metadata view for one version. */
export async function fetchPackageMetadata(
  name: string,
  version: string,
): Promise<PackageMetadata> {
  if (!isValidVersion(version)) {
    throw new AnalysisError('INVALID_VERSION', 'That is not a valid version string.');
  }

  const packument = await fetchPackument(name);
  const versions = packument.versions ?? {};

  // A dist-tag such as `latest` is resolved to a concrete version.
  const resolved = versions[version] ? version : (packument['dist-tags']?.[version] ?? version);
  const document = versions[resolved];

  if (!document) {
    throw new AnalysisError('NO_SUCH_VERSION', 'That version was not found in the registry.');
  }

  const releaseHistory = parseReleaseHistory(packument.time);
  const published = packument.time?.[resolved];
  const publishedAt = published ? new Date(published) : null;

  const dist = document.dist ?? {};

  return {
    name,
    version: resolved,
    ecosystem: 'NPM',
    description: asString(document.description ?? packument.description, 4096),
    keywords: asStringArray(document.keywords ?? packument.keywords),
    license: asString(document.license, 128),
    repositoryUrl: normaliseRepositoryUrl(document.repository ?? packument.repository),
    homepage: asString(document.homepage ?? packument.homepage),
    scripts: asStringRecord(document.scripts),
    dependencies: asStringRecord(document.dependencies),
    maintainers: parseMaintainers(document.maintainers ?? packument.maintainers),
    publishedAt: publishedAt && !Number.isNaN(publishedAt.getTime()) ? publishedAt : null,
    releaseHistory,
    weeklyDownloads: await fetchWeeklyDownloads(name),
    // npm does not publish a reverse-dependency count through this API.
    dependentCount: null,
    tarballUrl: asString(dist.tarball),
    integrity: asString(dist.integrity ?? dist.shasum, 256),
    hasProvenanceAttestation: Boolean(dist.attestations?.provenance),
  };
}

export interface DownloadedTarball {
  bytes: Buffer;
  sha256: string;
  /** True when the registry-declared integrity matched what we downloaded. */
  integrityVerified: boolean;
}

/**
 * Download a tarball.
 *
 * The URL is checked to be on the registry's own host before it is fetched.
 * `dist.tarball` is attacker-controlled — a package can publish any URL it
 * likes there — and while `safeFetch` would already refuse a private address,
 * there is no reason to let a package redirect us to an arbitrary public host
 * either.
 */
export async function downloadTarball(
  tarballUrl: string,
  expectedIntegrity?: string | null,
): Promise<DownloadedTarball> {
  let parsed: URL;
  try {
    parsed = new URL(tarballUrl);
  } catch {
    throw new AnalysisError('BAD_TARBALL_URL', 'The registry returned an unusable tarball URL.');
  }

  if (parsed.hostname !== 'registry.npmjs.org' && !parsed.hostname.endsWith('.npmjs.org')) {
    throw new AnalysisError(
      'BAD_TARBALL_URL',
      'Refusing to download a tarball from outside the registry.',
    );
  }

  const response = await safeFetch(parsed.toString(), {
    accept: 'application/octet-stream',
    maxBytes: MAX_TARBALL_BYTES,
    timeoutMs: 30_000,
  });

  if (response.status !== 200) {
    throw new ExternalServiceError('registry.npmjs.org', `Tarball request returned ${response.status}.`);
  }

  const sha256 = createHash('sha256').update(response.body).digest('hex');

  return {
    bytes: response.body,
    sha256,
    integrityVerified: verifyIntegrity(response.body, expectedIntegrity),
  };
}

/**
 * Check a `dist.integrity` (SRI) or legacy `dist.shasum` value.
 *
 * A mismatch is reported rather than thrown: it is evidence about the package,
 * not a transport failure, and the provenance family wants to know about it.
 */
export function verifyIntegrity(bytes: Buffer, expected?: string | null): boolean {
  if (!expected) return false;

  if (expected.includes('-')) {
    const [algorithm, digest] = expected.split('-', 2);
    if (!algorithm || !digest) return false;
    if (!['sha1', 'sha256', 'sha512'].includes(algorithm)) return false;
    return createHash(algorithm).update(bytes).digest('base64') === digest;
  }

  // Legacy shasum: hex sha1.
  if (/^[a-f0-9]{40}$/i.test(expected)) {
    return createHash('sha1').update(bytes).digest('hex') === expected.toLowerCase();
  }

  return false;
}
