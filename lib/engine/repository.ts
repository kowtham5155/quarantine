import { logger } from '@/lib/logger';
import { safeFetch, safeFetchJson } from '@/lib/net/fetcher';
import { extractTarball, withScanDirectory } from '@/lib/engine/extract';
import { candidateTags, hashNormalised } from '@/lib/engine/signals/provenance';
import type { RepositorySnapshot } from '@/lib/engine/types';
import { readFile } from 'node:fs/promises';

/**
 * Fetch a source tree from a git host, for provenance comparison.
 *
 * Only GitHub is supported for now, because it is the only host whose tarball
 * endpoint is stable, unauthenticated and rate-limited generously enough to be
 * usable. GitLab and Bitbucket degrade to "unreachable", which the provenance
 * family reports honestly rather than treating as divergence.
 *
 * ## Safety
 *
 * The repository URL comes from package metadata and is therefore
 * attacker-controlled. It goes through `safeFetch` like everything else — SSRF
 * guard, pinned addresses, redirect cap, timeout — and the downloaded archive
 * goes through the same bounded, zip-slip-guarded extractor as the package
 * tarball. A repository archive is no more trusted than a package tarball.
 */

const GITHUB_API = 'https://api.github.com';

export interface RepositoryRef {
  host: string;
  owner: string;
  repo: string;
}

/** Parse a normalised repository URL into host, owner and repo. */
export function parseRepositoryUrl(url: string): RepositoryRef | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }

  const segments = parsed.pathname.split('/').filter(Boolean);
  const owner = segments[0];
  const repo = segments[1]?.replace(/\.git$/, '');

  if (!owner || !repo) return null;

  // Owner and repo end up in a URL path; reject anything that is not a plain
  // path segment so a crafted metadata field cannot address something else.
  if (!/^[\w.-]+$/.test(owner) || !/^[\w.-]+$/.test(repo)) return null;
  if (owner === '..' || repo === '..') return null;

  return { host: parsed.hostname, owner, repo };
}

interface GitHubRepo {
  archived?: boolean;
  default_branch?: string;
}

interface GitHubTag {
  name?: string;
}

/**
 * Resolve the tag for a version and download that tree.
 *
 * Returns null when the repository exists but no tag matches the version —
 * a distinct outcome from "the repository could not be read", which throws.
 * The provenance family treats the two differently and it matters that it can.
 */
export async function fetchRepositorySnapshot(
  repositoryUrl: string,
  version: string,
  budgetMs: number,
): Promise<RepositorySnapshot | null> {
  if (budgetMs <= 0) return null;

  const ref = parseRepositoryUrl(repositoryUrl);
  if (!ref) return null;

  // Only GitHub for now; everything else reports as unreachable.
  if (ref.host !== 'github.com' && ref.host !== 'www.github.com') {
    logger.debug({ host: ref.host }, 'provenance: unsupported git host');
    return null;
  }

  const deadline = Date.now() + budgetMs;
  const remaining = (): number => Math.max(0, deadline - Date.now());

  const repository = await safeFetchJson<GitHubRepo>(
    `${GITHUB_API}/repos/${ref.owner}/${ref.repo}`,
    { accept: 'application/vnd.github+json', timeoutMs: Math.min(10_000, remaining()) },
  );

  const archived = repository.archived === true;

  const tag = await resolveTag(ref, version, remaining());
  if (!tag) {
    logger.debug({ owner: ref.owner, repo: ref.repo, version }, 'provenance: no matching tag');
    return null;
  }

  if (remaining() <= 0) return null;

  // The codeload tarball endpoint is the cheapest way to get a whole tree.
  const archive = await safeFetch(
    `https://codeload.github.com/${ref.owner}/${ref.repo}/tar.gz/refs/tags/${encodeURIComponent(tag)}`,
    {
      accept: 'application/octet-stream',
      maxBytes: 64 * 1024 * 1024,
      timeoutMs: Math.min(25_000, remaining()),
    },
  );

  if (archive.status !== 200) return null;

  // Extracted through the same bounded, guarded extractor as a package tarball.
  return withScanDirectory(async (root) => {
    const extraction = await extractTarball(archive.body, root);

    const files: Array<{ path: string; content: Buffer }> = [];
    for (const file of extraction.files) {
      if (file.isBinary) {
        // Binary content is compared by raw hash; no normalisation applies.
        files.push({ path: file.path, content: Buffer.alloc(0) });
        continue;
      }
      try {
        files.push({ path: file.path, content: await readFile(file.absolutePath) });
      } catch {
        // Unreadable file: omit rather than guess.
      }
    }

    const map = new Map<string, string>();
    for (const file of files) map.set(file.path, hashNormalised(file.content));

    return {
      host: ref.host,
      owner: ref.owner,
      repo: ref.repo,
      tag,
      files: map,
      archived,
    };
  });
}

/**
 * Find the tag that corresponds to a version.
 *
 * Tries the common conventions in order, then falls back to listing the
 * repository's tags and matching by normalised version. Monorepos frequently
 * use `package-name@1.2.3`, which no naming convention would have guessed.
 */
async function resolveTag(
  ref: RepositoryRef,
  version: string,
  budgetMs: number,
): Promise<string | null> {
  if (budgetMs <= 0) return null;

  const deadline = Date.now() + budgetMs;
  const bare = version.replace(/^v/, '');

  try {
    const tags = await safeFetchJson<GitHubTag[]>(
      `${GITHUB_API}/repos/${ref.owner}/${ref.repo}/tags?per_page=100`,
      {
        accept: 'application/vnd.github+json',
        timeoutMs: Math.min(10_000, Math.max(0, deadline - Date.now())),
      },
    );

    const names = tags.map((tag) => tag.name).filter((name): name is string => Boolean(name));

    // Exact conventional matches first.
    for (const candidate of candidateTags(version)) {
      if (names.includes(candidate)) return candidate;
    }

    // Monorepo style: anything ending in the version.
    const suffixMatch = names.find(
      (name) => name.endsWith(`@${bare}`) || name.endsWith(`-${bare}`) || name.endsWith(`/${bare}`),
    );
    if (suffixMatch) return suffixMatch;

    return null;
  } catch (error) {
    logger.debug({ err: error, owner: ref.owner, repo: ref.repo }, 'provenance: tag listing failed');
    return null;
  }
}
