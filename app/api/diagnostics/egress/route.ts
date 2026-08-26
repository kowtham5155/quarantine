import { isBlockedAddress, resolvePublicHost, safeFetch } from '@/lib/net/fetcher';
import { errorResponse, jsonResponse, requireCronSecret } from '@/lib/http';
import { loggerForRequest } from '@/lib/logger';
import { lookup as dnsLookup } from 'node:dns/promises';

/**
 * GET /api/diagnostics/egress — what this deployment can actually reach.
 *
 * TEMPORARY. This exists to answer one question after a deploy: does the
 * provenance check work from here, or is the SSRF guard refusing the git host
 * because of how this network resolves names? Delete it once that is settled.
 *
 * ## Why it is safe to expose at all
 *
 * The host list is fixed in this file. There is no `?host=` parameter, on
 * purpose: an authenticated endpoint that resolves and fetches an arbitrary
 * name is an SSRF oracle with a login page in front of it, and the guard this
 * route exists to test is precisely what stops that being interesting. It also
 * requires the same Bearer `CRON_SECRET` as the cron routes, compared in
 * constant time.
 *
 * ## What it reports
 *
 * For each host: every address the resolver returned, whether the guard would
 * refuse each one individually, and whether the host as a whole is accepted —
 * resolution is all-or-nothing, so one bad address refuses the name. Then a
 * live bounded GET against the GitHub API, because "the guard allows it" and
 * "the packets arrive" are different claims and only the second one matters.
 */

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

/** Fixed. Do not make this caller-supplied — see the note above. */
const HOSTS = [
  'api.github.com',
  'codeload.github.com',
  'github.com',
  'raw.githubusercontent.com',
  'registry.npmjs.org',
  'pypi.org',
] as const;

interface HostReport {
  host: string;
  addresses: Array<{ address: string; family: number; blocked: boolean }>;
  accepted: boolean;
  reason?: string;
}

async function reportHost(host: string): Promise<HostReport> {
  let addresses: HostReport['addresses'] = [];

  try {
    const records = await dnsLookup(host, { all: true, verbatim: true });
    addresses = records.map((record) => ({
      address: record.address,
      family: record.family,
      blocked: isBlockedAddress(record.address),
    }));
  } catch (error) {
    return {
      host,
      addresses: [],
      accepted: false,
      reason: `DNS lookup failed: ${(error as Error).message}`,
    };
  }

  try {
    await resolvePublicHost(host);
    return { host, addresses, accepted: true };
  } catch (error) {
    return { host, addresses, accepted: false, reason: (error as Error).message };
  }
}

export async function GET(request: Request): Promise<Response> {
  const { correlationId } = loggerForRequest(request.headers);

  try {
    requireCronSecret(request);

    const hosts = await Promise.all(HOSTS.map(reportHost));

    // A real request through the real fetcher. `/repos/{owner}/{repo}` is the
    // first call the provenance check makes, so if this works, that works.
    let apiProbe: Record<string, unknown>;
    try {
      const response = await safeFetch('https://api.github.com/repos/lodash/lodash', {
        accept: 'application/vnd.github+json',
        timeoutMs: 10_000,
        maxBytes: 256 * 1024,
      });
      apiProbe = {
        ok: response.status === 200,
        status: response.status,
        // Present when a GITHUB_TOKEN is configured and accepted; 60/hour without one.
        rateLimit: response.headers.get('x-ratelimit-limit'),
        rateLimitRemaining: response.headers.get('x-ratelimit-remaining'),
      };
    } catch (error) {
      apiProbe = { ok: false, error: (error as Error).message };
    }

    return jsonResponse({
      checkedAt: new Date().toISOString(),
      hosts,
      apiProbe,
      provenanceReachable:
        hosts.every((host) => host.host !== 'api.github.com' || host.accepted) &&
        hosts.every((host) => host.host !== 'codeload.github.com' || host.accepted) &&
        apiProbe.ok === true,
    });
  } catch (error) {
    return errorResponse(error, correlationId);
  }
}
