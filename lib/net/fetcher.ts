import { isIP } from 'node:net';
import { lookup as dnsLookup } from 'node:dns/promises';
import type { LookupFunction } from 'node:net';
import { Agent, fetch as undiciFetch, type Response as UndiciResponse } from 'undici';

import { ExternalServiceError } from '@/lib/errors';
import { logger } from '@/lib/logger';

/**
 * The single outbound HTTP path for the whole application (CLAUDE.md rule 6).
 *
 * Nothing else may call `fetch` against a URL that came from package metadata.
 * Repository URLs, homepages and tarball locations are all attacker-controlled,
 * and an attacker who can choose a URL we will fetch server-side can reach the
 * cloud metadata endpoint, the loopback interface, and anything else on the
 * deployment's private network.
 *
 * ## The TOCTOU problem, and why this pins addresses
 *
 * The obvious implementation — resolve the hostname, check the address, then
 * call `fetch(url)` — is not safe. Between the check and the connection the
 * name is resolved a *second* time by the HTTP stack, and an attacker
 * controlling the authoritative nameserver can return a public address to the
 * first query and 169.254.169.254 to the second. This is DNS rebinding, and it
 * defeats every "resolve then validate" guard.
 *
 * The fix is to make the validated address the one that is actually connected
 * to. `pinnedLookup` below hands the agent the exact addresses this module
 * already vetted, so the connection cannot land anywhere else. Redirects are
 * followed manually, and each hop repeats the whole check.
 */

export const FETCH_TIMEOUT_MS = 10_000;
export const MAX_REDIRECTS = 3;
export const USER_AGENT = 'Quarantine/1.0 (+https://quarantine.dev/security)';

/** Response bodies larger than this are refused. Tarballs use a larger cap. */
export const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

/** Per-host rate limit: at most this many requests inside the window. */
export const HOST_RATE_LIMIT = 20;
export const HOST_RATE_WINDOW_MS = 10_000;

// ---------------------------------------------------------------------------
// Address validation
// ---------------------------------------------------------------------------

/**
 * IPv4 ranges that must never be connected to. RFC1918 private space, loopback,
 * link-local (which is where every cloud metadata service lives), and the
 * various reserved blocks that can be coerced into routing somewhere useful.
 */
const BLOCKED_IPV4: Array<[string, number]> = [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8], // RFC1918
  ['100.64.0.0', 10], // carrier-grade NAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local — cloud metadata
  ['172.16.0.0', 12], // RFC1918
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.168.0.0', 16], // RFC1918
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24], // TEST-NET-3
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved, includes 255.255.255.255
];

function ipv4ToInt(address: string): number | null {
  const octets = address.split('.');
  if (octets.length !== 4) return null;

  let value = 0;
  for (const octet of octets) {
    if (!/^\d{1,3}$/.test(octet)) return null;
    const part = Number(octet);
    if (part > 255) return null;
    value = value * 256 + part;
  }
  return value;
}

function isBlockedIpv4(address: string): boolean {
  const value = ipv4ToInt(address);
  if (value === null) return true; // unparseable is not proven safe

  for (const [network, bits] of BLOCKED_IPV4) {
    const base = ipv4ToInt(network);
    if (base === null) continue;
    // >>> 0 keeps the mask unsigned; a /0 would shift by 32 and be a no-op.
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    if ((value & mask) >>> 0 === (base & mask) >>> 0) return true;
  }
  return false;
}

/** The eight 16-bit groups of an IPv6 address, or null if it will not parse. */
function ipv6Groups(address: string): number[] | null {
  const [head = '', tail] = address.split('::');
  if (tail !== undefined && address.split('::').length > 2) return null;

  const parse = (part: string): number[] | null => {
    if (part === '') return [];
    const out: number[] = [];
    for (const group of part.split(':')) {
      if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
      out.push(Number.parseInt(group, 16));
    }
    return out;
  };

  const left = parse(head);
  const right = tail === undefined ? [] : parse(tail);
  if (left === null || right === null) return null;

  if (tail === undefined) return left.length === 8 ? left : null;

  const missing = 8 - left.length - right.length;
  if (missing < 0) return null;
  return [...left, ...Array.from({ length: missing }, () => 0), ...right];
}

/** Dotted-quad for a 32-bit value carried in two IPv6 groups. */
function ipv4FromGroups(high: number, low: number): string {
  return [high >> 8, high & 0xff, low >> 8, low & 0xff].join('.');
}

/**
 * An IPv4 address embedded in an IPv6 one, for the transition mechanisms that
 * carry one inside the other. Returns null when this address embeds nothing.
 *
 * These are decoded rather than blanket-blocked. Blocking the whole prefix is
 * safe but wrong in a way that matters: a DNS64 resolver — which is what a
 * NAT64-only network gives you, and what this repository's own sandbox runs —
 * synthesises `64:ff9b::` records for *every* name, including GitHub's. Refuse
 * the prefix outright and every git host on the internet becomes unreachable,
 * which is how the provenance check ended up looking broken. Decoding gives the
 * real answer: `64:ff9b::14cf:4955` is GitHub at 20.207.73.85 and is allowed,
 * while `64:ff9b::a9fe:a9fe` is the cloud metadata service at 169.254.169.254
 * and is still refused, by the same IPv4 rules as everything else.
 */
function embeddedIpv4(normalised: string): string | null {
  // ::ffff:127.0.0.1 and ::127.0.0.1 spell the v4 address out.
  const dotted = /^::(?:ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/.exec(normalised);
  if (dotted?.[1]) return dotted[1];

  const groups = ipv6Groups(normalised);
  if (!groups) return null;

  // ::ffff:0:0/96 — IPv4-mapped, written in hex.
  if (
    groups[0] === 0 &&
    groups[1] === 0 &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0xffff
  ) {
    return ipv4FromGroups(groups[6] ?? 0, groups[7] ?? 0);
  }

  // 64:ff9b::/96 — the well-known NAT64 prefix (RFC 6052).
  if (groups[0] === 0x64 && groups[1] === 0xff9b && groups.slice(2, 6).every((g) => g === 0)) {
    return ipv4FromGroups(groups[6] ?? 0, groups[7] ?? 0);
  }

  // 2002::/16 — 6to4 carries the v4 address in the next 32 bits.
  if (groups[0] === 0x2002) return ipv4FromGroups(groups[1] ?? 0, groups[2] ?? 0);

  return null;
}

function isBlockedIpv6(address: string): boolean {
  const normalised = address.toLowerCase().split('%')[0] ?? '';

  // An address that carries an IPv4 one is exactly as safe as the address
  // inside it — ::ffff:127.0.0.1 reaches loopback just fine.
  const embedded = embeddedIpv4(normalised);
  if (embedded !== null) return isBlockedIpv4(embedded);

  if (normalised === '::' || normalised === '::1') return true; // unspecified, loopback
  if (normalised.startsWith('fe80')) return true; // link-local
  if (/^f[cd]/.test(normalised)) return true; // fc00::/7 unique local
  if (normalised.startsWith('ff')) return true; // multicast

  return false;
}

/** True when connecting to this address would reach private or reserved space. */
export function isBlockedAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return isBlockedIpv4(address);
  if (family === 6) return isBlockedIpv6(address);
  return true; // not an IP literal at all
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

export interface ResolvedHost {
  hostname: string;
  /** Every address the name resolved to. All of them passed validation. */
  addresses: Array<{ address: string; family: 4 | 6 }>;
}

/**
 * Resolve a hostname and reject it unless **every** address it returned is
 * public.
 *
 * All-or-nothing on purpose. A name that resolves to one public address and one
 * private one is a rebinding attempt dressed up as a multi-homed host, and
 * there is no legitimate reason for a package registry or a git host to look
 * like that.
 */
export async function resolvePublicHost(hostname: string): Promise<ResolvedHost> {
  // `URL.hostname` keeps the brackets on an IPv6 literal (`[::1]`), and `isIP`
  // does not accept them. Stripping them first is what stops a bracketed
  // literal from falling through to the DNS path unchecked.
  const literal =
    hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;

  const literalFamily = isIP(literal);
  if (literalFamily !== 0) {
    if (isBlockedAddress(literal)) {
      throw new ExternalServiceError('fetcher', 'Refusing to connect to a private address.');
    }
    return {
      hostname,
      addresses: [{ address: literal, family: literalFamily === 4 ? 4 : 6 }],
    };
  }

  let records: Array<{ address: string; family: number }>;
  try {
    records = await dnsLookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new ExternalServiceError('fetcher', 'Could not resolve that host.');
  }

  if (records.length === 0) {
    throw new ExternalServiceError('fetcher', 'Could not resolve that host.');
  }

  for (const record of records) {
    if (isBlockedAddress(record.address)) {
      logger.warn({ hostname, address: record.address }, 'SSRF guard rejected a resolved address');
      throw new ExternalServiceError('fetcher', 'Refusing to connect to a private address.');
    }
  }

  return {
    hostname,
    addresses: records.map((record) => ({
      address: record.address,
      family: record.family === 4 ? 4 : 6,
    })),
  };
}

/**
 * A `lookup` implementation that returns only the addresses already validated
 * above, so the socket cannot resolve the name a second time and land somewhere
 * else. This is what closes the rebinding window.
 */
function pinnedLookup(resolved: ResolvedHost): LookupFunction {
  return ((hostname, options, callback) => {
    const done = typeof options === 'function' ? options : callback;
    if (typeof done !== 'function') return;

    // Defence in depth: if the stack asks for a name we did not vet, refuse.
    if (hostname !== resolved.hostname) {
      done(new Error('Unexpected hostname during connection'), '', 0);
      return;
    }

    const wantsAll = typeof options === 'object' && options !== null && options.all === true;
    if (wantsAll) {
      (done as (err: NodeJS.ErrnoException | null, addresses: unknown) => void)(
        null,
        resolved.addresses,
      );
      return;
    }

    const first = resolved.addresses[0];
    if (!first) {
      done(new Error('No validated address available'), '', 0);
      return;
    }
    done(null, first.address, first.family);
  }) as LookupFunction;
}

// ---------------------------------------------------------------------------
// Per-host rate limiting
// ---------------------------------------------------------------------------

const hostWindows = new Map<string, number[]>();

/** In-process sliding window. The registry is shared; do not hammer it. */
function checkHostRate(hostname: string): void {
  const now = Date.now();
  const cutoff = now - HOST_RATE_WINDOW_MS;

  const recent = (hostWindows.get(hostname) ?? []).filter((at) => at > cutoff);
  if (recent.length >= HOST_RATE_LIMIT) {
    throw new ExternalServiceError(
      hostname,
      'Rate limit for this host reached. Try again shortly.',
    );
  }

  recent.push(now);
  hostWindows.set(hostname, recent);
}

/** Test hook: forget every recorded request. */
export function resetHostRateLimits(): void {
  hostWindows.clear();
}

// ---------------------------------------------------------------------------
// The guarded fetch
// ---------------------------------------------------------------------------

export interface SafeFetchOptions {
  /**
   * Request method. POST exists for outbound webhook delivery, which is the
   * only thing this application sends rather than fetches; a POST is still
   * subject to every guard, including re-validating each redirect hop.
   */
  method?: 'GET' | 'POST';
  /** Request body, for POST. Sent as `application/json` unless overridden. */
  body?: string;
  /** Response header accept value. Defaults to JSON. */
  accept?: string;
  /** Cap on the response body. Defaults to MAX_RESPONSE_BYTES. */
  maxBytes?: number;
  timeoutMs?: number;
  /** Extra request headers. `host` and `user-agent` cannot be overridden. */
  headers?: Record<string, string>;
}

export interface SafeResponse {
  status: number;
  /**
   * Response headers. Typed as the read interface rather than the DOM `Headers`
   * class, because the value comes from undici's fetch and only ever needs to be
   * read — see the note on the dispatcher in `safeFetch`.
   */
  headers: Pick<Headers, 'get'>;
  body: Buffer;
  /** The URL actually fetched, after redirects. */
  finalUrl: string;
}

function assertHttpUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ExternalServiceError('fetcher', 'That URL is not valid.');
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new ExternalServiceError('fetcher', 'Only http and https URLs can be fetched.');
  }

  // Credentials in a URL are a redirect-laundering trick and are never needed.
  if (url.username || url.password) {
    throw new ExternalServiceError('fetcher', 'URLs with embedded credentials are refused.');
  }

  return url;
}

/**
 * Fetch a URL with the full guard applied: public-address-only DNS, pinned
 * connection, fixed User-Agent, bounded time, bounded body, bounded redirects,
 * per-host rate limit.
 */
export async function safeFetch(
  rawUrl: string,
  options: SafeFetchOptions = {},
): Promise<SafeResponse> {
  const {
    method = 'GET',
    body: requestBody,
    accept = 'application/json',
    maxBytes = MAX_RESPONSE_BYTES,
    timeoutMs = FETCH_TIMEOUT_MS,
    headers = {},
  } = options;

  let url = assertHttpUrl(rawUrl);
  const startedAt = Date.now();

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    checkHostRate(url.hostname);

    // Resolve and validate on *every* hop. A redirect to a private address is
    // the most common way an SSRF guard that only checks the first URL is
    // bypassed.
    const resolved = await resolvePublicHost(url.hostname);

    const remaining = timeoutMs - (Date.now() - startedAt);
    if (remaining <= 0) {
      throw new ExternalServiceError(url.hostname, 'Request timed out.');
    }

    // The dispatcher is where the pinning actually takes effect: undici opens
    // the socket through this `connect.lookup`, so the only addresses reachable
    // are the ones validated above.
    const agent = new Agent({
      connect: { lookup: pinnedLookup(resolved) },
      connections: 1,
      pipelining: 0,
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), remaining);

    // undici's own `fetch`, not the global one.
    //
    // The global `fetch` in Node is a *different copy* of undici, bundled into
    // the runtime, and it validates a dispatcher against its own internal
    // handler interface. Handing it an Agent constructed from the `undici`
    // package fails at dispatch time with `invalid onRequestStart method`,
    // which is how the whole registry layer stopped being reachable. Calling
    // undici's fetch keeps the Agent and its pinned lookup in one
    // implementation — and it also sidesteps Next's patched global fetch, which
    // must never cache or dedupe the download of an untrusted archive.
    let response: UndiciResponse;
    try {
      response = await undiciFetch(url, {
        method,
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          ...(requestBody === undefined ? {} : { 'content-type': 'application/json' }),
          ...headers,
          accept,
          'user-agent': USER_AGENT,
          'accept-encoding': 'gzip, deflate',
        },
        ...(requestBody === undefined ? {} : { body: requestBody }),
        dispatcher: agent,
      });
    } catch (error) {
      clearTimeout(timer);
      await agent.close();
      const aborted = error instanceof Error && error.name === 'AbortError';
      throw new ExternalServiceError(
        url.hostname,
        aborted ? 'Request timed out.' : 'Request failed.',
        { cause: error },
      );
    } finally {
      clearTimeout(timer);
    }

    // Manual redirect handling, so each hop is re-validated.
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      await agent.close();

      if (!location) {
        throw new ExternalServiceError(url.hostname, 'Redirect without a location header.');
      }
      if (hop === MAX_REDIRECTS) {
        throw new ExternalServiceError(url.hostname, 'Too many redirects.');
      }

      const next = assertHttpUrl(new URL(location, url).toString());
      logger.debug({ from: url.hostname, to: next.hostname }, 'following redirect');
      url = next;
      continue;
    }

    let body: Buffer;
    try {
      body = await readBounded(response, maxBytes, url.hostname);
    } finally {
      await agent.close();
    }

    return {
      status: response.status,
      headers: response.headers,
      body,
      finalUrl: url.toString(),
    };
  }

  throw new ExternalServiceError(url.hostname, 'Too many redirects.');
}

/**
 * Read a response body, aborting as soon as it exceeds the cap.
 *
 * The cap is enforced while streaming rather than after `arrayBuffer()`, so a
 * declared-small-but-actually-enormous response cannot exhaust memory before we
 * notice. A missing or lying content-length changes nothing.
 */
async function readBounded(
  response: UndiciResponse,
  maxBytes: number,
  hostname: string,
): Promise<Buffer> {
  const declared = Number(response.headers.get('content-length') ?? '');
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new ExternalServiceError(hostname, 'Response is larger than the allowed size.');
  }

  if (!response.body) return Buffer.alloc(0);

  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;

      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new ExternalServiceError(hostname, 'Response is larger than the allowed size.');
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }

  return Buffer.concat(chunks, total);
}

/** `safeFetch`, then parse as JSON. Non-2xx and unparseable bodies throw. */
export async function safeFetchJson<T>(url: string, options: SafeFetchOptions = {}): Promise<T> {
  const response = await safeFetch(url, { ...options, accept: 'application/json' });

  if (response.status < 200 || response.status >= 300) {
    throw new ExternalServiceError(
      new URL(response.finalUrl).hostname,
      `Upstream returned ${response.status}.`,
      { details: { upstreamStatus: response.status } },
    );
  }

  try {
    return JSON.parse(response.body.toString('utf8')) as T;
  } catch (error) {
    throw new ExternalServiceError(
      new URL(response.finalUrl).hostname,
      'Upstream returned a malformed response.',
      { cause: error },
    );
  }
}
