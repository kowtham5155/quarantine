import { describe, expect, it } from 'vitest';

import { ForbiddenError } from '@/lib/errors';
import { requireSameOrigin } from '@/lib/http';

/**
 * `requireSameOrigin` is the only thing standing in front of the one
 * cookie-authenticated Route Handler, so both halves matter: it must accept the
 * app talking to itself, and reject anything else.
 *
 * The setup file loads .env.local, so APP_URL and AUTH_URL are localhost here.
 * That is exactly the interesting case — a deployment whose configured origin
 * is not the origin it is actually served on.
 */

const DEPLOYED = 'https://quarantine.onrender.com';

function post(headers: Record<string, string>): Request {
  return new Request('https://internal.invalid/api/analyses/abc/run', {
    method: 'POST',
    headers,
  });
}

describe('requireSameOrigin', () => {
  it('accepts the app calling itself on a host the env vars do not name', () => {
    // The bug: login worked (trustHost) while this rejected every scan.
    expect(() =>
      requireSameOrigin(
        post({
          origin: DEPLOYED,
          'x-forwarded-host': 'quarantine.onrender.com',
          'x-forwarded-proto': 'https',
        }),
      ),
    ).not.toThrow();
  });

  it('still accepts a configured origin with no proxy headers at all', () => {
    expect(() => requireSameOrigin(post({ origin: 'http://localhost:3000' }))).not.toThrow();
  });

  it('falls back to the Host header when there is no forwarded host', () => {
    expect(() =>
      requireSameOrigin(
        post({ origin: DEPLOYED, host: 'quarantine.onrender.com', 'x-forwarded-proto': 'https' }),
      ),
    ).not.toThrow();
  });

  it('takes the first entry of a comma-joined forwarded header', () => {
    expect(() =>
      requireSameOrigin(
        post({
          origin: DEPLOYED,
          'x-forwarded-host': 'quarantine.onrender.com, inner.internal',
          'x-forwarded-proto': 'https, http',
        }),
      ),
    ).not.toThrow();
  });

  it('rejects a cross-site origin even though the request reached the right host', () => {
    expect(() =>
      requireSameOrigin(
        post({
          origin: 'https://evil.example',
          'x-forwarded-host': 'quarantine.onrender.com',
          'x-forwarded-proto': 'https',
        }),
      ),
    ).toThrow(ForbiddenError);
  });

  it('does not let a scheme downgrade pass as the same origin', () => {
    expect(() =>
      requireSameOrigin(
        post({
          origin: 'http://quarantine.onrender.com',
          'x-forwarded-host': 'quarantine.onrender.com',
          'x-forwarded-proto': 'https',
        }),
      ),
    ).toThrow(ForbiddenError);
  });

  it('rejects a look-alike host', () => {
    expect(() =>
      requireSameOrigin(
        post({
          origin: 'https://quarantine.onrender.com.evil.example',
          'x-forwarded-host': 'quarantine.onrender.com',
          'x-forwarded-proto': 'https',
        }),
      ),
    ).toThrow(ForbiddenError);
  });

  it('rejects a missing Origin that fetch metadata calls cross-site', () => {
    expect(() => requireSameOrigin(post({ 'sec-fetch-site': 'cross-site' }))).toThrow(
      ForbiddenError,
    );
  });

  it('rejects a missing Origin with no fetch metadata to vouch for it', () => {
    expect(() => requireSameOrigin(post({}))).toThrow(ForbiddenError);
  });

  it('accepts a missing Origin that fetch metadata calls same-origin', () => {
    expect(() => requireSameOrigin(post({ 'sec-fetch-site': 'same-origin' }))).not.toThrow();
  });
});
