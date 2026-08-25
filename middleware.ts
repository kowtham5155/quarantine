import { NextResponse, type NextRequest } from 'next/server';

/**
 * Edge middleware: security headers, a per-request CSP nonce, and coarse route
 * protection.
 *
 * The nonce is generated here and handed to the app two ways — as `x-nonce` for
 * `headers()` consumers, and inside the CSP header on the *request*, which is
 * how Next discovers it and stamps its own script and style tags.
 *
 * Route protection here is a cheap redirect, not an authorisation decision. It
 * only asks whether a session cookie is present. Identity, org membership and
 * role are verified in the service layer against the database on every call
 * (CLAUDE.md rule 3) — middleware never grants access, it only avoids rendering
 * a protected shell for an obviously signed-out visitor.
 */

/** Prefixes that never require a session. */
const PUBLIC_PREFIXES = [
  '/',
  '/login',
  '/register',
  '/forgot-password',
  '/reset-password',
  '/verify-email',
  // The invite page renders a sign-in prompt itself when there is no session,
  // so it must not be bounced to /login before it can name the organisation.
  '/accept-invite',
  '/pricing',
  '/how-it-works',
  '/detections',
  '/research',
  '/security',
  '/docs',
  '/legal',
  '/p', // public package report permalinks
] as const;

/** API namespaces that authenticate themselves (webhook signature, cron secret, API key). */
const SELF_AUTHENTICATING_API_PREFIXES = [
  '/api/auth',
  '/api/cron',
  '/api/webhooks',
  '/api/v1',
  '/api/health',
] as const;

const SESSION_COOKIE_NAMES = [
  'authjs.session-token',
  '__Secure-authjs.session-token',
  'next-auth.session-token',
  '__Secure-next-auth.session-token',
] as const;

const isDev = process.env.NODE_ENV !== 'production';

function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

function buildContentSecurityPolicy(nonce: string): string {
  // The dev server needs eval for React Refresh. Production scripts are
  // nonce-only: no unsafe-inline, no unsafe-eval.
  const scriptSrc = isDev
    ? `'self' 'nonce-${nonce}' 'strict-dynamic' 'unsafe-eval'`
    : `'self' 'nonce-${nonce}' 'strict-dynamic'`;

  // Styles carry no nonce, deliberately.
  //
  // A nonce on `style-src` makes the browser ignore `'unsafe-inline'`, and that
  // in turn blocks every inline *style attribute* — which a nonce cannot cover,
  // because an attribute has nowhere to carry one. Every meter, risk bar and
  // chart in this application sets a computed width that way, so a nonced
  // style-src silently drops the visualisation layer: verified in a browser,
  // where the console filled with "Applying inline style violates ... The
  // action has been blocked".
  //
  // The alternatives are hashing every possible style attribute value (not
  // possible for a width computed from data) or dropping the visualisations.
  // So `style-src` allows inline styles and scripts do not: script-src keeps the
  // nonce plus strict-dynamic, which is the directive that stops code
  // execution. CSS injection needs an HTML injection point to land in, and
  // there is none — no `dangerouslySetInnerHTML` exists in this codebase and
  // package-derived strings are only ever rendered as text — while
  // `default-src 'self'` with `img-src 'self' blob: data:` closes the usual
  // CSS-based exfiltration channels.
  const styleSrc = `'self' 'unsafe-inline'`;
  const connectSrc = isDev ? `'self' ws: http://localhost:*` : `'self'`;

  return [
    `default-src 'self'`,
    `script-src ${scriptSrc}`,
    `style-src ${styleSrc}`,
    `img-src 'self' blob: data:`,
    `font-src 'self' data:`,
    `connect-src ${connectSrc}`,
    // Package-derived content is only ever rendered as escaped text.
    `object-src 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `frame-ancestors 'none'`,
    `frame-src 'none'`,
    `worker-src 'self' blob:`,
    `manifest-src 'self'`,
    `upgrade-insecure-requests`,
  ].join('; ');
}

function applySecurityHeaders(headers: Headers, csp: string): void {
  headers.set('Content-Security-Policy', csp);
  headers.set('X-Frame-Options', 'DENY');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
  );
  headers.set('X-DNS-Prefetch-Control', 'off');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Resource-Policy', 'same-origin');
  if (!isDev) {
    headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }
}

function isPublicPath(pathname: string): boolean {
  if (pathname === '/') return true;
  return PUBLIC_PREFIXES.some(
    (prefix) => prefix !== '/' && (pathname === prefix || pathname.startsWith(`${prefix}/`)),
  );
}

function isSelfAuthenticatingApi(pathname: string): boolean {
  return SELF_AUTHENTICATING_API_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`),
  );
}

function hasSessionCookie(request: NextRequest): boolean {
  return SESSION_COOKIE_NAMES.some((name) => Boolean(request.cookies.get(name)?.value));
}

export function middleware(request: NextRequest): NextResponse {
  const nonce = generateNonce();
  const csp = buildContentSecurityPolicy(nonce);
  const { pathname, search } = request.nextUrl;

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('x-pathname', pathname);
  // Next reads the nonce back out of this header to stamp its own tags.
  requestHeaders.set('Content-Security-Policy', csp);

  const needsSession =
    !isPublicPath(pathname) && !(pathname.startsWith('/api/') && isSelfAuthenticatingApi(pathname));

  if (needsSession && !hasSessionCookie(request)) {
    if (pathname.startsWith('/api/')) {
      const body = JSON.stringify({
        error: { code: 'AUTH_ERROR', message: 'Authentication is required.' },
      });
      const response = new NextResponse(body, {
        status: 401,
        headers: { 'content-type': 'application/json' },
      });
      applySecurityHeaders(response.headers, csp);
      return response;
    }

    const loginUrl = new URL('/login', request.url);
    loginUrl.searchParams.set('next', `${pathname}${search}`);
    const response = NextResponse.redirect(loginUrl);
    applySecurityHeaders(response.headers, csp);
    return response;
  }

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  applySecurityHeaders(response.headers, csp);
  return response;
}

export const config = {
  matcher: [
    /*
     * Everything except Next's own build output, the favicon and static media.
     * Prefetch requests are skipped: they would burn a nonce per hover.
     */
    {
      source:
        '/((?!_next/static|_next/image|favicon.ico|robots.txt|sitemap.xml|.*\\.(?:png|jpg|jpeg|gif|webp|svg|ico|woff|woff2|ttf)$).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
};
