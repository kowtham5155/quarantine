# Quarantine

Pre-install supply chain malware detection for open-source dependencies. Analyses
the actual published tarball — not a CVE database — and returns a verdict before a
package reaches a developer machine or CI runner.

## Stack — do not substitute
- Next.js 15 App Router, TypeScript strict
- Tailwind + shadcn/ui + lucide-react
- Prisma + PostgreSQL (Neon)
- Auth.js v5, credentials + TOTP
- Zod at every input boundary
- Recharts
- Vitest + Playwright
- Deploy: single Render Web Service (Node)

## Architecture rules
1. Single Next.js app. Server Actions for mutations; Route Handlers (/api/*) only
   for webhooks, cron, CLI, and the public API.
2. Layering is strict: app/(routes) -> lib/services/* -> lib/db. Components never
   touch Prisma. Services are pure and unit-testable.
3. Every service function takes `ctx: { userId, orgId, role }` as its first argument
   and enforces tenant isolation itself. Never trust the caller to have filtered.
4. Every Prisma query on tenant data includes `where: { orgId }`. No exceptions.
5. Errors flow through the AppError hierarchy in lib/errors.ts. Never leak stack
   traces or raw error text to a client.
6. All outbound network calls go through lib/net/fetcher.ts: 10s timeout, max 3
   redirects, SSRF guard (resolve DNS first; reject 10/8, 172.16/12, 192.168/16,
   127/8, 169.254/16, ::1, fc00::/7), fixed User-Agent, per-host rate limiting.
7. No `any`. No `@ts-ignore`. No console.log — use lib/logger.ts (pino) with
   request-scoped correlation IDs.

## THE SAFETY RULE — read this before writing any analysis code
This system downloads untrusted archives that may contain real malware.

- NEVER execute, require, import, or eval package contents. Ever.
- NEVER run `npm install` on an analysed package.
- Extraction is bounded: 50MB total, 10,000 entries, 10MB per file, max depth 20.
- Zip-slip guard: reject any entry whose resolved path escapes the extraction root.
- Extract to a per-scan temp dir; delete it in a finally block, always.
- Analysis is purely static: parse with @babel/parser, walk the AST, read bytes.
- Treat every string from a package as hostile input when rendering it.

Violating any of these is a critical bug, not a style issue.

## Code quality
- Every file complete and runnable. Never "// ... rest of implementation" or
  "// TODO". If a file is too long, split across messages — never truncate.
- Full file path as a heading above every code block.
- After each phase report: files changed, commands to run, expected result,
  anything deferred.
- Ambiguity: state your assumption in one line and proceed. Don't stop to ask.

## Security baseline
- Argon2id (@node-rs/argon2), 12-char min, zxcvbn score >= 3
- HttpOnly + Secure + SameSite=Lax cookies; 30-min idle, 12-hour absolute
- CSRF on all state-changing routes
- Login rate limit 5/15min per IP+email, then exponential lockout
- Strict CSP with per-request nonce, no unsafe-inline
- HSTS, X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy
- Escape all package-derived strings on render; DOMPurify anything as HTML
- Prisma parameterised queries only; never $queryRawUnsafe
- Append-only audit log for every privileged action
- API keys stored SHA-256 hashed, shown plaintext exactly once

## Design
Dark-first developer-tool aesthetic. Zinc/slate neutrals, one blue accent.
Verdict colours: KNOWN_MALICIOUS #991b1b, LIKELY_MALICIOUS #dc2626,
SUSPICIOUS #ea580c, LOW_RISK #ca8a04, CLEAN #059669.
No purple gradients, no glassmorphism. Monospace for all package names, versions,
hashes, and code. Every page: loading.tsx, error.tsx, empty state. Responsive from
360px. WCAG 2.1 AA.
