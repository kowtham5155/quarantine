# Quarantine — Claude Code Build Kit

> **How to use.** Save **Setup** as `CLAUDE.md` in your repo root — Claude Code reads it every turn, so the rules stay enforced for the whole build instead of decaying. Then send Prompts 1–10 as separate turns, in order. End every prompt with the verification block. Commit after every gate.

---

## Setup — save this as `CLAUDE.md`

```md
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
```

---

## PROMPT 1 — Scaffold

```
Read CLAUDE.md, then build the foundation.

1. Next.js 15 App Router + TypeScript strict. package.json with pinned versions,
   scripts: dev build start lint typecheck test test:e2e db:migrate db:seed db:studio
2. next.config.ts — output: 'standalone', poweredByHeader false,
   serverExternalPackages for prisma, argon2, tar
3. tsconfig strict + noUncheckedIndexedAccess + @/* alias
4. Tailwind config + globals.css: full token set as CSS variables — dark-first
   palette, the five verdict colours, signal-family colours, radii, Geist Sans +
   Geist Mono
5. eslint flat config + prettier + .editorconfig
6. lib/logger.ts (pino, redacts password/token/apiKey/authorization)
7. lib/errors.ts — ValidationError, AuthError, ForbiddenError, NotFoundError,
   RateLimitError, ExternalServiceError, AnalysisError
8. lib/env.ts — Zod env schema, throws at boot: DATABASE_URL, AUTH_SECRET,
   AUTH_URL, APP_URL, CRON_SECRET, GITHUB_TOKEN (optional, for provenance diffing
   rate limits), NODE_ENV
9. .env.example
10. middleware.ts — security headers, CSP nonce, route protection
11. shadcn/ui into components/ui/: button input label card badge table dialog sheet
    dropdown-menu select tabs toast tooltip skeleton alert avatar checkbox
    radio-group textarea switch progress separator popover command pagination
    breadcrumb accordion collapsible scroll-area
12. components/shared/: AppShell Sidebar TopBar PageHeader DataTable(generic,
    sortable+filterable+paginated) EmptyState StatCard VerdictBadge SignalBadge
    ConfidenceMeter CodeViewer(line numbers + highlighted ranges) DiffViewer
    PackageRef CopyButton TimeAgo ConfirmDialog LoadingSkeleton
13. app/layout.tsx, app/page.tsx placeholder, not-found.tsx, error.tsx,
    global-error.tsx
14. README.md

Then run: npm run typecheck && npm run lint && npm run build
Fix everything until all three pass. Do not report back until they do.
```

---

## PROMPT 2 — Schema & seed

```
Build the data layer. Every tenant model has orgId + index; every model has id
(cuid), createdAt, updatedAt.

Organization  name slug(unique) plan settings Json deletedAt
User          email(unique) passwordHash name avatarUrl emailVerifiedAt totpSecret
              totpEnabled lastLoginAt failedLoginCount lockedUntil
Membership    userId orgId role(OWNER|ADMIN|ANALYST|VIEWER) @@unique([userId,orgId])
Invitation    orgId email role tokenHash expiresAt acceptedAt
Session       userId tokenHash ip userAgent expiresAt revokedAt
VerificationToken identifier tokenHash type expiresAt

Package       ecosystem(NPM|PYPI) name latestVersion description repositoryUrl
              weeklyDownloads firstPublishedAt maintainerCount isDeprecated
              @@unique([ecosystem,name])
PackageVersion packageId version publishedAt tarballUrl integrity unpackedSize
              fileCount hasInstallScripts publisherId provenanceAttested
              @@unique([packageId,version])
Analysis      orgId packageVersionId status(QUEUED|RUNNING|COMPLETED|FAILED|PARTIAL)
              verdict(CLEAN|LOW_RISK|SUSPICIOUS|LIKELY_MALICIOUS|KNOWN_MALICIOUS)
              confidence Float weightedScore Float hardTriggersFired String[]
              startedAt completedAt durationMs engineVersion errorMessage
              signalCounts Json filesAnalysed
SignalHit     analysisId ruleId family severity weight confidence
              filePath lineStart lineEnd excerpt evidence Json contextModifier
Rule          ruleId(unique) family name description severity baseWeight
              remediation references String[] enabled falsePositiveNotes
ProvenanceCheck analysisId repoUrl gitRef status(MATCH|DIVERGENT|NO_REPO|
              REPO_UNREACHABLE|NO_TAG) filesOnlyInTarball String[]
              filesOnlyInRepo String[] modifiedFiles String[] diffSummary Json
TyposquatMatch analysisId targetPackage distance technique similarity
              targetDownloads
MaintainerEvent packageId type(ADDED|REMOVED|PUBLISHED) actor occurredAt metadata Json

Project       orgId name description ecosystem source(UPLOAD|GITHUB) repoUrl
              lastScanAt riskSummary Json
Dependency    projectId packageVersionId isDirect depth path String[] declaredRange
ProjectScan   orgId projectId status startedAt completedAt totalDeps flaggedDeps
              blockedDeps summary Json

Policy        orgId name description enabled action(ALLOW|WARN|BLOCK)
              conditions Json priority
PolicyViolation orgId policyId projectId packageVersionId analysisId
              state(OPEN|EXCEPTED|RESOLVED) detectedAt
Exception     orgId packageVersionId policyId justification requestedById
              approvedById expiresAt state(PENDING|APPROVED|DENIED|EXPIRED)
QuarantineItem orgId packageVersionId reason state(HELD|RELEASED|CONFIRMED_BAD)
              reviewedById reviewedAt

Campaign      orgId(nullable=global) name description fingerprint
              indicatorType(EXFIL_ENDPOINT|MAINTAINER|CODE_HASH|WALLET)
              indicatorValue firstSeenAt lastSeenAt packageCount
CampaignMember campaignId packageVersionId confidence

CorpusEntry   ecosystem packageName version label(MALICIOUS|CLEAN) source notes
              expectedSignals String[]
EvalRun       corpusSize truePositives falsePositives trueNegatives falseNegatives
              precision recall f1 falsePositiveRate meanLatencyMs p95LatencyMs
              engineVersion perFamilyMetrics Json ranAt

Alert         orgId projectId packageVersionId type severity title body readAt resolvedAt
Report        orgId projectId type format generatedById params Json status storagePath
ApiKey        orgId name keyHash prefix scopes String[] lastUsedAt expiresAt
              revokedAt createdById
Webhook       orgId url secret events String[] active lastDeliveryAt failureCount
AuditLog      orgId actorId actorEmail action entityType entityId metadata Json
              ip userAgent createdAt   [append-only]
Notification  userId orgId type title body link readAt

Also:
- lib/db.ts — Prisma singleton safe for hot reload
- lib/rbac.ts — role x action matrix + can(ctx, action, resource)
- prisma/seed.ts — 2 orgs, 6 users covering all roles, the full ~40-rule catalogue
  with real descriptions and remediation text, 40 packages across all five verdicts
  with realistic signal hits and file excerpts, 3 projects with dependency trees,
  4 policies, 2 campaigns, and a 60-entry corpus.
  Demo login: admin@quarantine.dev / Demo@Pass123
  Seed must make the app look fully populated on first login.

Then run: npx prisma migrate dev --name init && npm run db:seed && npm run typecheck
Fix until clean.
```

---

## PROMPT 3 — Auth & tenancy

```
Implement authentication, authorization, multi-tenancy.

- auth.ts / auth.config.ts — Auth.js v5, credentials, JWT with orgId + role, TOTP
  second factor
- lib/services/auth.service.ts — register login verifyEmail requestPasswordReset
  resetPassword changePassword enableTotp verifyTotp disableTotp listSessions
  revokeSession
- lib/services/org.service.ts — create update inviteMember acceptInvite
  changeMemberRole removeMember switchOrg
- lib/rate-limit.ts — Postgres-backed sliding window (no Redis)
- lib/audit.ts — audit(ctx, action, entity, metadata), called from every
  privileged service method

Routes: /login (password then TOTP step) /register (zxcvbn meter)
/forgot-password /reset-password/[token] /verify-email/[token]
/accept-invite/[token] /onboarding (3 steps: org -> team -> first project)

Mandatory:
- Argon2id, 12-char min, zxcvbn >= 3
- Timing-safe comparison on every token check
- Tokens: 32 random bytes, stored SHA-256 hashed, single-use, 1h expiry
- Enumeration-safe responses ("If that email exists, we've sent a link")
- Every auth event audited

Then run: npm run typecheck && npm run lint && npm run build
Fix until clean, then give me manual test steps for each flow.
```

---

## PROMPT 4 — The analysis engine

```
This is the core of the project. Re-read the SAFETY RULE in CLAUDE.md before you
write a single line — you are handling real malware samples.

Build lib/engine/:

  types.ts          Signal, SignalFamily, Verdict, AnalysisContext, PackageArtifact
  fetcher.ts        SSRF-guarded fetch (see CLAUDE.md rule 6) + per-host rate limit
  registry/npm.ts   registry.npmjs.org client: packument, version metadata,
                    maintainers, publish timestamps, tarball URL, integrity,
                    download counts. Cache aggressively — the registry is the
                    slowest dependency in the system.
  registry/pypi.ts  pypi.org/pypi/<pkg>/json equivalent
  extract.ts        BOUNDED tar.gz extraction. 50MB total / 10k entries / 10MB per
                    file / depth 20. Zip-slip guard: reject any entry whose
                    resolved path escapes the root. Temp dir per scan, deleted in
                    a finally block, always. Never executes anything.
  ast.ts            @babel/parser with { errorRecovery: true }, plugins for jsx,
                    typescript, decorators. Walk helpers for imports, call
                    expressions, member expressions, string literals.

  signals/install.ts     FAMILY 1 — install-time execution
    Q-INS-001 lifecycle script present (preinstall/install/postinstall)
    Q-INS-002 script invokes curl/wget/bash -c/powershell/node -e
    Q-INS-003 script base64- or hex-decodes a payload
    Q-INS-004 script reads ~/.npmrc, ~/.ssh, ~/.aws, .env, /etc/passwd
    Q-INS-005 script makes an outbound network call
    Q-INS-006 script writes outside the package directory
    Q-INS-007 install entrypoint is obfuscated or minified

  signals/obfuscation.ts FAMILY 2 — obfuscation and evasion
    Q-OBF-001 Shannon entropy above threshold (tune on the corpus, don't guess)
    Q-OBF-002 base64/hex literal > 1KB
    Q-OBF-003 eval() / new Function() / require(atob(...))
    Q-OBF-004 hex string array + decoder function (JS obfuscator signature)
    Q-OBF-005 bidirectional Unicode control chars (Trojan Source)
    Q-OBF-006 minified file with no source and no .min in the name
    Q-OBF-007 deep string concatenation building identifiers dynamically

  signals/capability.ts  FAMILY 3 — dangerous capability in context
    Q-CAP-001 child_process import
    Q-CAP-002 net/dgram/dns import
    Q-CAP-003 vm module import
    Q-CAP-004 wholesale process.env iteration (exfil pattern)
    Q-CAP-005 credential path read (.ssh, .aws, keychain, .npmrc)
    Q-CAP-006 crypto wallet path read (.ethereum, wallet.dat)
    Q-CAP-007 hardcoded IP address in a network call
    Q-CAP-008 Discord/Telegram webhook URL
    Q-CAP-009 native binary or .node file in a declared pure-JS package
    CONTEXT MODIFIER: weight these by declared package purpose (keywords,
    description, dependents). child_process in a build tool is normal; in a
    string utility it is an alarm. Implement this as an explicit multiplier and
    document how it is derived.

  signals/typosquat.ts   FAMILY 4 — identity
    Q-TYP-001 Damerau-Levenshtein <= 2 from top-5000 packages
    Q-TYP-002 homoglyph / Unicode confusable substitution
    Q-TYP-003 separator manipulation (- vs _ vs none)
    Q-TYP-004 scope confusion (@types/foo vs @typesfoo)
    Q-TYP-005 combosquatting (popular name + affix)
    Q-TYP-006 dependency-confusion posture
    Ship the top-5000 list as a static data file — do not fetch it at runtime.
    Suppress when the candidate itself has high downloads (that's the real one).

  signals/maintainer.ts  FAMILY 5 — release forensics
    Q-MNT-001 dormancy break (inactive N months then sudden release)
    Q-MNT-002 maintainer added within N days of this release
    Q-MNT-003 new maintainer account (low age, few packages)
    Q-MNT-004 sole maintainer on a high-download package
    Q-MNT-005 out-of-order or anomalous version jump
    Q-MNT-006 release cadence anomaly vs the package's own history

  signals/provenance.ts  FAMILY 6 — the highest-value family
    Q-PRV-001 no repository field
    Q-PRV-002 repository URL 404s or is archived
    Q-PRV-003 FILES IN TARBALL ABSENT FROM THE GIT TAG  <- event-stream signature
    Q-PRV-004 files modified between repo and tarball
    Q-PRV-005 binary blobs in a source-only package
    Q-PRV-006 no SLSA/Sigstore provenance attestation
    Implementation: resolve the git tag for the version (try v<ver>, <ver>,
    release-<ver>), download the GitHub tarball, normalise both trees (strip
    build output, node_modules, lockfiles, and anything in .npmignore/files),
    then compare by content hash. Degrade gracefully at every failure point —
    NO_REPO and REPO_UNREACHABLE are distinct outcomes from DIVERGENT, and
    conflating them creates false positives.

  verdict.ts   The hybrid model:
    hard triggers -> minimum LIKELY_MALICIOUS regardless of weighted score:
      install script + network exfil, credential read in install script,
      executable code in tarball absent from source, known-bad hash match
    otherwise weighted = Σ(weight × confidence × contextModifier) -> bucket
    confidence = f(signals fired, corroboration across families, completeness)
    MUST return the full signal list — fired AND not fired — with file, line
    range, and excerpt for every hit. A verdict a developer cannot inspect is a
    verdict they will ignore.

  index.ts     analyse(ecosystem, name, version): orchestrates with
               Promise.allSettled, 90s global budget, per-family timeouts,
               partial results. One failing family must never fail the analysis.

  lib/services/analysis.service.ts — queue, run, get, list, compare versions
  lib/services/campaign.service.ts — cluster by exfil endpoint / maintainer /
               code hash; surface the campaign, not the individual package

Execution model (no persistent worker on free hosting):
  POST /api/analyses/[id]/run  runs inline with streamed progress
  app/api/cron/analyses/route.ts  Bearer CRON_SECRET, timing-safe compare,
  batched, idempotent

Tests — Vitest, fixtures only, zero live network:
  every signal module against captured fixtures (both malicious and benign)
  verdict.ts: every hard trigger, every bucket boundary, confidence calculation
  extract.ts: zip-slip attempt, size bomb, entry-count bomb, depth bomb
  fetcher.ts: every private IP range, DNS rebinding, redirect limit, timeout
  typosquat: known typosquats must hit, top-500 packages must NOT hit

Then run: npm run typecheck && npm run lint && npm run test && npm run build
Fix everything until all four pass. Do not report back until they do.
```

---

## PROMPT 5 — Pages A: scanning and package intelligence

```
Build these routes completely. Real data from services — no mock data anywhere.
Each gets loading.tsx, error.tsx, empty state, full responsiveness.

PUBLIC
  /                    Landing: the npm-audit-blind-spot framing, the incident
                       table (event-stream / ua-parser-js / xz), the six signal
                       families, live scan CTA
  /how-it-works        The detection methodology in depth
  /detections          Public rule catalogue — all ~40 rules, searchable
  /research            Evaluation results: precision, recall, FPR, per-family
                       breakdown, methodology, corpus composition
  /docs                API + CLI documentation
  /security            Our own threat model — how we handle malware samples safely
  /legal/terms  /legal/privacy

SCANNING
  /dashboard           Verdict distribution, packages analysed, open policy
                       violations, quarantine queue depth, recent campaigns,
                       analysis throughput, 6 stat cards
  /scan                THE HEADLINE PAGE. Paste a package name, or upload a
                       lockfile. Streaming progress per signal family. Result
                       lands on the report page.
  /packages            All analysed packages, filter by verdict/ecosystem/family
  /packages/[eco]/[name]
                       Package overview: all versions, verdict per version,
                       download trend, maintainer list, repository link
  /packages/[eco]/[name]/[version]
                       THE VERDICT REPORT: verdict banner with confidence meter,
                       hard triggers fired, signal families as a radar/bar
                       breakdown, top signals with excerpts, metadata panel
  /packages/[eco]/[name]/[version]/signals
                       Every rule — fired and not fired — grouped by family, with
                       weight, confidence, context modifier, file, line, excerpt
  /packages/[eco]/[name]/[version]/files
                       File tree with per-file risk shading; click a file to open
                       CodeViewer with flagged line ranges highlighted. Package
                       content is HOSTILE INPUT — escape everything, never
                       dangerouslySetInnerHTML.
  /packages/[eco]/[name]/[version]/provenance
                       Tarball vs GitHub: side-by-side tree, files-only-in-tarball
                       called out prominently, per-file diff viewer
  /packages/[eco]/[name]/[version]/maintainers
                       Release + maintainer timeline, dormancy gaps marked,
                       maintainer changes flagged
  /packages/[eco]/[name]/[version]/compare
                       Diff this version against the previous one — what changed,
                       which signals are new
  /packages/[eco]/[name]/similar
                       Typosquat neighbourhood: candidates, distance, technique,
                       relative downloads
  /analyses            Analysis history and queue
  /analyses/[id]

Then run: npm run typecheck && npm run lint && npm run build
Fix until clean, then confirm the route tree back to me.
```

---

## PROMPT 6 — Pages B: projects, policy, intelligence, ops

```
Remaining routes, same quality bar.

PROJECTS
  /projects            Project list with risk summary per project
  /projects/new        Upload a lockfile or connect a public GitHub repo
  /projects/[id]       Dependency tree with verdict overlay, direct vs transitive,
                       risk-weighted; expandable, virtualised for large trees
  /projects/[id]/dependencies   Flat filterable table, depth and path shown
  /projects/[id]/violations     Policy violations for this project
  /projects/[id]/sbom           CycloneDX 1.5 JSON export
  /projects/[id]/history        Risk over time as dependencies changed
  /projects/[id]/settings

POLICY & GOVERNANCE
  /policies            Policy list, priority order, enabled state
  /policies/new        Condition builder: verdict threshold, specific rule fired,
                       signal family score, package age, maintainer count,
                       license, ecosystem. Action: ALLOW / WARN / BLOCK.
  /policies/[id]       Edit + a live "what would this have blocked" preview
                       against existing analyses
  /violations          Org-wide violation inbox, bulk triage
  /quarantine          Held packages awaiting review: verdict, why it was held,
                       release / confirm-bad actions
  /exceptions          Exception requests with justification, approver, expiry.
                       Expired exceptions auto-revert to enforcing.

INTELLIGENCE
  /feed                Live feed of newly published packages flagged in the last
                       24h, ecosystem-wide
  /campaigns           Clustered malicious package families
  /campaigns/[id]      Shared indicator, member packages, timeline, IOC export
  /corpus              Labelled evaluation corpus management
  /corpus/eval         Run an evaluation, view precision/recall/FPR, per-family
                       metrics, per-rule contribution, latency distribution
  /rules               Internal rule catalogue editor: weight tuning, enable/
                       disable, false-positive notes
  /rules/[id]          Rule detail + every package it has fired on

INTEGRATIONS
  /integrations              Overview
  /integrations/api-keys     Create (plaintext once), scope, revoke
  /integrations/webhooks     CRUD, event selection, test delivery, delivery log
  /integrations/ci           GitHub Action YAML + CLI install snippet generator,
                             pre-filled with the org's API key and policy

REPORTING & SETTINGS
  /reports  /reports/new  /reports/[id]   (print-optimised, @media print CSS)
  /alerts   /search
  /settings/profile  /settings/security (TOTP QR + backup codes + session list)
  /settings/organization  /settings/members  /settings/notifications
  /audit-log

ADMIN
  /admin  /admin/organizations  /admin/users  /admin/jobs  /admin/engine
  /unauthorized  /not-found

Then run: npm run typecheck && npm run lint && npm run build
Fix until clean. Confirm the full route tree — target is 60+.
```

---

## PROMPT 7 — CLI and GitHub Action

```
Ship the developer-experience layer. This is what makes the project read as a real
product rather than a web app, and it is a strong resume line on its own.

1. packages/cli/ — a standalone npm package `quarantine-cli`
   quarantine scan <package>@<version>     analyse one package
   quarantine check                        analyse ./package-lock.json against
                                           org policy, exit 1 on BLOCK
   quarantine sbom                         emit CycloneDX
   quarantine login                        store API key in ~/.quarantinerc
   Output: pretty table by default, --json for machines, --sarif for GitHub code
   scanning. Respects --fail-on <verdict>. Uses the public API only.

2. .github/actions/quarantine-scan/ — a composite GitHub Action
   inputs: api-key, fail-on, project-id
   Posts a PR comment summarising new risky dependencies introduced by the PR,
   and uploads SARIF so findings appear in the Security tab.

3. app/api/v1/ — the public API the CLI consumes:
   POST /api/v1/analyses          analyse a package
   GET  /api/v1/analyses/[id]
   POST /api/v1/projects/[id]/check   evaluate a lockfile against policy
   GET  /api/v1/packages/[eco]/[name]/[version]
   API-key auth (SHA-256 hash lookup), scoped, rate limited per key, versioned,
   consistent error envelope, OpenAPI spec at /api/v1/openapi.json

Then run: npm run typecheck && npm run lint && npm run test && npm run build
Fix until all pass.
```

---

## PROMPT 8 — Evaluation

```
Build the evaluation harness. This is the difference between a portfolio project
and a class assignment — an interviewer will respect this more than any feature.

1. scripts/build-corpus.ts
   Positive class: known-malicious package versions from published supply-chain
   datasets and historical incident disclosures. Store as offline FIXTURES —
   captured tarball contents committed to the repo — so evaluation is reproducible
   and never depends on a live registry still serving a pulled package.
   Negative class: top 500 by downloads + 500 random low-download packages.
   The low-download negatives matter: typosquat detectors trivially over-fire on
   obscure legitimate packages, and hiding that is the easiest way to report a
   dishonest FPR.

2. scripts/evaluate.ts
   Run the engine over the whole corpus. Compute precision, recall, F1, FPR —
   overall, per signal family, and per rule. Report FPR separately for popular vs
   obscure negatives. Record mean and p95 latency. Persist an EvalRun row.

3. Tune from the results, don't guess:
   - entropy threshold (Q-OBF-001)
   - typosquat distance cutoff and download-based suppression
   - context modifier multipliers
   - hard trigger conditions — verify each has near-zero FPR, because a hard
     trigger that misfires destroys trust in the whole tool
   Document every threshold change and why the data justified it.

4. /research page renders the latest EvalRun: confusion matrix, per-family bars,
   per-rule contribution, latency distribution, corpus composition, and an honest
   limitations section.

Then run the evaluation and show me the actual numbers.
```

---

## PROMPT 9 — Hardening

```
Production hardening. Fix, don't just report.

1. SAFETY RE-AUDIT — the most important item. Re-read the SAFETY RULE in
   CLAUDE.md and verify against the actual code:
   - Is there ANY path where package content could be executed, required,
     imported, or eval'd? Trace every code path that touches extracted content.
   - Are extraction bounds enforced BEFORE writing to disk, not after?
   - Is the zip-slip guard using path.resolve and checking containment correctly?
   - Is the temp dir cleaned up on every path including thrown exceptions?
   - Is package-derived content escaped everywhere it renders? Check every
     component that displays a package name, description, file path, or excerpt.
   Report findings, then fix all of them.

2. OWASP TOP 10 self-audit — A01 access control (verify EVERY service method
   enforces orgId and role), A02 crypto, A03 injection + XSS, A04 insecure design,
   A05 misconfiguration, A06 vulnerable deps, A07 auth failures, A08 integrity
   (webhook signatures), A09 logging, A10 SSRF (the fetcher — re-verify
   exhaustively). Findings table, then apply every fix.

3. PERFORMANCE
   - Composite Prisma indexes on orgId+X for every list query
   - Kill N+1s; select only needed columns
   - Cache registry responses aggressively — it's the slowest dependency
   - Suspense streaming on dashboard, next/dynamic for charts and CodeViewer
   - Virtualise the dependency tree and large file lists
   - Lighthouse >= 90 on all four categories for /dashboard

4. RELIABILITY
   - /api/health with DB connectivity + engine version
   - Graceful degradation when npm registry or GitHub is unreachable
   - Idempotent analysis triggering (no duplicate concurrent runs)
   - Global error boundary with a correlation ID surfaced to the user

5. UX POLISH — optimistic updates + toasts, skeletons everywhere, Cmd+K palette,
   zero layout shift

6. Full test suite:
   Vitest integration (real test Postgres): auth, project CRUD, analysis
   lifecycle, policy evaluation, exception expiry, cross-tenant access attempts
   (must all 403/404)
   Playwright E2E: (1) register -> onboarding -> dashboard  (2) scan a package ->
   view verdict -> drill to flagged line  (3) upload lockfile -> policy blocks ->
   request exception -> approve  (4) create policy -> preview -> enforce
   (5) generate API key -> call the API  (6) cross-tenant URL access denied
   (7) mobile 390px  (8) axe-core on 10 pages, zero critical violations
   .github/workflows/ci.yml: install -> typecheck -> lint -> unit -> integration
   (postgres service) -> build -> e2e -> coverage

7. docs/: ARCHITECTURE.md (mermaid), DETECTION_METHODOLOGY.md, THREAT_MODEL.md,
   API.md, EVALUATION.md, DEPLOYMENT.md

Then run everything. Fix until green.
```

---

## PROMPT 10 — Deploy

```
Ship to Render.

1. render.yaml — web service, env node, plan free,
   build: npm ci && npx prisma generate && npx prisma migrate deploy && npm run build
   start: npm run start
   healthCheckPath: /api/health, autoDeploy true, all envVars declared
   (sync:false for secrets)
2. .node-version -> 20
3. Confirm next.config.ts has output: 'standalone'
4. app/api/cron/analyses/route.ts — Bearer CRON_SECRET, timing-safe compare
5. scripts/seed-prod.ts — idempotent production demo seed
6. DEPLOYMENT.md — click-by-click Render steps, every env var with how to generate
   it, Neon setup, external cron setup, rollback procedure
7. A 25-item post-deploy smoke checklist to run against the LIVE URL

Design around these constraints:
- Render free web services spin down after 15 min idle, ~1 min cold start. Make
  first load tolerable; external cron pings /api/health every 10 min.
- Free Render Postgres EXPIRES 30 days after creation — use Neon free tier
  instead so the database outlives the deadline.
- Filesystem is ephemeral. Extraction temp dirs go in /tmp and are always cleaned
  up. Never persist anything to disk.
- Free instance is 512MB. Extraction bounds are a memory control, not just a
  safety control — enforce them strictly and stream where possible.
- If the build OOMs: NODE_OPTIONS=--max-old-space-size=2048
```

---

## Runbook

```bash
# Database — Neon free tier (does NOT expire; Render's free Postgres does)
# neon.tech -> New Project -> copy the pooled connection string

# Verify locally before deploying. Never deploy an unverified build.
npm ci
npx prisma migrate dev --name init
npm run db:seed
npm run typecheck && npm run lint && npm run test && npm run build
npm run start

git init && git add -A && git commit -m "feat: Quarantine"
git branch -M main
git remote add origin https://github.com/<you>/quarantine.git
git push -u origin main

# Render -> New -> Web Service -> connect repo
#   Build: npm ci && npx prisma generate && npx prisma migrate deploy && npm run build
#   Start: npm run start
#   Health check: /api/health
#   Env: DATABASE_URL, AUTH_SECRET (openssl rand -base64 32),
#        AUTH_URL, APP_URL, CRON_SECRET (openssl rand -hex 32),
#        GITHUB_TOKEN (a read-only PAT — raises the provenance-diff rate limit),
#        NODE_ENV=production, NODE_VERSION=20

# Render Shell:
npx tsx scripts/seed-prod.ts

# cron-job.org (free):
#   GET  /api/health          every 10 min   (keeps it warm)
#   GET  /api/cron/analyses   hourly, header: Authorization: Bearer <CRON_SECRET>
```

---

## 48-hour schedule

| Hours | Work | Gate |
|---|---|---|
| 0–1 | `CLAUDE.md`, repo, Prompt 1 | dev server serves a styled shell |
| 1–3 | Prompt 2, then **deploy the near-empty app to Render** | live URL responds, DB connected |
| 3–5 | Prompt 3 | register, log in, role blocks an action |
| 5–14 | Prompt 4 — the engine. Protect this time. | a real package analysis returns a verdict with evidence |
| 14–16 | Sleep. Not optional. | — |
| 16–24 | Prompt 5 | scan → verdict → drill to flagged source line |
| 24–30 | Prompt 6 | route count confirmed at 60+ |
| 30–34 | Prompt 7 | CLI runs, Action posts a PR comment |
| 34–38 | Prompt 8 | real precision/recall numbers on `/research` |
| 38–43 | Prompt 9 | CI green, safety re-audit clean |
| 43–46 | Prompt 10 | 25 smoke tests pass on the live URL |
| 46–48 | README with screenshots, demo video, rehearsal | demo runs twice without touching code |

**Cut order if you fall behind:** `/campaigns`, `/feed`, PyPI support, the GitHub Action, `/reports`. **Never cut:** the engine, the provenance diff, `/scan`, the verdict report, the evaluation.

---

## Interview answers to have ready

**"Why not just use npm audit?"** — npm audit answers whether a package has a *known published CVE*. That requires someone to have already found, reported, and disclosed the flaw. Malicious packages are designed to execute in the window before that happens. Quarantine asks a different question: is this artefact behaving maliciously *right now*.

**"How do you avoid false positives?"** — Three mechanisms. Context modifiers, so `child_process` in a build tool scores differently from `child_process` in a string utility. Hard triggers reserved only for signals with near-zero measured FPR. And an evaluation corpus that deliberately includes obscure legitimate packages, because that's where typosquat detectors actually over-fire — I report FPR separately for popular and obscure negatives so the number is honest.

**"What if a package legitimately needs an install script?"** — It's a WARN signal, not a block, and it feeds a policy engine rather than a hard rule. Organisations set their own threshold, and the exception workflow lets a team approve a specific package with a written justification and an expiry date. The tool's job is evidence and enforcement, not judgment.

**"You're downloading malware — how do you not get compromised?"** — Nothing is ever executed. Analysis is purely static AST and byte inspection. Extraction is bounded against zip bombs and guarded against zip-slip, into a temp dir deleted in a finally block. All fetching goes through an SSRF-guarded client. And every string that comes out of a package is treated as hostile input when rendered.

**"What would you build next?"** — Dynamic analysis in a sandboxed runtime, which catches payloads that only decode at execution. I scoped it out deliberately — executing untrusted code needs real isolation infrastructure, and doing it badly is worse than not doing it at all.
