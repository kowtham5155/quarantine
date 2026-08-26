# Quarantine

Pre-install supply chain malware detection for open-source dependencies.

`npm audit` tells you about known vulnerabilities in code that is already on your
machine. Quarantine analyses the **actual published tarball** — not a CVE
database — and returns a verdict _before_ a package reaches a developer machine
or a CI runner.

> **Static analysis only.** This system downloads untrusted archives that may
> contain real malware. It never executes, requires, imports or evaluates
> package contents, and it never runs `npm install` on an analysed package. The
> full rule set lives in [`CLAUDE.md`](./CLAUDE.md) under **THE SAFETY RULE**;
> violating it is a critical bug, not a style issue.

---

## Stack

| Concern    | Choice                                                 |
| ---------- | ------------------------------------------------------ |
| Framework  | Next.js 15 (App Router), React 19, TypeScript 5.9      |
| Styling    | Tailwind v4 + shadcn/ui (new-york) + lucide-react      |
| Data       | Prisma 6 + PostgreSQL (Neon)                           |
| Auth       | Auth.js v5 — credentials + TOTP                        |
| Validation | Zod at every input boundary                            |
| Charts     | Recharts                                               |
| Tests      | Vitest (unit) + Playwright (e2e)                       |
| Deploy     | Single Render Web Service (Node, `output: standalone`) |

Dependencies are pinned to exact versions — no ranges — so an install today
resolves to the same tree as an install in six months.

## Getting started

```bash
npm install
cp .env.example .env.local     # then fill in DATABASE_URL and the secrets

# The Prisma CLI reads .env, not .env.local — .env.local is a Next.js
# convention the CLI has never heard of. Give it the two connection strings:
grep -E '^(DATABASE_URL|DIRECT_URL)=' .env.local > .env

npx prisma migrate deploy      # needs DIRECT_URL, the unpooled Neon string
npm run dev                    # http://localhost:3000
```

Without that `.env`, `npx prisma migrate deploy` fails with
`Environment variable not found: DIRECT_URL`. Both files are gitignored. The
`npm run db:*` scripts go through `dotenv -e .env.local` and work either way; it
is the bare `npx prisma ...` form that needs `.env`.

Generate the two secrets with:

```bash
openssl rand -base64 32   # AUTH_SECRET
openssl rand -hex 32      # CRON_SECRET
```

`lib/env.ts` validates the environment at boot and throws on anything missing or
malformed, naming the variable but never printing its value.

## The deployed instance

<!-- Fill both in once Render is live. -->

**URL:** _not yet deployed_

**Demo login:** _set when the instance is seeded_ — a **read-only (VIEWER)**
account. It can open every surface in the application and change nothing: it
cannot run a scan, edit a policy, release a package from quarantine, decide an
exception, or invite anyone. The dashboard behind it holds six real analyses —
`ms`, `left-pad`, `lodash`, `esbuild`, `chalk`, `semver` — produced by running
the actual engine against the live npm registry, not seeded rows.

There is **no default credential anywhere in this repository**. The demo account
exists only when a deployment is seeded with `SEED_DEMO_ACCOUNT=true` and a
`DEMO_PASSWORD` chosen for that instance, and the seed refuses a password that
fails the same strength policy the registration form applies. A credential
published for one specific read-only instance is a different object from a
guessable default shipped to everyone who clones the project — the second is a
vulnerability in every deployment at once.

To run your own, see [`DEPLOYMENT.md`](./DEPLOYMENT.md).

## Scripts

| Script               | What it does                           |
| -------------------- | -------------------------------------- |
| `npm run dev`        | Dev server                             |
| `npm run build`      | Production build (`standalone` output) |
| `npm run start`      | Serve the production build             |
| `npm run lint`       | ESLint flat config                     |
| `npm run typecheck`  | `tsc --noEmit`                         |
| `npm run test`       | Vitest unit suite                      |
| `npm run test:e2e`   | Playwright end-to-end suite            |
| `npm run db:migrate` | `prisma migrate dev`                   |
| `npm run db:seed`    | `prisma db seed`                       |
| `npm run db:studio`  | `prisma studio`                        |
| `npm run format`     | Prettier                               |

## Layout

```
app/                 Routes. Server Components by default.
components/ui/       shadcn/ui primitives.
components/shared/   Application components (shell, tables, viewers, badges).
lib/                 Framework-free modules.
  constants.ts       Verdict scale and the six signal families.
  diff.ts            Bounded line diff for provenance reporting.
  env.ts             Zod-validated environment contract.
  errors.ts          AppError hierarchy.
  logger.ts          pino, with secret redaction.
  safe-display.ts    Guards for rendering package-derived strings.
  utils.ts           `cn`.
middleware.ts        Security headers, CSP nonce, route protection.
tests/unit           Vitest.
tests/e2e            Playwright.
```

Layering is strict and enforced by review: `app/(routes)` → `lib/services/*` →
`lib/db`. Components never touch Prisma. Every service function takes
`ctx: { userId, orgId, role }` first and enforces tenant isolation itself.

## Signal families

| Family                         | Prefix  | What it looks at                                        |
| ------------------------------ | ------- | ------------------------------------------------------- |
| Install-time execution         | `Q-INS` | Lifecycle scripts and what they reach for               |
| Obfuscation & evasion          | `Q-OBF` | Entropy, encoded payloads, `eval`, Trojan Source        |
| Dangerous capability           | `Q-CAP` | Process/socket/credential access vs. declared purpose   |
| Identity & typosquatting       | `Q-TYP` | Edit distance, homoglyphs, dependency-confusion posture |
| Maintainer & release forensics | `Q-MNT` | Dormancy breaks, fresh maintainers, cadence anomalies   |
| Provenance & integrity         | `Q-PRV` | Tarball-vs-source diffing, binary blobs, attestation    |

Verdicts: `KNOWN_MALICIOUS` · `LIKELY_MALICIOUS` · `SUSPICIOUS` · `LOW_RISK` ·
`CLEAN`, each reported with a confidence figure derived from how much of the
package the engine could actually inspect.

## Security posture

- Strict CSP with a per-request nonce, no `unsafe-inline` in production.
- HSTS, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`,
  `Permissions-Policy` on every response.
- Argon2id password hashing, TOTP second factor, 30-minute idle and 12-hour
  absolute session lifetimes.
- Every string lifted from a package is treated as hostile on render: bidi and
  zero-width characters stripped, lengths bounded, never
  `dangerouslySetInnerHTML`.
- Errors leave the server through the `AppError` hierarchy — stable codes only,
  never stack traces or raw upstream text.

Our own threat model is published at `/security`.

## Accessibility & design

Dark-first developer-tool aesthetic: zinc/slate neutrals, a single blue accent,
monospace for every package name, version, hash and code excerpt. Verdict colour
is never the only channel — label and icon carry the same meaning. Targets WCAG
2.1 AA and is responsive from 360px.
