# Deploying Quarantine

One Render Web Service and one Neon Postgres database. No worker, no broker, no
object store — the queue drains on a cron ping and analysis runs inline in the
request that asks for it.

Target: about 20 minutes from a clean checkout to a working URL.

---

## 1. Database — Neon

Render's free Postgres expires after 30 days; Neon's free tier does not. Use
Neon.

1. [neon.tech](https://neon.tech) → **New Project**.
2. Copy **both** connection strings from the dashboard:
   - the **pooled** one (host contains `-pooler`) → `DATABASE_URL`
   - the **direct** one (same credentials, no `-pooler`) → `DIRECT_URL`

Both are needed. Neon serves the pooled connection through PgBouncer in
transaction mode, which cannot run migrations; Prisma uses `DIRECT_URL` for
`migrate` and the pooled one for everything else. Give it a pooled URL only and
the deploy fails during migration with a prepared-statement error.

### Locally: two files, and the Prisma CLI only reads one of them

On Render both variables are set in the service environment and this does not
arise. Locally it does, once, for everybody:

| file         | read by                                              | contents                                      |
| ------------ | ---------------------------------------------------- | --------------------------------------------- |
| `.env.local` | the Next.js runtime — dev server, build, `npm start` | every variable in the table below             |
| `.env`       | the Prisma CLI                                       | `DATABASE_URL` and `DIRECT_URL`, nothing else |

`.env.local` is a **Next.js** convention, not a dotenv standard, and the Prisma
CLI has never heard of it. So with only `.env.local` present:

```
$ npx prisma migrate deploy
Error: Environment variable not found: DIRECT_URL
```

Create `.env` alongside it holding just the two connection strings, copied
verbatim from `.env.local`. Both files are gitignored (`.gitignore` lines 8–10)
and neither is tracked.

Keep the two copies identical. If they drift, the application and your
migrations are pointed at different databases, and the symptom is a missing
column somewhere unrelated rather than anything naming the real cause.

The `npm run db:*` scripts sidestep this entirely — they invoke Prisma through
`dotenv -e .env.local` — so `npm run db:deploy` works with or without `.env`. It
is the bare `npx prisma ...` form that needs it.

---

## 2. Secrets

Generate these locally and keep them — Render will not show a secret again once
saved.

```bash
openssl rand -base64 32   # AUTH_SECRET
openssl rand -hex 32      # CRON_SECRET
```

### `GITHUB_TOKEN` — get one, it is not optional in practice

A **fine-grained personal access token with no scopes and no repository access
at all**. It is used purely to raise a rate limit against public endpoints:
GitHub Settings → Developer settings → Personal access tokens → Fine-grained →
_Generate new token_, resource owner yourself, **Repository access: Public
repositories (read-only)**, no account permissions. Nothing it can do to a
private repository, because it can see none.

**Without it the GitHub API allows 60 requests per hour, per IP.** Every
provenance check spends at least two — one for the repository, one to resolve
the tag — so roughly **25 analyses exhausts the hour**. After that the
repository read fails, `Q-PRV-002` fires, and every subsequent analysis returns
`REPO_UNREACHABLE` and is marked `PARTIAL` with reduced confidence.

That degradation is silent in the way that matters: it looks like a correctly
handled failure, not like a misconfiguration, and it is indistinguishable on the
report from a repository that genuinely does not respond. A demo that runs a
dozen scans will hit it. With a token the limit is 5,000 requests per hour.

Verify which one you are on after deploying — see §6.

---

## 3. Render Web Service

**New → Web Service**, connect the repository, then:

| Setting           | Value                                                                                       |
| ----------------- | ------------------------------------------------------------------------------------------- |
| Runtime           | Node                                                                                        |
| Build command     | `npm ci --include=dev && npx prisma generate && npx prisma migrate deploy && npm run build` |
| Start command     | `npm run start`                                                                             |
| Health check path | `/api/health`                                                                               |
| Instance type     | Free is enough to demo; it sleeps after 15 minutes idle                                     |

### `--include=dev` is not optional

`NODE_ENV=production` has to be set for the running service, and Render applies
service environment variables to the **build** as well. npm reads `NODE_ENV`:
under `production` it treats an install as `--omit=dev` and skips every
devDependency. In this project that is 374 packages, and it takes the build
tooling with it:

| package                                          | devDependency | needed for                                 |
| ------------------------------------------------ | ------------- | ------------------------------------------ |
| `tailwindcss`, `postcss`, `@tailwindcss/postcss` | yes           | compiling the stylesheet                   |
| `typescript`, `@types/*`                         | yes           | `next build` type-checks by default here   |
| `tsx`                                            | yes           | `scripts/seed-prod.ts` in the Render Shell |
| `prisma`                                         | yes           | `prisma generate` and `migrate deploy`     |

The failure this produces is not obvious from the message. It can surface as a
missing PostCSS plugin, or — on Node 20 — as

```
Error: <Html> should not be imported outside of pages/_document.
Error occurred prerendering page "/404".
```

which reads like an App Router bug and is nothing of the sort: with the CSS and
TypeScript pipeline missing, the build falls back to the pages-router error
page, and that page imports `_document`. There is no `pages/` directory in this
project and nothing here imports `next/document`. Chasing the error message
leads nowhere; the cause is the install.

`--include=dev` overrides the `NODE_ENV` inference explicitly, so the build gets
its tooling and the running service still has `NODE_ENV=production`.

### Environment variables

Set every one of these. The app validates them at boot through a Zod schema
(`lib/env.ts`) and refuses to start on a missing or malformed value, rather than
failing on the third request.

| Variable                | Required             | Value                                                                     |
| ----------------------- | -------------------- | ------------------------------------------------------------------------- |
| `DATABASE_URL`          | yes                  | Neon **pooled** connection string                                         |
| `DIRECT_URL`            | yes                  | Neon **direct** connection string, for migrations                         |
| `AUTH_SECRET`           | yes                  | `openssl rand -base64 32` — min 32 chars                                  |
| `AUTH_URL`              | yes                  | `https://<service>.onrender.com` — exact origin, no trailing slash        |
| `APP_URL`               | yes                  | Same as `AUTH_URL`                                                        |
| `CRON_SECRET`           | yes                  | `openssl rand -hex 32` — min 32 chars                                     |
| `GITHUB_TOKEN`          | strongly recommended | Fine-grained PAT, no scopes — see §2                                      |
| `NODE_ENV`              | yes                  | `production`                                                              |
| `NODE_VERSION`          | yes                  | `20` (the app requires ≥ 20.11)                                           |
| `PLATFORM_ADMIN_EMAILS` | no                   | Comma-separated emails allowed into `/admin`. Empty closes it to everyone |
| `SEED_DEMO_ACCOUNT`     | no                   | `true` to seed a read-only demo account — see §4                          |
| `DEMO_PASSWORD`         | with the above       | Password for that account. Never committed; checked against the policy    |
| `DEMO_EMAIL`            | no                   | Defaults to `demo@quarantine.dev`                                         |
| `LOG_LEVEL`             | no                   | `info` by default                                                         |

`AUTH_URL` and `APP_URL` must match the origin the browser actually uses. A
mismatch produces a login that appears to succeed and then bounces back to the
login page, because the session cookie was issued for a different origin.

---

## 4. Seed the rule catalogue

Once the first deploy is live, open the **Render Shell** and run:

```bash
npx tsx scripts/seed-prod.ts
```

This is not demo data. A `Rule` row carries the weight and severity the scorer
multiplies each signal by; with an empty catalogue the engine still runs and
still fires signals, but nothing scores and every verdict comes back wrong in
the same direction. Expect `rules total 41`.

The script is idempotent and non-destructive — run it on every deploy if you
like. It refreshes rule text and weights, and deliberately does **not** touch
`enabled` or `falsePositiveNotes` on rules that already exist, because those are
operator decisions and a deploy must not silently undo them.

Do **not** run `prisma/seed.ts` against a deployed database. That is the
development seed and it begins by truncating every table.

### The first account

Register it at `/register`. That creates the account, its organisation, and
makes the user the organisation's owner.

**There is no default credential in this repository, and no password written
down anywhere in it.** A guessable default shipped to everyone who clones the
project is a vulnerability in every deployment at once.

### Optional: a read-only demo account

For a deployment you intend to hand out a login for, set these before running
the seed:

```bash
SEED_DEMO_ACCOUNT=true DEMO_PASSWORD='<a strong password you choose for this instance>' npx tsx scripts/seed-prod.ts
```

Optionally `DEMO_EMAIL` to override the default `demo@quarantine.dev`.

What it does:

- Creates the **Quarantine Demo** organisation and one account in it with the
  **VIEWER** role. Viewer can read every surface and change nothing: no scans,
  no policy edits, no releasing a package from quarantine, no deciding an
  exception, no invitations. A visitor cannot alter what the next visitor sees.
  If the account is ever promoted, a later run puts it back to VIEWER.
- Refuses a weak `DEMO_PASSWORD`, using the same zxcvbn policy the registration
  form applies. A demo account on a public URL is still an account.
- Rewrites the password hash on every run, so rotating the credential is a
  redeploy rather than a database session.
- **Runs six real analyses** — `ms`, `left-pad`, `lodash`, `esbuild`, `chalk`,
  `semver` — through the same engine the scan page uses, so the dashboard has
  genuine verdicts in it rather than fabricated rows. About twenty seconds of
  network, skipped entirely on a second run. A package that fails to analyse is
  reported and skipped rather than failing the deploy.

The distinction that makes this safe: a password published for one specific
instance, attached to a read-only account, is a different object from a default
credential compiled into the source.

---

## 5. Cron

Two jobs at [cron-job.org](https://cron-job.org) (free):

| Schedule     | Request                                                                                                | Purpose                                                                    |
| ------------ | ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| every 10 min | `GET https://<service>.onrender.com/api/health`                                                        | Keeps a free instance from sleeping. A cold start is ~30s and looks broken |
| hourly       | `GET https://<service>.onrender.com/api/cron/analyses`<br>header `Authorization: Bearer <CRON_SECRET>` | Drains the analysis queue                                                  |

The queue exists for the analyses nobody is watching: a CLI call that hung up, a
project scan that expanded into forty package versions, a run whose request was
cut off. One invocation is bounded — it stops accepting new work after a budget
and leaves the rest `QUEUED` for the next tick, so it always finishes inside the
platform request timeout.

---

## 6. Verify the deployment

**Health.**

```bash
curl https://<service>.onrender.com/api/health
# {"status":"ok","engineVersion":"1.0.0","uptimeSeconds":7,
#  "checks":{"database":"ok","databaseLatencyMs":31}}
```

`503` with `"database":"unreachable"` means `DATABASE_URL` is wrong or the Neon
project is suspended. The real error is in the Render log with a correlation id;
the endpoint deliberately gives nothing away.

**Egress and the GitHub rate limit.** This is the check worth running, because
the network a deployment sits on is not the network you developed on:

```bash
curl -H "Authorization: Bearer <CRON_SECRET>" \
     https://<service>.onrender.com/api/diagnostics/egress
```

Look for:

- `provenanceReachable: true`
- `apiProbe.rateLimit` — **`5000`** means `GITHUB_TOKEN` is set and accepted;
  **`60`** means it is missing or rejected, and provenance will degrade under
  demo load exactly as described in §2.
- every host `accepted: true`. If GitHub is refused, the response shows each
  resolved address and which one the SSRF guard rejected — a NAT64 network
  synthesises `64:ff9b::` addresses that used to fail this check.

This route is temporary and gated behind `CRON_SECRET`. Delete
`app/api/diagnostics/egress/` once the deployment is settled.

**End to end.** Sign in, go to `/scan`, and scan `ms@2.1.3`. Expect `CLEAN`,
and a provenance status of `MATCH` against tag `2.1.3` on the package's
provenance tab. If provenance says `REPO_UNREACHABLE`, check the egress
diagnostic before anything else.

---

## Notes on the shape of this deployment

- **`output: 'standalone'`** is set in `next.config.ts`. Render's `npm run start`
  path works with it; note that `next start` prints a warning about standalone
  builds, which is expected and harmless here.
- **Native and filesystem-bound packages** — Prisma, `@node-rs/argon2`, `tar`,
  `pino` — are listed in `serverExternalPackages` and must stay there. They do
  not survive bundling.
- **Free instances sleep.** The first request after 15 idle minutes takes about
  30 seconds. The 10-minute health ping is what keeps a demo responsive.
- **Analysis runs inline** in the request that asks for it, streamed as NDJSON
  to the scan page. There is no worker to scale separately, and no queue broker
  to operate — which is a deliberate constraint of a single-service deployment,
  not an oversight.
