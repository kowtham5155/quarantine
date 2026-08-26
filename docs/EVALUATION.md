# Evaluation

Four defects found by measuring this engine against real published code, with
the method, the numbers before and after, and what each one means for anyone
relying on a verdict.

Every measurement here is reproducible from this repository. Nothing in it was
executed, imported or installed: files are parsed, walked and read as bytes,
which is the same constraint the engine itself works under.

**A note on what is not here.** There is a labelled corpus in
`prisma/seed-data/corpus.ts` — 8 documented historical incidents, 16 synthetic
campaign samples, 36 clean negatives — but it stores _labels_, not artefacts,
and sixteen of its malicious entries no longer exist on npm. No precision figure
below comes from it. Where a corpus was needed, the corpus is this project's own
`node_modules`: 570 real, published, installed packages.

---

## Finding 1 — `Q-CAP-001` fired on `regex.exec()`

**The rule.** `Q-CAP-001` reports a package reaching for process execution. It
has two paths: an import path (`require('child_process')` and friends) and a
member-expression fallback for code that reaches `exec` without a recognisable
import. The fallback matched any member expression ending in
`exec|execSync|spawn|spawnSync|fork|execFile|execFileSync`.

`RegExp.prototype.exec` ends in `.exec`. So does `String.prototype.match`'s
common companion idiom, and so does every parser, matcher and templating library
on npm. `separator.exec(string)` in lodash was being reported as process
execution.

**Why it mattered more than it looks.** `Q-CAP-001` is one of three inputs to
the `obfuscated-exec-with-exfil` hard trigger. A minified bundle that uses a
regex, imports `dns`, and trips any obfuscation rule was forced to
`LIKELY_MALICIOUS` — a false "do not install" on an ordinary package.

**Method.** Ground truth is computed independently of the rule under test: a
package genuinely reaches for process execution when an AST walk finds
`child_process` being loaded anywhere in it. Each variant is then scored on
whether `Q-CAP-001` fires for that package. Corpus: 570 packages.
Script: [`scripts/measure-capability-precision.ts`](../scripts/measure-capability-precision.ts).

### Original run

Recorded in `BUILD_LOG.md` at the time the defect was found:

| variant                              |  TP |  FP |  FN | precision |
| ------------------------------------ | --: | --: | --: | --------: |
| A — original, any exec-family member |  29 |  64 |   0 | **0.312** |
| B — drop bare `exec`                 |  29 |   4 |   0 |     0.879 |
| C — drop bare `exec` and `fork`      |  29 |   1 |   0 | **0.967** |

**69% of `Q-CAP-001` firings were false positives**, every one a regex `.exec`:
`picomatch`, `semver`, `chalk`, `eslint`, `prettier`, `react-dom`, `acorn`,
`js-yaml`, `dotenv`, `undici` and 54 others.

That run initially reported **15 missed detections**. All 15 were `/regex/.exec`
— a defect in the measurement, not in the rule. Corrected ground truth gave 0,
and the recall column has been 0 false negatives in every run since. The lesson
is recorded here rather than quietly dropped: the first number a measurement
produces is a claim about the measurement as much as about the thing measured.

### Current run, against the shipped fix

The original measurement recommended variant B and deliberately left the fix
undone, on the grounds that narrowing a rule changes verdicts and is a product
decision. What eventually shipped is neither B nor C: bare `exec` and `fork`
fire only when the receiver names the module (`child_process`, `childProcess`,
`cp`, `proc`), while the unambiguous names (`execSync`, `spawnSync`, `spawn`,
`execFile`, `execFileSync`) still fire alone. That keeps `cp.exec(...)` — which
C drops — without keeping `separator.exec(...)`.

Re-running the measurement with variant D added, and with the ground-truth
correction described in Finding 1a below:

| variant                              |     TP |    FP |    FN | precision |    recall |
| ------------------------------------ | -----: | ----: | ----: | --------: | --------: |
| A — original, any exec-family member |     28 |    60 |     0 |     0.318 |     1.000 |
| B — drop bare `exec`                 |     28 |     2 |     0 |     0.933 |     1.000 |
| C — drop bare `exec` and `fork`      |     28 |     0 |     0 |     1.000 |     1.000 |
| **D — shipped, receiver-gated**      | **28** | **0** | **0** | **1.000** | **1.000** |

The small differences from the original run (28 loading packages rather than 29,
A at 0.318 rather than 0.312) come from this script bounding itself to 60 files
and 2MB per package so one enormous dependency cannot dominate the run. The
shape is unchanged and reproduces cleanly.

**Precision 0.312 → 1.000 on this corpus, with zero recall lost.** Read
"1.000" as "no false positive in 570 packages", not as a general claim: it is
one corpus, and its ground truth is a definition, not an oracle.

### Finding 1a — the last false positive was the ground truth's fault

Variants C and D each showed exactly one remaining false positive: `rolldown`.
It is not one. `rolldown` ships

```js
const childProcess = __require("child_process");
childProcess.execFileSync(...)
```

`__require` is a bundler-renamed `require` produced by `createRequire`. The
engine's `collectImports` only recognises the identifier `require`, so the
import path missed it — and so did a ground truth that used the same definition.
The member fallback is what caught it. Correcting ground truth to accept any
call taking `child_process` as its string-literal argument, whatever the callee
is named, moves `rolldown` from FP to TP and gives the table above.

Two things follow, and both are worth more than the extra 0.036 of precision:

1. **The fallback is not redundant.** It was the only path that detected
   `rolldown`. The original measurement concluded the fallback's unique
   contribution was the indirect case, measured at 0 samples; this is a second
   unique contribution, measured at 1.
2. **Renamed loaders defeat the import path.** Any bundled package that renames
   `require` is invisible to `collectImports`. Measured impact: 1 of 570
   packages. Not fixed; recorded as a limitation below.

---

## Finding 2 — `Q-CAP-004` fired on `JSON.stringify` of anything

**The defect.** `Q-CAP-004` reports wholesale environment access — the
exfiltration shape, where a package enumerates every variable rather than
reading the one it needs. It tested whether the **whole file** contained the
text `process.env`, and then fired on _any_ `Object.keys`, `Object.entries`,
`Object.values`, `Object.assign` or `JSON.stringify` call in that file.

**Method.** Full analysis of `esbuild@0.28.2` through the running application
against the live npm registry, before and after, reading the persisted
`SignalHit` rows.

**Before.** 11 hits, severity `CRITICAL`, weight 8 each, on calls including
`JSON.stringify` of a version string in `install.js` and `Object.keys` of an
options object in `lib/main.js`. None of them touched the environment. Total
hits on the package: 19.

**After.** The rule inspects the call's own arguments —
`JSON.stringify(process.env)`, `Object.assign({}, process.env)` and
`{ ...process.env }` fire; nothing else does. Total hits: **19 → 9**. The one
surviving `Q-CAP-004` is real: `install.js:181` spreads the environment into a
child process.

**What it means.** A `CRITICAL` weight-8 signal is one of the heaviest inputs to
the weighted score. Ten spurious copies of it on a package as ordinary as a
build tool is the difference between a report someone acts on and a report
someone learns to ignore. The corrected rule still catches the behaviour it was
written for.

---

## Finding 3 — the SSRF guard made GitHub unreachable on NAT64 networks

**The defect.** The guard blanket-blocked the well-known NAT64 prefix
`64:ff9b::/96`. On any network behind DNS64 — which is what a NAT64-only network
gives you — the resolver _synthesises_ an address in that prefix for every name
without real IPv6. GitHub therefore resolved to two addresses:

```
api.github.com        64:ff9b::14cf:4955    20.207.73.85
codeload.github.com   64:ff9b::14cf:4958    20.207.73.88
```

The last 32 bits of `64:ff9b::14cf:4955` _are_ `20.207.73.85`, which is GitHub.
Resolution is all-or-nothing by design — a name that resolves to one public and
one private address is a rebinding attempt — so one synthesised address refused
the whole host. Both GitHub hosts, identically.

`registry.npmjs.org` and `raw.githubusercontent.com` publish real AAAA records,
receive no synthesised one, and passed. That is why tarball downloads always
worked and only the repository read failed, and why the symptom presented as
"provenance is broken" rather than "the network is unusual".

**Consequence.** Every provenance check returned `REPO_UNREACHABLE`, every
analysis was marked `PARTIAL`, and confidence was reduced on every verdict the
system produced. The failure was silent in the sense that mattered: it looked
like a correctly-handled degradation, and it had a plausible cover story.

**The fix.** NAT64 (`64:ff9b::/96`), 6to4 (`2002::/16`) and IPv4-mapped
(`::ffff:0:0/96`) addresses all carry an IPv4 address in their low bits. The
guard now decodes it and applies the ordinary IPv4 rules:

| address              | embedded IPv4   | verdict                      |
| -------------------- | --------------- | ---------------------------- |
| `64:ff9b::14cf:4955` | 20.207.73.85    | allowed — GitHub             |
| `64:ff9b::a9fe:a9fe` | 169.254.169.254 | **refused** — cloud metadata |
| `64:ff9b::a00:1`     | 10.0.0.1        | **refused** — RFC1918        |
| `2002:ac10:1::1`     | 172.16.0.1      | **refused** — RFC1918        |
| `::ffff:127.0.0.1`   | 127.0.0.1       | **refused** — loopback       |

Pinned by tests in both directions in `tests/unit/fetcher.test.ts`.

**This is stricter than what it replaced, not looser.** The blanket block only
ever covered the _well-known_ prefix. RFC 6052 also allows operator-specific
NAT64 prefixes, and an address in one of those carrying `169.254.169.254` would
have passed the old check and is caught by the new one.

`GET /api/diagnostics/egress` reports what a given deployment can reach: every
resolved address, the guard's verdict on each, and a live probe of the GitHub
API. It requires the `CRON_SECRET` bearer and takes no caller-supplied host — an
authenticated endpoint that resolves an arbitrary name is an SSRF oracle with a
login page in front of it.

---

## Finding 4 — `Q-PRV-003` called every built package malicious

**The rule.** `Q-PRV-003` fires when the published tarball contains runnable
files that the source repository at the matching tag does not. This is the
`event-stream` signature — code no reviewer ever saw, shipped to every machine
that installs the package — and it is a **hard trigger**: one firing reaches
`LIKELY_MALICIOUS` on its own, by design.

**How it surfaced.** It could not surface at all while the repository was
unreachable (Finding 3). The moment the comparison actually ran,
`lodash@4.17.21` scored `LIKELY_MALICIOUS`. This would have appeared on the
first deploy to any network where GitHub resolves normally.

**Why.** It is also exactly what a _built_ package looks like. lodash publishes
148 repository files as more than a thousand generated per-method modules. The
tarball is generated from the source, not copied from it.

**The first fix failed.** Requiring the extra files to be a small share of the
tarball handled lodash — and then `esbuild@0.28.2` scored `LIKELY_MALICIOUS`
instead. esbuild publishes two runnable files, `install.js` and `lib/main.js`,
both compiled from TypeScript in its repository. With so few files, no ratio
test can see the build. A discriminator that works on large builds and fails on
small ones is not a discriminator.

**What works.** Ask the _repository_ whether it builds anything: a `tsconfig`, a
bundler or Babel config, a `Makefile`, a `go.mod`, a `Cargo.toml`, or any
non-declaration TypeScript, JSX, Svelte or Vue source. A repository with a build
system is expected to publish files it does not itself contain. A repository
without one that ships an extra runnable file is unexplained — and
`flatmap-stream`, plain JavaScript published from plain JavaScript, still fires.

**Skipped, not downgraded.** When a build is detected the rule is _skipped_.
Firing it at low confidence would not have worked: the hard trigger reads
whether the rule fired, not how sure it was. The check's status stays
`DIVERGENT` — the trees genuinely differ — and `diffSummary.unverifiable`
records why, so the report says "published from a build — not directly
comparable" instead of aiming event-stream copy at a legitimate publisher.

**Verified end to end** through the running application against the live
registry and the live GitHub API:

| package          | provenance                   | tag       | repo files | verdict  |
| ---------------- | ---------------------------- | --------- | ---------: | -------- |
| `ms@2.1.3`       | **MATCH**                    | `2.1.3`   |          9 | CLEAN    |
| `left-pad@1.3.0` | **MATCH**                    | `v1.3.0`  |         11 | CLEAN    |
| `lodash@4.17.21` | **DIVERGENT** (build output) | `4.17.21` |        148 | LOW_RISK |
| `esbuild@0.28.2` | **DIVERGENT** (build output) | `v0.28.2` |        351 | LOW_RISK |

`Q-PRV-004`, which compares every file the two trees _share_, is unaffected and
still reports esbuild's modified `README.md` and lodash's modified
`package.json`.

**Stated limitation: a build whose output is also tampered with lands in the
skipped branch.** Separating those two cases requires reproducible builds, not
file diffing. Comparing a built artefact against source can tell you the files
differ; it cannot tell you which difference was intended. The other five
families still read every byte of every file in the archive, so the injected
code is not unobserved — it is only unobserved _by this rule_.

### Two smaller corrections found alongside

- `ProvenanceCheck.repoUrl` and `.gitRef` were never written. Every row claimed
  a result without recording what it had compared against. A `MATCH` nobody can
  attribute to a specific tag is not evidence.
- An **archived** repository was reported as `REPO_UNREACHABLE`, discarding a
  comparison that had run. `left-pad@1.3.0` compared clean against its archived
  repository and displayed as unchecked. Archived and unreachable are now
  distinguished by whether the comparison actually ran.

---

## Limitations

Stated because a detection tool that only advertises what it catches is telling
half the story.

- **Indirect capability access through a non-identifier receiver is
  undetected.** `require('./vendor').execSync(...)` flattens to no
  identifier-rooted member expression, so the fallback never sees it. Reachable
  in principle. **Measured impact: 0 of 570 packages** — the import path already
  covers every direct form, including the inline one-liner, because
  `collectImports` walks for any `require(<string literal>)` anywhere in the
  tree.
- **Renamed module loaders defeat the import path.** `__require('child_process')`
  in bundled output is not recognised as an import (Finding 1a). **Measured
  impact: 1 of 570 packages**, and in that instance the member fallback caught
  it anyway.
- **Thresholds are provisional.** The verdict bucket boundaries were chosen, not
  fitted. A score near a boundary is an opinion. Fitting them needs the labelled
  corpus to hold artefacts rather than labels.
- **The labelled corpus has never been run.** See the note at the top. No
  precision or recall figure in this document is derived from it.
- **One ecosystem is properly covered.** npm is complete; PyPI is implemented
  but has had far less real traffic through it, and none of the measurements
  here touch it.
- **Provenance covers GitHub only.** GitLab, Bitbucket and self-hosted git
  report as unsupported, which is reported as its own state rather than as a
  failed comparison.

---

## Reproducing

```bash
npx tsx scripts/measure-capability-precision.ts   # Finding 1, ~1 min over node_modules
npm run test                                      # 539 unit tests, includes Findings 1 and 3
```

Findings 2 and 4 were measured by running full analyses through the application
against the live registry and reading the persisted `SignalHit` and
`ProvenanceCheck` rows. `BUILD_LOG.md` records each run with its date.
