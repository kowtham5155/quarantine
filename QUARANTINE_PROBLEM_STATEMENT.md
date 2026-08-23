# Quarantine — Pre-Install Supply Chain Malware Detection for Open-Source Dependencies

**Capstone / Portfolio Problem Statement | Domain: Software Supply Chain Security · Application Security**

---

## 1. Problem Statement

Every dependency scanner in common use — `npm audit`, Dependabot, Snyk, Trivy — answers one question: *does this package contain a **known, published** vulnerability?* They work by matching package names and versions against a CVE database.

That is a fundamentally reactive model, and it has a structural blind spot: **a CVE only exists after someone has already found, reported, triaged, and published the flaw.** For a deliberately malicious package, that process takes days to months — and the entire purpose of a supply chain attack is to execute in the window before anyone notices.

Every major open-source supply chain attack has walked through exactly this gap:

| Incident | Mechanism | Time undetected |
|---|---|---|
| `event-stream` | Maintainer handed control to an attacker, who published a version whose tarball contained code not present in the GitHub repository | ~2.5 months |
| `ua-parser-js` | Maintainer's npm account hijacked; malicious versions with a `preinstall` script published | hours, but ~7M weekly downloads |
| `node-ipc` | Trusted maintainer shipped destructive payload in a patch release | days |
| `xz-utils` | Multi-year social-engineering campaign; malicious payload hidden in test fixture binaries, absent from the visible source | ~2 years |

In every case, `npm audit` returned **zero findings** at the moment of maximum exposure. The signals that would have caught them were all present and observable — an install script, an obfuscated blob, a tarball that didn't match the repository, a maintainer added last week — but nothing was looking at them.

### The gap

> There is no accessible tool that assesses whether a package is **actively malicious right now**, at the moment you are about to install it, using behavioural and provenance evidence rather than a vulnerability database.

Commercial products in this space (Socket, Phylum, Endor Labs) exist and are effective — which validates the problem — but they are closed, priced for enterprises, and unavailable to the individual developers, students, and small teams who install the overwhelming majority of packages.

---

## 2. Proposed Solution

**Quarantine** analyses the *actual published artefact* — not a database entry — and returns a verdict before the package reaches a developer's machine or a CI runner.

Given a package name and version, an uploaded lockfile, or a connected repository, the engine downloads the real tarball from the registry and evaluates it across six independent signal families:

### Signal family 1 — Install-time execution
The highest-weight family, because it is where nearly all real npm malware lives. A library has almost no legitimate reason to execute code at install time.

- Presence of `preinstall` / `install` / `postinstall` lifecycle scripts
- Install scripts invoking `curl`, `wget`, `bash -c`, `powershell`, `node -e`, or base64 decoding
- Install scripts reading `~/.npmrc`, `~/.ssh`, `~/.aws`, `.env`, `/etc/passwd`
- Install scripts making outbound network calls or writing outside the package directory

### Signal family 2 — Obfuscation and evasion
- Shannon entropy per file above an empirically-tuned threshold
- Base64 or hex string literals exceeding 1 KB
- `eval()`, `new Function()`, `require(atob(...))`
- Hex-encoded string arrays with an accompanying decoder function — the canonical output signature of common JS obfuscators
- Bidirectional Unicode control characters (Trojan Source, CVE-2021-42574)
- Minified files with no corresponding source and no `.min` in the filename

### Signal family 3 — Dangerous capability in a package that shouldn't need it
Capability is contextual: `child_process` in a build tool is normal; in a string-formatting utility it is an alarm.

- `child_process`, `vm`, `net`, `dgram`, `dns` imports
- Wholesale iteration of `process.env` — the environment-exfiltration pattern
- Reads of credential and wallet paths (`.ethereum`, `wallet.dat`, keychain paths)
- Hardcoded IP addresses, or Discord/Telegram webhook URLs — both extremely common exfiltration channels in observed npm malware

### Signal family 4 — Identity and typosquatting
- Damerau–Levenshtein distance ≤ 2 from any of the top 5,000 packages by download count
- Homoglyph and Unicode-confusable substitution
- Separator manipulation (`node-fetch` / `nodefetch` / `node_fetch`)
- Scope confusion (`@types/foo` vs `@typesfoo`)
- Combosquatting (`react-dom-router`)
- Dependency-confusion posture: a public package whose name matches internal-registry naming conventions

### Signal family 5 — Maintainer and release forensics
- Dormancy break: package inactive for months, then a sudden release
- Maintainer added within N days of the release under evaluation
- Maintainer account age, total package count, publish history
- Sole maintainer on a high-download package (takeover exposure)
- Version published out of semver order, or an anomalous version jump
- Release cadence anomaly against the package's own history

### Signal family 6 — Provenance and integrity
The family that would have caught `event-stream` and `xz`.

- Missing `repository` field, or a repository URL that 404s or is archived
- **Tarball-versus-source diffing:** fetch the git tag corresponding to the published version and diff its contents against the published tarball. *Files present in the tarball but absent from the repository is the event-stream signature.*
- Binary blobs in a pure-source package
- Absent npm provenance attestation (SLSA / Sigstore) where the ecosystem supports it
- `files` / `.npmignore` configuration shipping unexpected content

---

## 3. The Verdict Model

A linear 0–100 score is the wrong abstraction here, and saying so is a defensible design decision worth making explicitly.

Real detection engines combine **weighted evidence** with **hard triggers**, because some single signals are dispositive regardless of everything else. An install script that base64-decodes a payload and POSTs `process.env` to a hardcoded IP is malicious no matter how healthy the maintainer history looks.

```
Verdict ∈ { CLEAN, LOW_RISK, SUSPICIOUS, LIKELY_MALICIOUS, KNOWN_MALICIOUS }

hard_triggers = any([
  install_script_with_network_exfiltration,
  credential_path_read_in_install_script,
  tarball_contains_executable_code_absent_from_source,
  known_malicious_hash_match,
])
if hard_triggers: verdict = LIKELY_MALICIOUS (minimum)

else:
  weighted = Σ (signal.weight × signal.confidence × context_modifier)
  verdict  = threshold_bucket(weighted)

confidence = f(signals_fired, corroboration_across_families, analysis_completeness)
```

Every verdict returns the **full signal list — fired and not fired** — with the exact file, line number, and code excerpt for each hit. A verdict a developer cannot inspect is a verdict they will eventually ignore.

---

## 4. Novelty and Contribution

1. **Pre-install behavioural detection instead of post-disclosure CVE matching.** A different question from the one every free tool currently answers.
2. **Tarball-versus-source provenance diffing.** The single highest-value check in the system, absent from all free tooling, and the specific mechanism behind the two most severe supply chain incidents on record.
3. **Context-aware capability scoring.** The same import is benign or alarming depending on the package's declared purpose — a modifier no signature-based scanner applies.
4. **Hybrid hard-trigger and weighted-evidence verdict model** with full explainability down to the source line.
5. **Cross-package campaign clustering.** Malicious packages are published in families sharing exfiltration endpoints, maintainer accounts, and code fingerprints. Clustering surfaces the campaign rather than the individual package.

---

## 5. Objectives

- **O1** — Implement a static analysis engine covering six signal families and ~40 detection rules.
- **O2** — Implement tarball-versus-source provenance diffing against GitHub.
- **O3** — Implement a typosquat detection model over the top 5,000 packages by download count.
- **O4** — Design and implement the hybrid hard-trigger / weighted-evidence verdict model with full explainability.
- **O5** — Build a multi-tenant, RBAC-enforced platform with policy enforcement, quarantine workflow, and exception management.
- **O6** — Ship CI integration: a CLI and a GitHub Action that fail a build on policy violation.
- **O7** — Evaluate against a labelled corpus of known-malicious and known-clean packages; report precision, recall, and false-positive rate.
- **O8** — Deploy to a public live URL with CI/CD, automated testing, and hardened production configuration.

---

## 6. Evaluation Methodology

This is what separates a portfolio project from a class assignment, and it is the part an interviewer will respect most.

**Corpus construction**
- *Positive class:* known-malicious package versions drawn from published supply-chain-attack datasets and historical incident disclosures.
- *Negative class:* the top 500 packages by download count, plus a random sample of 500 low-download packages — the latter matters because typosquat detectors trivially over-fire on obscure legitimate packages.

**Metrics reported**
- Precision, recall, F1 per signal family and overall
- False-positive rate on the negative class, reported separately for popular and obscure packages
- Per-signal contribution analysis — which rules actually carry the model
- Mean and p95 analysis latency per package

**Why report the false-positive rate prominently:** a supply chain scanner that cries wolf gets disabled in week two. Being explicit about this trade-off — and tuning for it — is the mark of someone who has thought about operating a security tool, not just building one.

---

## 7. Why This Is Job-Ready

**It maps to roles that are actively hiring.** Application Security Engineer, Product Security Engineer, DevSecOps, Supply Chain Security, Detection Engineering. Supply chain security is a named priority in essentially every mature security organisation.

**It demonstrates the skills those roles screen for:**

| Skill | Where it shows |
|---|---|
| Static analysis / AST work | The signal engine |
| Detection engineering | Rule design, hard triggers, FP tuning |
| Threat modelling | Capability-in-context scoring |
| Secure system design | SSRF-guarded fetching, sandboxed analysis, tenant isolation |
| Data engineering | Registry ingestion, caching, corpus management |
| Full-stack product engineering | 60+ route platform |
| Developer experience | CLI and GitHub Action |
| Measurement discipline | Precision/recall evaluation |

**It gives you interview answers, not just a link.** "Why not just use npm audit?" "How do you avoid false positives?" "What would you do about a maintainer who legitimately needs an install script?" These are real questions with real answers you will have already worked through.

**Resume lines it earns you:**
- Built a static analysis engine detecting the attack class behind the `event-stream`, `ua-parser-js`, and `xz-utils` supply chain compromises, achieving *X*% precision at *Y*% false-positive rate against a labelled corpus of 1,000+ packages.
- Implemented tarball-versus-source provenance diffing to detect published artefacts diverging from their declared repository source.
- Shipped a CLI and GitHub Action enforcing organisational dependency policy in CI.

---

## 8. Scope Boundaries

**In scope:** static analysis of published artefacts; provenance verification; typosquat detection; maintainer forensics; verdict modelling; policy enforcement and quarantine workflow; multi-tenant platform; CI integration; evaluation.

**Out of scope, deliberately:**
- **Dynamic analysis / sandboxed execution of packages.** Correct in principle, but executing untrusted code requires isolation infrastructure well beyond free-tier hosting, and doing it badly is worse than not doing it. Stated as future work.
- Automated remediation or auto-patching.
- Analysis of private or internal registries.

**Safety note:** the system downloads untrusted archives. It must **never execute them**. Extraction is bounded (size cap, entry-count cap, path-traversal guard against zip-slip), analysis is purely static, and all fetching passes through an SSRF-guarded client. This is a security tool that handles malware samples — its own threat model is part of the design, and is a strong thing to be able to discuss.
