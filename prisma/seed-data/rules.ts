import { Severity, SignalFamily } from '@prisma/client';

/**
 * The detection rule catalogue.
 *
 * Weights are the *base* contribution to the weighted score before the context
 * modifier is applied. They are deliberately not uniform across families:
 * install-time execution carries the most weight because that is where nearly
 * all real npm malware lives, and identity signals carry the least because a
 * name that resembles a popular package is suggestive, never conclusive.
 */

export interface SeedRule {
  ruleId: string;
  family: SignalFamily;
  name: string;
  description: string;
  severity: Severity;
  baseWeight: number;
  remediation: string;
  references: string[];
  falsePositiveNotes?: string;
}

export const SEED_RULES: SeedRule[] = [
  // -------------------------------------------------------------------------
  // Family 1 — Install-time execution
  // -------------------------------------------------------------------------
  {
    ruleId: 'Q-INS-001',
    family: SignalFamily.INSTALL,
    name: 'Lifecycle script present',
    description:
      'The package declares a preinstall, install or postinstall script. These run automatically with the installing user’s privileges before any of the package’s code is imported, which makes them the single most abused execution surface in the npm ecosystem.',
    severity: Severity.MEDIUM,
    baseWeight: 3,
    remediation:
      'Install with --ignore-scripts and confirm the package still functions. If the script only compiles native bindings, that is expected for a native module; if the package is pure JavaScript, ask why it needs one at all.',
    references: [
      'https://docs.npmjs.com/cli/v10/using-npm/scripts',
      'https://blog.npmjs.org/post/141702881055/package-install-scripts-vulnerability',
    ],
    falsePositiveNotes:
      'Native modules (node-gyp, prebuild-install) legitimately need install scripts. The context modifier suppresses this heavily when the package declares binding.gyp or a prebuild dependency.',
  },
  {
    ruleId: 'Q-INS-002',
    family: SignalFamily.INSTALL,
    name: 'Install script invokes a shell or interpreter',
    description:
      'A lifecycle script shells out to curl, wget, bash -c, powershell, or node -e. Fetching and executing content at install time defeats every form of review that looked at the published tarball, because the payload is not in the tarball.',
    severity: Severity.CRITICAL,
    baseWeight: 9,
    remediation:
      'Do not install. Treat any machine that already ran this install as compromised: rotate npm tokens, SSH keys and cloud credentials that were readable by the installing user.',
    references: ['https://owasp.org/www-project-top-10-ci-cd-security-risks/'],
  },
  {
    ruleId: 'Q-INS-003',
    family: SignalFamily.INSTALL,
    name: 'Install script decodes an encoded payload',
    description:
      'A lifecycle script base64- or hex-decodes a string and executes or writes the result. Encoding exists here for exactly one reason: to prevent a reviewer or a naive scanner from reading what the script does.',
    severity: Severity.CRITICAL,
    baseWeight: 9,
    remediation:
      'Do not install. Decode the literal offline to establish what it would have done, and treat that as the blast radius.',
    references: ['https://cwe.mitre.org/data/definitions/506.html'],
  },
  {
    ruleId: 'Q-INS-004',
    family: SignalFamily.INSTALL,
    name: 'Install script reads a credential path',
    description:
      'A lifecycle script reads ~/.npmrc, ~/.ssh, ~/.aws, a .env file, or /etc/passwd. No legitimate build step needs the installing user’s long-lived secrets.',
    severity: Severity.CRITICAL,
    baseWeight: 10,
    remediation:
      'Do not install. Rotate every credential reachable from the paths named in the evidence, starting with npm and cloud provider tokens.',
    references: ['https://cwe.mitre.org/data/definitions/522.html'],
  },
  {
    ruleId: 'Q-INS-005',
    family: SignalFamily.INSTALL,
    name: 'Install script makes an outbound network call',
    description:
      'A lifecycle script opens a network connection. Combined with any credential or environment read, this is the exfiltration half of the most common npm attack chain.',
    severity: Severity.HIGH,
    baseWeight: 8,
    remediation:
      'Do not install. Block the endpoint named in the evidence at the egress firewall and search proxy logs for prior connections to it.',
    references: ['https://attack.mitre.org/techniques/T1195/002/'],
  },
  {
    ruleId: 'Q-INS-006',
    family: SignalFamily.INSTALL,
    name: 'Install script writes outside the package directory',
    description:
      'A lifecycle script writes to a path outside its own package root — a shell profile, a systemd unit, a cron entry, or another package’s directory. This is how install-time execution becomes persistence.',
    severity: Severity.CRITICAL,
    baseWeight: 9,
    remediation:
      'Do not install. On any machine that ran this, audit the written paths in the evidence for persistence artefacts.',
    references: ['https://attack.mitre.org/tactics/TA0003/'],
  },
  {
    ruleId: 'Q-INS-007',
    family: SignalFamily.INSTALL,
    name: 'Install entrypoint is obfuscated or minified',
    description:
      'The file a lifecycle script executes is minified or obfuscated with no readable source alongside it. Build output does not normally appear on the install path.',
    severity: Severity.HIGH,
    baseWeight: 7,
    remediation:
      'Do not install until the entrypoint has been deobfuscated and reviewed. Compare against the repository source if one exists.',
    references: ['https://cwe.mitre.org/data/definitions/656.html'],
  },

  // -------------------------------------------------------------------------
  // Family 2 — Obfuscation and evasion
  // -------------------------------------------------------------------------
  {
    ruleId: 'Q-OBF-001',
    family: SignalFamily.OBFUSCATION,
    name: 'File entropy above threshold',
    description:
      'Shannon entropy for the file exceeds the corpus-tuned threshold for its extension. High entropy in a .js file means the bytes are not source code: they are packed, encrypted or encoded.',
    severity: Severity.MEDIUM,
    baseWeight: 4,
    remediation:
      'Inspect the high-entropy region identified in the evidence. If it is a legitimate embedded asset (a wasm blob, a font, a source map) it should be in a separate file with an honest extension.',
    references: ['https://en.wikipedia.org/wiki/Entropy_(information_theory)'],
    falsePositiveNotes:
      'Minified bundles, source maps and embedded wasm all raise entropy legitimately. Threshold is tuned per extension against the clean half of the corpus, and the signal is suppressed when a matching unminified source file is present.',
  },
  {
    ruleId: 'Q-OBF-002',
    family: SignalFamily.OBFUSCATION,
    name: 'Oversized base64 or hex literal',
    description:
      'A single base64 or hex string literal exceeds 1 KB. Payloads are shipped as string literals because a string literal is not executable until something decodes it, which keeps it out of the reach of naive scanners.',
    severity: Severity.HIGH,
    baseWeight: 6,
    remediation:
      'Decode the literal offline and establish what it contains. Legitimate embedded assets belong in their own file, not in a string.',
    references: ['https://cwe.mitre.org/data/definitions/506.html'],
    falsePositiveNotes:
      'Inlined icons, test fixtures and certificate bundles produce large literals legitimately. Weight is reduced when the literal decodes to a known image or PEM header.',
  },
  {
    ruleId: 'Q-OBF-003',
    family: SignalFamily.OBFUSCATION,
    name: 'Dynamic code evaluation',
    description:
      'The package calls eval(), new Function(), or require() on a computed expression such as require(atob(...)). Each of these turns runtime data into executable code, which is what makes the tarball an unreliable description of what the package does.',
    severity: Severity.HIGH,
    baseWeight: 7,
    remediation:
      'Establish what is being evaluated. If the input is attacker-influenced or fetched at runtime, treat the package as arbitrary code execution.',
    references: ['https://cwe.mitre.org/data/definitions/95.html'],
    falsePositiveNotes:
      'Template engines, test frameworks and polyfills use dynamic evaluation legitimately. The context modifier accounts for the declared package purpose.',
  },
  {
    ruleId: 'Q-OBF-004',
    family: SignalFamily.OBFUSCATION,
    name: 'Encoded string array with decoder function',
    description:
      'A large array of hex- or base64-encoded strings sits alongside a function that indexes and decodes it. This is the canonical output signature of the common JavaScript obfuscators, and it is not something a human writes.',
    severity: Severity.HIGH,
    baseWeight: 7,
    remediation:
      'Run the decoder offline against the array to recover the original strings before making any trust decision about this package.',
    references: ['https://obfuscator.io/'],
  },
  {
    ruleId: 'Q-OBF-005',
    family: SignalFamily.OBFUSCATION,
    name: 'Bidirectional Unicode control characters',
    description:
      'The file contains bidi control characters. These reorder how source is displayed without changing how it is parsed, so reviewed code and executed code differ. Known as Trojan Source (CVE-2021-42574).',
    severity: Severity.CRITICAL,
    baseWeight: 8,
    remediation:
      'Do not install. View the file with bidi rendering disabled to see the true token order.',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-42574', 'https://trojansource.codes/'],
  },
  {
    ruleId: 'Q-OBF-006',
    family: SignalFamily.OBFUSCATION,
    name: 'Minified file with no source and no .min marker',
    description:
      'A file is minified, carries no .min in its name, and has no corresponding unminified source in the tarball. Honest build output announces itself; this does not.',
    severity: Severity.MEDIUM,
    baseWeight: 4,
    remediation:
      'Compare the file against the repository source. If the repository has no equivalent, treat it under Q-PRV-003 as well.',
    references: [],
    falsePositiveNotes:
      'Some publishers ship only bundled output by convention. Suppressed when the package declares a build script that plausibly produces the file.',
  },
  {
    ruleId: 'Q-OBF-007',
    family: SignalFamily.OBFUSCATION,
    name: 'Identifiers assembled by string concatenation',
    description:
      'Property or module names are built at runtime from concatenated fragments, for example "ch" + "ild_pro" + "cess". The only purpose of splitting an identifier this way is to prevent a static scanner from matching it.',
    severity: Severity.HIGH,
    baseWeight: 6,
    remediation:
      'Constant-fold the expressions in the evidence to recover the real identifiers, then re-evaluate the capability signals against them.',
    references: ['https://cwe.mitre.org/data/definitions/656.html'],
  },

  // -------------------------------------------------------------------------
  // Family 3 — Dangerous capability in context
  // -------------------------------------------------------------------------
  {
    ruleId: 'Q-CAP-001',
    family: SignalFamily.CAPABILITY,
    name: 'child_process import',
    description:
      'The package imports child_process. Whether this matters depends entirely on what the package claims to be: normal in a build tool, an alarm in a string-formatting utility.',
    severity: Severity.MEDIUM,
    baseWeight: 5,
    remediation:
      'Check the call sites in the evidence. Command strings built from package input, environment variables or network responses are the dangerous shape.',
    references: ['https://cwe.mitre.org/data/definitions/78.html'],
    falsePositiveNotes:
      'Build tools, CLIs and test runners use child_process routinely. The context modifier derives an expected-capability profile from keywords, description and dependents, and can reduce this weight to near zero.',
  },
  {
    ruleId: 'Q-CAP-002',
    family: SignalFamily.CAPABILITY,
    name: 'Raw socket module import',
    description:
      'The package imports net, dgram or dns. Raw socket access in a library that presents itself as a utility is a capability it has no stated use for.',
    severity: Severity.MEDIUM,
    baseWeight: 5,
    remediation:
      'Identify the destination host or port in the call sites. Hardcoded addresses should be treated together with Q-CAP-007.',
    references: [],
    falsePositiveNotes:
      'Network clients, proxies and service-discovery libraries need these modules by definition.',
  },
  {
    ruleId: 'Q-CAP-003',
    family: SignalFamily.CAPABILITY,
    name: 'vm module import',
    description:
      'The package imports node:vm. The vm module compiles and runs new code, which makes it functionally equivalent to eval with a nicer interface, and the sandbox it appears to offer is not a security boundary.',
    severity: Severity.HIGH,
    baseWeight: 6,
    remediation:
      'Establish what is being compiled. Treat any vm usage over runtime-fetched content as arbitrary code execution.',
    references: ['https://nodejs.org/api/vm.html#vm-executing-javascript'],
  },
  {
    ruleId: 'Q-CAP-004',
    family: SignalFamily.CAPABILITY,
    name: 'Wholesale process.env iteration',
    description:
      'The package enumerates the entire environment — Object.keys(process.env), JSON.stringify(process.env), or a spread of it — rather than reading the specific variables it needs. In CI the environment is where the secrets are, so this is the environment-exfiltration pattern.',
    severity: Severity.CRITICAL,
    baseWeight: 8,
    remediation:
      'Do not install in any environment holding credentials. Rotate every secret exposed to the build. Legitimate configuration reads name their variables.',
    references: ['https://attack.mitre.org/techniques/T1552/001/'],
    falsePositiveNotes:
      'Diagnostic and env-dumping tools do this by design. Suppressed when the package’s declared purpose is environment inspection and the result is not sent anywhere.',
  },
  {
    ruleId: 'Q-CAP-005',
    family: SignalFamily.CAPABILITY,
    name: 'Credential path read',
    description:
      'The package references ~/.ssh, ~/.aws, ~/.npmrc, a keychain path, or a browser credential store. These paths have no role in a package’s own functionality.',
    severity: Severity.CRITICAL,
    baseWeight: 9,
    remediation: 'Do not install. Rotate the credentials at every path named in the evidence.',
    references: ['https://attack.mitre.org/techniques/T1552/'],
  },
  {
    ruleId: 'Q-CAP-006',
    family: SignalFamily.CAPABILITY,
    name: 'Cryptocurrency wallet path read',
    description:
      'The package references a wallet location such as .ethereum, wallet.dat, Exodus, or a browser extension wallet directory. Wallet theft is the most direct monetisation available to a package with filesystem access.',
    severity: Severity.CRITICAL,
    baseWeight: 9,
    remediation:
      'Do not install. On any machine that ran this package, move funds to a new wallet from a clean device.',
    references: ['https://attack.mitre.org/techniques/T1005/'],
  },
  {
    ruleId: 'Q-CAP-007',
    family: SignalFamily.CAPABILITY,
    name: 'Hardcoded IP address in a network call',
    description:
      'A network call targets a literal IP address rather than a hostname. Legitimate services move, so they use DNS; hardcoded addresses avoid the DNS logging and blocklists that a hostname would attract.',
    severity: Severity.HIGH,
    baseWeight: 7,
    remediation:
      'Block the address at egress and search proxy and flow logs for prior connections to it.',
    references: ['https://attack.mitre.org/techniques/T1071/'],
    falsePositiveNotes:
      'Test fixtures, RFC 5737 documentation ranges and loopback addresses are excluded before this fires.',
  },
  {
    ruleId: 'Q-CAP-008',
    family: SignalFamily.CAPABILITY,
    name: 'Discord or Telegram webhook URL',
    description:
      'The package contains a Discord or Telegram webhook URL. Both are free, require no attacker infrastructure, and blend into normal HTTPS traffic, which is why they are the most common exfiltration channel in observed npm malware.',
    severity: Severity.CRITICAL,
    baseWeight: 9,
    remediation:
      'Do not install. Report the webhook to the platform, and treat any data reachable by the package as disclosed.',
    references: ['https://attack.mitre.org/techniques/T1567/'],
  },
  {
    ruleId: 'Q-CAP-009',
    family: SignalFamily.CAPABILITY,
    name: 'Native binary in a declared pure-JavaScript package',
    description:
      'The tarball contains a .node addon, an ELF/Mach-O/PE executable, or a shared library, while the manifest declares no native build. Compiled code cannot be reviewed by reading the tarball.',
    severity: Severity.HIGH,
    baseWeight: 7,
    remediation:
      'Do not install. Submit the binary named in the evidence for separate analysis; it is outside the scope of source review.',
    references: [],
  },

  // -------------------------------------------------------------------------
  // Family 4 — Identity and typosquatting
  // -------------------------------------------------------------------------
  {
    ruleId: 'Q-TYP-001',
    family: SignalFamily.TYPOSQUAT,
    name: 'Small edit distance from a popular package',
    description:
      'The package name is within Damerau–Levenshtein distance 2 of a package in the top 5,000 by download count, while having a tiny fraction of its downloads. This is the shape of a name that exists to catch typing mistakes.',
    severity: Severity.MEDIUM,
    baseWeight: 4,
    remediation:
      'Confirm the name against the dependency that was actually intended. Check for a transitive dependency that introduced it without anyone typing it.',
    references: ['https://arxiv.org/abs/2005.09535'],
    falsePositiveNotes:
      'Suppressed when the candidate itself has high download counts — that is the real package, not the squat. Short names collide by chance; minimum length applies.',
  },
  {
    ruleId: 'Q-TYP-002',
    family: SignalFamily.TYPOSQUAT,
    name: 'Homoglyph or Unicode confusable substitution',
    description:
      'The name substitutes visually identical characters — Cyrillic а for Latin a, a Turkish dotless ı for i. The rendered name is indistinguishable from the target while being a completely different string.',
    severity: Severity.HIGH,
    baseWeight: 7,
    remediation: 'Do not install. Compare the raw bytes of the name against the intended package.',
    references: ['https://www.unicode.org/reports/tr39/'],
  },
  {
    ruleId: 'Q-TYP-003',
    family: SignalFamily.TYPOSQUAT,
    name: 'Separator manipulation',
    description:
      'The name matches a popular package once hyphens, underscores and dots are normalised away — node-fetch against nodefetch or node_fetch.',
    severity: Severity.MEDIUM,
    baseWeight: 5,
    remediation: 'Confirm the exact spelling against the upstream project’s own documentation.',
    references: [],
  },
  {
    ruleId: 'Q-TYP-004',
    family: SignalFamily.TYPOSQUAT,
    name: 'Scope confusion',
    description:
      'An unscoped package imitates a scoped one, or a lookalike scope imitates the real one — @types/foo against typesfoo, or @babel-core against @babel/core.',
    severity: Severity.HIGH,
    baseWeight: 6,
    remediation:
      'Verify the scope owner on the registry. Scoped packages under a known organisation are the trustworthy form.',
    references: [],
  },
  {
    ruleId: 'Q-TYP-005',
    family: SignalFamily.TYPOSQUAT,
    name: 'Combosquatting',
    description:
      'The name is a popular package plus a plausible affix — react-dom-router, express-middleware-core. The affix implies an official relationship that does not exist.',
    severity: Severity.MEDIUM,
    baseWeight: 4,
    remediation:
      'Check whether the upstream project actually publishes this package. Most do not publish community add-ons under their own name.',
    references: [],
    falsePositiveNotes:
      'Genuine ecosystem plugins follow exactly this naming pattern. Weight is reduced when the maintainer overlaps with the base package’s maintainers.',
  },
  {
    ruleId: 'Q-TYP-006',
    family: SignalFamily.TYPOSQUAT,
    name: 'Dependency-confusion posture',
    description:
      'A public package uses a naming convention associated with private internal registries, and was published recently with minimal history. This is the setup for a dependency-confusion attack, where a misconfigured resolver prefers the public package over the internal one.',
    severity: Severity.HIGH,
    baseWeight: 6,
    remediation:
      'Pin your internal scope in .npmrc and confirm the resolver cannot fall back to the public registry for it.',
    references: ['https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610'],
  },

  // -------------------------------------------------------------------------
  // Family 5 — Maintainer and release forensics
  // -------------------------------------------------------------------------
  {
    ruleId: 'Q-MNT-001',
    family: SignalFamily.MAINTAINER,
    name: 'Dormancy break',
    description:
      'The package was inactive for months and then published a release. A long-abandoned package with real download volume is an attractive takeover target precisely because nobody is watching it.',
    severity: Severity.MEDIUM,
    baseWeight: 4,
    remediation:
      'Read the diff between this release and the last one. A genuine revival usually comes with a changelog and repository activity.',
    references: [],
    falsePositiveNotes:
      'Stable, finished libraries legitimately go quiet for years. This signal only matters when corroborated by another family.',
  },
  {
    ruleId: 'Q-MNT-002',
    family: SignalFamily.MAINTAINER,
    name: 'Maintainer added shortly before this release',
    description:
      'A maintainer was added to the package within days of the version under evaluation being published. In the event-stream compromise this was the entire attack: the new maintainer was handed publish rights and shipped a malicious release.',
    severity: Severity.HIGH,
    baseWeight: 6,
    remediation:
      'Verify the handover was intentional and publicly discussed. Check the repository for an issue or commit acknowledging the new maintainer.',
    references: [
      'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident',
    ],
  },
  {
    ruleId: 'Q-MNT-003',
    family: SignalFamily.MAINTAINER,
    name: 'New or thin maintainer account',
    description:
      'The publishing account is recently created, publishes few packages, and has no other ecosystem footprint. Attackers register accounts for a campaign; long-standing maintainers accumulate history.',
    severity: Severity.MEDIUM,
    baseWeight: 4,
    remediation:
      'Cross-check the account against the repository’s commit history. A publisher who has never committed to the project is worth questioning.',
    references: [],
  },
  {
    ruleId: 'Q-MNT-004',
    family: SignalFamily.MAINTAINER,
    name: 'Sole maintainer on a high-download package',
    description:
      'A single account can publish a package with substantial download volume. This is exposure rather than evidence: one compromised credential reaches every dependent.',
    severity: Severity.LOW,
    baseWeight: 2,
    remediation:
      'Prefer pinned versions and enable provenance verification for this dependency. Consider vendoring if it is critical.',
    references: [],
    falsePositiveNotes:
      'Extremely common and almost never malicious on its own. Contributes to risk posture, not to a malicious verdict.',
  },
  {
    ruleId: 'Q-MNT-005',
    family: SignalFamily.MAINTAINER,
    name: 'Out-of-order or anomalous version jump',
    description:
      'The version was published out of semver order, or jumps far beyond the established cadence. Attackers publish high version numbers so that loose ranges resolve to their release.',
    severity: Severity.MEDIUM,
    baseWeight: 4,
    remediation:
      'Pin the exact version you intend to use and confirm the jump is explained by a changelog entry.',
    references: ['https://semver.org/'],
  },
  {
    ruleId: 'Q-MNT-006',
    family: SignalFamily.MAINTAINER,
    name: 'Release cadence anomaly',
    description:
      'The interval between releases departs sharply from the package’s own history — a burst of releases hours apart from a project that previously shipped quarterly.',
    severity: Severity.LOW,
    baseWeight: 3,
    remediation:
      'Check whether the burst corresponds to a genuine incident response or to an attacker iterating on a payload.',
    references: [],
  },

  // -------------------------------------------------------------------------
  // Family 6 — Provenance and integrity
  // -------------------------------------------------------------------------
  {
    ruleId: 'Q-PRV-001',
    family: SignalFamily.PROVENANCE,
    name: 'No repository field',
    description:
      'The manifest declares no repository. Without one there is no source to compare the tarball against, so the published artefact is the only description of the package that exists.',
    severity: Severity.LOW,
    baseWeight: 3,
    remediation:
      'Prefer a package that publishes its source. Treat the absence as a permanent ceiling on how much this package can be verified.',
    references: [],
    falsePositiveNotes:
      'Older packages predate the convention. Weight is reduced for packages first published before 2016.',
  },
  {
    ruleId: 'Q-PRV-002',
    family: SignalFamily.PROVENANCE,
    name: 'Repository URL unreachable or archived',
    description:
      'The declared repository 404s, is archived, or is otherwise unreachable. A dead repository with a live publish stream means releases are coming from somewhere other than the stated source.',
    severity: Severity.MEDIUM,
    baseWeight: 4,
    remediation:
      'Establish where releases are actually built. This is reported separately from DIVERGENT because being unable to check is not the same as finding a mismatch.',
    references: [],
  },
  {
    ruleId: 'Q-PRV-003',
    family: SignalFamily.PROVENANCE,
    name: 'Executable file in tarball absent from the git tag',
    description:
      'The published tarball contains executable code that does not exist in the repository at the corresponding tag. This is the event-stream signature: the source looked fine because the malicious code was never in it.',
    severity: Severity.CRITICAL,
    baseWeight: 10,
    remediation:
      'Do not install. The files listed in the evidence are the payload; nothing in the repository would have revealed them.',
    references: [
      'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident',
      'https://slsa.dev/spec/v1.0/threats',
    ],
  },
  {
    ruleId: 'Q-PRV-004',
    family: SignalFamily.PROVENANCE,
    name: 'File content differs between repository and tarball',
    description:
      'A file exists in both the repository tag and the tarball, but with different content after build output and lockfiles are normalised away. The published artefact was modified after it left source control.',
    severity: Severity.HIGH,
    baseWeight: 8,
    remediation:
      'Review the diff. Differences confined to generated output are expected; differences in hand-written source are not.',
    references: ['https://slsa.dev/'],
    falsePositiveNotes:
      'Transpilation, bundling and version-stamping produce legitimate differences. Normalisation strips known build output and anything matched by .npmignore or files before comparing.',
  },
  {
    ruleId: 'Q-PRV-005',
    family: SignalFamily.PROVENANCE,
    name: 'Binary blob in a source-only package',
    description:
      'The tarball ships a binary artefact that the repository does not contain and the manifest does not explain.',
    severity: Severity.HIGH,
    baseWeight: 6,
    remediation:
      'Do not install until the artefact has been analysed separately. Reading the source tells you nothing about it.',
    references: [],
  },
  {
    ruleId: 'Q-PRV-006',
    family: SignalFamily.PROVENANCE,
    name: 'No provenance attestation',
    description:
      'The version carries no SLSA/Sigstore provenance attestation, in an ecosystem that supports them. Without one there is no cryptographic link between the artefact and the build that claims to have produced it.',
    severity: Severity.INFO,
    baseWeight: 1,
    remediation:
      'Prefer versions published with provenance. Ask upstream to enable it in their release workflow.',
    references: ['https://docs.npmjs.com/generating-provenance-statements'],
    falsePositiveNotes:
      'The overwhelming majority of published packages still have no attestation. Informational only; it never contributes to a malicious verdict on its own.',
  },
];
