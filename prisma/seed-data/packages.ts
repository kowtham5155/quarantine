import type { JsonObject } from './json';
import { Ecosystem, MaintainerEventType, ProvenanceStatus, Verdict } from '@prisma/client';

/**
 * Seed package corpus — 40 packages spanning all five verdicts.
 *
 * The four KNOWN_MALICIOUS entries are real, publicly documented supply chain
 * compromises; their signal hits describe what the engine would have found in
 * those tarballs. Everything at LIKELY_MALICIOUS and SUSPICIOUS uses invented
 * names so the demo database never labels a real published package as
 * malicious. The CLEAN set is genuine popular packages.
 *
 * Excerpts are short illustrative fragments of the kind that appear in a
 * detection report — enough to show the shape of the finding and its location,
 * never a working payload.
 */

export interface SeedSignal {
  ruleId: string;
  confidence: number;
  contextModifier?: number;
  filePath?: string;
  lineStart?: number;
  lineEnd?: number;
  excerpt?: string;
  evidence?: JsonObject;
}

export interface SeedProvenance {
  status: ProvenanceStatus;
  repoUrl?: string;
  gitRef?: string;
  filesOnlyInTarball?: string[];
  filesOnlyInRepo?: string[];
  modifiedFiles?: string[];
  diffSummary?: JsonObject;
}

export interface SeedTyposquat {
  targetPackage: string;
  distance: number;
  technique: string;
  similarity: number;
  targetDownloads: number;
}

export interface SeedMaintainerEvent {
  type: MaintainerEventType;
  actor: string;
  daysAgo: number;
  metadata?: JsonObject;
}

export interface SeedVersion {
  version: string;
  publishedDaysAgo: number;
  unpackedSize: number;
  fileCount: number;
  hasInstallScripts: boolean;
  publisherId: string;
  provenanceAttested: boolean;
}

export interface SeedPackage {
  ecosystem: Ecosystem;
  name: string;
  description: string;
  repositoryUrl?: string;
  weeklyDownloads: number;
  maintainerCount: number;
  isDeprecated?: boolean;
  firstPublishedDaysAgo: number;
  versions: SeedVersion[];
  /** Version the seeded analysis targets. Defaults to the first version listed. */
  analysedVersion?: string;
  verdict: Verdict;
  confidence: number;
  weightedScore: number;
  hardTriggersFired?: string[];
  durationMs: number;
  filesAnalysed: number;
  signals: SeedSignal[];
  provenance?: SeedProvenance;
  typosquats?: SeedTyposquat[];
  maintainerEvents?: SeedMaintainerEvent[];
}

const NPM = Ecosystem.NPM;

// ---------------------------------------------------------------------------
// KNOWN_MALICIOUS — real, publicly documented compromises
// ---------------------------------------------------------------------------

const KNOWN_MALICIOUS: SeedPackage[] = [
  {
    ecosystem: NPM,
    name: 'event-stream',
    description: 'Streaming toolkit. Version 3.3.6 shipped a malicious transitive dependency.',
    repositoryUrl: 'https://github.com/dominictarr/event-stream',
    weeklyDownloads: 1_900_000,
    maintainerCount: 2,
    firstPublishedDaysAgo: 4600,
    versions: [
      {
        version: '3.3.6',
        publishedDaysAgo: 2820,
        unpackedSize: 48_320,
        fileCount: 27,
        hasInstallScripts: false,
        publisherId: 'right9ctrl',
        provenanceAttested: false,
      },
      {
        version: '3.3.4',
        publishedDaysAgo: 3100,
        unpackedSize: 44_100,
        fileCount: 24,
        hasInstallScripts: false,
        publisherId: 'dominictarr',
        provenanceAttested: false,
      },
    ],
    analysedVersion: '3.3.6',
    verdict: Verdict.KNOWN_MALICIOUS,
    confidence: 0.99,
    weightedScore: 96.5,
    hardTriggersFired: ['executable_code_in_tarball_absent_from_source', 'known_bad_hash_match'],
    durationMs: 8420,
    filesAnalysed: 27,
    signals: [
      {
        ruleId: 'Q-PRV-003',
        confidence: 0.99,
        filePath: 'node_modules/flatmap-stream/index.min.js',
        lineStart: 1,
        lineEnd: 1,
        excerpt: '/* minified payload present in tarball, absent from git tag v3.3.6 */',
        evidence: {
          gitRef: 'v3.3.6',
          filesOnlyInTarball: ['index.min.js'],
          note: 'The repository at this tag contains no minified entrypoint.',
        },
      },
      {
        ruleId: 'Q-OBF-004',
        confidence: 0.97,
        filePath: 'node_modules/flatmap-stream/index.min.js',
        lineStart: 1,
        lineEnd: 1,
        excerpt: "var _0x1a2b=['...','...'];function _0x3c4d(a,b){return _0x1a2b[a-0x0];}",
        evidence: { arrayLength: 148, decoderFunction: '_0x3c4d' },
      },
      {
        ruleId: 'Q-OBF-002',
        confidence: 0.95,
        filePath: 'node_modules/flatmap-stream/index.min.js',
        lineStart: 1,
        excerpt: "var e=Buffer.from('<3.2KB base64 literal>','base64')",
        evidence: { literalBytes: 3287, encoding: 'base64' },
      },
      {
        ruleId: 'Q-OBF-003',
        confidence: 0.96,
        filePath: 'node_modules/flatmap-stream/index.min.js',
        lineStart: 1,
        excerpt: 'new Function(decoded)()',
        evidence: { sink: 'new Function' },
      },
      {
        ruleId: 'Q-MNT-002',
        confidence: 0.94,
        evidence: {
          maintainerAdded: 'right9ctrl',
          daysBeforeRelease: 74,
          note: 'Publish rights were handed over on request, then used to ship this release.',
        },
      },
      {
        ruleId: 'Q-CAP-006',
        confidence: 0.92,
        filePath: 'node_modules/flatmap-stream/index.min.js',
        lineStart: 1,
        excerpt: '/* decoded stage 2 references a bitcoin wallet module */',
        evidence: { target: 'copay wallet build', decodedStage: 2 },
      },
    ],
    provenance: {
      status: ProvenanceStatus.DIVERGENT,
      repoUrl: 'https://github.com/dominictarr/event-stream',
      gitRef: 'v3.3.6',
      filesOnlyInTarball: ['node_modules/flatmap-stream/index.min.js'],
      modifiedFiles: ['package.json'],
      diffSummary: { added: 1, modified: 1, removed: 0 },
    },
    maintainerEvents: [
      { type: MaintainerEventType.ADDED, actor: 'right9ctrl', daysAgo: 2894 },
      { type: MaintainerEventType.PUBLISHED, actor: 'right9ctrl', daysAgo: 2820 },
      { type: MaintainerEventType.PUBLISHED, actor: 'dominictarr', daysAgo: 3100 },
    ],
  },
  {
    ecosystem: NPM,
    name: 'ua-parser-js',
    description:
      'User-agent parser. Three versions were published from a hijacked maintainer account in October 2021.',
    repositoryUrl: 'https://github.com/faisalman/ua-parser-js',
    weeklyDownloads: 8_100_000,
    maintainerCount: 1,
    firstPublishedDaysAgo: 4200,
    versions: [
      {
        version: '0.7.29',
        publishedDaysAgo: 1760,
        unpackedSize: 92_400,
        fileCount: 18,
        hasInstallScripts: true,
        publisherId: 'faisalman',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.KNOWN_MALICIOUS,
    confidence: 0.99,
    weightedScore: 98.2,
    hardTriggersFired: [
      'install_script_with_network_exfiltration',
      'credential_read_in_install_script',
      'known_bad_hash_match',
    ],
    durationMs: 6180,
    filesAnalysed: 18,
    signals: [
      {
        ruleId: 'Q-INS-001',
        confidence: 0.99,
        filePath: 'package.json',
        lineStart: 31,
        excerpt: '"preinstall": "node preinstall.js"',
        evidence: { hooks: ['preinstall'] },
      },
      {
        ruleId: 'Q-INS-002',
        confidence: 0.98,
        filePath: 'preinstall.js',
        lineStart: 12,
        lineEnd: 14,
        excerpt:
          "const IS_WIN = process.platform === 'win32'; /* branches into a shell download */",
        evidence: { interpreters: ['cmd.exe', '/bin/sh'], platformAware: true },
      },
      {
        ruleId: 'Q-INS-005',
        confidence: 0.98,
        filePath: 'preinstall.js',
        lineStart: 18,
        excerpt: '/* fetches a second-stage binary over plain HTTP */',
        evidence: { protocol: 'http', stage: 2 },
      },
      {
        ruleId: 'Q-INS-004',
        confidence: 0.95,
        filePath: 'preinstall.js',
        lineStart: 24,
        excerpt: '/* enumerates the user profile for credential stores */',
        evidence: { paths: ['~/.npmrc', 'AppData/Local'] },
      },
      {
        ruleId: 'Q-CAP-009',
        confidence: 0.93,
        filePath: 'jsextension',
        excerpt: '/* ELF 64-bit executable shipped in a pure-JS package */',
        evidence: { format: 'ELF', sizeBytes: 1_204_224 },
      },
      {
        ruleId: 'Q-MNT-004',
        confidence: 0.88,
        evidence: { maintainers: 1, weeklyDownloads: 8_100_000 },
      },
      {
        ruleId: 'Q-MNT-006',
        confidence: 0.85,
        evidence: {
          releasesInWindow: 3,
          windowHours: 4,
          historicalMedianDays: 21,
        },
      },
    ],
    provenance: {
      status: ProvenanceStatus.DIVERGENT,
      repoUrl: 'https://github.com/faisalman/ua-parser-js',
      gitRef: '0.7.29',
      filesOnlyInTarball: ['preinstall.js', 'jsextension'],
      diffSummary: { added: 2, modified: 1, removed: 0 },
    },
    maintainerEvents: [{ type: MaintainerEventType.PUBLISHED, actor: 'faisalman', daysAgo: 1760 }],
  },
  {
    ecosystem: NPM,
    name: 'coa',
    description:
      'Command-option argument parser. Compromised in November 2021 alongside rc, via the same account takeover.',
    repositoryUrl: 'https://github.com/veged/coa',
    weeklyDownloads: 9_400_000,
    maintainerCount: 2,
    firstPublishedDaysAgo: 3900,
    versions: [
      {
        version: '2.0.3',
        publishedDaysAgo: 1742,
        unpackedSize: 61_800,
        fileCount: 22,
        hasInstallScripts: true,
        publisherId: 'unknown',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.KNOWN_MALICIOUS,
    confidence: 0.98,
    weightedScore: 94.7,
    hardTriggersFired: ['install_script_with_network_exfiltration', 'known_bad_hash_match'],
    durationMs: 5240,
    filesAnalysed: 22,
    signals: [
      {
        ruleId: 'Q-INS-001',
        confidence: 0.99,
        filePath: 'package.json',
        lineStart: 18,
        excerpt: '"postinstall": "node compile.js"',
        evidence: { hooks: ['postinstall'] },
      },
      {
        ruleId: 'Q-INS-007',
        confidence: 0.94,
        filePath: 'compile.js',
        lineStart: 1,
        excerpt: '/* single-line obfuscated entrypoint, no readable source alongside */',
        evidence: { entropy: 5.42, lines: 1 },
      },
      {
        ruleId: 'Q-INS-005',
        confidence: 0.96,
        filePath: 'compile.js',
        lineStart: 1,
        excerpt: '/* retrieves a payload from a hardcoded host */',
        evidence: { protocol: 'http' },
      },
      {
        ruleId: 'Q-CAP-007',
        confidence: 0.9,
        filePath: 'compile.js',
        lineStart: 1,
        excerpt: '/* connection target is a bare IPv4 literal */',
        evidence: { addressClass: 'public-ipv4' },
      },
      {
        ruleId: 'Q-MNT-005',
        confidence: 0.87,
        evidence: { publishedOutOfOrder: true, previousLatest: '2.0.2' },
      },
    ],
    provenance: {
      status: ProvenanceStatus.DIVERGENT,
      repoUrl: 'https://github.com/veged/coa',
      gitRef: 'v2.0.3',
      filesOnlyInTarball: ['compile.js'],
      diffSummary: { added: 1, modified: 1, removed: 0 },
    },
    maintainerEvents: [{ type: MaintainerEventType.PUBLISHED, actor: 'unknown', daysAgo: 1742 }],
  },
  {
    ecosystem: NPM,
    name: 'rc',
    description:
      'Runtime configuration loader. Versions 1.2.9, 1.3.9 and 2.3.9 were published from a compromised account.',
    repositoryUrl: 'https://github.com/dominictarr/rc',
    weeklyDownloads: 14_200_000,
    maintainerCount: 1,
    firstPublishedDaysAgo: 4100,
    versions: [
      {
        version: '1.2.9',
        publishedDaysAgo: 1742,
        unpackedSize: 39_600,
        fileCount: 16,
        hasInstallScripts: true,
        publisherId: 'unknown',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.KNOWN_MALICIOUS,
    confidence: 0.98,
    weightedScore: 93.1,
    hardTriggersFired: ['install_script_with_network_exfiltration', 'known_bad_hash_match'],
    durationMs: 4870,
    filesAnalysed: 16,
    signals: [
      {
        ruleId: 'Q-INS-001',
        confidence: 0.99,
        filePath: 'package.json',
        lineStart: 14,
        excerpt: '"postinstall": "node compile.js"',
        evidence: { hooks: ['postinstall'] },
      },
      {
        ruleId: 'Q-INS-003',
        confidence: 0.93,
        filePath: 'compile.js',
        lineStart: 1,
        excerpt: '/* decodes an embedded literal before executing it */',
        evidence: { encoding: 'base64' },
      },
      {
        ruleId: 'Q-INS-005',
        confidence: 0.95,
        filePath: 'compile.js',
        lineStart: 1,
        excerpt: '/* outbound request during postinstall */',
        evidence: { protocol: 'http' },
      },
      {
        ruleId: 'Q-MNT-005',
        confidence: 0.9,
        evidence: {
          publishedOutOfOrder: true,
          note: 'Three parallel version lines published within minutes of each other.',
        },
      },
      {
        ruleId: 'Q-MNT-004',
        confidence: 0.86,
        evidence: { maintainers: 1, weeklyDownloads: 14_200_000 },
      },
    ],
    provenance: {
      status: ProvenanceStatus.DIVERGENT,
      repoUrl: 'https://github.com/dominictarr/rc',
      gitRef: 'v1.2.9',
      filesOnlyInTarball: ['compile.js'],
      diffSummary: { added: 1, modified: 1, removed: 0 },
    },
    maintainerEvents: [{ type: MaintainerEventType.PUBLISHED, actor: 'unknown', daysAgo: 1742 }],
  },
];

export const SEED_PACKAGES_KNOWN_MALICIOUS = KNOWN_MALICIOUS;

// ---------------------------------------------------------------------------
// LIKELY_MALICIOUS — hard triggers fired; names are invented
// ---------------------------------------------------------------------------

const LIKELY_MALICIOUS: SeedPackage[] = [
  {
    ecosystem: NPM,
    name: 'lodahs',
    description: 'Utility helpers for modern JavaScript.',
    weeklyDownloads: 412,
    maintainerCount: 1,
    firstPublishedDaysAgo: 21,
    versions: [
      {
        version: '4.17.22',
        publishedDaysAgo: 6,
        unpackedSize: 18_240,
        fileCount: 9,
        hasInstallScripts: true,
        publisherId: 'npm-utils-team',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.LIKELY_MALICIOUS,
    confidence: 0.94,
    weightedScore: 87.4,
    hardTriggersFired: [
      'install_script_with_network_exfiltration',
      'credential_read_in_install_script',
    ],
    durationMs: 3120,
    filesAnalysed: 9,
    signals: [
      {
        ruleId: 'Q-INS-001',
        confidence: 0.99,
        filePath: 'package.json',
        lineStart: 11,
        excerpt: '"postinstall": "node ./scripts/setup.js"',
        evidence: { hooks: ['postinstall'] },
      },
      {
        ruleId: 'Q-INS-004',
        confidence: 0.96,
        filePath: 'scripts/setup.js',
        lineStart: 7,
        lineEnd: 9,
        excerpt: 'const home = os.homedir(); /* reads .npmrc and .ssh from here */',
        evidence: { paths: ['~/.npmrc', '~/.ssh/id_rsa'] },
      },
      {
        ruleId: 'Q-INS-005',
        confidence: 0.95,
        filePath: 'scripts/setup.js',
        lineStart: 14,
        excerpt: '/* POSTs the collected values to a remote collector */',
        evidence: { method: 'POST' },
      },
      {
        ruleId: 'Q-CAP-008',
        confidence: 0.97,
        filePath: 'scripts/setup.js',
        lineStart: 3,
        excerpt: "const HOOK = 'https://discord.com/api/webhooks/<redacted>'",
        evidence: { channel: 'discord' },
      },
      {
        ruleId: 'Q-TYP-001',
        confidence: 0.93,
        evidence: { target: 'lodash', distance: 2, technique: 'transposition' },
      },
      {
        ruleId: 'Q-MNT-003',
        confidence: 0.9,
        evidence: { accountAgeDays: 23, packagesPublished: 4 },
      },
      {
        ruleId: 'Q-PRV-001',
        confidence: 0.99,
        evidence: { repositoryField: null },
      },
    ],
    provenance: { status: ProvenanceStatus.NO_REPO },
    typosquats: [
      {
        targetPackage: 'lodash',
        distance: 2,
        technique: 'TRANSPOSITION',
        similarity: 0.93,
        targetDownloads: 52_000_000,
      },
    ],
    maintainerEvents: [
      { type: MaintainerEventType.PUBLISHED, actor: 'npm-utils-team', daysAgo: 6 },
    ],
  },
  {
    ecosystem: NPM,
    name: 'axioss-http',
    description: 'Promise-based HTTP client with retry support.',
    weeklyDownloads: 780,
    maintainerCount: 1,
    firstPublishedDaysAgo: 34,
    versions: [
      {
        version: '1.7.10',
        publishedDaysAgo: 11,
        unpackedSize: 26_800,
        fileCount: 14,
        hasInstallScripts: false,
        publisherId: 'http-tools',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.LIKELY_MALICIOUS,
    confidence: 0.91,
    weightedScore: 79.8,
    hardTriggersFired: ['known_bad_hash_match'],
    durationMs: 2980,
    filesAnalysed: 14,
    signals: [
      {
        ruleId: 'Q-CAP-004',
        confidence: 0.95,
        filePath: 'lib/interceptor.js',
        lineStart: 42,
        excerpt: 'const payload = JSON.stringify(process.env);',
        evidence: { pattern: 'whole-environment serialisation' },
      },
      {
        ruleId: 'Q-CAP-008',
        confidence: 0.96,
        filePath: 'lib/interceptor.js',
        lineStart: 47,
        excerpt: "const sink = 'https://api.telegram.org/bot<redacted>/sendMessage'",
        evidence: { channel: 'telegram' },
      },
      {
        ruleId: 'Q-OBF-007',
        confidence: 0.88,
        filePath: 'lib/interceptor.js',
        lineStart: 38,
        excerpt: "require('ht' + 'tps')",
        evidence: { reconstructed: 'https' },
      },
      {
        ruleId: 'Q-TYP-001',
        confidence: 0.9,
        evidence: { target: 'axios', distance: 2, technique: 'combosquat+insertion' },
      },
      {
        ruleId: 'Q-PRV-006',
        confidence: 0.99,
        evidence: { attestation: null },
      },
    ],
    provenance: { status: ProvenanceStatus.NO_REPO },
    typosquats: [
      {
        targetPackage: 'axios',
        distance: 2,
        technique: 'INSERTION',
        similarity: 0.88,
        targetDownloads: 48_000_000,
      },
    ],
    maintainerEvents: [{ type: MaintainerEventType.PUBLISHED, actor: 'http-tools', daysAgo: 11 }],
  },
  {
    ecosystem: NPM,
    name: 'expresss-session',
    description: 'Session middleware.',
    weeklyDownloads: 260,
    maintainerCount: 1,
    firstPublishedDaysAgo: 15,
    versions: [
      {
        version: '1.18.2',
        publishedDaysAgo: 4,
        unpackedSize: 21_400,
        fileCount: 11,
        hasInstallScripts: true,
        publisherId: 'session-core',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.LIKELY_MALICIOUS,
    confidence: 0.92,
    weightedScore: 84.2,
    hardTriggersFired: ['install_script_with_network_exfiltration'],
    durationMs: 2640,
    filesAnalysed: 11,
    signals: [
      {
        ruleId: 'Q-INS-001',
        confidence: 0.99,
        filePath: 'package.json',
        lineStart: 9,
        excerpt: '"preinstall": "node index-setup.js"',
        evidence: { hooks: ['preinstall'] },
      },
      {
        ruleId: 'Q-INS-003',
        confidence: 0.94,
        filePath: 'index-setup.js',
        lineStart: 2,
        excerpt: "Buffer.from('<1.4KB base64 literal>', 'base64').toString()",
        evidence: { literalBytes: 1432 },
      },
      {
        ruleId: 'Q-INS-005',
        confidence: 0.93,
        filePath: 'index-setup.js',
        lineStart: 5,
        excerpt: '/* beacons to a remote host on install */',
        evidence: { protocol: 'https' },
      },
      {
        ruleId: 'Q-OBF-003',
        confidence: 0.92,
        filePath: 'index-setup.js',
        lineStart: 6,
        excerpt: 'eval(decoded)',
        evidence: { sink: 'eval' },
      },
      {
        ruleId: 'Q-TYP-003',
        confidence: 0.91,
        evidence: { target: 'express-session', technique: 'letter doubling' },
      },
    ],
    provenance: { status: ProvenanceStatus.NO_REPO },
    typosquats: [
      {
        targetPackage: 'express-session',
        distance: 1,
        technique: 'REPETITION',
        similarity: 0.96,
        targetDownloads: 3_400_000,
      },
    ],
    maintainerEvents: [{ type: MaintainerEventType.PUBLISHED, actor: 'session-core', daysAgo: 4 }],
  },
  {
    ecosystem: NPM,
    name: 'node-fetch-cli',
    description: 'Command line wrapper around fetch.',
    weeklyDownloads: 143,
    maintainerCount: 1,
    firstPublishedDaysAgo: 9,
    versions: [
      {
        version: '3.3.3',
        publishedDaysAgo: 2,
        unpackedSize: 33_900,
        fileCount: 12,
        hasInstallScripts: true,
        publisherId: 'fetch-maintainer',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.LIKELY_MALICIOUS,
    confidence: 0.93,
    weightedScore: 88.9,
    hardTriggersFired: [
      'install_script_with_network_exfiltration',
      'credential_read_in_install_script',
    ],
    durationMs: 3410,
    filesAnalysed: 12,
    signals: [
      {
        ruleId: 'Q-INS-001',
        confidence: 0.99,
        filePath: 'package.json',
        lineStart: 13,
        excerpt: '"postinstall": "sh ./postinstall.sh"',
        evidence: { hooks: ['postinstall'] },
      },
      {
        ruleId: 'Q-INS-002',
        confidence: 0.97,
        filePath: 'postinstall.sh',
        lineStart: 3,
        excerpt: '# pipes a fetched script straight into a shell',
        evidence: { interpreters: ['sh'], remoteSource: true },
      },
      {
        ruleId: 'Q-INS-004',
        confidence: 0.95,
        filePath: 'postinstall.sh',
        lineStart: 5,
        excerpt: '# archives ~/.aws and ~/.config/gcloud',
        evidence: { paths: ['~/.aws', '~/.config/gcloud'] },
      },
      {
        ruleId: 'Q-INS-006',
        confidence: 0.9,
        filePath: 'postinstall.sh',
        lineStart: 9,
        excerpt: '# appends a line to ~/.bashrc',
        evidence: { writtenPaths: ['~/.bashrc'], persistence: true },
      },
      {
        ruleId: 'Q-CAP-007',
        confidence: 0.89,
        filePath: 'postinstall.sh',
        lineStart: 3,
        excerpt: '# destination is a bare IPv4 literal',
        evidence: { addressClass: 'public-ipv4' },
      },
      {
        ruleId: 'Q-TYP-005',
        confidence: 0.86,
        evidence: { base: 'node-fetch', affix: '-cli' },
      },
    ],
    provenance: { status: ProvenanceStatus.NO_REPO },
    typosquats: [
      {
        targetPackage: 'node-fetch',
        distance: 4,
        technique: 'COMBOSQUAT',
        similarity: 0.81,
        targetDownloads: 41_000_000,
      },
    ],
    maintainerEvents: [
      { type: MaintainerEventType.PUBLISHED, actor: 'fetch-maintainer', daysAgo: 2 },
    ],
  },
  {
    ecosystem: NPM,
    name: 'discordjs-utils-core',
    description: 'Helper utilities for Discord bots.',
    weeklyDownloads: 96,
    maintainerCount: 1,
    firstPublishedDaysAgo: 12,
    versions: [
      {
        version: '2.1.0',
        publishedDaysAgo: 3,
        unpackedSize: 44_100,
        fileCount: 19,
        hasInstallScripts: false,
        publisherId: 'dcore-dev',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.LIKELY_MALICIOUS,
    confidence: 0.9,
    weightedScore: 81.6,
    hardTriggersFired: ['known_bad_hash_match'],
    durationMs: 3860,
    filesAnalysed: 19,
    signals: [
      {
        ruleId: 'Q-CAP-005',
        confidence: 0.94,
        filePath: 'src/collect.js',
        lineStart: 18,
        lineEnd: 24,
        excerpt: '/* walks browser profile directories for saved credentials */',
        evidence: { targets: ['Local Storage', 'leveldb'] },
      },
      {
        ruleId: 'Q-CAP-008',
        confidence: 0.95,
        filePath: 'src/collect.js',
        lineStart: 31,
        excerpt: "const WEBHOOK = 'https://discord.com/api/webhooks/<redacted>'",
        evidence: { channel: 'discord' },
      },
      {
        ruleId: 'Q-OBF-004',
        confidence: 0.91,
        filePath: 'src/collect.js',
        lineStart: 1,
        excerpt: "const _0xa1=['...','...'];const _0xb2=(i)=>_0xa1[i];",
        evidence: { arrayLength: 92 },
      },
      {
        ruleId: 'Q-CAP-006',
        confidence: 0.88,
        filePath: 'src/collect.js',
        lineStart: 26,
        excerpt: '/* checks for an Exodus wallet directory */',
        evidence: { wallets: ['Exodus'] },
      },
      {
        ruleId: 'Q-MNT-003',
        confidence: 0.87,
        evidence: { accountAgeDays: 14, packagesPublished: 7 },
      },
    ],
    provenance: { status: ProvenanceStatus.NO_REPO },
    maintainerEvents: [{ type: MaintainerEventType.PUBLISHED, actor: 'dcore-dev', daysAgo: 3 }],
  },
  {
    ecosystem: NPM,
    name: '@typesnode/runtime',
    description: 'Runtime type helpers.',
    weeklyDownloads: 58,
    maintainerCount: 1,
    firstPublishedDaysAgo: 7,
    versions: [
      {
        version: '1.0.4',
        publishedDaysAgo: 1,
        unpackedSize: 12_600,
        fileCount: 6,
        hasInstallScripts: true,
        publisherId: 'typesnode',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.LIKELY_MALICIOUS,
    confidence: 0.89,
    weightedScore: 78.3,
    hardTriggersFired: ['credential_read_in_install_script'],
    durationMs: 2210,
    filesAnalysed: 6,
    signals: [
      {
        ruleId: 'Q-INS-001',
        confidence: 0.99,
        filePath: 'package.json',
        lineStart: 8,
        excerpt: '"install": "node ./bin/link.js"',
        evidence: { hooks: ['install'] },
      },
      {
        ruleId: 'Q-INS-004',
        confidence: 0.92,
        filePath: 'bin/link.js',
        lineStart: 4,
        excerpt: "fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8')",
        evidence: { paths: ['~/.npmrc'] },
      },
      {
        ruleId: 'Q-TYP-004',
        confidence: 0.94,
        evidence: { impersonates: '@types/node', technique: 'scope confusion' },
      },
      {
        ruleId: 'Q-TYP-006',
        confidence: 0.83,
        evidence: { internalNamingConvention: true, accountAgeDays: 7 },
      },
      {
        ruleId: 'Q-MNT-003',
        confidence: 0.91,
        evidence: { accountAgeDays: 7, packagesPublished: 1 },
      },
    ],
    provenance: { status: ProvenanceStatus.NO_REPO },
    typosquats: [
      {
        targetPackage: '@types/node',
        distance: 2,
        technique: 'SCOPE_CONFUSION',
        similarity: 0.9,
        targetDownloads: 89_000_000,
      },
    ],
    maintainerEvents: [{ type: MaintainerEventType.PUBLISHED, actor: 'typesnode', daysAgo: 1 }],
  },
  {
    ecosystem: NPM,
    name: 'crypto-wallet-helper',
    description: 'Helpers for reading wallet keystores.',
    weeklyDownloads: 34,
    maintainerCount: 1,
    firstPublishedDaysAgo: 5,
    versions: [
      {
        version: '0.4.1',
        publishedDaysAgo: 1,
        unpackedSize: 29_300,
        fileCount: 10,
        hasInstallScripts: false,
        publisherId: 'wallet-tools',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.LIKELY_MALICIOUS,
    confidence: 0.88,
    weightedScore: 76.9,
    hardTriggersFired: ['known_bad_hash_match'],
    durationMs: 2740,
    filesAnalysed: 10,
    signals: [
      {
        ruleId: 'Q-CAP-006',
        confidence: 0.96,
        filePath: 'src/scan.js',
        lineStart: 9,
        lineEnd: 15,
        excerpt: "const WALLET_PATHS = ['.ethereum/keystore', 'wallet.dat', '.electrum/wallets']",
        evidence: { wallets: ['Ethereum', 'Bitcoin Core', 'Electrum'] },
      },
      {
        ruleId: 'Q-CAP-002',
        confidence: 0.84,
        filePath: 'src/beacon.js',
        lineStart: 3,
        excerpt: "const net = require('net')",
        evidence: { modules: ['net'] },
      },
      {
        ruleId: 'Q-CAP-007',
        confidence: 0.87,
        filePath: 'src/beacon.js',
        lineStart: 11,
        excerpt: '/* connects to a hardcoded address on a high port */',
        evidence: { addressClass: 'public-ipv4' },
      },
      {
        ruleId: 'Q-OBF-002',
        confidence: 0.8,
        filePath: 'src/beacon.js',
        lineStart: 1,
        excerpt: "const K = '<1.1KB hex literal>'",
        evidence: { literalBytes: 1104, encoding: 'hex' },
      },
      {
        ruleId: 'Q-PRV-001',
        confidence: 0.99,
        evidence: { repositoryField: null },
      },
    ],
    provenance: { status: ProvenanceStatus.NO_REPO },
    maintainerEvents: [{ type: MaintainerEventType.PUBLISHED, actor: 'wallet-tools', daysAgo: 1 }],
  },
  {
    ecosystem: NPM,
    name: 'reqeusts',
    description: 'Simplified HTTP requests.',
    weeklyDownloads: 187,
    maintainerCount: 1,
    firstPublishedDaysAgo: 18,
    versions: [
      {
        version: '2.88.3',
        publishedDaysAgo: 8,
        unpackedSize: 16_700,
        fileCount: 8,
        hasInstallScripts: true,
        publisherId: 'req-team',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.LIKELY_MALICIOUS,
    confidence: 0.9,
    weightedScore: 80.4,
    hardTriggersFired: ['install_script_with_network_exfiltration'],
    durationMs: 2480,
    filesAnalysed: 8,
    signals: [
      {
        ruleId: 'Q-INS-001',
        confidence: 0.99,
        filePath: 'package.json',
        lineStart: 10,
        excerpt: '"postinstall": "node p.js"',
        evidence: { hooks: ['postinstall'] },
      },
      {
        ruleId: 'Q-INS-005',
        confidence: 0.94,
        filePath: 'p.js',
        lineStart: 3,
        excerpt: '/* sends hostname and username to a remote endpoint */',
        evidence: { fields: ['hostname', 'username', 'cwd'] },
      },
      {
        ruleId: 'Q-CAP-004',
        confidence: 0.89,
        filePath: 'p.js',
        lineStart: 2,
        excerpt: 'Object.keys(process.env).forEach(...)',
        evidence: { pattern: 'environment enumeration' },
      },
      {
        ruleId: 'Q-TYP-001',
        confidence: 0.95,
        evidence: { target: 'requests', distance: 2, technique: 'transposition' },
      },
      {
        ruleId: 'Q-TYP-002',
        confidence: 0.72,
        evidence: { confusables: [] },
      },
    ],
    provenance: { status: ProvenanceStatus.NO_REPO },
    typosquats: [
      {
        targetPackage: 'request',
        distance: 2,
        technique: 'TRANSPOSITION',
        similarity: 0.9,
        targetDownloads: 12_000_000,
      },
    ],
    maintainerEvents: [{ type: MaintainerEventType.PUBLISHED, actor: 'req-team', daysAgo: 8 }],
  },
];

export const SEED_PACKAGES_LIKELY_MALICIOUS = LIKELY_MALICIOUS;

// ---------------------------------------------------------------------------
// SUSPICIOUS — corroboration across families, no hard trigger
// ---------------------------------------------------------------------------

const SUSPICIOUS: SeedPackage[] = [
  {
    ecosystem: NPM,
    name: 'fast-json-parse-plus',
    description: 'Faster JSON parsing with schema hints.',
    repositoryUrl: 'https://github.com/example-org/fast-json-parse-plus',
    weeklyDownloads: 4_200,
    maintainerCount: 1,
    firstPublishedDaysAgo: 190,
    versions: [
      {
        version: '2.3.0',
        publishedDaysAgo: 14,
        unpackedSize: 58_400,
        fileCount: 21,
        hasInstallScripts: false,
        publisherId: 'fjp-maint',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.SUSPICIOUS,
    confidence: 0.78,
    weightedScore: 52.6,
    durationMs: 3040,
    filesAnalysed: 21,
    signals: [
      {
        ruleId: 'Q-OBF-003',
        confidence: 0.82,
        contextModifier: 0.7,
        filePath: 'lib/compile.js',
        lineStart: 64,
        excerpt: 'const fn = new Function("obj", body);',
        evidence: { sink: 'new Function', note: 'Schema compiler; input is the declared schema.' },
      },
      {
        ruleId: 'Q-OBF-001',
        confidence: 0.71,
        filePath: 'dist/index.js',
        excerpt: '/* bundled output, entropy above threshold for .js */',
        evidence: { entropy: 5.18, threshold: 4.9 },
      },
      {
        ruleId: 'Q-PRV-004',
        confidence: 0.76,
        filePath: 'lib/compile.js',
        evidence: { changedLines: 34, note: 'Differs from the v2.3.0 tag after normalisation.' },
      },
      {
        ruleId: 'Q-MNT-004',
        confidence: 0.8,
        evidence: { maintainers: 1, weeklyDownloads: 4_200 },
      },
    ],
    provenance: {
      status: ProvenanceStatus.DIVERGENT,
      repoUrl: 'https://github.com/example-org/fast-json-parse-plus',
      gitRef: 'v2.3.0',
      modifiedFiles: ['lib/compile.js'],
      diffSummary: { added: 0, modified: 1, removed: 0 },
    },
  },
  {
    ecosystem: NPM,
    name: 'env-config-loader',
    description: 'Loads configuration from the environment with type coercion.',
    repositoryUrl: 'https://github.com/example-org/env-config-loader',
    weeklyDownloads: 11_800,
    maintainerCount: 2,
    firstPublishedDaysAgo: 620,
    versions: [
      {
        version: '3.1.2',
        publishedDaysAgo: 9,
        unpackedSize: 22_100,
        fileCount: 13,
        hasInstallScripts: false,
        publisherId: 'ecl-team',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.SUSPICIOUS,
    confidence: 0.74,
    weightedScore: 48.9,
    durationMs: 2180,
    filesAnalysed: 13,
    signals: [
      {
        ruleId: 'Q-CAP-004',
        confidence: 0.86,
        contextModifier: 0.45,
        filePath: 'src/load.js',
        lineStart: 22,
        excerpt: 'const all = { ...process.env };',
        evidence: {
          note: 'Package purpose is environment loading, so enumeration is expected; nothing is transmitted.',
        },
      },
      {
        ruleId: 'Q-MNT-001',
        confidence: 0.79,
        evidence: { dormantDays: 411, previousRelease: '3.1.1' },
      },
      {
        ruleId: 'Q-MNT-006',
        confidence: 0.68,
        evidence: { historicalMedianDays: 45, latestGapDays: 411 },
      },
      {
        ruleId: 'Q-PRV-006',
        confidence: 0.99,
        evidence: { attestation: null },
      },
    ],
    provenance: {
      status: ProvenanceStatus.MATCH,
      repoUrl: 'https://github.com/example-org/env-config-loader',
      gitRef: 'v3.1.2',
      diffSummary: { added: 0, modified: 0, removed: 0 },
    },
  },
  {
    ecosystem: NPM,
    name: 'build-tools-native',
    description: 'Native build helpers for cross-platform compilation.',
    repositoryUrl: 'https://github.com/example-org/build-tools-native',
    weeklyDownloads: 2_600,
    maintainerCount: 1,
    firstPublishedDaysAgo: 340,
    versions: [
      {
        version: '1.4.0',
        publishedDaysAgo: 20,
        unpackedSize: 1_940_000,
        fileCount: 46,
        hasInstallScripts: true,
        publisherId: 'btn-dev',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.SUSPICIOUS,
    confidence: 0.71,
    weightedScore: 55.1,
    durationMs: 5210,
    filesAnalysed: 46,
    signals: [
      {
        ruleId: 'Q-INS-001',
        confidence: 0.99,
        contextModifier: 0.3,
        filePath: 'package.json',
        lineStart: 16,
        excerpt: '"install": "node-gyp rebuild"',
        evidence: { hooks: ['install'], nativeBuild: true, bindingGyp: true },
      },
      {
        ruleId: 'Q-CAP-001',
        confidence: 0.9,
        contextModifier: 0.35,
        filePath: 'lib/exec.js',
        lineStart: 8,
        excerpt: "const { execFile } = require('child_process')",
        evidence: { note: 'Declared purpose is invoking compilers.' },
      },
      {
        ruleId: 'Q-CAP-009',
        confidence: 0.83,
        filePath: 'prebuilds/linux-x64/node.napi.node',
        excerpt: '/* prebuilt native addon, no matching source in tarball */',
        evidence: { format: 'ELF', sizeBytes: 1_412_096 },
      },
      {
        ruleId: 'Q-PRV-005',
        confidence: 0.81,
        filePath: 'prebuilds/linux-x64/node.napi.node',
        evidence: { absentFromRepo: true },
      },
    ],
    provenance: {
      status: ProvenanceStatus.DIVERGENT,
      repoUrl: 'https://github.com/example-org/build-tools-native',
      gitRef: 'v1.4.0',
      filesOnlyInTarball: ['prebuilds/linux-x64/node.napi.node'],
      diffSummary: { added: 1, modified: 0, removed: 0 },
    },
  },
  {
    ecosystem: NPM,
    name: 'react-dom-router',
    description: 'Routing helpers for React DOM applications.',
    weeklyDownloads: 890,
    maintainerCount: 1,
    firstPublishedDaysAgo: 96,
    versions: [
      {
        version: '6.2.1',
        publishedDaysAgo: 26,
        unpackedSize: 41_200,
        fileCount: 17,
        hasInstallScripts: false,
        publisherId: 'rdr-dev',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.SUSPICIOUS,
    confidence: 0.69,
    weightedScore: 44.3,
    durationMs: 2760,
    filesAnalysed: 17,
    signals: [
      {
        ruleId: 'Q-TYP-005',
        confidence: 0.88,
        evidence: { base: 'react-router-dom', technique: 'word reordering' },
      },
      {
        ruleId: 'Q-TYP-001',
        confidence: 0.74,
        evidence: { target: 'react-router-dom', distance: 2 },
      },
      {
        ruleId: 'Q-MNT-003',
        confidence: 0.72,
        evidence: { accountAgeDays: 101, packagesPublished: 3 },
      },
      {
        ruleId: 'Q-PRV-001',
        confidence: 0.99,
        evidence: { repositoryField: null },
      },
    ],
    provenance: { status: ProvenanceStatus.NO_REPO },
    typosquats: [
      {
        targetPackage: 'react-router-dom',
        distance: 4,
        technique: 'COMBOSQUAT',
        similarity: 0.79,
        targetDownloads: 14_000_000,
      },
    ],
  },
  {
    ecosystem: NPM,
    name: 'sharp-resize-lite',
    description: 'Thin image resizing wrapper.',
    repositoryUrl: 'https://github.com/example-org/sharp-resize-lite',
    weeklyDownloads: 5_400,
    maintainerCount: 1,
    firstPublishedDaysAgo: 280,
    versions: [
      {
        version: '0.9.4',
        publishedDaysAgo: 33,
        unpackedSize: 68_900,
        fileCount: 24,
        hasInstallScripts: true,
        publisherId: 'srl-dev',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.SUSPICIOUS,
    confidence: 0.73,
    weightedScore: 46.8,
    durationMs: 3320,
    filesAnalysed: 24,
    signals: [
      {
        ruleId: 'Q-INS-001',
        confidence: 0.99,
        contextModifier: 0.5,
        filePath: 'package.json',
        lineStart: 12,
        excerpt: '"postinstall": "node scripts/fetch-binaries.js"',
        evidence: { hooks: ['postinstall'] },
      },
      {
        ruleId: 'Q-INS-005',
        confidence: 0.85,
        contextModifier: 0.6,
        filePath: 'scripts/fetch-binaries.js',
        lineStart: 19,
        excerpt: '/* downloads a prebuilt binary over HTTPS from a release host */',
        evidence: { protocol: 'https', checksumVerified: false },
      },
      {
        ruleId: 'Q-PRV-002',
        confidence: 0.8,
        evidence: { repoStatus: 'archived' },
      },
      {
        ruleId: 'Q-MNT-004',
        confidence: 0.78,
        evidence: { maintainers: 1, weeklyDownloads: 5_400 },
      },
    ],
    provenance: {
      status: ProvenanceStatus.REPO_UNREACHABLE,
      repoUrl: 'https://github.com/example-org/sharp-resize-lite',
      diffSummary: { reason: 'repository archived' },
    },
  },
  {
    ecosystem: NPM,
    name: 'logger-transport-http',
    description: 'HTTP transport for structured loggers.',
    repositoryUrl: 'https://github.com/example-org/logger-transport-http',
    weeklyDownloads: 8_900,
    maintainerCount: 2,
    firstPublishedDaysAgo: 450,
    versions: [
      {
        version: '4.0.1',
        publishedDaysAgo: 17,
        unpackedSize: 31_600,
        fileCount: 15,
        hasInstallScripts: false,
        publisherId: 'lth-team',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.SUSPICIOUS,
    confidence: 0.7,
    weightedScore: 41.2,
    durationMs: 2410,
    filesAnalysed: 15,
    signals: [
      {
        ruleId: 'Q-CAP-002',
        confidence: 0.84,
        contextModifier: 0.4,
        filePath: 'src/transport.js',
        lineStart: 6,
        excerpt: "const dns = require('dns')",
        evidence: { modules: ['dns'], note: 'Resolves the configured collector host.' },
      },
      {
        ruleId: 'Q-CAP-004',
        confidence: 0.79,
        contextModifier: 0.6,
        filePath: 'src/meta.js',
        lineStart: 11,
        excerpt: 'const meta = pick(process.env, ALLOWED);',
        evidence: { note: 'Allow-listed rather than wholesale, but the list is broad.' },
      },
      {
        ruleId: 'Q-MNT-005',
        confidence: 0.75,
        evidence: { previousLatest: '3.2.0', jump: 'major+minor' },
      },
      {
        ruleId: 'Q-PRV-006',
        confidence: 0.99,
        evidence: { attestation: null },
      },
    ],
    provenance: {
      status: ProvenanceStatus.MATCH,
      repoUrl: 'https://github.com/example-org/logger-transport-http',
      gitRef: 'v4.0.1',
      diffSummary: { added: 0, modified: 0, removed: 0 },
    },
  },
  {
    ecosystem: NPM,
    name: 'semver-utils-extra',
    description: 'Additional semver comparison helpers.',
    weeklyDownloads: 1_900,
    maintainerCount: 1,
    firstPublishedDaysAgo: 150,
    versions: [
      {
        version: '1.2.0',
        publishedDaysAgo: 41,
        unpackedSize: 14_800,
        fileCount: 9,
        hasInstallScripts: false,
        publisherId: 'sue-dev',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.SUSPICIOUS,
    confidence: 0.66,
    weightedScore: 38.7,
    durationMs: 1840,
    filesAnalysed: 9,
    signals: [
      {
        ruleId: 'Q-OBF-006',
        confidence: 0.77,
        filePath: 'index.js',
        excerpt: '/* minified, no .min marker, no source alongside */',
        evidence: { averageLineLength: 812 },
      },
      {
        ruleId: 'Q-OBF-001',
        confidence: 0.7,
        filePath: 'index.js',
        evidence: { entropy: 5.06, threshold: 4.9 },
      },
      {
        ruleId: 'Q-TYP-005',
        confidence: 0.68,
        evidence: { base: 'semver-utils', affix: '-extra' },
      },
      {
        ruleId: 'Q-PRV-001',
        confidence: 0.99,
        evidence: { repositoryField: null },
      },
    ],
    provenance: { status: ProvenanceStatus.NO_REPO },
  },
  {
    ecosystem: NPM,
    name: 'cli-progress-native',
    description: 'Progress bars with native terminal acceleration.',
    repositoryUrl: 'https://github.com/example-org/cli-progress-native',
    weeklyDownloads: 3_300,
    maintainerCount: 1,
    firstPublishedDaysAgo: 210,
    versions: [
      {
        version: '2.0.0',
        publishedDaysAgo: 12,
        unpackedSize: 402_000,
        fileCount: 28,
        hasInstallScripts: true,
        publisherId: 'cpn-dev',
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.SUSPICIOUS,
    confidence: 0.72,
    weightedScore: 49.4,
    durationMs: 3610,
    filesAnalysed: 28,
    signals: [
      {
        ruleId: 'Q-INS-001',
        confidence: 0.99,
        contextModifier: 0.4,
        filePath: 'package.json',
        lineStart: 15,
        excerpt: '"install": "prebuild-install || node-gyp rebuild"',
        evidence: { hooks: ['install'], nativeBuild: true },
      },
      {
        ruleId: 'Q-CAP-009',
        confidence: 0.86,
        filePath: 'build/Release/progress.node',
        excerpt: '/* native addon present; manifest declares no gypfile */',
        evidence: { format: 'ELF', gypfileDeclared: false },
      },
      {
        ruleId: 'Q-MNT-005',
        confidence: 0.73,
        evidence: { previousLatest: '1.8.2', jump: 'major' },
      },
      {
        ruleId: 'Q-MNT-001',
        confidence: 0.69,
        evidence: { dormantDays: 168 },
      },
    ],
    provenance: {
      status: ProvenanceStatus.DIVERGENT,
      repoUrl: 'https://github.com/example-org/cli-progress-native',
      gitRef: 'v2.0.0',
      filesOnlyInTarball: ['build/Release/progress.node'],
      diffSummary: { added: 1, modified: 0, removed: 0 },
    },
  },
];

export const SEED_PACKAGES_SUSPICIOUS = SUSPICIOUS;

// ---------------------------------------------------------------------------
// LOW_RISK — minor signals, no corroboration
// ---------------------------------------------------------------------------

interface LowRiskSpec {
  name: string;
  description: string;
  repositoryUrl?: string;
  weeklyDownloads: number;
  maintainerCount: number;
  firstPublishedDaysAgo: number;
  version: string;
  publishedDaysAgo: number;
  unpackedSize: number;
  fileCount: number;
  publisherId: string;
  confidence: number;
  weightedScore: number;
  signals: SeedSignal[];
  provenance: SeedProvenance;
}

function lowRisk(spec: LowRiskSpec): SeedPackage {
  return {
    ecosystem: NPM,
    name: spec.name,
    description: spec.description,
    ...(spec.repositoryUrl ? { repositoryUrl: spec.repositoryUrl } : {}),
    weeklyDownloads: spec.weeklyDownloads,
    maintainerCount: spec.maintainerCount,
    firstPublishedDaysAgo: spec.firstPublishedDaysAgo,
    versions: [
      {
        version: spec.version,
        publishedDaysAgo: spec.publishedDaysAgo,
        unpackedSize: spec.unpackedSize,
        fileCount: spec.fileCount,
        hasInstallScripts: false,
        publisherId: spec.publisherId,
        provenanceAttested: false,
      },
    ],
    verdict: Verdict.LOW_RISK,
    confidence: spec.confidence,
    weightedScore: spec.weightedScore,
    durationMs: 1200 + spec.fileCount * 40,
    filesAnalysed: spec.fileCount,
    signals: spec.signals,
    provenance: spec.provenance,
  };
}

const LOW_RISK: SeedPackage[] = [
  lowRisk({
    name: 'left-pad-modern',
    description: 'String padding with a modern API surface.',
    repositoryUrl: 'https://github.com/example-org/left-pad-modern',
    weeklyDownloads: 24_000,
    maintainerCount: 1,
    firstPublishedDaysAgo: 900,
    version: '3.0.1',
    publishedDaysAgo: 120,
    unpackedSize: 8_400,
    fileCount: 6,
    publisherId: 'lpm-dev',
    confidence: 0.88,
    weightedScore: 12.4,
    signals: [
      {
        ruleId: 'Q-MNT-004',
        confidence: 0.82,
        evidence: { maintainers: 1, weeklyDownloads: 24_000 },
      },
      { ruleId: 'Q-PRV-006', confidence: 0.99, evidence: { attestation: null } },
    ],
    provenance: {
      status: ProvenanceStatus.MATCH,
      repoUrl: 'https://github.com/example-org/left-pad-modern',
      gitRef: 'v3.0.1',
      diffSummary: { added: 0, modified: 0, removed: 0 },
    },
  }),
  lowRisk({
    name: 'dotenv-expand-plus',
    description: 'Variable expansion for dotenv files.',
    repositoryUrl: 'https://github.com/example-org/dotenv-expand-plus',
    weeklyDownloads: 61_000,
    maintainerCount: 2,
    firstPublishedDaysAgo: 780,
    version: '11.0.3',
    publishedDaysAgo: 45,
    unpackedSize: 11_900,
    fileCount: 8,
    publisherId: 'dep-team',
    confidence: 0.86,
    weightedScore: 15.1,
    signals: [
      {
        ruleId: 'Q-CAP-004',
        confidence: 0.7,
        contextModifier: 0.3,
        filePath: 'src/expand.js',
        lineStart: 14,
        excerpt: 'for (const key of Object.keys(parsed)) { ... }',
        evidence: { note: 'Iterates the parsed dotenv object, not process.env.' },
      },
      { ruleId: 'Q-PRV-006', confidence: 0.99, evidence: { attestation: null } },
    ],
    provenance: {
      status: ProvenanceStatus.MATCH,
      repoUrl: 'https://github.com/example-org/dotenv-expand-plus',
      gitRef: 'v11.0.3',
      diffSummary: { added: 0, modified: 0, removed: 0 },
    },
  }),
  lowRisk({
    name: 'chalk-colours',
    description: 'Terminal colour helpers with British spelling.',
    repositoryUrl: 'https://github.com/example-org/chalk-colours',
    weeklyDownloads: 3_100,
    maintainerCount: 1,
    firstPublishedDaysAgo: 520,
    version: '5.3.0',
    publishedDaysAgo: 88,
    unpackedSize: 9_800,
    fileCount: 7,
    publisherId: 'cc-dev',
    confidence: 0.84,
    weightedScore: 18.6,
    signals: [
      { ruleId: 'Q-TYP-005', confidence: 0.61, evidence: { base: 'chalk', affix: '-colours' } },
      {
        ruleId: 'Q-MNT-004',
        confidence: 0.78,
        evidence: { maintainers: 1, weeklyDownloads: 3_100 },
      },
      { ruleId: 'Q-PRV-006', confidence: 0.99, evidence: { attestation: null } },
    ],
    provenance: {
      status: ProvenanceStatus.MATCH,
      repoUrl: 'https://github.com/example-org/chalk-colours',
      gitRef: 'v5.3.0',
      diffSummary: { added: 0, modified: 0, removed: 0 },
    },
  }),
  lowRisk({
    name: 'tiny-glob-fs',
    description: 'Minimal glob matching over the filesystem.',
    repositoryUrl: 'https://github.com/example-org/tiny-glob-fs',
    weeklyDownloads: 18_400,
    maintainerCount: 1,
    firstPublishedDaysAgo: 640,
    version: '0.2.9',
    publishedDaysAgo: 210,
    unpackedSize: 13_200,
    fileCount: 9,
    publisherId: 'tgf-dev',
    confidence: 0.83,
    weightedScore: 16.9,
    signals: [
      { ruleId: 'Q-MNT-001', confidence: 0.64, evidence: { dormantDays: 198 } },
      {
        ruleId: 'Q-MNT-004',
        confidence: 0.8,
        evidence: { maintainers: 1, weeklyDownloads: 18_400 },
      },
      { ruleId: 'Q-PRV-006', confidence: 0.99, evidence: { attestation: null } },
    ],
    provenance: {
      status: ProvenanceStatus.MATCH,
      repoUrl: 'https://github.com/example-org/tiny-glob-fs',
      gitRef: 'v0.2.9',
      diffSummary: { added: 0, modified: 0, removed: 0 },
    },
  }),
  lowRisk({
    name: 'yaml-front-matter-lite',
    description: 'Front-matter extraction without a full YAML parser.',
    repositoryUrl: 'https://github.com/example-org/yaml-front-matter-lite',
    weeklyDownloads: 7_600,
    maintainerCount: 1,
    firstPublishedDaysAgo: 410,
    version: '1.1.4',
    publishedDaysAgo: 64,
    unpackedSize: 10_100,
    fileCount: 7,
    publisherId: 'yfml-dev',
    confidence: 0.85,
    weightedScore: 13.2,
    signals: [
      {
        ruleId: 'Q-MNT-004',
        confidence: 0.76,
        evidence: { maintainers: 1, weeklyDownloads: 7_600 },
      },
      { ruleId: 'Q-PRV-006', confidence: 0.99, evidence: { attestation: null } },
    ],
    provenance: {
      status: ProvenanceStatus.MATCH,
      repoUrl: 'https://github.com/example-org/yaml-front-matter-lite',
      gitRef: 'v1.1.4',
      diffSummary: { added: 0, modified: 0, removed: 0 },
    },
  }),
  lowRisk({
    name: 'deep-merge-utils',
    description: 'Recursive object merging with array strategies.',
    repositoryUrl: 'https://github.com/example-org/deep-merge-utils',
    weeklyDownloads: 96_000,
    maintainerCount: 3,
    firstPublishedDaysAgo: 1100,
    version: '4.3.1',
    publishedDaysAgo: 30,
    unpackedSize: 15_700,
    fileCount: 11,
    publisherId: 'dmu-team',
    confidence: 0.9,
    weightedScore: 9.8,
    signals: [{ ruleId: 'Q-PRV-006', confidence: 0.99, evidence: { attestation: null } }],
    provenance: {
      status: ProvenanceStatus.MATCH,
      repoUrl: 'https://github.com/example-org/deep-merge-utils',
      gitRef: 'v4.3.1',
      diffSummary: { added: 0, modified: 0, removed: 0 },
    },
  }),
  lowRisk({
    name: 'uuid-v7-shim',
    description: 'UUID v7 generation for runtimes without native support.',
    repositoryUrl: 'https://github.com/example-org/uuid-v7-shim',
    weeklyDownloads: 41_000,
    maintainerCount: 1,
    firstPublishedDaysAgo: 300,
    version: '2.1.0',
    publishedDaysAgo: 18,
    unpackedSize: 7_300,
    fileCount: 5,
    publisherId: 'u7-dev',
    confidence: 0.87,
    weightedScore: 14.5,
    signals: [
      {
        ruleId: 'Q-MNT-004',
        confidence: 0.81,
        evidence: { maintainers: 1, weeklyDownloads: 41_000 },
      },
      { ruleId: 'Q-PRV-006', confidence: 0.99, evidence: { attestation: null } },
    ],
    provenance: {
      status: ProvenanceStatus.MATCH,
      repoUrl: 'https://github.com/example-org/uuid-v7-shim',
      gitRef: 'v2.1.0',
      diffSummary: { added: 0, modified: 0, removed: 0 },
    },
  }),
  lowRisk({
    name: 'p-retry-lite',
    description: 'Retry a promise-returning function with backoff.',
    repositoryUrl: 'https://github.com/example-org/p-retry-lite',
    weeklyDownloads: 52_000,
    maintainerCount: 2,
    firstPublishedDaysAgo: 720,
    version: '6.0.2',
    publishedDaysAgo: 52,
    unpackedSize: 9_100,
    fileCount: 6,
    publisherId: 'prl-team',
    confidence: 0.89,
    weightedScore: 11.3,
    signals: [
      {
        ruleId: 'Q-MNT-006',
        confidence: 0.6,
        evidence: { historicalMedianDays: 90, latestGapDays: 15 },
      },
      { ruleId: 'Q-PRV-006', confidence: 0.99, evidence: { attestation: null } },
    ],
    provenance: {
      status: ProvenanceStatus.MATCH,
      repoUrl: 'https://github.com/example-org/p-retry-lite',
      gitRef: 'v6.0.2',
      diffSummary: { added: 0, modified: 0, removed: 0 },
    },
  }),
];

// ---------------------------------------------------------------------------
// CLEAN — genuine popular packages, nothing fired
// ---------------------------------------------------------------------------

interface CleanSpec {
  name: string;
  description: string;
  repositoryUrl: string;
  weeklyDownloads: number;
  maintainerCount: number;
  firstPublishedDaysAgo: number;
  version: string;
  publishedDaysAgo: number;
  unpackedSize: number;
  fileCount: number;
  publisherId: string;
  attested: boolean;
}

function clean(spec: CleanSpec): SeedPackage {
  return {
    ecosystem: NPM,
    name: spec.name,
    description: spec.description,
    repositoryUrl: spec.repositoryUrl,
    weeklyDownloads: spec.weeklyDownloads,
    maintainerCount: spec.maintainerCount,
    firstPublishedDaysAgo: spec.firstPublishedDaysAgo,
    versions: [
      {
        version: spec.version,
        publishedDaysAgo: spec.publishedDaysAgo,
        unpackedSize: spec.unpackedSize,
        fileCount: spec.fileCount,
        hasInstallScripts: false,
        publisherId: spec.publisherId,
        provenanceAttested: spec.attested,
      },
    ],
    verdict: Verdict.CLEAN,
    confidence: spec.attested ? 0.96 : 0.92,
    weightedScore: spec.attested ? 0 : 1,
    durationMs: 900 + spec.fileCount * 12,
    filesAnalysed: spec.fileCount,
    signals: spec.attested
      ? []
      : [{ ruleId: 'Q-PRV-006', confidence: 0.99, evidence: { attestation: null } }],
    provenance: {
      status: ProvenanceStatus.MATCH,
      repoUrl: spec.repositoryUrl,
      gitRef: `v${spec.version}`,
      diffSummary: { added: 0, modified: 0, removed: 0 },
    },
  };
}

const CLEAN: SeedPackage[] = [
  clean({
    name: 'react',
    description: 'JavaScript library for building user interfaces.',
    repositoryUrl: 'https://github.com/facebook/react',
    weeklyDownloads: 32_000_000,
    maintainerCount: 8,
    firstPublishedDaysAgo: 4300,
    version: '19.2.0',
    publishedDaysAgo: 40,
    unpackedSize: 328_000,
    fileCount: 42,
    publisherId: 'react-bot',
    attested: true,
  }),
  clean({
    name: 'lodash',
    description: 'Modular utility library.',
    repositoryUrl: 'https://github.com/lodash/lodash',
    weeklyDownloads: 52_000_000,
    maintainerCount: 3,
    firstPublishedDaysAgo: 4500,
    version: '4.17.21',
    publishedDaysAgo: 1700,
    unpackedSize: 1_412_000,
    fileCount: 1054,
    publisherId: 'jdalton',
    attested: false,
  }),
  clean({
    name: 'express',
    description: 'Fast, unopinionated web framework for Node.js.',
    repositoryUrl: 'https://github.com/expressjs/express',
    weeklyDownloads: 34_000_000,
    maintainerCount: 6,
    firstPublishedDaysAgo: 4900,
    version: '4.21.2',
    publishedDaysAgo: 260,
    unpackedSize: 212_000,
    fileCount: 18,
    publisherId: 'wesleytodd',
    attested: false,
  }),
  clean({
    name: 'axios',
    description: 'Promise-based HTTP client for the browser and Node.js.',
    repositoryUrl: 'https://github.com/axios/axios',
    weeklyDownloads: 48_000_000,
    maintainerCount: 4,
    firstPublishedDaysAgo: 3600,
    version: '1.7.9',
    publishedDaysAgo: 150,
    unpackedSize: 2_100_000,
    fileCount: 86,
    publisherId: 'jasonsaayman',
    attested: true,
  }),
  clean({
    name: 'zod',
    description: 'TypeScript-first schema validation with static type inference.',
    repositoryUrl: 'https://github.com/colinhacks/zod',
    weeklyDownloads: 19_000_000,
    maintainerCount: 2,
    firstPublishedDaysAgo: 1900,
    version: '3.24.1',
    publishedDaysAgo: 95,
    unpackedSize: 684_000,
    fileCount: 118,
    publisherId: 'colinhacks',
    attested: true,
  }),
  clean({
    name: 'typescript',
    description: 'TypeScript is a language for application-scale JavaScript.',
    repositoryUrl: 'https://github.com/microsoft/TypeScript',
    weeklyDownloads: 62_000_000,
    maintainerCount: 12,
    firstPublishedDaysAgo: 4400,
    version: '5.7.3',
    publishedDaysAgo: 70,
    unpackedSize: 22_800_000,
    fileCount: 96,
    publisherId: 'typescript-bot',
    attested: true,
  }),
  clean({
    name: 'next',
    description: 'The React framework for production.',
    repositoryUrl: 'https://github.com/vercel/next.js',
    weeklyDownloads: 8_400_000,
    maintainerCount: 15,
    firstPublishedDaysAgo: 3200,
    version: '15.1.6',
    publishedDaysAgo: 55,
    unpackedSize: 94_000_000,
    fileCount: 412,
    publisherId: 'vercel-release-bot',
    attested: true,
  }),
  clean({
    name: 'prisma',
    description: 'Next-generation ORM for Node.js and TypeScript.',
    repositoryUrl: 'https://github.com/prisma/prisma',
    weeklyDownloads: 2_900_000,
    maintainerCount: 9,
    firstPublishedDaysAgo: 2400,
    version: '6.3.0',
    publishedDaysAgo: 38,
    unpackedSize: 8_200_000,
    fileCount: 64,
    publisherId: 'prisma-bot',
    attested: true,
  }),
  clean({
    name: 'vitest',
    description: 'Blazing fast unit test framework powered by Vite.',
    repositoryUrl: 'https://github.com/vitest-dev/vitest',
    weeklyDownloads: 7_100_000,
    maintainerCount: 7,
    firstPublishedDaysAgo: 1400,
    version: '3.0.5',
    publishedDaysAgo: 22,
    unpackedSize: 1_840_000,
    fileCount: 148,
    publisherId: 'vitest-bot',
    attested: true,
  }),
  clean({
    name: 'pino',
    description: 'Very low overhead Node.js logger.',
    repositoryUrl: 'https://github.com/pinojs/pino',
    weeklyDownloads: 6_200_000,
    maintainerCount: 5,
    firstPublishedDaysAgo: 3100,
    version: '9.6.0',
    publishedDaysAgo: 61,
    unpackedSize: 268_000,
    fileCount: 38,
    publisherId: 'mcollina',
    attested: false,
  }),
  clean({
    name: 'tailwindcss',
    description: 'A utility-first CSS framework.',
    repositoryUrl: 'https://github.com/tailwindlabs/tailwindcss',
    weeklyDownloads: 13_000_000,
    maintainerCount: 6,
    firstPublishedDaysAgo: 2100,
    version: '3.4.17',
    publishedDaysAgo: 110,
    unpackedSize: 4_600_000,
    fileCount: 92,
    publisherId: 'tailwindlabs',
    attested: true,
  }),
  clean({
    name: 'date-fns',
    description: 'Modern JavaScript date utility library.',
    repositoryUrl: 'https://github.com/date-fns/date-fns',
    weeklyDownloads: 22_000_000,
    maintainerCount: 4,
    firstPublishedDaysAgo: 3300,
    version: '4.1.0',
    publishedDaysAgo: 190,
    unpackedSize: 22_400_000,
    fileCount: 1_640,
    publisherId: 'kossnocorp',
    attested: false,
  }),
];

export const SEED_PACKAGES_LOW_RISK = LOW_RISK;
export const SEED_PACKAGES_CLEAN = CLEAN;

/** All 40 seed packages, worst verdict first. */
export const SEED_PACKAGES: SeedPackage[] = [
  ...KNOWN_MALICIOUS,
  ...LIKELY_MALICIOUS,
  ...SUSPICIOUS,
  ...LOW_RISK,
  ...CLEAN,
];
