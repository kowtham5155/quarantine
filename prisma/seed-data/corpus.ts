import { CorpusLabel, Ecosystem } from '@prisma/client';

/**
 * Labelled evaluation corpus — 60 entries.
 *
 * The clean half is deliberately split between popular packages (where a false
 * positive is catastrophic and immediately noticed) and obscure ones (where the
 * signals that separate malware from an unmaintained hobby project are much
 * weaker). Evaluation reports false-positive rate separately for the two
 * groups, because a single blended number hides exactly the failure mode that
 * matters.
 */

export interface SeedCorpusEntry {
  packageName: string;
  version: string;
  label: CorpusLabel;
  source: string;
  notes?: string;
  expectedSignals: string[];
  /** Obscure negatives are the hard case for false positives. */
  popular?: boolean;
}

const M = CorpusLabel.MALICIOUS;
const C = CorpusLabel.CLEAN;

export const SEED_CORPUS: SeedCorpusEntry[] = [
  // --- Confirmed malicious: documented historical incidents ----------------
  {
    packageName: 'event-stream',
    version: '3.3.6',
    label: M,
    source: 'npm advisory / public post-mortem',
    notes: 'flatmap-stream payload present in tarball, absent from the repository tag.',
    expectedSignals: ['Q-PRV-003', 'Q-OBF-004', 'Q-OBF-003', 'Q-MNT-002'],
  },
  {
    packageName: 'ua-parser-js',
    version: '0.7.29',
    label: M,
    source: 'npm advisory / GHSA',
    notes: 'Account takeover; preinstall script fetched a second stage.',
    expectedSignals: ['Q-INS-001', 'Q-INS-002', 'Q-INS-005', 'Q-CAP-009'],
  },
  {
    packageName: 'coa',
    version: '2.0.3',
    label: M,
    source: 'npm advisory',
    notes: 'Same campaign as rc; obfuscated postinstall entrypoint.',
    expectedSignals: ['Q-INS-001', 'Q-INS-007', 'Q-INS-005'],
  },
  {
    packageName: 'rc',
    version: '1.2.9',
    label: M,
    source: 'npm advisory',
    notes: 'Three version lines published within minutes.',
    expectedSignals: ['Q-INS-001', 'Q-INS-003', 'Q-MNT-005'],
  },
  {
    packageName: 'eslint-scope',
    version: '3.7.2',
    label: M,
    source: 'npm advisory / public post-mortem',
    notes: 'Credential theft targeting ~/.npmrc.',
    expectedSignals: ['Q-INS-001', 'Q-INS-004', 'Q-INS-005'],
  },
  {
    packageName: 'node-ipc',
    version: '10.1.1',
    label: M,
    source: 'GHSA-97m3-w2cp-4xx6',
    notes: 'Destructive payload gated on IP geolocation.',
    expectedSignals: ['Q-OBF-002', 'Q-CAP-007', 'Q-INS-006'],
  },
  {
    packageName: 'flatmap-stream',
    version: '0.1.1',
    label: M,
    source: 'npm advisory',
    notes: 'The payload carrier in the event-stream incident.',
    expectedSignals: ['Q-OBF-004', 'Q-OBF-002', 'Q-OBF-003'],
  },
  {
    packageName: 'electron-native-notify',
    version: '1.1.6',
    label: M,
    source: 'public post-mortem',
    notes: 'Long-dormant package updated with a wallet-targeting payload.',
    expectedSignals: ['Q-MNT-001', 'Q-CAP-006', 'Q-OBF-003'],
  },

  // --- Confirmed malicious: synthetic campaign samples ---------------------
  ...[
    ['lodahs', '4.17.22', ['Q-INS-004', 'Q-INS-005', 'Q-CAP-008', 'Q-TYP-001']],
    ['axioss-http', '1.7.10', ['Q-CAP-004', 'Q-CAP-008', 'Q-OBF-007']],
    ['expresss-session', '1.18.2', ['Q-INS-003', 'Q-OBF-003', 'Q-TYP-003']],
    ['node-fetch-cli', '3.3.3', ['Q-INS-002', 'Q-INS-004', 'Q-INS-006']],
    ['discordjs-utils-core', '2.1.0', ['Q-CAP-005', 'Q-CAP-008', 'Q-OBF-004']],
    ['@typesnode/runtime', '1.0.4', ['Q-INS-004', 'Q-TYP-004', 'Q-TYP-006']],
    ['crypto-wallet-helper', '0.4.1', ['Q-CAP-006', 'Q-CAP-007', 'Q-CAP-002']],
    ['reqeusts', '2.88.3', ['Q-INS-005', 'Q-CAP-004', 'Q-TYP-001']],
    ['colours-terminal', '1.4.0', ['Q-TYP-002', 'Q-INS-001', 'Q-INS-005']],
    ['babel-preset-env-cli', '7.1.2', ['Q-INS-002', 'Q-OBF-002']],
    ['webpack-cli-utils', '5.0.9', ['Q-CAP-001', 'Q-CAP-008', 'Q-OBF-007']],
    ['jsonwebtoken-lite', '9.0.4', ['Q-CAP-005', 'Q-OBF-003']],
    ['mongoose-schema-utils', '8.2.1', ['Q-CAP-004', 'Q-INS-005']],
    ['aws-sdk-helper', '3.1.7', ['Q-CAP-005', 'Q-INS-004', 'Q-CAP-008']],
    ['puppeteer-extra-lite', '3.3.2', ['Q-CAP-001', 'Q-INS-002']],
    ['bootstrap-icons-core', '1.11.4', ['Q-OBF-005', 'Q-OBF-002']],
  ].map(([packageName, version, expectedSignals]) => ({
    packageName: packageName as string,
    version: version as string,
    label: M,
    source: 'quarantine campaign corpus',
    notes: 'Synthetic sample modelled on an observed campaign.',
    expectedSignals: expectedSignals as string[],
  })),

  // --- Clean: popular negatives -------------------------------------------
  ...[
    ['react', '19.2.0'],
    ['lodash', '4.17.21'],
    ['express', '4.21.2'],
    ['axios', '1.7.9'],
    ['zod', '3.24.1'],
    ['typescript', '5.7.3'],
    ['next', '15.1.6'],
    ['prisma', '6.3.0'],
    ['vitest', '3.0.5'],
    ['pino', '9.6.0'],
    ['tailwindcss', '3.4.17'],
    ['date-fns', '4.1.0'],
    ['chalk', '5.4.1'],
    ['commander', '13.0.0'],
    ['glob', '11.0.1'],
    ['semver', '7.7.1'],
    ['esbuild', '0.24.2'],
    ['rollup', '4.34.6'],
  ].map(([packageName, version]) => ({
    packageName: packageName as string,
    version: version as string,
    label: C,
    source: 'top-5000 by weekly downloads',
    notes: 'Popular negative. A false positive here is immediately visible.',
    expectedSignals: [],
    popular: true,
  })),

  // --- Clean: obscure negatives (the hard case) ---------------------------
  ...[
    ['left-pad-modern', '3.0.1', ['Q-MNT-004']],
    ['dotenv-expand-plus', '11.0.3', ['Q-CAP-004']],
    ['chalk-colours', '5.3.0', ['Q-TYP-005', 'Q-MNT-004']],
    ['tiny-glob-fs', '0.2.9', ['Q-MNT-001', 'Q-MNT-004']],
    ['yaml-front-matter-lite', '1.1.4', ['Q-MNT-004']],
    ['deep-merge-utils', '4.3.1', []],
    ['uuid-v7-shim', '2.1.0', ['Q-MNT-004']],
    ['p-retry-lite', '6.0.2', ['Q-MNT-006']],
    ['ini-parser-strict', '2.0.3', ['Q-MNT-004']],
    ['xml-escape-utils', '1.2.2', ['Q-PRV-001']],
    ['cron-parser-tiny', '0.7.1', ['Q-MNT-001']],
    ['base32-encode-lite', '3.0.0', ['Q-OBF-002']],
    ['node-gyp-build-shim', '4.8.1', ['Q-INS-001', 'Q-CAP-009']],
    ['image-size-probe', '1.9.0', ['Q-MNT-004']],
    ['tar-stream-lite', '3.1.8', ['Q-MNT-004']],
    ['bufferutil-shim', '4.0.9', ['Q-INS-001', 'Q-CAP-009']],
    ['diff-match-patch-es', '1.0.5', []],
    ['ansi-regex-strict', '6.1.1', []],
  ].map(([packageName, version, expectedSignals]) => ({
    packageName: packageName as string,
    version: version as string,
    label: C,
    source: 'long-tail sample, manually reviewed',
    notes:
      'Obscure negative. Low downloads and a sole maintainer look superficially like a malicious package.',
    expectedSignals: expectedSignals as string[],
    popular: false,
  })),
];

export const CORPUS_ECOSYSTEM = Ecosystem.NPM;
