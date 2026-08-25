/**
 * The four incidents this system is built around.
 *
 * Static reference content, not data: it is the same for every reader, it is
 * drawn from public post-mortems, and it belongs in the repository rather than
 * in a table nobody can review.
 */

export interface Incident {
  package: string;
  year: string;
  mechanism: string;
  /** How long the malicious artefact was published before anyone caught it. */
  undetected: string;
  /** Which signal families would have had something to say about it. */
  families: Array<
    'INSTALL' | 'OBFUSCATION' | 'CAPABILITY' | 'TYPOSQUAT' | 'MAINTAINER' | 'PROVENANCE'
  >;
  /** The observable evidence that was sitting there the whole time. */
  evidence: string;
}

export const INCIDENTS: Incident[] = [
  {
    package: 'event-stream',
    year: '2018',
    mechanism:
      'Maintainer handed control to an attacker, who published a version whose tarball contained code not present in the GitHub repository.',
    undetected: '~2.5 months',
    families: ['PROVENANCE', 'OBFUSCATION', 'MAINTAINER'],
    evidence: 'An encrypted payload in the tarball with no counterpart at the repository tag.',
  },
  {
    package: 'ua-parser-js',
    year: '2021',
    mechanism:
      "Maintainer's npm account was hijacked and malicious versions published with a preinstall script.",
    undetected: 'hours, at ~7M weekly downloads',
    families: ['INSTALL', 'CAPABILITY'],
    evidence: 'A preinstall script that downloaded and ran a binary before any code was imported.',
  },
  {
    package: 'node-ipc',
    year: '2022',
    mechanism: 'A trusted maintainer shipped a destructive payload in a patch release.',
    undetected: 'days',
    families: ['OBFUSCATION', 'CAPABILITY', 'MAINTAINER'],
    evidence: 'Base64-encoded file paths and filesystem writes outside the package directory.',
  },
  {
    package: 'xz-utils',
    year: '2024',
    mechanism:
      'Multi-year social-engineering campaign; the payload was hidden in test fixture binaries and absent from the visible source.',
    undetected: '~2 years',
    families: ['PROVENANCE', 'MAINTAINER'],
    evidence: 'Binary fixtures in the release tarball that the repository build did not produce.',
  },
];
