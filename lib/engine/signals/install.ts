import { collectImports, collectStrings, parseSource } from '@/lib/engine/ast';
import {
  MINIFIED_AVG_LINE_LENGTH,
  MINIFIED_MIN_FILE_BYTES,
} from '@/lib/engine/thresholds';
import type { AnalysisContext, FamilyResult } from '@/lib/engine/types';
import { evidence, excerptAround, lineOf, readText, runFamily } from '@/lib/engine/signals/helpers';

/**
 * FAMILY 1 — install-time execution.
 *
 * This is where nearly all real npm malware lives. A lifecycle script runs
 * automatically, with the installing user's privileges, before any of the
 * package's code is ever imported — so it fires on a developer laptop and on a
 * CI runner without anyone calling a single function.
 *
 * Everything here is string analysis over the declared `scripts` block and, for
 * PyPI, over `setup.py` as text. Nothing is executed. There is deliberately no
 * "run it and see" path: the whole point is to decide before installation.
 */

export const INSTALL_RULES = [
  'Q-INS-001',
  'Q-INS-002',
  'Q-INS-003',
  'Q-INS-004',
  'Q-INS-005',
  'Q-INS-006',
  'Q-INS-007',
] as const;

/** Script names npm runs on its own during an install. */
const LIFECYCLE_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'] as const;

/** Hooks that run on a plain `npm install` of a dependency. */
const AUTO_RUN_HOOKS = new Set(['preinstall', 'install', 'postinstall']);

const INTERPRETER_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\bcurl\b/i, label: 'curl' },
  { pattern: /\bwget\b/i, label: 'wget' },
  { pattern: /\bbash\s+-c\b/i, label: 'bash -c' },
  { pattern: /\bsh\s+-c\b/i, label: 'sh -c' },
  { pattern: /\bpowershell\b/i, label: 'powershell' },
  { pattern: /\bnode\s+-e\b/i, label: 'node -e' },
  { pattern: /\bnode\s+--eval\b/i, label: 'node --eval' },
  { pattern: /\bpython3?\s+-c\b/i, label: 'python -c' },
  { pattern: /\beval\b/, label: 'eval' },
  { pattern: /\bnc\s+-/i, label: 'netcat' },
  { pattern: /\bIEX\b/, label: 'Invoke-Expression' },
];

const DECODE_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\bbase64\s+(?:-d|--decode|-D)\b/i, label: 'base64 -d' },
  { pattern: /\batob\s*\(/i, label: 'atob()' },
  { pattern: /Buffer\.from\s*\([^)]*['"]base64['"]/i, label: "Buffer.from(…, 'base64')" },
  { pattern: /\bxxd\s+-r\b/i, label: 'xxd -r' },
  { pattern: /\bbase64\.b64decode\b/i, label: 'base64.b64decode' },
  { pattern: /\bcodecs\.decode\b/i, label: 'codecs.decode' },
  { pattern: /\bfromCharCode\b/, label: 'String.fromCharCode' },
  { pattern: /\bunhexlify\b/i, label: 'unhexlify' },
];

const CREDENTIAL_PATHS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\.npmrc\b/, label: '.npmrc' },
  { pattern: /\.ssh\b/, label: '~/.ssh' },
  { pattern: /\.aws\b/, label: '~/.aws' },
  { pattern: /\.docker\/config\.json/, label: 'docker config' },
  { pattern: /\.kube\/config/, label: 'kubeconfig' },
  { pattern: /\/etc\/passwd/, label: '/etc/passwd' },
  { pattern: /\/etc\/shadow/, label: '/etc/shadow' },
  { pattern: /\.env\b/, label: '.env' },
  { pattern: /\.git-credentials/, label: '.git-credentials' },
  { pattern: /id_rsa|id_ed25519/, label: 'private key' },
  { pattern: /\.netrc\b/, label: '.netrc' },
  { pattern: /HOME\s*\+|\$HOME|%USERPROFILE%/, label: 'home directory' },
];

const NETWORK_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /https?:\/\/[^\s'"$]+/i, label: 'http URL' },
  { pattern: /\bcurl\b/i, label: 'curl' },
  { pattern: /\bwget\b/i, label: 'wget' },
  { pattern: /\bfetch\s*\(/, label: 'fetch()' },
  { pattern: /\brequire\s*\(\s*['"]https?['"]\s*\)/, label: "require('http')" },
  { pattern: /\burllib\b|\brequests\.(?:get|post)\b/i, label: 'python http' },
  { pattern: /\bnc\s+-/i, label: 'netcat' },
  { pattern: /\bInvoke-WebRequest\b/i, label: 'Invoke-WebRequest' },
];

const WRITE_OUTSIDE_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: />\s*\/(?:etc|usr|bin|sbin|opt|var|root)\//, label: 'redirect to a system path' },
  { pattern: /\bcp\s+[^\s]+\s+\/(?:etc|usr|bin|sbin|opt|var|root)\//, label: 'copy to a system path' },
  { pattern: /\bmv\s+[^\s]+\s+\/(?:etc|usr|bin|sbin|opt|var|root)\//, label: 'move to a system path' },
  { pattern: /~\/\.(?:bashrc|zshrc|profile|bash_profile)/, label: 'shell profile' },
  { pattern: /\bcrontab\b/, label: 'crontab' },
  { pattern: /LaunchAgents|systemd\/system|\.service\b/, label: 'service persistence' },
  { pattern: /\bchmod\s+\+x\b/, label: 'chmod +x' },
  { pattern: />\s*\$HOME\//, label: 'redirect into the home directory' },
];

/** Files PyPI executes at install time for a source distribution. */
const PYTHON_INSTALL_FILES = new Set(['setup.py', 'setup.cfg', 'conftest.py']);

export async function analyseInstall(context: AnalysisContext): Promise<FamilyResult> {
  return runFamily('INSTALL', context, INSTALL_RULES, async (builder) => {
    const { metadata, files } = context.artifact;

    // -----------------------------------------------------------------------
    // Collect the install surface: npm's scripts block, plus Python's setup.py
    // -----------------------------------------------------------------------
    interface InstallSource {
      label: string;
      body: string;
      /** True when this runs automatically during a dependency install. */
      autoRun: boolean;
      file: string;
    }

    const surfaces: InstallSource[] = [];

    for (const [hook, body] of Object.entries(metadata.scripts)) {
      if (!LIFECYCLE_HOOKS.includes(hook as (typeof LIFECYCLE_HOOKS)[number])) continue;
      surfaces.push({
        label: hook,
        body,
        autoRun: AUTO_RUN_HOOKS.has(hook),
        file: 'package.json',
      });
    }

    for (const file of files) {
      const base = file.path.split('/').pop() ?? '';
      if (!PYTHON_INSTALL_FILES.has(base)) continue;
      if (file.path.includes('/')) continue; // only the top-level setup.py runs

      const text = await readText(file);
      if (text === null) continue;
      surfaces.push({ label: base, body: text, autoRun: true, file: file.path });
    }

    if (surfaces.length === 0) {
      // Nothing runs at install time. Every rule in this family is evaluated
      // and passes — a real finding, not a gap.
      for (const ruleId of INSTALL_RULES) builder.pass(ruleId);
      return;
    }

    // -----------------------------------------------------------------------
    // Q-INS-001 — a lifecycle script exists at all
    // -----------------------------------------------------------------------
    const autoRunSurfaces = surfaces.filter((surface) => surface.autoRun);

    if (autoRunSurfaces.length > 0) {
      builder.fire(
        'Q-INS-001',
        0.95,
        autoRunSurfaces.map((surface) =>
          evidence(surface.file, undefined, surface.body, { hook: surface.label }),
        ),
      );
    }

    // -----------------------------------------------------------------------
    // Q-INS-002 through Q-INS-006 — what the script actually does
    // -----------------------------------------------------------------------
    const scan = (
      ruleId: string,
      patterns: Array<{ pattern: RegExp; label: string }>,
      confidence: number,
    ): void => {
      let matched = false;

      for (const surface of surfaces) {
        for (const { pattern, label } of patterns) {
          const match = pattern.exec(surface.body);
          if (!match) continue;

          matched = true;
          builder.fire(ruleId, surface.autoRun ? confidence : confidence * 0.6, [
            evidence(
              surface.file,
              surface.file === 'package.json' ? undefined : lineOf(surface.body, match.index),
              excerptAround(surface.body, match.index),
              { hook: surface.label, matched: label, autoRun: surface.autoRun },
            ),
          ]);
        }
      }

      if (!matched) builder.pass(ruleId);
    };

    scan('Q-INS-002', INTERPRETER_PATTERNS, 0.9);
    scan('Q-INS-003', DECODE_PATTERNS, 0.85);
    scan('Q-INS-004', CREDENTIAL_PATHS, 0.9);
    scan('Q-INS-005', NETWORK_PATTERNS, 0.85);
    scan('Q-INS-006', WRITE_OUTSIDE_PATTERNS, 0.8);

    // -----------------------------------------------------------------------
    // Q-INS-007 — the entrypoint the script invokes is obfuscated or minified
    // -----------------------------------------------------------------------
    let entrypointFlagged = false;

    for (const surface of surfaces) {
      for (const target of resolveScriptTargets(surface.body)) {
        const file = files.find(
          (candidate) => candidate.path === target || candidate.path === `${target}.js`,
        );
        if (!file) continue;

        const text = await readText(file);
        if (text === null) continue;

        const reason = obfuscationReason(text, file.size);
        if (!reason) continue;

        entrypointFlagged = true;
        builder.fire('Q-INS-007', 0.8, [
          evidence(file.path, 1, text.slice(0, 200), { hook: surface.label, reason }),
        ]);
      }
    }

    if (!entrypointFlagged) builder.pass('Q-INS-007');
  });
}

/**
 * Local script files an install command runs, e.g. `node ./scripts/build.js`.
 *
 * String matching only — the command is never executed to find out what it
 * would resolve to.
 */
export function resolveScriptTargets(command: string): string[] {
  const targets: string[] = [];
  const pattern = /(?:^|[\s;&|])(?:node|npx|ts-node|python3?)\s+(?:--?\S+\s+)*['"]?([^\s'";|&]+)/g;

  let match: RegExpExecArray | null;
  while ((match = pattern.exec(command)) !== null) {
    const target = match[1];
    if (!target) continue;
    if (target.startsWith('-')) continue;
    targets.push(target.replace(/^\.\//, ''));
  }

  return targets;
}

/** Why a file reads as obfuscated, or null when it looks ordinary. */
export function obfuscationReason(text: string, size: number): string | null {
  if (/^\s*(?:var|const|let)\s+_0x[0-9a-f]+/m.test(text)) return 'hex-mangled identifiers';
  if (/\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}/.test(text)) return 'hex escape run';

  if (size >= MINIFIED_MIN_FILE_BYTES) {
    const lines = text.split('\n');
    const average = text.length / Math.max(1, lines.length);
    if (average > MINIFIED_AVG_LINE_LENGTH) return 'minified';
  }

  // A file that is mostly one enormous string literal is a payload, not code.
  const parsed = parseSource('entry', text);
  if (parsed.parsed) {
    const strings = collectStrings(parsed);
    const stringBytes = strings.reduce((total, record) => total + record.length, 0);
    if (text.length > 512 && stringBytes / text.length > 0.7) return 'dominated by string data';

    // An entrypoint whose only job is to pull in something else.
    const imports = collectImports(parsed);
    if (imports.length === 0 && /eval|Function\s*\(/.test(text)) return 'dynamic evaluation';
  }

  return null;
}
