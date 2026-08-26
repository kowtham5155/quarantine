import type { Node } from '@babel/types';

import {
  calleeText,
  collectCalls,
  collectImports,
  collectMemberExpressions,
  collectStrings,
  excerptAt,
} from '@/lib/engine/ast';
import {
  CONTEXT_FRAMEWORK_DEPENDENTS,
  type ContextBucket,
} from '@/lib/engine/thresholds';
import type { AnalysisContext, FamilyResult, PackageMetadata } from '@/lib/engine/types';
import {
  confidenceForSource,
  evidence,
  excerptAround,
  lineOf,
  loadSources,
  runFamily,
} from '@/lib/engine/signals/helpers';

/**
 * FAMILY 3 — dangerous capability, weighted by declared purpose.
 *
 * Capability alone means very little. `child_process` in a build tool is the
 * whole point of the package; the same import in a string-padding utility is an
 * alarm. This family therefore fires readily and leans on the context modifier
 * to decide how much each hit is worth — see `deriveContextBucket` below and
 * `CONTEXT_MODIFIERS` in thresholds.ts.
 */

/** Calls that read a whole object at once, the shape env exfiltration takes. */
const ENUMERATING_CALLEES = new Set([
  'Object.keys',
  'Object.entries',
  'Object.values',
  'Object.assign',
  'JSON.stringify',
]);

/** `process.env`, however it is spelled at this position. */
function isEnvironmentNode(node: Node | null | undefined): boolean {
  if (!node) return false;
  if (node.type === 'SpreadElement') return isEnvironmentNode(node.argument as Node);
  return calleeText(node) === 'process.env';
}

/** Does this call read `process.env` itself, rather than merely sit near one? */
function readsEnvironment(node: Node): boolean {
  const args =
    node.type === 'CallExpression' || node.type === 'NewExpression'
      ? ((node.arguments ?? []) as Node[])
      : [];

  for (const argument of args) {
    if (isEnvironmentNode(argument)) return true;

    // `Object.assign({}, process.env)` and `JSON.stringify({ ...process.env })`
    // wrap it one level down, which is the same read with more syntax.
    if (argument.type === 'ObjectExpression') {
      for (const property of argument.properties as Node[]) {
        if (isEnvironmentNode(property)) return true;
      }
    }
  }

  return false;
}

/**
 * A member call that is really `child_process`, reached without an import.
 *
 * `.exec` alone is not enough: `RegExp.prototype.exec` and `String.prototype`
 * matchers share the name, and lodash's `separator.exec(string)` was being
 * reported as process execution. The unambiguous names still fire on their own;
 * bare `exec` has to be hanging off something that names the module.
 */
function isProcessExecMember(text: string): boolean {
  if (/\.(?:execSync|spawnSync|spawn|execFile|execFileSync)$/.test(text)) return true;
  if (/\.fork$/.test(text)) return /child_?process|^cp\.|^proc\./i.test(text);
  if (!/\.exec$/.test(text)) return false;

  const receiver = text.slice(0, -'.exec'.length);
  return /(?:^|\.)(?:child_process|childProcess|cp|proc|process)$/i.test(receiver);
}

export const CAPABILITY_RULES = [
  'Q-CAP-001',
  'Q-CAP-002',
  'Q-CAP-003',
  'Q-CAP-004',
  'Q-CAP-005',
  'Q-CAP-006',
  'Q-CAP-007',
  'Q-CAP-008',
  'Q-CAP-009',
] as const;

// ---------------------------------------------------------------------------
// Context derivation
// ---------------------------------------------------------------------------

/**
 * Keyword sets that place a package in a context bucket.
 *
 * Order matters: the first bucket that matches wins, most-permissive first, so
 * a package describing itself as both a bundler and an http client is judged as
 * a bundler.
 */
const BUCKET_KEYWORDS: Array<{ bucket: ContextBucket; patterns: RegExp[] }> = [
  {
    bucket: 'BUILD_TOOL',
    patterns: [
      /\bbuild\b/,
      /\bbundler?\b/,
      /\bcompiler?\b/,
      /\btranspiler?\b/,
      /\bcli\b/,
      /\btask[- ]?runner\b/,
      /\btest[- ]?runner\b/,
      /\blinter?\b/,
      /\bwebpack\b/,
      /\brollup\b/,
      /\besbuild\b/,
      /\bvite\b/,
      /\bbabel\b/,
      /\bscaffold/,
      /\bgenerator\b/,
      /\bcodegen\b/,
    ],
  },
  {
    bucket: 'SYSTEM',
    patterns: [
      /\bshell\b/,
      /\bexec\b/,
      /\bspawn\b/,
      /\bprocess\b/,
      /\bfilesystem\b/,
      /\bdaemon\b/,
      /\bnative\b/,
      /\bbinding/,
      /\bnode-gyp\b/,
      /\bprebuild/,
      /\bffi\b/,
      /\bsystem\b/,
    ],
  },
  {
    bucket: 'NETWORK',
    patterns: [
      /\bhttp\b/,
      /\bhttps\b/,
      /\bclient\b/,
      /\brequest\b/,
      /\bfetch\b/,
      /\bsocket\b/,
      /\bwebsocket\b/,
      /\bapi\b/,
      /\brpc\b/,
      /\bgrpc\b/,
      /\bserver\b/,
      /\bproxy\b/,
      /\bdns\b/,
    ],
  },
  {
    bucket: 'FRAMEWORK',
    patterns: [
      /\bframework\b/,
      /\breact\b/,
      /\bvue\b/,
      /\bangular\b/,
      /\bsvelte\b/,
      /\bnext\.?js\b/,
      /\bnuxt\b/,
      /\bexpress\b/,
      /\bfastify\b/,
      /\bkoa\b/,
      /\bssr\b/,
    ],
  },
];

/**
 * Classify a package from **metadata only**.
 *
 * Deliberately never reads the code being judged. If the classifier looked at
 * imports, a package could earn itself a discount on `child_process` simply by
 * importing `webpack` — the evasion writes itself. Keywords, name and
 * description are attacker-controlled too, but they are a public claim about
 * what the package is, which is exactly what the modifier is meant to weigh.
 *
 * A package that declares nothing lands in UTILITY and is judged strictly:
 * silence is not a defence.
 */
export function deriveContextBucket(metadata: PackageMetadata): ContextBucket {
  if (
    metadata.dependentCount !== null &&
    metadata.dependentCount >= CONTEXT_FRAMEWORK_DEPENDENTS
  ) {
    return 'FRAMEWORK';
  }

  const haystack = [
    metadata.name,
    metadata.description ?? '',
    ...metadata.keywords,
  ]
    .join(' ')
    .toLowerCase();

  for (const { bucket, patterns } of BUCKET_KEYWORDS) {
    if (patterns.some((pattern) => pattern.test(haystack))) return bucket;
  }

  return 'UTILITY';
}

// ---------------------------------------------------------------------------
// Capability patterns
// ---------------------------------------------------------------------------

const EXEC_MODULES = new Set(['child_process', 'node:child_process']);
const NET_MODULES = new Set([
  'net',
  'node:net',
  'dgram',
  'node:dgram',
  'dns',
  'node:dns',
  'dns/promises',
  'node:dns/promises',
  'tls',
  'node:tls',
]);
const VM_MODULES = new Set(['vm', 'node:vm', 'worker_threads', 'node:worker_threads']);

const CREDENTIAL_PATH_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\.ssh\//, label: '~/.ssh' },
  { pattern: /id_rsa|id_ed25519|id_ecdsa/, label: 'private key' },
  { pattern: /\.aws\/credentials/, label: 'aws credentials' },
  { pattern: /\.aws\/config/, label: 'aws config' },
  { pattern: /\.npmrc/, label: '.npmrc' },
  { pattern: /\.docker\/config\.json/, label: 'docker config' },
  { pattern: /\.kube\/config/, label: 'kubeconfig' },
  { pattern: /Library\/Keychains/, label: 'macOS keychain' },
  { pattern: /\.git-credentials/, label: 'git credentials' },
  { pattern: /\.netrc/, label: '.netrc' },
  { pattern: /\/etc\/shadow|\/etc\/passwd/, label: 'system account file' },
  { pattern: /AppData\\\\Roaming\\\\.*\\\\Login Data/i, label: 'browser login data' },
  { pattern: /Cookies\.sqlite|cookies\.sqlite/, label: 'browser cookies' },
];

const WALLET_PATH_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\.ethereum\//, label: '.ethereum' },
  { pattern: /wallet\.dat/, label: 'wallet.dat' },
  { pattern: /\.bitcoin\//, label: '.bitcoin' },
  { pattern: /keystore/i, label: 'keystore' },
  { pattern: /Exodus.*exodus\.wallet/i, label: 'Exodus wallet' },
  { pattern: /Electrum\/wallets/i, label: 'Electrum wallet' },
  { pattern: /nkbihfbeogaeaoehlefnkodbefgpgknn/, label: 'MetaMask extension id' },
  { pattern: /\.config\/solana/, label: 'solana config' },
  { pattern: /Ledger Live/i, label: 'Ledger Live' },
];

/**
 * A hardcoded IPv4 address. Excludes the dotted-quad-looking version strings
 * and the loopback/documentation ranges that appear in tests and examples.
 */
const IPV4_LITERAL = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;

const WEBHOOK_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /discord(?:app)?\.com\/api\/webhooks/i, label: 'Discord webhook' },
  { pattern: /discord\.com\/api\/v\d+\/webhooks/i, label: 'Discord webhook' },
  { pattern: /api\.telegram\.org\/bot/i, label: 'Telegram bot API' },
  { pattern: /hooks\.slack\.com\/services/i, label: 'Slack webhook' },
  { pattern: /webhook\.site/i, label: 'webhook.site' },
  { pattern: /pipedream\.net/i, label: 'Pipedream endpoint' },
  { pattern: /requestbin|\.ngrok\.io|\.ngrok-free\.app/i, label: 'tunnelling endpoint' },
  { pattern: /oast\.(?:fun|live|site|online|pro|me)/i, label: 'OAST callback host' },
  { pattern: /\.interact\.sh/i, label: 'interact.sh callback' },
  { pattern: /burpcollaborator\.net/i, label: 'Burp Collaborator' },
];

const NATIVE_EXTENSIONS = /\.(node|so|dylib|dll|exe|wasm)$/i;

export async function analyseCapability(context: AnalysisContext): Promise<FamilyResult> {
  return runFamily('CAPABILITY', context, CAPABILITY_RULES, async (builder) => {
    const { files, metadata } = context.artifact;
    const { sources } = await loadSources(files);

    const fired = new Set<string>();
    const mark = (ruleId: string): void => void fired.add(ruleId);

    for (const source of sources) {
      const { file, text, parsed } = source;

      // ---------------------------------------------------------------------
      // Q-CAP-001 / 002 / 003 — module imports
      // ---------------------------------------------------------------------
      const imports = parsed.parsed ? collectImports(parsed) : importsByRegex(text);

      for (const record of imports) {
        const target = record.source;

        if (EXEC_MODULES.has(target)) {
          mark('Q-CAP-001');
          builder.fire('Q-CAP-001', confidenceForSource(source, 0.95), [
            evidence(file.path, record.line, undefined, { module: target, kind: record.kind }),
          ]);
        }

        if (NET_MODULES.has(target)) {
          mark('Q-CAP-002');
          builder.fire('Q-CAP-002', confidenceForSource(source, 0.9), [
            evidence(file.path, record.line, undefined, { module: target, kind: record.kind }),
          ]);
        }

        if (VM_MODULES.has(target)) {
          mark('Q-CAP-003');
          builder.fire('Q-CAP-003', confidenceForSource(source, 0.9), [
            evidence(file.path, record.line, undefined, { module: target, kind: record.kind }),
          ]);
        }
      }

      // ---------------------------------------------------------------------
      // Q-CAP-004 — wholesale process.env access
      // ---------------------------------------------------------------------
      // Reading one variable is ordinary configuration. Enumerating the whole
      // environment is the exfiltration shape: CI secrets, tokens, everything.
      if (parsed.parsed) {
        for (const call of collectCalls(parsed)) {
          if (!ENUMERATING_CALLEES.has(call.callee)) continue;

          // The environment has to be what this call is actually reading.
          // Testing the whole file for `process.env` fires on every
          // `JSON.stringify` in any file that mentions the environment once —
          // esbuild's install.js took eleven CRITICAL hits that way, none of
          // them touching the environment at all.
          if (!readsEnvironment(call.node)) continue;

          mark('Q-CAP-004');
          builder.fire('Q-CAP-004', confidenceForSource(source, 0.8), [
            evidence(file.path, call.line, excerptAt(text, call.line), {
              pattern: call.callee,
            }),
          ]);
        }

        // `{ ...process.env }` is the same idea with different syntax.
        if (/\.\.\.\s*process\.env/.test(text)) {
          const index = text.search(/\.\.\.\s*process\.env/);
          mark('Q-CAP-004');
          builder.fire('Q-CAP-004', confidenceForSource(source, 0.85), [
            evidence(file.path, lineOf(text, index), excerptAround(text, index), {
              pattern: 'spread',
            }),
          ]);
        }
      } else if (/Object\.(?:keys|entries|values)\s*\(\s*process\.env|\.\.\.\s*process\.env/.test(text)) {
        const index = text.search(/Object\.(?:keys|entries|values)\s*\(\s*process\.env|\.\.\.\s*process\.env/);
        mark('Q-CAP-004');
        builder.fire('Q-CAP-004', confidenceForSource(source, 0.8), [
          evidence(file.path, lineOf(text, index), excerptAround(text, index), {
            viaByteScan: true,
          }),
        ]);
      }

      // ---------------------------------------------------------------------
      // Q-CAP-005 / 006 — credential and wallet paths
      // ---------------------------------------------------------------------
      const literals = parsed.parsed
        ? collectStrings(parsed).map((record) => ({ value: record.value, line: record.line }))
        : [{ value: text, line: 1 }];

      for (const literal of literals) {
        for (const { pattern, label } of CREDENTIAL_PATH_PATTERNS) {
          if (!pattern.test(literal.value)) continue;
          mark('Q-CAP-005');
          builder.fire('Q-CAP-005', confidenceForSource(source, 0.9), [
            evidence(file.path, literal.line, literal.value.slice(0, 120), { target: label }),
          ]);
        }

        for (const { pattern, label } of WALLET_PATH_PATTERNS) {
          if (!pattern.test(literal.value)) continue;
          mark('Q-CAP-006');
          builder.fire('Q-CAP-006', confidenceForSource(source, 0.9), [
            evidence(file.path, literal.line, literal.value.slice(0, 120), { target: label }),
          ]);
        }

        // -------------------------------------------------------------------
        // Q-CAP-008 — exfiltration endpoints
        // -------------------------------------------------------------------
        for (const { pattern, label } of WEBHOOK_PATTERNS) {
          if (!pattern.test(literal.value)) continue;
          mark('Q-CAP-008');
          builder.fire('Q-CAP-008', confidenceForSource(source, 0.95), [
            evidence(file.path, literal.line, literal.value.slice(0, 160), { endpoint: label }),
          ]);
        }
      }

      // ---------------------------------------------------------------------
      // Q-CAP-007 — hardcoded IP in what looks like a network call
      // ---------------------------------------------------------------------
      IPV4_LITERAL.lastIndex = 0;
      let ipMatch: RegExpExecArray | null;
      while ((ipMatch = IPV4_LITERAL.exec(text)) !== null) {
        const address = ipMatch[0];
        if (!isRoutableLiteral(address)) continue;

        // Only interesting next to something that could send it somewhere.
        const around = text.slice(Math.max(0, ipMatch.index - 120), ipMatch.index + 120);
        if (!/https?:|connect|socket|fetch|request|axios|post|get\s*\(|curl|\/\/|:\d{2,5}/i.test(around)) {
          continue;
        }

        mark('Q-CAP-007');
        builder.fire('Q-CAP-007', confidenceForSource(source, 0.75), [
          evidence(file.path, lineOf(text, ipMatch.index), excerptAround(text, ipMatch.index), {
            address,
          }),
        ]);
        break;
      }

      // Member access to exec/spawn without an import — e.g. destructured from
      // a re-export, or reached through a global.
      if (parsed.parsed) {
        for (const member of collectMemberExpressions(parsed)) {
          if (!isProcessExecMember(member.text)) continue;
          if (fired.has('Q-CAP-001')) break;

          mark('Q-CAP-001');
          builder.fire('Q-CAP-001', confidenceForSource(source, 0.6), [
            evidence(file.path, member.line, undefined, { member: member.text, viaMember: true }),
          ]);
          break;
        }
      }
    }

    // -----------------------------------------------------------------------
    // Q-CAP-009 — native binaries in a package that claims to be pure JS
    // -----------------------------------------------------------------------
    const declaresNative =
      files.some((file) => /(?:^|\/)binding\.gyp$/.test(file.path)) ||
      Object.keys(metadata.dependencies).some((dependency) =>
        /node-gyp|prebuild|node-pre-gyp|node-addon-api|bindings/.test(dependency),
      ) ||
      Object.values(metadata.scripts).some((script) => /node-gyp|prebuild/.test(script)) ||
      metadata.keywords.some((keyword) => /native|binding|addon|ffi/i.test(keyword));

    const binaries = files.filter((file) => NATIVE_EXTENSIONS.test(file.path));

    if (binaries.length > 0 && !declaresNative) {
      mark('Q-CAP-009');
      builder.fire(
        'Q-CAP-009',
        0.9,
        binaries
          .slice(0, 10)
          .map((file) =>
            evidence(file.path, undefined, undefined, { bytes: file.size, sha256: file.sha256 }),
          ),
      );
    }

    for (const ruleId of CAPABILITY_RULES) {
      if (!fired.has(ruleId)) builder.pass(ruleId);
    }
  });
}

/**
 * Whether a dotted quad is a real, routable address worth reporting.
 *
 * Version strings, loopback, and the documentation ranges that legitimately
 * appear in tests and READMEs are all excluded — flagging `127.0.0.1` in a test
 * fixture is exactly the kind of noise that makes a scanner ignorable.
 */
export function isRoutableLiteral(address: string): boolean {
  const octets = address.split('.').map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet > 255)) {
    return false;
  }

  const [a, b] = octets as [number, number, number, number];

  if (a === 0 || a === 127) return false; // this-network, loopback
  if (a === 10) return false; // RFC1918
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false; // link-local
  if (a === 192 && b === 0) return false; // TEST-NET-1 / protocol assignments
  if (a === 198 && (b === 18 || b === 19 || b === 51)) return false; // benchmarking, TEST-NET-2
  if (a === 203 && b === 0) return false; // TEST-NET-3
  if (a >= 224) return false; // multicast and reserved

  return true;
}

/** Import extraction for files the parser could not handle. */
function importsByRegex(text: string): Array<{ source: string; kind: 'require'; line: number }> {
  const out: Array<{ source: string; kind: 'require'; line: number }> = [];
  const pattern = /(?:require\s*\(\s*|from\s+|import\s*\(\s*)['"]([^'"]{1,200})['"]/g;

  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    const target = match[1];
    if (target) out.push({ source: target, kind: 'require', line: lineOf(text, match.index) });
    if (out.length >= 500) break;
  }

  return out;
}
