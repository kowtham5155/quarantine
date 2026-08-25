import { Severity, SignalFamily } from '@prisma/client';
import { describe, expect, it } from 'vitest';

import { splitCoordinate } from '@/app/(app)/scan/scan-state';
import {
  familyBreakdown,
  fileInventory,
  hardTriggerDetail,
  type RuleMeta,
  type SignalHitRow,
} from '@/lib/services/package.service';

function hit(overrides: Partial<SignalHitRow> = {}): SignalHitRow {
  return {
    id: Math.random().toString(36).slice(2),
    ruleId: 'Q-INS-001',
    family: SignalFamily.INSTALL,
    severity: Severity.HIGH,
    weight: 10,
    confidence: 1,
    contextModifier: 1,
    filePath: 'package.json',
    lineStart: 3,
    lineEnd: 3,
    excerpt: '"postinstall": "node ./setup.js"',
    evidence: {},
    ...overrides,
  };
}

function rule(overrides: Partial<RuleMeta> = {}): RuleMeta {
  return {
    ruleId: 'Q-INS-001',
    family: SignalFamily.INSTALL,
    name: 'Install script present',
    description: '',
    severity: Severity.HIGH,
    baseWeight: 10,
    remediation: '',
    references: [],
    enabled: true,
    falsePositiveNotes: null,
    ...overrides,
  };
}

describe('fileInventory', () => {
  it('groups hits by file and counts a rule once, however many times it matched', () => {
    const rows = fileInventory([
      hit({ filePath: 'index.js', ruleId: 'Q-OBF-001', weight: 6, lineStart: 1, lineEnd: 2 }),
      hit({ filePath: 'index.js', ruleId: 'Q-OBF-001', weight: 6, lineStart: 40, lineEnd: 40 }),
      hit({ filePath: 'index.js', ruleId: 'Q-CAP-001', weight: 4, lineStart: 7, lineEnd: 7 }),
    ]);

    expect(rows).toHaveLength(1);
    expect(rows[0]?.ruleIds).toEqual(['Q-CAP-001', 'Q-OBF-001']);
    // 6 + 4, not 6 + 6 + 4.
    expect(rows[0]?.risk).toBe(10);
    expect(rows[0]?.flaggedLines).toBe(4);
  });

  it('ranks files by risk and keeps the worst severity per file', () => {
    const rows = fileInventory([
      hit({ filePath: 'low.js', ruleId: 'Q-CAP-002', weight: 2, severity: Severity.LOW }),
      hit({ filePath: 'high.js', ruleId: 'Q-INS-002', weight: 9, severity: Severity.MEDIUM }),
      hit({ filePath: 'high.js', ruleId: 'Q-INS-003', weight: 1, severity: Severity.CRITICAL }),
    ]);

    expect(rows.map((row) => row.path)).toEqual(['high.js', 'low.js']);
    expect(rows[0]?.worstSeverity).toBe(Severity.CRITICAL);
  });

  it('ignores hits with no file, which belong to the signals tab instead', () => {
    expect(fileInventory([hit({ filePath: null })])).toEqual([]);
  });
});

describe('familyBreakdown', () => {
  it('counts enabled rules per family and multiplies weight by confidence and context', () => {
    const rules = [
      rule(),
      rule({ ruleId: 'Q-INS-002' }),
      rule({ ruleId: 'Q-INS-003', enabled: false }),
      rule({ ruleId: 'Q-CAP-001', family: SignalFamily.CAPABILITY }),
    ];

    const breakdown = familyBreakdown(rules, [
      hit({ ruleId: 'Q-INS-001', weight: 10, confidence: 0.5, contextModifier: 1.4 }),
    ]);

    const install = breakdown.find((row) => row.family === SignalFamily.INSTALL);
    expect(install?.evaluated).toBe(2);
    expect(install?.fired).toBe(1);
    expect(install?.contribution).toBe(7);

    const capability = breakdown.find((row) => row.family === SignalFamily.CAPABILITY);
    expect(capability?.fired).toBe(0);
    expect(capability?.worstSeverity).toBeNull();
  });
});

describe('hardTriggerDetail', () => {
  it('resolves recorded trigger ids to their label and rationale', () => {
    const [trigger] = hardTriggerDetail(['install-network-exfil']);
    expect(trigger?.label).toBe('Install script makes an outbound network call');
    expect(trigger?.rationale).toContain('dropper');
  });

  it('drops ids the engine no longer defines rather than rendering a blank row', () => {
    expect(hardTriggerDetail(['retired-trigger'])).toEqual([]);
  });
});

describe('splitCoordinate', () => {
  it('splits a scoped name from its version', () => {
    expect(splitCoordinate('@types/node@20.1.0')).toEqual({ name: '@types/node', version: '20.1.0' });
  });

  it('treats a bare scoped name as having no version', () => {
    expect(splitCoordinate('@types/node')).toEqual({ name: '@types/node', version: null });
  });

  it('handles the unscoped forms and the npm: prefix', () => {
    expect(splitCoordinate('lodash')).toEqual({ name: 'lodash', version: null });
    expect(splitCoordinate('lodash@4.17.21')).toEqual({ name: 'lodash', version: '4.17.21' });
    expect(splitCoordinate('npm:lodash@latest')).toEqual({ name: 'lodash', version: 'latest' });
  });

  it('does not produce an empty name or version', () => {
    expect(splitCoordinate('lodash@')).toEqual({ name: 'lodash@', version: null });
  });
});
