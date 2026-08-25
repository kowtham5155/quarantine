import { IndicatorType, type Prisma } from '@prisma/client';
import { describe, expect, it } from 'vitest';

import {
  campaignFingerprint,
  campaignName,
  extractIndicators,
  hostFromUrl,
} from '@/lib/services/campaign.service';

/**
 * Campaign clustering, the pure half.
 *
 * `extractIndicators` decides that two packages belong to the same attack. A
 * bug here does not produce a slightly wrong number — it asserts a relationship
 * between two strangers' packages, which is why the function takes no database,
 * no clock and no network, and why the tests below spend most of their effort
 * on what must *not* become an indicator.
 *
 * SAFETY: every excerpt below is a hand-written string standing in for a
 * verbatim slice of package source. It is compared as an opaque string.
 */

interface HitInput {
  ruleId: string;
  excerpt?: string | null;
  evidence?: Prisma.JsonValue;
  confidence?: number;
}

function hit(input: HitInput) {
  return {
    ruleId: input.ruleId,
    excerpt: input.excerpt ?? null,
    evidence: input.evidence ?? {},
    confidence: input.confidence ?? 0.9,
  };
}

describe('hostFromUrl', () => {
  it('lowercases the host and drops the port and path', () => {
    expect(hostFromUrl('https://Drop.Example.INVALID:8443/collect?x=1')).toBe('drop.example.invalid');
  });

  it('drops embedded credentials', () => {
    expect(hostFromUrl('http://user:pass@drop.invalid/x')).toBe('drop.invalid');
  });

  it('returns null for something that is not a URL', () => {
    expect(hostFromUrl('not a url')).toBeNull();
  });
});

describe('extractIndicators', () => {
  it('returns nothing for an analysis with no hits', () => {
    expect(extractIndicators([])).toEqual([]);
  });

  it('returns nothing for hits that carry no clusterable artefact', () => {
    expect(
      extractIndicators([
        hit({ ruleId: 'Q-OBF-006', excerpt: 'averageLineLength' }),
        hit({ ruleId: 'Q-INS-001', excerpt: 'node ./scripts/build.js' }),
      ]),
    ).toEqual([]);
  });

  describe('exfiltration endpoints', () => {
    it('takes a literal address straight from the evidence', () => {
      const indicators = extractIndicators([
        hit({ ruleId: 'Q-CAP-007', evidence: { address: '93.184.216.34' } }),
      ]);

      expect(indicators).toEqual([
        {
          type: IndicatorType.EXFIL_ENDPOINT,
          value: '93.184.216.34',
          confidence: 0.9,
          ruleIds: ['Q-CAP-007'],
        },
      ]);
    });

    it('parses the host out of a webhook excerpt', () => {
      const indicators = extractIndicators([
        hit({
          ruleId: 'Q-CAP-008',
          excerpt: "const drop = 'https://webhook.site/abcd-1234';",
          evidence: { endpoint: 'webhook.site' },
        }),
      ]);

      expect(indicators).toEqual([
        expect.objectContaining({ type: IndicatorType.EXFIL_ENDPOINT, value: 'webhook.site' }),
      ]);
    });

    it('ignores registry and git hosts, which every package talks to', () => {
      const indicators = extractIndicators([
        hit({
          ruleId: 'Q-CAP-008',
          excerpt: 'https://registry.npmjs.org/x https://raw.githubusercontent.com/a/b',
        }),
      ]);

      expect(indicators).toEqual([]);
    });

    it('ignores a URL in a rule that does not describe an endpoint', () => {
      // Clustering on any URL anywhere would file half the ecosystem together.
      const indicators = extractIndicators([
        hit({ ruleId: 'Q-OBF-001', excerpt: "see https://drop.invalid/docs for detail" }),
      ]);

      expect(indicators).toEqual([]);
    });

    it('collects every distinct host in one excerpt', () => {
      const indicators = extractIndicators([
        hit({ ruleId: 'Q-CAP-008', excerpt: 'https://a.invalid/x then https://b.invalid/y' }),
      ]);

      expect(indicators.map((indicator) => indicator.value).sort()).toEqual([
        'a.invalid',
        'b.invalid',
      ]);
    });
  });

  describe('wallet addresses', () => {
    it('recognises an EVM address and folds its checksum casing', () => {
      const address = '0xAbC0000000000000000000000000000000000123';
      const indicators = extractIndicators([
        hit({ ruleId: 'Q-CAP-006', excerpt: `to = "${address}"` }),
      ]);

      expect(indicators).toEqual([
        expect.objectContaining({ type: IndicatorType.WALLET, value: address.toLowerCase() }),
      ]);
    });

    it('recognises a bech32 bitcoin address without folding its case', () => {
      const address = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
      const indicators = extractIndicators([
        hit({ ruleId: 'Q-CAP-006', excerpt: `pay ${address}` }),
      ]);

      expect(indicators).toEqual([
        expect.objectContaining({ type: IndicatorType.WALLET, value: address }),
      ]);
    });

    it('looks for wallets in any hit, not only the wallet rule', () => {
      const indicators = extractIndicators([
        hit({
          ruleId: 'Q-OBF-001',
          excerpt: 'const t = "0xabc0000000000000000000000000000000000123";',
        }),
      ]);

      expect(indicators.map((indicator) => indicator.type)).toEqual([IndicatorType.WALLET]);
    });

    it('does not mistake a hex hash for an address', () => {
      const indicators = extractIndicators([
        hit({ ruleId: 'Q-OBF-002', excerpt: `sha = "${'a'.repeat(64)}"` }),
      ]);

      expect(indicators).toEqual([]);
    });
  });

  describe('code hashes', () => {
    it('takes the file hash from a native-binary hit', () => {
      const sha256 = 'A'.repeat(64);
      const indicators = extractIndicators([hit({ ruleId: 'Q-CAP-009', evidence: { sha256 } })]);

      expect(indicators).toEqual([
        expect.objectContaining({ type: IndicatorType.CODE_HASH, value: sha256.toLowerCase() }),
      ]);
    });

    it('ignores a value that is not a SHA-256', () => {
      const indicators = extractIndicators([
        hit({ ruleId: 'Q-CAP-009', evidence: { sha256: 'not-a-hash' } }),
      ]);

      expect(indicators).toEqual([]);
    });

    it('ignores a hash carried by a rule that is not about a shipped binary', () => {
      const indicators = extractIndicators([
        hit({ ruleId: 'Q-PRV-003', evidence: { sha256: 'b'.repeat(64) } }),
      ]);

      expect(indicators).toEqual([]);
    });
  });

  describe('maintainer accounts', () => {
    it('clusters on a maintainer named by a takeover-shaped hit', () => {
      const indicators = extractIndicators([
        hit({ ruleId: 'Q-MNT-002', evidence: { maintainer: 'Right9ctrl' } }),
      ]);

      expect(indicators).toEqual([
        expect.objectContaining({ type: IndicatorType.MAINTAINER, value: 'right9ctrl' }),
      ]);
    });

    it('ignores the sole-maintainer rule, which fires on healthy projects', () => {
      // Clustering on Q-MNT-004 would file every one-person project under the
      // same "campaign".
      const indicators = extractIndicators([
        hit({ ruleId: 'Q-MNT-004', evidence: { maintainer: 'sindresorhus' } }),
      ]);

      expect(indicators).toEqual([]);
    });

    it('ignores the placeholder the maintainer rules use when the name is absent', () => {
      const indicators = extractIndicators([
        hit({ ruleId: 'Q-MNT-003', evidence: { maintainer: 'unknown' } }),
      ]);

      expect(indicators).toEqual([]);
    });
  });

  describe('deduplication', () => {
    it('merges repeats of one indicator, keeping the highest confidence', () => {
      const indicators = extractIndicators([
        hit({ ruleId: 'Q-CAP-008', excerpt: 'https://drop.invalid/a', confidence: 0.4 }),
        hit({ ruleId: 'Q-CAP-008', excerpt: 'https://drop.invalid/b', confidence: 0.95 }),
      ]);

      expect(indicators).toHaveLength(1);
      expect(indicators[0]?.confidence).toBe(0.95);
      expect(indicators[0]?.ruleIds).toEqual(['Q-CAP-008']);
    });

    it('records every rule that contributed to the same indicator', () => {
      const indicators = extractIndicators([
        hit({ ruleId: 'Q-CAP-007', evidence: { address: '93.184.216.34' } }),
        hit({ ruleId: 'Q-CAP-008', excerpt: 'http://93.184.216.34/x' }),
      ]);

      const address = indicators.find((indicator) => indicator.value === '93.184.216.34');
      expect(address?.ruleIds).toEqual(['Q-CAP-007', 'Q-CAP-008']);
    });

    it('keeps indicators of different types apart even at the same value', () => {
      const value = 'c'.repeat(64);
      const indicators = extractIndicators([
        hit({ ruleId: 'Q-CAP-009', evidence: { sha256: value } }),
        hit({ ruleId: 'Q-MNT-002', evidence: { maintainer: value } }),
      ]);

      expect(indicators).toHaveLength(2);
    });
  });

  describe('hostile input', () => {
    it('survives evidence that is not an object', () => {
      const indicators = extractIndicators([
        { ruleId: 'Q-CAP-007', excerpt: null, evidence: ['not', 'an', 'object'], confidence: 0.5 },
        { ruleId: 'Q-CAP-009', excerpt: null, evidence: null, confidence: 0.5 },
      ]);

      expect(indicators).toEqual([]);
    });

    it('caps an absurdly long indicator rather than storing a payload', () => {
      const indicators = extractIndicators([
        hit({ ruleId: 'Q-MNT-002', evidence: { maintainer: 'x'.repeat(5_000) } }),
      ]);

      expect(indicators[0]?.value.length).toBeLessThanOrEqual(255);
    });

    it('ignores an empty maintainer name', () => {
      expect(extractIndicators([hit({ ruleId: 'Q-MNT-002', evidence: { maintainer: '' } })])).toEqual(
        [],
      );
    });
  });
});

describe('campaignFingerprint', () => {
  it('is stable for the same org, type and value', () => {
    const a = campaignFingerprint('org_1', IndicatorType.EXFIL_ENDPOINT, 'drop.invalid');
    const b = campaignFingerprint('org_1', IndicatorType.EXFIL_ENDPOINT, 'drop.invalid');
    expect(a).toBe(b);
  });

  it('separates two orgs that independently see the same indicator', () => {
    // Campaign.fingerprint is globally unique, so the org has to be inside it
    // or one tenant's scan could extend another's campaign.
    const a = campaignFingerprint('org_1', IndicatorType.EXFIL_ENDPOINT, 'drop.invalid');
    const b = campaignFingerprint('org_2', IndicatorType.EXFIL_ENDPOINT, 'drop.invalid');
    expect(a).not.toBe(b);
  });

  it('separates indicator types at the same value', () => {
    const a = campaignFingerprint('org_1', IndicatorType.MAINTAINER, 'x');
    const b = campaignFingerprint('org_1', IndicatorType.CODE_HASH, 'x');
    expect(a).not.toBe(b);
  });

  it('is a sha256 digest, not the indicator itself', () => {
    const fingerprint = campaignFingerprint('org_1', IndicatorType.MAINTAINER, 'right9ctrl');
    expect(fingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(fingerprint).not.toContain('right9ctrl');
  });
});

describe('campaignName', () => {
  it('names a campaign after the indicator that defines it', () => {
    expect(campaignName(IndicatorType.EXFIL_ENDPOINT, 'drop.invalid')).toContain('drop.invalid');
  });

  it('produces a name for every indicator type', () => {
    for (const type of Object.values(IndicatorType)) {
      expect(campaignName(type, 'value').length).toBeGreaterThan(0);
    }
  });
});
