'use client';

import { Plus, Trash2 } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { SIGNAL_FAMILIES, SIGNAL_FAMILY_META, VERDICTS, VERDICT_META } from '@/lib/constants';
import {
  CONDITION_LABELS,
  CONDITION_TYPES,
  type PolicyCondition,
  type PolicyConditionType,
} from '@/lib/policy-conditions';

export interface RuleOption {
  ruleId: string;
  name: string;
}

export interface ConditionBuilderProps {
  conditions: PolicyCondition[];
  onChange: (conditions: PolicyCondition[]) => void;
  /** The rule catalogue, so "a rule fired" is a choice rather than a guess. */
  rules: readonly RuleOption[];
  disabled?: boolean;
}

const MAX_CONDITIONS = 10;

/**
 * The enum members each condition variant accepts.
 *
 * The service builds its schema from the Prisma enums; `@/lib/constants` holds
 * the same members as string unions for display. Pulling the accepted type back
 * out of `PolicyCondition` keeps the select honest if either ever drifts.
 */
type VerdictValue = Extract<PolicyCondition, { type: 'verdict_at_least' }>['verdict'];
type FamilyValue = Extract<PolicyCondition, { type: 'family_score_at_least' }>['family'];
type EcosystemValue = Extract<PolicyCondition, { type: 'ecosystem_is' }>['ecosystem'];

/** A fresh condition of each type, with a value already in it so it validates. */
function blankCondition(type: PolicyConditionType): PolicyCondition {
  switch (type) {
    case 'verdict_at_least':
      return { type, verdict: 'SUSPICIOUS' };
    case 'rule_fired':
      return { type, ruleId: '' };
    case 'family_score_at_least':
      return { type, family: 'INSTALL', score: 50 };
    case 'package_age_below_days':
      return { type, days: 30 };
    case 'maintainer_count_below':
      return { type, count: 2 };
    case 'license_not_in':
      return { type, licenses: ['MIT', 'Apache-2.0'] };
    case 'ecosystem_is':
      return { type, ecosystem: 'NPM' };
  }
}

/** Clamp a typed number into the range the schema will accept. */
function boundedInt(raw: string, min: number, max: number, fallback: number): number {
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value)) return fallback;
  return Math.min(Math.max(value, min), max);
}

/**
 * The condition editor.
 *
 * Conditions are ANDed: every one must hold for the policy to fire. That is
 * stated on the surface rather than left to be discovered, because a reader who
 * assumes OR will write a policy that blocks their entire estate.
 *
 * The value lives in React state and is posted as one JSON field, which the
 * Server Action re-parses with the same Zod union the engine evaluates. The
 * builder is a convenience; it is not the validation.
 */
export function ConditionBuilder({
  conditions,
  onChange,
  rules,
  disabled = false,
}: ConditionBuilderProps) {
  const update = (index: number, next: PolicyCondition) => {
    onChange(conditions.map((condition, position) => (position === index ? next : condition)));
  };

  const remove = (index: number) => {
    onChange(conditions.filter((_, position) => position !== index));
  };

  const add = () => {
    if (conditions.length >= MAX_CONDITIONS) return;
    onChange([...conditions, blankCondition('verdict_at_least')]);
  };

  return (
    <div className="space-y-3">
      <input type="hidden" name="conditions" value={JSON.stringify(conditions)} />

      {conditions.length === 0 ? (
        <p className="rounded-md border border-dashed border-border px-4 py-6 text-center text-sm text-muted-foreground">
          No conditions yet. A policy with no conditions matches nothing.
        </p>
      ) : null}

      <ul className="space-y-3">
        {conditions.map((condition, index) => (
          <li
            key={index}
            className="space-y-3 rounded-lg border border-border bg-surface/40 p-3 sm:p-4"
          >
            <div className="flex items-start gap-2">
              <span className="mt-2 shrink-0 font-mono text-[11px] text-muted-foreground">
                {index === 0 ? 'IF' : 'AND'}
              </span>

              <div className="min-w-0 flex-1 space-y-3">
                <div className="space-y-1.5">
                  <Label htmlFor={`condition-${index}-type`} className="sr-only">
                    Condition {index + 1} type
                  </Label>
                  <Select
                    value={condition.type}
                    disabled={disabled}
                    onValueChange={(value) =>
                      update(index, blankCondition(value as PolicyConditionType))
                    }
                  >
                    <SelectTrigger id={`condition-${index}-type`} className="w-full sm:w-72">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {CONDITION_TYPES.map((type) => (
                        <SelectItem key={type} value={type}>
                          {CONDITION_LABELS[type]}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <ConditionValue
                  condition={condition}
                  index={index}
                  rules={rules}
                  disabled={disabled}
                  onChange={(next) => update(index, next)}
                />
              </div>

              <Button
                type="button"
                variant="ghost"
                size="icon"
                disabled={disabled}
                onClick={() => remove(index)}
                aria-label={`Remove condition ${index + 1}`}
              >
                <Trash2 aria-hidden="true" />
              </Button>
            </div>
          </li>
        ))}
      </ul>

      <div className="flex flex-wrap items-center gap-3">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={add}
          disabled={disabled || conditions.length >= MAX_CONDITIONS}
        >
          <Plus aria-hidden="true" />
          Add condition
        </Button>
        <p className="text-xs text-muted-foreground">
          Every condition must hold — they are ANDed. {MAX_CONDITIONS} is the limit; past that,
          write a second policy.
        </p>
      </div>
    </div>
  );
}

interface ConditionValueProps {
  condition: PolicyCondition;
  index: number;
  rules: readonly RuleOption[];
  disabled: boolean;
  onChange: (condition: PolicyCondition) => void;
}

/** The one input each condition type needs, and nothing else. */
function ConditionValue({ condition, index, rules, disabled, onChange }: ConditionValueProps) {
  const id = `condition-${index}-value`;

  switch (condition.type) {
    case 'verdict_at_least':
      return (
        <div className="space-y-1.5">
          <Label htmlFor={id} className="text-xs text-muted-foreground">
            Verdict, or anything worse than it
          </Label>
          <Select
            value={condition.verdict}
            disabled={disabled}
            onValueChange={(value) =>
              onChange({ type: 'verdict_at_least', verdict: value as VerdictValue })
            }
          >
            <SelectTrigger id={id} className="w-full sm:w-72">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {VERDICTS.map((verdict) => (
                <SelectItem key={verdict} value={verdict}>
                  {VERDICT_META[verdict].label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      );

    case 'rule_fired':
      return (
        <div className="space-y-1.5">
          <Label htmlFor={id} className="text-xs text-muted-foreground">
            Rule
          </Label>
          <Select
            value={condition.ruleId}
            disabled={disabled}
            onValueChange={(value) => onChange({ type: 'rule_fired', ruleId: value })}
          >
            <SelectTrigger id={id} className="w-full sm:w-96">
              <SelectValue placeholder="Choose a rule…" />
            </SelectTrigger>
            <SelectContent>
              {rules.map((rule) => (
                <SelectItem key={rule.ruleId} value={rule.ruleId}>
                  <span className="font-mono text-xs">{rule.ruleId}</span> · {rule.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      );

    case 'family_score_at_least':
      return (
        <div className="flex flex-wrap gap-3">
          <div className="space-y-1.5">
            <Label htmlFor={`${id}-family`} className="text-xs text-muted-foreground">
              Signal family
            </Label>
            <Select
              value={condition.family}
              disabled={disabled}
              onValueChange={(value) =>
                onChange({
                  type: 'family_score_at_least',
                  family: value as FamilyValue,
                  score: condition.score,
                })
              }
            >
              <SelectTrigger id={`${id}-family`} className="w-full sm:w-64">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SIGNAL_FAMILIES.map((family) => (
                  <SelectItem key={family} value={family}>
                    {SIGNAL_FAMILY_META[family].label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor={`${id}-score`} className="text-xs text-muted-foreground">
              Score at least (0–100)
            </Label>
            <Input
              id={`${id}-score`}
              type="number"
              min={0}
              max={100}
              value={condition.score}
              disabled={disabled}
              className="w-32"
              onChange={(event) =>
                onChange({
                  type: 'family_score_at_least',
                  family: condition.family,
                  score: boundedInt(event.target.value, 0, 100, 50),
                })
              }
            />
          </div>
        </div>
      );

    case 'package_age_below_days':
      return (
        <div className="space-y-1.5">
          <Label htmlFor={id} className="text-xs text-muted-foreground">
            First published fewer than this many days ago
          </Label>
          <Input
            id={id}
            type="number"
            min={1}
            max={3650}
            value={condition.days}
            disabled={disabled}
            className="w-32"
            onChange={(event) =>
              onChange({
                type: 'package_age_below_days',
                days: boundedInt(event.target.value, 1, 3650, 30),
              })
            }
          />
        </div>
      );

    case 'maintainer_count_below':
      return (
        <div className="space-y-1.5">
          <Label htmlFor={id} className="text-xs text-muted-foreground">
            Fewer maintainers than
          </Label>
          <Input
            id={id}
            type="number"
            min={1}
            max={100}
            value={condition.count}
            disabled={disabled}
            className="w-32"
            onChange={(event) =>
              onChange({
                type: 'maintainer_count_below',
                count: boundedInt(event.target.value, 1, 100, 2),
              })
            }
          />
        </div>
      );

    case 'license_not_in':
      return (
        <div className="space-y-1.5">
          <Label htmlFor={id} className="text-xs text-muted-foreground">
            Allowed licences, comma separated
          </Label>
          <Input
            id={id}
            value={condition.licenses.join(', ')}
            disabled={disabled}
            placeholder="MIT, Apache-2.0, BSD-3-Clause"
            onChange={(event) =>
              onChange({
                type: 'license_not_in',
                licenses: event.target.value
                  .split(',')
                  .map((entry) => entry.trim())
                  .filter((entry) => entry.length > 0)
                  .slice(0, 40),
              })
            }
          />
          <p className="text-xs text-muted-foreground">
            The policy fires on a package whose licence is <em>not</em> in this list, including one
            that declares no licence at all.
          </p>
        </div>
      );

    case 'ecosystem_is':
      return (
        <div className="space-y-1.5">
          <Label htmlFor={id} className="text-xs text-muted-foreground">
            Registry
          </Label>
          <Select
            value={condition.ecosystem}
            disabled={disabled}
            onValueChange={(value) =>
              onChange({
                type: 'ecosystem_is',
                ecosystem: (value === 'PYPI' ? 'PYPI' : 'NPM') as EcosystemValue,
              })
            }
          >
            <SelectTrigger id={id} className="w-full sm:w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="NPM">npm</SelectItem>
              <SelectItem value="PYPI">PyPI</SelectItem>
            </SelectContent>
          </Select>
        </div>
      );
  }
}
