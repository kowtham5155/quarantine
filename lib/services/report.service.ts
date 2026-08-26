import {
  type Prisma,
  ReportFormat,
  ReportStatus,
  ReportType,
  Verdict,
  ViolationState,
} from '@prisma/client';
import { z } from 'zod';

import { audit } from '@/lib/audit';
import { VERDICTS } from '@/lib/constants';
import { prisma } from '@/lib/db';
import { NotFoundError, ValidationError } from '@/lib/errors';
import { assertCan, type AuthContext } from '@/lib/rbac';
import { runEvaluation } from '@/lib/services/corpus.service';
import * as projectService from '@/lib/services/project.service';

/**
 * Reports are snapshots.
 *
 * The numbers are computed once, at generation, and stored on the row. Reading
 * a report never recomputes it — a report someone cited in a change ticket last
 * Tuesday has to still say what it said last Tuesday, and a "report" that
 * silently tracks live data is a dashboard with a date on it.
 *
 * Every generator is org-scoped through the services it calls, and the row
 * itself carries `orgId` (CLAUDE.md rule 4).
 */

export interface RequestInfo {
  ip?: string | null;
  userAgent?: string | null;
}

export const REPORT_TYPE_LABELS: Record<ReportType, string> = {
  [ReportType.ORG_POSTURE]: 'Organisation posture',
  [ReportType.PROJECT_RISK]: 'Project risk',
  [ReportType.SBOM]: 'SBOM (CycloneDX 1.5)',
  [ReportType.VIOLATIONS]: 'Policy violations',
  [ReportType.EVALUATION]: 'Engine evaluation',
};

export const REPORT_TYPE_DESCRIPTIONS: Record<ReportType, string> = {
  [ReportType.ORG_POSTURE]:
    'Verdict distribution, flagged packages and open governance across the whole organisation.',
  [ReportType.PROJECT_RISK]:
    'One project: direct and transitive dependencies, their verdicts, and what is held.',
  [ReportType.SBOM]: 'A CycloneDX 1.5 bill of materials for one project, with verdicts attached.',
  [ReportType.VIOLATIONS]: 'Every policy violation in the window, with its state and its policy.',
  [ReportType.EVALUATION]:
    'Precision, recall and false-positive rate of the engine against the labelled corpus.',
};

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

export interface ReportSection {
  heading: string;
  /** Rendered as a definition list. */
  facts?: Array<{ label: string; value: string }>;
  /** Rendered as a table. Every cell is escaped on render. */
  table?: { columns: string[]; rows: string[][] };
  note?: string;
}

export interface ReportPayload {
  title: string;
  subtitle: string;
  generatedAt: string;
  sections: ReportSection[];
  /** Raw document for machine formats. SBOM puts CycloneDX here verbatim. */
  raw?: unknown;
}

function isPayload(value: Prisma.JsonValue): value is ReportPayload & Prisma.JsonObject {
  return (
    !!value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    typeof (value as Record<string, unknown>).title === 'string' &&
    Array.isArray((value as Record<string, unknown>).sections)
  );
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

export const generateReportSchema = z.object({
  type: z.nativeEnum(ReportType),
  format: z.nativeEnum(ReportFormat).default(ReportFormat.HTML),
  projectId: z.string().trim().min(1).max(64).optional(),
  windowDays: z.number().int().min(1).max(365).default(30),
});

export type GenerateReportInput = z.infer<typeof generateReportSchema>;

const numberFormat = new Intl.NumberFormat('en-GB');

function fact(label: string, value: string | number): { label: string; value: string } {
  return { label, value: typeof value === 'number' ? numberFormat.format(value) : value };
}

async function buildOrgPosture(ctx: AuthContext, windowDays: number): Promise<ReportPayload> {
  const since = new Date(Date.now() - windowDays * 86_400_000);

  const [byVerdict, total, inWindow, openViolations, held, flagged] = await Promise.all([
    prisma.analysis.groupBy({
      by: ['verdict'],
      where: { orgId: ctx.orgId, verdict: { not: null } },
      _count: { _all: true },
    }),
    prisma.analysis.count({ where: { orgId: ctx.orgId } }),
    prisma.analysis.count({ where: { orgId: ctx.orgId, completedAt: { gte: since } } }),
    prisma.policyViolation.count({ where: { orgId: ctx.orgId, state: ViolationState.OPEN } }),
    prisma.quarantineItem.count({ where: { orgId: ctx.orgId, state: 'HELD' } }),
    prisma.analysis.findMany({
      where: {
        orgId: ctx.orgId,
        verdict: { in: [Verdict.SUSPICIOUS, Verdict.LIKELY_MALICIOUS, Verdict.KNOWN_MALICIOUS] },
      },
      include: {
        packageVersion: {
          select: { version: true, package: { select: { ecosystem: true, name: true } } },
        },
      },
      orderBy: { completedAt: 'desc' },
      take: 50,
    }),
  ]);

  const counts = new Map(byVerdict.map((row) => [row.verdict, row._count._all]));

  return {
    title: 'Organisation posture',
    subtitle: `Every analysis this organisation has run, with the last ${windowDays} days called out.`,
    generatedAt: new Date().toISOString(),
    sections: [
      {
        heading: 'Summary',
        facts: [
          fact('Analyses, all time', total),
          fact(`Analyses, last ${windowDays} days`, inWindow),
          fact('Open policy violations', openViolations),
          fact('Packages held in quarantine', held),
        ],
      },
      {
        heading: 'Verdict distribution',
        table: {
          columns: ['Verdict', 'Analyses'],
          rows: VERDICTS.map((verdict) => [
            verdict,
            numberFormat.format(counts.get(verdict as Verdict) ?? 0),
          ]),
        },
      },
      {
        heading: 'Flagged packages',
        note:
          flagged.length === 0
            ? 'Nothing has been flagged as suspicious or worse.'
            : 'Most recent first, capped at fifty.',
        table: {
          columns: ['Registry', 'Package', 'Version', 'Verdict', 'Completed'],
          rows: flagged.map((row) => [
            row.packageVersion.package.ecosystem,
            row.packageVersion.package.name,
            row.packageVersion.version,
            row.verdict ?? '—',
            row.completedAt?.toISOString() ?? '—',
          ]),
        },
      },
    ],
  };
}

async function buildProjectRisk(ctx: AuthContext, projectId: string): Promise<ReportPayload> {
  const project = await projectService.get(ctx, projectId);
  const rows = await projectService.listDependencies(ctx, projectId);
  const risk = projectService.summariseRisk(rows);

  const flagged = rows.filter(
    (row) =>
      row.verdict === Verdict.SUSPICIOUS ||
      row.verdict === Verdict.LIKELY_MALICIOUS ||
      row.verdict === Verdict.KNOWN_MALICIOUS,
  );

  return {
    title: `Project risk — ${project.name}`,
    subtitle: 'Dependency graph with this organisation’s verdicts applied.',
    generatedAt: new Date().toISOString(),
    sections: [
      {
        heading: 'Summary',
        facts: [
          fact('Dependencies', risk.total),
          fact('Direct', risk.direct),
          fact('Transitive', risk.transitive),
          fact('Analysed', risk.analysed),
          fact('Not yet analysed', risk.unanalysed),
          fact('Flagged', risk.flagged),
          fact('Held', risk.blocked),
          fact('Worst verdict', risk.worstVerdict ?? 'none'),
        ],
      },
      {
        heading: 'Flagged dependencies',
        note: flagged.length === 0 ? 'No dependency is flagged.' : undefined,
        table: {
          columns: ['Package', 'Version', 'Verdict', 'Depth', 'Path'],
          rows: flagged.map((row) => [
            row.name,
            row.version,
            row.verdict ?? '—',
            String(row.depth),
            row.path.length > 0 ? row.path.join(' › ') : 'direct',
          ]),
        },
      },
      {
        heading: 'Unanalysed dependencies',
        note: 'A dependency with no verdict has not been ruled out; it has not been looked at.',
        table: {
          columns: ['Package', 'Version', 'Direct'],
          rows: rows
            .filter((row) => row.verdict === null)
            .slice(0, 200)
            .map((row) => [row.name, row.version, row.isDirect ? 'yes' : 'no']),
        },
      },
    ],
  };
}

async function buildSbomReport(ctx: AuthContext, projectId: string): Promise<ReportPayload> {
  const { project, document } = await projectService.buildSbom(ctx, projectId);

  return {
    title: `SBOM — ${project.name}`,
    subtitle: 'CycloneDX 1.5, with verdicts as component properties.',
    generatedAt: new Date().toISOString(),
    sections: [
      {
        heading: 'Document',
        facts: [
          fact('Format', 'CycloneDX 1.5'),
          fact('Components', document.components.length),
          fact('Serial number', document.serialNumber),
        ],
      },
      {
        heading: 'Components',
        table: {
          columns: ['purl', 'Verdict', 'Scope'],
          rows: document.components.slice(0, 500).map((component) => {
            const properties = (component.properties ?? []) as Array<{
              name: string;
              value: string;
            }>;
            const verdict = properties.find((property) => property.name === 'quarantine:verdict');
            return [
              String(component.purl ?? ''),
              verdict?.value ?? 'NOT_ANALYSED',
              String(component.scope ?? ''),
            ];
          }),
        },
      },
    ],
    raw: document,
  };
}

async function buildViolations(ctx: AuthContext, windowDays: number): Promise<ReportPayload> {
  const since = new Date(Date.now() - windowDays * 86_400_000);

  const rows = await prisma.policyViolation.findMany({
    where: { orgId: ctx.orgId, detectedAt: { gte: since } },
    include: {
      policy: { select: { name: true, action: true } },
      project: { select: { name: true } },
      packageVersion: {
        select: { version: true, package: { select: { ecosystem: true, name: true } } },
      },
    },
    orderBy: { detectedAt: 'desc' },
    take: 1000,
  });

  const byState = new Map<ViolationState, number>();
  for (const row of rows) byState.set(row.state, (byState.get(row.state) ?? 0) + 1);

  return {
    title: 'Policy violations',
    subtitle: `Everything policy caught in the last ${windowDays} days.`,
    generatedAt: new Date().toISOString(),
    sections: [
      {
        heading: 'Summary',
        facts: [
          fact('Violations in window', rows.length),
          fact('Open', byState.get(ViolationState.OPEN) ?? 0),
          fact('Excepted', byState.get(ViolationState.EXCEPTED) ?? 0),
          fact('Resolved', byState.get(ViolationState.RESOLVED) ?? 0),
        ],
      },
      {
        heading: 'Violations',
        table: {
          columns: ['Detected', 'Policy', 'Action', 'Package', 'Version', 'Project', 'State'],
          rows: rows.map((row) => [
            row.detectedAt.toISOString(),
            row.policy.name,
            row.policy.action,
            row.packageVersion.package.name,
            row.packageVersion.version,
            row.project?.name ?? '—',
            row.state,
          ]),
        },
      },
    ],
  };
}

async function buildEvaluation(ctx: AuthContext & { actorEmail: string }): Promise<ReportPayload> {
  const result = await runEvaluation(ctx);

  return {
    title: 'Engine evaluation',
    subtitle: `Engine ${result.engineVersion} against ${result.corpusSize} labelled packages.`,
    generatedAt: new Date().toISOString(),
    sections: [
      {
        heading: 'Metrics',
        facts: [
          fact('Positive class', `${result.threshold} or worse`),
          fact('Corpus size', result.corpusSize),
          fact('Covered by an analysis', result.covered),
          fact('Precision', result.precision.toFixed(3)),
          fact('Recall', result.recall.toFixed(3)),
          fact('F1', result.f1.toFixed(3)),
          fact('False-positive rate', result.falsePositiveRate.toFixed(3)),
          fact('Mean latency', `${result.meanLatencyMs} ms`),
          fact('p95 latency', `${result.p95LatencyMs} ms`),
        ],
      },
      {
        heading: 'Confusion matrix',
        table: {
          columns: ['', 'Predicted malicious', 'Predicted clean'],
          rows: [
            ['Labelled malicious', String(result.truePositives), String(result.falseNegatives)],
            ['Labelled clean', String(result.falsePositives), String(result.trueNegatives)],
          ],
        },
      },
      {
        heading: 'Rule contribution',
        note: 'Ordered by firings on clean packages — the false-positive budget.',
        table: {
          columns: ['Rule', 'Family', 'On malicious', 'On clean', 'Precision'],
          rows: result.rules.map((rule) => [
            rule.ruleId,
            rule.family,
            String(rule.onMalicious),
            String(rule.onClean),
            rule.precision.toFixed(3),
          ]),
        },
      },
    ],
  };
}

export interface ReportRow {
  id: string;
  type: ReportType;
  format: ReportFormat;
  status: ReportStatus;
  projectId: string | null;
  projectName: string | null;
  generatedByName: string | null;
  createdAt: Date;
  title: string;
}

export async function listReports(ctx: AuthContext): Promise<ReportRow[]> {
  assertCan(ctx, 'report:read', { orgId: ctx.orgId });

  const rows = await prisma.report.findMany({
    where: { orgId: ctx.orgId },
    include: {
      project: { select: { id: true, name: true } },
      generatedBy: { select: { name: true } },
    },
    orderBy: { createdAt: 'desc' },
    take: 200,
  });

  return rows.map((row) => ({
    id: row.id,
    type: row.type,
    format: row.format,
    status: row.status,
    projectId: row.project?.id ?? null,
    projectName: row.project?.name ?? null,
    generatedByName: row.generatedBy?.name ?? null,
    createdAt: row.createdAt,
    title: isPayload(row.payload) ? row.payload.title : REPORT_TYPE_LABELS[row.type],
  }));
}

export interface ReportDetail extends ReportRow {
  payload: ReportPayload | null;
  params: Record<string, unknown>;
}

export async function getReport(ctx: AuthContext, reportId: string): Promise<ReportDetail> {
  assertCan(ctx, 'report:read', { orgId: ctx.orgId });

  const row = await prisma.report.findFirst({
    where: { id: reportId, orgId: ctx.orgId },
    include: {
      project: { select: { id: true, name: true } },
      generatedBy: { select: { name: true } },
    },
  });

  if (!row) throw new NotFoundError('That report does not exist.');

  const payload = isPayload(row.payload) ? (row.payload as ReportPayload) : null;

  return {
    id: row.id,
    type: row.type,
    format: row.format,
    status: row.status,
    projectId: row.project?.id ?? null,
    projectName: row.project?.name ?? null,
    generatedByName: row.generatedBy?.name ?? null,
    createdAt: row.createdAt,
    title: payload?.title ?? REPORT_TYPE_LABELS[row.type],
    payload,
    params:
      row.params && typeof row.params === 'object' && !Array.isArray(row.params)
        ? (row.params as Record<string, unknown>)
        : {},
  };
}

export async function generateReport(
  ctx: AuthContext & { actorEmail: string },
  input: z.input<typeof generateReportSchema>,
  request: RequestInfo = {},
): Promise<{ id: string }> {
  assertCan(ctx, 'report:generate', { orgId: ctx.orgId });

  const parsed = generateReportSchema.safeParse(input);
  if (!parsed.success) throw ValidationError.fromIssues(parsed.error.issues);
  const { type, format, projectId, windowDays } = parsed.data;

  const needsProject = type === ReportType.PROJECT_RISK || type === ReportType.SBOM;
  if (needsProject && !projectId) {
    throw new ValidationError('Choose a project for that report type.', {
      details: { fieldErrors: { projectId: ['Choose a project.'] } },
    });
  }

  // Ownership is proved before anything is generated: `get` throws NotFound for
  // a project belonging to another org.
  if (projectId) await projectService.get(ctx, projectId);

  const row = await prisma.report.create({
    data: {
      orgId: ctx.orgId,
      projectId: projectId ?? null,
      type,
      format,
      generatedById: ctx.userId,
      status: ReportStatus.GENERATING,
      params: { windowDays } as Prisma.InputJsonValue,
    },
    select: { id: true },
  });

  try {
    let payload: ReportPayload;

    switch (type) {
      case ReportType.ORG_POSTURE:
        payload = await buildOrgPosture(ctx, windowDays);
        break;
      case ReportType.PROJECT_RISK:
        payload = await buildProjectRisk(ctx, projectId as string);
        break;
      case ReportType.SBOM:
        payload = await buildSbomReport(ctx, projectId as string);
        break;
      case ReportType.VIOLATIONS:
        payload = await buildViolations(ctx, windowDays);
        break;
      case ReportType.EVALUATION:
        payload = await buildEvaluation(ctx);
        break;
    }

    await prisma.report.update({
      where: { id: row.id },
      data: {
        status: ReportStatus.READY,
        payload: payload as unknown as Prisma.InputJsonValue,
      },
    });
  } catch (error) {
    await prisma.report.update({
      where: { id: row.id },
      data: { status: ReportStatus.FAILED },
    });
    throw error;
  }

  await audit(
    ctx,
    'report.generated',
    { type: 'Report', id: row.id },
    { reportType: type, format },
    request,
  );

  return row;
}

export async function deleteReport(
  ctx: AuthContext & { actorEmail: string },
  reportId: string,
  request: RequestInfo = {},
): Promise<void> {
  assertCan(ctx, 'report:generate', { orgId: ctx.orgId });

  const result = await prisma.report.deleteMany({ where: { id: reportId, orgId: ctx.orgId } });
  if (result.count === 0) throw new NotFoundError('That report does not exist.');

  await audit(ctx, 'report.deleted', { type: 'Report', id: reportId }, {}, request);
}

// ---------------------------------------------------------------------------
// Machine formats
// ---------------------------------------------------------------------------

/**
 * Escape one CSV field.
 *
 * A leading `=`, `+`, `-` or `@` is prefixed with a quote: package names and
 * descriptions are attacker-controlled, and a spreadsheet treats such a field
 * as a formula. This is the same class of problem as escaping on render, in a
 * different renderer.
 */
export function csvCell(value: string): string {
  const guarded = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return `"${guarded.replaceAll('"', '""')}"`;
}

/** Flatten a payload's tables into one CSV document. */
export function toCsv(payload: ReportPayload): string {
  const lines: string[] = [];

  for (const section of payload.sections) {
    lines.push(csvCell(section.heading));

    if (section.facts) {
      for (const item of section.facts) {
        lines.push([csvCell(item.label), csvCell(item.value)].join(','));
      }
    }

    if (section.table) {
      lines.push(section.table.columns.map(csvCell).join(','));
      for (const row of section.table.rows) lines.push(row.map(csvCell).join(','));
    }

    lines.push('');
  }

  return lines.join('\n');
}
