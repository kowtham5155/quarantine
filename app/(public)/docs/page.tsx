import type { Metadata } from 'next';
import Link from 'next/link';

import { CodeViewer } from '@/components/shared/CodeViewer';
import { PageHeader } from '@/components/shared/PageHeader';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';

export const metadata: Metadata = {
  title: 'Docs',
  description:
    'Quarantine API and CLI documentation: what is available today, what each endpoint returns, and how a verdict is shaped.',
};

const RUN_EXAMPLE = `POST /api/analyses/<id>/run
Accept: application/x-ndjson

{"event":"accepted","analysisId":"cl…","package":{"ecosystem":"NPM","name":"left-pad","version":"1.3.0"}}
{"event":"progress","stage":"metadata","status":"completed","elapsedMs":214}
{"event":"progress","stage":"download","status":"completed","detail":"8214 bytes","elapsedMs":812}
{"event":"progress","stage":"extract","status":"completed","detail":"6 files","elapsedMs":934}
{"event":"progress","stage":"INSTALL","status":"completed","detail":"11ms","elapsedMs":1004}
{"event":"result","verdict":"CLEAN","confidence":0.92,"weightedScore":0,"firedSignals":0,"evaluatedSignals":41}`;

const VERDICT_SHAPE = `{
  "verdict": "SUSPICIOUS",          // CLEAN | LOW_RISK | SUSPICIOUS | LIKELY_MALICIOUS | KNOWN_MALICIOUS
  "confidence": 0.71,               // 0–1: corroboration and analysis completeness
  "weightedScore": 18.4,            // Σ weight × confidence × context modifier
  "hardTriggers": [                 // combinations that force a minimum verdict
    { "id": "install-network-exfil", "label": "Install script makes an outbound network call" }
  ],
  "signals": [                      // every rule evaluated — fired and not fired
    {
      "ruleId": "Q-INS-001",
      "family": "INSTALL",
      "fired": true,
      "confidence": 0.95,
      "contextModifier": 1,
      "evidence": [
        { "file": "package.json", "startLine": 12, "excerpt": "\\"postinstall\\": \\"node ./setup.js\\"" }
      ]
    }
  ]
}`;

export default function DocsPage() {
  return (
    <div className="space-y-12">
      <PageHeader
        title="Documentation"
        description="What the API returns today, and what is still being built. Nothing on this page describes an endpoint that does not exist yet without saying so."
      />

      <section aria-labelledby="status" className="space-y-4">
        <h2 id="status" className="text-2xl font-semibold tracking-tight">
          Surface status
        </h2>
        <div className="overflow-x-auto rounded-lg border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Surface</TableHead>
                <TableHead>Authentication</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow>
                <TableCell className="font-mono text-xs">POST /api/analyses/:id/run</TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  Session cookie, same-origin
                </TableCell>
                <TableCell>
                  <Badge variant="outline">Available</Badge>
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="font-mono text-xs">POST /api/cron/analyses</TableCell>
                <TableCell className="text-sm text-muted-foreground">Cron secret</TableCell>
                <TableCell>
                  <Badge variant="outline">Available</Badge>
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="font-mono text-xs">/api/v1/*</TableCell>
                <TableCell className="text-sm text-muted-foreground">API key</TableCell>
                <TableCell>
                  <Badge variant="secondary">Planned</Badge>
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="font-mono text-xs">quarantine CLI</TableCell>
                <TableCell className="text-sm text-muted-foreground">API key</TableCell>
                <TableCell>
                  <Badge variant="secondary">Planned</Badge>
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell className="font-mono text-xs">GitHub Action</TableCell>
                <TableCell className="text-sm text-muted-foreground">API key</TableCell>
                <TableCell>
                  <Badge variant="secondary">Planned</Badge>
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </div>
      </section>

      <section aria-labelledby="run" className="space-y-4">
        <h2 id="run" className="text-2xl font-semibold tracking-tight">
          Running a scan
        </h2>
        <div className="max-w-3xl space-y-3 text-sm text-muted-foreground">
          <p>
            A scan is queued from the{' '}
            <Link href="/scan" className="text-primary underline-offset-4 hover:underline">
              scan page
            </Link>{' '}
            and then run through a streaming endpoint. The response is NDJSON — one JSON object per
            line, flushed as each stage completes — because an analysis takes tens of seconds and a
            single response at the end tells you nothing while you wait.
          </p>
          <p>
            A failure discovered before the body opens comes back as an ordinary HTTP error. A
            failure after that arrives as a final <code className="font-mono">error</code> line,
            because the status code is long committed by then.
          </p>
        </div>
        <CodeViewer code={RUN_EXAMPLE} filename="POST /api/analyses/:id/run" language="ndjson" />
      </section>

      <section aria-labelledby="verdict" className="space-y-4">
        <h2 id="verdict" className="text-2xl font-semibold tracking-tight">
          The verdict object
        </h2>
        <p className="max-w-3xl text-sm text-muted-foreground">
          Every analysis returns the full signal list, fired and not fired, with the file, line and
          excerpt for each hit. A verdict a developer cannot inspect is a verdict they will
          eventually ignore.
        </p>
        <CodeViewer code={VERDICT_SHAPE} filename="verdict.json" language="json" />
      </section>

      <section aria-labelledby="errors" className="space-y-4">
        <h2 id="errors" className="text-2xl font-semibold tracking-tight">
          Errors
        </h2>
        <p className="max-w-3xl text-sm text-muted-foreground">
          Errors are returned in one shape, and never carry a stack trace or raw error text. The
          correlation id in the response header is the handle for finding the failure in the server
          logs.
        </p>
        <div className="grid gap-4 sm:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Shape</CardTitle>
              <CardDescription>Every error, every endpoint.</CardDescription>
            </CardHeader>
            <CardContent>
              <CodeViewer
                showCopy={false}
                code={`{ "error": { "code": "VALIDATION_ERROR", "message": "…" } }`}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Codes</CardTitle>
              <CardDescription>Stable across versions.</CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="space-y-1 font-mono text-xs text-muted-foreground">
                <li>VALIDATION_ERROR — 400</li>
                <li>AUTH_ERROR — 401</li>
                <li>FORBIDDEN — 403</li>
                <li>NOT_FOUND — 404</li>
                <li>RATE_LIMITED — 429</li>
                <li>ANALYSIS_ERROR — 422</li>
                <li>INTERNAL_ERROR — 500</li>
              </ul>
            </CardContent>
          </Card>
        </div>
      </section>
    </div>
  );
}
