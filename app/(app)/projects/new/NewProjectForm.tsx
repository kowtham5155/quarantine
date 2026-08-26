'use client';

import { useActionState, useState } from 'react';
import { FileUp, GitBranch, Loader2 } from 'lucide-react';

import { FieldError, FormBanner } from '@/components/shared/FormFeedback';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';

import { createProjectAction } from '../actions';
import { initialProjectState } from '../project-state';

/**
 * Create a project from a lockfile upload or a public repository URL.
 *
 * The lockfile is read in the Server Action and parsed by a pure parser; it is
 * never written to disk, and no dependency is installed or executed to produce
 * the graph.
 */
export function NewProjectForm() {
  const [state, action, pending] = useActionState(createProjectAction, initialProjectState);
  const [source, setSource] = useState<'UPLOAD' | 'GITHUB'>('UPLOAD');

  return (
    <form action={action} className="space-y-6">
      <input type="hidden" name="source" value={source} />
      <FormBanner state={state} />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">The project</CardTitle>
          <CardDescription>
            A name you will recognise in an alert at three in the morning.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="name">Name</Label>
            <Input
              id="name"
              name="name"
              required
              maxLength={80}
              autoComplete="off"
              placeholder="checkout-api"
              aria-describedby={state.fieldErrors?.name ? 'name-error' : undefined}
            />
            <FieldError state={state} field="name" />
          </div>

          <div className="space-y-2">
            <Label htmlFor="description">
              Description <span className="text-muted-foreground">(optional)</span>
            </Label>
            <Textarea
              id="description"
              name="description"
              maxLength={500}
              rows={2}
              placeholder="Payment service. Anything held here blocks a release."
            />
            <FieldError state={state} field="description" />
          </div>

          <div className="space-y-2">
            <Label htmlFor="ecosystem">Registry</Label>
            <Select name="ecosystem" defaultValue="NPM">
              <SelectTrigger id="ecosystem" className="w-full sm:w-56">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="NPM">npm</SelectItem>
                <SelectItem value="PYPI">PyPI</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Where the graph comes from</CardTitle>
          <CardDescription>
            A lockfile is the ground truth for what actually gets installed. A repository URL
            records where to look, and you upload its lockfile the same way.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs
            value={source === 'UPLOAD' ? 'upload' : 'github'}
            onValueChange={(value) => setSource(value === 'github' ? 'GITHUB' : 'UPLOAD')}
          >
            <TabsList className="mb-4">
              <TabsTrigger value="upload">
                <FileUp aria-hidden="true" />
                Upload a lockfile
              </TabsTrigger>
              <TabsTrigger value="github">
                <GitBranch aria-hidden="true" />
                Public repository
              </TabsTrigger>
            </TabsList>

            <TabsContent value="upload" className="space-y-2">
              <Label htmlFor="lockfile">package-lock.json or yarn.lock</Label>
              <Input
                id="lockfile"
                name="lockfile"
                type="file"
                accept=".json,.lock,application/json,text/plain"
                aria-describedby="lockfile-help"
              />
              <p id="lockfile-help" className="text-xs text-muted-foreground">
                Parsed as text. Nothing is installed, executed or written to disk. You can also add
                one later.
              </p>
              <FieldError state={state} field="lockfile" />
            </TabsContent>

            <TabsContent value="github" className="space-y-2">
              <Label htmlFor="repoUrl">Repository URL</Label>
              <Input
                id="repoUrl"
                name="repoUrl"
                type="url"
                maxLength={500}
                placeholder="https://github.com/acme/checkout-api"
              />
              <p className="text-xs text-muted-foreground">
                Recorded for provenance and linked from the project. Quarantine does not clone the
                repository: upload its lockfile to build the graph.
              </p>
              <FieldError state={state} field="repoUrl" />
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" disabled={pending}>
          {pending ? <Loader2 aria-hidden="true" className="animate-spin" /> : null}
          {pending ? 'Creating…' : 'Create project'}
        </Button>
        <p className="text-xs text-muted-foreground">
          Creating a project records the graph. Scanning its dependencies is a separate, bounded
          step you trigger from the project page.
        </p>
      </div>
    </form>
  );
}
