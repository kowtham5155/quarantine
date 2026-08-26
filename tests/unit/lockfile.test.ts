import { describe, expect, it } from 'vitest';

import { parseLockfile } from '@/lib/lockfile';

describe('parseLockfile', () => {
  it('reads a v3 package-lock packages map and marks direct dependencies', () => {
    const content = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'app', dependencies: { lodash: '^4.17.0' } },
        'node_modules/lodash': { version: '4.17.21' },
        'node_modules/lodash/node_modules/@scope/inner': { version: '1.0.0' },
        'packages/workspace-a': { link: true },
      },
    });

    const result = parseLockfile('package-lock.json', content);

    expect(result.kind).toBe('package-lock');
    expect(result.entries).toEqual([
      { name: '@scope/inner', version: '1.0.0', direct: false, depth: 1, path: [] },
      { name: 'lodash', version: '4.17.21', direct: true, depth: 0, path: [] },
    ]);
  });

  it('reads a v1 nested dependency tree', () => {
    const content = JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        express: { version: '4.18.2', dependencies: { cookie: { version: '0.5.0' } } },
      },
    });

    const result = parseLockfile('package-lock.json', content);

    expect(result.entries).toEqual([
      { name: 'cookie', version: '0.5.0', direct: false, depth: 1, path: ['express'] },
      { name: 'express', version: '4.18.2', direct: true, depth: 0, path: [] },
    ]);
  });

  it('reads a classic yarn.lock, including multi-specifier descriptors', () => {
    const content = [
      '# yarn lockfile v1',
      '',
      '"@babel/core@^7.0.0", "@babel/core@^7.1.0":',
      '  version "7.24.0"',
      '  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.24.0.tgz"',
      '',
      'left-pad@^1.3.0:',
      '  version "1.3.0"',
      '',
    ].join('\n');

    const result = parseLockfile('yarn.lock', content);

    expect(result.kind).toBe('yarn');
    expect(result.entries).toEqual([
      { name: '@babel/core', version: '7.24.0', direct: false, depth: 1, path: [] },
      { name: 'left-pad', version: '1.3.0', direct: false, depth: 1, path: [] },
    ]);
  });

  it('walks the declared graph for depth and path rather than the install path', () => {
    // `deep` is installed three levels down in node_modules but is only one
    // edge from the root: install depth and graph depth are different things.
    const content = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { top: '^1.0.0' } },
        'node_modules/top': { version: '1.0.0', dependencies: { mid: '^2.0.0' } },
        'node_modules/top/node_modules/mid': { version: '2.0.0', dependencies: { leaf: '^3.0.0' } },
        'node_modules/top/node_modules/mid/node_modules/leaf': { version: '3.0.0' },
      },
    });

    const byName = new Map(
      parseLockfile('package-lock.json', content).entries.map((entry) => [entry.name, entry]),
    );

    expect(byName.get('top')).toMatchObject({ depth: 0, path: [], direct: true });
    expect(byName.get('mid')).toMatchObject({ depth: 1, path: ['top'] });
    expect(byName.get('leaf')).toMatchObject({ depth: 2, path: ['top', 'mid'] });
  });

  it('rejects coordinates that are not plausible package names or versions', () => {
    const content = JSON.stringify({
      packages: {
        '': {},
        'node_modules/../../etc/passwd': { version: '1.0.0' },
        'node_modules/ok': { version: '../../evil' },
        'node_modules/UPPER': { version: '1.0.0' },
      },
    });

    expect(parseLockfile('package-lock.json', content).entries).toEqual([]);
  });

  it('caps the entry list and reports that it did', () => {
    const packages: Record<string, unknown> = { '': {} };
    for (let index = 0; index < 10; index++) {
      packages[`node_modules/pkg-${index}`] = { version: '1.0.0' };
    }

    const result = parseLockfile('package-lock.json', JSON.stringify({ packages }), {
      maxEntries: 3,
    });

    expect(result.entries).toHaveLength(3);
    expect(result.found).toBe(10);
    expect(result.truncated).toBe(true);
  });

  it('reports an unreadable file as unknown rather than throwing', () => {
    expect(parseLockfile('package-lock.json', '{ not json').kind).toBe('unknown');
    expect(parseLockfile('notes.txt', 'hello').kind).toBe('unknown');
  });
});
