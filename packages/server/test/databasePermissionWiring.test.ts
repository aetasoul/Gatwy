import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import databaseRouter from '../src/routes/database.js';

// Regression test for the finding in Sicurezza.md #5: `requireDbPermission` was
// defined but never wired as middleware, so every /:connectionId/* route under
// packages/server/src/routes/database.ts (except /connect, checked inline) skipped
// the protocols.postgres / protocols.mysql role check entirely — any authenticated
// user with read access to a DB connection (owner, shared, or role-shared) could
// run arbitrary SQL through it regardless of role permissions.
//
// This test only inspects the router's middleware stack (no real DB needed): it
// asserts requireDbPermission actually runs, and runs before every route handler
// for a :connectionId sub-path. It exists to catch a regression where the `.use()`
// wiring line is removed or reordered, not to re-verify the permission logic itself.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Layer = { name: string; route?: { path: string }; match: (path: string) => boolean };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const stack = (databaseRouter as any).stack as Layer[];

describe('database router: requireDbPermission wiring', () => {
  it('is mounted as router-level middleware', () => {
    const permLayerIndex = stack.findIndex(l => l.name === 'requireDbPermission');
    assert.notEqual(permLayerIndex, -1, 'requireDbPermission must be wired with router.use(...)');
  });

  it('runs before every /:connectionId/* route handler', () => {
    const permLayerIndex = stack.findIndex(l => l.name === 'requireDbPermission');
    const routeLayers = stack.filter(l => l.route);
    assert.ok(routeLayers.length >= 8, 'expected the full set of database routes to be registered');
    for (const layer of routeLayers) {
      const layerIndex = stack.indexOf(layer);
      assert.ok(
        layerIndex > permLayerIndex,
        `route ${layer.route!.path} is registered before requireDbPermission (index ${layerIndex} <= ${permLayerIndex})`,
      );
    }
  });

  it('its mount path covers every :connectionId sub-route', () => {
    const permLayer = stack.find(l => l.name === 'requireDbPermission')!;
    const paths = [
      '/abc123/connect', '/abc123/disconnect',
      '/abc123/databases', '/abc123/schemas', '/abc123/tables', '/abc123/table/users',
      '/abc123/query', '/abc123/history', '/abc123/export',
    ];
    for (const p of paths) {
      assert.ok(permLayer.match(p), `expected requireDbPermission's mount path to match ${p}`);
    }
  });
});
