import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';

import {
  addActiveSession,
  removeActiveSession,
  setActiveSessionStatus,
  listActiveSessions,
  getActiveSession,
  endActiveSession,
  targetKey,
  isTargetInUseByOthers,
} from '../src/ws/activeSessions.js';

const base = {
  userId: 'u1', connectionId: 'c1', connectionName: 'router', protocol: 'ssh' as const,
  end: () => {},
};

describe('activeSessions registry', () => {
  beforeEach(() => {
    for (const s of listActiveSessions()) removeActiveSession(s.id);
  });

  it('adds a session as connected and lists it', () => {
    addActiveSession({ ...base, id: 's1' });
    const list = listActiveSessions();
    assert.equal(list.length, 1);
    assert.equal(list[0].id, 's1');
    assert.equal(list[0].status, 'connected');
    assert.ok(list[0].startedAt <= Date.now());
  });

  it('follows grace and reattach', () => {
    addActiveSession({ ...base, id: 's1' });
    setActiveSessionStatus('s1', 'grace');
    assert.equal(listActiveSessions()[0].status, 'grace');
    setActiveSessionStatus('s1', 'connected');
    assert.equal(listActiveSessions()[0].status, 'connected');
  });

  it('removes a session, and a repeated remove or status update on it is harmless', () => {
    addActiveSession({ ...base, id: 's1' });
    removeActiveSession('s1');
    removeActiveSession('s1');
    setActiveSessionStatus('s1', 'grace');
    assert.equal(listActiveSessions().length, 0);
  });

  it('lists sessions oldest first', async () => {
    addActiveSession({ ...base, id: 'a' });
    await new Promise((r) => setTimeout(r, 5));
    addActiveSession({ ...base, id: 'b', protocol: 'rdp' });
    assert.deepEqual(listActiveSessions().map((s) => s.id), ['a', 'b']);
  });
  it('endActiveSession runs end() once, removes the entry and reports false afterwards', () => {
    let ended = 0;
    addActiveSession({ ...base, id: 's1', end: () => { ended++; } });
    assert.ok(getActiveSession('s1'));
    assert.equal(endActiveSession('s1'), true);
    assert.equal(endActiveSession('s1'), false);
    assert.equal(ended, 1);
    assert.equal(getActiveSession('s1'), undefined);
    assert.equal(listActiveSessions().length, 0);
  });

  it('endActiveSession removes the entry even when end() throws, and does not touch other sessions', () => {
    addActiveSession({ ...base, id: 'bad', end: () => { throw new Error('boom'); } });
    addActiveSession({ ...base, id: 'other' });
    assert.equal(endActiveSession('bad'), true);
    assert.deepEqual(listActiveSessions().map((x) => x.id), ['other']);
  });

  it('endActiveSession returns false for an unknown id', () => {
    assert.equal(endActiveSession('nope'), false);
  });

  it('targetKey ignores host case and surrounding spaces', () => {
    assert.equal(targetKey('  Win-Host.LAN ', 3389), 'win-host.lan:3389');
  });

  it('isTargetInUseByOthers looks at other users only, on the same protocol, host and port', () => {
    addActiveSession({ ...base, id: 'mine', userId: 'me', protocol: 'rdp', target: targetKey('h', 3389) });
    addActiveSession({ ...base, id: 'theirs-ssh', userId: 'u2', protocol: 'ssh', target: targetKey('h', 3389) });
    addActiveSession({ ...base, id: 'theirs-port', userId: 'u2', protocol: 'rdp', target: targetKey('h', 3390) });
    assert.equal(isTargetInUseByOthers('rdp', targetKey('h', 3389), 'me'), false);
    addActiveSession({ ...base, id: 'theirs', userId: 'u2', protocol: 'rdp', target: targetKey('H', 3389) });
    assert.equal(isTargetInUseByOthers('rdp', targetKey('h', 3389), 'me'), true);
    assert.equal(isTargetInUseByOthers('rdp', targetKey('h', 3389), 'u2'), true, 'the other user sees mine');
    removeActiveSession('theirs');
    assert.equal(isTargetInUseByOthers('rdp', targetKey('h', 3389), 'me'), false);
  });

  it('a session without a target never matches', () => {
    addActiveSession({ ...base, id: 'no-target', userId: 'u2', protocol: 'rdp' });
    assert.equal(isTargetInUseByOthers('rdp', targetKey('h', 3389), 'me'), false);
    assert.equal(isTargetInUseByOthers('rdp', '', 'me'), false);
    assert.equal(isTargetInUseByOthers('rdp', 'undefined', 'me'), false);
  });

});
