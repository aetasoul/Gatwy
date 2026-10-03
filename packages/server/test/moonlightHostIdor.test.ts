import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';
import type { AddressInfo } from 'net';
import { once } from 'node:events';
import { WebSocket, WebSocketServer } from 'ws';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-moonlight-idor-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'moonlight-idor-test-secret';

const { initDb, closeDb } = await import('../src/db/index.js');
const { execute } = await import('../src/db/helpers.js');
const {
  canAccessMoonlightHost,
  classifyMoonlightRequest,
  parseStreamRequest,
  MLW_STREAM_WS_PATH,
} = await import('../src/ws/moonlightGuard.js');
const { bridgeStream } = await import('../src/ws/moonlightProxy.js');

describe('classifyMoonlightRequest', () => {
  const kind = (method: string, url: string, upgrade = false) => classifyMoonlightRequest(method, url, upgrade).kind;

  it('forwards static files for GET/HEAD only', () => {
    for (const url of ['/mlw', '/mlw/', '/mlw/stream.html?hostId=1&appId=2', '/mlw/resources/main.3f2a.js', '/mlw/locales/it.json']) {
      assert.equal(kind('GET', url), 'http', url);
    }
    assert.equal(kind('HEAD', '/mlw/stream.html'), 'http');
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      assert.deepEqual(classifyMoonlightRequest(method, '/mlw/stream.html', false), {
        kind: 'deny', status: 405, reason: 'Method not allowed',
      });
    }
  });

  it('forwards only the two read-only API calls the stream page makes', () => {
    assert.equal(kind('GET', '/mlw/api/authenticate'), 'http');
    assert.equal(kind('GET', '/mlw/api/role?id=null'), 'http');
    assert.equal(kind('POST', '/mlw/api/authenticate'), 'deny');
    assert.equal(kind('DELETE', '/mlw/api/role'), 'deny');
  });

  it('denies host management, pairing, apps, users, roles, settings and WebRTC', () => {
    const denied: Array<[string, string]> = [
      ['GET', '/mlw/api/hosts'],
      ['GET', '/mlw/api/host?host_id=1'],
      ['POST', '/mlw/api/host'],
      ['PATCH', '/mlw/api/host'],
      ['DELETE', '/mlw/api/host?host_id=1'],
      ['POST', '/mlw/api/host/wake'],
      ['POST', '/mlw/api/host/cancel'],
      ['POST', '/mlw/api/pair'],
      ['GET', '/mlw/api/apps?host_id=1'],
      ['GET', '/mlw/api/app/image?host_id=1&app_id=1'],
      ['GET', '/mlw/api/user'],
      ['GET', '/mlw/api/users'],
      ['POST', '/mlw/api/user'],
      ['GET', '/mlw/api/roles'],
      ['PATCH', '/mlw/api/role'],
      ['GET', '/mlw/api/settings/default'],
      ['POST', '/mlw/api/login'],
      ['POST', '/mlw/api/host/stream/webrtc'],
      ['GET', '/mlw/api/host/stream/webrtc'],
      ['GET', '/mlw/api/host/stream/web_socket'],
    ];
    for (const [method, url] of denied) assert.equal(kind(method, url), 'deny', `${method} ${url}`);
  });

  it('denies every path trick that could reach /api through an allowed-looking path', () => {
    const tricks = [
      '/mlw/stream.html/../api/hosts',
      '/mlw/./api/hosts',
      '/mlw/../api/hosts',
      '/mlw/%2e%2e/api/hosts',
      '/mlw/%2E%2E/api/hosts',
      '/mlw/%61pi/hosts',
      '/mlw/api%2Fhosts',
      '/mlw/api%2fhosts',
      '/mlw/resources%2F..%2Fapi/hosts',
      '/mlw//api/hosts',
      '/mlw/api//hosts',
      '/mlw/api/hosts/',
      '/mlw/api/hosts/.',
      '/mlw/API/hosts',
      '/mlw/Api/hosts',
      '/mlw/api\\hosts',
      '/mlw/api;x=1/hosts',
      '/mlw/api/hosts%00',
      '/mlw/api/hosts%20',
      '/mlw/api/authenticate/',
    ];
    for (const url of tricks) assert.equal(kind('GET', url), 'deny', url);
  });

  it('does not treat other prefixes as /mlw', () => {
    for (const url of ['/mlwx/api/hosts', '/api/hosts', '/ml', '']) assert.equal(kind('GET', url), 'deny', url);
  });

  it('returns the normalized path to forward and keeps the query separate', () => {
    assert.deepEqual(classifyMoonlightRequest('GET', '/mlw/api/role?id=null', false), {
      kind: 'http', path: '/mlw/api/role', search: '?id=null',
    });
    assert.deepEqual(classifyMoonlightRequest('GET', '/mlw/stream.html?hostId=3', false), {
      kind: 'http', path: '/mlw/stream.html', search: '?hostId=3',
    });
  });

  it('upgrades only on the stream WebSocket path, whatever the query', () => {
    assert.deepEqual(classifyMoonlightRequest('GET', MLW_STREAM_WS_PATH, true), { kind: 'stream-ws', path: MLW_STREAM_WS_PATH });
    assert.equal(kind('GET', `${MLW_STREAM_WS_PATH}?host_id=1`, true), 'stream-ws');
    for (const url of [
      '/mlw/stream.html',
      '/mlw/api/hosts',
      '/mlw/api/host/stream/webrtc',
      `${MLW_STREAM_WS_PATH}/`,
      '/mlw/api/host/stream/web_socket/../web_socket',
      '/mlw/api/host/stream/%77eb_socket',
    ]) {
      assert.equal(kind('GET', url, true), 'deny', url);
    }
  });
});

describe('parseStreamRequest', () => {
  it('accepts a real client request and re-serializes it', () => {
    const text = JSON.stringify({ Request: { host_id: 7, app_id: 1, width: 1920, height: 1080, fps: 60, bitrate: 20000, hdr: false, supported_codecs: 3, preferred_codecs: 0 } });
    const result = parseStreamRequest(text);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.hostId, 7);
      assert.equal(result.forward, text);
    }
  });

  it('forwards the value it validated when a key is duplicated (last one wins, one key left)', () => {
    const result = parseStreamRequest('{"Request":{"host_id":99,"host_id":7}}');
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.hostId, 7);
      assert.equal(result.forward, '{"Request":{"host_id":7}}');
    }
  });

  it('rejects anything that is not a single Request with an integer u32 host_id', () => {
    const bad = [
      '',
      'not json',
      '[]',
      'null',
      '{"Stats":{"Ping":1}}',
      '{"Request":null}',
      '{"Request":{}}',
      '{"Request":{"host_id":"7"}}',
      '{"Request":{"host_id":1.5}}',
      '{"Request":{"host_id":-1}}',
      '{"Request":{"host_id":4294967296}}',
      '{"Request":{"host_id":1e400}}',
      '{"Request":{"host_id":1},"Stats":{"Ping":1}}',
      `{"Request":{"host_id":1,"pad":"${'a'.repeat(5000)}"}}`,
    ];
    for (const text of bad) assert.equal(parseStreamRequest(text).ok, false, text.slice(0, 60));
  });
});

const OWNER = 'user-mlidor-owner';
const OTHER = 'user-mlidor-other';
const HOST_OWNER = 11;
const HOST_SHARED = 12;
const HOST_OTHER = 13;
const HEADER = { name: 'X-Gatwy-Moonlight-User', value: 'gatwy' };

type Seen = { path: string; headers: http.IncomingHttpHeaders; messages: string[] };

let dir: string;
let gateway: http.Server;
let gatewayWss: WebSocketServer;
let gatewayPort: number;
let upstreamServer: http.Server;
let upstreamWss: WebSocketServer;
let upstreamPort: number;
let upstreamSeen: Seen[] = [];

before(async () => {
  dir = dataDir;
  await initDb();
  for (const id of [OWNER, OTHER]) {
    execute(
      `INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, 'user')`,
      [id, id, 'x', id],
    );
  }
  const addConn = (id: string, userId: string, shared: number, mlHostId: number | null, protocol = 'moonlight') => execute(
    `INSERT INTO connections (id, user_id, group_id, name, protocol, host, port, shared, extra_config_json) VALUES (?, ?, NULL, ?, ?, 'h', 47989, ?, ?)`,
    [id, userId, id, protocol, shared, mlHostId === null ? null : JSON.stringify({ mlHostId })],
  );
  addConn('conn-mlidor-owner', OWNER, 0, HOST_OWNER);
  addConn('conn-mlidor-shared', OWNER, 1, HOST_SHARED);
  addConn('conn-mlidor-other', OTHER, 0, HOST_OTHER);
  // Not a Moonlight connection: its extra_config_json must not grant any host.
  addConn('conn-mlidor-ssh', OWNER, 1, 99, 'ssh');

  // Fake moonlight-web: records what reaches it and answers the first message.
  upstreamServer = http.createServer();
  upstreamWss = new WebSocketServer({ server: upstreamServer, perMessageDeflate: false });
  upstreamWss.on('connection', (ws, req) => {
    const seen: Seen = { path: req.url ?? '', headers: req.headers, messages: [] };
    upstreamSeen.push(seen);
    ws.on('message', (data) => {
      seen.messages.push(data.toString());
      if (seen.messages.length === 1) ws.send(JSON.stringify({ Response: { ok: true } }));
    });
  });
  await new Promise<void>((resolve) => upstreamServer.listen(0, '127.0.0.1', resolve));
  upstreamPort = (upstreamServer.address() as AddressInfo).port;

  // Gateway under test: the real bridgeStream(), user taken from a header instead of a JWT.
  gateway = http.createServer();
  gatewayWss = new WebSocketServer({ noServer: true, perMessageDeflate: false });
  gateway.on('upgrade', (req, socket, head) => {
    const userId = String(req.headers['x-test-user']);
    gatewayWss.handleUpgrade(req, socket, head, (client) => {
      bridgeStream(client, userId, req, MLW_STREAM_WS_PATH, HEADER, { host: '127.0.0.1', port: upstreamPort });
    });
  });
  await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', resolve));
  gatewayPort = (gateway.address() as AddressInfo).port;
});

after(async () => {
  for (const c of [...gatewayWss.clients, ...upstreamWss.clients]) c.terminate();
  await Promise.all([
    new Promise<void>((resolve) => gateway.close(() => resolve())),
    new Promise<void>((resolve) => upstreamServer.close(() => resolve())),
  ]);
  closeDb();
  fs.rmSync(dir, { recursive: true, force: true });
});

const request = (hostId: number) => JSON.stringify({ Request: { host_id: hostId, app_id: 1, width: 1280, height: 720, fps: 60 } });

async function open(userId: string): Promise<WebSocket> {
  const ws = new WebSocket(`ws://127.0.0.1:${gatewayPort}${MLW_STREAM_WS_PATH}`, { headers: { 'x-test-user': userId } });
  await once(ws, 'open');
  return ws;
}

async function closeCode(ws: WebSocket): Promise<number> {
  const [code] = await once(ws, 'close') as [number];
  return code;
}

async function settle(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 150));
}

describe('canAccessMoonlightHost', () => {
  it('grants only hosts of Moonlight connections the user can access', () => {
    assert.equal(canAccessMoonlightHost(OWNER, HOST_OWNER), true);
    assert.equal(canAccessMoonlightHost(OWNER, HOST_SHARED), true);
    assert.equal(canAccessMoonlightHost(OWNER, HOST_OTHER), false);
    assert.equal(canAccessMoonlightHost(OTHER, HOST_OWNER), false, 'private host of another user');
    assert.equal(canAccessMoonlightHost(OTHER, HOST_SHARED), true, 'connection shared with everyone');
    assert.equal(canAccessMoonlightHost(OTHER, HOST_OTHER), true);
    assert.equal(canAccessMoonlightHost(OWNER, 99), false, 'extra_config_json of a non-Moonlight connection');
    assert.equal(canAccessMoonlightHost(OWNER, 12345), false, 'unknown host');
  });
});

describe('stream WebSocket bridge (the IDOR: host_id in the first message)', () => {
  it('lets a user stream from their own host and relays both directions', async () => {
    upstreamSeen = [];
    const ws = await open(OWNER);
    const received: string[] = [];
    ws.on('message', (d) => received.push(d.toString()));
    ws.send(request(HOST_OWNER));
    await settle();
    ws.send(JSON.stringify({ Stats: { Ping: 5 } }));
    await settle();

    assert.equal(upstreamSeen.length, 1);
    assert.equal(upstreamSeen[0].path, MLW_STREAM_WS_PATH);
    assert.equal(upstreamSeen[0].headers['x-gatwy-moonlight-user'], 'gatwy');
    assert.equal(upstreamSeen[0].messages.length, 2);
    assert.equal(JSON.parse(upstreamSeen[0].messages[0]).Request.host_id, HOST_OWNER);
    assert.deepEqual(JSON.parse(upstreamSeen[0].messages[1]), { Stats: { Ping: 5 } });
    assert.deepEqual(received.map((m) => JSON.parse(m)), [{ Response: { ok: true } }]);
    ws.close();
  });

  it('lets another user stream from a host that is shared with everyone', async () => {
    upstreamSeen = [];
    const ws = await open(OTHER);
    ws.send(request(HOST_SHARED));
    await settle();
    assert.equal(upstreamSeen.length, 1);
    ws.close();
  });

  it("refuses another user's private host and never connects upstream", async () => {
    upstreamSeen = [];
    const ws = await open(OTHER);
    const closed = closeCode(ws);
    ws.send(request(HOST_OWNER));
    assert.equal(await closed, 1008);
    await settle();
    assert.equal(upstreamSeen.length, 0);
  });

  it('refuses an unknown host', async () => {
    upstreamSeen = [];
    const ws = await open(OWNER);
    const closed = closeCode(ws);
    ws.send(request(4242));
    assert.equal(await closed, 1008);
    assert.equal(upstreamSeen.length, 0);
  });

  it('refuses a first message that is not a stream request, or is binary', async () => {
    upstreamSeen = [];
    for (const payload of [JSON.stringify({ Stats: { Ping: 1 } }), 'garbage', Buffer.from([1, 2, 3])]) {
      const ws = await open(OWNER);
      const closed = closeCode(ws);
      ws.send(payload);
      assert.equal(await closed, 1008);
    }
    assert.equal(upstreamSeen.length, 0);
  });

  it('forwards what it validated when host_id is duplicated', async () => {
    upstreamSeen = [];
    // OTHER owns HOST_OTHER only: the last duplicate is what both JSON.parse and the check see.
    const denied = await open(OTHER);
    const deniedClosed = closeCode(denied);
    denied.send(`{"Request":{"host_id":${HOST_OTHER},"host_id":${HOST_OWNER}}}`);
    assert.equal(await deniedClosed, 1008);
    assert.equal(upstreamSeen.length, 0);

    const allowed = await open(OTHER);
    allowed.send(`{"Request":{"host_id":${HOST_OWNER},"host_id":${HOST_OTHER}}}`);
    await settle();
    assert.equal(upstreamSeen.length, 1);
    assert.equal(upstreamSeen[0].messages[0], `{"Request":{"host_id":${HOST_OTHER}}}`);
    allowed.close();
  });

  it('closes the stream when a second request tries to switch host, and never forwards it', async () => {
    upstreamSeen = [];
    const ws = await open(OTHER);
    ws.send(request(HOST_OTHER));
    await settle();
    const closed = closeCode(ws);
    ws.send(request(HOST_OWNER));
    assert.equal(await closed, 1008);
    await settle();
    assert.equal(upstreamSeen.length, 1);
    assert.equal(upstreamSeen[0].messages.every((m) => !m.includes(`"host_id":${HOST_OWNER}`)), true);
  });
});
