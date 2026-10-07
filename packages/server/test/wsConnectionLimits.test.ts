// Regression tests for the per-user connection limit on the WebSocket proxies. The slot taken by
// acquireConnection() must be released exactly once per accepted session, and never for a session
// that was refused:
//  - RDP registered its release on 'close' before calling acquireConnection(), so every attempt
//    refused by the limit freed a slot it never held;
//  - SSH/Telnet only released in teardownSession(), which is only reached once a session is
//    cached, so every failure after acquireConnection() leaked a slot;
//  - teardownSession() ran twice when the reattach grace expired (ssh.end() re-enters it through
//    the shell 'close' handler): two disconnect audit events and two releases.
// Real proxies, temporary DB, fake upstreams.
import assert from 'node:assert/strict';
import { describe, it, before, after, afterEach, mock } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http, { type Server } from 'node:http';
import net, { type AddressInfo } from 'node:net';
import crypto from 'node:crypto';
import { WebSocket } from 'ws';
import ssh2 from 'ssh2';

const SshServer = ssh2.Server;

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-ws-limits-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'ws-connection-limits-test-secret';

const { initDb, stopAutoSave } = await import('../src/db/index.js');
const { execute, queryAll } = await import('../src/db/helpers.js');
const { setSettings } = await import('../src/services/settings.js');
const { issueWsTicket } = await import('../src/services/wsTicket.js');
const { setupSshProxy } = await import('../src/ws/sshProxy.js');
const { setupTelnetProxy } = await import('../src/ws/telnetProxy.js');
const { setupRdpProxy } = await import('../src/ws/rdpProxy.js');
const { getSession } = await import('../src/ws/sshSessionCache.js');

const LIMIT = 2;

let proxyServer: Server;
let proxyPort: number;
let sshUpstream: { port: number; close: () => void };
let tcpUpstream: { port: number; close: () => void };
let deadPort: number;
const clients: Client[] = [];

interface Client { ws: WebSocket; msgs: string[]; closed: Promise<number>; code: () => number | null }

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function until(cond: () => boolean, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (cond()) return true; await sleep(25); }
  return cond();
}

function listen(srv: net.Server | http.Server): Promise<number> {
  return new Promise((res) => srv.listen(0, '127.0.0.1', () => res((srv.address() as AddressInfo).port)));
}

// An SSH server that accepts any authentication and opens a shell that prints READY.
async function startFakeSsh() {
  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });
  const accepted = new Set<{ end: () => void }>();
  const srv = new SshServer({ hostKeys: [privateKey] }, (client) => {
    accepted.add(client);
    client.on('authentication', (ctx) => ctx.accept());
    client.on('ready', () => client.on('session', (accept) => {
      const session = accept();
      session.on('pty', (a) => a && a());
      session.on('window-change', (a) => a && a());
      session.on('shell', (a) => { a().write('READY\r\n'); });
    }));
    client.on('close', () => accepted.delete(client));
    client.on('error', () => { /* the proxy may drop the connection abruptly */ });
  });
  const port = await listen(srv as unknown as net.Server);
  return { port, close: () => { accepted.forEach((c) => c.end()); srv.close(); } };
}

// A TCP server that accepts and keeps the connections open (enough for a Telnet session).
async function startFakeTcp() {
  const sockets = new Set<net.Socket>();
  const srv = net.createServer((s) => {
    sockets.add(s);
    s.on('close', () => sockets.delete(s));
    s.on('error', () => { /* ignore */ });
  });
  const port = await listen(srv);
  return { port, close: () => { sockets.forEach((s) => s.destroy()); srv.close(); } };
}

function addUser(id: string) {
  execute('INSERT INTO users (id, username, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)',
    [id, id, 'x', id, 'admin']);
}

function addConn(id: string, userId: string, protocol: string, port: number, extra?: object) {
  execute(
    `INSERT INTO connections (id, user_id, name, protocol, host, port, extra_config_json) VALUES (?, ?, ?, ?, '127.0.0.1', ?, ?)`,
    [id, userId, id, protocol, port, extra ? JSON.stringify(extra) : null]);
}

function open(pathAndQuery: string, user: string): Client {
  const ticket = issueWsTicket(user, `token-${user}`);
  const sep = pathAndQuery.includes('?') ? '&' : '?';
  const ws = new WebSocket(`ws://127.0.0.1:${proxyPort}${pathAndQuery}${sep}ticket=${ticket}`);
  const msgs: string[] = [];
  let code: number | null = null;
  ws.on('message', (d: Buffer) => msgs.push(d.toString()));
  const closed = new Promise<number>((res) => {
    ws.on('close', (c: number) => { code = c; res(c); });
    ws.on('error', () => { /* 'close' follows */ });
  });
  const client = { ws, msgs, closed, code: () => code };
  clients.push(client);
  return client;
}

const sid = () => crypto.randomUUID();
const isConnected = (c: Client) => c.msgs.some((m) => m.includes('Connected'));

// After the failing attempts, can the user still open a healthy session?
async function healthyAttemptConnects(pathAndQuery: string, user: string): Promise<boolean> {
  const c = open(pathAndQuery, user);
  await until(() => isConnected(c) || c.code() !== null, 5000);
  return isConnected(c);
}

before(async () => {
  await initDb();
  setSettings({ 'security.max_connections_per_user': String(LIMIT) });

  proxyServer = http.createServer();
  setupSshProxy(proxyServer as never);
  setupTelnetProxy(proxyServer as never);
  setupRdpProxy(proxyServer as never);
  proxyPort = await listen(proxyServer);

  sshUpstream = await startFakeSsh();
  tcpUpstream = await startFakeTcp();
  const dead = net.createServer();
  deadPort = await listen(dead);
  await new Promise((r) => dead.close(r));
});

// Closing a cached SSH/Telnet client starts a grace timer that would keep the process alive for
// minutes: create those timers under the mock and drop them.
afterEach(async () => {
  mock.timers.enable({ apis: ['setTimeout'] });
  clients.splice(0).forEach((c) => c.ws.terminate());
  for (let i = 0; i < 50; i++) await new Promise((r) => setImmediate(r));
  mock.timers.reset();
  await sleep(100);
});

after(() => {
  sshUpstream.close();
  tcpUpstream.close();
  proxyServer.close();
  stopAutoSave();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

describe('connection limit accounting on the WebSocket proxies', () => {
  it('RDP: attempts refused by the limit do not free a slot', async () => {
    addUser('u-rdp');
    addConn('rdp1', 'u-rdp', 'rdp', 1);
    const attempts: Client[] = [];
    for (let i = 0; i < 6; i++) {
      attempts.push(open('/ws/rdp-raw?connectionId=rdp1', 'u-rdp'));
      await sleep(150);
    }
    await until(() => attempts.filter((c) => c.code() === 4008).length >= 4, 3000);
    await sleep(300);
    assert.equal(attempts.filter((c) => c.code() === null).length, LIMIT,
      `codes: ${JSON.stringify(attempts.map((c) => c.code()))}`);
  });

  it('SSH: a connection of another protocol (4002) does not leak a slot', async () => {
    addUser('u-ssh-4002');
    addConn('tel-as-ssh', 'u-ssh-4002', 'telnet', 1);
    addConn('ssh-ok-4002', 'u-ssh-4002', 'ssh', sshUpstream.port);
    for (let i = 0; i < LIMIT; i++) {
      const c = open(`/ws/ssh?connectionId=tel-as-ssh&sessionId=${sid()}`, 'u-ssh-4002');
      assert.equal(await c.closed, 4002);
    }
    assert.equal(await healthyAttemptConnects(`/ws/ssh?connectionId=ssh-ok-4002&sessionId=${sid()}`, 'u-ssh-4002'), true);
  });

  it('SSH: an error before the handshake completes does not leak a slot', async () => {
    addUser('u-ssh-err');
    addConn('ssh-dead', 'u-ssh-err', 'ssh', deadPort);
    addConn('ssh-ok-err', 'u-ssh-err', 'ssh', sshUpstream.port);
    for (let i = 0; i < LIMIT; i++) {
      const c = open(`/ws/ssh?connectionId=ssh-dead&sessionId=${sid()}`, 'u-ssh-err');
      assert.equal(await c.closed, 4003);
    }
    assert.equal(await healthyAttemptConnects(`/ws/ssh?connectionId=ssh-ok-err&sessionId=${sid()}`, 'u-ssh-err'), true);
  });

  it('SSH: leaving while the one-time password is awaited does not leak a slot', async () => {
    addUser('u-ssh-prompt');
    addConn('ssh-prompt', 'u-ssh-prompt', 'ssh', sshUpstream.port, { promptOnConnect: true });
    addConn('ssh-ok-prompt', 'u-ssh-prompt', 'ssh', sshUpstream.port);
    for (let i = 0; i < LIMIT; i++) {
      const c = open(`/ws/ssh?connectionId=ssh-prompt&sessionId=${sid()}`, 'u-ssh-prompt');
      await until(() => c.ws.readyState === WebSocket.OPEN, 2000);
      c.ws.close();
      await c.closed;
    }
    await sleep(200);
    assert.equal(await healthyAttemptConnects(`/ws/ssh?connectionId=ssh-ok-prompt&sessionId=${sid()}`, 'u-ssh-prompt'), true);
  });

  it('Telnet: a connection of another protocol (4002) does not leak a slot', async () => {
    addUser('u-tel-4002');
    addConn('ssh-as-tel', 'u-tel-4002', 'ssh', 1);
    addConn('tel-ok-4002', 'u-tel-4002', 'telnet', tcpUpstream.port);
    for (let i = 0; i < LIMIT; i++) {
      const c = open(`/ws/telnet?connectionId=ssh-as-tel&sessionId=${sid()}`, 'u-tel-4002');
      assert.equal(await c.closed, 4002);
    }
    assert.equal(await healthyAttemptConnects(`/ws/telnet?connectionId=tel-ok-4002&sessionId=${sid()}`, 'u-tel-4002'), true);
  });

  it('Telnet: a refused TCP connection does not leak a slot', async () => {
    addUser('u-tel-err');
    addConn('tel-dead', 'u-tel-err', 'telnet', deadPort);
    addConn('tel-ok-err', 'u-tel-err', 'telnet', tcpUpstream.port);
    for (let i = 0; i < LIMIT; i++) {
      const c = open(`/ws/telnet?connectionId=tel-dead&sessionId=${sid()}`, 'u-tel-err');
      assert.equal(await c.closed, 4003);
    }
    assert.equal(await healthyAttemptConnects(`/ws/telnet?connectionId=tel-ok-err&sessionId=${sid()}`, 'u-tel-err'), true);
  });

  it('SSH: the expiry of the reattach grace tears the session down once', async () => {
    addUser('u-ssh-grace');
    addConn('ssh-grace', 'u-ssh-grace', 'ssh', sshUpstream.port);
    const live = open(`/ws/ssh?connectionId=ssh-grace&sessionId=${sid()}`, 'u-ssh-grace');
    const leaving = open(`/ws/ssh?connectionId=ssh-grace&sessionId=leaving-${sid()}`, 'u-ssh-grace');
    const leavingId = new URL(leaving.ws.url).searchParams.get('sessionId')!;
    await until(() => isConnected(live) && isConnected(leaving), 5000);
    assert.ok(isConnected(live) && isConnected(leaving), 'both sessions should connect');

    // Close one client and let its grace period run out without waiting two minutes.
    mock.timers.enable({ apis: ['setTimeout'] });
    leaving.ws.close();
    for (let i = 0; i < 20000 && !getSession(leavingId)?.timer; i++) await new Promise((r) => setImmediate(r));
    assert.ok(getSession(leavingId)?.timer, 'closing the client should start the grace timer');
    mock.timers.tick(120_000);
    mock.timers.reset();
    await until(() => getSession(leavingId) === undefined, 3000);
    await sleep(500); // the second teardown, if any, comes from the shell 'close' event

    const disconnects = queryAll<{ id: string }>("SELECT rowid AS id FROM audit_log WHERE event_type = 'session.ssh.disconnect'", []);
    assert.equal(disconnects.length, 1, 'one disconnect audit event for the expired session');

    // One live session plus one expired: exactly one slot is free again.
    const next = open(`/ws/ssh?connectionId=ssh-grace&sessionId=${sid()}`, 'u-ssh-grace');
    await until(() => isConnected(next) || next.code() !== null, 5000);
    assert.ok(isConnected(next), 'a slot should be free after the expiry');
    const overLimit = open(`/ws/ssh?connectionId=ssh-grace&sessionId=${sid()}`, 'u-ssh-grace');
    assert.equal(await overLimit.closed, 4008);
  });
});
