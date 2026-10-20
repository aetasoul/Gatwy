// Regression test: a WebSocket upgrade whose Host header or request target is not a valid URL
// used to make `new URL(...)` throw inside the 'upgrade' listeners of the SSH, Telnet and RDP
// proxies. Nothing caught it, so a single unauthenticated request ended the whole process.
// The proxies now parse the request target against a fixed base inside a try/catch and drop the
// socket when it cannot be parsed.
import assert from 'node:assert/strict';
import { describe, it, before, after } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http, { type Server } from 'node:http';
import net, { type AddressInfo } from 'node:net';
import { WebSocket } from 'ws';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-ws-upgrade-url-test-'));
process.env.DATA_DIR = dataDir;
process.env.JWT_SECRET = 'ws-upgrade-url-test-secret';

const { initDb, stopAutoSave } = await import('../src/db/index.js');
const { setupSshProxy } = await import('../src/ws/sshProxy.js');
const { setupTelnetProxy } = await import('../src/ws/telnetProxy.js');
const { setupRdpProxy } = await import('../src/ws/rdpProxy.js');
const { setupVncProxy } = await import('../src/ws/vncProxy.js');

let server: Server;
let port: number;
const uncaught: Error[] = [];
const onUncaught = (err: Error) => { uncaught.push(err); };

before(async () => {
  await initDb();
  process.on('uncaughtException', onUncaught);
  server = http.createServer();
  // The proxies only use the 'upgrade' event, so a plain http server is enough here.
  setupSshProxy(server as never);
  setupTelnetProxy(server as never);
  setupRdpProxy(server as never);
  setupVncProxy(server as never);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
});

after(() => {
  process.off('uncaughtException', onUncaught);
  server.closeAllConnections();
  server.close();
  stopAutoSave();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

// Sends a raw upgrade request and resolves as soon as the status line arrives or the socket is
// closed. The result is the status line, or '' when the server dropped the socket without
// answering. The timer is only a guard so a hang fails the test instead of blocking it.
function rawUpgrade(target: string, host: string | null): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: '127.0.0.1', port }, () => {
      sock.write([
        `GET ${target} HTTP/1.1`,
        ...(host === null ? [] : [`Host: ${host}`]),
        'Connection: Upgrade',
        'Upgrade: websocket',
        'Sec-WebSocket-Version: 13',
        'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
        '', '',
      ].join('\r\n'));
    });
    let resp = '';
    const guard = setTimeout(() => {
      sock.destroy();
      reject(new Error(`no 101 and no close within 3s for ${target} (Host: ${host})`));
    }, 3000);
    const done = () => { clearTimeout(guard); sock.destroy(); resolve(resp.split('\r\n')[0]); };
    sock.on('data', (d) => { resp += d; if (resp.includes('\r\n')) done(); });
    sock.on('error', done);
    sock.on('close', done);
  });
}

// A valid upgrade on the real path: the proxy accepts it and closes with 4001 (no ticket).
function validUpgradeCloseCode(wsPath: string): Promise<number> {
  return new Promise((resolve) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}${wsPath}`);
    ws.once('close', (code) => resolve(code));
    ws.once('error', () => resolve(0));
  });
}

const PROXY_PATHS = ['/ws/ssh', '/ws/telnet', '/ws/rdp-raw'];
// VNC has no URL parsing of its own, but the SSH, Telnet and RDP listeners run on its upgrades too.
// Without a ticket the VNC proxy drops the socket, which is what the test waits for.
const VNC_PATH = '/ws/vnc/some-connection-id';
const BAD_HOSTS = ['a b', 'x@', '[', 'a:b', 'a%zz'];

describe('WebSocket upgrade with an unparseable Host or request target', () => {
  for (const wsPath of PROXY_PATHS) {
    for (const host of BAD_HOSTS) {
      it(`${wsPath} still upgrades with Host: ${JSON.stringify(host)}`, async () => {
        const before = uncaught.length;
        // The Host header is not used to read the path or the query, so it is simply ignored.
        const status = await rawUpgrade(wsPath, host);
        assert.ok(status.includes('101'), `got: ${JSON.stringify(status)}`);
        assert.equal(uncaught.length, before, `uncaught exception: ${uncaught.at(-1)?.message}`);
      });
    }
  }

  for (const host of BAD_HOSTS) {
    it(`${VNC_PATH} is closed without a crash with Host: ${JSON.stringify(host)}`, async () => {
      const before = uncaught.length;
      const status = await rawUpgrade(VNC_PATH, host);
      assert.equal(status, '', 'no ticket: the socket must be dropped without a response');
      assert.equal(uncaught.length, before, `uncaught exception: ${uncaught.at(-1)?.message}`);
    });
  }

  it('drops a request target that is not a valid URL even with a good Host', async () => {
    for (const target of ['//a%zz', 'http://[', '//x@', '//[']) {
      const before = uncaught.length;
      const status = await rawUpgrade(target, `127.0.0.1:${port}`);
      assert.equal(status, '', `target ${target} must be dropped`);
      assert.equal(uncaught.length, before, `target ${target}: ${uncaught.at(-1)?.message}`);
    }
  });

  it('does not crash on a malformed Host for a path no proxy claims', async () => {
    // Nothing answers or closes such an upgrade, so there is no event to wait for. A throw inside
    // a listener is synchronous with the 'upgrade' event, so once a later valid upgrade has been
    // served, the earlier one has been dispatched too.
    const before = uncaught.length;
    const sock = net.connect({ host: '127.0.0.1', port });
    sock.on('error', () => {});
    await new Promise<void>((r) => sock.once('connect', () => r()));
    sock.write('GET /anything/else HTTP/1.1\r\nHost: a%zz\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n'
      + 'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n');
    assert.equal(await validUpgradeCloseCode('/ws/ssh'), 4001);
    sock.destroy();
    assert.equal(uncaught.length, before, `uncaught exception: ${uncaught.at(-1)?.message}`);
  });

  it('keeps accepting valid upgrades afterwards', async () => {
    for (const wsPath of PROXY_PATHS) {
      assert.equal(await validUpgradeCloseCode(wsPath), 4001, `${wsPath} must still reach the proxy`);
    }
  });

  it('still upgrades a request without a Host header', async () => {
    const status = await rawUpgrade('/ws/ssh', null);
    assert.ok(status.includes('101'), `got: ${status}`);
  });
});
