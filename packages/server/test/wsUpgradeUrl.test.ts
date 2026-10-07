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

// Sends a raw upgrade request and resolves with the status line (empty if the socket was dropped).
function rawUpgrade(target: string, host: string | null): Promise<string> {
  return new Promise((resolve) => {
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
    sock.on('data', (d) => { resp += d; });
    sock.on('error', () => resolve(resp.split('\r\n')[0]));
    sock.on('close', () => resolve(resp.split('\r\n')[0]));
    setTimeout(() => { sock.destroy(); resolve(resp.split('\r\n')[0]); }, 3000);
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
const BAD_HOSTS = ['a b', 'x@', '[', 'a:b', 'a%zz'];

describe('WebSocket upgrade with an unparseable Host or request target', () => {
  for (const wsPath of PROXY_PATHS) {
    for (const host of BAD_HOSTS) {
      it(`${wsPath} survives Host: ${JSON.stringify(host)}`, async () => {
        const before = uncaught.length;
        await rawUpgrade(wsPath, host);
        // The Host header is not used to read the path or the query, so it is simply ignored.
        assert.equal(uncaught.length, before, `uncaught exception: ${uncaught.at(-1)?.message}`);
      });
    }
  }

  it('survives a request target that is not a valid URL even with a good Host', async () => {
    for (const target of ['//a%zz', '//a b', 'http://[', '//x@']) {
      const before = uncaught.length;
      await rawUpgrade(target, `127.0.0.1:${port}`);
      assert.equal(uncaught.length, before, `target ${target}: ${uncaught.at(-1)?.message}`);
    }
  });

  it('survives a malformed Host on any path, not only the proxy paths', async () => {
    const before = uncaught.length;
    await rawUpgrade('/anything/else', 'a%zz');
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
