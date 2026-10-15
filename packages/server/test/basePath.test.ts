// BASE_PATH support for running Gatwy behind a reverse-proxy path prefix (e.g. Traefik's
// PathPrefix('/sys/ftp')). Without this, the built client's root-absolute asset references
// (`src="/assets/index-<hash>.js"`) and the server's route mounts ignore the prefix, so a
// browser requests the asset at the host root instead of under the prefix — 404, or the wrong
// app's HTML served back as "JS" (NS_ERROR_CORRUPTED_CONTENT in Firefox).
import assert from 'node:assert/strict';
import { describe, it, after } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const { normalizeBasePath, config } = await import('../src/config.js');
const { renderIndexHtml, renderManifest } = await import('../src/services/indexHtml.js');
const { moonlightPathPrefix } = await import('../src/services/moonlightWeb.js');
const { classifyMoonlightRequest } = await import('../src/ws/moonlightGuard.js');

describe('normalizeBasePath', () => {
  it("defaults to the root sentinel '/' for unset/empty input (no regression for existing deployments)", () => {
    assert.equal(normalizeBasePath(undefined), '/');
    assert.equal(normalizeBasePath(''), '/');
    assert.equal(normalizeBasePath('   '), '/');
    assert.equal(normalizeBasePath('/'), '/');
  });

  it('ensures exactly one leading slash and no trailing slash', () => {
    assert.equal(normalizeBasePath('sys/ftp'), '/sys/ftp');
    assert.equal(normalizeBasePath('/sys/ftp'), '/sys/ftp');
    assert.equal(normalizeBasePath('/sys/ftp/'), '/sys/ftp');
    assert.equal(normalizeBasePath('sys/ftp/'), '/sys/ftp');
  });

  it('rejects characters that are unsafe in HTML or Express route patterns', () => {
    for (const bad of ['/a"b', '/a<b>', '/a:b', '/a*', '/a(b)', '/a b', '/a//b', '/../x', '/./x', '/a?b', '/a#b']) {
      assert.throws(() => normalizeBasePath(bad), /Invalid BASE_PATH/, bad);
    }
  });
});

describe('moonlight under a prefix', () => {
  it('moonlight-web is told the full public prefix (BASE_PATH + /mlw)', () => {
    const prev = config.basePath;
    try {
      config.basePath = '/';
      assert.equal(moonlightPathPrefix(), '/mlw');
      config.basePath = '/sys/ftp';
      assert.equal(moonlightPathPrefix(), '/sys/ftp/mlw');
    } finally {
      config.basePath = prev;
    }
  });

  it('the guard takes the mount prefix and forwards the prefixed path upstream', () => {
    const mount = '/sys/ftp/mlw';
    assert.deepEqual(classifyMoonlightRequest('GET', '/sys/ftp/mlw/config.js?x=1', false, mount), {
      kind: 'http', path: '/sys/ftp/mlw/config.js', search: '?x=1',
    });
    assert.deepEqual(classifyMoonlightRequest('GET', '/sys/ftp/mlw/api/role', false, mount), {
      kind: 'http', path: '/sys/ftp/mlw/api/role', search: '',
    });
    assert.deepEqual(classifyMoonlightRequest('GET', '/sys/ftp/mlw/api/host/stream/web_socket', true, mount), {
      kind: 'stream-ws', path: '/sys/ftp/mlw/api/host/stream/web_socket',
    });
    assert.deepEqual(classifyMoonlightRequest('GET', '/mlw/config.js', false), {
      kind: 'http', path: '/mlw/config.js', search: '',
    });
  });

  it('the guard stays fail-closed under a prefix', () => {
    const mount = '/sys/ftp/mlw';
    const kind = (method: string, url: string, upgrade = false) => classifyMoonlightRequest(method, url, upgrade, mount).kind;
    assert.equal(kind('GET', '/mlw/config.js'), 'deny', 'unprefixed path is not the mount');
    assert.equal(kind('GET', '/sys/ftp/mlwx/config.js'), 'deny');
    assert.equal(kind('GET', '/sys/ftp/mlw/../x'), 'deny');
    assert.equal(kind('GET', '/sys/ftp/mlw/%2e%2e/x'), 'deny');
    assert.equal(kind('GET', '/sys/ftp/mlw/api/host'), 'deny', 'host listing is not allowlisted');
    assert.equal(kind('POST', '/sys/ftp/mlw/api/host'), 'deny');
    assert.equal(kind('GET', '/sys/ftp/mlw/api/pair', true), 'deny', 'only the stream WebSocket may upgrade');
    assert.equal(kind('GET', '/mlw/api/host/stream/web_socket', true), 'deny', 'unprefixed stream path is not the mount');
  });
});

describe('renderManifest', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-manifest-test-'));
  fs.writeFileSync(path.join(dir, 'manifest.webmanifest'), JSON.stringify({
    name: 'Gatwy', start_url: '/', scope: '/', icons: [{ src: '/favicon.png', sizes: '512x512' }],
  }));
  after(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('moves start_url, scope and icons under the prefix', () => {
    const m = JSON.parse(renderManifest(dir, '/sys/ftp')) as { name: string; start_url: string; scope: string; icons: { src: string }[] };
    assert.equal(m.name, 'Gatwy');
    assert.equal(m.start_url, '/sys/ftp/');
    assert.equal(m.scope, '/sys/ftp/');
    assert.equal(m.icons[0].src, '/sys/ftp/favicon.png');
  });
});

describe('basePathPrefix', () => {
  it("converts the root sentinel '/' to '' so route mounts never get a doubled leading slash", () => {
    const prev = config.basePath;
    try {
      config.basePath = '/';
      assert.equal(config.basePathPrefix, '');
      config.basePath = '/sys/ftp';
      assert.equal(config.basePathPrefix, '/sys/ftp');
    } finally {
      config.basePath = prev;
    }
  });
});

describe('renderIndexHtml', () => {
  const clientDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gatwy-index-html-test-'));
  const indexPath = path.join(clientDir, 'index.html');
  fs.writeFileSync(
    indexPath,
    [
      '<!DOCTYPE html>',
      '<html lang="en">',
      '  <head>',
      '    <link rel="icon" type="image/png" href="/favicon.png" />',
      '    <link rel="manifest" href="/manifest.webmanifest" />',
      '    <link rel="stylesheet" href="/assets/index-abc123.css" />',
      '  </head>',
      '  <body>',
      '    <div id="root"></div>',
      '    <script type="module" src="/assets/index-abc123.js"></script>',
      '  </body>',
      '</html>',
    ].join('\n'),
  );

  after(() => {
    fs.rmSync(clientDir, { recursive: true, force: true });
  });

  it('leaves root-absolute references untouched at the root (no regression)', () => {
    const html = renderIndexHtml(clientDir, '');  // '' — see basePathPrefix above
    assert.match(html, /href="\/favicon\.png"/);
    assert.match(html, /href="\/manifest\.webmanifest"/);
    assert.match(html, /href="\/assets\/index-abc123\.css"/);
    assert.match(html, /src="\/assets\/index-abc123\.js"/);
    assert.match(html, /<base href="\/" \/>/);
    assert.match(html, /<meta name="gatwy-base-path" content="" \/>/);
  });

  it('prefixes every root-absolute asset reference with BASE_PATH', () => {
    const html = renderIndexHtml(clientDir, '/sys/ftp');
    assert.match(html, /href="\/sys\/ftp\/favicon\.png"/);
    assert.match(html, /href="\/sys\/ftp\/manifest\.webmanifest"/);
    assert.match(html, /href="\/sys\/ftp\/assets\/index-abc123\.css"/);
    assert.match(html, /src="\/sys\/ftp\/assets\/index-abc123\.js"/);
    assert.match(html, /<base href="\/sys\/ftp\/" \/>/);
    assert.match(html, /<meta name="gatwy-base-path" content="\/sys\/ftp" \/>/);
  });
});
