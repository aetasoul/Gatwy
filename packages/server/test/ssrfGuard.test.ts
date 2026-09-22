import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { isDangerousTunnelHost } from '../src/services/ssrfGuard.js';

describe('isDangerousTunnelHost', () => {
  it('blocks loopback, link-local, metadata, and unspecified addresses', () => {
    assert.equal(isDangerousTunnelHost('127.0.0.1'), true);
    assert.equal(isDangerousTunnelHost('127.5.5.5'), true);
    assert.equal(isDangerousTunnelHost('::1'), true);
    assert.equal(isDangerousTunnelHost('localhost'), true);
    assert.equal(isDangerousTunnelHost('LOCALHOST'), true);
    assert.equal(isDangerousTunnelHost('169.254.169.254'), true); // AWS/Azure/GCP metadata
    assert.equal(isDangerousTunnelHost('0.0.0.0'), true);
    assert.equal(isDangerousTunnelHost('fc00::1'), true);
    assert.equal(isDangerousTunnelHost('fe80::1'), true);
  });

  it('allows RFC-1918 private ranges (legitimate internal targets on the remote side)', () => {
    assert.equal(isDangerousTunnelHost('10.0.0.5'), false);
    assert.equal(isDangerousTunnelHost('172.16.0.5'), false);
    assert.equal(isDangerousTunnelHost('192.168.1.5'), false);
  });

  it('allows ordinary public hosts', () => {
    assert.equal(isDangerousTunnelHost('example.com'), false);
    assert.equal(isDangerousTunnelHost('8.8.8.8'), false);
  });
});
