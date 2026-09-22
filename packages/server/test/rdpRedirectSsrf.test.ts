// End-to-end (parser + guard) regression test for Sicurezza.md finding #4: an RDP server
// can send a Server Redirection PDU naming an arbitrary host/port, which rdpProxy.ts used to
// dial without any restriction (SSRF + credential relay to a target the connection owner
// never chose). This builds a real wire-format redirection PDU byte-by-byte — the same bytes
// inspectServerPreActivationFrame() parses in production — targeting a loopback address, and
// checks the parsed host is one isDangerousTunnelHost() (the guard now wired into
// rdpProxy.ts before it dials out) actually rejects.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  inspectServerPreActivationFrame,
  IO_CHANNEL_ID,
  SEC_REDIRECTION_PKT,
  LB_TARGET_NET_ADDRESS,
} from '../src/ws/rdpRedirect.js';
import { isDangerousTunnelHost } from '../src/services/ssrfGuard.js';

/** MCS SendDataIndication header wrapping a Server Redirection PDU on the I/O channel,
 *  in the shape decodeSendDataIndication()/getMcsTypeByte() expect: [03 00][len16][...][f0]
 *  at offset 5, choice 0x68 at offset 7, then initiator(2) + channelId(2) + priority(1) +
 *  PER length + payload. */
function wrapSendDataIndication(channelId: number, payload: Buffer): Buffer {
  const head = Buffer.from([
    0x03, 0x00, 0x00, 0x00, // 03 00 <len16 filled below>
    0x00,                   // (unused byte in this minimal encoding)
    0xf0,                   // MCS byte checked at offset 5
    0x00,                   // padding so choice lands at offset 7
    0x68,                   // SendDataIndication choice
  ]);
  const initiatorAndChannel = Buffer.from([0x00, 0x00, (channelId >> 8) & 0xff, channelId & 0xff, 0x00]);
  const perLen = payload.length < 0x80
    ? Buffer.from([payload.length])
    : Buffer.from([0x80 | ((payload.length >> 8) & 0x7f), payload.length & 0xff]);
  const frame = Buffer.concat([head, initiatorAndChannel, perLen, payload]);
  frame.writeUInt16BE(frame.length, 2);
  return frame;
}

/** A minimal Server Redirection PDU carrying only LB_TARGET_NET_ADDRESS, as
 *  parseServerRedirectionPacket() reads it: [flags16=SEC_REDIRECTION_PKT][len16][pad2]
 *  [redirectionFlags32][len32-prefixed UTF-16LE target address]. */
function buildRedirectionPacket(targetAddress: string): Buffer {
  const addrBuf = Buffer.from(`${targetAddress}\0`, 'utf16le');
  const lenPrefix = Buffer.alloc(4);
  lenPrefix.writeUInt32LE(addrBuf.length, 0);
  const body = Buffer.concat([lenPrefix, addrBuf]); // LB_TARGET_NET_ADDRESS: length32-prefixed UTF-16LE
  const header = Buffer.alloc(12); // flags16 + packetLength16 + reserved4 + redirectionFlags32
  header.writeUInt16LE(SEC_REDIRECTION_PKT, 0);
  header.writeUInt16LE(12 + body.length, 2);
  header.writeUInt32LE(LB_TARGET_NET_ADDRESS, 8);
  return Buffer.concat([header, body]);
}

describe('inspectServerPreActivationFrame + isDangerousTunnelHost (RDP redirect SSRF guard)', () => {
  it('parses a malicious redirection PDU pointing at loopback, and the guard rejects it', () => {
    const redirectionPacket = buildRedirectionPacket('127.0.0.1:3389');
    const frame = wrapSendDataIndication(IO_CHANNEL_ID, redirectionPacket);

    const result = inspectServerPreActivationFrame(frame, 3389);
    assert.equal(result.kind, 'redirect');
    if (result.kind !== 'redirect') return;
    assert.equal(result.redirect.host, '127.0.0.1');
    assert.equal(isDangerousTunnelHost(result.redirect.host), true);
  });

  it('parses a redirection PDU pointing at cloud metadata, and the guard rejects it', () => {
    const redirectionPacket = buildRedirectionPacket('169.254.169.254');
    const frame = wrapSendDataIndication(IO_CHANNEL_ID, redirectionPacket);

    const result = inspectServerPreActivationFrame(frame, 3389);
    assert.equal(result.kind, 'redirect');
    if (result.kind !== 'redirect') return;
    assert.equal(isDangerousTunnelHost(result.redirect.host), true);
  });

  it('parses a redirection PDU pointing at an ordinary internal host, which the guard allows', () => {
    const redirectionPacket = buildRedirectionPacket('10.0.0.5:3389');
    const frame = wrapSendDataIndication(IO_CHANNEL_ID, redirectionPacket);

    const result = inspectServerPreActivationFrame(frame, 3389);
    assert.equal(result.kind, 'redirect');
    if (result.kind !== 'redirect') return;
    assert.equal(result.redirect.host, '10.0.0.5');
    assert.equal(isDangerousTunnelHost(result.redirect.host), false);
  });

  it('ignores frames on a channel other than the I/O channel', () => {
    const redirectionPacket = buildRedirectionPacket('127.0.0.1');
    const frame = wrapSendDataIndication(IO_CHANNEL_ID + 1, redirectionPacket);

    const result = inspectServerPreActivationFrame(frame, 3389);
    assert.equal(result.kind, 'other');
  });
});
