// Pure RDP wire-protocol parsing for Server Redirection PDUs — no per-connection state,
// safe to unit test directly (moved out of setupRdpProxy's closure in rdpProxy.ts so it can
// be exercised without a live WebSocket/TLS/RDP server).

export interface RedirectInfo {
  host: string;
  port: number;
  routingToken?: Buffer;
  username?: string;
  domain?: string;
  password?: string;
}

export const IO_CHANNEL_ID = 1003;
export const MCS_DISCONNECT_PROVIDER_ULTIMATUM = 0x08;
export const PDU_TYPE_DEMAND_ACTIVE = 0x1;
export const PDU_TYPE_DEACTIVATE_ALL = 0x6;
export const PDU_TYPE_SERVER_REDIRECTION = 0x0a;
export const SEC_REDIRECTION_PKT = 0x0400;
export const LB_TARGET_NET_ADDRESS = 0x00000001;
export const LB_LOAD_BALANCE_INFO = 0x00000002;
export const LB_USERNAME = 0x00000004;
export const LB_DOMAIN = 0x00000008;
export const LB_PASSWORD = 0x00000010;
export const LB_TARGET_FQDN = 0x00000100;
export const LB_TARGET_NETBIOS_NAME = 0x00000200;
export const LB_PASSWORD_IS_PK_ENCRYPTED = 0x00004000;

export function parsePerLength(buf: Buffer, off: number): { value: number; bytesRead: number } | null {
  if (off >= buf.length) return null;
  const first = buf[off];
  if ((first & 0x80) === 0) return { value: first, bytesRead: 1 };
  if (off + 1 >= buf.length) return null;
  return { value: ((first & 0x7f) << 8) | buf[off + 1], bytesRead: 2 };
}

export function decodeSendDataIndication(frame: Buffer): { channelId: number; userData: Buffer } | null {
  if (frame.length < 8 || frame[0] !== 0x03 || frame[1] !== 0x00 || frame[5] !== 0xf0) return null;

  let off = 7;
  if (off >= frame.length || frame[off] !== 0x68) return null;
  off += 1; // SendDataIndication choice

  if (off + 5 > frame.length) return null;
  off += 2; // initiator id
  const channelId = (frame[off] << 8) | frame[off + 1];
  off += 2;
  off += 1; // dataPriority + segmentation

  const userDataLen = parsePerLength(frame, off);
  if (!userDataLen) return null;
  off += userDataLen.bytesRead;
  if (off + userDataLen.value > frame.length) return null;

  return { channelId, userData: frame.subarray(off, off + userDataLen.value) };
}

export function getMcsTypeByte(frame: Buffer): number | null {
  if (frame.length < 8 || frame[0] !== 0x03 || frame[1] !== 0x00 || frame[5] !== 0xf0) return null;
  return frame[7];
}

export function isDisconnectProviderUltimatum(frame: Buffer): boolean {
  const mcsType = getMcsTypeByte(frame);
  if (mcsType === null) return false;
  if (mcsType === MCS_DISCONNECT_PROVIDER_ULTIMATUM) return true;
  // Some servers encode this choice with PER class bits in the upper nibble.
  if ((mcsType & 0xfc) === 0x28) return true;
  return false;
}

export function decodeDisconnectProviderUltimatumReason(frame: Buffer): { raw: number | null; decoded: number | null } {
  if (!isDisconnectProviderUltimatum(frame)) return { raw: null, decoded: null };
  if (frame.length < 9) return { raw: null, decoded: null };
  const raw = frame[8];
  return { raw, decoded: raw & 0x0f };
}

export function parseShareControlHeader(userData: Buffer): { pduType: number; body: Buffer } | null {
  if (userData.length < 8) return null;
  const totalLength = userData.readUInt16LE(0);
  const pduType = userData.readUInt16LE(2) & 0x0f;
  const bodyLength = Math.max(0, Math.min(totalLength, userData.length) - 8);
  return { pduType, body: userData.subarray(8, 8 + bodyLength) };
}

export function readLengthPrefixedData(buf: Buffer, off: number, end: number): { value: Buffer; next: number } | null {
  if (off + 4 > end) return null;
  const length = buf.readUInt32LE(off);
  if (off + 4 + length > end) return null;
  return { value: buf.subarray(off + 4, off + 4 + length), next: off + 4 + length };
}

export function readLengthPrefixedUnicode(buf: Buffer, off: number, end: number): { value: string; next: number } | null {
  const data = readLengthPrefixedData(buf, off, end);
  if (!data) return null;
  let bytes = data.value;
  while (bytes.length >= 2 && bytes.readUInt16LE(bytes.length - 2) === 0) {
    bytes = bytes.subarray(0, bytes.length - 2);
  }
  return { value: bytes.toString('utf16le'), next: data.next };
}

export function splitTargetAddress(address: string, defaultPort: number): { host: string; port: number } {
  const trimmed = address.trim();
  if (trimmed.startsWith('[')) {
    const end = trimmed.indexOf(']');
    if (end > 0) {
      const host = trimmed.slice(1, end);
      const rawPort = trimmed.slice(end + 1).replace(/^:/, '');
      const port = Number.parseInt(rawPort, 10);
      return { host, port: Number.isFinite(port) ? port : defaultPort };
    }
  }

  const firstColon = trimmed.indexOf(':');
  const lastColon = trimmed.lastIndexOf(':');
  if (firstColon > 0 && firstColon === lastColon) {
    const host = trimmed.slice(0, lastColon);
    const port = Number.parseInt(trimmed.slice(lastColon + 1), 10);
    return { host, port: Number.isFinite(port) ? port : defaultPort };
  }

  return { host: trimmed, port: defaultPort };
}

export function parseServerRedirectionPacket(data: Buffer, defaultPort: number): RedirectInfo | null {
  let off = 0;
  if (data.length >= 14 && data.readUInt16LE(0) === 0x0000) off = 2;
  if (data.length < off + 12) return null;

  const flags = data.readUInt16LE(off);
  if (flags !== SEC_REDIRECTION_PKT) return null;

  const packetLength = data.readUInt16LE(off + 2);
  const end = Math.min(data.length, off + packetLength);
  const redirectionFlags = data.readUInt32LE(off + 8);
  off += 12;

  let targetAddress = '';
  let targetFqdn = '';
  let targetNetbios = '';
  let username = '';
  let domain = '';
  let password = '';
  let routingToken: Buffer | undefined;

  if (redirectionFlags & LB_TARGET_NET_ADDRESS) {
    const parsed = readLengthPrefixedUnicode(data, off, end);
    if (!parsed) return null;
    targetAddress = parsed.value;
    off = parsed.next;
  }
  if (redirectionFlags & LB_LOAD_BALANCE_INFO) {
    const parsed = readLengthPrefixedData(data, off, end);
    if (!parsed) return null;
    routingToken = Buffer.from(parsed.value);
    off = parsed.next;
  }
  if (redirectionFlags & LB_USERNAME) {
    const parsed = readLengthPrefixedUnicode(data, off, end);
    if (!parsed) return null;
    username = parsed.value;
    off = parsed.next;
  }
  if (redirectionFlags & LB_DOMAIN) {
    const parsed = readLengthPrefixedUnicode(data, off, end);
    if (!parsed) return null;
    domain = parsed.value;
    off = parsed.next;
  }
  if (redirectionFlags & LB_PASSWORD) {
    const parsed = readLengthPrefixedData(data, off, end);
    if (!parsed) return null;
    if ((redirectionFlags & LB_PASSWORD_IS_PK_ENCRYPTED) === 0) {
      let bytes = parsed.value;
      while (bytes.length >= 2 && bytes.readUInt16LE(bytes.length - 2) === 0) {
        bytes = bytes.subarray(0, bytes.length - 2);
      }
      password = bytes.toString('utf16le');
    }
    off = parsed.next;
  }
  if (redirectionFlags & LB_TARGET_FQDN) {
    const parsed = readLengthPrefixedUnicode(data, off, end);
    if (!parsed) return null;
    targetFqdn = parsed.value;
    off = parsed.next;
  }
  if (redirectionFlags & LB_TARGET_NETBIOS_NAME) {
    const parsed = readLengthPrefixedUnicode(data, off, end);
    if (!parsed) return null;
    targetNetbios = parsed.value;
  }

  const target = targetFqdn || targetAddress || targetNetbios;
  const { host, port } = splitTargetAddress(target || '', defaultPort);
  if (!host) return null;

  return {
    host,
    port,
    routingToken,
    username: username || undefined,
    domain: domain || undefined,
    password: password || undefined,
  };
}

export function inspectServerPreActivationFrame(frame: Buffer, defaultPort: number):
  | { kind: 'other'; mcsType: number | null; frameHexHead: string }
  | { kind: 'disconnect-provider-ultimatum'; reasonRaw: number | null; reasonDecoded: number | null; mcsType: number | null; frameHexHead: string }
  | { kind: 'demand-active' }
  | { kind: 'deactivate-all' }
  | { kind: 'redirect'; redirect: RedirectInfo } {
  const frameHexHead = frame.subarray(0, Math.min(24, frame.length)).toString('hex');
  const mcsType = getMcsTypeByte(frame);

  if (isDisconnectProviderUltimatum(frame)) {
    const reason = decodeDisconnectProviderUltimatumReason(frame);
    return {
      kind: 'disconnect-provider-ultimatum',
      reasonRaw: reason.raw,
      reasonDecoded: reason.decoded,
      mcsType,
      frameHexHead,
    };
  }

  const indication = decodeSendDataIndication(frame);
  if (!indication || indication.channelId !== IO_CHANNEL_ID) return { kind: 'other', mcsType, frameHexHead };

  const basicRedirection = parseServerRedirectionPacket(indication.userData, defaultPort);
  if (basicRedirection) return { kind: 'redirect', redirect: basicRedirection };

  const shareControl = parseShareControlHeader(indication.userData);
  if (!shareControl) return { kind: 'other', mcsType, frameHexHead };

  if (shareControl.pduType === PDU_TYPE_DEACTIVATE_ALL) return { kind: 'deactivate-all' };
  if (shareControl.pduType === PDU_TYPE_DEMAND_ACTIVE) return { kind: 'demand-active' };
  if (shareControl.pduType === PDU_TYPE_SERVER_REDIRECTION) {
    const redirect = parseServerRedirectionPacket(shareControl.body, defaultPort);
    if (redirect) return { kind: 'redirect', redirect };
  }

  return { kind: 'other', mcsType, frameHexHead };
}
