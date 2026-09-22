/** Block loopback and cloud metadata endpoints in tunnel remote hosts (C8 SSRF fix).
 *  RFC-1918 private ranges are intentionally allowed — tunnels to internal servers are a
 *  legitimate use case relative to the SSH target's network, not the Gatwy server. */
export function isDangerousTunnelHost(host: string): boolean {
  const h = host.trim().toLowerCase();
  return (
    /^127\./.test(h) ||                // IPv4 loopback
    h === '::1' ||                     // IPv6 loopback
    h === 'localhost' ||               // loopback hostname
    /^169\.254\./.test(h) ||           // link-local / cloud metadata (AWS/Azure/GCP)
    /^0\.0\.0\.0/.test(h) ||           // unspecified address
    /^fc00:/i.test(h) ||               // unique local IPv6
    /^fe80:/i.test(h)                  // link-local IPv6
  );
}
