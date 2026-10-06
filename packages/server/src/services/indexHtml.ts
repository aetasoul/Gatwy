import fs from 'fs';
import path from 'path';

/**
 * Builds the index.html served for the SPA catch-all route, rewritten to work behind a
 * reverse-proxy path prefix (`BASE_PATH`, see config.ts#normalizeBasePath). 
 */
export function renderIndexHtml(clientDir: string, basePath: string): string {
  const raw = fs.readFileSync(path.join(clientDir, 'index.html'), 'utf-8');
  let html = raw;
  if (basePath) {
    html = html.replace(/((?:href|src)=")\//g, `$1${basePath}/`);
  }
  const headInjection = `<base href="${basePath}/" />\n    <meta name="gatwy-base-path" content="${basePath}" />\n  </head>`;
  html = html.replace(/<\/head>/, headInjection);
  return html;
}

/** The PWA manifest with its root-absolute URLs moved under the reverse-proxy prefix. */
export function renderManifest(clientDir: string, basePath: string): string {
  const manifest = JSON.parse(fs.readFileSync(path.join(clientDir, 'manifest.webmanifest'), 'utf-8')) as {
    start_url?: string;
    scope?: string;
    icons?: { src: string }[];
  };
  const prefix = (u: string | undefined) => (u && u.startsWith('/') ? `${basePath}${u}` : u);
  manifest.start_url = prefix(manifest.start_url);
  manifest.scope = prefix(manifest.scope);
  manifest.icons = manifest.icons?.map((i) => ({ ...i, src: prefix(i.src) as string }));
  return JSON.stringify(manifest);
}
