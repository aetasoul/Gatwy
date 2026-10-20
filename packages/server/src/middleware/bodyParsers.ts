import express, { type Request, type Response, type NextFunction, type RequestHandler } from 'express';

// SECURITY: body parsers buffer the whole body in memory, so anything
// mounted before authentication lets anonymous clients (concurrently) consume memory.
// The global parser is therefore small; routes that really need more declare a bigger
// parser themselves, after their auth + permission check.

/** Default JSON limit, applied to every request before authentication. */
export const DEFAULT_JSON_LIMIT = 100 * 1024;
/** Settings update (base64-encoded logo, ~4 MB image → ~5.4 MB base64). Authenticated route only. */
export const SETTINGS_JSON_LIMIT = 6 * 1024 * 1024;
/** Connections import. Authenticated route only. */
export const CONNECTIONS_IMPORT_JSON_LIMIT = 6 * 1024 * 1024;

// express.json alone rejects an oversized body only after reading (and discarding) all of it
// off the socket. This wrapper answers 413 as soon as the declared Content-Length, or the bytes
// actually received on a chunked body, exceed the limit, and closes the connection.
function boundedJson(limit: number): RequestHandler {
  const parser = express.json({ limit });
  return (req: Request, res: Response, next: NextFunction) => {
    let rejected = false;
    const reject = () => {
      if (rejected) return;
      rejected = true;
      req.off('data', onData);
      if (res.headersSent) return;
      res.setHeader('Connection', 'close');
      res.status(413).json({ error: 'Request body too large' });
    };
    // Only JSON bodies are touched: a 'data' listener would start the stream flowing and
    // steal the body from a downstream raw parser.
    const hasJsonBody = !!req.is('application/json');
    const declared = Number(req.headers['content-length']);
    if (hasJsonBody && Number.isFinite(declared) && declared > limit) return reject();
    let seen = 0;
    function onData(chunk: Buffer) {
      seen += chunk.length;
      if (seen > limit) reject();
    }
    if (hasJsonBody) req.on('data', onData);
    parser(req, res, (err?: unknown) => {
      req.off('data', onData);
      if (!rejected) next(err);
    });
  };
}

const defaultJson = boundedJson(DEFAULT_JSON_LIMIT);

// Routes that mount their own (larger) JSON parser behind auth; the global one must skip them,
// otherwise it would reject/buffer the body first. Express routing is case-insensitive and
// ignores a trailing slash, so normalise the same way.
// The app is mounted under config.basePathPrefix ('' at root), and the global parser sees the
// full path, so the exemption paths carry the prefix too.
function hasOwnJsonParser(req: Request, basePathPrefix: string): boolean {
  const p = req.path.toLowerCase().replace(/\/+$/, '');
  const bp = basePathPrefix.toLowerCase();
  return (req.method === 'PUT' && p === `${bp}/api/v1/settings`)
    || (req.method === 'POST' && p === `${bp}/api/v1/connections/import`);
}

/**
 * App-level JSON parser: small limit, skipping routes that mount their own after auth.
 * `basePathPrefix` is config.basePathPrefix.
 */
export function createGlobalJsonParser(basePathPrefix = ''): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    if (hasOwnJsonParser(req, basePathPrefix)) return next();
    defaultJson(req, res, next);
  };
}

/**
 * Route-level parser with a larger limit; mount it after authRequired + the permission check.
 * Plain express.json: an authorised user going over the limit gets a clean 413.
 */
export function largeJson(limit: number): RequestHandler {
  return express.json({ limit });
}
