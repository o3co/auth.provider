import { type Logger } from "@o3co/auth-provider-core";
import type { ErrorRequestHandler } from "express";
/**
 * Terminal Express error handler (#293 item 8).
 *
 * Anything a route threw past its own try/catch — and every body-parser
 * rejection, which fires before any route runs — used to fall through to
 * Express's default handler: an HTML 500 outside the structured-log pipeline,
 * carrying a stack trace outside production. A client that parses only the
 * RFC 6749 §5.2 JSON envelope this surface answers with everywhere else has
 * no way to read that page.
 *
 * Body-parser failures (malformed JSON/form, over-limit, bad charset) carry
 * their own 4xx `status` and are the client's fault: keep the status, wrap it
 * in the shared envelope, and do not log them as server errors. Everything
 * else is logged with the request path and answered `500 server_error`.
 *
 * Mount it AFTER every route (`app.use(handle.router)` included) — Express
 * routes errors only to handlers registered later.
 */
export declare const createTerminalErrorHandler: (logger: Logger) => ErrorRequestHandler;
//# sourceMappingURL=terminalError.d.mts.map