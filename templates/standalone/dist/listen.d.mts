import { type Server } from "node:http";
import { type Logger } from "@o3co/auth-provider-core";
import type { Express } from "express";
/**
 * Start the HTTP listener, and say so once it is bound.
 *
 * Resolves with the server once its socket is bound, after logging
 * `server_listening` (info) with the port the socket holds — the configured
 * one, or the one the OS picked for `0`. Rejects with the server's error when
 * the socket cannot be bound (`EADDRINUSE`, `EACCES`), and logs nothing: the
 * composition root awaits this, so the error ends boot the way any other boot
 * failure does.
 *
 * The server is built here (`http.createServer(app)`, as `app.listen` itself
 * does) and its events are wired here, so none of this rests on how a given
 * Express version wires them. Until the socket is bound, one `error` listener
 * turns a bind failure into the rejection. Once it is bound, that listener is
 * removed and the server gets the one it keeps: a later `error` — an `accept`
 * that fails with EMFILE — is logged as `server_error` (error, `err`: core's
 * `loggableError` projection) and the process keeps running, the server
 * accepting what it can. Without a listener of its own, such an error would be
 * thrown out of the process.
 *
 * The standalone used to call `app.listen` with a callback that ignored its
 * argument: Express 5 hands that callback the bind error too, so it announced
 * a server on a port another process held and swallowed the error that should
 * have ended the process.
 */
export declare function listen(app: Express, port: number, logger: Logger): Promise<Server>;
//# sourceMappingURL=listen.d.mts.map