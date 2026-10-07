/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { createServer } from "node:http";
import { loggableError } from "@o3co/auth-provider-core";
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
export function listen(app, port, logger) {
    const server = createServer(app);
    return new Promise((resolve, reject) => {
        const refuse = (err) => {
            server.off("listening", bound);
            reject(err);
        };
        const bound = () => {
            server.off("error", refuse);
            server.on("error", (serverErr) => {
                logger.error({ err: loggableError(serverErr) }, "server_error");
            });
            const address = server.address();
            logger.info({ port: address?.port ?? port }, "server_listening");
            resolve(server);
        };
        server.once("error", refuse);
        server.once("listening", bound);
        server.listen(port);
    });
}
