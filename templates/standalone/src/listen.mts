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
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Logger } from "@o3co/auth-provider-core";
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
 * Express 5's `app.listen` passes the server's `error` to the same callback
 * as its `listening`, and consumes the event. A callback that ignores its
 * argument therefore announces a server on a port another process holds,
 * while the error that should have stopped the process is swallowed — which
 * is what this used to do.
 */
export function listen(app: Express, port: number, logger: Logger): Promise<Server> {
	return new Promise((resolve, reject) => {
		const server = app.listen(port, (err?: Error) => {
			if (err !== undefined) {
				reject(err);
				return;
			}
			const address = server.address() as AddressInfo | null;
			logger.info({ port: address?.port ?? port }, "server_listening");
			resolve(server);
		});
	});
}
