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

/**
 * A refused connection for tests: one fixed loopback origin nothing listens
 * on, checked before it is handed out. A port bound with `listen(0)` and
 * closed again is no such origin: a test file running beside may be handed
 * that port before the request is made, and the refusal becomes an answer.
 */

import { connect } from "node:net";

/**
 * Port 2 is below every ephemeral range, so no `listen(0)` is handed it, and
 * it is not on fetch's bad-port list (port 1 is).
 */
const REFUSED_ORIGIN = "http://127.0.0.1:2";

/** How long the probe waits: a firewall that drops the connection fails here, not as a hung test. */
const PROBE_TIMEOUT_MS = 2_000;

/** Resolves when a TCP connection to `origin` is refused; rejects naming what happened instead. */
export const assertConnectionRefused = async (origin: string): Promise<void> => {
	const { hostname, port } = new URL(origin);
	const outcome = await new Promise<string>((resolve) => {
		const socket = connect(Number(port), hostname);
		socket.setTimeout(PROBE_TIMEOUT_MS, () => {
			socket.destroy();
			resolve("no answer in time");
		});
		socket.once("connect", () => {
			socket.destroy();
			resolve("a connection was accepted");
		});
		socket.once("error", (error: NodeJS.ErrnoException) =>
			resolve(error.code === "ECONNREFUSED" ? "refused" : (error.code ?? error.message)),
		);
	});
	if (outcome !== "refused") throw new Error(`${origin} does not refuse connections: ${outcome}`);
};

/**
 * The loopback origin a connection to is refused, once a probe has seen it
 * refused. The same origin on every call.
 */
export const refusedOrigin = async (): Promise<string> => {
	await assertConnectionRefused(REFUSED_ORIGIN);
	return REFUSED_ORIGIN;
};
