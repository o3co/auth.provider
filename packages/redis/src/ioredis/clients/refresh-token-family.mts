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
 * The refresh-token family store's client over one ioredis connection. Its `duplicate()` opens
 * a connection of its own, logs that connection's errors by their projection only, and closes
 * it on disposal without ever rejecting.
 */

import { type EventLogger, loggableError } from "@o3co/auth-provider-core";
import type { Redis } from "ioredis";
import type {
	DisposableRefreshTokenFamilyClient,
	RefreshTokenFamilyClient,
	RefreshTokenFamilyMultiClient,
} from "../../clients.mjs";
import { assertPipelineSucceeded } from "../commands.mjs";

export function makeIoredisRefreshTokenFamilyClient(
	io: Redis,
	logger: EventLogger,
): RefreshTokenFamilyClient {
	// RefreshTokenFamilyClient needs duplicate() returning DisposableRefreshTokenFamilyClient.
	// The duplicate is built by recursively wrapping the duplicated ioredis instance.
	const buildRefreshClient = (underlying: Redis): RefreshTokenFamilyClient => ({
		set: (k, v, _mode, ttl, _cond) => underlying.set(k, v, "PX", ttl, "NX") as Promise<"OK" | null>,
		get: (k) => underlying.get(k),
		pttl: (k) => underlying.pttl(k),
		watch: (...keys) => underlying.watch(...keys) as Promise<"OK">,
		unwatch: () => underlying.unwatch() as Promise<"OK">,
		multi: () => buildRefreshMulti(underlying.multi()),
		duplicate: () => {
			const dup = underlying.duplicate();
			// `duplicate()` copies options but not listeners, and an `error` event with no
			// listener throws and takes the process down. This connection never leaves the
			// wrapper, so the listener is ours. It logs the projection: ioredis attaches the
			// failed command to the error, and for a refused handshake that is `AUTH` with the
			// password.
			dup.on("error", (err: unknown) => {
				logger.error({ err: loggableError(err) }, "redis_duplicate_connection_error");
			});
			const inner = buildRefreshClient(dup);
			const disposable: DisposableRefreshTokenFamilyClient = {
				...inner,
				[Symbol.asyncDispose]: async () => {
					// Disposal must never fail. After a committed rotation, a rejection would
					// report failure, the client would retry with the old refresh token, and
					// replay detection would revoke the family; if the body threw, a rejecting
					// disposal would bury its error in a SuppressedError. `disconnect()` is
					// synchronous and never rejects.
					try {
						await dup.quit();
					} catch {
						dup.disconnect();
					}
				},
			};
			return disposable;
		},
	});

	const buildRefreshMulti = (p: ReturnType<Redis["multi"]>): RefreshTokenFamilyMultiClient => {
		const m: RefreshTokenFamilyMultiClient = {
			set: (k, v, _mode, ttl) => {
				p.set(k, v, "PX", ttl);
				return m;
			},
			// `null` survives as the WATCH-abort signal `updateFamily` retries on;
			// a queued SET that failed must not be reported as a committed
			// rotation.
			exec: async () => assertPipelineSucceeded(await p.exec(), "refreshTokenFamilyClient.exec"),
		};
		return m;
	};

	const refreshTokenFamilyClient = buildRefreshClient(io);
	return refreshTokenFamilyClient;
}
