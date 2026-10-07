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
 * a connection of its own that never carries a command across a reconnect, logs that
 * connection's errors by their projection only, and closes it on disposal without ever
 * rejecting.
 */

import { type EventLogger, loggableError } from "@o3co/auth-provider-core";
import type { Redis } from "ioredis";
import type {
	DisposableRefreshTokenFamilyClient,
	RefreshTokenFamilyClient,
	RefreshTokenFamilyMultiClient,
} from "../../clients.mjs";
import { assertPipelineSucceeded } from "../commands.mjs";
import { type IoredisDurabilityOptions, redisDurability } from "../durability.mjs";

/**
 * The duplicate's connection options over the parent's. `WATCH` lives and dies with one
 * connection, so the duplicate has no reconnect, no offline queue and no resend: once its
 * connection is lost, every later command, the `EXEC` included, rejects. It connects when
 * built, and its commands wait for that (see {@link readyWithin}), since without an offline
 * queue a command sent while connecting is refused.
 */
const DUPLICATE_OPTIONS = {
	lazyConnect: true,
	enableOfflineQueue: false,
	retryStrategy: () => null,
	autoResendUnfulfilledCommands: false,
} as const;

/**
 * Connects `conn` and settles once it is ready. With a `commandTimeout`, a connection not
 * ready within it (a server loading its dataset never is) is closed and the wait rejects as a
 * timed-out command does, so no command is sent on it afterwards. With none, the wait is the
 * connection's own.
 */
function readyWithin(conn: Redis): Promise<void> {
	const connecting = conn.connect();
	const limitMs = conn.options.commandTimeout;
	if (typeof limitMs !== "number") return connecting;
	let timer: NodeJS.Timeout | undefined;
	const timedOut = new Promise<never>((_, reject) => {
		timer = setTimeout(() => {
			conn.disconnect();
			reject(new Error("Command timed out"));
		}, limitMs);
	});
	return Promise.race([connecting, timedOut]).finally(() => clearTimeout(timer));
}

export function makeIoredisRefreshTokenFamilyClient(
	io: Redis,
	logger: EventLogger,
	options: IoredisDurabilityOptions = {},
): RefreshTokenFamilyClient {
	// RefreshTokenFamilyClient needs duplicate() returning DisposableRefreshTokenFamilyClient.
	// The duplicate is built by recursively wrapping the duplicated ioredis instance.
	// No command is sent on `underlying` before `connected` settles.
	const buildRefreshClient = (
		underlying: Redis,
		connected: Promise<unknown>,
	): RefreshTokenFamilyClient => ({
		set: (k, v, _mode, ttl, _cond) =>
			connected.then(() => underlying.set(k, v, "PX", ttl, "NX") as Promise<"OK" | null>),
		get: (k) => connected.then(() => underlying.get(k)),
		pttl: (k) => connected.then(() => underlying.pttl(k)),
		watch: (...keys) => connected.then(() => underlying.watch(...keys) as Promise<"OK">),
		unwatch: () => connected.then(() => underlying.unwatch() as Promise<"OK">),
		multi: () => buildRefreshMulti(underlying.multi(), connected),
		durability: () => connected.then(() => redisDurability(underlying, options)),
		duplicate: () => {
			const dup = underlying.duplicate(DUPLICATE_OPTIONS);
			// `duplicate()` copies options but not listeners, and an `error` event with no
			// listener throws and takes the process down. This connection never leaves the
			// wrapper, so the listener is ours. It logs the projection: ioredis attaches the
			// failed command to the error, and for a refused handshake that is `AUTH` with the
			// password.
			dup.on("error", (err: unknown) => {
				logger.error({ err: loggableError(err) }, "redis_duplicate_connection_error");
			});
			// A failed connect is the error of the first command; it is logged by the listener.
			const connected = readyWithin(dup);
			connected.catch(() => {});
			const inner = buildRefreshClient(dup, connected);
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

	const buildRefreshMulti = (
		p: ReturnType<Redis["multi"]>,
		connected: Promise<unknown>,
	): RefreshTokenFamilyMultiClient => {
		const m: RefreshTokenFamilyMultiClient = {
			set: (k, v, _mode, ttl) => {
				p.set(k, v, "PX", ttl);
				return m;
			},
			// `null` survives as the WATCH-abort signal `updateFamily` retries on;
			// a queued SET that failed must not be reported as a committed
			// rotation.
			exec: async () => {
				await connected;
				return assertPipelineSucceeded(await p.exec(), "refreshTokenFamilyClient.exec");
			},
		};
		return m;
	};

	// The caller's connection, its options and its lifetime stay the caller's.
	const refreshTokenFamilyClient = buildRefreshClient(io, Promise.resolve());
	return refreshTokenFamilyClient;
}
