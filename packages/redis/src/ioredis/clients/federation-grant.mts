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
 * The federation grant store's client, over a connection a Cluster client can serve: every
 * write one script, the lock one `SET … NX PX`, the index read one `ZRANGE`.
 */

import type { Redis } from "ioredis";
import type { FederationGrantStoreClient } from "../../clients.mjs";
import { fgFields, fgNumber, fgWritten } from "../codec.mjs";
import { runScript } from "../commands.mjs";
import {
	FG_ACTIVATE,
	FG_CREATE,
	FG_NAME_INTENT,
	FG_NOTE_FAILURE,
	FG_PRUNE,
	FG_REPLACE,
	FG_REQUIRE_REAUTH,
	FG_RESERVE,
	FG_RETIRE_INTENT,
	FG_REVOKE,
	FG_SNAPSHOT,
	FG_TOUCH,
	FG_UNLOCK,
} from "../scripts/federation-grant.mjs";

/**
 * The commands a federation grant store needs from its connection.
 *
 * Narrower than `Redis` on purpose: everything a write does happens inside a
 * script, and a listing's reads are routed one key at a time, so a Cluster
 * client satisfies this too — without widening the WATCH-based adapters in
 * {@link makeIoredisClients}, which a Cluster cannot serve.
 */
export interface FederationGrantRedisCommands {
	evalsha(sha: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
	eval(script: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
	zrange(key: string, start: number, stop: number): Promise<string[]>;
	set(
		key: string,
		value: string,
		expiryMode: "PX",
		ttlMs: number,
		condition: "NX",
	): Promise<"OK" | null>;
}

/**
 * The federation grant store's connection, separate from {@link makeIoredisClients} so that a
 * Cluster deployment can have one.
 */
export function makeIoredisFederationGrantStoreClient(
	// `Redis` beside the narrow interface: ioredis's overloaded `zrange` is not assignable to the
	// interface's signature, so a strict caller could not pass its `Redis`. A Cluster client
	// still satisfies the interface.
	io: FederationGrantRedisCommands | Redis,
): FederationGrantStoreClient {
	const connection = io as unknown as Redis;
	return {
		async createPending(grantKey, credKey, input) {
			return fgWritten(
				await runScript(
					connection,
					FG_CREATE,
					[grantKey, credKey],
					[
						fgNumber(input.nowMs),
						input.base,
						input.handle,
						fgNumber(input.intentExpiresAtMs),
						fgNumber(input.retentionMs),
					],
				),
			);
		},

		async snapshot(grantKey, credKey) {
			const reply = await runScript(connection, FG_SNAPSHOT, [grantKey, credKey], []);
			if (!Array.isArray(reply) || reply[0] !== 1) return null;
			return {
				fields: fgFields(reply[1]),
				credential: typeof reply[2] === "string" ? reply[2] : null,
			};
		},

		async nameIntent(grantKey, input) {
			return fgWritten(
				await runScript(
					connection,
					FG_NAME_INTENT,
					[grantKey],
					[fgNumber(input.nowMs), input.handle, fgNumber(input.intentExpiresAtMs)],
				),
			);
		},

		async retireIntent(grantKey, input) {
			return fgWritten(
				await runScript(
					connection,
					FG_RETIRE_INTENT,
					[grantKey],
					[fgNumber(input.nowMs), input.handle === undefined ? "0" : "1", input.handle ?? ""],
				),
			);
		},

		async activate(grantKey, credKey, input) {
			return fgWritten(
				await runScript(
					connection,
					FG_ACTIVATE,
					[grantKey, credKey],
					[
						fgNumber(input.nowMs),
						input.handle,
						input.authorization,
						fgNumber(input.expiresAtMs),
						input.identityRevision,
						input.upstreamIssuer,
						input.upstreamSubject,
						input.credential,
						input.extension === undefined ? "0" : "1",
						input.extension ?? "",
					],
				),
			);
		},

		async replaceCredentials(grantKey, credKey, input) {
			return fgWritten(
				await runScript(
					connection,
					FG_REPLACE,
					[grantKey, credKey],
					[
						fgNumber(input.nowMs),
						fgNumber(input.expectedVersion),
						input.credential,
						input.ineligible === null ? "0" : "1",
						input.ineligible ?? "",
						input.extension === undefined ? "0" : "1",
						input.extension ?? "",
					],
				),
			);
		},

		async requireReauthorization(grantKey, credKey, input) {
			return fgWritten(
				await runScript(
					connection,
					FG_REQUIRE_REAUTH,
					[grantKey, credKey],
					[fgNumber(input.nowMs), fgNumber(input.expectedVersion)],
				),
			);
		},

		async revoke(grantKey, credKey, input) {
			return fgWritten(
				await runScript(
					connection,
					FG_REVOKE,
					[grantKey, credKey],
					[fgNumber(input.atMs), input.by],
				),
			);
		},

		async noteRefreshFailure(grantKey, input) {
			return fgWritten(
				await runScript(
					connection,
					FG_NOTE_FAILURE,
					[grantKey],
					[
						fgNumber(input.nowMs),
						fgNumber(input.expectedVersion),
						fgNumber(input.atMs),
						input.kind,
						fgNumber(input.rowMs),
						input.retryAfterSeconds === undefined ? "0" : "1",
						input.retryAfterSeconds === undefined ? "" : String(input.retryAfterSeconds),
						input.upstreamCode === undefined ? "0" : "1",
						input.upstreamCode ?? "",
					],
				),
			);
		},

		async touch(grantKey, atMs) {
			await runScript(connection, FG_TOUCH, [grantKey], [fgNumber(atMs)]);
		},

		async reserve(indexKey, member, horizonMs, allowanceMs) {
			await runScript(
				connection,
				FG_RESERVE,
				[indexKey],
				[member, fgNumber(horizonMs), fgNumber(allowanceMs)],
			);
		},

		async tryLock(lockKey, token, ttlMs) {
			const reply = await io.set(lockKey, token, "PX", ttlMs, "NX");
			return reply === "OK";
		},

		async unlock(lockKey, token) {
			await runScript(connection, FG_UNLOCK, [lockKey], [token]);
		},

		async members(indexKey) {
			// Through the narrow interface, with numbers: a client written to it —
			// a Cluster's, an operator's own — is promised numbers, and the union
			// parameter above has no one `zrange` signature to call directly.
			return await (io as FederationGrantRedisCommands).zrange(indexKey, 0, -1);
		},

		async prune(indexKey, clockMs, allowanceMs) {
			await runScript(connection, FG_PRUNE, [indexKey], [fgNumber(clockMs), fgNumber(allowanceMs)]);
		},
	};
}
