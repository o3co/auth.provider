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
 * The session stores' clients over one ioredis connection. Every MULTI/EXEC reply is checked
 * for a queued failure, and every script runs through `runScript`, EVALSHA-first.
 */

import type { Redis } from "ioredis";
import type {
	SubjectRevocationClient,
	SubjectSessionIndexClient,
	SubjectSessionIndexMultiClient,
	UserSessionStoreClient,
} from "../../clients.mjs";
import { assertPipelineSucceeded, runScript } from "../commands.mjs";
import { type IoredisDurabilityOptions, redisDurability } from "../durability.mjs";
import {
	PRUNE_AND_LIST,
	REPLACE_IF_UNCHANGED,
	SET_REVOCATION_BOUNDARIES,
} from "../scripts/user-sessions.mjs";

export function makeIoredisUserSessionStoreClient(io: Redis): UserSessionStoreClient {
	const userSessionStoreClient: UserSessionStoreClient = {
		// Cast required because TypeScript cannot unify a single arrow function
		// against an overloaded property signature (the two `set` overloads
		// have distinct return types). The runtime branch on `cond` upholds
		// each overload's contract.
		set: ((k: string, v: string, _mode: "PX", ttl: number, cond?: "NX") =>
			cond === "NX"
				? io.set(k, v, "PX", ttl, "NX")
				: io.set(k, v, "PX", ttl)) as UserSessionStoreClient["set"],
		get: (k) => io.get(k),
		del: (k) => io.del(k),
		replaceIfUnchanged: async (k, expected, next) =>
			(await runScript(io, REPLACE_IF_UNCHANGED, [k], [expected, next])) === 1,
	};
	return userSessionStoreClient;
}

export function makeIoredisSubjectSessionIndexClient(io: Redis): SubjectSessionIndexClient {
	const buildSubjectIndexMulti = (p: ReturnType<Redis["multi"]>) => {
		const m: SubjectSessionIndexMultiClient = {
			zAdd: (k, e) => {
				p.zadd(k, e.score, e.value);
				return m;
			},
			// `PEXPIREAT NX` then `PEXPIREAT GT`: Redis treats a non-volatile key
			// as having infinite TTL for `GT`, so a bare `GT` silently no-ops on
			// the first write. NX sets the first TTL; GT only raises it.
			pExpireGT: (k, ms) => {
				p.pexpireat(k, ms, "NX");
				p.pexpireat(k, ms, "GT");
				return m;
			},
			exec: async () => assertPipelineSucceeded(await p.exec(), "subjectSessionIndexClient.exec"),
		};
		return m;
	};

	const subjectSessionIndexClient: SubjectSessionIndexClient = {
		multi: () => buildSubjectIndexMulti(io.multi()),
		zAdd: (k, e) => io.zadd(k, e.score, e.value) as Promise<unknown> as Promise<number>,
		pruneExpiredAndList: async (key) =>
			(await runScript(io, PRUNE_AND_LIST, [key], [])) as string[],
		zRem: (k, m) => io.zrem(k, m) as Promise<number>,
		unlink: (k) => io.unlink(k),
	};
	return subjectSessionIndexClient;
}

export function makeIoredisSubjectRevocationClient(
	io: Redis,
	options: IoredisDurabilityOptions = {},
): SubjectRevocationClient {
	const subjectRevocationClient: SubjectRevocationClient = {
		get: (k) => io.get(k),
		advanceRevocationBoundaries: async (key, mode, write) => {
			const [value, serverNow] = (await runScript(
				io,
				SET_REVOCATION_BOUNDARIES,
				[key],
				[
					mode,
					String(write.beforeMs),
					String(write.expiresAtMs),
					String(write.grantRetentionMs),
					String(write.skewMs),
				],
			)) as [string, string];
			return { value, serverNowMs: Number(serverNow) };
		},
		durability: () => redisDurability(io, options),
	};
	return subjectRevocationClient;
}
