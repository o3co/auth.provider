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
 * for a queued failure, and the subject index's sweep and the revocation record's write run
 * EVALSHA-first under a cache flag of this module.
 */

import type { Redis } from "ioredis";
import type {
	SessionRPRegistryClient,
	SessionRPRegistryMultiClient,
	SessionSidSortedSetClient,
	SessionSidSortedSetMultiClient,
	SubjectRevocationClient,
	SubjectSessionIndexClient,
	SubjectSessionIndexMultiClient,
	UserSessionStoreClient,
} from "../../clients.mjs";
import { assertPipelineSucceeded, isNoScriptError, runScript } from "../commands.mjs";
import {
	LUA_PRUNE_AND_LIST,
	LUA_PRUNE_AND_LIST_SHA,
	LUA_SET_REVOCATION_BOUNDARIES,
	LUA_SET_REVOCATION_BOUNDARIES_SHA,
	REPLACE_IF_UNCHANGED,
} from "../scripts/user-sessions.mjs";

/** Script-cache residency flag for {@link LUA_SET_REVOCATION_BOUNDARIES}. */
let watermarkScriptCached = false;

/** Script-cache residency flag for {@link LUA_PRUNE_AND_LIST}. */
let pruneAndListScriptCached = false;

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

export function makeIoredisSessionRPRegistryClient(io: Redis): SessionRPRegistryClient {
	// `pExpireGT` is `PEXPIREAT NX` then `PEXPIREAT GT`: Redis treats a key with no TTL as
	// infinite for GT/LT/NX, so a bare GT on a fresh key would no-op and leave it persistent. NX
	// sets the first TTL; GT only raises it, so a stale `expiresAt` arriving late cannot shorten it.
	const buildRPRegistryMulti = (p: ReturnType<Redis["multi"]>): SessionRPRegistryMultiClient => {
		const m: SessionRPRegistryMultiClient = {
			hSet: (k, f, v) => {
				p.hset(k, f, v);
				return m;
			},
			pExpireAt: (k, ms) => {
				p.pexpireat(k, ms);
				return m;
			},
			pExpireGT: (k, ms) => {
				p.pexpireat(k, ms, "NX");
				p.pexpireat(k, ms, "GT");
				return m;
			},
			exec: async () => assertPipelineSucceeded(await p.exec(), "sessionRPRegistryClient.exec"),
		};
		return m;
	};

	const sessionRPRegistryClient: SessionRPRegistryClient = {
		unlink: (k) => io.unlink(k),
		hSet: (k, f, v) => io.hset(k, f, v) as Promise<number>,
		// `hscanStream` emits a flat `[field, value, field, value, …]` array per
		// cursor; re-pair it so callers never see the flattening.
		hScanIterator: (key, opts) =>
			(async function* () {
				const stream = io.hscanStream(key, { count: opts?.COUNT });
				for await (const flat of stream) {
					const pairs = flat as string[];
					for (let i = 0; i + 1 < pairs.length; i += 2) {
						yield [pairs[i] as string, pairs[i + 1] as string] as const;
					}
				}
			})(),
		multi: () => buildRPRegistryMulti(io.multi()),
		pExpireAt: (k, ms) => io.pexpireat(k, ms),
		// 1 when either NX (first write) or GT (raise) set the TTL. Returns early on NX: the GT
		// that follows a successful NX answers 0 and would misreport the first write.
		pExpireGT: async (k, ms) => {
			const nx = await io.pexpireat(k, ms, "NX");
			if (nx === 1) return nx;
			return io.pexpireat(k, ms, "GT");
		},
	};
	return sessionRPRegistryClient;
}

export function makeIoredisSessionSidSortedSetClient(io: Redis): SessionSidSortedSetClient {
	const buildSortedSetMulti = (p: ReturnType<Redis["multi"]>): SessionSidSortedSetMultiClient => {
		const m: SessionSidSortedSetMultiClient = {
			pExpireAt: (k, ms) => {
				p.pexpireat(k, ms);
				return m;
			},
			pExpireGT: (k, ms) => {
				p.pexpireat(k, ms, "NX");
				p.pexpireat(k, ms, "GT");
				return m;
			},
			zAdd: (k, e, opts) => {
				if (opts?.NX) p.zadd(k, "NX", e.score, e.value);
				else p.zadd(k, e.score, e.value);
				return m;
			},
			exec: async () => assertPipelineSucceeded(await p.exec(), "sessionSidSortedSetClient.exec"),
		};
		return m;
	};

	const sortedSetClient: SessionSidSortedSetClient = {
		unlink: (k) => io.unlink(k),
		multi: () => buildSortedSetMulti(io.multi()),
		pExpireAt: (k, ms) => io.pexpireat(k, ms),
		// See sessionRPRegistryClient.pExpireGT above for return-value rationale.
		pExpireGT: async (k, ms) => {
			const nx = await io.pexpireat(k, ms, "NX");
			if (nx === 1) return nx;
			return io.pexpireat(k, ms, "GT");
		},
		zAdd: (k, e, opts) =>
			opts?.NX
				? (io.zadd(k, "NX", e.score, e.value) as Promise<unknown> as Promise<number>)
				: (io.zadd(k, e.score, e.value) as Promise<unknown> as Promise<number>),
		// ioredis 6 types zrange's `stop` as `string | Buffer` (no `number`);
		// the wire protocol stringifies args anyway, so String() is lossless.
		zRange: (k, s, e) => io.zrange(k, String(s), String(e)),
		zRem: (k, m) => io.zrem(k, m) as Promise<number>,
	};
	return sortedSetClient;
}

export function makeIoredisSubjectSessionIndexClient(io: Redis): SubjectSessionIndexClient {
	const buildSubjectIndexMulti = (p: ReturnType<Redis["multi"]>) => {
		const m: SubjectSessionIndexMultiClient = {
			zAdd: (k, e) => {
				p.zadd(k, e.score, e.value);
				return m;
			},
			// Same NX-then-GT pair as the sid-keyed client, and for the same
			// reason: Redis treats a non-volatile key as having infinite TTL for
			// `GT`, so a bare `GT` silently no-ops on the first write.
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
		async pruneExpiredAndList(key) {
			// EVALSHA-first with a NOSCRIPT fallback, as above.
			if (pruneAndListScriptCached) {
				try {
					return (await io.evalsha(LUA_PRUNE_AND_LIST_SHA, 1, key)) as string[];
				} catch (err) {
					if (!isNoScriptError(err)) throw err;
					pruneAndListScriptCached = false;
				}
			}
			const r = (await io.eval(LUA_PRUNE_AND_LIST, 1, key)) as string[];
			pruneAndListScriptCached = true;
			return r;
		},
		zRem: (k, m) => io.zrem(k, m) as Promise<number>,
		unlink: (k) => io.unlink(k),
	};
	return subjectSessionIndexClient;
}

export function makeIoredisSubjectRevocationClient(io: Redis): SubjectRevocationClient {
	const subjectRevocationClient: SubjectRevocationClient = {
		get: (k) => io.get(k),
		async setRevocationBoundaries(key, mode, beforeMs, expiresAtMs, grantRetentionMs) {
			// EVALSHA-first with a NOSCRIPT fallback to EVAL; see `scriptCached` in
			// `./federation-tokens.mts`.
			const args = [
				key,
				mode,
				String(beforeMs),
				String(expiresAtMs),
				String(grantRetentionMs),
			] as const;
			if (watermarkScriptCached) {
				try {
					return (await io.evalsha(LUA_SET_REVOCATION_BOUNDARIES_SHA, 1, ...args)) as string;
				} catch (err) {
					if (!isNoScriptError(err)) throw err;
					watermarkScriptCached = false;
				}
			}
			const stored = (await io.eval(LUA_SET_REVOCATION_BOUNDARIES, 1, ...args)) as string;
			// EVAL implicitly loads the script into Redis's server-side cache.
			watermarkScriptCached = true;
			return stored;
		},
	};
	return subjectRevocationClient;
}
