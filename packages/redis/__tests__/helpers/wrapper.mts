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
import type Redis from "ioredis";
import type { RedisClient, RedisMulti } from "../../src/types.mjs";

/**
 * Test-only wrapper translating ioredis's variadic call shape to the
 * structural `RedisClient` interface defined in `../../src/types.mts`.
 * Production consumers ship their own wrapper (per A1 §5.5 inline comment).
 */
export function makeIoredisRedisClient(io: Redis): RedisClient {
	const wrap = (): RedisClient => ({
		set: (k, v, _mode, ttl, _cond) => io.set(k, v, "PX", ttl, "NX") as Promise<"OK" | null>,
		del: (k) => io.del(k),
		pttl: (k) => io.pttl(k),
		exists: (k) => io.exists(k),
		get: (k) => io.get(k),
		watch: (...keys) => io.watch(...keys) as Promise<"OK">,
		unwatch: () => io.unwatch() as Promise<"OK">,
		multi: () => makeMulti(io),
		duplicate: () => {
			throw new Error("duplicate() requires per-call dispose; not modeled in tests");
		},
		hSet: (k, f, v) => io.hset(k, f, v) as Promise<number>,
		hVals: (k) => io.hvals(k),
		pExpireAt: (k, ms) => io.pexpireat(k, ms),
		zAdd: (k, e, opts) =>
			opts?.NX
				? (io.zadd(k, "NX", e.score, e.value) as Promise<unknown> as Promise<number>)
				: (io.zadd(k, e.score, e.value) as Promise<unknown> as Promise<number>),
		zRange: (k, s, e) => io.zrange(k, s, e),
		zRem: (k, m) => io.zrem(k, m) as Promise<number>,
	});
	return wrap();
}

function makeMulti(io: Redis): RedisMulti {
	const p = io.multi();
	const m: RedisMulti = {
		set: (k, v, _mode, ttl) => {
			p.set(k, v, "PX", ttl);
			return m;
		},
		hSet: (k, f, v) => {
			p.hset(k, f, v);
			return m;
		},
		pExpireAt: (k, ms) => {
			p.pexpireat(k, ms);
			return m;
		},
		zAdd: (k, e, opts) => {
			if (opts?.NX) p.zadd(k, "NX", e.score, e.value);
			else p.zadd(k, e.score, e.value);
			return m;
		},
		exec: async () => p.exec(),
	};
	return m;
}
