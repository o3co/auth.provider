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
 * The rate limiter's client over one ioredis connection: one script reads the count and its
 * `PTTL` after the increment and its expiry.
 */

import type { Redis } from "ioredis";
import type { RateLimiterClient, RateLimitIncrement } from "../../clients.mjs";
import { LUA_INCREMENT_WITH_TTL } from "../scripts/rate-limiter.mjs";

export function makeIoredisRateLimiterClient(io: Redis): RateLimiterClient {
	const incrementWithTtlAndPttl = async (
		k: string,
		ttlSeconds: number,
	): Promise<RateLimitIncrement> => {
		const [count, pttl] = (await io.eval(LUA_INCREMENT_WITH_TTL, 1, k, String(ttlSeconds))) as [
			number,
			number,
		];
		return { count, pttl };
	};
	const rateLimiterClient: RateLimiterClient = {
		// One script for both; the count-only method serves callers that hold this client directly.
		incrementWithTtl: async (k, ttlSeconds) => (await incrementWithTtlAndPttl(k, ttlSeconds)).count,
		incrementWithTtlAndPttl,
	};
	return rateLimiterClient;
}
