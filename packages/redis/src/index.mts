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

// Side-effect import: declaration-merge `redisClient` into core's ComponentMap.
// Consumer's `import "@o3co/auth-provider-redis"` is enough to enable type
// inference for the redisClient slot.
import "./component-map.mjs";

export {
	createRedisChallengeStore,
	type RedisChallengeStoreOptions,
	redisChallengeStoreBuilder,
	redisChallengeStoreModule,
} from "./challenges.mjs";
export {
	createRedisReplaySeenSet,
	type RedisReplaySeenSetOptions,
	redisReplaySeenSetBuilder,
	redisReplaySeenSetModule,
} from "./replay-seen-set.mjs";
export type { RedisClient } from "./types.mjs";
