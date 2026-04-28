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
import type {} from "@o3co/auth-provider-core";
import type { RedisClient } from "./types.mjs";

/**
 * Declaration-merge `redisClient` into core's ComponentMap.
 *
 * `@o3co/auth-provider-redis` claims the unnamespaced `redisClient` key
 * intentionally (per the precedent set by core's other unnamespaced slots
 * like `keyStore` and `auditSink`). Consumers who augment ComponentMap for
 * their own Redis use MUST namespace their key (e.g. `acme.cacheClient`) per
 * the unnamespaced-name reservation policy.
 *
 * Per A1 §5.5. The `declare module` block uses the PACKAGE NAME, NOT a
 * relative path — only the package name pulls in consumer augmentations to
 * the same `ComponentMap` interface.
 */
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly redisClient?: RedisClient;
	}
}
