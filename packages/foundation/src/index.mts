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

import type {
	AdapterFactory,
	CodeRepository,
	PathResolver,
	UserRepository,
} from "@o3co/auth-provider-core";
import { HttpUserRepository } from "./repositories/HttpUserRepository.mjs";

/**
 * Registers the foundation's built-in adapter factories. As of v0.5.0
 * (Phase 10 Q4), the only built-in adapter remaining in foundation is
 * the HTTP UserRepository — the Redis CodeRepository was relocated to
 * `@o3co/auth-provider-redis`.
 *
 * The `codeFactory` parameter is retained for backward compatibility with
 * the v0.4.x signature; foundation no longer registers any code adapter.
 *
 * Consumers that need redis-backed code storage should wire it directly:
 *
 *   import { redisCodeRepositoryBuilder } from "@o3co/auth-provider-redis";
 *   codeFactory.register("redis", redisCodeRepositoryBuilder);
 */
export const registerBuiltinAdapters = (factories: {
	userFactory: AdapterFactory<UserRepository>;
	// Kept for v0.4.x signature compatibility; no registrations performed.
	codeFactory?: AdapterFactory<CodeRepository>;
	pathResolver?: PathResolver;
}): void => {
	factories.userFactory.register("http", (config) => {
		if (typeof config.authenticateUrl !== "string") {
			throw new Error('HttpUserRepository requires "authenticateUrl" in config');
		}
		if (typeof config.authenticateByTokenUrl !== "string") {
			throw new Error('HttpUserRepository requires "authenticateByTokenUrl" in config');
		}
		return new HttpUserRepository({
			authenticateUrl: config.authenticateUrl,
			authenticateByTokenUrl: config.authenticateByTokenUrl,
			timeout: (() => {
				if (typeof config.timeout === "number" && Number.isFinite(config.timeout)) {
					return config.timeout;
				}
				if (typeof config.timeout === "string") {
					const n = Number(config.timeout);
					if (Number.isFinite(n) && n > 0) {
						return n;
					}
				}
				return 5000;
			})(),
		});
	});
};

export { HttpUserRepository } from "./repositories/HttpUserRepository.mjs";
