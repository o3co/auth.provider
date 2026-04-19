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
import { RedisCodeRepository } from "./repositories/RedisCodeRepository.mjs";

export const registerBuiltinAdapters = (factories: {
	userFactory: AdapterFactory<UserRepository>;
	codeFactory: AdapterFactory<CodeRepository>;
	pathResolver?: PathResolver;
}): void => {
	const { pathResolver } = factories;
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
			timeout: typeof config.timeout === "number" ? config.timeout : 5000,
		});
	});

	factories.codeFactory.register("redis", (config) => {
		if (typeof config.endpointUri !== "string") {
			throw new Error('RedisCodeRepository requires "endpointUri" in config');
		}
		return RedisCodeRepository.create(config, pathResolver);
	});
};

export { HttpUserRepository } from "./repositories/HttpUserRepository.mjs";
export { RedisCodeRepository } from "./repositories/RedisCodeRepository.mjs";
