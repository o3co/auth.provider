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

import type { CodeRepository, RepositoryFactory, UserRepository } from "@o3co/auth-provider-core";
import { HttpUserRepository } from "./HttpUserRepository.mjs";
import { RedisCodeRepository } from "./RedisCodeRepository.mjs";

export const registerBuiltinRepositories = (factories: {
	userFactory: RepositoryFactory<UserRepository>;
	codeFactory: RepositoryFactory<CodeRepository>;
}): void => {
	factories.userFactory.register("http", (config) => {
		return new HttpUserRepository({
			baseURL: config.baseURL as string,
			timeout: (config.timeout as number) ?? 5000,
		});
	});

	factories.codeFactory.register("redis", (config) => {
		return RedisCodeRepository.create(config);
	});
};

export { HttpUserRepository } from "./HttpUserRepository.mjs";
export { RedisCodeRepository } from "./RedisCodeRepository.mjs";
